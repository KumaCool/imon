//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"imon/internal/helperupdate"
)

// Set by the release builder to the pinned Ed25519 public key in lowercase hex.
var updateBuild string

const (
	updateRejected = 2
	updateBadArch  = 3
	updateTooOld   = 4
	updateFailed   = 5
)

type helperRecord struct {
	Version   int    `json:"version"`
	Collector string `json:"collector"`
	Digest    string `json:"binary_sha256"`
	Release   string `json:"release"`
	Key       string `json:"update_key"`
}

type helperInstall struct {
	helper   string
	manifest string
}

func (i helperInstall) nextBinary() string {
	return filepath.Join(filepath.Dir(i.helper), ".helper-next")
}
func (i helperInstall) nextManifest() string {
	return filepath.Join(filepath.Dir(i.manifest), ".helper-next.json")
}

func (i helperInstall) stagingManifest() string { return i.nextManifest() + ".tmp" }

func installedPaths() (helperInstall, error) {
	path, err := os.Executable()
	if err != nil {
		return helperInstall{}, err
	}
	for _, layout := range []string{"imon", "infra-monitor"} {
		if path == "/usr/local/libexec/"+layout+"/firewall-read" {
			return helperInstall{path, "/var/lib/" + layout + "/firewall-manifest.json"}, nil
		}
	}
	return helperInstall{}, errors.New("unknown helper installation")
}

func trustedUpdateDir(path string) error {
	for dir := path; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe helper directory")
		}
		if dir == "/" {
			return nil
		}
	}
}

func validateUpdateFile(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode() != mode || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("unsafe helper file")
	}
	return nil
}

func keyBytes(key string) (ed25519.PublicKey, bool) {
	raw, err := hex.DecodeString(key)
	return raw, err == nil && len(raw) == ed25519.PublicKeySize && hex.EncodeToString(raw) == key
}

func readRecord(path, pinnedKey string) (helperRecord, error) {
	if err := validateUpdateFile(path, 0600); err != nil {
		return helperRecord{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return helperRecord{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil {
		return helperRecord{}, err
	}
	var record helperRecord
	if len(data) > 512 || json.Unmarshal(data, &record) != nil {
		return helperRecord{}, errors.New("invalid helper manifest")
	}
	rawDigest, err := hex.DecodeString(record.Digest)
	if err != nil || len(rawDigest) != sha256.Size || hex.EncodeToString(rawDigest) != record.Digest ||
		!helperupdate.ValidRelease(record.Release) || record.Key != pinnedKey || record.Version != 2 ||
		record.Collector == "" || record.Collector == "root" {
		return helperRecord{}, errors.New("invalid helper manifest")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return helperRecord{}, errors.New("invalid helper manifest")
	}
	return record, nil
}

func runningAsCollector(collector string) bool {
	if os.Getenv("SUDO_USER") != collector {
		return false
	}
	account, err := user.Lookup(collector)
	if err != nil {
		return false
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	return err == nil && uid != 0 && strconv.FormatUint(uid, 10) == os.Getenv("SUDO_UID")
}

func withUpdateLock() (*os.File, error) {
	path := "/var/lib"
	if err := trustedUpdateDir(path); err != nil {
		return nil, err
	}
	lock, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			lock.Close()
			return nil, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func syncParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func stageFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func removeStagedFile(path string, mode os.FileMode) error {
	err := validateUpdateFile(path, mode)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func helperBinary(path string) ([]byte, string, error) {
	if err := validateUpdateFile(path, 0755); err != nil {
		return nil, "", err
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return binary, fmt.Sprintf("%x", sha256.Sum256(binary)), nil
}

// reconcile repairs the release manifest after an interrupted atomic executable rename.
func (i helperInstall) reconcile(current helperRecord, digest string) (helperRecord, error) {
	pending, err := readRecord(i.nextManifest(), current.Key)
	if err != nil && !os.IsNotExist(err) {
		return helperRecord{}, err
	}
	if err == nil {
		if pending.Collector != current.Collector || pending.Digest == current.Digest ||
			helperupdate.CompareReleases(pending.Release, current.Release) <= 0 {
			return helperRecord{}, errors.New("invalid pending helper manifest")
		}
		switch digest {
		case current.Digest:
			err = os.Remove(i.nextManifest())
		case pending.Digest:
			if err = syncParent(i.helper); err == nil {
				err = os.Rename(i.nextManifest(), i.manifest)
			}
			current = pending
		default:
			return helperRecord{}, errors.New("unknown installed helper")
		}
		if err != nil {
			return helperRecord{}, err
		}
		if err = syncParent(i.manifest); err != nil {
			return helperRecord{}, err
		}
	}
	if digest != current.Digest {
		return helperRecord{}, errors.New("unknown installed helper")
	}
	if err := removeStagedFile(i.stagingManifest(), 0600); err != nil {
		return helperRecord{}, err
	}
	if err := removeStagedFile(i.nextBinary(), 0755); err != nil {
		// Files staged before chmod and an interruption are still root-only.
		err = removeStagedFile(i.nextBinary(), 0600)
		if err != nil {
			return helperRecord{}, err
		}
	}
	return current, nil
}

func (i helperInstall) replace(prior []byte, next helperRecord, binary []byte) error {
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = stageFile(i.nextBinary(), binary, 0755); err != nil {
		return err
	}
	if err = stageFile(i.stagingManifest(), append(data, '\n'), 0600); err == nil {
		err = os.Rename(i.stagingManifest(), i.nextManifest())
	}
	if err != nil {
		_ = os.Remove(i.nextBinary())
		_ = os.Remove(i.stagingManifest())
		return err
	}
	if err = syncParent(i.manifest); err == nil {
		err = os.Rename(i.nextBinary(), i.helper)
	}
	if err != nil {
		_ = os.Remove(i.nextBinary())
		_ = os.Remove(i.nextManifest())
		return err
	}
	if err = syncParent(i.helper); err == nil {
		err = os.Rename(i.nextManifest(), i.manifest)
	}
	if err != nil {
		// Restore the previous executable where possible. The pending manifest
		// remains available to reconcile either valid executable after a crash.
		if stageFile(i.nextBinary(), prior, 0755) == nil &&
			os.Rename(i.nextBinary(), i.helper) == nil &&
			syncParent(i.helper) == nil {
			_ = os.Remove(i.nextManifest())
			_ = syncParent(i.manifest)
		}
		return err
	}
	return syncParent(i.manifest)
}

func matchesELFArch(data []byte, arch string) bool {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer file.Close()
	machine := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[arch]
	if machine == elf.EM_NONE || file.Machine != machine || file.Class != elf.ELFCLASS64 ||
		file.Type != elf.ET_EXEC || file.Data != elf.ELFDATA2LSB {
		return false
	}
	for _, segment := range file.Progs {
		if segment.Type == elf.PT_INTERP {
			return false
		}
	}
	return true
}

func readUpgrade(stdin io.Reader, key ed25519.PublicKey) (helperupdate.Payload, error) {
	type result struct {
		payload helperupdate.Payload
		err     error
	}
	results := make(chan result, 1)
	go func() {
		payload, err := helperupdate.Read(stdin, key, runtime.GOARCH)
		results <- result{payload, err}
	}()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case r := <-results:
		return r.payload, r.err
	case <-timer.C:
		return helperupdate.Payload{}, helperupdate.ErrInvalid
	}
}

func updatedRecord(current helperRecord, payload helperupdate.Payload) (helperRecord, int) {
	order := helperupdate.CompareReleases(payload.Release, current.Release)
	if order == 0 && payload.Digest == current.Digest {
		return current, 0
	}
	if order <= 0 || payload.Digest == current.Digest {
		return current, updateTooOld
	}
	next := current
	next.Digest = payload.Digest
	next.Release = payload.Release
	return next, 0
}

func sameFile(left, right string) bool {
	a, err := os.Stat(left)
	if err != nil {
		return false
	}
	b, err := os.Stat(right)
	return err == nil && os.SameFile(a, b)
}

func runHelperUpdate(command string, stdin io.Reader, stdout io.Writer) int {
	if updateBuild == "" {
		return 1
	}
	key, valid := keyBytes(updateBuild)
	if !valid {
		return updateFailed
	}
	var payload helperupdate.Payload
	if command == "update" {
		var err error
		payload, err = readUpgrade(stdin, key)
		if errors.Is(err, helperupdate.ErrArchitecture) {
			return updateBadArch
		}
		if err != nil {
			return updateRejected
		}
		if !matchesELFArch(payload.Binary, payload.Arch) {
			return updateBadArch
		}
	}
	install, err := installedPaths()
	if err != nil {
		return updateFailed
	}
	lock, err := withUpdateLock()
	if err != nil {
		return updateFailed
	}
	defer lock.Close()
	if trustedUpdateDir(filepath.Dir(install.helper)) != nil || trustedUpdateDir(filepath.Dir(install.manifest)) != nil {
		return updateFailed
	}
	current, err := readRecord(install.manifest, updateBuild)
	if err != nil || !runningAsCollector(current.Collector) {
		return updateFailed
	}
	oldHelper, digest, err := helperBinary(install.helper)
	if err != nil {
		return updateFailed
	}
	current, err = install.reconcile(current, digest)
	if err != nil {
		return updateFailed
	}
	if command == "update" {
		next, code := updatedRecord(current, payload)
		if code != 0 {
			return code
		}
		if next != current {
			// A request queued behind another update must run the installed
			// helper before it can replace the executable again.
			if !sameFile("/proc/self/exe", install.helper) ||
				install.replace(oldHelper, next, payload.Binary) != nil {
				return updateFailed
			}
			current = next
		}
	}
	if _, err := fmt.Fprintln(stdout, "installed", current.Digest); err != nil {
		return updateFailed
	}
	return 0
}
