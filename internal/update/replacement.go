package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Replacement owns an executable candidate and a link to the original.
// All three paths must be on the same filesystem for atomic replacement.
type Replacement struct {
	Target    string
	Tag       string
	original  os.FileInfo
	candidate string
	backup    string
	installed bool
}

func prepare(ctx context.Context, target, archive string, current info) (_ *Replacement, err error) {
	target, err = filepath.EvalSymlinks(target)
	if err != nil {
		return nil, err
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	original, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	if !original.Mode().IsRegular() || original.Mode().Perm()&0100 == 0 || original.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("update target must be a regular executable")
	}
	file, err := os.CreateTemp(filepath.Dir(target), ".imon-candidate-*")
	if err != nil {
		return nil, err
	}
	r := &Replacement{Target: target, Tag: current.Tag, original: original, candidate: file.Name()}
	defer func() {
		_ = file.Close()
		if err != nil {
			r.Cleanup()
		}
	}()
	// Recheck the staged file itself before extracting an executable from it.
	if !fileMatches(archive, current) {
		return nil, errChecksum
	}
	if err := extract(archive, file); err != nil {
		return nil, err
	}
	if err := file.Chmod(original.Mode().Perm() & 0755); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	probe, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(probe, r.candidate, "--version").Output(); err != nil || strings.TrimSpace(string(output)) != current.Tag {
		return nil, fmt.Errorf("%w: executable did not report %s", errArchive, current.Tag)
	}
	// Reserve rollback before telling the UI that an update can proceed.
	r.backup = r.candidate + ".previous"
	if err := os.Link(target, r.backup); err != nil {
		return nil, err
	}
	return r, nil
}

func extract(archive string, into io.Writer) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return errors.Join(errArchive, err)
	}
	defer gz.Close()
	// Limit the entire expanded stream, including tar headers and padding.
	const maxExpanded = maxArchiveSize + (1 << 20)
	limit := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	t := tar.NewReader(limit)
	seen := map[string]bool{}
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.Join(errArchive, err)
		}
		// The build produces a flat archive containing the binary and a guide.
		if seen[h.Name] || h.Typeflag != tar.TypeReg || h.Mode&^0777 != 0 || h.Size <= 0 || h.Size > maxArchiveSize {
			return errArchive
		}
		seen[h.Name] = true
		switch h.Name {
		case "imon":
			if _, err := io.Copy(into, t); err != nil {
				return errors.Join(errArchive, err)
			}
		case "backup-and-restore.md":
			if h.Size > 1<<20 {
				return errArchive
			}
		default:
			return errArchive
		}
	}
	// Only zero tar padding may follow the end marker. Reading to EOF validates
	// the gzip trailer and ensures appended gzip members are not silently used.
	if !seen["imon"] || limit.N <= 0 {
		return errArchive
	}
	var tail [32768]byte
	var trailing int
	for {
		n, err := limit.Read(tail[:])
		trailing += n
		if trailing > 1<<20 || !allZero(tail[:n]) {
			return errArchive
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || limit.N <= 0 {
			return errors.Join(errArchive, err)
		}
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Install replaces the current executable. Cleanup must not run until the
// candidate starts successfully or Rollback restores the original.
func (r *Replacement) Install() error {
	current, err := os.Lstat(r.Target)
	if err != nil {
		return err
	}
	if !os.SameFile(r.original, current) || current.Size() != r.original.Size() || !current.ModTime().Equal(r.original.ModTime()) {
		return errors.New("running executable changed during update")
	}
	if err := os.Rename(r.candidate, r.Target); err != nil {
		return err
	}
	r.installed = true
	r.candidate = ""
	return nil
}

func (r *Replacement) Rollback() error {
	if !r.installed {
		return nil
	}
	if err := os.Rename(r.backup, r.Target); err != nil {
		return fmt.Errorf("restore executable from %s: %w", filepath.Base(r.backup), err)
	}
	r.backup = ""
	r.installed = false
	return nil
}

func (r *Replacement) Cleanup() {
	if r.candidate != "" {
		_ = os.Remove(r.candidate)
	}
	if r.backup != "" {
		_ = os.Remove(r.backup)
	}
}
