// Package helperupdate defines Imon's signed Linux helper update format.
package helperupdate

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const magic = "IMON-HELPER-UPDATE-1"

const maxBinarySize = 16 << 20

var (
	ErrInvalid      = errors.New("invalid helper update")
	ErrArchitecture = errors.New("wrong helper update architecture")
)

type Payload struct {
	Release string
	Arch    string
	Digest  string
	Binary  []byte
}

func releaseParts(release string) ([3]uint32, bool) {
	var parts [3]uint32
	if !strings.HasPrefix(release, "v") || len(release) > 33 {
		return parts, false
	}
	fields := strings.Split(release[1:], ".")
	if len(fields) != len(parts) {
		return parts, false
	}
	for i, field := range fields {
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != field {
			return parts, false
		}
		parts[i] = uint32(value)
	}
	return parts, true
}

func ValidRelease(release string) bool {
	_, ok := releaseParts(release)
	return ok
}

// CompareReleases compares two releases previously checked with ValidRelease.
func CompareReleases(left, right string) int {
	a, _ := releaseParts(left)
	b, _ := releaseParts(right)
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func validArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

func signatureInput(release, arch, digest string) string {
	return magic + "\n" + release + "\n" + arch + "\n" + digest + "\n"
}

func decodeHex(value string, size int) ([]byte, bool) {
	if len(value) != 2*size || strings.ToLower(value) != value {
		return nil, false
	}
	raw, err := hex.DecodeString(value)
	return raw, err == nil
}

func Sign(binary []byte, release, arch string, key ed25519.PrivateKey) (digest, signature string, err error) {
	if !ValidRelease(release) || !validArch(arch) || len(binary) == 0 || len(binary) > maxBinarySize ||
		len(key) != ed25519.PrivateKeySize {
		return "", "", ErrInvalid
	}
	digest = fmt.Sprintf("%x", sha256.Sum256(binary))
	return digest, hex.EncodeToString(ed25519.Sign(key, []byte(signatureInput(release, arch, digest)))), nil
}

func Write(w io.Writer, binary []byte, release, arch, signature string) error {
	if _, ok := decodeHex(signature, ed25519.SignatureSize); !ok ||
		!ValidRelease(release) || !validArch(arch) || len(binary) == 0 || len(binary) > maxBinarySize {
		return ErrInvalid
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(binary))
	if _, err := io.WriteString(w, signatureInput(release, arch, digest)+signature+"\n"); err != nil {
		return err
	}
	n, err := w.Write(binary)
	if err == nil && n != len(binary) {
		err = io.ErrShortWrite
	}
	return err
}

func Read(r io.Reader, key ed25519.PublicKey, expectedArch string) (Payload, error) {
	const headerBufferSize = 256
	reader := bufio.NewReaderSize(r, headerBufferSize)
	fields := make([]string, 5)
	for i := range fields {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return Payload{}, ErrInvalid
		}
		fields[i] = string(line[:len(line)-1])
	}
	release, arch, digest := fields[1], fields[2], fields[3]
	signature, hasSignature := decodeHex(fields[4], ed25519.SignatureSize)
	if _, validDigest := decodeHex(digest, sha256.Size); !validDigest || fields[0] != magic ||
		!ValidRelease(release) || !validArch(arch) || !hasSignature || len(key) != ed25519.PublicKeySize ||
		!ed25519.Verify(key, []byte(signatureInput(release, arch, digest)), signature) {
		return Payload{}, ErrInvalid
	}
	if arch != expectedArch {
		return Payload{}, ErrArchitecture
	}
	binary, err := io.ReadAll(io.LimitReader(reader, maxBinarySize+1))
	if err != nil || len(binary) == 0 || len(binary) > maxBinarySize || fmt.Sprintf("%x", sha256.Sum256(binary)) != digest {
		return Payload{}, ErrInvalid
	}
	return Payload{Release: release, Arch: arch, Digest: digest, Binary: binary}, nil
}
