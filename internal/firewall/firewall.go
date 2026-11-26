// Package firewall assembles the architecture-specific maintenance artifact.
package firewall

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"imon/internal/firewall/installer"
	"imon/internal/helperupdate"
)

//go:embed all:bundles
var assets embed.FS

func readBinary(arch string) ([]byte, error) {
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("unsupported firewall architecture")
	}
	binary, err := assets.ReadFile("bundles/firewall-read-" + arch)
	if err != nil {
		return nil, fmt.Errorf("firewall helper archive unavailable")
	}
	return binary, nil
}

var (
	versionAMD64 = sync.OnceValues(func() (string, error) { return computeVersion("amd64") })
	versionARM64 = sync.OnceValues(func() (string, error) { return computeVersion("arm64") })
)

// Version identifies the immutable embedded helper independently of the panel.
func Version(arch string) (string, error) {
	switch arch {
	case "amd64":
		return versionAMD64()
	case "arm64":
		return versionARM64()
	default:
		return "", fmt.Errorf("unsupported firewall architecture")
	}
}

func computeVersion(arch string) (string, error) {
	binary, err := readBinary(arch)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(binary)), nil
}

type updateMetadata struct {
	Release   string `json:"release"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func signedUpdate(arch string, binary []byte) (updateMetadata, []byte, error) {
	var metadata updateMetadata
	encoded, err := assets.ReadFile("bundles/firewall-read-" + arch + ".json")
	if errors.Is(err, fs.ErrNotExist) {
		return metadata, nil, nil
	}
	if err != nil {
		return metadata, nil, err
	}
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return metadata, nil, err
	}
	key, err := hex.DecodeString(metadata.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || metadata.PublicKey != hex.EncodeToString(key) {
		return metadata, nil, errors.New("invalid bundled helper signing key")
	}
	var envelope bytes.Buffer
	if err := helperupdate.Write(&envelope, binary, metadata.Release, arch, metadata.Signature); err != nil {
		return metadata, nil, err
	}
	if _, err := helperupdate.Read(bytes.NewReader(envelope.Bytes()), ed25519.PublicKey(key), arch); err != nil {
		return metadata, nil, fmt.Errorf("invalid bundled helper update: %w", err)
	}
	return metadata, envelope.Bytes(), nil
}

// UpdatePackage returns the signed, architecture-specific update envelope.
// A source or local unsigned build cannot update an installed helper.
func UpdatePackage(arch string) ([]byte, error) {
	binary, err := readBinary(arch)
	if err != nil {
		return nil, err
	}
	_, envelope, err := signedUpdate(arch, binary)
	if err == nil && envelope == nil {
		err = errors.New("signed host helper update unavailable")
	}
	return envelope, err
}

func Script(arch string) ([]byte, error) {
	binary, err := readBinary(arch)
	if err != nil {
		return nil, err
	}
	metadata, _, err := signedUpdate(arch, binary)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(binary)
	var payload strings.Builder
	for len(b64) > 76 {
		payload.WriteString(b64[:76])
		payload.WriteByte('\n')
		b64 = b64[76:]
	}
	payload.WriteString(b64)
	text := strings.ReplaceAll(installer.Source, "@BINARY_SHA256@", fmt.Sprintf("%x", sha256.Sum256(binary)))
	text = strings.ReplaceAll(text, "@FIREWALL_BINARY@", payload.String())
	text = strings.ReplaceAll(text, "@HELPER_RELEASE@", metadata.Release)
	text = strings.ReplaceAll(text, "@HELPER_UPDATE_KEY@", metadata.PublicKey)
	return []byte(text), nil
}
