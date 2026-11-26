// Package firewall assembles the architecture-specific maintenance artifact.
package firewall

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"strings"
)

//go:embed maintain.sh all:bundles
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

// Version identifies the reader itself, independently of the panel version
// and any changes to the wrapping maintenance script.
func Version(arch string) (string, error) {
	binary, err := readBinary(arch)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(binary)), nil
}

func Script(arch string) ([]byte, error) {
	binary, err := readBinary(arch)
	if err != nil {
		return nil, err
	}
	template, err := assets.ReadFile("maintain.sh")
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
	text := strings.ReplaceAll(string(template), "@BINARY_SHA256@", fmt.Sprintf("%x", sha256.Sum256(binary)))
	text = strings.ReplaceAll(text, "@FIREWALL_BINARY@", payload.String())
	return []byte(text), nil
}
