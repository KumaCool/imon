package helperupdate

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func TestSignedEnvelope(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	body := []byte("synthetic helper executable")
	digest, signature, err := Sign(body, "v0.2.0", "amd64", key)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := Write(&wire, body, "v0.2.0", "amd64", signature); err != nil {
		t.Fatal(err)
	}
	packet, err := Read(bytes.NewReader(wire.Bytes()), publicKey, "amd64")
	if err != nil || packet.Digest != digest || packet.Release != "v0.2.0" ||
		packet.Arch != "amd64" || !bytes.Equal(packet.Binary, body) {
		t.Fatalf("unexpected payload: %+v, %v", packet, err)
	}
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name string
		wire string
		key  ed25519.PublicKey
		arch string
		want error
	}{
		{"wrong key", wire.String(), wrongKey, "amd64", ErrInvalid},
		{"wrong architecture", wire.String(), publicKey, "arm64", ErrArchitecture},
		{"architecture tampering", strings.Replace(wire.String(), "\namd64\n", "\narm64\n", 1), publicKey, "amd64", ErrInvalid},
		{"release tampering", strings.Replace(wire.String(), "\nv0.2.0\n", "\nv9.2.0\n", 1), publicKey, "amd64", ErrInvalid},
		{"binary tampering", strings.Replace(wire.String(), "synthetic", "different", 1), publicKey, "amd64", ErrInvalid},
		{"added bytes", wire.String() + "data", publicKey, "amd64", ErrInvalid},
		{"truncated body", wire.String()[:wire.Len()-1], publicKey, "amd64", ErrInvalid},
		{"oversized header", strings.Repeat("x", 512) + wire.String(), publicKey, "amd64", ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(tc.wire), tc.key, tc.arch); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReleaseOrdering(t *testing.T) {
	for _, invalid := range []string{"1.2.3", "v01.2.3", "v1.2.03", "v1.2.3-rc.1", "v4294967296.2.3", "v+1.2.3", "v1.2"} {
		if ValidRelease(invalid) {
			t.Errorf("accepted invalid release %q", invalid)
		}
	}
	if !ValidRelease("v4294967295.0.0") || CompareReleases("v0.10.0", "v0.9.9") != 1 ||
		CompareReleases("v1.0.0", "v1.0.1") != -1 || CompareReleases("v1.0.0", "v1.0.0") != 0 {
		t.Fatal("unexpected release ordering")
	}
}
