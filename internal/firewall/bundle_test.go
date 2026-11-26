package firewall

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestEmbeddedReleaseBundles(t *testing.T) {
	for _, target := range []struct {
		arch    string
		machine elf.Machine
	}{{"amd64", elf.EM_X86_64}, {"arm64", elf.EM_AARCH64}} {
		t.Run(target.arch, func(t *testing.T) {
			path := "bundles/firewall-read-" + target.arch
			binary, err := assets.ReadFile(path)
			script, scriptErr := Script(target.arch)
			if err != nil {
				if os.Getenv("IMON_REQUIRE_BUNDLES") == "1" || scriptErr == nil {
					t.Fatalf("%s is required: %v (script error: %v)", path, err, scriptErr)
				}
				t.Skip("local source build without bundled reader")
			}
			if scriptErr != nil {
				t.Fatal(scriptErr)
			}
			version, versionErr := Version(target.arch)
			if versionErr != nil || version != fmt.Sprintf("%x", sha256.Sum256(binary)) {
				t.Fatalf("reader version = %q, %v", version, versionErr)
			}
			reader, err := elf.NewFile(bytes.NewReader(binary))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if reader.Machine != target.machine || reader.Class != elf.ELFCLASS64 || reader.Type != elf.ET_EXEC {
				t.Fatalf("%s has unexpected ELF class/type/machine: %v/%v/%v", path, reader.Class, reader.Type, reader.Machine)
			}
			for _, segment := range reader.Progs {
				if segment.Type == elf.PT_INTERP {
					t.Fatalf("%s has a dynamic loader", path)
				}
			}
			content := string(script)
			if !strings.Contains(content, fmt.Sprintf("\nwanted=%x\n", sha256.Sum256(binary))) ||
				strings.Contains(content, "@BINARY_SHA256@") || strings.Contains(content, "@FIREWALL_BINARY@") ||
				strings.Contains(content, "@HELPER_RELEASE@") || strings.Contains(content, "@HELPER_UPDATE_KEY@") {
				t.Fatal("generated script does not contain a resolved reader checksum and payload")
			}
			_, rest, found := strings.Cut(content, "<<'IMON_BINARY'\n")
			payload, _, terminated := strings.Cut(rest, "\nIMON_BINARY\n")
			if !found || !terminated {
				t.Fatal("generated script is missing the embedded reader")
			}
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil || !bytes.Equal(binary, decoded) {
				t.Fatal("generated script does not reproduce the bundled reader")
			}
			metadata, signed, err := signedUpdate(target.arch, binary)
			if err != nil {
				t.Fatal(err)
			}
			update, updateErr := UpdatePackage(target.arch)
			if signed == nil {
				if os.Getenv("IMON_REQUIRE_SIGNED_HELPERS") == "1" || updateErr == nil {
					t.Fatalf("no signed update for %s: %v", target.arch, updateErr)
				}
			} else {
				if updateErr != nil || !bytes.Equal(update, signed) {
					t.Fatalf("unavailable signed update: %v", updateErr)
				}
				if !strings.Contains(content, metadata.PublicKey) || !strings.Contains(content, metadata.Release) {
					t.Fatal("installer is missing signed helper metadata")
				}
			}
		})
	}
}
