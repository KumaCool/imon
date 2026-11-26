//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imon/internal/helperupdate"
)

func TestAcceptOnlyNewHelperReleases(t *testing.T) {
	prior := helperRecord{Version: 2, Collector: "fixture_reader", Release: "v0.2.0", Digest: "old"}
	for _, tc := range []struct {
		release, digest string
		status          int
	}{
		{"v0.1.0", "old", updateTooOld},
		{"v0.1.0", "new", updateTooOld},
		{"v0.2.0", "new", updateTooOld},
		{"v0.2.0", "old", 0},
		{"v0.3.0", "old", updateTooOld},
		{"v0.3.0", "new", 0},
	} {
		next, status := updatedRecord(prior, helperupdate.Payload{Release: tc.release, Digest: tc.digest})
		if status != tc.status {
			t.Errorf("%+v returned %d", tc, status)
		}
		if tc.status == 0 {
			if next.Release != tc.release || next.Digest != tc.digest || next.Collector != prior.Collector {
				t.Errorf("%+v produced %+v", tc, next)
			}
		} else if next != prior {
			t.Errorf("rejected release changed installed record: %+v", next)
		}
	}
}

func installedFixture(t *testing.T) (helperInstall, helperRecord, helperRecord, []byte, []byte) {
	t.Helper()
	if !root() {
		t.Skip("helper transaction uses root-owned files")
	}
	dir := t.TempDir()
	install := helperInstall{helper: filepath.Join(dir, "firewall-read"), manifest: filepath.Join(dir, "firewall-manifest.json")}
	previous, replacement := []byte("old fixture executable"), []byte("updated fixture executable")
	prior := helperRecord{
		Version: 2, Collector: "fixture_reader",
		Release: "v0.2.0", Digest: fmt.Sprintf("%x", sha256.Sum256(previous)),
		Key: strings.Repeat("12", 32),
	}
	next := prior
	next.Release, next.Digest = "v0.3.0", fmt.Sprintf("%x", sha256.Sum256(replacement))
	if err := stageFile(install.helper, previous, 0755); err != nil {
		t.Fatal(err)
	}
	stageFixtureManifest(t, install.manifest, prior)
	return install, prior, next, previous, replacement
}

func stageFixtureManifest(t *testing.T, path string, record helperRecord) {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func verifyFixture(t *testing.T, install helperInstall, expected helperRecord) {
	t.Helper()
	record, err := readRecord(install.manifest, expected.Key)
	if err != nil || record != expected {
		t.Fatalf("unexpected installed manifest: %+v, %v", record, err)
	}
	_, digest, err := helperBinary(install.helper)
	if err != nil || digest != expected.Digest {
		t.Fatalf("unexpected installed executable: %s, %v", digest, err)
	}
}

func TestHelperReplacement(t *testing.T) {
	install, prior, next, previous, replacement := installedFixture(t)
	openPrevious, err := os.Open(install.helper)
	if err != nil {
		t.Fatal(err)
	}
	defer openPrevious.Close()
	oldPath := fmt.Sprintf("/proc/self/fd/%d", openPrevious.Fd())
	if !sameFile(oldPath, install.helper) {
		t.Fatal("original executable file identity not recognized")
	}
	if err := os.Mkdir(install.nextManifest(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := install.replace(previous, next, replacement); err == nil {
		t.Fatal("staging should fail if the pending manifest path is blocked")
	}
	verifyFixture(t, install, prior)
	if err := os.Remove(install.nextManifest()); err != nil {
		t.Fatal(err)
	}
	if err := install.replace(previous, next, replacement); err != nil {
		t.Fatal(err)
	}
	verifyFixture(t, install, next)
	if sameFile(oldPath, install.helper) {
		t.Fatal("queued old helper would see itself as the installed executable")
	}
}

func TestHelperRecoversInterruptedReplacement(t *testing.T) {
	for _, switched := range []bool{false, true} {
		t.Run(fmt.Sprint(switched), func(t *testing.T) {
			install, prior, next, _, replacement := installedFixture(t)
			if err := stageFile(install.nextBinary(), replacement, 0755); err != nil {
				t.Fatal(err)
			}
			stageFixtureManifest(t, install.nextManifest(), next)
			expected := prior
			if switched {
				if err := os.Rename(install.nextBinary(), install.helper); err != nil {
					t.Fatal(err)
				}
				expected = next
			}
			_, digest, err := helperBinary(install.helper)
			if err != nil {
				t.Fatal(err)
			}
			reconciled, err := install.reconcile(prior, digest)
			if err != nil || reconciled != expected {
				t.Fatalf("unexpected reconciled manifest: %+v, %v", reconciled, err)
			}
			verifyFixture(t, install, expected)
			for _, path := range []string{install.nextBinary(), install.nextManifest(), install.stagingManifest()} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("staged file not cleaned: %v", err)
				}
			}
		})
	}
}

func TestHelperRestoresBinaryIfManifestActivationFails(t *testing.T) {
	install, prior, next, previous, replacement := installedFixture(t)
	savedManifest := install.manifest + ".saved"
	if err := os.Rename(install.manifest, savedManifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(install.manifest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := install.replace(previous, next, replacement); err == nil {
		t.Fatal("manifest activation should fail when its destination is a directory")
	}
	if err := os.Remove(install.manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedManifest, install.manifest); err != nil {
		t.Fatal(err)
	}
	verifyFixture(t, install, prior)
	for _, path := range []string{install.nextBinary(), install.nextManifest(), install.stagingManifest()} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("staged file not cleaned after rollback: %v", err)
		}
	}
}
