//go:build linux || darwin

package appdata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateModes(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "created", "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	path := filepath.Dir(d.DBPath())
	for p, mode := range map[string]os.FileMode{
		filepath.Dir(path): 0700, path: 0700,
		d.DBPath(): 0600, filepath.Join(path, "instance.lock"): 0600,
	} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("want %04o, got %v (%v)", mode, info, err)
		}
	}
}

func TestRejectPublicDirectory(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	reject(t, path)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("Open unexpectedly changed data directory permissions: %v (%v)", info, err)
	}
}

func TestRejectSharedParent(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	reject(t, filepath.Join(path, "data"))
}

func TestValidationFailureReleasesLock(t *testing.T) {
	path := privateTestDir(t)
	db := filepath.Join(path, databaseName)
	if err := os.WriteFile(db, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(db, 0644); err != nil {
		t.Fatal(err)
	}
	reject(t, path)
	if err := os.Chmod(db, 0600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectDirectoryAndStateLinks(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	reject(t, alias)

	source := filepath.Join(target, "keep")
	const content = "unchanged"
	if err := os.WriteFile(source, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(string, string) error{
		"lock symlink": func(path, source string) error {
			return os.Symlink(source, filepath.Join(path, "instance.lock"))
		},
		"database hardlink": func(path, source string) error {
			return os.Link(source, filepath.Join(path, databaseName))
		},
		"wal symlink": func(path, source string) error {
			return os.Symlink(source, filepath.Join(path, databaseName+"-wal"))
		},
		"database public": func(path, _ string) error {
			db := filepath.Join(path, databaseName)
			if err := os.WriteFile(db, nil, 0600); err != nil {
				return err
			}
			return os.Chmod(db, 0644)
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			path := privateTestDir(t)
			if err := prepare(path, source); err != nil {
				t.Fatal(err)
			}
			reject(t, path)
			got, err := os.ReadFile(source)
			if err != nil || string(got) != content {
				t.Fatalf("Open unexpectedly changed the linked file: %q (%v)", got, err)
			}
		})
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func reject(t *testing.T, path string) {
	t.Helper()
	d, err := Open(path)
	if err == nil {
		d.Close()
		t.Fatal("Open accepted an insecure data directory")
	}
}
