package appdata

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDefaultPathAfterRename(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "imon")
	legacy := filepath.Join(base, "infra-monitor")
	assertPath := func(want string) {
		t.Helper()
		if path, err := defaultPath(base); err != nil || path != want {
			t.Fatalf("defaultPath = %q, %v; want %q", path, err, want)
		}
	}
	assertPath(current)
	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	assertPath(legacy)
	if err := os.Mkdir(current, 0700); err != nil {
		t.Fatal(err)
	}
	assertPath(current)
}

func TestDirectoryLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app data")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if filepath.Base(d.DBPath()) != databaseName || filepath.Base(filepath.Dir(d.DBPath())) != "app data" {
		t.Fatalf("unexpected database path: %s", d.DBPath())
	}
	if info, err := os.Stat(d.DBPath()); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("expected a regular database file, got %v (%v)", info, err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestSecondProcess$")
	cmd.Env = append(os.Environ(), "IMON_TEST_LOCKED_DIR="+d.DBPath())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second process did not detect the lock: %v\n%s", err, output)
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSecondProcess(t *testing.T) {
	db := os.Getenv("IMON_TEST_LOCKED_DIR")
	if db == "" {
		t.Skip("only run in the lock-check subprocess")
	}
	d, err := Open(filepath.Dir(db))
	if !errors.Is(err, ErrLocked) {
		if d != nil {
			d.Close()
		}
		t.Fatalf("Open returned %v, want ErrLocked", err)
	}
}
