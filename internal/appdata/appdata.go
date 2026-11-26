package appdata

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const databaseName = "state.sqlite3"

var ErrLocked = errors.New("another instance is using the data directory")

// Directory owns the process lock. Close the database before releasing it.
type Directory struct {
	dbPath  string
	release func() error
}

func Open(override string) (*Directory, error) {
	path := override
	if path == "" {
		base, err := defaultBase()
		if err != nil {
			return nil, fmt.Errorf("locate user data directory: %w", err)
		}
		path, err = defaultPath(base)
		if err != nil {
			return nil, fmt.Errorf("locate existing data directory: %w", err)
		}
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve data directory: %w", err)
	}
	if filepath.Dir(path) == path {
		return nil, errors.New("a filesystem root cannot be used as the data directory")
	}
	p, err := currentAccess()
	if err != nil {
		return nil, fmt.Errorf("determine data directory permissions: %w", err)
	}

	parent, err := p.ensureParent(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("prepare data directory parent: %w", err)
	}
	path = filepath.Join(parent, filepath.Base(path))
	if err := p.mkdir(path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	release, err := p.lock(path)
	if err != nil {
		return nil, fmt.Errorf("open data directory: %w", err)
	}
	dbPath := filepath.Join(path, databaseName)
	for _, suffix := range []string{"-wal", "-shm", "-journal", ""} {
		if err := p.checkFile(dbPath+suffix, suffix == ""); err != nil {
			return nil, errors.Join(fmt.Errorf("prepare %s: %w", databaseName+suffix, err), release())
		}
	}
	return &Directory{dbPath: dbPath, release: release}, nil
}

func defaultPath(base string) (string, error) {
	path := filepath.Join(base, "imon")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return path, err
	}
	// Reuse the original directory and its instance lock for existing users.
	legacyPath := filepath.Join(base, "infra-monitor")
	if _, err := os.Lstat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		return legacyPath, err
	}
	return path, nil
}

// Existing parent aliases, such as macOS /var, are resolved before use.
// The final directory is verified without following a symlink.
func (p accessPolicy) ensureParent(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, p.validateParent(resolved)
	}
	if !errors.Is(err, os.ErrNotExist) || filepath.Dir(path) == path {
		return "", err
	}
	parent, err := p.ensureParent(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	path = filepath.Join(parent, filepath.Base(path))
	if err := p.mkdir(path); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("data directory parent is not a directory")
	}
	return path, p.validateParent(path)
}

func (d *Directory) DBPath() string { return d.dbPath }

func (d *Directory) Close() error {
	if d.release == nil {
		return nil
	}
	release := d.release
	d.release = nil
	return release()
}
