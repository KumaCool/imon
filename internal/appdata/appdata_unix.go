//go:build linux || darwin

package appdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

type accessPolicy struct{ uid uint32 }

func currentAccess() (accessPolicy, error) {
	return accessPolicy{uid: uint32(os.Geteuid())}, nil
}

func defaultBase() (string, error) {
	if runtime.GOOS == "darwin" {
		return os.UserConfigDir()
	}
	if base := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(base) {
		return base, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share"), nil
}

func (p accessPolicy) mkdir(path string) error { return os.Mkdir(path, 0700) }

func (p accessPolicy) validateParent(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		uid := info.Sys().(*syscall.Stat_t).Uid
		if !info.IsDir() || (uid != 0 && uid != p.uid) ||
			(info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return errors.New("data directory must be under a trusted directory")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func (p accessPolicy) lock(path string) (func() error, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != p.uid || info.Mode().Perm() != 0700 {
		return nil, errors.New("data directory must be owned by the current user, not a symlink, with mode 0700")
	}
	file, err := p.openFile(filepath.Join(path, "instance.lock"), true)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return file.Close, nil
}

func (p accessPolicy) checkFile(path string, create bool) error {
	f, err := p.openFile(path, create)
	if !create && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

func (p accessPolicy) openFile(path string, create bool) (*os.File, error) {
	const privateFileError = "state file must be a private regular file owned by the current user (mode 0600)"
	info, err := os.Lstat(path)
	if err == nil && !p.isPrivateFile(info) {
		return nil, errors.New(privateFileError)
	}
	if err != nil && (!create || !errors.Is(err, os.ErrNotExist)) {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if create {
		flags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_CREAT
	}
	fd, err := unix.Open(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err = f.Stat()
	if err != nil || !p.isPrivateFile(info) {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New(privateFileError)
	}
	return f, nil
}

func (p accessPolicy) isPrivateFile(info os.FileInfo) bool {
	stat := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && stat.Uid == p.uid && stat.Nlink == 1
}
