//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func root() bool { return os.Geteuid() == 0 }

// Systemd may load packaged units through symlinks or write units below /run.
// Verify the resolved definition and all paths leading to it.
func trustedUnitFile(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	// Walk from the root so each symlink is resolved only after checking
	// that its parent path cannot be changed by the SSH account.
	for range 40 {
		current := "/"
		parts := strings.Split(path[1:], "/")
		for i, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil {
				return false
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return false
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(current)
				if err != nil {
					return false
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(current), target)
				}
				path = filepath.Join(target, filepath.Join(parts[i+1:]...))
				break
			}
			if info.Mode().Perm()&0022 != 0 {
				return false
			}
			if i == len(parts)-1 {
				return info.Mode().IsRegular()
			}
			if !info.IsDir() {
				return false
			}
		}
	}
	return false
}

func trustedPath(path string) error {
	for part := path; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 ||
			(part != path && !info.IsDir()) ||
			(part == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0)) {
			return errors.New("unsafe tool path")
		}
		if part == "/" {
			return nil
		}
	}
}
