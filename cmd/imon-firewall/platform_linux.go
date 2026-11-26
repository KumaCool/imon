//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func root() bool { return os.Geteuid() == 0 }

func trustedPath(path string) error {
	for part := path; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || part == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0) || part != path && !info.IsDir() {
			return errors.New("unsafe tool path")
		}
		if part == "/" {
			return nil
		}
	}
}
