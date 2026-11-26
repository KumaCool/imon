//go:build !linux

package main

import "errors"

func root() bool                  { return false }
func trustedPath(string) error    { return errors.New("linux only") }
func trustedUnitFile(string) bool { return false }
