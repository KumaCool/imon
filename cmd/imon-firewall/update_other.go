//go:build !linux

package main

import "io"

func runHelperUpdate(string, io.Reader, io.Writer) int { return 1 }

func runHelperUninstall(io.Writer) int { return 1 }
