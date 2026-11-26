//go:build linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"imon/internal/firewall/installer"
)

func runHelperUninstall(out io.Writer) int {
	collector := os.Getenv("SUDO_USER")
	if !runningAsCollector(collector) {
		return updateFailed
	}
	install, err := installedPaths()
	if err != nil || !sameFile("/proc/self/exe", install.helper) {
		return updateFailed
	}
	// The script and arguments are fixed. Nothing from the caller is used as
	// shell code or passed to the installer on standard input.
	// Let the script finish its transaction, including any rollback on failure.
	cmd := exec.Command("/bin/sh", "-s", "--", "uninstall", "--collector", collector)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(installer.Source)
	var result bytes.Buffer
	cmd.Stdout = &result
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil || result.String() != "uninstalled\n" {
		return updateFailed
	}
	if _, err := fmt.Fprintln(out, "uninstalled"); err != nil {
		return updateFailed
	}
	return 0
}
