package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"imon/internal/systemd"
)

const (
	serviceNotRun    = 81
	serviceUncertain = 82
)

type portSnapshot struct {
	SS4     *string `json:"ss_ipv4,omitempty"`
	SS6     *string `json:"ss_ipv6,omitempty"`
	Netstat *string `json:"netstat,omitempty"`
}

func writePorts(w io.Writer) error {
	ss := func(family string) *string {
		data, code := readCommand("ss", "-H", "-l", "-n", "-t", "-u", "-p", family)
		if code != "" {
			return nil
		}
		value := string(data)
		return &value
	}
	snapshot := portSnapshot{SS4: ss("-4"), SS6: ss("-6")}
	if snapshot.SS4 == nil || snapshot.SS6 == nil {
		data, code := readCommand("netstat", "-lnptu")
		if code == "" {
			value := string(data)
			snapshot.Netstat = &value
		}
	}
	if snapshot.SS4 == nil && snapshot.SS6 == nil && snapshot.Netstat == nil {
		return fmt.Errorf("no port reader available")
	}
	return json.NewEncoder(w).Encode(snapshot)
}

func serviceRequest(r io.Reader) (action, unit string, valid bool) {
	data, err := io.ReadAll(io.LimitReader(r, 264))
	if err != nil || len(data) >= 264 || !bytes.HasSuffix(data, []byte("\n")) {
		return "", "", false
	}
	action, unit, ok := strings.Cut(string(data[:len(data)-1]), "\n")
	return action, unit, ok && (action == "start" || action == "stop") && systemd.ValidUnit(unit)
}

func serviceDefinition(data, unit string, trusted func(string) bool) bool {
	properties := make(map[string]string, 6)
	for line := range strings.SplitSeq(data, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, duplicate := properties[key]; duplicate {
			return false
		}
		properties[key] = value
	}
	if properties["Id"] != unit || properties["LoadState"] != "loaded" ||
		properties["NeedDaemonReload"] != "no" || !trusted(properties["FragmentPath"]) {
		return false
	}
	// Generated units may identify a source such as a SysV init script.
	if source := properties["SourcePath"]; source != "" && !trusted(source) {
		return false
	}
	for _, dropIn := range strings.Fields(properties["DropInPaths"]) {
		if !trusted(dropIn) {
			return false
		}
	}
	return true
}

func runService(r io.Reader) int {
	deadline := time.AfterFunc(5*time.Second, func() { os.Exit(serviceNotRun) })
	action, unit, valid := serviceRequest(r)
	if !deadline.Stop() {
		return serviceNotRun
	}
	if !valid {
		return serviceNotRun
	}
	path, err := resolve("systemctl")
	if err != nil {
		return serviceNotRun
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	// Ask for the canonical unit ID before mutation. An alias cannot redirect
	// an approved name to a different unit.
	show := exec.CommandContext(ctx, path, "--system", "--no-pager", "--all", "show",
		"-p", "Id", "-p", "LoadState", "-p", "NeedDaemonReload", "-p", "FragmentPath",
		"-p", "SourcePath", "-p", "DropInPaths", "--", unit)
	show.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	show.WaitDelay = time.Second
	var inspected limited
	show.Stdout = &inspected
	if err := show.Run(); err != nil || inspected.overflow {
		return serviceNotRun
	}
	if !serviceDefinition(inspected.String(), unit, trustedUnitFile) {
		return serviceNotRun
	}
	cmd := exec.CommandContext(ctx, path, "--system", "--no-ask-password", action, "--", unit)
	cmd.Env = show.Env
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return serviceUncertain
	}
	return 0
}
