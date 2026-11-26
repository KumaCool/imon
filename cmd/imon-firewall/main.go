// Command imon-firewall provides the privileged Imon host operations.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxOutput = 512 << 10

type backend struct {
	Backend string `json:"backend"`
	Status  string `json:"status"`
	At      int64  `json:"observed_at"`
	Format  string `json:"format,omitempty"`
	Payload any    `json:"payload,omitempty"`
	Error   string `json:"error_code,omitempty"`
	Version int    `json:"version"`
}

type limited struct {
	bytes.Buffer
	overflow bool
}

func (w *limited) Write(p []byte) (int, error) {
	remaining := maxOutput - w.Len()
	if len(p) > remaining {
		w.overflow = true
		_, _ = w.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	return w.Buffer.Write(p)
}

func resolve(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path, err := filepath.EvalSymlinks(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		if err := trustedPath(path); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", os.ErrNotExist
}

func readCommand(name string, args ...string) ([]byte, string) {
	path, err := resolve(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "not_installed"
	}
	if err != nil {
		return nil, "untrusted_tool"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	// xtables-legacy-multi selects the requested command by argv[0].
	cmd.Args[0] = name
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var out limited
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, "timeout"
	}
	if out.overflow {
		return nil, "output_limit"
	}
	if err != nil {
		return nil, "read_failed"
	}
	return out.Bytes(), ""
}

func result(name, format, code string, payload any) backend {
	b := backend{Backend: name, Format: format, At: time.Now().UnixMilli(), Version: 1}
	if code == "" {
		b.Status = "ok"
		b.Payload = payload
	} else {
		b.Status = "failed"
		b.Error = code
		if code == "not_installed" {
			b.Status = "not_installed"
		} else if code == "unsupported_backend" {
			b.Status = "unsupported"
		}
	}
	return b
}

func legacyFamily(base string) ([]byte, string) {
	data, code := readCommand(base + "-legacy-save")
	if code != "not_installed" {
		return data, code
	}
	version, code := readCommand(base, "--version")
	if code != "" {
		return nil, code
	}
	if !strings.Contains(string(version), "(legacy)") {
		return nil, "unsupported_backend"
	}
	return readCommand(base + "-save")
}

func scan() []backend {
	out := make([]backend, 3)
	done := make(chan int, 3)
	go func() {
		data, code := readCommand("ufw", "status", "verbose")
		out[0] = result("ufw", "text", code, string(data))
		done <- 0
	}()
	go func() {
		data, code := readCommand("nft", "-j", "list", "ruleset")
		if code == "" && !json.Valid(data) {
			code = "invalid_response"
		}
		out[1] = result("nftables", "json", code, json.RawMessage(data))
		done <- 1
	}()
	go func() {
		each := map[string]backend{}
		families := make(chan backend, 2)
		for _, family := range []string{"ipv4", "ipv6"} {
			go func() {
				tool := "iptables"
				if family == "ipv6" {
					tool = "ip6tables"
				}
				data, code := legacyFamily(tool)
				families <- result(family, "text", code, string(data))
			}()
		}
		for range 2 {
			b := <-families
			each[b.Backend] = b
		}
		code := ""
		if each["ipv4"].Status != "ok" && each["ipv6"].Status != "ok" {
			code = each["ipv4"].Error
			if code == "not_installed" && each["ipv6"].Error != "not_installed" {
				code = each["ipv6"].Error
			}
		}
		out[2] = result("iptables-legacy", "families", code, each)
		done <- 2
	}()
	for range out {
		<-done
	}
	return out
}

func main() {
	if !root() || len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "Imon host helper requires root")
		os.Exit(1)
	}
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "ports":
			if err := writePorts(os.Stdout); err == nil {
				return
			}
		case "service":
			os.Exit(runService(os.Stdin))
		case "uninstall":
			os.Exit(runHelperUninstall(os.Stdout))
		case "update", "version":
			os.Exit(runHelperUpdate(os.Args[1], os.Stdin, os.Stdout))
		}
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"results": scan()}); err != nil {
		os.Exit(1)
	}
}
