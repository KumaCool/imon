package collector

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestFirewallReaderLayouts(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires a POSIX shell")
	}
	currentHash, legacyHash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, test := range []struct {
		name            string
		current, legacy bool
		legacySudoOnly  bool
		wantStatus      string
		wantHelper      string
	}{
		{name: "absent", wantStatus: "uninstalled", wantHelper: "imon"},
		{name: "current", current: true, wantStatus: "installed " + currentHash, wantHelper: "imon"},
		{name: "legacy", legacy: true, wantStatus: "installed " + legacyHash, wantHelper: "infra-monitor"},
		{name: "duplicate", current: true, legacy: true, wantStatus: "unknown"},
		{name: "legacy grant remains", current: true, legacySudoOnly: true, wantStatus: "unknown"},
		{name: "only legacy grant remains", legacySudoOnly: true, wantStatus: "unknown", wantHelper: "infra-monitor"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			write := func(name, contents string) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
					t.Fatal(err)
				}
			}
			install := func(name string) {
				write("lib/"+name+"/firewall-read", "")
				write("state/"+name+"/firewall-manifest.json", "")
				write("sudoers/"+name+"-firewall", "")
			}
			if test.current {
				install("imon")
			}
			if test.legacy {
				install("infra-monitor")
			}
			if test.legacySudoOnly {
				write("sudoers/infra-monitor-firewall", "")
			}
			// Stub metadata tools so the fixture needs neither root nor a
			// Linux userland. The shell still checks real path existence.
			const stubTools = `fixture_stat() {
  case "$2:$4" in
    '%u:%h:%a:'*/firewall-manifest.json) printf '0:1:600\n' ;;
    '%u:%h:%a:'*/firewall-read) printf '0:1:755\n' ;;
    '%u:'*) printf '0\n' ;;
    '%a:'*) printf '755\n' ;;
    *) return 1 ;;
  esac
}
fixture_sha256sum() {
  case "$2" in
    */imon/firewall-read) printf '%s  %s\n' "$CURRENT_HASH" "$2" ;;
    */infra-monitor/firewall-read) printf '%s  %s\n' "$LEGACY_HASH" "$2" ;;
    *) return 1 ;;
  esac
}
fixture_sudo() {
  [ "$#" = 3 ] && [ "$1" = -n ] && [ "$2" = -- ] || exit 2
  printf '%s\n' "$3"
  exit
}
`
			paths := strings.NewReplacer(
				"/var/lib", "$FIXTURE/state",
				"/usr/local/libexec", "$FIXTURE/lib",
				"/etc/sudoers.d", "$FIXTURE/sudoers",
				"/usr/bin/stat", "fixture_stat",
				"/usr/bin/sha256sum", "fixture_sha256sum",
				"exec sudo", "fixture_sudo",
			)
			run := func(script string) (string, error) {
				cmd := exec.Command("/bin/sh", "-c", stubTools+paths.Replace(script))
				cmd.Env = append(os.Environ(), "FIXTURE="+root, "CURRENT_HASH="+currentHash, "LEGACY_HASH="+legacyHash)
				output, err := cmd.CombinedOutput()
				return strings.TrimSpace(string(output)), err
			}
			if status, err := run(inspectFirewallCommand); err != nil || status != test.wantStatus {
				t.Fatalf("inspect = %q, %v; want %q", status, err, test.wantStatus)
			}
			output, err := run(firewallCommand)
			if test.wantHelper == "" {
				if err == nil || output != "" {
					t.Fatalf("ambiguous read = %q, %v", output, err)
				}
				return
			}
			if want := filepath.Join(root, "lib", test.wantHelper, "firewall-read"); err != nil || output != want {
				t.Fatalf("reader = %q, %v; want %q", output, err, want)
			}
		})
	}
}

func TestDetectFirewallDiscoversExistingReaderVersionWithoutReadingRules(t *testing.T) {
	digest := strings.Repeat("a", 64)
	var reads atomic.Int32
	cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
		switch command {
		case hostProbeCommand:
		case locale + "id -u":
			_, _ = io.WriteString(channel, "1000\n")
		case locale + "sudo -n -- id -u":
			return 1
		case "/usr/bin/uname -m":
			_, _ = io.WriteString(channel, "aarch64\n")
		case inspectFirewallCommand:
			_, _ = io.WriteString(channel, "installed "+digest+"\n")
		case firewallCommand:
			reads.Add(1)
			return 1
		default:
			t.Errorf("unexpected command during read-only detection: %q", command)
			return 1
		}
		return 0
	})
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	identity := ssh.FingerprintSHA256(key)
	result, err := DetectFirewall(t.Context(), cfg, identity)
	if err != nil || result.Status != "installed" || result.Version != digest || result.Architecture != "arm64" || result.MarkersAbsent {
		t.Fatalf("discovery = %+v, %v", result, err)
	}
	if got := reads.Load(); got != 0 {
		t.Fatalf("discovery attempted %d rule reads", got)
	}
	result, err = MaintainFirewall(t.Context(), cfg, nil, identity, "verify", nil)
	if Code(err) != "firewall_unreadable" || result.Status != "unknown" || reads.Load() != 1 {
		t.Fatalf("verification of unreadable rules = %+v, %v; reads = %d", result, err, reads.Load())
	}
}

func TestFirewallUninstallRequiresAuthoritativeAbsence(t *testing.T) {
	var empty atomic.Bool
	cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
		switch {
		case command == hostProbeCommand:
		case command == "sudo -n -- /usr/bin/id -u":
			_, _ = io.WriteString(channel, "0\n")
		case strings.HasPrefix(command, "imon_payload | sudo -n -- /bin/sh -c ") && strings.Contains(command, "uninstall --collector demo"):
			if empty.Load() {
				_, _ = io.WriteString(channel, "uninstalled\n")
			}
		default:
			t.Errorf("unexpected command during removal: %q", command)
			return 1
		}
		return 0
	})
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	adminKey := filepath.Join(t.TempDir(), "admin-key")
	private, err := os.ReadFile(cfg.SSH.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminKey, private, 0600); err != nil {
		t.Fatal(err)
	}
	admin := &Config{SSH: Endpoint{User: "fixture-admin", KeyFile: adminKey}}
	script := []byte("#!/bin/sh\n# synthetic package\n")
	result, err := MaintainFirewall(t.Context(), cfg, admin, ssh.FingerprintSHA256(key), "uninstall", script)
	if Code(err) != "result_unconfirmed" || result.Status != "unknown" || result.MarkersAbsent {
		t.Fatalf("no removal proof = %+v, %v", result, err)
	}
	empty.Store(true)
	result, err = MaintainFirewall(t.Context(), cfg, admin, ssh.FingerprintSHA256(key), "uninstall", script)
	if err != nil || result.Status != "verified" || !result.MarkersAbsent {
		t.Fatalf("verified absence = %+v, %v", result, err)
	}
}
