package collector

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestUpdateFirewallUsesOnlyInstalledHelperAndRequiresReadback(t *testing.T) {
	oldVersion, newVersion := strings.Repeat("a", 64), strings.Repeat("b", 64)
	pkg := []byte("fixture-only update package\x00\xff")
	for _, test := range []struct {
		name, observed, current, update, readback, status, code string
		calls                                                   int32
	}{
		{name: "first install", observed: "markers-absent", code: "helper_update_not_installed"},
		{name: "old authorization", current: "imon:helper-legacy", code: FirewallMigrationRequired},
		{name: "broken new authorization", current: "imon:helper-exit 5", code: "helper_update_host_state"},
		{name: "already current", current: "installed " + newVersion, status: "verified"},
		{name: "verified update", update: "installed " + newVersion, readback: "installed " + newVersion, status: "verified", calls: 1},
		{name: "tampered update", update: "imon:helper-exit 2", code: "helper_update_invalid", calls: 1},
		{name: "different architecture", update: "imon:helper-exit 3", code: "helper_update_architecture", calls: 1},
		{name: "older release", update: "imon:helper-exit 4", code: "helper_update_stale", calls: 1},
		{name: "already applied by another panel", update: "imon:helper-exit 4", readback: "installed " + newVersion, status: "verified", calls: 1},
		{name: "interrupted transaction", update: "imon:helper-exit 5", status: "unknown", code: "helper_update_host_state", calls: 1},
		{name: "remote update is unconfirmed", update: "installed " + newVersion, status: "unknown", code: "result_unconfirmed", calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var updates atomic.Int32
			cfg := sshFixture(t, func(command string, input io.Reader, channel ssh.Channel) int {
				var output string
				switch command {
				case hostProbeCommand:
				case inspectFirewallCommand:
					output = test.observed
					if output == "" {
						output = "installed " + oldVersion
					}
				case helperVersionCommand:
					output = test.current
					if updates.Load() != 0 {
						output = test.readback
					}
					if output == "" {
						output = "installed " + oldVersion
					}
				case helperUpdateCommand:
					updates.Add(1)
					payload, err := io.ReadAll(input)
					if err != nil || !bytes.Equal(payload, pkg) {
						t.Errorf("signed update payload = %q, %v", payload, err)
					}
					output = test.update
				default:
					t.Errorf("unexpected SSH operation %q", command)
					return 1
				}
				if output != "" {
					_, _ = io.WriteString(channel, output+"\n")
				}
				return 0
			})
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
			if err != nil {
				t.Fatal(err)
			}
			result, err := UpdateFirewall(t.Context(), cfg, ssh.FingerprintSHA256(key), "amd64", newVersion, pkg)
			if Code(err) != test.code || result.Status != test.status || result.Architecture != "amd64" || updates.Load() != test.calls {
				t.Fatalf("result=%+v err=%v calls=%d", result, err, updates.Load())
			}
			if test.status == "verified" && result.Version != newVersion {
				t.Fatalf("confirmed version %q; want %q", result.Version, newVersion)
			}
			var previousVersion string
			if test.code == FirewallMigrationRequired {
				previousVersion = oldVersion
			}
			if result.PreviousVersion != previousVersion {
				t.Fatalf("previous version %q; want %q", result.PreviousVersion, previousVersion)
			}
		})
	}
}

func TestHelperVersionRecognizesRestrictedAndAdministrativeLegacyAccounts(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires a POSIX shell")
	}
	const sudoFixture = `sudo() {
  case "$*" in
    '-n -- /usr/local/libexec/imon/firewall-read version')
      case "$FIXTURE" in
        signed) printf 'installed %s\n' "$VERSION" ;;
        broken) return 5 ;;
        password-required) printf 'sudo: a password is required\n' >&2; return 1 ;;
        *) return 1 ;;
      esac ;;
    '-n -- /usr/local/libexec/imon/firewall-read')
      case "$FIXTURE" in restricted|admin|password-required|broken) return 0;; *) return 1;; esac ;;
    '-n -l -- /usr/local/libexec/imon/firewall-read')
      [ "$FIXTURE" != denied ] ;;
    '-n -l -- /usr/local/libexec/imon/firewall-read update')
      [ "$FIXTURE" != restricted ] ;;
    '-n -- /bin/sh -c /usr/bin/id -u')
      [ "$FIXTURE" = admin ] || return 1
      printf '0\n' ;;
    *) return 2 ;;
  esac
}
`
	for _, test := range []struct{ fixture, expect string }{
		{"signed", "installed " + strings.Repeat("a", 64)},
		{"broken", "imon:helper-exit 5"},
		{"restricted", "imon:helper-legacy"},
		{"admin", "imon:helper-legacy"},
		{"password-required", "imon:helper-legacy"},
		{"denied", "imon:helper-exit 1"},
		{"update-only", "imon:helper-exit 1"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			script := sudoFixture + strings.Replace(helperVersionCommand, helperPathCommand, "helper=/usr/local/libexec/imon/firewall-read", 1)
			cmd := exec.Command("/bin/sh", "-c", script)
			cmd.Env = append(os.Environ(), "FIXTURE="+test.fixture, "VERSION="+strings.Repeat("a", 64))
			got, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(got)) != test.expect {
				t.Fatalf("version probe = %q, %v; want %q", got, err, test.expect)
			}
		})
	}
}

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
		case command == autoMaintenanceProbe:
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

func TestSelfUninstallFirewallRequiresHelperConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, output, status, code string
		exit                       int
	}{
		{name: "removed", output: "uninstalled", status: "uninstalled"},
		{name: "old or denied", output: "imon:helper-exit 1", code: FirewallAdministratorRequired},
		{name: "helper failure", output: "imon:helper-exit 5", status: "unknown", code: "result_unconfirmed"},
		{name: "no confirmation", status: "unknown", code: "result_unconfirmed"},
		{name: "unexpected confirmation", output: "uninstalled\nextra output", status: "unknown", code: "result_unconfirmed"},
		{name: "command failure after output", output: "uninstalled", status: "unknown", code: "command_failed", exit: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
				switch command {
				case hostProbeCommand:
					return 0
				case helperUninstallCommand:
					calls.Add(1)
					if tc.output != "" {
						_, _ = io.WriteString(channel, tc.output+"\n")
					}
					return tc.exit
				default:
					t.Errorf("unexpected command during self-uninstall: %q", command)
					return 1
				}
			})
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
			if err != nil {
				t.Fatal(err)
			}
			result, err := UninstallFirewall(t.Context(), cfg, ssh.FingerprintSHA256(key))
			if Code(err) != tc.code || result.Status != tc.status || result.MarkersAbsent != (tc.status == "uninstalled") || calls.Load() != 1 {
				t.Fatalf("self-uninstall result=%+v err=%v calls=%d", result, err, calls.Load())
			}
		})
	}
}

func TestAutomaticMaintenanceVerifiesInstalledUnitDigest(t *testing.T) {
	const script = "#!/bin/sh\n# synthetic package\n"
	digest := strings.Repeat("a", 64)
	var installed atomic.Bool
	cfg := sshFixture(t, func(command string, input io.Reader, channel ssh.Channel) int {
		switch {
		case command == hostProbeCommand:
		case command == autoMaintenanceProbe:
			_, _ = io.WriteString(channel, "0\n")
		case strings.HasPrefix(command, "imon_payload | sudo -n -- /bin/sh -c ") && strings.Contains(command, "install --collector demo"):
			staged, err := io.ReadAll(input)
			if err != nil || string(staged) != script {
				t.Errorf("embedded script = %q, %v", staged, err)
			}
			installed.Store(true)
			_, _ = io.WriteString(channel, "installed "+digest+"\n")
		case command == locale+"id -u":
			_, _ = io.WriteString(channel, "1000\n")
		case command == locale+"sudo -n -- id -u":
			return 126
		case command == firewallCommand:
			_, _ = io.WriteString(channel, `{"results":[{"backend":"nftables","status":"not_installed"}]}`)
		default:
			t.Errorf("unexpected automatic command %q", command)
			return 1
		}
		return 0
	})
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	result, err := MaintainFirewall(t.Context(), cfg, nil, ssh.FingerprintSHA256(key), "install", []byte(script))
	if err != nil || !installed.Load() || result.Status != "verified" || result.Version != digest || result.StagedPath != "" {
		t.Fatalf("automatic installation result = %+v, %v", result, err)
	}
}
