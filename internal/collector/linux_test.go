package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSystemdInventorySingleChannel(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
		code string
	}{
		{name: "units", want: 66},
		{name: "empty"},
		{name: "denied", code: "permission_denied"},
		{name: "access-denied", code: "permission_denied"},
		{name: "bad-response", code: "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat("/bin/sh"); err != nil {
				t.Skip("requires a POSIX shell")
			}
			path := t.TempDir()
			if err := os.WriteFile(filepath.Join(path, "systemctl"), []byte(fakeInventorySystemctl), 0700); err != nil {
				t.Fatal(err)
			}
			var channels atomic.Int32
			cfg := sshFixture(t, func(script string, _ io.Reader, pipe ssh.Channel) int {
				if script == hostProbeCommand {
					return 0
				}
				channels.Add(1)
				cmd := exec.Command("/bin/sh", "-s")
				cmd.Env = append(os.Environ(), "PATH="+path+string(os.PathListSeparator)+os.Getenv("PATH"), "INVENTORY_FIXTURE="+tc.name)
				cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(script), pipe, pipe.Stderr()
				if err := cmd.Run(); err != nil {
					if exit, ok := err.(*exec.ExitError); ok {
						return exit.ExitCode()
					}
					t.Errorf("run inventory: %v", err)
					return 1
				}
				return 0
			})
			rows, err := Collect(context.Background(), "host", cfg, "", "systemd")
			if len(rows) != tc.want || Code(err) != tc.code || channels.Load() != 1 {
				t.Fatalf("inventory: got %d rows, %v, %d channels; want %d rows, %q, 1 channel", len(rows), err, channels.Load(), tc.want, tc.code)
			}
			if tc.name == "units" {
				var first unitStatus
				if err := json.Unmarshal(rows[0].Data, &first); err != nil || first.CPUUsageNSec == nil || *first.CPUUsageNSec != 2000000000 ||
					first.MemoryBytes == nil || *first.MemoryBytes != 0 || first.CPUPercent != nil {
					t.Fatalf("initial resource sample: %+v, %v", first, err)
				}
				for _, key := range []string{`mounted\x2dpath.service`, "sample@node.service", "unit-64.service"} {
					var found bool
					for _, row := range rows {
						if row.Key == key {
							found = true
							if !strings.Contains(string(row.Data), `"state":"running"`) {
								t.Errorf("missing projected state for %s: %s", key, row.Data)
							}
						}
					}
					if !found {
						t.Errorf("missing %s", key)
					}
				}
			}
		})
	}
}

func TestNativeFirewallRequiresReadableBackendAndUsesLegacyBinaries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		uid        string
		sudoRoot   bool
		nftSuccess bool
		wantNative bool
	}{
		{name: "no readable backend", uid: "0"},
		{name: "restricted sudo", uid: "1000", sudoRoot: true},
		{name: "nft readable", uid: "0", nftSuccess: true, wantNative: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
				switch command {
				case hostProbeCommand:
					return 0
				case locale + "id -u":
					_, _ = io.WriteString(channel, tc.uid+"\n")
					return 0
				case locale + "sudo -n -- id -u":
					if tc.sudoRoot {
						_, _ = io.WriteString(channel, "0\n")
						return 0
					}
					return 1
				case locale + "sudo -n -- ufw status verbose", locale + "sudo -n -- nft -j list ruleset",
					locale + "sudo -n -- iptables-legacy-save", locale + "sudo -n -- ip6tables-legacy-save":
					return 126
				case locale + "ufw status verbose", locale + "nft -j list ruleset", locale + "iptables-legacy-save", locale + "ip6tables-legacy-save":
					if command == locale+"nft -j list ruleset" && tc.nftSuccess {
						_, _ = io.WriteString(channel, `{"nftables":[]}`)
						return 0
					}
					return 127
				default:
					t.Errorf("unexpected command %q", command)
					return 1
				}
			})
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
			if err != nil {
				t.Fatal(err)
			}
			session, err := Open(t.Context(), "host", cfg, ssh.FingerprintSHA256(key))
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			rows, native, err := session.ssh.nativeFirewall(t.Context())
			if err != nil || native != tc.wantNative {
				t.Fatalf("native firewall probe = %v, %v; want native=%v", native, err, tc.wantNative)
			}
			if !tc.wantNative {
				if rows != nil {
					t.Fatalf("unreadable probe returned rows: %+v", rows)
				}
				return
			}
			var gotNFT, gotLegacy bool
			for _, item := range rows {
				if item.Key == "nftables" && strings.Contains(string(item.Data), `"status":"ok"`) {
					gotNFT = true
				}
				if item.Key == "iptables-legacy" {
					gotLegacy = true
				}
			}
			if !gotNFT || !gotLegacy {
				t.Fatalf("missing readable nftables or explicit legacy result: %+v", rows)
			}
		})
	}
}

const fakeInventorySystemctl = `#!/bin/sh
case "$*" in
  *list-unit-files*)
    case "$INVENTORY_FIXTURE" in
      empty) exit 0;;
      denied) printf '%s\n' 'Failed to connect to bus: Permission denied' >&2; exit 1;;
      access-denied) printf '%s\n' 'Failed to list unit files: Access denied' >&2; exit 1;;
    esac
    i=1
    while [ "$i" -le 64 ]; do
      printf 'unit-%02d.service enabled preset\n' "$i"
      i=$((i + 1))
    done
    printf '%s\n' 'sample@.service disabled preset' 'not-a-service.socket enabled preset' '-option.service enabled preset' 'mounted\x2dpath.service disabled preset';;
  *list-units*)
    [ "$INVENTORY_FIXTURE" = empty ] && exit 0
    printf '%s\n' 'unit-01.service loaded active running' 'sample@node.service loaded active running';;
  *show*)
    case "$*" in *' -p CPUUsageNSec -p MemoryCurrent -- '*) ;; *) exit 2;; esac
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
    [ "$#" -gt 0 ] || exit 2
    shift
    [ "$#" -gt 0 ] && [ "$#" -le 64 ] || exit 2
    [ "$INVENTORY_FIXTURE" = bad-response ] && exit 0
    for unit in "$@"; do
      printf 'Id=%s\nLoadState=loaded\nActiveState=active\nSubState=running\nInvocationID=fixture\nCPUUsageNSec=2000000000\nMemoryCurrent=0\n\n' "$unit"
    done;;
  *) exit 2;;
esac`

func TestSystemdResourceDeltasAndMissingValues(t *testing.T) {
	parse := func(cpu, memory, invocation string, at int64) unitStatus {
		t.Helper()
		items, err := parseUnits(fmt.Appendf(nil, "Id=sample.service\nLoadState=loaded\nActiveState=active\nInvocationID=%s\nCPUUsageNSec=%s\nMemoryCurrent=%s\n", invocation, cpu, memory))
		if err != nil {
			t.Fatal(err)
		}
		item := items["sample.service"]
		item.SampledAt = at
		return item
	}
	previous := parse("1000000000", "[not set]", "first", 1000)
	current := parse("6000000000", "1024", "first", 3000)
	if cpu := systemdCPU(current, previous); cpu == nil || *cpu != 250 {
		t.Fatalf("expected 250%% CPU, got %v", cpu)
	}
	if previous.MemoryBytes != nil || current.MemoryBytes == nil || *current.MemoryBytes != 1024 {
		t.Fatalf("unexpected memory fields: %+v / %+v", previous, current)
	}
	for _, next := range []unitStatus{
		parse("6000000000", "1024", "second", 3000), // Restarted invocation.
		parse("10", "1024", "first", 3000),          // Reset counter.
		parse("infinity", "0", "first", 3000),
		parse("18446744073709551615", "0", "first", 3000),
		parse("invalid", "0", "first", 3000),
		parse("6000000000", "0", "first", 999),
	} {
		if cpu := systemdCPU(next, previous); cpu != nil {
			t.Fatalf("invalid baseline yielded %v for %+v", *cpu, next)
		}
	}
}

func TestSystemdEscapedUnitNamesRemainActionable(t *testing.T) {
	for _, name := range []string{"demo.service", "mounted\\x2dpath.service", "scope:worker.service", "demo@node.service"} {
		if !ValidSystemdServiceUnit(name) {
			t.Errorf("valid systemd unit %q was rejected", name)
		}
	}
	for _, name := range []string{"demo@.service", "-invalid.service", "bad unit.service", `bad\z1name.service`} {
		if ValidSystemdServiceUnit(name) {
			t.Errorf("invalid systemd unit %q was accepted", name)
		}
	}
}

func TestLinuxMetricsDeltaAndReset(t *testing.T) {
	previousAt := time.Unix(600, 0)
	raw := func(boot string, index int, user, idle, rx, tx uint64) []byte {
		return []byte(fmt.Sprintf("%s\ncpu %d 0 0 %d 0 0 0 0 999 999\nMemTotal: 1000 kB\nMemAvailable: 420 kB\nInter-| Receive | Transmit\neth0: %d 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0\n[{\"ifindex\":%d,\"ifname\":\"eth0\"}]\n", boot, user, idle, rx, tx, index))
	}
	prev, err := parseRawMetrics(raw("boot-a", 2, 100, 100, 0, 0), previousAt)
	if err != nil {
		t.Fatal(err)
	}
	samples := sampleBaselines(prev)
	next, err := parseRawMetrics(raw("boot-a", 2, 340, 860, 60*1024*1024, 24*1024*1024), previousAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := metricsRows(next, samples, 2*time.Minute, []byte("Filesystem Type 1B-blocks Used Avail Mounted on\n /dev/example ext4 1000 920 80 /\n"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		key   string
		value float64
	}{
		"cpu":      {"cpu_percent", 24},
		"disk:/":   {"disk_percent", 92},
		"memory":   {"memory_percent", 58},
		"nic:eth0": {"rx_bytes_per_second", 1048576},
	}
	for _, r := range rows {
		arg, ok := cases[r.Key]
		if !ok {
			t.Fatalf("unexpected %q", r.Key)
		}
		var values map[string]any
		if err := json.Unmarshal(r.Data, &values); err != nil {
			t.Fatal(err)
		}
		if got := values[arg.key]; got != arg.value {
			t.Errorf("%s = %v, want %v", r.Key, got, arg.value)
		}
		delete(cases, r.Key)
	}
	if len(cases) != 0 {
		t.Errorf("missing rows: %v", cases)
	}
	changed, err := parseRawMetrics(raw("boot-b", 3, 341, 861, 60*1024*1024, 24*1024*1024), previousAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := percentCPU(changed, samples["cpu"], 2*time.Minute); got != nil {
		t.Fatal("CPU reused an old boot")
	}
	changed.BootID = prev.BootID
	if rx, tx := speedNIC(changed, changed.NICs["eth0"], samples["nic:eth0"], 2*time.Minute); rx != nil || tx != nil {
		t.Fatal("rate reused an old interface")
	}
}

func TestLinuxDiskKeepsSharedFilesystemMounts(t *testing.T) {
	disks := []byte("Filesystem Type 1B-blocks Used Avail Mounted on\n" +
		"/dev/example root btrfs 1000 500 450 /\n" +
		"/dev/example root btrfs 1000 500 450 /home\n" +
		"/dev/example ext4 2000 1000 900 /srv/example data\n")
	rows, err := parseDisks(disks)
	if err != nil || len(rows) != 3 {
		t.Fatalf("parseDisks: %d rows, %v", len(rows), err)
	}
	for i, want := range []struct{ mountpoint, shared string }{
		{"/", "/dev/example root"},
		{"/home", "/dev/example root"},
		{"/srv/example data", ""},
	} {
		var got struct {
			Mountpoint       string `json:"mountpoint"`
			SharedFilesystem string `json:"shared_filesystem"`
		}
		if err := json.Unmarshal(rows[i].Data, &got); err != nil {
			t.Fatal(err)
		}
		if rows[i].Key != "disk:"+want.mountpoint || got.Mountpoint != want.mountpoint || got.SharedFilesystem != want.shared {
			t.Errorf("row %d: %q %+v, want %+v", i, rows[i].Key, got, want)
		}
	}
}

func TestLinuxNetworkAndUnitProjection(t *testing.T) {
	for _, tc := range []struct{ input, family, address, process string }{
		{"LISTEN 0 128 192.0.2.10:8080 0.0.0.0:*", "ipv4", "192.0.2.10", "unreadable"},
		{"LISTEN 0 128 [::]:8080 [::]:* users:((\"demo\",pid=5,fd=7))", "ipv6", "::", "ok"},
	} {
		items, err := parseListeners([]byte(tc.input), "tcp", tc.family)
		if err != nil || len(items) != 1 || items[0].Port != 8080 || items[0].Address != tc.address || items[0].ProcessState != tc.process {
			t.Fatalf("listener = %#v, %v", items, err)
		}
	}
	netstat, err := parseNetstatListeners([]byte("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      12/demo\ntcp6       0      0 :::8443                :::*                    LISTEN      -\nudp        0      0 0.0.0.0:5353            0.0.0.0:*                           9/dns\n"))
	if err != nil || len(netstat) != 3 {
		t.Fatalf("netstat listeners = %#v, %v", netstat, err)
	}
	if netstat[0].Protocol != "tcp" || netstat[0].Family != "ipv4" || netstat[0].Address != "127.0.0.1" || netstat[0].Port != 8080 || netstat[0].ProcessState != "ok" {
		t.Fatalf("unexpected tcp netstat listener: %#v", netstat[0])
	}
	if netstat[1].Family != "ipv6" || netstat[1].Address != "::" || netstat[1].Port != 8443 || netstat[1].ProcessState != "unreadable" {
		t.Fatalf("unexpected tcp6 netstat listener: %#v", netstat[1])
	}
	routes, err := parseRoutes([]byte("[{\"dst\":\"default\",\"table\":123,\"nexthops\":[{\"gateway\":\"192.0.2.1\",\"dev\":\"eth0\"}]}]"), "ipv4")
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes = %v, %v", routes, err)
	}
	var route map[string]any
	if err := json.Unmarshal(routes[0].Data, &route); err != nil {
		t.Fatal(err)
	}
	if route["table"] != float64(123) || len(route["next_hops"].([]any)) != 1 {
		t.Fatalf("bad route: %v", route)
	}

	items, err := parseUnits([]byte("Id=demo.service\nLoadState=loaded\nActiveState=active\nSubState=running\n\nId=bad.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\n"))
	if err != nil || len(items) != 2 || *items["demo.service"].State != "running" || *items["bad.service"].State != "failed" {
		t.Fatalf("units = %v, %v", items, err)
	}
}

func TestListenersFallBackToNetstatWhenSSIsMissing(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "ss"), []byte("#!/bin/sh\nexit 127\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "netstat"), []byte("#!/bin/sh\nprintf '%s\\n' 'Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name' 'tcp 0 0 127.0.0.1:8080 0.0.0.0:* LISTEN 12/demo' 'udp6 0 0 :::5353 :::* -/-'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := sshFixture(t, func(script string, _ io.Reader, channel ssh.Channel) int {
		if script == hostProbeCommand {
			return 0
		}
		cmd := exec.Command("/bin/sh", "-s")
		cmd.Env = append(os.Environ(), "PATH="+path+string(os.PathListSeparator)+os.Getenv("PATH"))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(script), channel, channel.Stderr()
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Errorf("run listener collection: %v", err)
			return 1
		}
		return 0
	})
	rows, err := Collect(context.Background(), "host", cfg, "", "listeners")
	if err != nil || len(rows) != 2 {
		t.Fatalf("netstat fallback: got %d rows, %v", len(rows), err)
	}
	var first, second listenRecord
	if err := json.Unmarshal(rows[0].Data, &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rows[1].Data, &second); err != nil {
		t.Fatal(err)
	}
	if first.Protocol != "tcp" || first.Address != "127.0.0.1" || first.Port != 8080 || first.Process != "12/demo" {
		t.Fatalf("unexpected first listener: %+v", first)
	}
	if second.Protocol != "udp" || second.Family != "ipv6" || second.Address != "::" || second.Port != 5353 {
		t.Fatalf("unexpected second listener: %+v", second)
	}
}

func TestParseListenersAcceptsSSNetidColumn(t *testing.T) {
	items, err := parseListeners([]byte("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"+
		"tcp LISTEN 0 128 192.0.2.10:8080 0.0.0.0:* users:((\"demo\",pid=5,fd=7))\n"), "tcp", "ipv4")
	if err != nil || len(items) != 1 {
		t.Fatalf("parse netid ss row: %#v, %v", items, err)
	}
	item := items[0]
	if item.Protocol != "tcp" || item.Family != "ipv4" || item.Address != "192.0.2.10" || item.Port != 8080 || item.Process == "" || item.ProcessState != "ok" {
		t.Fatalf("unexpected netid ss listener: %+v", item)
	}

	items, err = parseListeners([]byte("udp6 UNCONN 0 0 :::5353 :::* users:((\"dns\",pid=9,fd=3))\n"), "udp", "ipv6")
	if err != nil || len(items) != 1 {
		t.Fatalf("parse netid udp6 row: %#v, %v", items, err)
	}
	item = items[0]
	if item.Protocol != "udp" || item.Family != "ipv6" || item.Address != "::" || item.Port != 5353 {
		t.Fatalf("unexpected netid udp6 listener: %+v", item)
	}
}

func TestParseListenersInfersFamilyForAggregateSSOutput(t *testing.T) {
	items, err := parseListeners([]byte(
		"LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"+
			"LISTEN 0 128 [::]:8443 [::]:*\n"), "tcp", "")
	if err != nil || len(items) != 2 {
		t.Fatalf("aggregate ss listeners: %#v, %v", items, err)
	}
	if items[0].Family != "ipv4" || items[0].Address != "0.0.0.0" || items[0].Port != 8080 {
		t.Fatalf("unexpected IPv4 aggregate listener: %+v", items[0])
	}
	if items[1].Family != "ipv6" || items[1].Address != "::" || items[1].Port != 8443 {
		t.Fatalf("unexpected IPv6 aggregate listener: %+v", items[1])
	}
}

func TestParseListenersKeepsValidRowsWhenOneLineIsMalformed(t *testing.T) {
	items, err := parseListeners([]byte(
		"LISTEN 0 128 malformed 0.0.0.0:*\n"+
			"LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n"), "tcp", "ipv4")
	if err != nil || len(items) != 1 {
		t.Fatalf("tolerant ss parsing: %#v, %v", items, err)
	}
	if items[0].Address != "127.0.0.1" || items[0].Port != 8080 {
		t.Fatalf("unexpected listener: %+v", items[0])
	}
}

func TestParseListenersKeepsRowsWithoutProcessMetadata(t *testing.T) {
	for _, tc := range []struct {
		input, protocol, family, address string
		port                             uint16
	}{
		{"LISTEN 0 511 192.0.2.10%eth0:18080 0.0.0.0:*", "tcp", "ipv4", "192.0.2.10%eth0", 18080},
		{"LISTEN 0 4096 [2001:db8::10]%eth0:443 [::]:*", "tcp", "ipv6", "2001:db8::10%eth0", 443},
		{"UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*", "udp", "ipv4", "0.0.0.0", 5353},
		{"UNCONN 0 0 [::]:5353 [::]:*", "udp", "ipv6", "::", 5353},
	} {
		items, err := parseListeners([]byte(tc.input), tc.protocol, tc.family)
		if err != nil || len(items) != 1 {
			t.Fatalf("parse listener without process metadata: %#v, %v", items, err)
		}
		item := items[0]
		if item.Protocol != tc.protocol || item.Family != tc.family || item.Address != tc.address || item.Port != tc.port {
			t.Errorf("listener = %+v, want %s/%s %s:%d", item, tc.protocol, tc.family, tc.address, tc.port)
		}
		if item.Process != "" || item.ProcessState != "unreadable" {
			t.Errorf("listener should retain the port and report missing process metadata: %+v", item)
		}
	}
}

func TestParseListenersAcceptsLinuxSSOutputWithScopedAddresses(t *testing.T) {
	data := []byte("LISTEN 0      511 192.0.2.10%eth0:18080 0.0.0.0:*\n" +
		"LISTEN 0      2048 127.0.0.1:35633 0.0.0.0:* users:((\"demo\",pid=18082,fd=44))\n")
	items, err := parseListeners(data, "tcp", "ipv4")
	if err != nil || len(items) != 2 {
		t.Fatalf("parse Linux ss output: %#v, %v", items, err)
	}
	if items[0].Address != "192.0.2.10%eth0" || items[0].Port != 18080 || items[0].ProcessState != "unreadable" {
		t.Errorf("scoped listener should remain visible without process metadata: %+v", items[0])
	}
	if items[1].Address != "127.0.0.1" || items[1].Port != 35633 || items[1].ProcessState != "ok" || !strings.Contains(items[1].Process, "demo") {
		t.Errorf("listener with process metadata parsed incorrectly: %+v", items[1])
	}
}

func TestParseListenersAcceptsScopedIPv6SSAddresses(t *testing.T) {
	for _, local := range []string{
		"[2001:db8::1234]%if0:443",
		"[2001:db8::1234%if0]:443",
	} {
		items, err := parseListeners([]byte("LISTEN 0 4096 "+local+" [::]:*\n"), "tcp", "ipv6")
		if err != nil || len(items) != 1 {
			t.Fatalf("parse scoped IPv6 listener %q: %#v, %v", local, items, err)
		}
		item := items[0]
		if item.Protocol != "tcp" || item.Family != "ipv6" || item.Address != "2001:db8::1234%if0" || item.Port != 443 {
			t.Fatalf("unexpected scoped IPv6 listener for %q: %+v", local, item)
		}
	}
}

func TestListenersKeepSuccessfulSSRowsWhenOneFamilyFails(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "ss"), []byte("#!/bin/sh\ncase \"$*\" in\n  *\"-t -p -4\"*) printf '%s\\n' 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"demo\",pid=5,fd=7))';;\n  *\"-6\"*) exit 1;;\n  *\"-t -p\"*) exit 1;;\n  *) exit 0;;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "netstat"), []byte("#!/bin/sh\nprintf '%s\\n' 'Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name' 'udp 0 0 0.0.0.0:5353 0.0.0.0:* 9/dns'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := sshFixture(t, func(script string, _ io.Reader, channel ssh.Channel) int {
		if script == hostProbeCommand {
			return 0
		}
		cmd := exec.Command("/bin/sh", "-s")
		cmd.Env = append(os.Environ(), "PATH="+path+string(os.PathListSeparator)+os.Getenv("PATH"))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(script), channel, channel.Stderr()
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Errorf("run partial listener collection: %v", err)
			return 1
		}
		return 0
	})
	rows, err := Collect(context.Background(), "host", cfg, "", "listeners")
	if err != nil || len(rows) != 2 {
		t.Fatalf("partial ss fallback: got %d rows, %v", len(rows), err)
	}
	var first, second listenRecord
	if err := json.Unmarshal(rows[0].Data, &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rows[1].Data, &second); err != nil {
		t.Fatal(err)
	}
	if first.Protocol != "tcp" || first.Port != 8080 || first.Process != `users:(("demo",pid=5,fd=7))` {
		t.Fatalf("unexpected ss listener: %+v", first)
	}
	if second.Protocol != "udp" || second.Port != 5353 || second.Process != "9/dns" {
		t.Fatalf("unexpected netstat listener: %+v", second)
	}
}

func TestListenersDoNotPublishPartialSSRowsWhenFallbackIsUnavailable(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "ss"), []byte("#!/bin/sh\ncase \"$*\" in\n  *\"-t -p -4\"*) printf '%s\\n' 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"demo\",pid=5,fd=7))';;\n  *) exit 1;;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "netstat"), []byte("#!/bin/sh\nexit 127\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := sshFixture(t, func(script string, _ io.Reader, channel ssh.Channel) int {
		if script == hostProbeCommand {
			return 0
		}
		cmd := exec.Command("/bin/sh", "-s")
		cmd.Env = append(os.Environ(), "PATH="+path+string(os.PathListSeparator)+os.Getenv("PATH"))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(script), channel, channel.Stderr()
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Errorf("run incomplete listener collection: %v", err)
			return 1
		}
		return 0
	})
	rows, err := Collect(context.Background(), "host", cfg, "", "listeners")
	if err == nil || Code(err) != "command_unavailable" || rows != nil {
		t.Fatalf("incomplete listener snapshot: got %d rows, %v; want command_unavailable and no rows", len(rows), err)
	}
}

func TestListenersEnrichOnlyExactExistingEndpoints(t *testing.T) {
	cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
		switch command {
		case hostProbeCommand:
			return 0
		case locale + "ss -H -l -n -t -p -4":
			_, _ = io.WriteString(channel, "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8081 0.0.0.0:*\n")
		case locale + "ss -H -l -n -t -p -6", locale + "ss -H -l -n -u -p -4", locale + "ss -H -l -n -u -p -6":
		case portsHelperCommand:
			_ = json.NewEncoder(channel).Encode(map[string]string{
				"ss_ipv4": "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"web\",pid=20,fd=3))\n" +
					"udp UNCONN 0 0 127.0.0.1:8081 0.0.0.0:* users:((\"udp\",pid=21,fd=4))\n" +
					"tcp LISTEN 0 128 127.0.0.1:8082 0.0.0.0:* users:((\"other\",pid=22,fd=4))\n",
			})
		default:
			t.Errorf("unexpected command: %q", command)
			return 1
		}
		return 0
	})
	rows, err := Collect(t.Context(), "host", cfg, "", "listeners")
	if err != nil || len(rows) != 2 {
		t.Fatalf("listeners = %v, %v", rows, err)
	}
	for i, r := range rows {
		var listener listenRecord
		if err := json.Unmarshal(r.Data, &listener); err != nil {
			t.Fatal(err)
		}
		if i == 0 && (listener.Port != 8080 || listener.ProcessState != "ok" || !strings.Contains(listener.Process, "pid=20")) {
			t.Fatalf("new process owner = %+v", listener)
		}
		if i == 1 && (listener.Port != 8081 || listener.ProcessState != "unreadable" || listener.Process != "") {
			t.Fatalf("unmatched listener = %+v", listener)
		}
	}
}
