// Command linux-smoke exercises disposable infrastructure fixtures.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"imon/internal/collector"
	"imon/internal/firewall"
)

func checked(err error, operation string) {
	if err != nil {
		log.Fatalf("%s: %v", operation, err)
	}
}

func expect(ok bool, message string) {
	if !ok {
		log.Fatal(message)
	}
}

func writeFixture(kind, arch string) {
	var data []byte
	var err error
	switch kind {
	case "script":
		data, err = firewall.Script(arch)
	case "update":
		data, err = firewall.UpdatePackage(arch)
	default:
		log.Fatal("unknown fixture type")
	}
	checked(err, "generate "+kind)
	_, err = os.Stdout.Write(data)
	checked(err, "write "+kind)
}

func main() {
	if len(os.Args) == 3 {
		writeFixture(os.Args[1], os.Args[2])
		return
	}
	expect(len(os.Args) == 1, "usage: host-smoke [script|update ARCH]")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	checked(err, "read fixture host key")
	collection := collector.Config{SSH: collector.Endpoint{
		Address: "127.0.0.1", Port: 22444, User: "fixture_reader", KeyFile: "/tmp/fixture_reader", HostKey: string(key),
	}}
	operation := collection
	operation.SSH.User = "fixture_operator"
	operation.SSH.KeyFile = "/tmp/fixture_operator"
	identity, warnings, err := collector.Probe(ctx, "host", collection)
	checked(err, "SSH connection test")
	expect(len(warnings) == 1 && warnings[0] == "firewall_unreadable", "unprivileged probe did not report unreadable firewall")
	session, err := collector.Open(ctx, "host", collection, identity)
	checked(err, "connect Linux collector")
	defer session.Close()
	rows, err := session.Collect(ctx, "systemd")
	checked(err, "collect systemd")
	matched := false
	for _, item := range rows {
		if item.Key == "imon-fixture.service" && strings.Contains(string(item.Data), `"state":"running"`) {
			matched = true
		}
	}
	expect(matched, "running fixture service not found")
	rows, err = session.Collect(ctx, "os_info")
	checked(err, "collect Linux OS release")
	expect(len(rows) == 1 && rows[0].Key == "os", "expected one OS release row")
	var release struct {
		DisplayName string `json:"display_name"`
	}
	checked(json.Unmarshal(rows[0].Data, &release), "decode Linux OS release")
	expect(release.DisplayName == "Debian GNU/Linux 12 (bookworm)", "unexpected fixture OS release")
	for _, group := range []string{"host_metrics", "interfaces", "routes", "listeners"} {
		_, err := session.Collect(ctx, group)
		checked(err, "collect "+group)
	}
	listenerProcess := func() string {
		rows, err := session.Collect(ctx, "listeners")
		checked(err, "read fixture SSH listener")
		for _, row := range rows {
			if row.Key == "tcp|ipv4|127.0.0.1|22444" {
				var listener struct{ Process string }
				checked(json.Unmarshal(row.Data, &listener), "decode listener owner")
				return listener.Process
			}
		}
		log.Fatal("fixture SSH listener missing")
		return ""
	}
	expect(listenerProcess() == "", "unprivileged collection unexpectedly shows fixture SSH listener owner")
	fmt.Println("SSH probe and OS release, systemd, performance, interface, route and listener collection passed")
	checkActions := func(config collector.Config) {
		for _, pair := range [][2]string{{"stop", "running"}, {"start", "stopped"}} {
			recorded := false
			result, err := collector.RunServiceAction(ctx, "host", config, identity, collector.ActionRequest{
				Action: pair[0], ExpectedState: pair[1], Key: "imon-fixture.service", Name: "imon-fixture.service",
			}, func(int32) error { recorded = true; return nil })
			checked(err, "authorized systemd "+pair[0])
			expect(recorded && result.Sent && result.Confirmed, "systemd operation lacks readback")
		}
	}
	checkActions(operation)
	fmt.Println("Authorized SSH stop and start confirmed by systemd readback")

	arch, err := collector.FirewallPlatform(ctx, collection, identity)
	checked(err, "detect firewall bundle platform")
	legacy, err := os.ReadFile("/fixture/legacy-install.sh")
	checked(err, "read legacy firewall installation")
	migration, err := os.ReadFile("/fixture/migration-install.sh")
	checked(err, "read signed firewall installation")
	script, err := firewall.Script(arch)
	checked(err, "read embedded firewall bundle")
	update, err := firewall.UpdatePackage(arch)
	checked(err, "read signed firewall update")
	targetDigest, err := firewall.Version(arch)
	checked(err, "read embedded firewall digest")
	check := func(action, status string, admin *collector.Config, script []byte) {
		result, err := collector.MaintainFirewall(ctx, collection, admin, identity, action, script)
		checked(err, "firewall "+action)
		expect(result.Status == status, "unexpected firewall verification status: "+result.Status)
	}
	check("verify", "uninstalled", &operation, legacy)
	stage := func(action, verifyBefore string, port int, script []byte) {
		config := collection
		config.SSH.Port = port
		automatic, err := collector.MaintainFirewall(ctx, config, nil, identity, action, script)
		expect(collector.Code(err) == collector.FirewallAdministratorRequired && automatic.StagedPath == "", "automatic attempt staged a package without explicit upload selection")
		result, err := collector.StageFirewall(ctx, config, identity, action, script)
		checked(err, "stage firewall over SSH")
		expect(result.Status == "awaiting_admin", "script did not enter awaiting-admin state")
		digest := sha256.Sum256(script)
		expect(result.SHA256 == hex.EncodeToString(digest[:]), "script checksum does not match")
		dir, err := os.Stat(filepath.Dir(result.StagedPath))
		checked(err, "stat upload directory")
		file, err := os.Stat(result.StagedPath)
		checked(err, "stat script")
		expect(dir.Mode().Perm() == 0700 && file.Mode().Perm() == 0600, "staged script does not have private permissions")
		command := collector.FirewallAdminCommand(action, config.SSH.User, result.StagedPath, result.SHA256)
		expect(command != "", "missing administrator command")
		check("verify", verifyBefore, &operation, script)
		cmd := exec.CommandContext(ctx, "runuser", "-u", "fixture_operator", "--", "/bin/sh")
		cmd.Stdin = strings.NewReader(command + "\n")
		cmd.Stderr = os.Stderr
		checked(cmd.Run(), "run admin command for staged package")
		checked(collector.CleanFirewallStage(ctx, config, identity, result.StagedPath), "clean staged script")
		_, err = os.Stat(filepath.Dir(result.StagedPath))
		expect(os.IsNotExist(err), "staging directory still exists after cleanup")
	}
	for _, layout := range []string{"imon", "infra-monitor"} {
		fmt.Printf("Testing %s helper layout\n", layout)
		stage("install", "uninstalled", 22444, legacy)
		check("verify", "installed", &operation, legacy)
		check("install", "verified", &operation, legacy)
		expect(strings.Contains(listenerProcess(), "sshd"), "authorized port reader missing the fixture SSH process")
		checkActions(collection)
		fmt.Println("Host helper associated the SSH port with sshd and confirmed systemd stop and start with one authorization")

		// Emulate the previous package's sudoers file, paths, and per-service grants.
		lib := "/usr/local/libexec/" + layout
		state := "/var/lib/" + layout
		sudoers := "/etc/sudoers.d/" + layout + "-firewall"
		if layout == "infra-monitor" {
			checked(os.Rename("/usr/local/libexec/imon", lib), "recreate historical helper directory")
			checked(os.Rename("/var/lib/imon", state), "recreate historical state directory")
			checked(os.Rename("/etc/sudoers.d/imon-firewall", sudoers), "recreate historical sudoers file")
		}
		helper := filepath.Join(lib, "firewall-read")
		rules := fmt.Sprintf("fixture_reader ALL=(root) NOPASSWD: NOSETENV: %[1]s \"\", %[1]s ports, %[1]s grants, %[1]s service\n", helper)
		checked(os.WriteFile(sudoers, []byte(rules), 0440), "recreate old sudoers entry")
		units := filepath.Join(state, "service-units")
		checked(os.WriteFile(units, []byte("different.service\n"), 0600), "recreate legacy unit grants")
		removal, err := collector.UninstallFirewall(ctx, collection, identity)
		expect(collector.Code(err) == collector.FirewallAdministratorRequired && removal.Status == "",
			"legacy authorization did not require administrator removal")
		_, err = collector.UpdateFirewall(ctx, collection, identity, arch, targetDigest, update)
		expect(collector.Code(err) == collector.FirewallMigrationRequired, "legacy helper did not request migration: "+collector.Code(err))
		stage("install", "installed", 22444, migration)
		_, err = os.Stat(units)
		expect(os.IsNotExist(err), "legacy systemd grants remained after helper update")
		check("verify", "installed", &operation, migration)
		checkActions(collection)
		fmt.Println("Legacy helper required one administrator migration and removed obsolete per-service grants")

		installedDigest := func() string {
			result, err := collector.DetectFirewall(ctx, collection, identity)
			checked(err, "discover installed firewall digest")
			expect(result.Status == "installed", "firewall helper is missing after update attempt")
			return result.Version
		}
		before := installedDigest()
		expect(before != targetDigest, "fixture release binaries must have distinct digests")
		checkLayout := func(expected string) {
			executable, err := os.ReadFile(helper)
			checked(err, "read installed helper from original layout")
			digest := sha256.Sum256(executable)
			expect(hex.EncodeToString(digest[:]) == expected, "unexpected digest in original layout")
		}
		checkLayout(before)
		tampered := bytes.Clone(update)
		tampered[len(tampered)-1] ^= 1
		_, err = collector.UpdateFirewall(ctx, collection, identity, arch, targetDigest, tampered)
		expect(collector.Code(err) == "helper_update_invalid" && installedDigest() == before,
			"tampered package did not preserve the previous helper: "+collector.Code(err))
		fmt.Println("Tampered update rejected and previous helper digest preserved")
		result, err := collector.UpdateFirewall(ctx, collection, identity, arch, targetDigest, update)
		checked(err, "update from restricted SSH account")
		expect(result.Status == "verified" && result.Version == targetDigest && installedDigest() == targetDigest,
			"signed update returned a different helper digest")
		checkLayout(targetDigest)
		fmt.Println("Restricted SSH account installed and verified the signed update")
		previous, err := os.ReadFile("/fixture/previous-update")
		checked(err, "read previous signed firewall update")
		_, err = collector.UpdateFirewall(ctx, collection, identity, arch, before, previous)
		expect(collector.Code(err) == "helper_update_stale" && installedDigest() == targetDigest,
			"previous release was not rejected: "+collector.Code(err))
		expect(strings.Contains(listenerProcess(), "sshd"), "updated helper lost privileged listener collection")
		checkActions(collection)
		fmt.Println("Downgrade rejected and updated helper still reads port processes and controls systemd services")

		rows, err = session.Collect(ctx, "firewall")
		checked(err, "collect firewall rules")
		expect(len(rows) == 3, "missing firewall backends")
		for _, item := range rows {
			var data struct {
				Status  string          `json:"status"`
				Payload json.RawMessage `json:"payload"`
			}
			checked(json.Unmarshal(item.Data, &data), "decode firewall backend")
			expect(data.Status == "ok", "firewall backend failed: "+item.Key)
			switch item.Key {
			case "ufw":
				expect(strings.Contains(string(data.Payload), "18721"), "missing UFW rule")
			case "nftables":
				expect(strings.Contains(string(data.Payload), "18722"), "missing nftables rule")
			case "iptables-legacy":
				var families map[string]struct {
					Status  string `json:"status"`
					Payload string `json:"payload"`
				}
				checked(json.Unmarshal(data.Payload, &families), "decode legacy families")
				for family, port := range map[string]string{"ipv4": "18723", "ipv6": "18724"} {
					expect(families[family].Status == "ok" && strings.Contains(families[family].Payload, port), "missing legacy rule: "+family)
				}
			default:
				log.Fatalf("unexpected firewall backend: %s", item.Key)
			}
		}
		fmt.Println("UFW, nftables and iptables-legacy IPv4/IPv6 rules collected")
		// The collector has no blanket sudo rule. Only the exact Imon
		// uninstall command should run without administrator credentials.
		removal, err = collector.UninstallFirewall(ctx, collection, identity)
		checked(err, "uninstall as the restricted SSH account")
		expect(removal.Status == "uninstalled" && removal.MarkersAbsent, "helper did not confirm uninstallation")
		check("verify", "uninstalled", &operation, script)
		check("uninstall", "verified", &operation, script)
		fmt.Println("Restricted SSH account removed the authorization and verified cleanup")
		if layout == "imon" {
			check("install", "verified", &operation, legacy)
			stage("uninstall", "installed", 22445, script)
			check("verify", "uninstalled", &operation, script)
		}
		_, err = session.Collect(ctx, "firewall")
		expect(collector.Code(err) == "firewall_unreadable", "ordinary firewall read remains available after uninstall")
		expect(listenerProcess() == "", "privileged socket owner visible after helper removal")
		for _, path := range []string{lib, state, sudoers} {
			_, err := os.Lstat(path)
			expect(os.IsNotExist(err), "helper path remained after uninstall: "+path)
		}
		fmt.Println("SFTP upload, SSH stream fallback, explicit /bin/sh manual commands, idempotent maintenance and administrator verification passed")
	}
}
