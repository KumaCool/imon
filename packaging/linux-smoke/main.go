// Command linux-smoke exercises disposable infrastructure fixtures.
package main

import (
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

func main() {
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
	fmt.Println("SSH probe and OS release, systemd, performance, interface, route and listener collection passed")
	for _, pair := range [][2]string{{"stop", "running"}, {"start", "stopped"}} {
		recorded := false
		result, err := collector.RunServiceAction(ctx, "host", operation, identity, collector.ActionRequest{
			Action: pair[0], ExpectedState: pair[1], Key: "imon-fixture.service", Name: "imon-fixture.service",
		}, func(int32) error { recorded = true; return nil })
		checked(err, "authorized systemd "+pair[0])
		expect(recorded && result.Sent && result.Confirmed, "systemd operation lacks readback")
	}
	fmt.Println("Authorized SSH stop and start confirmed by systemd readback")

	arch, err := collector.FirewallPlatform(ctx, collection, identity)
	checked(err, "detect firewall bundle platform")
	script, err := firewall.Script(arch)
	checked(err, "read embedded firewall bundle")
	check := func(action, status string, admin *collector.Config) {
		result, err := collector.MaintainFirewall(ctx, collection, admin, identity, action, script)
		checked(err, "firewall "+action)
		expect(result.Status == status, "unexpected firewall verification status: "+result.Status)
	}
	check("verify", "uninstalled", &operation)
	stage := func(action string, port int) {
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
		verifyBefore := "uninstalled"
		if action == "uninstall" {
			verifyBefore = "installed"
		}
		check("verify", verifyBefore, &operation)
		cmd := exec.CommandContext(ctx, "runuser", "-u", "fixture_operator", "--", "/bin/sh")
		cmd.Stdin = strings.NewReader(command + "\n")
		cmd.Stderr = os.Stderr
		checked(cmd.Run(), "run admin command for staged package")
		checked(collector.CleanFirewallStage(ctx, config, identity, result.StagedPath), "clean staged script")
		_, err = os.Stat(filepath.Dir(result.StagedPath))
		expect(os.IsNotExist(err), "staging directory still exists after cleanup")
	}
	stage("install", 22444)
	check("verify", "installed", &operation)
	check("install", "verified", &operation)
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
	stage("uninstall", 22445)
	check("verify", "uninstalled", &operation)
	check("uninstall", "verified", &operation)
	_, err = session.Collect(ctx, "firewall")
	expect(collector.Code(err) == "firewall_unreadable", "ordinary firewall read remains available after uninstall")
	fmt.Println("SFTP upload, SSH stream fallback, explicit /bin/sh manual commands, idempotent maintenance and administrator verification passed")
}
