package collector

import (
	"context"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRunUnitActionShellQuotesEscapedUnitName(t *testing.T) {
	const unit = `mounted\x2dpath.service`
	var commands []string
	activeState := "inactive"
	cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
		commands = append(commands, command)
		switch {
		case command == hostProbeCommand:
			return 0
		case strings.Contains(command, "systemctl --no-pager show"):
			subState := "dead"
			if activeState == "active" {
				subState = "running"
			}
			_, _ = io.WriteString(channel, "Id="+unit+"\nLoadState=loaded\nActiveState="+activeState+"\nSubState="+subState+"\nInvocationID=fixture\nCPUUsageNSec=0\nMemoryCurrent=0\n\n")
			return 0
		case strings.Contains(command, "systemctl start"):
			if !strings.Contains(command, "-- '"+unit+"'") {
				t.Errorf("systemd action did not shell-quote escaped unit: %q", command)
			}
			activeState = "active"
			return 0
		default:
			t.Fatalf("unexpected command: %q", command)
			return 1
		}
	})
	probe, err := openSSH(context.Background(), cfg, false, "")
	if err != nil {
		t.Fatal(err)
	}
	identity := probe.fingerprint
	probe.close()
	result, err := RunServiceAction(context.Background(), "host", cfg, identity, ActionRequest{
		Action: "start", Key: unit, Name: unit, ExpectedState: "stopped",
	}, func(int32) error { return nil })
	if err != nil || !result.Sent || !result.Confirmed || result.State != "running" {
		t.Fatalf("unit action = %+v, %v", result, err)
	}
	if len(commands) != 4 {
		t.Fatalf("commands = %d, want probe/read/write/read", len(commands))
	}
}

func TestRunUnitActionHelperReceivesOnlyExactActionAndUnit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exit     int
		wantCode string
		wantSent bool
	}{
		{"granted", 0, "", true},
		{"legacy helper requires upgrade", 80, "service_helper_upgrade_required", false},
		{"not run", 81, "service_action_not_run", false},
		{"result unknown", 82, "command_failed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const unit = "example.service"
			var stopped bool
			cfg := sshFixture(t, func(command string, input io.Reader, channel ssh.Channel) int {
				switch {
				case command == hostProbeCommand:
					return 0
				case strings.Contains(command, "systemctl --no-pager show"):
					if stopped {
						_, _ = io.WriteString(channel, "Id="+unit+"\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n")
					} else {
						_, _ = io.WriteString(channel, "Id="+unit+"\nLoadState=loaded\nActiveState=active\nSubState=running\n")
					}
					return 0
				case strings.HasSuffix(command, `sudo -n -- "$helper" service`):
					payload, err := io.ReadAll(input)
					if err != nil || string(payload) != "stop\n"+unit+"\n" {
						t.Errorf("helper arguments = %q, %v", payload, err)
					}
					if tc.exit == 0 {
						stopped = true
					}
					return tc.exit
				default:
					t.Errorf("unexpected command: %q", command)
					return 1
				}
			})
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
			if err != nil {
				t.Fatal(err)
			}
			result, err := RunServiceAction(t.Context(), "host", cfg, ssh.FingerprintSHA256(key), ActionRequest{
				Action: "stop", Key: unit, Name: unit, ExpectedState: "running",
			}, func(int32) error { return nil })
			if Code(err) != tc.wantCode || result.Sent != tc.wantSent || result.Confirmed != (tc.exit == 0) {
				t.Fatalf("action = %+v, %v", result, err)
			}
		})
	}
}
