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
