package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Endpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	KeyFile string `json:"key_file"`
	HostKey string `json:"host_key,omitempty"`
}

type Config struct {
	SSH            Endpoint  `json:"ssh"`
	Jump           *Endpoint `json:"jump,omitempty"`
	Kubeconfig     string    `json:"kubeconfig"`
	Context        string    `json:"context"`
	KubeExecSHA256 string    `json:"kube_exec_sha256,omitempty"`
}

type Row struct {
	Key  string
	Data json.RawMessage
}

type Options struct {
	Manual    bool
	MaxWindow time.Duration
	Previous  []Row
	// SampledAt is used for resources whose values are derived from two
	// consecutive observations (for example systemd CPU usage).
	SampledAt time.Time
}

type Error struct {
	Code string
}

func (e *Error) Error() string { return e.Code }

func fail(code string) error { return &Error{Code: code} }

func Code(err error) string {
	var typed *Error
	var confirmation *HostKeyConfirmation
	switch {
	case err == nil:
		return ""
	case errors.As(err, &typed):
		return typed.Code
	case errors.As(err, &confirmation):
		return confirmation.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "read_failed"
	}
}

func row(key string, value any) (Row, error) {
	if key == "" {
		return Row{}, fail("invalid_response")
	}
	encoded, err := json.Marshal(value)
	return Row{Key: key, Data: encoded}, err
}

func appendRow(rows []Row, key string, value any) ([]Row, error) {
	item, err := row(key, value)
	if err != nil {
		return nil, err
	}
	return append(rows, item), nil
}

func Groups(kind string) []string {
	switch kind {
	case "host", "linux":
		return []string{"host_metrics", "os_info", "systemd", "interfaces", "routes", "listeners", "firewall"}
	case "kubernetes", "cluster":
		return []string{"namespaces", "deployments", "pods", "services", "nodes"}
	default:
		return nil
	}
}

type Session struct {
	ssh      *sshConnection
	kube     *kubeConnection
	identity string
}

func Open(ctx context.Context, kind string, cfg Config, expectedIdentity string) (*Session, error) {
	return open(ctx, kind, cfg, expectedIdentity, false)
}

func open(ctx context.Context, kind string, cfg Config, expectedIdentity string, learnKeys bool) (*Session, error) {
	s := &Session{}
	var err error
	switch kind {
	case "host", "linux":
		s.ssh, err = openSSH(ctx, cfg, learnKeys, expectedIdentity)
		if err == nil {
			s.identity = s.ssh.fingerprint
			if expectedIdentity != "" && expectedIdentity != s.identity {
				err = fail("identity_changed")
			} else {
				probeCtx, cancel := context.WithTimeout(ctx, requestTimeout)
				_, err = s.ssh.run(probeCtx, hostProbeCommand)
				cancel()
			}
		}
	case "kubernetes", "cluster":
		s.kube, err = openKube(ctx, cfg)
		if err == nil {
			if learnKeys {
				s.identity, err = s.kube.probe(ctx, expectedIdentity)
			} else {
				s.identity, err = s.kube.identity(ctx, expectedIdentity)
			}
		}
	default:
		err = fail("invalid_kind")
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) Identity() string { return s.identity }

func (s *Session) Close() {
	if s.ssh != nil {
		s.ssh.close()
	}
	if s.kube != nil {
		s.kube.client.CloseIdleConnections()
	}
}

func Probe(ctx context.Context, kind string, cfg Config) (string, []string, error) {
	identity, warnings, _, err := ProbeBinding(ctx, kind, cfg, "")
	return identity, warnings, err
}

// ProbeBinding checks the connection and returns the configuration to persist.
// Runtime collection uses Open and requires pins that were saved by this test.
func ProbeBinding(ctx context.Context, kind string, cfg Config, expectedIdentity string) (string, []string, Config, error) {
	s, err := open(ctx, kind, cfg, expectedIdentity, true)
	if err != nil {
		return "", nil, cfg, err
	}
	defer s.Close()
	var warnings []string
	if s.ssh != nil {
		if cfg.SSH.HostKey == "" {
			cfg.SSH.HostKey = s.ssh.endpointKey
		}
		if cfg.Jump != nil && cfg.Jump.HostKey == "" {
			jump := *cfg.Jump
			jump.HostKey = s.ssh.jumpKey
			cfg.Jump = &jump
		}
		if _, err := s.ssh.firewall(ctx); err != nil {
			warnings = append(warnings, "firewall_unreadable")
		}
	} else {
		warnings = s.kube.warnings(ctx)
	}
	return s.Identity(), warnings, cfg, nil
}

func Collect(ctx context.Context, kind string, cfg Config, identity, group string) ([]Row, error) {
	s, err := Open(ctx, kind, cfg, identity)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Collect(ctx, group)
}

func (s *Session) Collect(ctx context.Context, group string) ([]Row, error) {
	return s.CollectWithOptions(ctx, group, Options{})
}

func (s *Session) CollectWithOptions(ctx context.Context, group string, opts Options) ([]Row, error) {
	if s.ssh != nil {
		timeout := 10 * time.Second
		if group == "systemd" {
			// systemctl may need to read properties for hundreds of unit files.
			timeout = 30 * time.Second
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return s.ssh.collect(ctx, group, opts)
	}
	if s.kube != nil {
		return s.kube.collect(ctx, group, opts)
	}
	return nil, fmt.Errorf("collector session has no connection")
}
