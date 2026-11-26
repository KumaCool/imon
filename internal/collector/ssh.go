package collector

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxSSHOutput     = 4 << 20
	hostProbeCommand = "LC_ALL=C; export LC_ALL; test -d /run/systemd/system && test -r /proc/stat"
	sshShellCommand  = "/bin/sh -s"
)

type sshConnection struct {
	client      *ssh.Client
	jump        *ssh.Client
	fingerprint string
	endpointKey string
	jumpKey     string
}

func openSSH(ctx context.Context, cfg Config, learnKeys bool, expectedIdentity string) (*sshConnection, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s := &sshConnection{}
	var dial func(context.Context, string, string) (net.Conn, error) = (&net.Dialer{}).DialContext
	var err error
	if cfg.Jump != nil {
		s.jump, s.jumpKey, _, err = dialSSH(ctx, *cfg.Jump, dial, "jump", learnKeys, "")
		if err != nil {
			return nil, err
		}
		dial = s.jump.DialContext
	}
	s.client, s.endpointKey, s.fingerprint, err = dialSSH(ctx, cfg.SSH, dial, "target", learnKeys, expectedIdentity)
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func dialSSH(ctx context.Context, ep Endpoint, dial func(context.Context, string, string) (net.Conn, error), role string, learnKeys bool, expectedIdentity string) (*ssh.Client, string, string, error) {
	if ep.Port == 0 {
		ep.Port = 22
	}
	if ep.Port < 1 || ep.Port > 65535 || ep.Address == "" || strings.ContainsAny(ep.Address, " \t\r\n/[]") || ep.User == "" || ep.KeyFile == "" {
		return nil, "", "", fail("invalid_ssh_config")
	}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(ep.Port))
	checkHostKey, hostKeyAlgs, err := sshHostTrust(addr, ep.HostKey, role, learnKeys)
	if err != nil {
		return nil, "", "", err
	}
	keyPath := ep.KeyFile
	if relative, ok := strings.CutPrefix(keyPath, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", "", fail("credential_unreadable")
		}
		keyPath = filepath.Join(home, relative)
	}
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, "", "", fail("credential_unreadable")
	}
	defer keyFile.Close()
	info, err := keyFile.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return nil, "", "", fail("credential_unreadable")
	}
	private, err := io.ReadAll(io.LimitReader(keyFile, (256<<10)+1))
	if err != nil || len(private) > 256<<10 {
		return nil, "", "", fail("credential_unreadable")
	}
	signer, err := ssh.ParsePrivateKey(private)
	clear(private)
	if err != nil {
		var encrypted *ssh.PassphraseMissingError
		if errors.As(err, &encrypted) {
			return nil, "", "", fail("credential_passphrase_required")
		}
		return nil, "", "", fail("credential_invalid")
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() == nil && (errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)) {
			return nil, "", "", fail("ssh_network_unreachable")
		}
		return nil, "", "", networkError(ctx, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	var hostKeyErr error
	var key ssh.PublicKey
	var firstKey sync.Once
	session, channels, requests, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              ep.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyAlgorithms: hostKeyAlgs,
		HostKeyCallback: func(hostname string, remote net.Addr, presented ssh.PublicKey) error {
			firstKey.Do(func() {
				if expectedIdentity != "" && ssh.FingerprintSHA256(presented) != expectedIdentity {
					hostKeyErr = fail("identity_changed")
				} else {
					hostKeyErr = checkHostKey(hostname, remote, presented)
				}
				key = presented
			})
			if !bytes.Equal(key.Marshal(), presented.Marshal()) {
				return fail("identity_changed")
			}
			return hostKeyErr
		},
	})
	stop()
	if ctx.Err() != nil {
		_ = conn.Close()
		return nil, "", "", ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		if hostKeyErr != nil {
			return nil, "", "", hostKeyErr
		}
		var negotiation *ssh.AlgorithmNegotiationError
		if (ep.HostKey != "" || expectedIdentity != "") && errors.As(err, &negotiation) && negotiation.What == "host key" {
			return nil, "", "", fail("identity_changed")
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, "", "", fail("authentication_failed")
		}
		return nil, "", "", networkError(ctx, err)
	}
	return ssh.NewClient(session, channels, requests), string(ssh.MarshalAuthorizedKey(key)), ssh.FingerprintSHA256(key), nil
}

func networkError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return fail("dns_failed")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fail("timeout")
	}
	return fail("connection_failed")
}

func (s *sshConnection) close() {
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.jump != nil {
		_ = s.jump.Close()
	}
}

type boundedSSHOutput struct {
	sync.Mutex
	remaining int
	exceeded  chan struct{}
}

type sshOutputWriter struct {
	limit *boundedSSHOutput
	buf   bytes.Buffer
}

func (w *sshOutputWriter) Write(p []byte) (int, error) {
	w.limit.Lock()
	defer w.limit.Unlock()
	if len(p) > w.limit.remaining {
		if w.limit.remaining > 0 {
			_, _ = w.buf.Write(p[:w.limit.remaining])
			w.limit.remaining = 0
		}
		select {
		case <-w.limit.exceeded:
		default:
			close(w.limit.exceeded)
		}
		return len(p), nil
	}
	w.limit.remaining -= len(p)
	return w.buf.Write(p)
}

func (s *sshConnection) run(ctx context.Context, command string) ([]byte, error) {
	return s.runLimited(ctx, command, maxSSHOutput)
}

func (s *sshConnection) runLimited(ctx context.Context, command string, maximum int) ([]byte, error) {
	return s.runInput(ctx, command, maximum, nil)
}

const sshPayloadStart = "imon_payload() {\n/usr/bin/base64 -d <<'IMON_PAYLOAD'\n"
const sshPayloadEnd = "IMON_PAYLOAD\n}\n"

func sshScriptInput(command string, input []byte) io.Reader {
	if len(input) == 0 {
		return strings.NewReader(command + "\n")
	}
	// Shells can buffer source from stdin. A quoted here-document keeps the
	// payload separate from shell syntax without relying on unread pipe bytes.
	var script bytes.Buffer
	script.Grow(len(sshPayloadStart) + base64.StdEncoding.EncodedLen(len(input)) + (len(input)+56)/57 + len(sshPayloadEnd) + len(command) + 1)
	script.WriteString(sshPayloadStart)
	var line [76]byte
	for len(input) > 0 {
		size := min(len(input), 57)
		out := line[:base64.StdEncoding.EncodedLen(size)]
		base64.StdEncoding.Encode(out, input[:size])
		script.Write(out)
		script.WriteByte('\n')
		input = input[size:]
	}
	script.WriteString(sshPayloadEnd)
	script.WriteString(command)
	script.WriteByte('\n')
	return &script
}

func (s *sshConnection) runInput(ctx context.Context, command string, maximum int, input []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	sessionReady := make(chan *ssh.Session, 1)
	openFailed := make(chan error, 1)
	go func() {
		session, err := s.client.NewSession()
		if err != nil {
			openFailed <- err
		} else {
			sessionReady <- session
		}
	}()
	var session *ssh.Session
	select {
	case session = <-sessionReady:
	case <-openFailed:
		return nil, fail("ssh_session_failed")
	case <-ctx.Done():
		s.close()
		return nil, ctx.Err()
	}
	defer session.Close()
	limit := &boundedSSHOutput{remaining: maximum, exceeded: make(chan struct{})}
	stdout := &sshOutputWriter{limit: limit}
	stderr := &sshOutputWriter{limit: limit}
	session.Stdout, session.Stderr = stdout, stderr
	session.Stdin = sshScriptInput(command, input)
	done := make(chan error, 1)
	go func() { done <- session.Run(sshShellCommand) }()
	select {
	case <-ctx.Done():
		s.close()
		return nil, ctx.Err()
	case <-limit.exceeded:
		s.close()
		return nil, fail("output_limit")
	case err := <-done:
		select {
		case <-limit.exceeded:
			return nil, fail("output_limit")
		default:
		}
		if err != nil {
			var exit *ssh.ExitError
			if errors.As(err, &exit) {
				switch exit.ExitStatus() {
				case 126:
					return nil, fail("permission_denied")
				case 127:
					return nil, fail("command_unavailable")
				}
				message := bytes.ToLower(stderr.buf.Bytes())
				if bytes.Contains(message, []byte("permission denied")) ||
					(command == systemdInventoryCommand && bytes.Contains(message, []byte("access denied"))) {
					return nil, fail("permission_denied")
				}
				return nil, fail("command_failed")
			}
			return nil, fail("ssh_session_failed")
		}
		return stdout.buf.Bytes(), nil
	}
}
