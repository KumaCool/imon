package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSSHUnreachableRouteClassification(t *testing.T) {
	cfg := sshFixture(t, func(string, io.Reader, ssh.Channel) int { return 0 })
	dial := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}
	}
	_, _, _, err := dialSSH(context.Background(), cfg.SSH, dial, "target", false, "")
	if got := Code(err); got != "ssh_network_unreachable" {
		t.Fatalf("SSH unreachable route: got %s, want ssh_network_unreachable", got)
	}
}

func sshFixture(t *testing.T, handler func(string, io.Reader, ssh.Channel) int, sftpHandler ...sftp.Handlers) Config {
	return sshFixtureWithAuth(t, handler, nil, sftpHandler...)
}

func sshFixtureWithAuth(t *testing.T, handler func(string, io.Reader, ssh.Channel) int, onAuth func(), sftpHandler ...sftp.Handlers) Config {
	t.Helper()
	return sshWireFixture(t, func(wire string, channel ssh.Channel) int {
		if wire != "/bin/sh -s" {
			t.Errorf("unexpected SSH exec request: %q", wire)
			return 127
		}
		script, err := io.ReadAll(channel)
		if err != nil {
			t.Errorf("read SSH script: %v", err)
			return 1
		}
		code := string(script)
		var input io.Reader = strings.NewReader("")
		if body, ok := strings.CutPrefix(code, sshPayloadStart); ok {
			encoded, command, ok := strings.Cut(body, sshPayloadEnd)
			if !ok {
				t.Error("missing SSH payload delimiter")
				return 1
			}
			code = command
			input = base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
		}
		return handler(strings.TrimSuffix(code, "\n"), input, channel)
	}, onAuth, sftpHandler...)
}

func sshWireFixture(t *testing.T, handler func(string, ssh.Channel) int, onAuth func(), sftpHandler ...sftp.Handlers) Config {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, userPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(userPrivate)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test-key")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if onAuth != nil {
			onAuth()
		}
		if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(userSigner.PublicKey()) {
			return nil, &ssh.ExitMissingError{}
		}
		return &ssh.Permissions{}, nil
	}}
	server.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				s, channels, requests, err := ssh.NewServerConn(conn, server)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer s.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for r := range requests {
							if r.Type == "subsystem" && len(sftpHandler) != 0 {
								var request struct{ Name string }
								if ssh.Unmarshal(r.Payload, &request) == nil && request.Name == "sftp" {
									_ = r.Reply(true, nil)
									sftpServer := sftp.NewRequestServer(channel, sftpHandler[0])
									defer sftpServer.Close()
									_ = sftpServer.Serve()
									return
								}
							}
							if r.Type != "exec" {
								_ = r.Reply(false, nil)
								continue
							}
							var request struct{ Command string }
							if ssh.Unmarshal(r.Payload, &request) != nil {
								_ = r.Reply(false, nil)
								return
							}
							_ = r.Reply(true, nil)
							code := handler(request.Command, channel)
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
							return
						}
					}()
				}
			}()
		}
	}()
	addr, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return Config{SSH: Endpoint{Address: addr, Port: n, User: "demo", KeyFile: path, HostKey: string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))}}
}

func TestSSHCommandsViaPOSIXShell(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "fish", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			path, err := exec.LookPath(shell)
			if err != nil {
				t.Skipf("%s unavailable", shell)
			}
			if _, err := os.Stat("/bin/sh"); err != nil {
				t.Skip("/bin/sh unavailable")
			}
			cfg := sshWireFixture(t, func(command string, channel ssh.Channel) int {
				if command != "/bin/sh -s" {
					t.Errorf("unexpected SSH exec request: %q", command)
					return 127
				}
				cmd := exec.CommandContext(t.Context(), path, "-c", command)
				cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, channel.Stderr()
				if err := cmd.Run(); err != nil {
					var exit *exec.ExitError
					if errors.As(err, &exit) {
						return exit.ExitCode()
					}
					t.Errorf("running fixture shell: %v", err)
					return 1
				}
				return 0
			}, nil)
			s, err := openSSH(t.Context(), cfg, false, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()

			const input = `stdin: \ ' "$HOME" ; &` + "\n"
			const literal = `literal: \\ \'' " $HOME ; $(false) ending \`
			const script = `LC_ALL=C; export LC_ALL; IFS= read -r line; printf '%s\n' "$LC_ALL" "$line" `
			command := "imon_payload | (" + script + shellQuote(literal) + ")"
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if out, err := s.run(ctx, "printf '%s\\n' "+shellQuote(literal)); err != nil || string(out) != literal+"\n" {
				t.Fatalf("SSH script output = %q, %v", out, err)
			}
			out, err := s.runInput(ctx, command, 1024, []byte(input))
			if want := "C\n" + input + literal + "\n"; err != nil || string(out) != want {
				t.Fatalf("SSH input/output = %q, %v; want %q", out, err, want)
			}
			raw := bytes.Repeat([]byte{0, 255, '\'', '\\', '\n'}, 20000)
			out, err = s.runInput(ctx, "imon_payload | /bin/cat", len(raw), raw)
			if err != nil || !bytes.Equal(out, raw) {
				t.Fatalf("SSH binary pass-through: got %d bytes, want %d identical bytes; error %v", len(out), len(raw), err)
			}
			if _, err = s.run(ctx, "exit 127"); Code(err) != "command_unavailable" {
				t.Fatalf("exit status mapped to %v; want command_unavailable", err)
			}
		})
	}
}

func TestSSHBindingTrust(t *testing.T) {
	var auth atomic.Int32
	cfg := sshFixtureWithAuth(t, func(string, io.Reader, ssh.Channel) int { return 0 }, func() { auth.Add(1) })
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort(cfg.SSH.Address, strconv.Itoa(cfg.SSH.Port))
	cfg.SSH.HostKey = ""
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "known_hosts")
	write := func(line string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(line+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(t.Context(), "host", cfg, ""); Code(err) != "invalid_host_key" || auth.Load() != 0 {
		t.Fatalf("runtime accepted unpinned binding: %v, auth calls=%d", err, auth.Load())
	}
	_, _, _, err = ProbeBinding(t.Context(), "host", cfg, "")
	var unknown *HostKeyConfirmation
	if !errors.As(err, &unknown) || unknown.Role != "target" || unknown.Address != addr || unknown.Fingerprint != ssh.FingerprintSHA256(key) || auth.Load() != 0 {
		t.Fatalf("unknown key did not stop before authentication: %v, auth calls=%d", err, auth.Load())
	}
	cfg.SSH.HostKey = unknown.Key
	identity, _, resolved, err := ProbeBinding(t.Context(), "host", cfg, "")
	if err != nil || identity != unknown.Fingerprint || resolved.SSH.HostKey != unknown.Key || auth.Load() == 0 {
		t.Fatalf("confirmed key did not permit authentication: %v, auth calls=%d", err, auth.Load())
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("confirming a binding must not write known_hosts")
	}
	cfg.SSH.HostKey = ""
	write(knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(addr))}, key))
	identity, _, resolved, err = ProbeBinding(t.Context(), "host", cfg, "")
	if err != nil || identity != unknown.Fingerprint || resolved.SSH.HostKey != unknown.Key {
		t.Fatalf("known hashed key did not permit authentication: %v", err)
	}
	before := auth.Load()
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ssh.NewPublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	write(knownhosts.Line([]string{addr}, otherKey))
	if _, _, _, err := ProbeBinding(t.Context(), "host", cfg, ""); Code(err) != "identity_changed" || auth.Load() != before {
		t.Fatalf("known_hosts mismatch did not stop before authentication: %v", err)
	}
	write("@revoked " + knownhosts.Line([]string{addr}, key))
	if _, _, _, err := ProbeBinding(t.Context(), "host", cfg, ""); Code(err) != "host_key_untrusted" || auth.Load() != before {
		t.Fatalf("revoked key did not stop before authentication: %v", err)
	}
	write("invalid-known-hosts-fixture")
	if _, _, _, err := ProbeBinding(t.Context(), "host", cfg, ""); Code(err) != "known_hosts_unreadable" || auth.Load() != before {
		t.Fatalf("malformed known_hosts was treated as a blank file: %v", err)
	}
}

func TestSSHIdentityAndFixedReadonlyCommands(t *testing.T) {
	var commands atomic.Int32
	cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
		commands.Add(1)
		switch command {
		case hostProbeCommand:
		case locale + "id -u":
			_, _ = io.WriteString(channel, "1000\n")
		case locale + "sudo -n -- id -u":
			return 1
		case firewallCommand:
			return 1
		case interfacesCommand:
			_, _ = io.WriteString(channel, `[{"ifindex":2,"ifname":"eth0","mtu":1500,"operstate":"UP","addr_info":[]}]`)
		default:
			t.Errorf("unexpected command %q", command)
			return 1
		}
		return 0
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	identity, warnings, err := Probe(ctx, "host", cfg)
	if err != nil || !strings.HasPrefix(identity, "SHA256:") || len(warnings) != 1 || warnings[0] != "firewall_unreadable" {
		t.Fatalf("probe = %q %v %v", identity, warnings, err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	wrong := cfg
	wrong.SSH.HostKey = string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	if _, _, err := Probe(ctx, "host", wrong); Code(err) != "identity_changed" || commands.Load() != 4 {
		t.Fatalf("unexpected host key caused remote commands: %v %d", err, commands.Load())
	}
	session, err := Open(ctx, "host", cfg, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	rows, err := session.Collect(ctx, "interfaces")
	if err != nil || len(rows) != 1 || rows[0].Key != "eth0" {
		t.Fatalf("interface = %v %v", rows, err)
	}
}

func TestSSHPrivateKeyReferenceDiagnostics(t *testing.T) {
	cfg := sshFixture(t, func(string, io.Reader, ssh.Channel) int { return 0 })
	data, err := os.ReadFile(cfg.SSH.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	openSSH, err := ssh.MarshalPrivateKey(key, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(key, "fixture", []byte("fixture-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ssh.MarshalPrivateKey(wrongKey, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := func(name string, content []byte) string {
		t.Helper()
		p := filepath.Join(home, name)
		if err := os.WriteFile(p, content, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, item := range []struct{ name, path, want string }{
		{"absolute OpenSSH key", path("open-key", pem.EncodeToMemory(openSSH)), ""},
		{"home-relative OpenSSH key", "~/open-key", ""},
		{"unreadable key", filepath.Join(home, "missing"), "credential_unreadable"},
		{"encrypted key", path("encrypted-key", pem.EncodeToMemory(encrypted)), "credential_passphrase_required"},
		{"public key", path("public-key", ssh.MarshalAuthorizedKey(signer.PublicKey())), "credential_invalid"},
		{"key rejected by host", path("other-key", pem.EncodeToMemory(wrong)), "authentication_failed"},
	} {
		t.Run(item.name, func(t *testing.T) {
			connection := cfg
			connection.SSH.KeyFile = item.path
			session, err := Open(t.Context(), "host", connection, "")
			if session != nil {
				defer session.Close()
			}
			if got := Code(err); got != item.want {
				t.Fatalf("got code %q; want %q", got, item.want)
			}
		})
	}
}

func TestMaintenanceStagesPrivatelyWithoutExecution(t *testing.T) {
	script := []byte("#!/bin/sh\n# synthetic package\n")
	cfg := sshFixture(t, func(command string, input io.Reader, channel ssh.Channel) int {
		switch command {
		case hostProbeCommand:
			return 0
		case autoMaintenanceProbe:
			return 126
		case stageOnlyCommand:
			staged, err := io.ReadAll(input)
			if err != nil || string(staged) != string(script) {
				t.Errorf("upload = %q %v", staged, err)
			}
			_, _ = io.WriteString(channel, "/var/tmp/imon-upload.ABCD1234/firewall-maintain.sh\n")
			return 0
		default:
			t.Errorf("unexpected command %q", command)
			return 1
		}
	})
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	identity := ssh.FingerprintSHA256(key)
	result, err := MaintainFirewall(t.Context(), cfg, nil, identity, "install", script)
	if Code(err) != FirewallAdministratorRequired || result.StagedPath != "" {
		t.Fatalf("automatic attempt changed staging = %#v %v", result, err)
	}
	result, err = StageFirewall(t.Context(), cfg, identity, "install", script)
	if err != nil || result.Status != "awaiting_admin" || result.StagedPath == "" || len(result.SHA256) != 64 {
		t.Fatalf("stage = %#v %v", result, err)
	}
	if command := FirewallAdminCommand("install", cfg.SSH.User, result.StagedPath, result.SHA256); !strings.Contains(command, "sha256sum -c -") {
		t.Fatalf("admin command = %q", command)
	}
	if command := FirewallAdminCommand("install", "demo;id", result.StagedPath, result.SHA256); command != "" {
		t.Fatalf("unwanted command = %q", command)
	}
}

type fixtureUpload struct {
	path string
	data string
	seen atomic.Int32
}

func (f *fixtureUpload) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if r.Filepath != f.path || !r.Pflags().Excl {
		return nil, os.ErrInvalid
	}
	return f, nil
}

func (f *fixtureUpload) Filecmd(r *sftp.Request) error {
	if r.Filepath != f.path || r.Method != "Setstat" {
		return os.ErrInvalid
	}
	return nil
}

func (f *fixtureUpload) WriteAt(b []byte, offset int64) (int, error) {
	if offset != 0 || string(b) != f.data {
		return 0, os.ErrInvalid
	}
	f.seen.Add(1)
	return len(b), nil
}

func TestMaintenancePrefersSFTP(t *testing.T) {
	upload := &fixtureUpload{path: "/var/tmp/imon-upload.ABCD1234/firewall-maintain.sh", data: "#!/bin/sh\n# synthetic package\n"}
	cfg := sshFixture(t, func(command string, _ io.Reader, channel ssh.Channel) int {
		switch command {
		case hostProbeCommand:
		case stageSFTPCommand:
			_, _ = io.WriteString(channel, upload.path+"\n")
		default:
			t.Errorf("unexpected command %q", command)
			return 1
		}
		return 0
	}, sftp.Handlers{FilePut: upload, FileCmd: upload})
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	result, err := StageFirewall(t.Context(), cfg, ssh.FingerprintSHA256(key), "install", []byte(upload.data))
	if err != nil || result.Status != "awaiting_admin" || result.StagedPath != upload.path || upload.seen.Load() != 1 {
		t.Fatalf("SFTP stage = %+v %v, writes = %d", result, err, upload.seen.Load())
	}
}

func TestMaintenanceVerifiesUninstallationOnlyWithAdminEvidence(t *testing.T) {
	script := []byte("#!/bin/sh\n# synthetic package\n")
	var verifyCalls atomic.Int32
	var badOutput atomic.Bool
	cfg := sshFixture(t, func(command string, input io.Reader, channel ssh.Channel) int {
		switch {
		case command == hostProbeCommand:
			return 0
		case command == locale+"id -u":
			_, _ = io.WriteString(channel, "1000\n")
			return 0
		case command == locale+"sudo -n -- id -u":
			return 1
		case command == "/usr/bin/uname -m":
			_, _ = io.WriteString(channel, "x86_64\n")
			return 0
		case command == inspectFirewallCommand:
			_, _ = io.WriteString(channel, "markers-absent\n")
			return 0
		case command == autoMaintenanceProbe:
			_, _ = io.WriteString(channel, "0\n")
			return 0
		case strings.HasPrefix(command, "imon_payload | sudo -n -- /bin/sh -c ") && strings.Contains(command, "verify --collector demo"):
			verifyCalls.Add(1)
			staged, err := io.ReadAll(input)
			if err != nil || string(staged) != string(script) {
				t.Errorf("verify package = %q %v", staged, err)
			}
			if badOutput.Load() {
				_, _ = io.WriteString(channel, "partial\n")
				return 0
			}
			_, _ = io.WriteString(channel, "uninstalled\n")
			return 0
		default:
			t.Errorf("unexpected verify command %q", command)
			return 1
		}
	})
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.SSH.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	identity := ssh.FingerprintSHA256(key)
	result, err := MaintainFirewall(t.Context(), cfg, nil, identity, "verify", nil)
	if err != nil || result.Status != "unknown" || !result.MarkersAbsent || result.Architecture != "amd64" || verifyCalls.Load() != 0 {
		t.Fatalf("ordinary verify = %+v %v", result, err)
	}
	adminKey := filepath.Join(t.TempDir(), "admin-key")
	file, err := os.ReadFile(cfg.SSH.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminKey, file, 0600); err != nil {
		t.Fatal(err)
	}
	admin := &Config{SSH: Endpoint{User: "fixture-admin", KeyFile: adminKey}}
	result, err = MaintainFirewall(t.Context(), cfg, admin, identity, "verify", script)
	if err != nil || result.Status != "uninstalled" || verifyCalls.Load() != 1 {
		t.Fatalf("administrator verify = %+v %v", result, err)
	}
	badOutput.Store(true)
	result, err = MaintainFirewall(t.Context(), cfg, admin, identity, "verify", script)
	if Code(err) != "result_unconfirmed" || result.Status != "unknown" || verifyCalls.Load() != 2 {
		t.Fatalf("invalid verification response = %+v %v", result, err)
	}
}
