package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imon/internal/collector"
	"imon/internal/store"

	"golang.org/x/crypto/ssh"
)

func bindingSSHFixture(t *testing.T, legitimateClient ssh.PublicKey, forwardedAddr string, response ...func(string) string) (collector.Endpoint, *atomic.Pointer[ssh.ServerConfig], *atomic.Int32, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var current atomic.Pointer[ssh.ServerConfig]
	var auth atomic.Int32
	server, fp := bindingSSHServer(t, legitimateClient, &auth)
	current.Store(server)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, channels, requests, err := ssh.NewServerConn(conn, current.Load())
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					switch incoming.ChannelType() {
					case "session":
						channel, requests, err := incoming.Accept()
						if err != nil {
							continue
						}
						go func() {
							defer channel.Close()
							for req := range requests {
								if req.Type != "exec" {
									_ = req.Reply(false, nil)
									continue
								}
								_ = req.Reply(true, nil)
								body, _ := io.ReadAll(channel)
								if len(response) != 0 {
									_, _ = io.WriteString(channel, response[0](string(body)))
								}
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							}
						}()
					case "direct-tcpip":
						var tunnel struct {
							Host       string
							Port       uint32
							Origin     string
							OriginPort uint32
						}
						if err := ssh.Unmarshal(incoming.ExtraData(), &tunnel); err != nil || forwardedAddr == "" || net.JoinHostPort(tunnel.Host, strconv.Itoa(int(tunnel.Port))) != forwardedAddr {
							_ = incoming.Reject(ssh.Prohibited, "fixture only")
							continue
						}
						dst, err := net.Dial("tcp", forwardedAddr)
						if err != nil {
							_ = incoming.Reject(ssh.ConnectionFailed, "fixture unavailable")
							continue
						}
						channel, requests, err := incoming.Accept()
						if err != nil {
							_ = dst.Close()
							continue
						}
						go ssh.DiscardRequests(requests)
						go func() {
							defer dst.Close()
							_, _ = io.Copy(dst, channel)
						}()
						go func() {
							defer channel.Close()
							_, _ = io.Copy(channel, dst)
						}()
					default:
						_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
					}
				}
			}()
		}
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return collector.Endpoint{Address: host, Port: n, User: "fixture"}, &current, &auth, fp
}

func TestUnbindHostRequiresVerifiedFirewallRemoval(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "fixture-key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey}), 0600); err != nil {
		t.Fatal(err)
	}
	var remote atomic.Value
	digest := "8645c" + strings.Repeat("a", 59)
	remote.Store("installed " + digest)
	var detectionCalls atomic.Int32
	endpoint, sshServer, auth, fingerprint := bindingSSHFixture(t, clientKey, "", func(command string) string {
		switch {
		case strings.Contains(command, "markers-absent"):
			detectionCalls.Add(1)
			return remote.Load().(string) + "\n"
		case strings.Contains(command, "/usr/bin/uname -m"):
			return "x86_64\n"
		case strings.Contains(command, "/firewall-read"):
			return `[{"backend":"nftables","status":"ok"}]`
		default:
			return ""
		}
	})
	endpoint.KeyFile = keyFile
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	_, _, config, err := collector.ProbeBinding(t.Context(), "host", collector.Config{SSH: endpoint}, "")
	var confirm *collector.HostKeyConfirmation
	if !errors.As(err, &confirm) {
		t.Fatalf("expected SSH confirmation: %v", err)
	}
	config.SSH = endpoint
	config.SSH.HostKey = confirm.Key
	ref, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), filepath.Join(dir, "fixture.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO targets (target_id,kind,name,connection_ref,connection_rev,enabled,identity)
			VALUES ('fixture','host','fixture',?,1,1,?)`, string(ref), fingerprint)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c, err := NewWithVersion(t.Context(), db, nil, "v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mux := http.NewServeMux()
	c.Register(mux)
	authorization := func() {
		t.Helper()
		response := collectionHTTP(t, mux, "GET", "/api/v1/hosts/fixture/firewall-authorization", "", 200)
		var state firewallAuthorizationState
		if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || state.Status != "installed" || state.InstalledVersion != digest || state.InstalledDisplayVersion != "v0.1.0 8645c" {
			t.Fatalf("unexpected cached authorization: %+v; %v", state, err)
		}
	}
	authorization()
	authorization()
	c.Close()
	c, err = NewWithVersion(t.Context(), db, nil, "v0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mux = http.NewServeMux()
	c.Register(mux)
	authorization()
	if count := detectionCalls.Load(); count != 1 {
		t.Fatalf("installed authorization was re-probed across reads or restart: %d", count)
	}
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE targets SET connection_rev=2 WHERE target_id='fixture'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	response := collectionHTTP(t, mux, "GET", "/api/v1/hosts/fixture/firewall-authorization", "", 200)
	if count := detectionCalls.Load(); count != 2 || !strings.Contains(response.Body.String(), `"installed_display_version":"v0.2.0 8645c"`) {
		t.Fatalf("new connection did not get a fresh observation: probes=%d body=%s", count, response.Body.String())
	}
	del := func(wantStatus string, codes ...string) {
		t.Helper()
		response := collectionHTTP(t, mux, "DELETE", "/api/v1/targets/fixture?confirm_unknown=true", "", 202)
		id := firewallJobID(t, response.Body.Bytes())
		var job struct {
			Status      string            `json:"status"`
			Results     map[string]string `json:"results"`
			Error       string            `json:"error_code"`
			CompletedAt *int64            `json:"completed_at"`
		}
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			res := collectionHTTP(t, mux, "GET", "/api/v1/jobs/"+id, "", 200)
			if err := json.Unmarshal(res.Body.Bytes(), &job); err != nil {
				t.Fatal(err)
			}
			if job.CompletedAt != nil {
				break
			}
		}
		if job.Status != wantStatus || len(codes) > 0 && !slices.Contains(codes, job.Error) || (job.Results["unbound"] == "true") != (wantStatus == "success") {
			t.Fatalf("unbind job: %+v", job)
		}
		if _, err := c.target(t.Context(), "fixture"); (err == nil) != (wantStatus != "success") {
			t.Fatalf("binding lookup after %q: %v", job.Status, err)
		}
	}
	del("failed", collector.FirewallAdministratorRequired, "maintenance_package_unavailable")
	remote.Store("markers-absent")
	del("failed", collector.FirewallAdministratorRequired, "maintenance_package_unavailable")
	originalServer := sshServer.Load()
	rotatedServer, _ := bindingSSHServer(t, clientKey, auth)
	sshServer.Store(rotatedServer)
	del("failed", "identity_changed")
	sshServer.Store(originalServer)
	seedFirewallJob(t, c, "cleared", "fixture", "uninstall", "success", "", map[string]string{
		"firewall_status": "uninstalled", "cleanup_confirmed": "true",
	})
	seedFirewallJob(t, c, "pending", "fixture", "install", "awaiting_admin", "", map[string]string{})
	del("failed", collector.FirewallAdministratorRequired, "maintenance_package_unavailable")
	remote.Store("uninstalled")
	del("success")
}

func bindingSSHServer(t *testing.T, user ssh.PublicKey, auth *atomic.Int32) (*ssh.ServerConfig, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, presented ssh.PublicKey) (*ssh.Permissions, error) {
		auth.Add(1)
		if !bytes.Equal(user.Marshal(), presented.Marshal()) {
			return nil, fmt.Errorf("fixture user key mismatch")
		}
		return nil, nil
	}}
	server.AddHostKey(signer)
	return server, ssh.FingerprintSHA256(signer.PublicKey())
}

func TestSSHBindingConfirmsEachHopAndPreservesPinsOnEdit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "fixture-key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	endpoint, server, targetAuth, targetFP := bindingSSHFixture(t, clientKey, "")
	targetAddr := net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port))
	jump, _, jumpAuth, jumpFP := bindingSSHFixture(t, clientKey, targetAddr)
	jumpAddr := net.JoinHostPort(jump.Address, strconv.Itoa(jump.Port))
	endpoint.KeyFile, jump.KeyFile = keyFile, keyFile

	db, err := store.Open(t.Context(), filepath.Join(dir, "fixture.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c, err := New(t.Context(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mux := http.NewServeMux()
	c.Register(mux)
	call := func(method, path string, in connectionInput, want int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(in)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s = %d; want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		var data map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	confirm := func(in connectionInput, role, addr, fingerprint string) string {
		t.Helper()
		result := call("POST", "/api/v1/targets/test", in, 409)
		details, _ := result["details"].(map[string]any)
		if result["code"] != "host_key_confirmation_required" || details["role"] != role || details["address"] != addr || details["fingerprint"] != fingerprint || len(details) != 4 {
			t.Fatalf("unexpected confirmation response: %v", result)
		}
		return details["confirmation_token"].(string)
	}
	input := connectionInput{Kind: "host", Name: "fixture", Config: collector.Config{SSH: endpoint, Jump: &jump}}
	input.SSHConfirm = confirm(input, "jump", jumpAddr, jumpFP)
	if jumpAuth.Load() != 0 || targetAuth.Load() != 0 {
		t.Fatal("first untrusted hop received authentication")
	}
	changed := input
	changed.SSH.User = "different"
	if got := call("POST", "/api/v1/targets/test", changed, 409)["code"]; got != "ssh_confirmation_expired" {
		t.Fatalf("confirmation used with different input: %v", got)
	}
	input.SSHConfirm = confirm(input, "target", targetAddr, targetFP)
	if jumpAuth.Load() == 0 || targetAuth.Load() != 0 {
		t.Fatal("unconfirmed target received authentication")
	}
	input.TestToken = call("POST", "/api/v1/targets/test", input, 200)["test_token"].(string)
	if targetAuth.Load() == 0 {
		t.Fatal("verified target never received authentication")
	}
	input.SSHConfirm = ""
	resp := call("POST", "/api/v1/targets", input, 201)
	id := resp["id"].(string)
	b, err := c.target(t.Context(), id)
	if err != nil || b.Config.SSH.HostKey == "" || b.Config.Jump.HostKey == "" || b.Identity != targetFP {
		t.Fatalf("binding did not save both verified keys: %v", err)
	}
	input.TargetID, input.ConnectionRev, input.TestToken = id, b.ConnectionRev, ""
	input.Name = "renamed fixture"
	input.TestToken = call("POST", "/api/v1/targets/test", input, 200)["test_token"].(string)
	call("PATCH", "/api/v1/targets/"+id, input, 200)
	before := targetAuth.Load()
	rotated, _ := bindingSSHServer(t, clientKey, targetAuth)
	server.Store(rotated)
	if got := call("POST", "/api/v1/targets/test", input, 409)["code"]; got != "identity_changed" || targetAuth.Load() != before {
		t.Fatalf("editing a binding accepted a rotated key: %v", got)
	}
}

func TestSeparateServiceCredentialsKeepBindingTrust(t *testing.T) {
	bound := binding{Target: store.Target{Kind: "host"}, Config: collector.Config{
		SSH:  collector.Endpoint{Address: "192.0.2.10", Port: 2222, User: "read-user", KeyFile: "/<READ_KEY>", HostKey: "<BOUND_KEY>"},
		Jump: &collector.Endpoint{Address: "192.0.2.20", Port: 22, User: "jump-user", KeyFile: "/<JUMP_KEY>", HostKey: "<BOUND_JUMP_KEY>"},
	}}
	operator := collector.Config{SSH: collector.Endpoint{User: "operator", KeyFile: "/<OPERATOR_KEY>"}}
	if !separateCredentials(bound, &operator) || operator.SSH.Address != bound.Config.SSH.Address || operator.SSH.Port != bound.Config.SSH.Port || operator.SSH.HostKey != bound.Config.SSH.HostKey || *operator.Jump != *bound.Config.Jump {
		t.Fatal("operational credentials did not inherit the saved connection identity")
	}
}
