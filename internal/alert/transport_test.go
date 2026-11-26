package alert

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTelegramReplies(t *testing.T) {
	for _, tc := range []struct {
		name, body, status string
		code               int
		retry              time.Duration
	}{
		{"accepted", `{"ok":true,"result":{}}`, "accepted", 200, 0},
		{"limited", `{"ok":false,"error_code":429,"parameters":{"retry_after":71}}`, "failed", 429, 71 * time.Second},
		{"rejected", `{"ok":false,"error_code":401}`, "failed", 401, 0},
		{"unconfirmed", `{"ok":false,"error_code":500}`, "unknown", 500, 0},
		{"proxy_reply", "upstream error", "unknown", 502, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/bot123:fake_TEST/sendMessage" || r.Method != http.MethodPost {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["chat_id"] != "-333" || body["text"] != "Example alert" {
					t.Errorf("bad input: %v %v", body, err)
				}
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			tlsConfig := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			result := telegram(t.Context(), notificationTarget{}, "-333", "Example alert", "123:fake_TEST", srv.URL, tlsConfig)
			if result.status != tc.status || result.retryAfter != tc.retry || result.retry != (tc.retry > 0) {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestSMTPVerifiedTransportAndReceipts(t *testing.T) {
	for _, tc := range []struct {
		name, mode, reply, status string
		offerTLS, retry           bool
	}{
		{"implicit accepted", "implicit", "250 ok", "accepted", false, false},
		{"starttls temporary", "starttls", "451 try again", "failed", true, true},
		{"starttls without receipt", "starttls", "", "unknown", true, false},
		{"starttls mandatory", "starttls", "", "failed", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certSource := httptest.NewTLSServer(http.NotFoundHandler())
			serverCert := certSource.TLS.Certificates[0]
			roots := x509.NewCertPool()
			roots.AddCert(certSource.Certificate())
			certSource.Close()
			socket, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			resultCh := make(chan error, 1)
			go func() {
				conn, err := socket.Accept()
				if err != nil {
					resultCh <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				var secure bool
				srvTLS := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
				if tc.mode == "implicit" {
					conn = tls.Server(conn, srvTLS)
					secure = true
				}
				channel := bufio.NewReader(conn)
				write := func(line string) error { _, err := fmt.Fprint(conn, line+"\r\n"); return err }
				if err := write("220 smtp.example.test fixture"); err != nil {
					resultCh <- err
					return
				}
				for {
					line, err := channel.ReadString('\n')
					if err != nil {
						resultCh <- err
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						reply := "250 smtp.example.test"
						if !secure && tc.offerTLS {
							reply = "250-smtp.example.test\r\n250 STARTTLS"
						}
						if err = write(reply); err == nil && !secure && !tc.offerTLS {
							resultCh <- nil
							return
						}
					case line == "STARTTLS\r\n" && !secure && tc.offerTLS:
						err = write("220 ready")
						conn = tls.Server(conn, srvTLS)
						channel = bufio.NewReader(conn)
						secure = true
					case secure && (strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "RCPT TO:")):
						err = write("250 ok")
					case secure && line == "DATA\r\n":
						if err = write("354 begin"); err != nil {
							resultCh <- err
							return
						}
						msg := new(strings.Builder)
						for {
							line, err = channel.ReadString('\n')
							if err != nil {
								resultCh <- err
								return
							}
							if line == ".\r\n" {
								break
							}
							msg.WriteString(line)
						}
						if !strings.Contains(msg.String(), "Example alert") {
							resultCh <- fmt.Errorf("missing mail payload")
							return
						}
						if tc.reply != "" {
							err = write(tc.reply)
						}
						resultCh <- err
						return
					default:
						err = fmt.Errorf("unexpected SMTP command or TLS state: %s %v", line, secure)
					}
					if err != nil {
						resultCh <- err
						return
					}
				}
			}()
			host, portText, err := net.SplitHostPort(socket.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			target := notificationTarget{Host: host, Port: port, TLSMode: tc.mode, From: "monitor@example.test"}
			result := email(t.Context(), target, "receiver@example.test", "Example alert", "", &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err := <-resultCh; err != nil {
				t.Fatal(err)
			}
			if result.status != tc.status || result.retry != tc.retry {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}
