package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var botTokenPattern = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
var chatPattern = regexp.MustCompile(`^(-?[0-9]+|@[A-Za-z0-9_]+)$`)

func validateDestination(t *notificationTarget) error {
	t.Name = strings.TrimSpace(t.Name)
	if len(t.Name) == 0 || len(t.Name) > 200 {
		return errors.New("name must contain 1–200 bytes")
	}
	if t.CredentialRef != "" && (!filepath.IsAbs(t.CredentialRef) || strings.ContainsAny(t.CredentialRef, "\r\n\x00")) {
		return errors.New("credential_ref must be an absolute path to a protected file")
	}
	switch t.Channel {
	case "telegram":
		if t.CredentialRef == "" {
			return errors.New("credential_ref is required for Telegram")
		}
		if len(t.ChatID) > 128 || !chatPattern.MatchString(t.ChatID) {
			return errors.New("chat_id must be a numeric Telegram chat ID or @channel")
		}
		if t.ProxyURL != "" {
			proxy, err := url.Parse(t.ProxyURL)
			if err != nil || proxy.Scheme != "http" || proxy.Hostname() == "" || proxy.User != nil || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" {
				return errors.New("proxy_url must be an HTTP CONNECT address without credentials")
			}
		}
		t.Host, t.Port, t.TLSMode, t.Username, t.From, t.Recipients = "", 0, "", "", "", nil
	case "email":
		if t.TLSMode != "implicit" && t.TLSMode != "starttls" {
			return errors.New("tls_mode must be implicit or starttls")
		}
		if t.Port == 0 {
			t.Port = 587
			if t.TLSMode == "implicit" {
				t.Port = 465
			}
		}
		if t.Host == "" || strings.ContainsAny(t.Host, " /\t\r\n[]@") || (strings.Contains(t.Host, ":") && net.ParseIP(t.Host) == nil) || t.Port < 1 || t.Port > 65535 {
			return errors.New("valid SMTP host and port are required")
		}
		if (t.Username == "") != (t.CredentialRef == "") || strings.ContainsAny(t.Username, "\r\n\x00") {
			return errors.New("SMTP authentication requires username and credential_ref together")
		}
		if !validMailbox(t.From) || len(t.Recipients) < 1 || len(t.Recipients) > 50 {
			return errors.New("valid sender and 1–50 recipients are required")
		}
		seen := map[string]bool{}
		for _, address := range t.Recipients {
			if !validMailbox(address) || seen[address] {
				return errors.New("each recipient must be a unique mailbox address")
			}
			seen[address] = true
		}
		t.ChatID, t.ProxyURL = "", ""
	default:
		return errors.New("channel must be telegram or email")
	}
	return nil
}

func validMailbox(input string) bool {
	if len(input) > 254 || strings.ContainsAny(input, "\r\n\x00") {
		return false
	}
	parsed, err := mail.ParseAddress(input)
	return err == nil && parsed.Name == "" && parsed.Address == input
}

type sendResult struct {
	status, detail string
	retry          bool
	retryAfter     time.Duration
}

func accepted() sendResult           { return sendResult{status: "accepted"} }
func failed(code string) sendResult  { return sendResult{status: "failed", detail: code} }
func unknown(code string) sendResult { return sendResult{status: "unknown", detail: code} }
func temporary(code string, delay time.Duration) sendResult {
	return sendResult{status: "failed", detail: code, retry: true, retryAfter: delay}
}

func credential(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return "", errors.New("credential must be a private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return "", errors.New("invalid credential file")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid credential file")
	}
	return value, nil
}

func sendNotification(ctx context.Context, target notificationTarget, address, message string) sendResult {
	var secret string
	if target.CredentialRef != "" {
		var err error
		secret, err = credential(target.CredentialRef)
		if err != nil {
			return failed("credential_unavailable")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if target.Channel == "telegram" {
		if !botTokenPattern.MatchString(secret) || len(secret) > 200 {
			return failed("invalid_telegram_token")
		}
		return telegram(ctx, target, address, message, secret, "https://api.telegram.org", tlsConfig)
	}
	return email(ctx, target, address, message, secret, tlsConfig)
}

func telegram(ctx context.Context, target notificationTarget, address, message, token, base string, tlsConfig *tls.Config) sendResult {
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if target.ProxyURL != "" {
		proxy, err := url.Parse(target.ProxyURL)
		if err != nil {
			return failed("invalid_proxy")
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Track whether a connection was available for the HTTP request. Connect
	// failures are retryable. Cancellation after the request could have been
	// sent leaves delivery ambiguous and must not cause another message.
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }})
	body, err := json.Marshal(map[string]string{"chat_id": address, "text": message})
	if err != nil {
		return failed("telegram_payload")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return failed("telegram_request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if connected.Load() {
			return unknown("telegram_no_reply")
		}
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return failed("telegram_tls_verification")
		}
		return temporary("telegram_connect", 0)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return unknown("telegram_incomplete_reply")
	}
	var result struct {
		OK         *bool `json:"ok"`
		Code       int   `json:"error_code"`
		Parameters struct {
			RetryAfter int64 `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.OK == nil {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return failed("telegram_redirect")
		}
		return unknown("telegram_unverified_reply")
	}
	if *result.OK && resp.StatusCode == 200 {
		return accepted()
	}
	if *result.OK {
		return unknown("telegram_inconsistent_reply")
	}
	switch {
	case result.Code == 429:
		seconds := max(int64(0), result.Parameters.RetryAfter)
		if seconds > int64((1<<63-1)/time.Second) {
			return failed("telegram_retry_after_overflow")
		}
		retry := time.Duration(seconds) * time.Second
		if delay, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64); err == nil && delay >= 0 && delay < int64((1<<63-1)/time.Second) {
			retry = max(retry, time.Duration(delay)*time.Second)
		}
		return temporary("telegram_rate_limited", retry)
	case result.Code >= 400 && result.Code < 500:
		return failed("telegram_rejected")
	case result.Code >= 500 && result.Code < 600:
		// A remote failure after sending may have been preceded by message
		// acceptance. Without an explicit nonacceptance such as 429 this is
		// ambiguous and cannot be retried.
		return unknown("telegram_server_error")
	default:
		return unknown("telegram_inconsistent_reply")
	}
}

func smtpReply(err error, phase string, sent bool) sendResult {
	var response *textproto.Error
	if errors.As(err, &response) {
		if response.Code >= 400 && response.Code < 500 {
			return temporary(phase+"_temporary", 0)
		}
		if response.Code >= 500 {
			return failed(phase + "_rejected")
		}
	}
	if sent {
		return unknown(phase + "_no_reply")
	}
	return temporary(phase+"_connection", 0)
}

func email(ctx context.Context, target notificationTarget, address, message, password string, tlsConfig *tls.Config) sendResult {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return temporary("smtp_connect", 0)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return temporary("smtp_deadline", 0)
		}
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.ServerName = target.Host
	var transport net.Conn = conn
	if target.TLSMode == "implicit" {
		secure := tls.Client(conn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return failed("smtp_tls")
		}
		transport = secure
	}
	client, err := smtp.NewClient(transport, target.Host)
	if err != nil {
		return smtpReply(err, "smtp_greeting", false)
	}
	defer client.Close()
	if target.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return failed("smtp_starttls_required")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return failed("smtp_starttls")
		}
	}
	if target.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", target.Username, password, target.Host)); err != nil {
			return failed("smtp_auth")
		}
	}
	if err := client.Mail(target.From); err != nil {
		return smtpReply(err, "smtp_sender", false)
	}
	if err := client.Rcpt(address); err != nil {
		return smtpReply(err, "smtp_recipient", false)
	}
	dot, err := client.Data()
	if err != nil {
		return smtpReply(err, "smtp_data", false)
	}
	// No externally provided values appear in headers other than validated
	// addresses. The MIME encoder keeps body text within SMTP line limits.
	payload := fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\nSubject: Imon notification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", target.From, address)
	if _, err := io.WriteString(dot, payload); err != nil {
		return temporary("smtp_body_connection", 0)
	}
	if err := encodeMailBody(dot, message); err != nil {
		return temporary("smtp_body_connection", 0)
	}
	if err := dot.Close(); err != nil {
		return smtpReply(err, "smtp_receipt", true)
	}
	return accepted()
}

func encodeMailBody(dst io.Writer, message string) error {
	encoded := quotedprintable.NewWriter(dst)
	if _, err := io.WriteString(encoded, message); err != nil {
		return err
	}
	return encoded.Close()
}
