package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"imon/internal/appdata"
)

type outputLine chan string

func (out outputLine) Write(p []byte) (int, error) {
	out <- string(p)
	return len(p), nil
}

func TestRunLocalPanel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	output := make(outputLine, 1)
	go func() { done <- run(ctx, dir, 0, output) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("panel did not shut down")
		}
	}()

	var line string
	select {
	case line = <-output:
	case err := <-done:
		done <- err
		t.Fatal("panel stopped during startup")
	case <-time.After(10 * time.Second):
		t.Fatal("panel did not start")
	}
	startup, err := url.Parse(strings.TrimSpace(strings.TrimPrefix(line, "Panel URL: ")))
	if err != nil || startup.Scheme != "http" || startup.Hostname() != "127.0.0.1" || startup.Fragment != "" || startup.RawQuery != "" {
		t.Fatal("expected a reusable local address without credentials")
	}
	if err := run(ctx, dir, 0, io.Discard); !errors.Is(err, appdata.ErrLocked) {
		t.Fatalf("second instance: %v; want directory locked", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	base := startup.Scheme + "://" + startup.Host
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/session", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal("could not build session request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("could not send session request")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("session exchange got HTTP %d", resp.StatusCode)
	}
	resp, err = client.Get(base + "/api/v1/targets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Items []json.RawMessage `json:"items"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&payload) != nil || payload.Items == nil || len(payload.Items) != 0 {
		t.Fatal("initial local target list must be a successful empty array")
	}
}

func TestMigrationFailureDoesNotStartPanel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	data, err := appdata.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := data.DBPath()
	if err := data.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE targets (legacy TEXT NOT NULL); INSERT INTO targets VALUES ('fixture');`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	var output strings.Builder
	err = run(context.Background(), dir, port, &output)
	if err == nil || !strings.Contains(err.Error(), "apply SQLite migration") || output.Len() != 0 {
		t.Fatalf("migration did not fail before binding port %s", strconv.Itoa(port))
	}
	if backups, err := filepath.Glob(path + ".pre-migrate-v0-*.bak"); err != nil || len(backups) != 1 {
		t.Fatal("failed migration must retain one pre-migration backup")
	}
	opened, err := appdata.Open(dir)
	if err != nil {
		t.Fatalf("failed startup should not retain directory lock: %v", err)
	}
	defer opened.Close()
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var value string
	if err := check.QueryRow(`SELECT legacy FROM targets`).Scan(&value); err != nil || value != "fixture" {
		t.Fatal("failed migration did not preserve the original database content")
	}
}
