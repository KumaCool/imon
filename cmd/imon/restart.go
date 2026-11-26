package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"imon/internal/appdata"
	"imon/internal/httpapi"
	"imon/internal/store"
	"imon/internal/update"
)

type startupResume struct {
	Credential string
	RolledBack bool
	listener   *os.File
	ready      *os.File
}

func receiveResume() (*startupResume, error) {
	// The parent passes the existing listener and private pipes, never session
	// credentials in command arguments or environment variables.
	config := os.NewFile(4, "update-config")
	if config == nil {
		return nil, errors.New("missing update resume pipe")
	}
	defer config.Close()
	resume := &startupResume{listener: os.NewFile(3, "update-listener"), ready: os.NewFile(5, "update-ready")}
	if err := json.NewDecoder(io.LimitReader(config, 1024)).Decode(resume); err != nil || len(resume.Credential) != 43 {
		return nil, errors.New("invalid update resume configuration")
	}
	return resume, nil
}

type panelRestart struct {
	replacement             *update.Replacement
	listener                *os.File
	database, repo, session string
}

func queueRestart(r *http.Request, replacement *update.Replacement, ln net.Listener, database, repo string, pending chan<- *panelRestart) error {
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		return errors.New("update requires a TCP listener")
	}
	session := httpapi.SessionCredential(r)
	if session == "" {
		return errors.New("update requires an authenticated session")
	}
	listener, err := tcp.File()
	if err != nil {
		return err
	}
	select {
	case pending <- &panelRestart{replacement, listener, database, repo, session}:
		return nil
	default:
		_ = listener.Close()
		return errors.New("an update is already queued")
	}
}

func (p *panelRestart) close() {
	_ = p.listener.Close()
	p.replacement.Cleanup()
}

func (p *panelRestart) restart(shutdownErr error) error {
	defer p.listener.Close()
	if shutdownErr != nil {
		p.replacement.Cleanup()
		return p.start(true)
	}
	// Workers and the DB have stopped. Take a private rollback snapshot before
	// the replacement can open the database and apply new migrations.
	backupDir, err := os.MkdirTemp(filepath.Dir(p.database), ".update-state-*")
	if err != nil {
		p.replacement.Cleanup()
		return errors.Join(err, p.start(true))
	}
	removeBackup := true
	defer func() {
		if removeBackup {
			_ = os.RemoveAll(backupDir)
		}
	}()
	backup := filepath.Join(backupDir, "state.sqlite3")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = store.BackupFile(ctx, p.database, backup)
	cancel()
	if err != nil {
		p.replacement.Cleanup()
		return errors.Join(err, p.start(true))
	}
	if err := p.replacement.Install(); err != nil {
		p.replacement.Cleanup()
		return errors.Join(err, p.start(true))
	}
	if err := p.start(false); err != nil {
		binaryErr := p.replacement.Rollback()
		stateErr := p.restoreState(backup)
		if binaryErr != nil || stateErr != nil {
			removeBackup = false
			return errors.Join(err, binaryErr, stateErr)
		}
		p.replacement.Cleanup()
		return p.start(true)
	}
	p.replacement.Cleanup()
	return nil
}

func (p *panelRestart) restoreState(backup string) (err error) {
	data, err := appdata.Open(filepath.Dir(p.database))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, data.Close()) }()
	// The failed replacement is reaped and the application lock is held, so
	// no live SQLite connection owns these sidecars.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(p.database + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(backup, p.database)
}

func (p *panelRestart) start(rolledBack bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	configIn, configOut, err := os.Pipe()
	if err != nil {
		return err
	}
	defer configIn.Close()
	defer configOut.Close()
	readyIn, readyOut, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readyIn.Close()
	defer readyOut.Close()
	if err := json.NewEncoder(configOut).Encode(startupResume{Credential: p.session, RolledBack: rolledBack}); err != nil {
		return err
	}
	_ = configOut.Close()
	cmd := exec.Command(p.replacement.Target, "--data-dir", filepath.Dir(p.database), "--release-repo", p.repo, "--update-resume")
	cmd.ExtraFiles = []*os.File{p.listener, configIn, readyOut}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = readyOut.Close()
	ready := make(chan error, 1)
	go func() {
		var message [6]byte
		_, err := io.ReadFull(readyIn, message[:])
		if err == nil && string(message[:]) != "ready\n" {
			err = errors.New("invalid update readiness response")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err == nil {
			go func() { _ = cmd.Wait() }()
			return nil
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("updated panel did not become ready: %w", err)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("updated panel did not become ready: %w", ctx.Err())
	}
}
