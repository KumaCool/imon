package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"imon/internal/httpapi"
	"imon/internal/panelruntime"
	"imon/internal/update"
)

var version = "v0.1.0"
var defaultReleaseRepo string

const defaultPort = 8765

func main() {
	var dir, backupPath, restorePath, repo string
	var showVersion, updateResume bool
	var port int
	flag.StringVar(&dir, "data-dir", "", "use this private data directory instead of the per-user default")
	flag.IntVar(&port, "port", defaultPort, "local Web panel port")
	flag.StringVar(&backupPath, "backup", "", "save a SQLite backup to a new file")
	flag.StringVar(&restorePath, "restore", "", "restore a SQLite backup while the panel is stopped")
	flag.StringVar(&repo, "release-repo", defaultReleaseRepo, "public GitHub release repository (owner/repo)")
	flag.BoolVar(&showVersion, "version", false, "print the local application version")
	flag.BoolVar(&updateResume, "update-resume", false, "internal: resume a local panel update")
	flag.Parse()
	if port <= 0 || port > 65535 || flag.NArg() != 0 || backupPath != "" && restorePath != "" {
		flag.Usage()
		os.Exit(2)
	}

	if showVersion {
		fmt.Println(version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	if backupPath != "" || restorePath != "" {
		err = panelruntime.DatabaseCommand(ctx, dir, backupPath, restorePath, os.Stdout)
	} else {
		var resume *startupResume
		if updateResume {
			resume, err = receiveResume()
		}
		if err == nil {
			err = runPanel(ctx, dir, port, os.Stdout, repo, resume, os.Executable)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "imon:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir string, port int, output io.Writer) error {
	return runWithRelease(ctx, dir, port, output, defaultReleaseRepo)
}

func runWithRelease(ctx context.Context, dir string, port int, output io.Writer, repo string) (err error) {
	return runPanel(ctx, dir, port, output, repo, nil, nil)
}

func runPanel(ctx context.Context, dir string, port int, output io.Writer, repo string, resume *startupResume, executable func() (string, error)) (err error) {
	var next *panelRestart
	defer func() {
		if next != nil {
			err = errors.Join(err, next.restart(err))
		}
	}()
	var listener net.Listener
	var resumeSession string
	var opts update.Options
	var runtime *panelruntime.Runtime
	if resume != nil {
		resumeSession, opts.RolledBack = resume.Credential, resume.RolledBack
	}
	requested := make(chan *panelRestart, 1)
	if executable != nil {
		if path, pathErr := executable(); pathErr == nil {
			opts.Executable = path
			opts.Install = func(r *http.Request, rpl *update.Replacement) error {
				return queueRestart(r, rpl, listener, runtime.DBPath(), repo, requested)
			}
		}
	}
	runtime, err = panelruntime.Open(ctx, dir, version, repo, opts)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, runtime.Close()) }()
	if resume != nil {
		listener, err = net.FileListener(resume.listener)
		_ = resume.listener.Close()
	} else {
		listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	if err != nil {
		return fmt.Errorf("listen for local panel (choose another --port if occupied): %w", err)
	}
	defer listener.Close()
	handler, url, err := httpapi.NewWeb(listener.Addr().String(), runtime.Handler, resumeSession)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if _, err := fmt.Fprintln(output, "Panel URL:", url); err != nil {
		return fmt.Errorf("print panel URL: %w", err)
	}
	if resume != nil {
		_, err := io.WriteString(resume.ready, "ready\n")
		_ = resume.ready.Close()
		if err != nil {
			return fmt.Errorf("signal updated panel readiness: %w", err)
		}
	}

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	case next = <-requested:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Shutdown(shutdown)
	if err != nil {
		_ = server.Close()
	}
	if serveErr := <-served; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	// An authenticated apply may have queued while a termination signal arrived.
	if next == nil {
		select {
		case abandoned := <-requested:
			abandoned.close()
		default:
		}
	}
	return err
}
