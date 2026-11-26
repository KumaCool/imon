package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"imon/internal/desktop"
	"imon/internal/panelruntime"
	"imon/internal/update"
)

var version = "v0.1.0"

func init() {
	runtime.LockOSThread()
}

func main() {
	var dir, backupPath, restorePath string
	var showVersion bool
	flag.StringVar(&dir, "data-dir", "", "use this private data directory instead of the per-user default")
	flag.StringVar(&backupPath, "backup", "", "save a SQLite backup to a new file")
	flag.StringVar(&restorePath, "restore", "", "restore a SQLite backup while the panel is stopped")
	flag.BoolVar(&showVersion, "version", false, "print the local application version")
	flag.Parse()
	if flag.NArg() != 0 || backupPath != "" && restorePath != "" {
		flag.Usage()
		os.Exit(2)
	}
	if showVersion {
		fmt.Println(version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	isDatabaseCommand := backupPath != "" || restorePath != ""
	var err error
	if isDatabaseCommand {
		err = panelruntime.DatabaseCommand(ctx, dir, backupPath, restorePath, os.Stdout)
	} else {
		err = run(ctx, dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "imon-desktop:", err)
		if !isDatabaseCommand {
			desktop.ShowStartupError(err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, dir string) (err error) {
	if err := desktop.Available(); err != nil {
		return err
	}
	app, err := panelruntime.Open(ctx, dir, version, "", update.Options{})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, app.Close()) }()
	return desktop.Run(ctx, app.Handler)
}
