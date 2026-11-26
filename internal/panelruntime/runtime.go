// Package panelruntime owns the shared panel state and business API lifecycle.
package panelruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"imon/internal/alert"
	"imon/internal/appdata"
	"imon/internal/control"
	"imon/internal/httpapi"
	"imon/internal/store"
	"imon/internal/update"
)

type Runtime struct {
	Handler http.Handler
	data    *appdata.Directory
	db      *store.Store
	alerts  *alert.Engine
	core    *control.Control
}

func Open(ctx context.Context, dir, version, repo string, opts update.Options) (_ *Runtime, err error) {
	data, err := appdata.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open application data: %w", err)
	}
	r := &Runtime{data: data}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	if r.db, err = store.Open(ctx, data.DBPath()); err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	if r.alerts, err = alert.New(ctx, r.db); err != nil {
		return nil, fmt.Errorf("initialize alerts: %w", err)
	}
	if r.core, err = control.NewWithVersion(ctx, r.db, control.AlertObserver{Engine: r.alerts}, version); err != nil {
		return nil, fmt.Errorf("initialize collection: %w", err)
	}
	versionRoutes := http.NewServeMux()
	if err = update.Register(versionRoutes, filepath.Dir(data.DBPath()), version, repo, opts); err != nil {
		return nil, err
	}
	r.Handler = httpapi.NewAPI(r.db, r.core.Register, r.alerts.Register, func(mux *http.ServeMux) {
		mux.Handle("/api/v1/version", versionRoutes)
		mux.Handle("/api/v1/version/update", versionRoutes)
		mux.Handle("/api/v1/version/update/apply", versionRoutes)
	})
	return r, nil
}

func (r *Runtime) DBPath() string { return r.data.DBPath() }

func (r *Runtime) Close() (err error) {
	if r.core != nil {
		r.core.Close()
	}
	if r.alerts != nil {
		r.alerts.Close()
	}
	if r.db != nil {
		err = r.db.Close()
	}
	return errors.Join(err, r.data.Close())
}

func DatabaseCommand(ctx context.Context, dir, backupPath, restorePath string, output io.Writer) (err error) {
	data, err := appdata.Open(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, data.Close()) }()
	if backupPath != "" {
		if err := store.BackupFile(ctx, data.DBPath(), backupPath); err != nil {
			return err
		}
		_, err := fmt.Fprintln(output, "Backup saved:", backupPath)
		return err
	}
	rollback, err := store.RestoreFile(ctx, restorePath, data.DBPath())
	if rollback != "" {
		_, writeErr := fmt.Fprintln(output, "Rollback backup:", rollback)
		err = errors.Join(err, writeErr)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "Database restored.")
	return err
}
