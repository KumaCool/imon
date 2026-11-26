// Package control coordinates local binding, collection, and resource queries.
package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

var (
	errConflict    = errors.New("conflict")
	errUnconfirmed = errors.New("result_unconfirmed")
	errIdentity    = errors.New("identity_changed")
	errForbidden   = errors.New("not_authorized")
	errInvalid     = errors.New("invalid_request")
)

type Observation struct {
	TargetID, TargetName, Group, BatchID                 string
	Period                                               time.Duration
	At                                                   time.Time
	Scheduled, PollingEnabled, CurrentSettings, Complete bool
	Rows                                                 []collector.Row
}

type Observer interface {
	Observe(context.Context, *sql.Tx, Observation) error
	Stop(context.Context, *sql.Tx, string, string) error
	Reset(context.Context, *sql.Tx) error
}

type Control struct {
	db               *store.Store
	observer         Observer
	version          string
	firewallProbeMu  sync.Mutex
	firewallProbes   map[firewallProbeKey]*firewallProbe
	ctx              context.Context
	stop             context.CancelFunc
	mu               sync.Mutex
	wg               sync.WaitGroup
	probes           chan struct{}
	proofs           map[string]proof
	sshConfirmations map[string]sshConfirmation
	wake             chan struct{}
	due              map[string]map[string]time.Time
	failures         map[string]int
	backoff          map[string]time.Time
	active           map[string]*collection
	queued           map[string]*collection
	round            map[string]*scheduledTarget
	ruleSet          map[string]scheduledRules
	streak           map[string]int
	settings         Settings
	incidentMu       sync.Mutex
	incidents        []collectionIncident
}

func New(ctx context.Context, db *store.Store, observer Observer) (*Control, error) {
	return NewWithVersion(ctx, db, observer, "")
}

func NewWithVersion(ctx context.Context, db *store.Store, observer Observer, version string) (*Control, error) {
	ctx, stop := context.WithCancel(ctx)
	c := &Control{db: db, observer: observer, version: version, ctx: ctx, stop: stop, probes: make(chan struct{}, 4), proofs: map[string]proof{}, sshConfirmations: map[string]sshConfirmation{}, wake: make(chan struct{}, 1), due: map[string]map[string]time.Time{}, failures: map[string]int{}, backoff: map[string]time.Time{}, active: map[string]*collection{}, queued: map[string]*collection{}, streak: map[string]int{}}
	err := db.Write(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT poll_enabled,host_interval,network_interval,cluster_interval,timeout,revision FROM sampling_settings WHERE id=1`).Scan(&c.settings.Enabled, &c.settings.Host, &c.settings.Network, &c.settings.Cluster, &c.settings.Timeout, &c.settings.Revision); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET status=CASE WHEN kind='collect' OR status='queued' THEN 'canceled' ELSE 'unknown' END,completed_at=?,error_code='process_restarted' WHERE status IN ('queued','running')`, time.Now().UnixMilli()); err != nil {
			return err
		}
		if observer != nil {
			return observer.Reset(ctx, tx)
		}
		return nil
	})
	if err != nil {
		stop()
		return nil, err
	}
	c.wg.Go(c.loop)
	return c, nil
}

func (c *Control) Close() { c.stop(); c.wg.Wait() }

func (c *Control) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/targets/test", c.testTarget)
	mux.HandleFunc("POST /api/v1/targets/kube-exec-approval", c.kubeExecApproval)
	mux.HandleFunc("GET /api/v1/hosts/{id}/firewall-authorization", c.firewallAuthorization)
	mux.HandleFunc("POST /api/v1/hosts/{id}/firewall-maintenance", c.firewallMaintenance)
	mux.HandleFunc("POST /api/v1/targets/{id}/maintenance/upload", c.firewallUpload)
	mux.HandleFunc("GET /api/v1/jobs/{id}/firewall-script", c.downloadFirewall)
	mux.HandleFunc("POST /api/v1/targets", c.saveTarget)
	mux.HandleFunc("PATCH /api/v1/targets/{id}", c.saveTarget)
	mux.HandleFunc("DELETE /api/v1/targets/{id}", c.unbind)
	mux.HandleFunc("GET /api/v1/targets", c.listTargets)
	mux.HandleFunc("GET /api/v1/targets/{id}", c.getTarget)
	mux.HandleFunc("PUT /api/v1/targets/{id}/node-link", c.nodeLink)
	mux.HandleFunc("DELETE /api/v1/targets/{id}/node-link", c.nodeLink)
	mux.HandleFunc("GET /api/v1/sampling-settings", c.getSettings)
	mux.HandleFunc("PUT /api/v1/sampling-settings", c.putSettings)
	mux.HandleFunc("POST /api/v1/collection-requests", c.requestCollection)
	mux.HandleFunc("GET /api/v1/collection-status", c.collectionStatus)
	mux.HandleFunc("GET /api/v1/jobs/{id}", c.getJob)
	mux.HandleFunc("GET /api/v1/hosts/{id}/metrics", c.metrics)
	mux.HandleFunc("GET /api/v1/hosts/{id}/network/{group}", c.network)
	mux.HandleFunc("GET /api/v1/clusters/{id}/resources/{group}", c.resources)
	mux.HandleFunc("GET /api/v1/services", c.services)
	mux.HandleFunc("GET /api/v1/services/{id}", c.getService)
	mux.HandleFunc("GET /api/v1/targets/{id}/service-authorization", c.authorization)
	mux.HandleFunc("PUT /api/v1/targets/{id}/service-authorization", c.authorization)
	mux.HandleFunc("DELETE /api/v1/targets/{id}/service-authorization", c.authorization)
	mux.HandleFunc("POST /api/v1/services/{id}/actions", c.serviceAction)
}

func collectionError(err error) string { return collector.Code(err) }
func newID() string                    { return randID() }

func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	typ, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if typ != "application/json" {
		fail(w, 415, "invalid_content_type", "需要 JSON 请求")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil || d.Decode(new(any)) != io.EOF {
		fail(w, 400, "invalid_request", "请求参数无效")
		return false
	}
	return true
}

func send(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	send(w, status, map[string]any{"code": code, "message": message, "retryable": status == 503})
}
func report(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, sql.ErrNoRows):
		fail(w, 404, "not_found", "对象不存在")
	case errors.Is(err, errConflict), errors.Is(err, store.ErrStaleTarget), errors.Is(err, store.ErrSnapshotMoved):
		fail(w, 409, "conflict", "状态已变化或仍有任务在执行，请刷新")
	case errors.Is(err, errUnconfirmed):
		fail(w, 409, "result_unconfirmed", "上一项远端操作结果待核实")
	case errors.Is(err, errIdentity):
		fail(w, 409, "identity_changed", "连接身份已变化，请重新绑定")
	case errors.Is(err, errForbidden):
		fail(w, 403, "not_authorized", "此对象尚未授权")
	case errors.Is(err, errInvalid):
		fail(w, 400, "invalid_request", "请求参数无效")
	default:
		fail(w, 503, "storage_unavailable", "本地存储暂不可用")
	}
}
