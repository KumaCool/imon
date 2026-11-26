package control

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"imon/internal/firewall"
	"imon/internal/store"
)

func queryFixture(t *testing.T) (*store.Store, *http.ServeMux) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
	queryOK(t, err)
	t.Cleanup(func() { queryOK(t, db.Close()) })
	c := &Control{db: db}
	mux := http.NewServeMux()
	c.Register(mux)
	return db, mux
}

func queryOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func queryTarget(t *testing.T, db *store.Store, id, kind string, revision int64) {
	t.Helper()
	queryOK(t, db.CreateTarget(t.Context(), store.Target{ID: id, Kind: kind, Name: id + "-label", ConnectionRev: revision, Enabled: true}))
}

func publishQuerySnapshot(t *testing.T, db *store.Store, target, group, batch string, items ...store.SnapshotRow) {
	t.Helper()
	key := store.SnapshotKey{TargetID: target, ConnectionRev: 1, Group: group, BatchID: batch}
	ctx := t.Context()
	at := time.Now().UnixMilli()
	queryOK(t, db.StartSnapshot(ctx, key, at))
	queryOK(t, db.StageSnapshotRows(ctx, key, items))
	queryOK(t, db.PublishSnapshot(ctx, key, at, at, nil))
}

func queryAPI(t *testing.T, mux *http.ServeMux, path string, status int, result any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != status {
		t.Fatalf("GET %s: got %d, want %d: %s", path, resp.Code, status, resp.Body.String())
	}
	if result != nil {
		queryOK(t, json.Unmarshal(resp.Body.Bytes(), result))
	}
}

func TestServiceResourceSortingAndPagination(t *testing.T) {
	db, mux := queryFixture(t)
	queryTarget(t, db, "host-fixture", "host", 1)
	queryTarget(t, db, "cluster-fixture", "cluster", 1)
	publishQuerySnapshot(t, db, "host-fixture", "systemd", "host-services",
		store.SnapshotRow{ObjectKey: "idle.service", Payload: json.RawMessage(`{"name":"idle.service","state":"running","cpu_percent":0,"memory_bytes":0}`)},
		store.SnapshotRow{ObjectKey: "unknown.service", Payload: json.RawMessage(`{"name":"unknown.service","state":"stopped"}`)})
	publishQuerySnapshot(t, db, "cluster-fixture", "deployments", "cluster-services",
		store.SnapshotRow{ObjectKey: "busy", Payload: json.RawMessage(`{"name":"busy","namespace":"fixture","state":"running","cpu_percent":125,"memory_bytes":8192}`)})
	type page struct {
		Items []service `json:"items"`
		Next  string    `json:"next_cursor"`
	}
	path := "/api/v1/services?sort=cpu&direction=desc&limit=1"
	var first, second, third page
	queryAPI(t, mux, path, 200, &first)
	if len(first.Items) != 1 || first.Items[0].Name != "busy" || first.Items[0].CPUPercent == nil || *first.Items[0].CPUPercent != 125 || first.Next == "" {
		t.Fatalf("unexpected first page: %+v", first)
	}
	queryAPI(t, mux, path+"&cursor="+url.QueryEscape(first.Next), 200, &second)
	if len(second.Items) != 1 || second.Items[0].Name != "idle.service" || second.Items[0].CPUPercent == nil || *second.Items[0].CPUPercent != 0 || second.Next == "" {
		t.Fatalf("unexpected second page: %+v", second)
	}
	queryAPI(t, mux, path+"&cursor="+url.QueryEscape(second.Next), 200, &third)
	if len(third.Items) != 1 || third.Items[0].Name != "unknown.service" || third.Items[0].CPUPercent != nil || third.Items[0].MemoryBytes != nil || third.Next != "" {
		t.Fatalf("unexpected third page: %+v", third)
	}
	var memory page
	queryAPI(t, mux, "/api/v1/services?sort=memory", 200, &memory)
	if len(memory.Items) != 3 || memory.Items[0].Name != "idle.service" || memory.Items[0].MemoryBytes == nil || *memory.Items[0].MemoryBytes != 0 ||
		memory.Items[1].Name != "busy" || memory.Items[2].Name != "unknown.service" {
		t.Fatalf("unexpected memory ordering: %+v", memory)
	}
	queryAPI(t, mux, "/api/v1/services?sort=memory&cursor="+url.QueryEscape(first.Next), 400, nil)
	queryAPI(t, mux, "/api/v1/services?sort=unsupported", 400, nil)
}

func TestHostServicesUseDedicatedGrantOnlyForListedUnits(t *testing.T) {
	db, mux := queryFixture(t)
	queryTarget(t, db, "host-fixture", "host", 1)
	publishQuerySnapshot(t, db, "host-fixture", "systemd", "host-services",
		store.SnapshotRow{ObjectKey: "valid.service", Payload: json.RawMessage(`{"name":"valid.service","state":"running"}`)},
		store.SnapshotRow{ObjectKey: "other.service", Payload: json.RawMessage(`{"name":"other.service","state":"running"}`)})
	type page struct {
		Items []service `json:"items"`
	}
	read := func() []service {
		t.Helper()
		var got page
		queryAPI(t, mux, "/api/v1/services?sort=name", 200, &got)
		if len(got.Items) != 2 {
			t.Fatalf("unexpected services: %+v", got)
		}
		return got.Items
	}
	before := read()
	if !before[0].Authorized || !before[0].UsesHostLogin || !before[1].Authorized || !before[1].UsesHostLogin {
		t.Fatalf("services didn't use the bound login: %+v", before)
	}
	objects, err := json.Marshal([]string{before[1].ID})
	queryOK(t, err)
	queryOK(t, db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO service_authorizations VALUES(?,?,?,?)`, "host-fixture", 1, "{}", string(objects))
		return err
	}))
	after := read()
	if !after[0].Authorized || !after[0].UsesHostLogin || !after[1].Authorized || after[1].UsesHostLogin {
		t.Fatalf("credentials didn't follow the dedicated grant: %+v", after)
	}
}

func TestTargetsFilterAndCurrentProbe(t *testing.T) {
	db, mux := queryFixture(t)
	queryTarget(t, db, "a-cluster", "cluster", 1)
	queryTarget(t, db, "b-host", "host", 1)
	queryTarget(t, db, "c-cluster", "cluster", 1)
	queryTarget(t, db, "d-host", "host", 2)
	queryOK(t, db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO target_probe VALUES ('b-host',1,100,0,'authentication_failed'),('d-host',1,200,1,'')`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO firewall_authorization_observations
			(target_id,connection_rev,status,version,architecture,markers_absent,app_version,observed_at)
			VALUES ('b-host',1,'installed','fixture-digest','amd64',0,'v0.1.0',100)`)
		return err
	}))
	publishQuerySnapshot(t, db, "b-host", "firewall", "firewall-snapshot",
		store.SnapshotRow{ObjectKey: "fixture", Payload: json.RawMessage(`{"backend":"nftables","status":"ok"}`)})
	type page struct {
		Items []targetView `json:"items"`
		Next  string       `json:"next_cursor"`
	}
	var first, last page
	queryAPI(t, mux, "/api/v1/targets?kind=host&limit=1", 200, &first)
	available, _ := firewall.Version("amd64")
	if len(first.Items) != 1 || first.Items[0].ID != "b-host" || first.Next != "b-host" ||
		first.Items[0].ConnectionStatus != "unreachable" || first.Items[0].ErrorCode != "authentication_failed" ||
		first.Items[0].ProbeObservedAt == nil || *first.Items[0].ProbeObservedAt != 100 ||
		first.Items[0].FirewallStatus != "readable" || first.Items[0].FirewallAuthorizationStatus != "installed" ||
		first.Items[0].HostAuthorizationUpdateAvailable != (available != "") {
		t.Fatalf("unexpected first host page: %+v", first)
	}
	if available != "" {
		queryOK(t, db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE firewall_authorization_observations SET version=? WHERE target_id='b-host'`, available)
			return err
		}))
		var current targetDetail
		queryAPI(t, mux, "/api/v1/targets/b-host", 200, &current)
		if current.FirewallAuthorizationStatus != "installed" || current.HostAuthorizationUpdateAvailable {
			t.Fatalf("current helper marked as updatable: %+v", current)
		}
	}
	queryAPI(t, mux, "/api/v1/targets?kind=host&limit=1&cursor="+url.QueryEscape(first.Next), 200, &last)
	if len(last.Items) != 1 || last.Items[0].ID != "d-host" || last.Next != "" || last.Items[0].ConnectionStatus != "pending" || last.Items[0].ProbeObservedAt != nil || last.Items[0].FirewallAuthorizationStatus != "" {
		t.Fatalf("unexpected final host page: %+v", last)
	}
	queryAPI(t, mux, "/api/v1/targets?kind=other", 400, nil)
}

func TestHostUsageAggregatesDiskAndKeepsOldSemantics(t *testing.T) {
	db, mux := queryFixture(t)
	queryTarget(t, db, "host-fixture", "host", 1)
	publishQuerySnapshot(t, db, "host-fixture", "os_info", "os",
		store.SnapshotRow{ObjectKey: "os", Payload: json.RawMessage(`{"display_name":"Example Linux 12"}`)})
	publishQuerySnapshot(t, db, "host-fixture", "host_metrics", "metrics",
		store.SnapshotRow{ObjectKey: "cpu", Payload: json.RawMessage(`{"cpu_percent":30}`)},
		store.SnapshotRow{ObjectKey: "memory", Payload: json.RawMessage(`{"used_bytes":0,"total_bytes":1024,"memory_percent":0}`)},
		store.SnapshotRow{ObjectKey: "disk:/", Payload: json.RawMessage(`{"used_bytes":50,"total_bytes":100,"disk_percent":80,"mountpoint":"/"}`)},
		store.SnapshotRow{ObjectKey: "disk:/data", Payload: json.RawMessage(`{"used_bytes":60,"total_bytes":100,"disk_percent":60,"mountpoint":"/data","shared_filesystem":"/dev/example-btrfs"}`)},
		store.SnapshotRow{ObjectKey: "disk:/home", Payload: json.RawMessage(`{"used_bytes":60,"total_bytes":100,"disk_percent":60,"mountpoint":"/home","shared_filesystem":"/dev/example-btrfs"}`)},
		store.SnapshotRow{ObjectKey: "disk:/later", Payload: json.RawMessage(`{"used_bytes":30,"total_bytes":50,"disk_percent":60,"mountpoint":"/later"}`)})
	var page struct {
		Items []struct {
			Summary struct {
				Usage   hostUsage `json:"host_usage"`
				DiskOld float64   `json:"disk_percent"`
				OS      struct {
					Name string `json:"display_name"`
				} `json:"os_info"`
			} `json:"summary"`
		} `json:"items"`
	}
	queryAPI(t, mux, "/api/v1/targets?kind=host", 200, &page)
	if len(page.Items) != 1 {
		t.Fatalf("expected one host, got %d", len(page.Items))
	}
	s := page.Items[0].Summary
	if s.OS.Name != "Example Linux 12" || s.DiskOld != 80 || s.Usage.ObservedAt == nil || s.Usage.CPU != nil ||
		s.Usage.Memory == nil || s.Usage.Memory.Used != 0 || s.Usage.Memory.Percent != 0 ||
		s.Usage.Disk == nil || s.Usage.Disk.Used != 140 || s.Usage.Disk.Total != 250 || s.Usage.Disk.Percent != 56 {
		t.Fatalf("unexpected host summary: %+v", s)
	}
}

func TestTargetDetailsReturnOnlyEditableConnectionFields(t *testing.T) {
	db, mux := queryFixture(t)
	queryTarget(t, db, "test-host", "host", 2)
	queryTarget(t, db, "test-cluster", "cluster", 3)
	ssh := `{"address":"192.0.2.10","port":22,"user":"fixture-user","key_file":"/<KEY>","host_key":"<PUBLIC_KEY>"}`
	jump := `{"address":"192.0.2.20","port":2222,"user":"fixture-jump","key_file":"/<JUMP_KEY>","host_key":"<JUMP_PUBLIC_KEY>"}`
	queryOK(t, db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE targets SET connection_ref=? WHERE target_id='test-host'`, `{"ssh":`+ssh+`,"jump":`+jump+`}`); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE targets SET connection_ref=? WHERE target_id='test-cluster'`, `{"kubeconfig":"/<KUBECONFIG>","context":"fixture-context","kube_exec_sha256":"<EXEC_DIGEST>","token":"<TOKEN>"}`)
		return err
	}))
	var list struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	queryAPI(t, mux, "/api/v1/targets", 200, &list)
	if len(list.Items) != 2 || list.Items[0]["config"] != nil || list.Items[1]["config"] != nil {
		t.Fatalf("target list returned connection config: %v", list.Items)
	}
	var address string
	queryOK(t, json.Unmarshal(list.Items[1]["address"], &address))
	if address != "192.0.2.10" || list.Items[1]["user"] != nil || list.Items[1]["key_file"] != nil ||
		list.Items[1]["host_key"] != nil {
		t.Fatalf("target list did not expose only the host address: %v", list.Items[1])
	}
	var host, cluster struct {
		Revision int64           `json:"connection_rev"`
		Config   json.RawMessage `json:"config"`
	}
	queryAPI(t, mux, "/api/v1/targets/test-host", 200, &host)
	queryAPI(t, mux, "/api/v1/targets/test-cluster", 200, &cluster)
	assertConfig := func(raw json.RawMessage, expected string) {
		t.Helper()
		var got, want map[string]any
		queryOK(t, json.Unmarshal(raw, &got))
		queryOK(t, json.Unmarshal([]byte(expected), &want))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected connection fields: got %v, want %v", got, want)
		}
	}
	if host.Revision != 2 || cluster.Revision != 3 {
		t.Fatalf("unexpected target detail revisions: host=%d, cluster=%d", host.Revision, cluster.Revision)
	}
	assertConfig(host.Config, `{"ssh":{"address":"192.0.2.10","port":22,"user":"fixture-user","key_file":"/<KEY>"},"jump":{"address":"192.0.2.20","port":2222,"user":"fixture-jump","key_file":"/<JUMP_KEY>"}}`)
	assertConfig(cluster.Config, `{"kubeconfig":"/<KUBECONFIG>","context":"fixture-context"}`)
}

func TestClusterNamespaceFilterPaginatesOnlyMatches(t *testing.T) {
	db, mux := queryFixture(t)
	queryTarget(t, db, "test-cluster", "cluster", 1)
	publishQuerySnapshot(t, db, "test-cluster", "pods", "batch-a",
		store.SnapshotRow{ObjectKey: "a", Payload: json.RawMessage(`{"namespace":"test-one"}`)},
		store.SnapshotRow{ObjectKey: "b", Payload: json.RawMessage(`{"namespace":"test-two"}`)},
		store.SnapshotRow{ObjectKey: "c", Payload: json.RawMessage(`{"namespace":"test-one"}`)},
		store.SnapshotRow{ObjectKey: "d", Payload: json.RawMessage(`{"namespace":"test-two"}`)},
	)
	var page snapshotView
	base := "/api/v1/clusters/test-cluster/resources/pods?limit=1&namespace="
	queryAPI(t, mux, base+"test-one", 200, &page)
	if len(page.Rows) != 1 || page.Rows[0].ObjectKey != "a" || page.NextCursor == nil {
		t.Fatalf("unexpected first filtered page: %+v", page)
	}
	cursor := "&cursor=" + url.QueryEscape(page.NextCursor.(string))
	queryAPI(t, mux, base+"test-two"+cursor, 409, nil)
	page = snapshotView{}
	queryAPI(t, mux, base+"test-one"+cursor, 200, &page)
	if len(page.Rows) != 1 || page.Rows[0].ObjectKey != "c" || page.NextCursor != nil {
		t.Fatalf("unexpected final filtered page: %+v", page)
	}
}

func TestClusterNamespaceTotalsOnlyUseCompleteSameRoundAndNodeLinksUseUID(t *testing.T) {
	db, mux := queryFixture(t)
	ctx := t.Context()
	queryTarget(t, db, "test-host", "host", 1)
	queryTarget(t, db, "test-cluster", "cluster", 1)
	publishQuerySnapshot(t, db, "test-cluster", "namespaces", "batch-a", store.SnapshotRow{ObjectKey: "ns", Payload: json.RawMessage(`{"name":"test-namespace"}`)})
	publishQuerySnapshot(t, db, "test-cluster", "deployments", "batch-a", store.SnapshotRow{ObjectKey: "dep", Payload: json.RawMessage(`{"namespace":"test-namespace"}`)})
	publishQuerySnapshot(t, db, "test-cluster", "services", "batch-a")
	publishQuerySnapshot(t, db, "test-cluster", "pods", "batch-older", store.SnapshotRow{ObjectKey: "pod", Payload: json.RawMessage(`{"namespace":"test-namespace"}`)})
	failed := store.SnapshotKey{TargetID: "test-cluster", ConnectionRev: 1, Group: "pods", BatchID: "batch-a"}
	queryOK(t, db.StartSnapshot(ctx, failed, 100))
	queryOK(t, db.StageSnapshotRows(ctx, failed, []store.SnapshotRow{{ObjectKey: "partial", Payload: json.RawMessage(`{"namespace":"test-namespace"}`)}}))
	queryOK(t, db.FailSnapshot(ctx, failed, 110, "permission_denied"))
	resource := "/api/v1/clusters/test-cluster/resources/"
	var page snapshotView
	queryAPI(t, mux, resource+"namespaces", 200, &page)
	if len(page.Rows) != 1 {
		t.Fatalf("namespace page has %d rows", len(page.Rows))
	}
	var data map[string]any
	queryOK(t, json.Unmarshal(page.Rows[0].Payload, &data))
	if data["deployment_count"] != float64(1) || data["pod_count"] != nil || data["service_count"] != float64(0) {
		t.Fatalf("incorrect namespace counts: %+v", data)
	}
	publishQuerySnapshot(t, db, "test-cluster", "nodes", "batch-a", store.SnapshotRow{ObjectKey: "node-original", Payload: json.RawMessage(`{"name":"test-node","ready":"True"}`)})
	queryOK(t, db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO node_links VALUES ('test-host','test-cluster','node-original')`)
		return err
	}))
	var target targetView
	queryAPI(t, mux, "/api/v1/targets/test-host", 200, &target)
	if target.NodeLink["status"] != "linked" || target.NodeLink["node_name"] != "test-node" {
		t.Fatalf("link did not resolve by UID: %+v", target.NodeLink)
	}
	page = snapshotView{}
	queryAPI(t, mux, resource+"nodes?namespace=test-namespace", 200, &page)
	if len(page.Rows) != 1 {
		t.Fatalf("nodes page has %d rows", len(page.Rows))
	}
	data = nil
	queryOK(t, json.Unmarshal(page.Rows[0].Payload, &data))
	if data["host_name"] != "test-host-label" || data["host_id"] != "test-host" {
		t.Fatalf("node did not include host label: %+v", data)
	}
	publishQuerySnapshot(t, db, "test-cluster", "nodes", "batch-b", store.SnapshotRow{ObjectKey: "node-replacement", Payload: json.RawMessage(`{"name":"test-node","ready":"True"}`)})
	target = targetView{}
	queryAPI(t, mux, "/api/v1/targets/test-host", 200, &target)
	if target.NodeLink["status"] != "missing" || target.NodeLink["node_name"] != "" {
		t.Fatalf("link incorrectly transferred to recreated node: %+v", target.NodeLink)
	}
}
