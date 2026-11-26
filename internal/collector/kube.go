package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	requestTimeout = 5 * time.Second
	pageLimit      = 8 << 20
	pageSize       = "200"
)

var kubePaths = map[string]string{
	"namespaces":      "/api/v1/namespaces",
	"nodes":           "/api/v1/nodes",
	"pods":            "/api/v1/pods",
	"services":        "/api/v1/services",
	"deployments":     "/apis/apps/v1/deployments",
	"endpoint_slices": "/apis/discovery.k8s.io/v1/endpointslices",
}

type kubeConnection struct {
	base   string
	client *http.Client
}

func openKube(ctx context.Context, cfg Config) (*kubeConnection, error) {
	loaded, err := readKubeconfig(cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	selected := cfg.Context
	if selected == "" {
		selected = loaded.CurrentContext
	}
	selectedContext := loaded.Contexts[selected]
	if selected == "" || selectedContext == nil {
		return nil, fail("invalid_context")
	}
	cluster := loaded.Clusters[selectedContext.Cluster]
	if cluster == nil || cluster.InsecureSkipTLSVerify {
		return nil, fail("insecure_tls")
	}
	u, err := url.Parse(cluster.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fail("insecure_tls")
	}
	var login *approvedPlugin
	if auth := loaded.AuthInfos[selectedContext.AuthInfo]; auth != nil {
		if auth.AuthProvider != nil {
			return nil, fail("auth_provider_unsupported")
		}
		if auth.Exec != nil {
			login, err = readPlugin(auth.Exec, cluster)
			if err != nil {
				return nil, err
			}
			if cfg.KubeExecSHA256 == "" || cfg.KubeExecSHA256 != login.digest {
				return nil, fail("exec_approval_required")
			}
		}
	}
	restConfig, err := clientcmd.NewNonInteractiveClientConfig(*loaded, selected, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, fail("invalid_kubeconfig")
	}
	restConfig.Timeout = requestTimeout
	if login != nil {
		if err := login.authenticate(ctx, restConfig); err != nil {
			return nil, err
		}
	}
	client, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, fail("invalid_kube_tls_or_credentials")
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &kubeConnection{base: strings.TrimRight(u.String(), "/"), client: client}, nil
}

func (k *kubeConnection) request(ctx context.Context, method, path string, query url.Values, payload []byte, result any) (err error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	endpoint := k.base + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fail("invalid_endpoint")
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := k.client.Do(request)
	if err != nil {
		var ssl *tls.CertificateVerificationError
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &ssl) || errors.As(err, &unknown) {
			return fail("tls_verification_failed")
		}
		return networkError(ctx, err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated:
	case http.StatusUnauthorized:
		return fail("authentication_failed")
	case http.StatusForbidden:
		return fail("permission_denied")
	case http.StatusNotFound:
		return fail("not_found")
	case http.StatusConflict:
		return fail("version_conflict")
	case http.StatusGone:
		return fail("resource_expired")
	case http.StatusTooManyRequests:
		return fail("rate_limited")
	case http.StatusMethodNotAllowed, http.StatusUnprocessableEntity, http.StatusBadRequest:
		return fail("request_rejected")
	default:
		return fail("api_request_failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, pageLimit+1))
	if err != nil {
		return networkError(ctx, err)
	}
	if len(data) > pageLimit {
		return fail("output_limit")
	}
	if err = json.Unmarshal(data, result); err != nil {
		return fail("invalid_response")
	}
	return nil
}

type ownerReference struct {
	Kind       string `json:"kind"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}

type objectMeta struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	UID        string            `json:"uid"`
	Generation int64             `json:"generation"`
	Version    string            `json:"resourceVersion"`
	Labels     map[string]string `json:"labels"`
	Owners     []ownerReference  `json:"ownerReferences"`
	CreatedAt  time.Time         `json:"creationTimestamp"`
	DeletedAt  *time.Time        `json:"deletionTimestamp"`
}

type kubeList struct {
	Meta struct {
		Cursor string `json:"continue"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

func (k *kubeConnection) firstPage(ctx context.Context, path string, limit string) (kubeList, error) {
	var page kubeList
	err := k.request(ctx, http.MethodGet, path, url.Values{"limit": {limit}}, nil, &page)
	if err == nil && page.Items == nil {
		err = fail("invalid_response")
	}
	return page, err
}

func (k *kubeConnection) identity(ctx context.Context, expected string) (string, error) {
	var identity struct {
		Meta objectMeta `json:"metadata"`
	}
	if err := k.request(ctx, http.MethodGet, kubePaths["namespaces"]+"/kube-system", nil, nil, &identity); err != nil {
		return "", err
	}
	if identity.Meta.UID == "" {
		return "", fail("invalid_response")
	}
	if expected != "" && identity.Meta.UID != expected {
		return "", fail("identity_changed")
	}
	return identity.Meta.UID, nil
}

func (k *kubeConnection) probe(ctx context.Context, expected string) (string, error) {
	identity, err := k.identity(ctx, expected)
	if err != nil {
		return "", err
	}
	if _, err = k.firstPage(ctx, kubePaths["nodes"], pageSize); err != nil {
		return "", err
	}
	return identity, nil
}

func (k *kubeConnection) warnings(ctx context.Context) []string {
	var result []string
	for _, kind := range []string{"namespaces", "deployments", "pods", "services", "endpoint_slices"} {
		if ctx.Err() != nil {
			break
		}
		if _, err := k.firstPage(ctx, kubePaths[kind], "1"); err != nil {
			code := Code(err)
			if kind == "endpoint_slices" && code == "not_found" {
				code = "unsupported"
			}
			result = append(result, kind+"_"+code)
		}
	}
	return result
}

func (k *kubeConnection) list(ctx context.Context, path string, consume func(json.RawMessage) error, reset func()) error {
	for attempt := 0; attempt < 2; attempt++ {
		cursor := ""
		consumed := make(map[string]struct{})
		for {
			params := url.Values{"limit": {pageSize}}
			if cursor != "" {
				params.Set("continue", cursor)
			}
			var page kubeList
			err := k.request(ctx, http.MethodGet, path, params, nil, &page)
			if Code(err) == "resource_expired" && attempt == 0 {
				reset()
				break
			}
			if err != nil {
				return err
			}
			if page.Items == nil {
				return fail("invalid_response")
			}
			for _, item := range page.Items {
				if err = consume(item); err != nil {
					return err
				}
			}
			cursor = page.Meta.Cursor
			if cursor == "" {
				return nil
			}
			if _, ok := consumed[cursor]; ok {
				return fail("invalid_response")
			}
			consumed[cursor] = struct{}{}
		}
	}
	return fail("resource_expired")
}

type condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func conditionStatus(conditions []condition, kind string) string {
	for _, item := range conditions {
		if item.Type == kind {
			switch item.Status {
			case "True", "False", "Unknown":
				return item.Status
			}
			break
		}
	}
	return "Unknown"
}

type deployment struct {
	Meta objectMeta `json:"metadata"`
	Spec struct {
		Desired *int32 `json:"replicas"`
		Paused  bool   `json:"paused"`
	} `json:"spec"`
	Status struct {
		Generation int64       `json:"observedGeneration"`
		Ready      int32       `json:"readyReplicas"`
		Actual     int32       `json:"replicas"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

func (d deployment) desired() int32 {
	if d.Spec.Desired == nil {
		return 1
	}
	return *d.Spec.Desired
}

func (d deployment) state(previous *int32) *string {
	var state string
	current := d.Status.Generation >= d.Meta.Generation
	desired := d.desired()
	if current && desired > 0 && d.Status.Ready < desired {
		for _, con := range d.Status.Conditions {
			if (con.Type == "Progressing" && con.Reason == "ProgressDeadlineExceeded" && con.Status == "False") ||
				(con.Type == "ReplicaFailure" && con.Status == "True") {
				state = "failed"
				return &state
			}
		}
	}
	switch {
	case current && desired > 0 && d.Status.Ready >= desired:
		state = "running"
	case current && desired == 0 && d.Status.Actual == 0 && d.Status.Ready == 0:
		state = "stopped"
	case previous != nil && *previous == 0 && desired > 0:
		state = "starting"
	default:
		return nil
	}
	return &state
}

func (d deployment) projection(previous *int32) map[string]any {
	v := metadataRow(d.Meta)
	v["source"] = "cluster"
	v["desired"] = d.desired()
	v["ready"] = d.Status.Ready
	v["replicas"] = d.Status.Actual
	v["observed_generation"] = d.Status.Generation
	v["generation"] = d.Meta.Generation
	v["state"] = d.state(previous)
	v["paused"] = d.Spec.Paused
	status := "ready"
	switch {
	case d.Status.Generation < d.Meta.Generation:
		status = "updating"
	case d.desired() == 0 && d.Status.Actual == 0:
		status = "scaled_down"
	case d.desired() == 0:
		status = "scaling_down"
	case d.Status.Ready < d.desired():
		status = "replicas_insufficient"
	}
	v["status"] = status
	return v
}

func metadataRow(meta objectMeta) map[string]any {
	return map[string]any{"uid": meta.UID, "name": meta.Name, "namespace": meta.Namespace, "deleting": meta.DeletedAt != nil}
}

func projectKube(group string, data []byte, previous map[string]int32) (Row, error) {
	if group == "deployments" {
		var d deployment
		if json.Unmarshal(data, &d) != nil || d.Meta.UID == "" || d.Meta.Name == "" || d.Meta.Namespace == "" {
			return Row{}, fail("invalid_response")
		}
		var old *int32
		if replicas, ok := previous[d.Meta.UID]; ok {
			old = &replicas
		}
		return row(d.Meta.UID, d.projection(old))
	}
	var item struct {
		Meta objectMeta `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			Phase      string      `json:"phase"`
			Conditions []condition `json:"conditions"`
		} `json:"status"`
	}
	if json.Unmarshal(data, &item) != nil || item.Meta.UID == "" || item.Meta.Name == "" {
		return Row{}, fail("invalid_response")
	}
	result := metadataRow(item.Meta)
	switch group {
	case "namespaces":
		result["phase"] = item.Status.Phase
	case "nodes":
		ready := conditionStatus(item.Status.Conditions, "Ready")
		result["ready"], result["state"] = ready, ready
	case "pods":
		if item.Meta.Namespace == "" {
			return Row{}, fail("invalid_response")
		}
		ready := conditionStatus(item.Status.Conditions, "Ready")
		result["phase"], result["ready"], result["node"] = item.Status.Phase, ready, item.Spec.NodeName
		result["node_name"] = item.Spec.NodeName
		result["abnormal"] = item.Meta.DeletedAt == nil &&
			(item.Status.Phase == "Failed" || item.Status.Phase == "Unknown" || (item.Status.Phase == "Running" && ready == "False"))
	default:
		return Row{}, fail("invalid_group")
	}
	return row(item.Meta.UID, result)
}

func (k *kubeConnection) collect(ctx context.Context, group string, opts Options) ([]Row, error) {
	path, known := kubePaths[group]
	if !known || group == "endpoint_slices" {
		return nil, fail("invalid_group")
	}
	if group == "services" {
		return k.collectServices(ctx)
	}
	previous := make(map[string]int32)
	if group == "deployments" {
		for _, r := range opts.Previous {
			var old struct {
				Desired *int32  `json:"desired"`
				State   *string `json:"state"`
			}
			if json.Unmarshal(r.Data, &old) == nil && old.Desired != nil {
				previous[r.Key] = *old.Desired
				if old.State != nil && *old.State == "starting" {
					previous[r.Key] = 0
				}
			}
		}
	}
	rows := make([]Row, 0)
	keys := make(map[string]bool)
	err := k.list(ctx, path, func(raw json.RawMessage) error {
		r, err := projectKube(group, raw, previous)
		if err != nil {
			return err
		}
		if keys[r.Key] {
			return fail("invalid_response")
		}
		keys[r.Key] = true
		rows = append(rows, r)
		return nil
	}, func() {
		rows = rows[:0]
		clear(keys)
	})
	if err != nil {
		return nil, err
	}
	if group == "deployments" && len(rows) > 0 {
		k.addDeploymentUsage(ctx, rows)
	}
	return rows, nil
}
