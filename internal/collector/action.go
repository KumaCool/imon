package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

type ActionRequest struct {
	Action          string
	Key             string
	Name            string
	Namespace       string
	ExpectedState   string
	ExpectedDesired *int32
	Replicas        *int32
}

type ActionResult struct {
	State           string `json:"state,omitempty"`
	Desired         *int32 `json:"desired,omitempty"`
	PreviousDesired *int32 `json:"previous_desired,omitempty"`
	Sent            bool   `json:"sent"`
	Confirmed       bool   `json:"confirmed"`
}

func RunServiceAction(ctx context.Context, kind string, cfg Config, identity string, req ActionRequest, beforeWrite func(oldDesired int32) error) (ActionResult, error) {
	if identity == "" || beforeWrite == nil || !actionStateValid(req.Action, req.ExpectedState) {
		return ActionResult{}, fail("invalid_action")
	}
	switch kind {
	case "host", "linux":
		return runUnitAction(ctx, cfg, identity, req, beforeWrite)
	case "cluster", "kubernetes":
		return runDeploymentAction(ctx, cfg, identity, req, beforeWrite)
	default:
		return ActionResult{}, fail("invalid_kind")
	}
}

// WaitDeployment observes convergence without sending another scale request.
func WaitDeployment(ctx context.Context, cfg Config, identity string, req ActionRequest, desired int32) (string, error) {
	k, err := openKube(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer k.client.CloseIdleConnections()
	if _, err := k.identity(ctx, identity); err != nil {
		return "", err
	}
	path := "/apis/apps/v1/namespaces/" + req.Namespace + "/deployments/" + req.Name
	want := "running"
	if desired == 0 {
		want = "stopped"
	}
	for {
		var current deployment
		if err := k.request(ctx, http.MethodGet, path, nil, nil, &current); err != nil {
			return "", err
		}
		if current.Meta.UID != req.Key || current.Meta.DeletedAt != nil || current.desired() != desired {
			return "", fail("state_changed")
		}
		if state := current.state(nil); state != nil && (*state == want || *state == "failed") {
			return *state, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func actionStateValid(action, state string) bool {
	return (action == "stop" && state == "running") ||
		(action == "start" && (state == "stopped" || state == "failed"))
}

func runUnitAction(ctx context.Context, cfg Config, identity string, req ActionRequest, beforeWrite func(int32) error) (ActionResult, error) {
	result := ActionResult{}
	if !ValidSystemdServiceUnit(req.Key) || req.Name != req.Key || req.Namespace != "" || req.ExpectedDesired != nil || req.Replicas != nil {
		return result, fail("invalid_action")
	}
	s, err := Open(ctx, "host", cfg, identity)
	if err != nil {
		return result, err
	}
	defer s.Close()
	read := func() (unitStatus, error) {
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		response, err := s.ssh.run(readCtx, showUnitsCommand+" "+shellQuote(req.Key))
		if err != nil {
			return unitStatus{}, err
		}
		parsed, err := parseUnits(response)
		if err != nil {
			return unitStatus{}, err
		}
		unit, ok := parsed[req.Key]
		if !ok || len(parsed) != 1 || unit.Load != "loaded" {
			return unitStatus{}, fail("object_changed")
		}
		return unit, nil
	}
	current, err := read()
	if err != nil {
		return result, err
	}
	if current.State == nil || *current.State != req.ExpectedState {
		return result, fail("state_changed")
	}
	if err := beforeWrite(0); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	result.Sent = true
	writeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	systemctl := "/usr/bin/systemctl " + req.Action + " -- " + shellQuote(req.Key)
	// Decide between the already-authorized native path and the host helper
	// before changing anything. Never retry a failed mutation through another
	// identity because systemctl might have already submitted the job.
	command := locale + `
if [ "$(/usr/bin/id -u)" = 0 ]; then
  exec ` + systemctl + `
fi
if sudo -n -l -- ` + systemctl + ` >/dev/null 2>&1; then
  exec sudo -n -- ` + systemctl + `
fi
` + helperPathCommand + `
[ -x "$helper" ] || exit 126
sudo -n -l -- "$helper" service >/dev/null 2>&1 || exit 126
imon_payload | sudo -n -- "$helper" service`
	_, err = s.ssh.runInput(writeCtx, command, maxSSHOutput, []byte(req.Action+"\n"+req.Key+"\n"))
	if err != nil {
		switch Code(err) {
		case "permission_denied", "service_helper_upgrade_required", "service_action_not_run":
			result.Sent = false
		}
		return result, err
	}
	observed, err := read()
	if err != nil {
		return result, err
	}
	if observed.State != nil {
		result.State = *observed.State
	}
	target := "running"
	if req.Action == "stop" {
		target = "stopped"
	}
	if result.State != target {
		return result, fail("result_unconfirmed")
	}
	result.Confirmed = true
	return result, nil
}

var kubeName = regexp.MustCompile("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")

func runDeploymentAction(ctx context.Context, cfg Config, identity string, req ActionRequest, beforeWrite func(int32) error) (ActionResult, error) {
	result := ActionResult{}
	if req.Key == "" || !kubeName.MatchString(req.Name) || !kubeName.MatchString(req.Namespace) || req.ExpectedDesired == nil {
		return result, fail("invalid_action")
	}
	if (req.Action == "start" && (*req.ExpectedDesired != 0 || req.Replicas == nil || *req.Replicas <= 0)) ||
		(req.Action == "stop" && (*req.ExpectedDesired <= 0 || req.Replicas != nil)) {
		return result, fail("invalid_action")
	}
	k, err := openKube(ctx, cfg)
	if err != nil {
		return result, err
	}
	defer k.client.CloseIdleConnections()
	if _, err := k.identity(ctx, identity); err != nil {
		return result, err
	}
	path := "/apis/apps/v1/namespaces/" + req.Namespace + "/deployments/" + req.Name
	var current deployment
	if err := k.request(ctx, http.MethodGet, path, nil, nil, &current); err != nil {
		return result, err
	}
	if current.Meta.UID != req.Key || current.Meta.Name != req.Name || current.Meta.Namespace != req.Namespace ||
		current.Meta.Version == "" || current.Meta.DeletedAt != nil || current.Spec.Paused {
		return result, fail("object_changed")
	}
	state := current.state(nil)
	desired := current.desired()
	if state == nil || *state != req.ExpectedState || desired != *req.ExpectedDesired {
		return result, fail("state_changed")
	}
	if err := k.validateNoHPA(ctx, req.Namespace, req.Name); err != nil {
		return result, err
	}
	var scale scaleResource
	if err := k.request(ctx, http.MethodGet, path+"/scale", nil, nil, &scale); err != nil {
		return result, err
	}
	if scale.Meta.UID != req.Key || scale.Meta.Version != current.Meta.Version || scale.Spec == nil || scale.Spec.Replicas != desired {
		return result, fail("version_conflict")
	}
	result.PreviousDesired = &desired
	next := int32(0)
	if req.Action == "start" {
		next = *req.Replicas
	}
	scale.Spec.Replicas = next
	body, err := json.Marshal(scale)
	if err != nil {
		return result, fail("invalid_request")
	}
	if err := beforeWrite(desired); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	result.Sent = true
	var written scaleResource
	if err := k.request(ctx, http.MethodPut, path+"/scale", nil, body, &written); err != nil {
		switch Code(err) {
		case "authentication_failed", "permission_denied", "not_found", "version_conflict", "request_rejected":
			result.Sent = false
		}
		return result, err
	}
	if written.Meta.UID != req.Key || written.Spec == nil || written.Spec.Replicas != next {
		return result, fail("result_unconfirmed")
	}
	var observed scaleResource
	if err := k.request(ctx, http.MethodGet, path+"/scale", nil, nil, &observed); err != nil {
		return result, err
	}
	if observed.Meta.UID != req.Key || observed.Spec == nil || observed.Spec.Replicas != next {
		return result, fail("result_unconfirmed")
	}
	result.Desired = &next
	result.Confirmed = true
	return result, nil
}

type scaleResource struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Meta       struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
		Version   string `json:"resourceVersion"`
	} `json:"metadata"`
	// Kubernetes can omit replicas in a present spec when the value is zero.
	Spec *struct {
		Replicas int32 `json:"replicas"`
	} `json:"spec"`
}

func (k *kubeConnection) validateNoHPA(ctx context.Context, namespace, name string) error {
	conflict := false
	err := k.list(ctx, "/apis/autoscaling/v2/namespaces/"+namespace+"/horizontalpodautoscalers", func(raw json.RawMessage) error {
		var hpa struct {
			Spec struct {
				Target struct {
					APIVersion string `json:"apiVersion"`
					Kind       string `json:"kind"`
					Name       string `json:"name"`
				} `json:"scaleTargetRef"`
			} `json:"spec"`
		}
		if json.Unmarshal(raw, &hpa) != nil || hpa.Spec.Target.Name == "" || hpa.Spec.Target.Kind == "" {
			return fail("invalid_response")
		}
		if hpa.Spec.Target.Name == name && hpa.Spec.Target.Kind == "Deployment" {
			conflict = true
		}
		return nil
	}, func() { conflict = false })
	if err != nil {
		return err
	}
	if conflict {
		return fail("autoscaler_present")
	}
	return nil
}
