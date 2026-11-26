package collector

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	kubePodMetricsPath  = "/apis/metrics.k8s.io/v1beta1/pods"
	kubeReplicaSetsPath = "/apis/apps/v1/replicasets"
	kubeMetricsTimeout  = 3 * time.Second
)

type kubePodMetric struct {
	Meta       objectMeta `json:"metadata"`
	Timestamp  time.Time  `json:"timestamp"`
	Containers []struct {
		Usage map[string]string `json:"usage"`
	} `json:"containers"`
}

type kubeUsage struct {
	cpuPercent  float64
	memoryBytes uint64
	missingCPU  bool
	missingMem  bool
}

func (u *kubeUsage) add(sample kubePodMetric) {
	if len(sample.Containers) == 0 {
		u.missingCPU, u.missingMem = true, true
	}
	for _, container := range sample.Containers {
		if !u.missingCPU {
			cpu, err := resource.ParseQuantity(container.Usage["cpu"])
			value := u.cpuPercent + cpu.AsApproximateFloat64()*100
			if err != nil || cpu.Sign() < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
				u.missingCPU = true
			} else {
				u.cpuPercent = value
			}
		}
		if !u.missingMem {
			memory, err := resource.ParseQuantity(container.Usage["memory"])
			if err != nil || memory.Sign() < 0 || memory.CmpInt64(math.MaxInt64-int64(u.memoryBytes)) > 0 {
				u.missingMem = true
			} else {
				u.memoryBytes += uint64(memory.Value())
			}
		}
	}
}

func controllerUID(meta objectMeta, kind string) string {
	for _, owner := range meta.Owners {
		if owner.Controller && owner.Kind == kind {
			return owner.UID
		}
	}
	return ""
}

func (k *kubeConnection) addDeploymentUsage(ctx context.Context, rows []Row) {
	budget := kubeMetricsTimeout
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)/4)
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	type namespacedKey struct{ namespace, id string }
	metrics := make(map[namespacedKey]kubePodMetric)
	err := k.list(ctx, kubePodMetricsPath, func(raw json.RawMessage) error {
		var sample kubePodMetric
		if json.Unmarshal(raw, &sample) != nil || sample.Meta.Namespace == "" || sample.Meta.Name == "" {
			return fail("invalid_response")
		}
		key := namespacedKey{sample.Meta.Namespace, sample.Meta.Name}
		if _, exists := metrics[key]; exists {
			return fail("invalid_response")
		}
		metrics[key] = sample
		return nil
	}, func() { clear(metrics) })
	// Metrics require separate RBAC and are not served by every cluster.
	if err != nil || len(metrics) == 0 {
		return
	}

	deployments := make(map[namespacedKey]int, len(rows))
	for i, r := range rows {
		var meta objectMeta
		if json.Unmarshal(r.Data, &meta) == nil {
			deployments[namespacedKey{meta.Namespace, r.Key}] = i
		}
	}
	replicaSets := make(map[namespacedKey]int)
	err = k.list(ctx, kubeReplicaSetsPath, func(raw json.RawMessage) error {
		var rs struct {
			Meta objectMeta `json:"metadata"`
		}
		if json.Unmarshal(raw, &rs) != nil || rs.Meta.Namespace == "" || rs.Meta.UID == "" {
			return fail("invalid_response")
		}
		if pos, ok := deployments[namespacedKey{rs.Meta.Namespace, controllerUID(rs.Meta, "Deployment")}]; ok {
			replicaSets[namespacedKey{rs.Meta.Namespace, rs.Meta.UID}] = pos
		}
		return nil
	}, func() { clear(replicaSets) })
	if err != nil || len(replicaSets) == 0 {
		return
	}

	usage := make(map[int]kubeUsage)
	err = k.list(ctx, kubePaths["pods"], func(raw json.RawMessage) error {
		var pod struct {
			Meta   objectMeta `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		}
		if json.Unmarshal(raw, &pod) != nil || pod.Meta.Namespace == "" || pod.Meta.Name == "" || pod.Meta.UID == "" {
			return fail("invalid_response")
		}
		pos, ok := replicaSets[namespacedKey{pod.Meta.Namespace, controllerUID(pod.Meta, "ReplicaSet")}]
		if !ok || pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			return nil
		}
		sample := metrics[namespacedKey{pod.Meta.Namespace, pod.Meta.Name}]
		if (sample.Meta.UID != "" && sample.Meta.UID != pod.Meta.UID) ||
			(!pod.Meta.CreatedAt.IsZero() && sample.Timestamp.Before(pod.Meta.CreatedAt)) {
			sample = kubePodMetric{}
		}
		if pod.Status.Phase == "Pending" && len(sample.Containers) == 0 {
			return nil
		}
		total := usage[pos]
		total.add(sample)
		usage[pos] = total
		return nil
	}, func() { clear(usage) })
	if err != nil || ctx.Err() != nil {
		return
	}
	for i, total := range usage {
		if total.missingCPU && total.missingMem {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(rows[i].Data, &fields) != nil {
			continue
		}
		if !total.missingCPU {
			fields["cpu_percent"], _ = json.Marshal(total.cpuPercent)
		}
		if !total.missingMem {
			fields["memory_bytes"], _ = json.Marshal(total.memoryBytes)
		}
		if data, err := json.Marshal(fields); err == nil {
			rows[i].Data = data
		}
	}
}
