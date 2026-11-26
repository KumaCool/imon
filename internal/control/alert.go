package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"imon/internal/alert"
)

type AlertObserver struct{ Engine *alert.Engine }

func (a AlertObserver) Reset(ctx context.Context, tx *sql.Tx) error {
	return a.Engine.ResetPending(ctx, tx)
}
func (a AlertObserver) Stop(ctx context.Context, tx *sql.Tx, id, reason string) error {
	return a.Engine.StopTarget(ctx, tx, id, reason)
}

func (a AlertObserver) Collection(ctx context.Context, tx *sql.Tx, targetID string, rev int64, group, code string, at time.Time) error {
	return a.Engine.ObserveCollection(ctx, tx, targetID, rev, group, code, at)
}
func (a AlertObserver) Observe(ctx context.Context, tx *sql.Tx, o Observation) error {
	n := alert.Observation{TargetID: o.TargetID, TargetName: o.TargetName, Group: o.Group, BatchID: o.BatchID, ObservedAt: o.At, Period: o.Period, Scheduled: o.Scheduled, PollingEnabled: o.PollingEnabled, CurrentSettings: o.CurrentSettings, Complete: o.Complete}
	if n.Group == "host_metrics" {
		n.Group = "metrics"
	}
	if o.Complete && o.Group == "listeners" {
		n.CompleteListenerKinds = []string{"tcp/ipv4", "tcp/ipv6", "udp/ipv4", "udp/ipv6"}
	}
	for _, row := range o.Rows {
		var fields map[string]any
		if json.Unmarshal(row.Data, &fields) != nil {
			continue
		}
		str := func(key string) string { v, _ := fields[key].(string); return v }
		selector := alert.Selector{TargetID: o.TargetID, Name: str("name"), Namespace: str("namespace")}
		add := func(metric string, v any) {
			if v == nil {
				return
			}
			s := selector
			s.Metric = metric
			n.Values = append(n.Values, alert.Value{Selector: s, ObjectName: str("name"), Value: v})
		}
		switch o.Group {
		case "probe":
			add("target_reachable", fields["reachable"])
		case "host_metrics":
			selector.Mountpoint = str("mountpoint")
			selector.Interface = str("interface")
			for _, v := range metricValues(row) {
				metric := map[string]string{"cpu_percent": "cpu_usage_percent", "memory_percent": "memory_usage_percent", "disk_percent": "disk_usage_percent", "available_bytes": "disk_available_bytes", "total_bytes": "disk_capacity_bytes", "rx_bytes_per_second": "network_receive_bytes_per_second", "tx_bytes_per_second": "network_transmit_bytes_per_second"}[v.Metric]
				add(metric, v.Value)
			}
		case "systemd":
			selector.Unit = row.Key
			add("systemd_state", fields["state"])
		case "listeners":
			port, _ := fields["port"].(float64)
			selector.Port = int(port)
			selector.Protocol = str("protocol")
			selector.Family = str("family")
			selector.Address = str("address")
			add("port_listening", true)
		case "nodes":
			selector.UID = row.Key
			add("node_ready", readyValue(str("ready")))
		case "pods":
			selector.UID = row.Key
			add("pod_phase", str("phase"))
			add("pod_ready", readyValue(str("ready")))
		case "deployments":
			selector.UID = row.Key
			add("deployment_state", fields["state"])
			desired, dok := fields["desired"].(float64)
			ready, rok := fields["ready"].(float64)
			observed, ook := fields["observed_generation"].(float64)
			generation, gok := fields["generation"].(float64)
			if dok && rok && ook && gok && observed >= generation && desired > 0 {
				add("deployment_replica_gap", max(desired-ready, 0))
			}
		}
	}
	return a.Engine.Observe(ctx, tx, n)
}

func readyValue(status string) any {
	switch status {
	case "True":
		return true
	case "False":
		return false
	default:
		return nil
	}
}
