// Package alert evaluates local observations and manages notification delivery.
package alert

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

type Selector struct {
	TargetID   string `json:"target_id"`
	Metric     string `json:"metric"`
	Mountpoint string `json:"mountpoint,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Unit       string `json:"unit,omitempty"`
	UID        string `json:"uid,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Family     string `json:"family,omitempty"`
	Address    string `json:"address,omitempty"`
	Port       int    `json:"port,omitempty"`
}

type Value struct {
	Selector   Selector
	ObjectName string
	Value      any
}

type Observation struct {
	TargetID, TargetName, Group, BatchID                 string
	ObservedAt                                           time.Time
	Scheduled, PollingEnabled, CurrentSettings, Complete bool
	Period                                               time.Duration
	Values                                               []Value
	CompleteListenerKinds                                []string
}

type Condition struct {
	Op    string `json:"op"`
	Value any    `json:"value"`
}

type Trigger struct {
	ConsecutiveSamples *int `json:"consecutive_samples,omitempty"`
	DurationSeconds    *int `json:"duration_seconds,omitempty"`
}

type Channels struct {
	Panel    bool `json:"panel"`
	Telegram bool `json:"telegram"`
	Email    bool `json:"email"`
}

type TargetIDs struct {
	Telegram []string `json:"telegram,omitempty"`
	Email    []string `json:"email,omitempty"`
}

type Rule struct {
	ID                    string    `json:"id,omitempty"`
	Revision              int64     `json:"revision,omitempty"`
	Name                  string    `json:"name"`
	Enabled               bool      `json:"enabled"`
	Severity              string    `json:"severity"`
	Selector              Selector  `json:"selector"`
	Condition             Condition `json:"condition"`
	Trigger               Trigger   `json:"trigger"`
	Channels              Channels  `json:"channels"`
	NotificationTargetIDs TargetIDs `json:"notification_target_ids"`
}

type Event struct {
	Source            string     `json:"source,omitempty"`
	Group             string     `json:"group,omitempty"`
	ErrorCategory     string     `json:"error_category,omitempty"`
	ID                string     `json:"id"`
	RuleID            string     `json:"rule_id"`
	RuleName          string     `json:"rule_name"`
	TargetID          string     `json:"target_id"`
	TargetName        string     `json:"target_name"`
	ObjectName        string     `json:"object_name"`
	Severity          string     `json:"severity"`
	Selector          Selector   `json:"selector"`
	Condition         Condition  `json:"condition"`
	Trigger           Trigger    `json:"trigger"`
	Status            string     `json:"status"`
	DetailState       string     `json:"detail_state"`
	InitialValue      any        `json:"initial_value"`
	LatestValue       any        `json:"latest_value"`
	ObservedAt        int64      `json:"observed_at"`
	TriggeredAt       int64      `json:"triggered_at"`
	RecoveredAt       *int64     `json:"recovered_at"`
	EndedAt           *int64     `json:"ended_at"`
	PanelRevision     int64      `json:"panel_revision"`
	PanelReadRevision int64      `json:"panel_read_revision"`
	SourceAvailable   bool       `json:"source_available"`
	Deliveries        []Delivery `json:"deliveries"`
}

type metricSpec struct{ group, targetKind, valueType string }

var metrics = map[string]metricSpec{
	"cpu_usage_percent":                 {"metrics", "host", "number"},
	"memory_usage_percent":              {"metrics", "host", "number"},
	"disk_usage_percent":                {"metrics", "host", "number"},
	"disk_available_bytes":              {"metrics", "host", "number"},
	"disk_capacity_bytes":               {"metrics", "host", "number"},
	"network_receive_bytes_per_second":  {"metrics", "host", "number"},
	"network_transmit_bytes_per_second": {"metrics", "host", "number"},
	"systemd_state":                     {"systemd", "host", "state"},
	"port_listening":                    {"listeners", "host", "bool"},
	"node_ready":                        {"nodes", "cluster", "bool"},
	"deployment_state":                  {"deployments", "cluster", "state"},
	"deployment_replica_gap":            {"deployments", "cluster", "number"},
	"pod_phase":                         {"pods", "cluster", "phase"},
	"pod_ready":                         {"pods", "cluster", "bool"},
	"target_reachable":                  {"probe", "", "bool"},
}

var serviceUnit = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@\\-]*\.service$`)

func validateRule(rule *Rule) error {
	rule.Name = strings.TrimSpace(rule.Name)
	if len(rule.Name) == 0 || len(rule.Name) > 200 {
		return errors.New("name must contain 1–200 bytes")
	}
	if rule.Severity != "info" && rule.Severity != "warning" && rule.Severity != "critical" {
		return errors.New("severity must be info, warning or critical")
	}
	spec, ok := metrics[rule.Selector.Metric]
	if !ok || rule.Selector.TargetID == "" {
		return errors.New("target_id and a valid metric are required")
	}
	key := rule.Selector
	switch key.Metric {
	case "disk_usage_percent", "disk_available_bytes", "disk_capacity_bytes":
		if !strings.HasPrefix(key.Mountpoint, "/") {
			return errors.New("mountpoint must be an absolute path")
		}
	case "network_receive_bytes_per_second", "network_transmit_bytes_per_second":
		if strings.TrimSpace(key.Interface) == "" {
			return errors.New("interface is required")
		}
	case "systemd_state":
		if !serviceUnit.MatchString(key.Unit) {
			return errors.New("systemd unit must name a service")
		}
	case "port_listening":
		address, err := netip.ParseAddr(key.Address)
		if key.Address == "*" && key.Family == "ipv4" {
			address, err = netip.ParseAddr("0.0.0.0")
		}
		if key.Address == "*" && key.Family == "ipv6" {
			address, err = netip.ParseAddr("::")
		}
		if err != nil || (key.Family == "ipv4" && !address.Is4()) || (key.Family == "ipv6" && !address.Is6()) || (key.Family != "ipv4" && key.Family != "ipv6") || (key.Protocol != "tcp" && key.Protocol != "udp") || key.Port < 1 || key.Port > 65535 {
			return errors.New("valid protocol, family, numeric address and port are required")
		}
		rule.Selector.Address = address.String()
	case "node_ready", "deployment_state", "deployment_replica_gap", "pod_phase", "pod_ready":
		if strings.TrimSpace(key.UID) == "" {
			return errors.New("resource UID is required")
		}
	}
	if _, valid := compare(spec.valueType, rule.Condition, rule.Condition.Value); !valid {
		return errors.New("condition does not match the selected metric")
	}
	samples, duration := rule.Trigger.ConsecutiveSamples, rule.Trigger.DurationSeconds
	if (samples == nil) == (duration == nil) || (samples != nil && (*samples < 1 || *samples > 1000000)) || (duration != nil && (*duration < 0 || *duration > 31536000)) {
		return errors.New("set either consecutive_samples (1–1000000) or duration_seconds (0–31536000)")
	}
	for _, ids := range [][]string{rule.NotificationTargetIDs.Telegram, rule.NotificationTargetIDs.Email} {
		if len(ids) > 50 {
			return errors.New("a rule may select up to 50 notification targets per channel")
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if id == "" || seen[id] {
				return errors.New("notification target IDs must be nonempty and unique")
			}
			seen[id] = true
		}
	}
	return nil
}

func canonicalSelector(s Selector) Selector {
	key := Selector{TargetID: s.TargetID, Metric: s.Metric}
	switch s.Metric {
	case "disk_usage_percent", "disk_available_bytes", "disk_capacity_bytes":
		key.Mountpoint = s.Mountpoint
	case "network_receive_bytes_per_second", "network_transmit_bytes_per_second":
		key.Interface = s.Interface
	case "systemd_state":
		key.Unit = s.Unit
	case "port_listening":
		key.Protocol, key.Family, key.Address, key.Port = s.Protocol, s.Family, s.Address, s.Port
		if address, err := netip.ParseAddr(key.Address); err == nil {
			key.Address = address.String()
		}
		if key.Address == "*" && key.Family == "ipv4" {
			key.Address = net.IPv4zero.String()
		}
		if key.Address == "*" && key.Family == "ipv6" {
			key.Address = net.IPv6zero.String()
		}
	case "node_ready", "deployment_state", "deployment_replica_gap", "pod_phase", "pod_ready":
		key.UID = s.UID
	}
	return key
}

func number(value any) (float64, bool) {
	var n float64
	switch v := value.(type) {
	case json.Number:
		var err error
		n, err = v.Float64()
		if err != nil {
			return 0, false
		}
	case float64:
		n = v
	case float32:
		n = float64(v)
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case uint64:
		n = float64(v)
	case int32:
		n = float64(v)
	default:
		return 0, false
	}
	return n, !math.IsNaN(n) && !math.IsInf(n, 0)
}

func compare(kind string, c Condition, observed any) (bool, bool) {
	if kind == "number" {
		got, ok := number(observed)
		want, valid := number(c.Value)
		if !ok || !valid {
			return false, false
		}
		switch c.Op {
		case "gt":
			return got > want, true
		case "gte":
			return got >= want, true
		case "lt":
			return got < want, true
		case "lte":
			return got <= want, true
		case "eq":
			return got == want, true
		case "ne":
			return got != want, true
		default:
			return false, false
		}
	}
	if c.Op != "eq" && c.Op != "ne" {
		return false, false
	}
	var equal bool
	switch kind {
	case "bool":
		got, ok := observed.(bool)
		want, valid := c.Value.(bool)
		if !ok || !valid {
			return false, false
		}
		equal = got == want
	case "state", "phase":
		got, ok := observed.(string)
		want, valid := c.Value.(string)
		if !ok || !valid || !validState(kind, got) || !validState(kind, want) {
			return false, false
		}
		equal = got == want
	default:
		return false, false
	}
	return equal == (c.Op == "eq"), true
}

func validState(kind, value string) bool {
	if kind == "phase" {
		switch value {
		case "Pending", "Running", "Succeeded", "Failed", "Unknown":
			return true
		}
		return false
	}
	switch value {
	case "running", "failed", "stopped", "starting":
		return true
	}
	return false
}
