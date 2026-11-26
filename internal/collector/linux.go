package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	locale            = "LC_ALL=C; export LC_ALL; "
	rawMetricsCommand = locale + "cat /proc/sys/kernel/random/boot_id && awk '/^cpu([0-9]+)?[[:space:]]/ { print; next } { exit }' /proc/stat && awk '/^Mem(Total|Available):/ { print }' /proc/meminfo && cat /proc/net/dev && ip -j link show"
	disksCommand      = locale + "df -l -B1 --output=source,fstype,size,used,avail,target -x tmpfs -x devtmpfs -x overlay -x squashfs -x ramfs -x rootfs -x proc -x sysfs -x nsfs -x cgroup -x cgroup2 -x devpts"
	interfacesCommand = locale + "ip -j address show"
	ipv4RoutesCommand = locale + "ip -j -4 route show table all"
	ipv6RoutesCommand = locale + "ip -j -6 route show table all"
	showUnitsCommand  = locale + "systemctl --no-pager show -p Id -p LoadState -p ActiveState -p SubState --"
	firewallCommand   = locale + `
present() { [ -e "$1" ] || [ -L "$1" ]; }
current=/usr/local/libexec/imon/firewall-read
legacy=/usr/local/libexec/infra-monitor/firewall-read
if present "$legacy" || present /var/lib/infra-monitor/firewall-manifest.json || present /etc/sudoers.d/infra-monitor-firewall; then
  if present "$current" || present /var/lib/imon/firewall-manifest.json || present /etc/sudoers.d/imon-firewall; then
    exit 1
  fi
  exec sudo -n -- "$legacy"
fi
exec sudo -n -- "$current"`
)

// Keep every inventory query on one SSH channel. Disable word expansion on the
// validated unit list and cap each systemctl invocation's argument count.
const systemdInventoryCommand = locale + `set -f
files=$(systemctl --no-pager --no-legend list-unit-files '*.service') || exit "$?"
loaded=$(systemctl --no-pager --no-legend --plain --all list-units --type=service) || exit "$?"
units=$(printf '%s\n%s\n' "$files" "$loaded" | awk '
  $1 ~ /^[A-Za-z0-9_][A-Za-z0-9_.@:\\-]*[.]service$/ && $1 !~ /@[.]service$/ && !seen[$1]++ { print $1 }
') || exit "$?"
if [ -z "$units" ]; then
  printf '%s\n' 'imon:no-units'
  exit 0
fi
show_units() {
  systemctl --no-pager show -p Id -p LoadState -p ActiveState -p SubState -p InvocationID -p CPUUsageNSec -p MemoryCurrent -- "$@" || exit "$?"
  printf '\n'
}
set --
for unit in $units; do
  set -- "$@" "$unit"
  if [ "$#" -eq 64 ]; then
    show_units "$@"
    set --
  fi
done
if [ "$#" -gt 0 ]; then
  show_units "$@"
fi`

func (s *sshConnection) collect(ctx context.Context, group string, opts Options) ([]Row, error) {
	switch group {
	case "host_metrics":
		return s.metrics(ctx, opts)
	case "os_info":
		data, err := s.runLimited(ctx, osReleaseCommand, 16<<10)
		if err != nil {
			return nil, err
		}
		if display := osDisplayName(data); display != "" {
			item, err := row("os", map[string]string{"display_name": display})
			return []Row{item}, err
		}
		return nil, nil
	case "systemd":
		return s.systemd(ctx, opts)
	case "interfaces":
		data, err := s.run(ctx, interfacesCommand)
		if err != nil {
			return nil, err
		}
		return parseInterfaces(data)
	case "routes":
		v4, err := s.run(ctx, ipv4RoutesCommand)
		if err != nil {
			return nil, err
		}
		v6, err := s.runLimited(ctx, ipv6RoutesCommand, maxSSHOutput-len(v4))
		if err != nil {
			return nil, err
		}
		first, err := parseRoutes(v4, "ipv4")
		if err != nil {
			return nil, err
		}
		second, err := parseRoutes(v6, "ipv6")
		if err != nil {
			return nil, err
		}
		return append(first, second...), nil
	case "listeners":
		return s.listeners(ctx)
	case "firewall":
		return s.firewall(ctx)
	default:
		return nil, fail("invalid_group")
	}
}

type netCounters struct {
	Index int    `json:"ifindex"`
	RX    uint64 `json:"rx_bytes"`
	TX    uint64 `json:"tx_bytes"`
}

type rawMetrics struct {
	BootID          string
	At              time.Time
	CPU             []uint64
	CPUIds          []int
	MemoryTotal     uint64
	MemoryAvailable *uint64
	NICs            map[string]netCounters
}

type baseline struct {
	BootID string       `json:"boot_id"`
	At     time.Time    `json:"sampled_at"`
	CPU    []uint64     `json:"cpu_counters,omitempty"`
	CPUIds []int        `json:"cpu_ids,omitempty"`
	NIC    *netCounters `json:"nic_counters,omitempty"`
}

type interfaceRecord struct {
	Index     int               `json:"ifindex"`
	Name      string            `json:"ifname"`
	State     string            `json:"operstate"`
	MTU       int               `json:"mtu"`
	Addresses []json.RawMessage `json:"addr_info"`
}

func parseRawMetrics(data []byte, at time.Time) (rawMetrics, error) {
	var result rawMetrics
	linksAt := bytes.IndexByte(data, '[')
	if linksAt < 0 {
		return result, fail("invalid_response")
	}
	var interfaces []interfaceRecord
	if err := json.Unmarshal(data[linksAt:], &interfaces); err != nil || interfaces == nil {
		return result, fail("invalid_response")
	}
	rows := strings.Split(string(data[:linksAt]), "\n")
	if len(rows) < 4 || strings.TrimSpace(rows[0]) == "" {
		return result, fail("invalid_response")
	}
	result.BootID, result.At = strings.TrimSpace(rows[0]), at
	cpu := strings.Fields(rows[1])
	if len(cpu) < 5 || cpu[0] != "cpu" {
		return result, fail("invalid_response")
	}
	for _, raw := range cpu[1:min(9, len(cpu))] {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return result, fail("invalid_response")
		}
		result.CPU = append(result.CPU, n)
	}
	indexes := make(map[string]int, len(interfaces))
	for _, item := range interfaces {
		indexes[item.Name] = item.Index
	}
	result.NICs = make(map[string]netCounters)
	i := 2
	for ; i < len(rows) && strings.HasPrefix(rows[i], "cpu"); i++ {
		fields := strings.Fields(rows[i])
		id, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu"))
		if err != nil || id < 0 || len(fields) < 5 {
			return result, fail("invalid_response")
		}
		result.CPUIds = append(result.CPUIds, id)
	}
	slices.Sort(result.CPUIds)
	for _, line := range rows[i:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "|") {
			continue
		}
		name, tail, ok := strings.Cut(line, ":")
		if !ok {
			return result, fail("invalid_response")
		}
		values := strings.Fields(tail)
		switch name {
		case "MemTotal", "MemAvailable":
			if len(values) != 2 || values[1] != "kB" {
				return result, fail("invalid_response")
			}
			n, err := strconv.ParseUint(values[0], 10, 64)
			if err != nil || n > ^uint64(0)/1024 {
				return result, fail("invalid_response")
			}
			n *= 1024
			if name == "MemTotal" {
				result.MemoryTotal = n
			} else {
				result.MemoryAvailable = &n
			}
		default:
			index := indexes[strings.TrimSpace(name)]
			if index == 0 {
				continue
			}
			if len(values) < 16 {
				return result, fail("invalid_response")
			}
			rx, rxErr := strconv.ParseUint(values[0], 10, 64)
			tx, txErr := strconv.ParseUint(values[8], 10, 64)
			if rxErr != nil || txErr != nil {
				return result, fail("invalid_response")
			}
			result.NICs[strings.TrimSpace(name)] = netCounters{Index: index, RX: rx, TX: tx}
		}
	}
	return result, nil
}

func priorBaselines(rows []Row) map[string]baseline {
	known := make(map[string]baseline)
	for _, item := range rows {
		var sample struct {
			Baseline baseline `json:"baseline"`
		}
		if json.Unmarshal(item.Data, &sample) == nil && sample.Baseline.BootID != "" {
			known[item.Key] = sample.Baseline
		}
	}
	return known
}

func baselineWindow(current rawMetrics, previous baseline, maxWindow time.Duration) (time.Duration, bool) {
	elapsed := current.At.Sub(previous.At)
	return elapsed, previous.BootID == current.BootID && elapsed > 0 && elapsed <= maxWindow
}

func percentCPU(current rawMetrics, prior baseline, maxWindow time.Duration) *float64 {
	_, ok := baselineWindow(current, prior, maxWindow)
	if !ok || len(current.CPU) < 4 || len(current.CPU) != len(prior.CPU) {
		return nil
	}
	var total, idle uint64
	for i, count := range current.CPU {
		if count < prior.CPU[i] {
			return nil
		}
		delta := count - prior.CPU[i]
		if delta > ^uint64(0)-total {
			return nil
		}
		total += delta
		if i == 3 || i == 4 {
			idle += delta
		}
	}
	if total == 0 {
		return nil
	}
	ratio := 100 * float64(total-idle) / float64(total)
	return &ratio
}

func speedNIC(current rawMetrics, counters netCounters, prior baseline, maxWindow time.Duration) (*float64, *float64) {
	elapsed, ok := baselineWindow(current, prior, maxWindow)
	if !ok || prior.NIC == nil || counters.Index != prior.NIC.Index || counters.RX < prior.NIC.RX || counters.TX < prior.NIC.TX {
		return nil, nil
	}
	rx := float64(counters.RX-prior.NIC.RX) / elapsed.Seconds()
	tx := float64(counters.TX-prior.NIC.TX) / elapsed.Seconds()
	return &rx, &tx
}

func (s *sshConnection) metrics(ctx context.Context, opts Options) ([]Row, error) {
	data, err := s.run(ctx, rawMetricsCommand)
	if err != nil {
		return nil, err
	}
	current, err := parseRawMetrics(data, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	rawLength := len(data)
	previous := priorBaselines(opts.Previous)
	maxWindow := opts.MaxWindow
	if maxWindow <= 0 {
		maxWindow = 2 * time.Minute
		if opts.Manual {
			maxWindow = 10 * time.Minute
		}
	}
	if opts.Manual && needsMetricsBaseline(current, previous, maxWindow) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
		second, secondErr := s.runLimited(ctx, rawMetricsCommand, maxSSHOutput-rawLength)
		if secondErr != nil && (ctx.Err() != nil || Code(secondErr) == "output_limit") {
			return nil, secondErr
		}
		if secondErr == nil {
			rawLength += len(second)
			next, parseErr := parseRawMetrics(second, time.Now().UTC())
			if parseErr == nil {
				previous = sampleBaselines(current)
				current = next
			}
		}
	}
	disks, err := s.runLimited(ctx, disksCommand, maxSSHOutput-rawLength)
	if err != nil {
		return nil, err
	}
	return metricsRows(current, previous, maxWindow, disks)
}

func needsMetricsBaseline(current rawMetrics, previous map[string]baseline, maxWindow time.Duration) bool {
	if percentCPU(current, previous["cpu"], maxWindow) == nil || !slices.Equal(current.CPUIds, previous["cpu"].CPUIds) {
		return true
	}
	for name, counters := range current.NICs {
		if rx, _ := speedNIC(current, counters, previous["nic:"+name], maxWindow); rx == nil {
			return true
		}
	}
	return false
}

func sampleBaselines(current rawMetrics) map[string]baseline {
	result := map[string]baseline{"cpu": {BootID: current.BootID, At: current.At, CPU: current.CPU, CPUIds: current.CPUIds}}
	for name, counters := range current.NICs {
		result["nic:"+name] = baseline{BootID: current.BootID, At: current.At, NIC: &counters}
	}
	return result
}

func metricsRows(current rawMetrics, previous map[string]baseline, maxWindow time.Duration, disks []byte) ([]Row, error) {
	var rows []Row
	samples := sampleBaselines(current)
	var memPercent *float64
	var memUsed *uint64
	if current.MemoryTotal > 0 && current.MemoryAvailable != nil && *current.MemoryAvailable <= current.MemoryTotal {
		used := current.MemoryTotal - *current.MemoryAvailable
		ratio := float64(used) * 100 / float64(current.MemoryTotal)
		memUsed, memPercent = &used, &ratio
	}
	cpuPercent := percentCPU(current, previous["cpu"], maxWindow)
	cpu := map[string]any{"metric": "cpu_percent", "cpu_percent": cpuPercent, "baseline": samples["cpu"]}
	if cores := len(current.CPUIds); cores > 0 && cpuPercent != nil && slices.Equal(current.CPUIds, previous["cpu"].CPUIds) {
		cpu["total_cores"] = cores
		cpu["used_cores"] = *cpuPercent * float64(cores) / 100
	}
	rows, err := appendRow(rows, "cpu", cpu)
	if err != nil {
		return nil, err
	}
	rows, err = appendRow(rows, "memory", map[string]any{"metric": "memory_percent", "memory_percent": memPercent, "total_bytes": current.MemoryTotal, "used_bytes": memUsed})
	if err != nil {
		return nil, err
	}
	for name, counters := range current.NICs {
		key := "nic:" + name
		rx, tx := speedNIC(current, counters, previous[key], maxWindow)
		rows, err = appendRow(rows, key, map[string]any{"name": name, "interface": name, "rx_bytes_per_second": rx, "tx_bytes_per_second": tx, "baseline": samples[key]})
		if err != nil {
			return nil, err
		}
	}
	diskRows, err := parseDisks(disks)
	if err != nil {
		return nil, err
	}
	rows = append(rows, diskRows...)
	slices.SortFunc(rows, func(a, b Row) int { return strings.Compare(a.Key, b.Key) })
	return rows, nil
}

var diskPattern = regexp.MustCompile(`^[[:space:]]*(.+?)[[:space:]]+(\S+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+(/.*)$`)

func parseDisks(data []byte) ([]Row, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 1 || !strings.Contains(lines[0], "Mounted on") {
		return nil, fail("invalid_response")
	}
	out := make([]Row, 0, len(lines)-1)
	seen := make(map[string]bool)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := diskPattern.FindStringSubmatch(line)
		if len(fields) != 7 || seen[fields[6]] {
			return nil, fail("invalid_response")
		}
		mountpoint := fields[6]
		seen[mountpoint] = true
		size, sizeErr := strconv.ParseUint(fields[3], 10, 64)
		used, usedErr := strconv.ParseUint(fields[4], 10, 64)
		available, availableErr := strconv.ParseUint(fields[5], 10, 64)
		if sizeErr != nil || usedErr != nil || availableErr != nil {
			return nil, fail("invalid_response")
		}
		var ratio *float64
		if used != 0 || available != 0 {
			value := float64(used) * 100 / (float64(used) + float64(available))
			ratio = &value
		}
		payload := map[string]any{"name": mountpoint, "mountpoint": mountpoint, "metric": "disk_percent", "used_bytes": used, "total_bytes": size, "available_bytes": available, "disk_percent": ratio}
		// df may list several subvolumes from one Btrfs filesystem.
		if fields[2] == "btrfs" {
			payload["shared_filesystem"] = fields[1]
		}
		item, err := row("disk:"+mountpoint, payload)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

var systemdServiceUnit = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.@:-]|\\x[0-9A-Fa-f]{2})*\.service$`)

// ValidSystemdServiceUnit accepts concrete service names, including systemd's
// escaped \xNN form, while excluding uninstantiated templates.
func ValidSystemdServiceUnit(name string) bool {
	return systemdServiceUnit.MatchString(name) && !strings.HasSuffix(name, "@.service")
}

type unitStatus struct {
	Name         string   `json:"name"`
	Source       string   `json:"source"`
	State        *string  `json:"state"`
	Load         string   `json:"load_state"`
	Active       string   `json:"active_state"`
	Sub          string   `json:"sub_state"`
	InvocationID string   `json:"invocation_id,omitempty"`
	CPUUsageNSec *uint64  `json:"cpu_usage_nsec,omitempty"`
	MemoryBytes  *uint64  `json:"memory_bytes,omitempty"`
	CPUPercent   *float64 `json:"cpu_percent,omitempty"`
	SampledAt    int64    `json:"sampled_at,omitempty"`
}

func parseUnits(data []byte) (map[string]unitStatus, error) {
	items := make(map[string]unitStatus)
	for _, block := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		properties := make(map[string]string, 4)
		for _, line := range strings.Split(strings.TrimSpace(block), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, fail("invalid_response")
			}
			properties[key] = value
		}
		item := unitStatus{Name: properties["Id"], Load: properties["LoadState"], Active: properties["ActiveState"], Sub: properties["SubState"], Source: "host", InvocationID: properties["InvocationID"]}
		if !ValidSystemdServiceUnit(item.Name) || item.Load == "" || item.Active == "" {
			return nil, fail("invalid_response")
		}
		item.CPUUsageNSec = systemdResource(properties["CPUUsageNSec"])
		item.MemoryBytes = systemdResource(properties["MemoryCurrent"])
		var state string
		switch {
		case item.Active == "failed":
			state = "failed"
		case item.Load == "loaded" && item.Active == "active":
			state = "running"
		case item.Load == "loaded" && item.Active == "inactive":
			state = "stopped"
		case item.Active == "activating":
			state = "starting"
		}
		if state != "" {
			item.State = &state
		}
		items[item.Name] = item
	}
	return items, nil
}

func systemdResource(raw string) *uint64 {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == ^uint64(0) {
		return nil
	}
	return &value
}

func systemdCPU(item, old unitStatus) *float64 {
	if item.CPUUsageNSec == nil || old.CPUUsageNSec == nil || old.SampledAt <= 0 || item.SampledAt <= old.SampledAt ||
		item.InvocationID != old.InvocationID || *item.CPUUsageNSec < *old.CPUUsageNSec {
		return nil
	}
	wallNS := float64(item.SampledAt-old.SampledAt) * float64(time.Millisecond)
	value := float64(*item.CPUUsageNSec-*old.CPUUsageNSec) * 100 / wallNS
	return &value
}

func (s *sshConnection) systemd(ctx context.Context, opts Options) ([]Row, error) {
	data, err := s.run(ctx, systemdInventoryCommand)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("imon:no-units")) {
		return []Row{}, nil
	}
	units, err := parseUnits(data)
	if err != nil || len(units) == 0 {
		return nil, fail("invalid_response")
	}
	names := make([]string, 0, len(units))
	previous := make(map[string]unitStatus, len(opts.Previous))
	for _, row := range opts.Previous {
		var item unitStatus
		if json.Unmarshal(row.Data, &item) == nil {
			previous[row.Key] = item
		}
	}
	sampledAt := opts.SampledAt
	if sampledAt.IsZero() {
		sampledAt = time.Now()
	}
	for name := range units {
		names = append(names, name)
	}
	slices.Sort(names)
	rows := make([]Row, 0, len(names))
	for _, name := range names {
		item := units[name]
		item.SampledAt = sampledAt.UnixMilli()
		item.CPUPercent = systemdCPU(item, previous[name])
		rows, err = appendRow(rows, name, item)
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func parseInterfaces(data []byte) ([]Row, error) {
	var items []interfaceRecord
	if json.Unmarshal(data, &items) != nil || items == nil {
		return nil, fail("invalid_response")
	}
	rows := make([]Row, 0, len(items))
	seen := make(map[string]bool)
	for _, item := range items {
		if item.Index < 1 || item.Name == "" || seen[item.Name] {
			return nil, fail("invalid_response")
		}
		seen[item.Name] = true
		var err error
		rows, err = appendRow(rows, item.Name, map[string]any{"name": item.Name, "interface": item.Name, "ifindex": item.Index, "state": item.State, "mtu": item.MTU, "addresses": item.Addresses})
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func parseRoutes(data []byte, family string) ([]Row, error) {
	var items []map[string]any
	if json.Unmarshal(data, &items) != nil || items == nil {
		return nil, fail("invalid_response")
	}
	rows := make([]Row, 0, len(items))
	seen := make(map[string]bool)
	for _, item := range items {
		if item == nil {
			return nil, fail("invalid_response")
		}
		prefix, _ := item["dst"].(string)
		if prefix == "" {
			prefix = "default"
		}
		item["family"] = family
		item["destination"] = prefix
		item["prefix"] = prefix
		item["interface"] = item["dev"]
		item["next_hops"] = item["nexthops"]
		if item["table"] == nil {
			item["table"] = "main"
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		key := string(encoded)
		if !seen[key] {
			seen[key] = true
			rows = append(rows, Row{Key: key, Data: encoded})
		}
	}
	return rows, nil
}

type listenRecord struct {
	Protocol     string `json:"protocol"`
	Family       string `json:"family"`
	Address      string `json:"address"`
	Port         uint16 `json:"port"`
	Process      string `json:"process,omitempty"`
	ProcessState string `json:"process_state"`
}

func parseListeners(data []byte, protocol, family string) ([]listenRecord, error) {
	result := make([]listenRecord, 0)
	malformed := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		// Some older `ss` builds ignore -H and leave the column header in the
		// output. Treat it as a header instead of failing the whole snapshot.
		if len(fields) > 0 && (fields[0] == "Netid" || fields[0] == "State") {
			continue
		}
		offset := 0
		rowProtocol, rowFamily := protocol, family
		if len(fields) > 0 {
			switch strings.ToLower(fields[0]) {
			case "tcp", "tcp6":
				offset = 1
				rowProtocol = "tcp"
				if strings.HasSuffix(strings.ToLower(fields[0]), "6") {
					rowFamily = "ipv6"
				}
			case "udp", "udp6":
				offset = 1
				rowProtocol = "udp"
				if strings.HasSuffix(strings.ToLower(fields[0]), "6") {
					rowFamily = "ipv6"
				}
			}
		}
		if len(fields) < offset+5 {
			malformed++
			continue
		}
		// The ss column layout is stable on iproute2, but vendor builds and
		// permission-filtered output can insert or omit fields. Find the first
		// valid local address/port instead of discarding the whole snapshot when
		// one line cannot be projected.
		localIndex := -1
		var address string
		parsedFamily := rowFamily
		var n uint64
		for i := offset + 3; i < len(fields); i++ {
			candidate := fields[i]
			colon := strings.LastIndexByte(candidate, ':')
			if colon < 1 {
				continue
			}
			candidateFamily := rowFamily
			if candidateFamily == "" {
				// An aggregate `ss` query does not include an explicit address
				// family. Infer it from the local address so IPv6 wildcard
				// listeners are not projected as IPv4 rows.
				rawAddress := strings.Trim(candidate[:colon], "[]")
				if strings.Contains(rawAddress, ":") || strings.HasPrefix(candidate[:colon], "[") {
					candidateFamily = "ipv6"
				} else {
					candidateFamily = "ipv4"
				}
			}
			parsedAddress, valid := normalizeListenerAddress(candidate[:colon], candidateFamily)
			if !valid {
				continue
			}
			parsedPort, err := strconv.ParseUint(candidate[colon+1:], 10, 16)
			if err != nil || parsedPort == 0 {
				continue
			}
			localIndex, address, parsedFamily, n = i, parsedAddress, candidateFamily, parsedPort
			break
		}
		if localIndex < 0 {
			malformed++
			continue
		}
		item := listenRecord{Protocol: rowProtocol, Family: parsedFamily, Address: address, Port: uint16(n), ProcessState: "unreadable"}
		if len(fields) > localIndex+2 {
			item.Process = strings.Join(fields[localIndex+2:], " ")
			item.ProcessState = "ok"
		}
		result = append(result, item)
	}
	if len(result) == 0 && malformed > 0 {
		return nil, fail("invalid_response")
	}
	return result, nil
}

func parseNetstatListeners(data []byte) ([]listenRecord, error) {
	result := make([]listenRecord, 0)
	malformed := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "Active" || fields[0] == "Proto" {
			continue
		}
		if len(fields) < 4 {
			malformed++
			continue
		}
		proto := strings.ToLower(fields[0])
		protocol, family := "", ""
		switch {
		case strings.HasPrefix(proto, "tcp"):
			protocol = "tcp"
		case strings.HasPrefix(proto, "udp"):
			protocol = "udp"
		default:
			continue
		}
		if strings.HasSuffix(proto, "6") {
			family = "ipv6"
		} else {
			family = "ipv4"
		}
		address, port, ok := listenerAddress(fields[3], family)
		if !ok {
			malformed++
			continue
		}
		item := listenRecord{Protocol: protocol, Family: family, Address: address, Port: port, ProcessState: "unreadable"}
		// netstat places the optional PID/program column after the state
		// column for TCP and directly after the peer column for UDP.
		processIndex := 5
		if protocol == "tcp" {
			processIndex = 6
		}
		if len(fields) > processIndex && fields[processIndex] != "-" && fields[processIndex] != "-/-" {
			item.Process = fields[processIndex]
			item.ProcessState = "ok"
		}
		result = append(result, item)
	}
	if len(result) == 0 && malformed > 0 {
		return nil, fail("invalid_response")
	}
	return result, nil
}

func listenerAddress(local, family string) (string, uint16, bool) {
	colon := strings.LastIndexByte(local, ':')
	if colon < 1 {
		return "", 0, false
	}
	address, ok := normalizeListenerAddress(local[:colon], family)
	if !ok {
		return "", 0, false
	}
	n, err := strconv.ParseUint(local[colon+1:], 10, 16)
	if err != nil || n == 0 {
		return "", 0, false
	}
	return address, uint16(n), true
}

// normalizeListenerAddress accepts the forms emitted by ss for scoped IPv6
// addresses, including both [addr%iface]:port and [addr]%iface:port.
func normalizeListenerAddress(raw, family string) (string, bool) {
	address := raw
	if strings.HasPrefix(address, "[") {
		if close := strings.IndexByte(address, ']'); close < 0 {
			return "", false
		} else {
			address = address[1:close] + address[close+1:]
		}
	}
	address = strings.Trim(address, "[]")
	validationAddress, _, _ := strings.Cut(address, "%")
	if address != "*" && net.ParseIP(validationAddress) == nil {
		return "", false
	}
	if address == "*" {
		address = "0.0.0.0"
		if family == "ipv6" {
			address = "::"
		}
	}
	return address, true
}

func appendListenerRecords(grouped map[string]listenRecord, items []listenRecord) {
	for _, listener := range items {
		key := listener.Protocol + "|" + listener.Family + "|" + listener.Address + "|" + strconv.Itoa(int(listener.Port))
		if old, ok := grouped[key]; ok && old.Process != "" {
			listener.ProcessState = old.ProcessState
			if listener.Process == "" || listener.Process == old.Process {
				listener.Process = old.Process
			} else {
				listener.Process = old.Process + " " + listener.Process
			}
		}
		grouped[key] = listener
	}
}

func listenerRows(grouped map[string]listenRecord) ([]Row, error) {
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]Row, 0, len(keys))
	for _, key := range keys {
		var err error
		result, err = appendRow(result, key, grouped[key])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *sshConnection) listeners(ctx context.Context) ([]Row, error) {
	commands := []struct{ command, protocol, family string }{
		{locale + "ss -H -l -n -t -p -4", "tcp", "ipv4"},
		{locale + "ss -H -l -n -t -p -6", "tcp", "ipv6"},
		{locale + "ss -H -l -n -u -p -4", "udp", "ipv4"},
		{locale + "ss -H -l -n -u -p -6", "udp", "ipv6"},
	}
	remaining := maxSSHOutput
	grouped := make(map[string]listenRecord)
	needsFallback := false
	for _, item := range commands {
		data, err := s.runLimited(ctx, item.command, remaining)
		if err != nil {
			if Code(err) != "command_unavailable" && Code(err) != "command_failed" {
				return nil, err
			}
			// Some ss builds return a non-zero status for an unavailable address
			// family. Keep other results and try netstat as a supplement.
			needsFallback = true
			continue
		}
		remaining -= len(data)
		items, err := parseListeners(data, item.protocol, item.family)
		if err != nil {
			needsFallback = true
			continue
		}
		appendListenerRecords(grouped, items)
	}
	if needsFallback {
		// A family-specific `ss` query can fail on hosts without that address
		// family even though the aggregate query is available. Retry without
		// `-4`/`-6` before falling back to netstat so valid listeners are not
		// silently omitted from the published snapshot.
		aggregate := []struct{ command, protocol string }{
			{locale + "ss -H -l -n -t -p", "tcp"},
			{locale + "ss -H -l -n -u -p", "udp"},
		}
		aggregateComplete := make(map[string]bool, len(aggregate))
		for _, item := range aggregate {
			if remaining <= 0 {
				break
			}
			data, err := s.runLimited(ctx, item.command, remaining)
			if err != nil {
				continue
			}
			remaining -= len(data)
			items, err := parseListeners(data, item.protocol, "")
			if err != nil {
				continue
			}
			appendListenerRecords(grouped, items)
			aggregateComplete[item.protocol] = true
		}
		if !aggregateComplete["tcp"] || !aggregateComplete["udp"] {
			// Minimal Linux images may not ship iproute2/ss. Fall back to the
			// net-tools output, which is available on older systemd hosts.
			data, err := s.runLimited(ctx, locale+"netstat -lnptu", remaining)
			if err != nil {
				// Do not publish a partial listener snapshot as complete. The
				// caller keeps the last successful snapshot and records the
				// collection error, so missing families/protocols are visible as
				// an unavailable collection instead of silently disappearing.
				return nil, err
			}
			items, err := parseNetstatListeners(data)
			if err != nil {
				return nil, err
			}
			appendListenerRecords(grouped, items)
		}
	}
	return listenerRows(grouped)
}

func (s *sshConnection) firewall(ctx context.Context) ([]Row, error) {
	if rows, native, err := s.nativeFirewall(ctx); native {
		return rows, err
	}
	data, err := s.run(ctx, firewallCommand)
	if err != nil {
		switch Code(err) {
		case "command_failed", "command_unavailable", "permission_denied":
			return nil, fail("firewall_unreadable")
		default:
			return nil, err
		}
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil || items == nil {
		var wrapped struct {
			Results []json.RawMessage `json:"results"`
		}
		if json.Unmarshal(data, &wrapped) != nil || wrapped.Results == nil {
			return nil, fail("invalid_response")
		}
		items = wrapped.Results
	}
	rows := make([]Row, 0, len(items))
	seen := make(map[string]bool)
	for _, encoded := range items {
		var item struct {
			Backend string
			Status  string
		}
		if json.Unmarshal(encoded, &item) != nil || item.Backend == "" || item.Status == "" || seen[item.Backend] {
			return nil, fail("invalid_response")
		}
		seen[item.Backend] = true
		rows = append(rows, Row{Key: item.Backend, Data: encoded})
	}
	return rows, nil
}

// nativeFirewall reads the host firewall with the bound SSH identity when it
// already has root privileges (directly or through non-interactive sudo). It
// returns native=false when the identity cannot prove that capability, so the
// installed read-only helper remains the fallback for ordinary accounts.
func (s *sshConnection) nativeFirewall(ctx context.Context) ([]Row, bool, error) {
	probe := locale + "id -u"
	output, err := s.runLimited(ctx, probe, 1024)
	prefix := ""
	if err != nil || strings.TrimSpace(string(output)) != "0" {
		output, err = s.runLimited(ctx, locale+"sudo -n -- id -u", 1024)
		if err != nil || strings.TrimSpace(string(output)) != "0" {
			return nil, false, nil
		}
		prefix = "sudo -n -- "
	}

	command := func(name string, args ...string) ([]byte, error) {
		parts := make([]string, 0, len(args)+2)
		parts = append(parts, prefix+name)
		parts = append(parts, args...)
		return s.run(ctx, locale+strings.Join(parts, " "))
	}
	rows := make([]Row, 0, 3)
	readable := false
	ufw, ufwErr := command("ufw", "status", "verbose")
	ufwEntry := map[string]any{"backend": "ufw", "format": "text", "version": 1, "observed_at": time.Now().UnixMilli()}
	if ufwErr == nil {
		readable = true
		ufwEntry["status"], ufwEntry["payload"] = "ok", string(ufw)
	} else if Code(ufwErr) == "command_unavailable" {
		ufwEntry["status"] = "not_installed"
	} else {
		ufwEntry["status"], ufwEntry["error_code"] = "failed", Code(ufwErr)
	}
	ufwRow, err := row("ufw", ufwEntry)
	if err != nil {
		return nil, true, err
	}
	rows = append(rows, ufwRow)

	nft, nftErr := command("nft", "-j", "list", "ruleset")
	nftEntry := map[string]any{"backend": "nftables", "format": "json", "version": 1, "observed_at": time.Now().UnixMilli()}
	if nftErr == nil {
		if !json.Valid(nft) {
			nftEntry["status"], nftEntry["error_code"] = "failed", "invalid_response"
		} else {
			readable = true
			nftEntry["status"], nftEntry["payload"] = "ok", json.RawMessage(nft)
		}
	} else if Code(nftErr) == "command_unavailable" {
		nftEntry["status"] = "not_installed"
	} else {
		nftEntry["status"], nftEntry["error_code"] = "failed", Code(nftErr)
	}
	nftRow, err := row("nftables", nftEntry)
	if err != nil {
		return nil, true, err
	}
	rows = append(rows, nftRow)

	legacy := make(map[string]any, 2)
	for _, family := range []string{"ipv4", "ipv6"} {
		tool := "iptables-legacy-save"
		if family == "ipv6" {
			tool = "ip6tables-legacy-save"
		}
		data, runErr := command(tool)
		entry := map[string]any{"backend": family, "format": "text", "version": 1, "observed_at": time.Now().UnixMilli()}
		if runErr == nil {
			readable = true
			entry["status"], entry["payload"] = "ok", string(data)
		} else if Code(runErr) == "command_unavailable" {
			entry["status"] = "not_installed"
		} else {
			entry["status"], entry["error_code"] = "failed", Code(runErr)
		}
		legacy[family] = entry
	}
	if !readable {
		return nil, false, nil
	}
	legacyRow, err := row("iptables-legacy", map[string]any{
		"backend": "iptables-legacy", "format": "families", "version": 1,
		"observed_at": time.Now().UnixMilli(), "status": "ok", "payload": legacy,
	})
	if err != nil {
		return nil, true, err
	}
	rows = append(rows, legacyRow)
	return rows, true, nil
}
