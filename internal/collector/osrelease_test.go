package collector

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestOSDisplayName(t *testing.T) {
	for input, want := range map[string]string{
		"PRETTY_NAME=\"Example Linux \\\"stable\\\"\"\nNAME=ignored": "Example Linux \"stable\"",
		"NAME='Example Linux'\nVERSION_ID=12":                        "Example Linux 12",
		"ID=example\nVERSION_ID=12":                                  "example 12",
		"PRETTY_NAME='unterminated\nNAME=Example":                    "Example",
		"PRETTY_NAME='$(not-executed)'":                              "$(not-executed)",
		"UNRELATED=example":                                          "",
	} {
		if got := osDisplayName([]byte(input)); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}

func TestCPUUsageCoresNeedsMatchingOnlineSet(t *testing.T) {
	now := time.Now()
	makeSample := func(at time.Time, aggregate string, id int) rawMetrics {
		t.Helper()
		raw, err := parseRawMetrics(fmt.Appendf(nil, "boot-fixture\ncpu %s\ncpu0 0 0 0 0\ncpu%d 0 0 0 0\nMemTotal: 64 kB\nMemAvailable: 64 kB\n[]\n", aggregate, id), at)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	previous := sampleBaselines(makeSample(now, "10 0 0 10", 2))
	current := makeSample(now.Add(time.Second), "10 0 0 30", 2)
	cpu := func(current rawMetrics) map[string]any {
		t.Helper()
		rows, err := metricsRows(current, previous, time.Minute, []byte("1B-blocks Used Available Mounted on\n"))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if rows[0].Key != "cpu" || json.Unmarshal(rows[0].Data, &fields) != nil {
			t.Fatal("missing CPU row")
		}
		return fields
	}
	if fields := cpu(current); fields["total_cores"] != 2.0 || fields["used_cores"] != 0.0 {
		t.Fatalf("idle two-core sample: %v", fields)
	}
	changed := makeSample(current.At, "10 0 0 30", 3)
	if fields := cpu(changed); fields["used_cores"] != nil || fields["cpu_percent"] != 0.0 {
		t.Fatalf("changed core set must suppress capacity without changing existing CPU percent: %v", fields)
	}
}
