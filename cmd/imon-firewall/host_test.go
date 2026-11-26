package main

import (
	"strings"
	"testing"
)

func TestServiceRequestOnlyAcceptsConcreteStartOrStop(t *testing.T) {
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{"start\nexample.service\n", true},
		{"stop\nworker@blue\\x2dgreen.service\n", true},
		{"enable\nexample.service\n", false},
		{"stop\nexample.socket\n", false},
		{"start\nworker@.service\n", false},
		{"start\n--user.service\n", false},
		{"start\nhello;id.service\n", false},
		{"stop\nexample.service\nextra.service\n", false},
		{"start\n" + strings.Repeat("x", 256) + ".service\n", false},
	} {
		if _, _, valid := serviceRequest(strings.NewReader(tc.input)); valid != tc.valid {
			t.Errorf("serviceRequest(%q) valid = %t", tc.input, valid)
		}
	}
}

func TestServiceDefinitionAcceptsCanonicalTrustedUnits(t *testing.T) {
	const unit = "sample.service"
	const fragment = "/run/systemd/generator.late/sample.service"
	const source = "/etc/init.d/sample"
	const dropIn = "/etc/systemd/system/sample.service.d/options.conf"
	const valid = "Id=" + unit + "\nLoadState=loaded\nNeedDaemonReload=no\nFragmentPath=" + fragment +
		"\nSourcePath=" + source + "\nDropInPaths=" + dropIn + "\n"
	trusted := func(path string) bool {
		return path == fragment || path == source || path == dropIn || path == "/run/systemd/transient/sample.service"
	}
	for _, tc := range []struct {
		name string
		data string
		want bool
	}{
		{"generated service", valid, true},
		{"transient service", strings.ReplaceAll(valid, fragment, "/run/systemd/transient/sample.service"), true},
		{"alias", strings.ReplaceAll(valid, "Id="+unit, "Id=alias.service"), false},
		{"unloaded", strings.ReplaceAll(valid, "LoadState=loaded", "LoadState=not-found"), false},
		{"reload required", strings.ReplaceAll(valid, "NeedDaemonReload=no", "NeedDaemonReload=yes"), false},
		{"writable fragment", strings.ReplaceAll(valid, fragment, "/tmp/sample.service"), false},
		{"writable source", strings.ReplaceAll(valid, source, "/tmp/sample"), false},
		{"writable drop-in", strings.ReplaceAll(valid, dropIn, "/tmp/options.conf"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := serviceDefinition(tc.data, unit, trusted); got != tc.want {
				t.Errorf("serviceDefinition() = %t, want %t", got, tc.want)
			}
		})
	}
}
