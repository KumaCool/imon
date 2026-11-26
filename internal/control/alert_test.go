package control

import "testing"

func TestReadyValue(t *testing.T) {
	for _, tt := range []struct {
		status string
		want   any
	}{
		{"True", true},
		{"False", false},
		{"Unknown", nil},
		{"", nil},
	} {
		if got := readyValue(tt.status); got != tt.want {
			t.Errorf("readyValue(%q) = %#v, want %#v", tt.status, got, tt.want)
		}
	}
}
