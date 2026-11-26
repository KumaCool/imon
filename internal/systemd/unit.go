package systemd

import (
	"regexp"
	"strings"
)

var serviceUnit = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.@:-]|\\x[0-9A-Fa-f]{2})*\.service$`)

// ValidUnit accepts concrete service units, including systemd's escaped
// \\xNN form, while excluding uninstantiated templates and unit patterns.
func ValidUnit(name string) bool {
	return len(name) <= 255 && serviceUnit.MatchString(name) && !strings.HasSuffix(name, "@.service")
}
