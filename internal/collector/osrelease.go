package collector

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const osReleaseCommand = locale + "if [ -e /etc/os-release ] || [ -L /etc/os-release ]; then cat /etc/os-release; elif [ -e /usr/lib/os-release ] || [ -L /usr/lib/os-release ]; then cat /usr/lib/os-release; fi"

func osDisplayName(data []byte) string {
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "PRETTY_NAME", "NAME", "VERSION", "VERSION_ID", "ID":
			if v, ok := osReleaseValue(strings.TrimSpace(value)); ok {
				fields[key] = v
			}
		}
	}
	switch {
	case fields["PRETTY_NAME"] != "":
		return fields["PRETTY_NAME"]
	case fields["NAME"] != "":
		version := fields["VERSION"]
		if version == "" {
			version = fields["VERSION_ID"]
		}
		return strings.TrimSpace(fields["NAME"] + " " + version)
	case fields["ID"] != "":
		return strings.TrimSpace(fields["ID"] + " " + fields["VERSION_ID"])
	default:
		return ""
	}
}

func osReleaseValue(raw string) (string, bool) {
	var quote byte
	if raw != "" && (raw[0] == '"' || raw[0] == '\'') {
		quote = raw[0]
		if len(raw) < 2 || raw[len(raw)-1] != quote {
			return "", false
		}
		raw = raw[1 : len(raw)-1]
	}
	var result strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == quote && quote != 0 {
			return "", false
		}
		if c == '\\' && quote != '\'' {
			if i+1 == len(raw) {
				return "", false
			}
			if next := raw[i+1]; quote == 0 || strings.ContainsRune("\"\\$`", rune(next)) {
				i++
				c = next
			}
		}
		result.WriteByte(c)
	}
	value := strings.TrimSpace(result.String())
	return value, len(value) <= 512 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}
