// Package installer holds the fixed Imon host maintenance script.
package installer

import _ "embed"

// Source contains the installer template. The uninstall action does not read
// the embedded release or binary placeholders.
//
//go:embed maintain.sh
var Source string
