package web

import "embed"

// Assets contains the self-contained local panel.
//
//go:embed index.html app.css app.js
var Assets embed.FS
