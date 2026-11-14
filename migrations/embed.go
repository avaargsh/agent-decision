package migrations

import "embed"

// FS exposes versioned SQL migrations to the Decision persistence layer.
//
//go:embed *.sql
var FS embed.FS
