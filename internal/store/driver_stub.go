//go:build !postgres

package store

import (
	"context"
	"database/sql"
	"errors"
)

var ErrPostgresBuildTagRequired = errors.New("PostgreSQL driver is not included; build with -tags postgres")

func OpenPostgres(context.Context, string) (*sql.DB, error) {
	return nil, ErrPostgresBuildTagRequired
}
