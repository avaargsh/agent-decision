// Command decision-role-audit verifies the effective permissions of one
// dedicated runtime PostgreSQL LOGIN. It does not migrate or modify schema.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func audit(ctx context.Context, dsn, schema, kind string) error {
	if strings.TrimSpace(dsn) == "" || strings.TrimSpace(schema) == "" {
		return errors.New("missing runtime database audit credentials or schema")
	}
	var role decision.RuntimeDatabaseRole
	switch kind {
	case string(decision.RuntimeRoleApplication):
		role = decision.RuntimeRoleApplication
	case string(decision.RuntimeRoleDispatcher):
		role = decision.RuntimeRoleDispatcher
	default:
		return errors.New("unknown runtime role kind")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open role audit connection: %w", err)
	}
	defer db.Close()
	return decision.VerifyRuntimeDatabaseRole(ctx, db, schema, role)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := audit(ctx, os.Getenv("DECISION_ROLE_DATABASE_URL"),
		os.Getenv("DECISION_ROLE_SCHEMA"), os.Getenv("DECISION_ROLE_KIND")); err != nil {
		// Redact underlying PostgreSQL driver errors from deployment logs.
		fmt.Fprintln(os.Stderr, "Decision runtime role audit FAILED; deployment remains blocked")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Decision runtime role audit PASS")
}
