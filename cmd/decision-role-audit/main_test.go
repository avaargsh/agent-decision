package main

import (
	"context"
	"os"
	"testing"
)

func TestAuditRejectsMissingOrUntrustedRoleConfiguration(t *testing.T) {
	for _, tc := range []struct {
		dsn, schema, role string
	}{
		{"", "public", "application"},
		{"unused", "", "application"},
		{"unused", "public", ""},
		{"unused", "public", "migrator"},
		{"unused", "public", "attestor"},
		{"unused", "public", "application;drop table"},
	} {
		if err := audit(context.Background(), tc.dsn, tc.schema, tc.role); err == nil {
			t.Fatalf("invalid role preflight config unexpectedly accepted: schema=%q role=%q", tc.schema, tc.role)
		}
	}
}

func TestAuditRejectsPrivilegedMigrationLogin(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" { t.Skip("DATABASE_URL is not configured") }
	for _, role := range []string{"application", "dispatcher"} {
		if err := audit(context.Background(), dsn, "public", role); err == nil {
			t.Fatalf("CI migrator/superuser accepted as %s", role)
		}
	}
}
