package decision

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func validTenantPoolStoreConfig() TenantPoolStoreConfig {
	return TenantPoolStoreConfig{
		Schema: "decision",
		DispatcherLogin: PostgresLoginIdentity{
			Database: "decision", RoleName: "decision_dispatcher", RoleOID: 103,
		},
		Tenants: []TenantPostgresLogin{
			{TenantID: "tenant-a", Login: PostgresLoginIdentity{Database: "decision", RoleName: "decision_tenant_a", RoleOID: 101}},
			{TenantID: "tenant-b", Login: PostgresLoginIdentity{Database: "decision", RoleName: "decision_tenant_b", RoleOID: 102}},
		},
		MaxOpenPerTenant: 2,
		MaxOpenTotal:     4,
	}
}

func TestNewTenantPoolStoreRejectsInvalidConfigurationBeforeOpeningPools(t *testing.T) {
	open := func(calls *int) TenantPoolOpener {
		return func(context.Context, PostgresLoginIdentity) (*sql.DB, error) {
			*calls++
			return nil, nil
		}
	}
	type testCase struct {
		name   string
		ctx    context.Context
		config TenantPoolStoreConfig
		nilOpen bool
	}
	cases := []testCase{
		{name: "nil_context", ctx: nil, config: validTenantPoolStoreConfig()},
		{name: "empty_schema", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Schema = ""; return c }()},
		{name: "missing_dispatcher", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.DispatcherLogin = PostgresLoginIdentity{}; return c }()},
		{name: "no_tenants", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants = nil; return c }()},
		{name: "duplicate_tenant", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants[1].TenantID = c.Tenants[0].TenantID; return c }()},
		{name: "duplicate_login_name", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants[1].Login.RoleName = c.Tenants[0].Login.RoleName; return c }()},
		{name: "duplicate_login_oid", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants[1].Login.RoleOID = c.Tenants[0].Login.RoleOID; return c }()},
		{name: "dispatcher_alias", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants[0].Login.RoleName = c.DispatcherLogin.RoleName; return c }()},
		{name: "different_database", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants[0].Login.Database = "other"; return c }()},
		{name: "invalid_tenant", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.Tenants[0].TenantID = "tenant a"; return c }()},
		{name: "over_budget", ctx: context.Background(), config: func() TenantPoolStoreConfig { c := validTenantPoolStoreConfig(); c.MaxOpenTotal = 3; return c }()},
		{name: "nil_opener", ctx: context.Background(), config: validTenantPoolStoreConfig(), nilOpen: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var opener TenantPoolOpener
			if !tc.nilOpen {
				opener = open(&calls)
			}
			store, err := NewTenantPoolStore(tc.ctx, tc.config, opener)
			if store != nil || !errors.Is(err, ErrCatalogDrift) {
				t.Fatalf("invalid deployment config accepted: store=%T err=%v", store, err)
			}
			if calls != 0 {
				t.Fatalf("invalid deployment config opened %d tenant pools", calls)
			}
		})
	}
}
