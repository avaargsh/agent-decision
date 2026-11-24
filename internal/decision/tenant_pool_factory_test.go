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
			{
				TenantID: "tenant-a",
				Login: PostgresLoginIdentity{Database: "decision", RoleName: "decision_tenant_a", RoleOID: 101},
			},
			{
				TenantID: "tenant-b",
				Login: PostgresLoginIdentity{Database: "decision", RoleName: "decision_tenant_b", RoleOID: 102},
			},
		},
		MaxOpenPerTenant: 2,
		MaxOpenTotal:     4,
	}
}

func TestNewTenantPoolStoreRejectsInvalidConfigurationBeforeOpeningPools(t *testing.T) {
	open := func(calls *int) TenantPoolOpener {
		return func(context.Context, PostgresLoginIdentity) (*sql.DB, error) {
			(*calls)++
			return nil, nil
		}
	}
	mutate := func(change func(*TenantPoolStoreConfig)) TenantPoolStoreConfig {
		config := validTenantPoolStoreConfig()
		change(&config)
		return config
	}
	type testCase struct {
		name       string
		ctx        context.Context
		config     TenantPoolStoreConfig
		withOpener bool
	}
	cases := []testCase{
		{name: "nil_context", ctx: nil, config: validTenantPoolStoreConfig(), withOpener: true},
		{name: "empty_schema", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Schema = "" }), withOpener: true},
		{name: "missing_dispatcher", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.DispatcherLogin = PostgresLoginIdentity{} }), withOpener: true},
		{name: "no_tenants", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants = nil }), withOpener: true},
		{name: "duplicate_tenant", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants[1].TenantID = c.Tenants[0].TenantID }), withOpener: true},
		{name: "duplicate_login_name", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants[1].Login.RoleName = c.Tenants[0].Login.RoleName }), withOpener: true},
		{name: "duplicate_login_oid", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants[1].Login.RoleOID = c.Tenants[0].Login.RoleOID }), withOpener: true},
		{name: "dispatcher_alias", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants[0].Login.RoleName = c.DispatcherLogin.RoleName }), withOpener: true},
		{name: "different_database", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants[0].Login.Database = "other" }), withOpener: true},
		{name: "invalid_tenant", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.Tenants[0].TenantID = "tenant a" }), withOpener: true},
		{name: "over_budget", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.MaxOpenTotal = 3 }), withOpener: true},
		{name: "zero_per_tenant", ctx: context.Background(), config: mutate(func(c *TenantPoolStoreConfig) { c.MaxOpenPerTenant = 0 }), withOpener: true},
		{name: "nil_opener", ctx: context.Background(), config: validTenantPoolStoreConfig(), withOpener: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var opener TenantPoolOpener
			if tc.withOpener {
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
