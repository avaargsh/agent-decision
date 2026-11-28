package decision

import (
	"context"
	"database/sql"
	"fmt"
)

// PostgresLoginIdentity is a deployment-provisioned PostgreSQL identity pin.
// Role OIDs are local to one cluster and must be re-provisioned after restore.
// This value contains no credentials or connection material.
type PostgresLoginIdentity struct {
	Database string
	RoleName string
	RoleOID  uint32
}

// TenantPostgresLogin binds one authenticated tenant to exactly one dedicated
// PostgreSQL LOGIN. The binding is immutable for the lifetime of the store.
type TenantPostgresLogin struct {
	TenantID string
	Login    PostgresLoginIdentity
}

// TenantPoolStoreConfig is a deployment-owned snapshot. DispatcherLogin is
// reserved to prevent an application tenant from reusing the dispatcher
// identity; this constructor does not open or return a dispatcher pool.
type TenantPoolStoreConfig struct {
	Schema           string
	DispatcherLogin  PostgresLoginIdentity
	Tenants          []TenantPostgresLogin
	MaxOpenPerTenant int
	MaxOpenTotal     int
}

// TenantPoolOpener must return a fresh, exclusively owned *sql.DB for the
// requested LOGIN. It is responsible for secret retrieval, PostgreSQL TLS
// server verification/cluster identity and schema-pinned settings on every
// physical connection. The registry independently checks database, LOGIN,
// role OID and tenant mapping at startup and on each ledger transaction.
type TenantPoolOpener func(context.Context, PostgresLoginIdentity) (*sql.DB, error)

// TenantPoolStore is the application Decision Store plus its pool lifecycle.
// Close drains active Store operations before closing the owned tenant pools.
type TenantPoolStore interface {
	Store
	Close() error
}

// NewTenantPoolStore constructs the bounded application Store from trusted
// deployment configuration. It never creates roles, credentials, schemas,
// migrations or a dispatcher pool. Unknown tenants fail closed; there is no
// shared-pool fallback. A factory error or failed identity/mapping check
// closes every pool already transferred to the constructor.
func NewTenantPoolStore(ctx context.Context, config TenantPoolStoreConfig, open TenantPoolOpener) (TenantPoolStore, error) {
	if ctx == nil || open == nil {
		return nil, fmt.Errorf("%w: tenant pool store requires startup context and pool opener", ErrCatalogDrift)
	}

	dispatcher := runtimeLoginBinding{
		Database: config.DispatcherLogin.Database,
		RoleName: config.DispatcherLogin.RoleName,
		RoleOID:  config.DispatcherLogin.RoleOID,
	}
	entries := make([]tenantLoginEntry, len(config.Tenants))
	for i, tenant := range config.Tenants {
		entries[i] = tenantLoginEntry{
			TenantID: tenant.TenantID,
			Login: runtimeLoginBinding{
				Database: tenant.Login.Database,
				RoleName: tenant.Login.RoleName,
				RoleOID:  tenant.Login.RoleOID,
			},
		}
	}

	logins, err := newTenantLoginRegistry(dispatcher, entries, len(entries))
	if err != nil {
		return nil, err
	}
	registry, err := newTenantPoolRegistry(
		ctx,
		logins,
		config.Schema,
		config.MaxOpenPerTenant,
		config.MaxOpenTotal,
		func(ctx context.Context, pin runtimeLoginBinding) (*sql.DB, error) {
			return open(ctx, PostgresLoginIdentity{
				Database: pin.Database,
				RoleName: pin.RoleName,
				RoleOID:  pin.RoleOID,
			})
		},
	)
	if err != nil {
		return nil, err
	}
	return registry, nil
}

var _ TenantPoolStore = (*tenantPoolRegistry)(nil)
