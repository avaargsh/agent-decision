package decision

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
)

// tenantPoolRegistry owns dedicated application pools for one validated
// deployment snapshot. It is not a public routing API. The factory must
// transfer fresh, exclusively owned pools with trusted TLS/cluster identity
// and pinned credentials on every physical connection. Startup attestation
// samples one connection per pool; it does not prove later session identity.
type tenantPoolRegistry struct {
	logins *tenantLoginRegistry
	mu     sync.RWMutex
	pools  map[string]*sql.DB
}

// newTenantPoolRegistry uses bounded eager startup, never caller-triggered
// pool creation. A nonnil pool returned by the factory transfers ownership
// even when accompanied by an error. No partially initialized registry is
// published, and the dispatcher is not an application pool.
func newTenantPoolRegistry(ctx context.Context, logins *tenantLoginRegistry, schema string, perTenant, total int, open func(context.Context, runtimeLoginBinding) (*sql.DB, error)) (*tenantPoolRegistry, error) {
	if logins == nil || len(logins.byTenant) == 0 || !validDecisionSchema(schema) ||
		perTenant <= 0 || total <= 0 || len(logins.byTenant) > total/perTenant || open == nil {
		return nil, fmt.Errorf("%w: invalid tenant pool registry configuration or budget", ErrCatalogDrift)
	}
	r := &tenantPoolRegistry{logins: logins, pools: make(map[string]*sql.DB, len(logins.byTenant))}
	owned := make(map[*sql.DB]struct{}, len(logins.byTenant))
	ready := false
	defer func() {
		if !ready {
			for db := range owned {
				_ = db.Close()
			}
		}
	}()
	tenants := make([]string, 0, len(logins.byTenant))
	for tenant := range logins.byTenant {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pin := logins.byTenant[tenant]
		db, err := open(ctx, pin)
		if db != nil {
			if _, exists := owned[db]; exists {
				return nil, fmt.Errorf("%w: tenant pool ownership collision", ErrCatalogDrift)
			}
			owned[db] = struct{}{}
		}
		if err != nil || db == nil {
			// Factory errors may contain connection configuration or secrets.
			return nil, fmt.Errorf("%w: tenant pool initialization failed", ErrStoreUnavailable)
		}
		db.SetMaxOpenConns(perTenant)
		db.SetMaxIdleConns(perTenant)
		if err := verifyBoundRuntimeDatabaseRole(ctx, db, schema, RuntimeRoleApplication, pin); err != nil {
			return nil, fmt.Errorf("%w: tenant pool identity or privilege check failed", ErrCatalogDrift)
		}
		r.pools[tenant] = db
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ready = true
	return r, nil
}

// resolve borrows a pool for a gateway-authenticated Principal. The caller
// must not close it, reconfigure it, or use a different tenant's arguments.
// A future transaction-scoped adapter must enforce these preconditions
// before this internal prototype can serve live requests.
func (r *tenantPoolRegistry) resolve(principal Principal) (*sql.DB, error) {
	if err := principal.Validate(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrStoreUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.pools == nil {
		return nil, ErrStoreUnavailable
	}
	if _, err := r.logins.resolve(principal); err != nil {
		return nil, err
	}
	db := r.pools[principal.TenantID]
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	return db, nil
}

// close is idempotent and excludes new resolutions while shutting down.
// Already borrowed handles are closed by database/sql; callers must drain
// live work before shutdown. No live caller exists in this slice.
func (r *tenantPoolRegistry) close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var failed bool
	for _, db := range r.pools {
		if err := db.Close(); err != nil {
			failed = true
		}
	}
	r.pools = nil
	if failed {
		return fmt.Errorf("%w: tenant pool shutdown failed", ErrStoreUnavailable)
	}
	return nil
}
