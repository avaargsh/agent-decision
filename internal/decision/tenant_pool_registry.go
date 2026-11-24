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
	schema string
	mu     sync.RWMutex
	pools  map[string]*sql.DB
}

var _ Store = (*tenantPoolRegistry)(nil)

// newTenantPoolRegistry uses bounded eager startup, never caller-triggered
// pool creation. A nonnil pool returned by the factory transfers ownership
// even when accompanied by an error. No partially initialized registry is
// published, and the dispatcher is not an application pool.
func newTenantPoolRegistry(ctx context.Context, logins *tenantLoginRegistry, schema string, perTenant, total int, open func(context.Context, runtimeLoginBinding) (*sql.DB, error)) (*tenantPoolRegistry, error) {
	if logins == nil || len(logins.byTenant) == 0 || !validDecisionSchema(schema) ||
		perTenant <= 0 || total <= 0 || len(logins.byTenant) > total/perTenant || open == nil {
		return nil, fmt.Errorf("%w: invalid tenant pool registry configuration or budget", ErrCatalogDrift)
	}
	r := &tenantPoolRegistry{
		logins: logins,
		schema: schema,
		pools:  make(map[string]*sql.DB, len(logins.byTenant)),
	}
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
		if err := verifyTenantLoginMapping(ctx, db, schema, tenant, pin); err != nil {
			return nil, fmt.Errorf("%w: tenant LOGIN mapping check failed", ErrCatalogDrift)
		}
		r.pools[tenant] = db
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ready = true
	return r, nil
}

// resolve is a low-level pool inspection helper for tests and startup
// diagnostics. Business ledger operations must use the Store methods below,
// which create a tenant-bound PostgresStore and hold the registry read lock
// through the complete transaction.
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

// storeForTenantLocked returns a bound store while the caller holds r.mu.RLock.
// The returned store must not outlive the lock-protected operation.
func (r *tenantPoolRegistry) storeForTenantLocked(tenantID string) (*PostgresStore, error) {
	if r.pools == nil || r.logins == nil || r.logins.byTenant == nil {
		return nil, ErrStoreUnavailable
	}
	pin, ok := r.logins.byTenant[tenantID]
	if !ok {
		return nil, fmt.Errorf("%w: tenant login not provisioned", ErrAuthorityRejected)
	}
	db := r.pools[tenantID]
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	return newBoundPostgresStore(db, r.schema, tenantID, pin)
}

// Each Store method holds the registry read lock until the underlying
// PostgresStore transaction has finished. close therefore drains active
// operations before closing pools and prevents a resolve/close race.

func (r *tenantPoolRegistry) GetByInvocation(ctx context.Context, tenantID, invocationID string) (Record, error) {
	if r == nil {
		return Record{}, ErrStoreUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	store, err := r.storeForTenantLocked(tenantID)
	if err != nil {
		return Record{}, err
	}
	return store.GetByInvocation(ctx, tenantID, invocationID)
}

func (r *tenantPoolRegistry) SaveOrGet(ctx context.Context, record Record) (Record, bool, error) {
	if r == nil {
		return Record{}, false, ErrStoreUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	store, err := r.storeForTenantLocked(record.TenantID)
	if err != nil {
		return Record{}, false, err
	}
	return store.SaveOrGet(ctx, record)
}

func (r *tenantPoolRegistry) GetByDecisionID(ctx context.Context, tenantID, agentID, sessionID, decisionID string) (Record, error) {
	if r == nil {
		return Record{}, ErrStoreUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	store, err := r.storeForTenantLocked(tenantID)
	if err != nil {
		return Record{}, err
	}
	return store.GetByDecisionID(ctx, tenantID, agentID, sessionID, decisionID)
}

func (r *tenantPoolRegistry) ListByRun(ctx context.Context, tenantID, agentID, sessionID, runID string, before *DecisionCursor, limit int) ([]Record, error) {
	if r == nil {
		return nil, ErrStoreUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	store, err := r.storeForTenantLocked(tenantID)
	if err != nil {
		return nil, err
	}
	return store.ListByRun(ctx, tenantID, agentID, sessionID, runID, before, limit)
}

// close is idempotent, excludes new Store operations, and waits for in-flight
// Store operations because they retain r.mu.RLock through transaction completion.
// Raw handles returned by resolve are diagnostic only and must not be used
// concurrently with close.
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

// Close implements the public TenantPoolStore lifecycle contract.
func (r *tenantPoolRegistry) Close() error {
	return r.close()
}
