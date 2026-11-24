package decision

import "fmt"

// tenantLoginEntry is deployment-owned configuration, never request data.
type tenantLoginEntry struct {
	TenantID string
	Login    runtimeLoginBinding
}

// tenantLoginRegistry is an immutable snapshot for one independently
// authenticated cluster/database. It contains no credentials or connections.
// The caller must establish the gateway Principal and cluster identity;
// this snapshot alone does not authenticate either or enforce database RLS.
type tenantLoginRegistry struct {
	byTenant map[string]runtimeLoginBinding
}

// newTenantLoginRegistry rejects ambiguous mappings before any pool opens.
// Role names and OIDs are independently unique within this cluster, including
// the reserved dispatcher. The limit is a deployment cardinality budget,
// not yet a connection-pool or concurrency budget.
func newTenantLoginRegistry(dispatcher runtimeLoginBinding, entries []tenantLoginEntry, limit int) (*tenantLoginRegistry, error) {
	valid := func(pin runtimeLoginBinding) bool {
		return pin.Database != "" && pin.RoleName != "" && pin.RoleOID != 0
	}
	if !valid(dispatcher) || limit <= 0 || len(entries) == 0 || len(entries) > limit {
		return nil, fmt.Errorf("%w: invalid tenant login registry configuration", ErrCatalogDrift)
	}
	byTenant := make(map[string]runtimeLoginBinding, len(entries))
	roleNames := map[string]struct{}{dispatcher.RoleName: {}}
	roleOIDs := map[uint32]struct{}{dispatcher.RoleOID: {}}
	for _, entry := range entries {
		if !nameRe.MatchString(entry.TenantID) || !valid(entry.Login) || entry.Login.Database != dispatcher.Database {
			return nil, fmt.Errorf("%w: invalid tenant login entry", ErrCatalogDrift)
		}
		if _, exists := byTenant[entry.TenantID]; exists {
			return nil, fmt.Errorf("%w: duplicate tenant login entry", ErrCatalogDrift)
		}
		if _, exists := roleNames[entry.Login.RoleName]; exists {
			return nil, fmt.Errorf("%w: duplicate or reserved runtime login name", ErrCatalogDrift)
		}
		if _, exists := roleOIDs[entry.Login.RoleOID]; exists {
			return nil, fmt.Errorf("%w: duplicate or reserved runtime login OID", ErrCatalogDrift)
		}
		byTenant[entry.TenantID] = entry.Login
		roleNames[entry.Login.RoleName] = struct{}{}
		roleOIDs[entry.Login.RoleOID] = struct{}{}
	}
	return &tenantLoginRegistry{byTenant: byTenant}, nil
}

// resolve accepts only a gateway-authenticated Principal (Validate checks
// structure, not cryptographic authentication). Unknown tenants never fall
// back to a shared login or dispatcher.
func (r *tenantLoginRegistry) resolve(principal Principal) (runtimeLoginBinding, error) {
	if err := principal.Validate(); err != nil {
		return runtimeLoginBinding{}, err
	}
	if r == nil || r.byTenant == nil {
		return runtimeLoginBinding{}, ErrStoreUnavailable
	}
	pin, exists := r.byTenant[principal.TenantID]
	if !exists {
		return runtimeLoginBinding{}, fmt.Errorf("%w: tenant login not provisioned", ErrAuthorityRejected)
	}
	return pin, nil
}
