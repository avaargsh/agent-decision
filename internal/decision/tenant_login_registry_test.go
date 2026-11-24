package decision

import (
	"errors"
	"testing"
)

func TestTenantLoginRegistry(t *testing.T) {
	a := runtimeLoginBinding{Database: "decision", RoleName: "tenant_a", RoleOID: 101}
	b := runtimeLoginBinding{Database: "decision", RoleName: "tenant_b", RoleOID: 102}
	dispatcher := runtimeLoginBinding{Database: "decision", RoleName: "dispatcher", RoleOID: 103}
	entries := []tenantLoginEntry{{TenantID: "tenant-a", Login: a}, {TenantID: "tenant-b", Login: b}}
	registry, err := newTenantLoginRegistry(dispatcher, entries, 2)
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{TenantID: "tenant-a", SubjectID: "subject", AgentID: "agent", SessionID: "session", CallerID: "agent-runtime"}
	// Configuration input must not alias the validated snapshot.
	entries[0].Login = b
	entries[0].TenantID = "tenant-b"
	got, err := registry.resolve(principal)
	if err != nil || got != a {
		t.Fatalf("tenant-a binding changed: %+v %v", got, err)
	}
	got.RoleOID = 999
	principal.TenantID = "tenant-b"
	if got, err := registry.resolve(principal); err != nil || got != b {
		t.Fatalf("tenant-b binding: %+v %v", got, err)
	}
	principal.TenantID = "tenant-unknown"
	if got, err := registry.resolve(principal); got != (runtimeLoginBinding{}) || !errors.Is(err, ErrAuthorityRejected) {
		t.Fatalf("unknown tenant resolved: %+v %v", got, err)
	}
	principal.TenantID = "tenant-a"
	principal.CallerID = "untrusted"
	if got, err := registry.resolve(principal); got != (runtimeLoginBinding{}) || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("invalid principal resolved: %+v %v", got, err)
	}
	principal.CallerID = "agent-runtime"
	var missing *tenantLoginRegistry
	if got, err := missing.resolve(principal); got != (runtimeLoginBinding{}) || !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("missing registry resolved: %+v %v", got, err)
	}
}

func TestTenantLoginRegistryRejectsAmbiguousConfiguration(t *testing.T) {
	a := runtimeLoginBinding{Database: "decision", RoleName: "tenant_a", RoleOID: 101}
	b := runtimeLoginBinding{Database: "decision", RoleName: "tenant_b", RoleOID: 102}
	dispatcher := runtimeLoginBinding{Database: "decision", RoleName: "dispatcher", RoleOID: 103}
	entry := tenantLoginEntry{TenantID: "tenant-a", Login: a}
	for _, tc := range []struct {
		name string
		dispatcher runtimeLoginBinding
		entries []tenantLoginEntry
		limit int
	}{
		{"empty", dispatcher, nil, 2},
		{"zero_limit", dispatcher, []tenantLoginEntry{entry}, 0},
		{"over_limit", dispatcher, []tenantLoginEntry{entry, {TenantID: "tenant-b", Login: b}}, 1},
		{"duplicate_tenant", dispatcher, []tenantLoginEntry{entry, {TenantID: "tenant-a", Login: b}}, 2},
		{"duplicate_role_name", dispatcher, []tenantLoginEntry{entry, {TenantID: "tenant-b", Login: runtimeLoginBinding{Database: "decision", RoleName: a.RoleName, RoleOID: 102}}}, 2},
		{"duplicate_role_oid", dispatcher, []tenantLoginEntry{entry, {TenantID: "tenant-b", Login: runtimeLoginBinding{Database: "decision", RoleName: b.RoleName, RoleOID: a.RoleOID}}}, 2},
		{"dispatcher_name", dispatcher, []tenantLoginEntry{{TenantID: "tenant-a", Login: runtimeLoginBinding{Database: "decision", RoleName: dispatcher.RoleName, RoleOID: 101}}}, 2},
		{"dispatcher_oid", dispatcher, []tenantLoginEntry{{TenantID: "tenant-a", Login: runtimeLoginBinding{Database: "decision", RoleName: a.RoleName, RoleOID: dispatcher.RoleOID}}}, 2},
		{"different_database", dispatcher, []tenantLoginEntry{{TenantID: "tenant-a", Login: runtimeLoginBinding{Database: "other", RoleName: a.RoleName, RoleOID: a.RoleOID}}}, 2},
		{"invalid_tenant", dispatcher, []tenantLoginEntry{{TenantID: "tenant a", Login: a}}, 2},
		{"empty_pin", dispatcher, []tenantLoginEntry{{TenantID: "tenant-a"}}, 2},
		{"missing_dispatcher", runtimeLoginBinding{}, []tenantLoginEntry{entry}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := newTenantLoginRegistry(tc.dispatcher, tc.entries, tc.limit); got != nil || !errors.Is(err, ErrCatalogDrift) {
				t.Fatalf("invalid configuration accepted: %v %v", got, err)
			}
		})
	}
}
