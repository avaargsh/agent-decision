// Package auth defines the authenticated principal boundary for HTTP handlers.
package auth

import "context"

type Principal struct {
	TenantID string
	Subject  string
	AgentID  string
}

type principalContextKey struct{}

// WithPrincipal is intended to be called only by trusted OIDC/mTLS or gateway middleware.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok && principal.TenantID != "" && principal.Subject != "" && principal.AgentID != ""
}
