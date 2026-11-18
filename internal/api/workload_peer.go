package api

import "net/url"

// A Guard verifier must be explicitly pinned to its own workload identity.
// The same constraint is used by the Runtime-facing listener.
func validTrustedWorkloadSPIFFE(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.Port() == "" &&
		u.Path != "" && u.Path != "/" && u.User == nil && u.Opaque == "" &&
		u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery &&
		u.Fragment == "" && u.String() == raw
}
