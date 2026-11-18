package decision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const maxACPPublicationWire = 512 * 1024
const maxACPReleaseBytes = 128 * 1024

var acpUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ACPRunBinding must originate from independently verified Run authority.
// Never populate it from a DecisionRequest or the signed payload itself.
type ACPRunBinding struct {
	TenantID       string `json:"tenant_id"`
	RunIntentID    string `json:"run_intent_id"`
	RunID          string `json:"run_id"`
	RequestDigest  string `json:"request_digest"`
	ProjectID      string `json:"project_id"`
	AgentID        string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID      string `json:"session_id"`
	SubjectID      string `json:"subject_id"`
	ActorID        string `json:"actor_id"`
	PolicyRevision string `json:"policy_revision"`
	ConfigDigest   string `json:"config_digest"`
}

// acpWireBinding mirrors the versioned wire contract, including the
// ACP-owned PrincipalID. Runtime does not mint that ID.
type acpWireBinding struct {
	SchemaVersion  string `json:"schema_version"`
	TenantID       string `json:"tenant_id"`
	RunIntentID    string `json:"run_intent_id"`
	RunID          string `json:"run_id"`
	RequestDigest  string `json:"request_digest"`
	ProjectID      string `json:"project_id"`
	AgentID        string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID      string `json:"session_id"`
	PrincipalID    string `json:"principal_id"`
	SubjectID      string `json:"subject_id"`
	ActorID        string `json:"actor_id"`
	PolicyRevision string `json:"policy_revision"`
	ConfigDigest   string `json:"config_digest"`
}

func (b acpWireBinding) binding() ACPRunBinding {
	return ACPRunBinding{
		TenantID: b.TenantID, RunIntentID: b.RunIntentID, RunID: b.RunID, RequestDigest: b.RequestDigest,
		ProjectID: b.ProjectID, AgentID: b.AgentID, AgentReleaseID: b.AgentReleaseID, SessionID: b.SessionID,
		SubjectID: b.SubjectID, ActorID: b.ActorID, PolicyRevision: b.PolicyRevision, ConfigDigest: b.ConfigDigest,
	}
}

type acpReleaseContract struct {
	ID           string          `json:"id"`
	Version      string          `json:"version"`
	InputSchema  json.RawMessage `json:"input_schema"`
	OutputSchema json.RawMessage `json:"output_schema"`
	EffectClass  string          `json:"effect_class"`
	Idempotency  string          `json:"idempotency"`
	TenantScoped bool            `json:"tenant_scoped"`
}

type acpRelease struct {
	SchemaVersion  string               `json:"schema_version"`
	TenantID       string               `json:"tenant_id"`
	ProjectID      string               `json:"project_id"`
	AgentID        string               `json:"agent_id"`
	AgentReleaseID string               `json:"agent_release_id"`
	PolicyRevision string               `json:"policy_revision"`
	CatalogVersion string               `json:"catalog_version"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	Services       []string             `json:"services"`
	Capabilities   []acpReleaseContract `json:"capabilities"`
}

type acpContext struct {
	Authority acpWireBinding `json:"authority"`
	Objective string         `json:"objective"`
	Service   string         `json:"service"`
	Signal    string         `json:"signal"`
}

type acpPublication struct {
	SchemaVersion      string         `json:"schema_version"`
	Authority          acpWireBinding `json:"authority"`
	Context            acpContext     `json:"context"`
	ContextSnapshot    SnapshotRef    `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef    `json:"capability_snapshot"`
	Capabilities       []CapabilityRef `json:"capabilities"`
	ContextContent     []byte         `json:"context_content"`
	CapabilityContent  []byte         `json:"capability_content"`
}

type signedACP struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type VerifiedACPPublication struct {
	Input              Input
	ContextSnapshot    SnapshotRef
	CapabilitySnapshot SnapshotRef
	Capabilities       []CapabilityRef
}

func acpHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func acpDigest(v string) bool {
	return strings.HasPrefix(v, "sha256:") && digestRe.MatchString(strings.TrimPrefix(v, "sha256:"))
}

// acpObject rejects duplicate decoded keys and excessive nesting, including
// inside embedded capability schemas. No semantic JSON alias is accepted in
// signed typed content: an independent re-marshal must equal the exact bytes.
func acpObject(raw []byte, limit int) bool {
	if len(raw) < 2 || len(raw) > limit || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(json.Token, int) bool
	walk = func(node json.Token, depth int) bool {
		delim, ok := node.(json.Delim)
		if !ok {
			return true
		}
		if depth > 32 || (delim != '{' && delim != '[') {
			return false
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				t, err := d.Token()
				key, ok := t.(string)
				if err != nil || !ok || keys[key] {
					return false
				}
				keys[key] = true
			}
			next, err := d.Token()
			if err != nil || !walk(next, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
	}
	first, err := d.Token()
	if err != nil || first != json.Delim('{') || !walk(first, 1) {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

func decodeACP(raw []byte, max int, dest any, canonical bool) bool {
	if !acpObject(raw, max) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dest); err != nil {
		return false
	}
	if canonical {
		b, err := json.Marshal(dest)
		return err == nil && bytes.Equal(b, raw)
	}
	return true
}

// VerifyACPPublication uses a deployment-pinned ACP public key and a
// separately obtained expected Run binding. It proves signed content,
// not current revocation or execution permission. A caller must fetch
// a fresh publication from authenticated ACP and verify current Runtime
// safety before using these inputs; never use cached bytes to authorize.
func VerifyACPPublication(wire []byte, key ed25519.PublicKey, expected ACPRunBinding, now time.Time) (VerifiedACPPublication, error) {
	fail := func() (VerifiedACPPublication, error) {
		return VerifiedACPPublication{}, fmt.Errorf("%w: invalid ACP publication", ErrAuthorityRejected)
	}
	if len(key) != ed25519.PublicKeySize || now.IsZero() ||
		!acpUUID.MatchString(expected.RunID) || !acpUUID.MatchString(expected.RunIntentID) ||
		!acpDigest(expected.RequestDigest) || !acpDigest(expected.ConfigDigest) {
		return fail()
	}
	for _, id := range []string{expected.TenantID, expected.ProjectID, expected.AgentID, expected.AgentReleaseID,
		expected.SessionID, expected.SubjectID, expected.ActorID, expected.PolicyRevision} {
		if !nameRe.MatchString(id) {
			return fail()
		}
	}
	if expected.ActorID != expected.SubjectID {
		return fail()
	}
	// HTTP encoder adds a newline; exact field names still checked by
	// canonical comparison on trimmed envelope. Signed payload is exact.
	var signed signedACP
	if !decodeACP(bytes.TrimSpace(wire), maxACPPublicationWire, &signed, true) ||
		signed.KeyID != acpHash(key) || len(signed.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, signed.Payload, signed.Signature) {
		return fail()
	}
	var p acpPublication
	if !decodeACP(signed.Payload, maxACPPublicationWire, &p, true) ||
		p.SchemaVersion != "acp.decision-publication.v1" ||
		p.Authority.SchemaVersion != "acp.run-authority.v1" ||
		p.Authority.binding() != expected || !nameRe.MatchString(p.Authority.PrincipalID) ||
		p.Context.Authority != p.Authority || p.Context.Objective != "sre_incident_triage" ||
		!nameRe.MatchString(p.Context.Service) ||
		(p.Context.Signal != "latency" && p.Context.Signal != "errors" && p.Context.Signal != "saturation") {
		return fail()
	}
	contextBytes, err := json.Marshal(p.Context)
	if err != nil || !bytes.Equal(contextBytes, p.ContextContent) ||
		"sha256:"+acpHash(p.CapabilityContent) != expected.ConfigDigest {
		return fail()
	}
	var release acpRelease
	if !decodeACP(p.CapabilityContent, maxACPReleaseBytes, &release, true) ||
		release.SchemaVersion != "acp.release-publication.v1" ||
		release.TenantID != expected.TenantID || release.ProjectID != expected.ProjectID ||
		release.AgentID != expected.AgentID || release.AgentReleaseID != expected.AgentReleaseID ||
		release.PolicyRevision != expected.PolicyRevision || !semverRe.MatchString(release.CatalogVersion) ||
		release.IssuedAt.IsZero() || release.ExpiresAt.Sub(release.IssuedAt) > 24*time.Hour ||
		now.Before(release.IssuedAt) || !now.Before(release.ExpiresAt) ||
		len(release.Services) == 0 || len(release.Services) > 32 || !slices.Contains(release.Services, p.Context.Service) ||
		release.Capabilities == nil || len(release.Capabilities) > 3 || p.Capabilities == nil ||
		len(p.Capabilities) != len(release.Capabilities) {
		return fail()
	}
	for i, svc := range release.Services {
		if !nameRe.MatchString(svc) || (i > 0 && release.Services[i-1] >= svc) {
			return fail()
		}
	}
	attestation := "acp:publication:" + signed.KeyID + ":" + expected.RunID
	verifySnapshot := func(ref SnapshotRef, kind, version string, content []byte) bool {
		digest := acpHash(content)
		return ref.ID == kind+"-"+digest && ref.Version == version && ref.SHA256 == digest &&
			ref.Source == "agent-control-panel" && ref.AttestationRef == attestation && ref.TrustLevel == "attested" &&
			ref.IssuedAt.Equal(release.IssuedAt) && ref.ExpiresAt.Equal(release.ExpiresAt) && validSnapshot(ref)
	}
	if !verifySnapshot(p.ContextSnapshot, "ctx", "acp-context-v1", contextBytes) ||
		!verifySnapshot(p.CapabilitySnapshot, "cap", release.CatalogVersion, p.CapabilityContent) {
		return fail()
	}
	for i, contract := range release.Capabilities {
		if _, ok := requiredSREStepKinds[contract.ID]; !ok || (i > 0 && release.Capabilities[i-1].ID >= contract.ID) ||
			!acpObject(contract.InputSchema, 16384) || !acpObject(contract.OutputSchema, 16384) {
			return fail()
		}
		raw, err := json.Marshal(contract)
		if err != nil {
			return fail()
		}
		want := CapabilityRef{
			ID: contract.ID, Version: contract.Version, ContractSHA256: acpHash(raw),
			InputSchemaRef: "sha256:" + acpHash(contract.InputSchema), OutputSchemaRef: "sha256:" + acpHash(contract.OutputSchema),
			EffectClass: contract.EffectClass, Idempotency: contract.Idempotency, TenantScoped: contract.TenantScoped,
		}
		if want.Validate(release.CatalogVersion) != nil || p.Capabilities[i] != want {
			return fail()
		}
	}
	return VerifiedACPPublication{
		Input: Input{Objective: p.Context.Objective, Service: p.Context.Service, Signal: p.Context.Signal},
		ContextSnapshot: p.ContextSnapshot, CapabilitySnapshot: p.CapabilitySnapshot,
		Capabilities: append([]CapabilityRef{}, p.Capabilities...),
	}, nil
}
