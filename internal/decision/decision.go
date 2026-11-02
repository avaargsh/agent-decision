// Package decision implements a deterministic, side-effect-free SRE planner.
// It never authorizes, issues permits, executes tools, or owns Run lifecycle.
package decision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	PolicyVersion = "sre-readonly-v1"
	SchemaVersion = "decision.v1"
	StatusProposed = "PROPOSED"
	StatusAbstained = "ABSTAINED"
)

var (
	ErrConflict = errors.New("invocation_id reused with different request")
	ErrUnauthenticated = errors.New("authenticated principal required")
	ErrUnauthorized = errors.New("principal is not authorized for this decision request")
	ErrAuthorityUnavailable = errors.New("authoritative snapshot verifier unavailable")
	ErrAuthorityRejected = errors.New("authoritative snapshot verification rejected")
	ErrInvalidRequest = errors.New("invalid decision request")
	ErrNotFound = errors.New("decision record not found")
	ErrInvalidCursor = errors.New("invalid decision page cursor")
)

var (
	nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	digestRe = regexp.MustCompile(`^[a-f0-9]{64}$`)
	semverRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	decisionIDRe = regexp.MustCompile(`^dec_[a-f0-9]{64}$`)
)

// Principal is supplied by a trusted OIDC/mTLS gateway, never decoded from the
// DecisionRequest body. CallerID is expected to be the Runtime service identity.
type Principal struct {
	TenantID string `json:"tenant_id"`
	SubjectID string `json:"subject_id"`
	AgentID string `json:"agent_id"`
	SessionID string `json:"session_id"`
	CallerID string `json:"caller_id"`
}

func (p Principal) Validate() error {
	if !nameRe.MatchString(p.TenantID) || !nameRe.MatchString(p.SubjectID) ||
		!nameRe.MatchString(p.AgentID) || !nameRe.MatchString(p.SessionID) ||
		p.CallerID != "agent-runtime" {
		return ErrUnauthenticated
	}
	return nil
}

type Identity struct {
	AgentID string `json:"agent_id"`
	SessionID string `json:"session_id"`
	RunID string `json:"run_id"`
}

type Input struct {
	Objective string `json:"objective"`
	Service string `json:"service"`
	Signal string `json:"signal"`
}

type Constraints struct {
	DeadlineMS int `json:"deadline_ms"`
	MaxTokens int `json:"max_tokens"`
	MaxCostMicros int64 `json:"max_cost_micros"`
	MaxCandidates int `json:"max_candidates"`
}

type VersionSet struct {
	CapabilityCatalogVersion string `json:"capability_catalog_version"`
	StrategyVersion string `json:"strategy_version"`
	PromptVersion string `json:"prompt_version"`
	ModelProfile string `json:"model_profile"`
}

// SnapshotRef is a reference to an immutable, externally owned snapshot.
// The fields are claims until AuthorityVerifier validates signature, owner,
// expiry, revocation and content digest against the authoritative source.
type SnapshotRef struct {
	ID string `json:"id"`
	Version string `json:"version"`
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
	AttestationRef string `json:"attestation_ref"`
	TrustLevel string `json:"trust_level"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EvidenceRef is a versioned, scoped evidence envelope. All fields are claims
// until AuthorityVerifier verifies tenant ownership, digest, attestation, and revocation.
type EvidenceRef struct {
	Ref string `json:"ref"`
	EvidenceType string `json:"evidence_type"`
	SchemaVersion string `json:"schema_version"`
	TenantID string `json:"tenant_id"`
	AgentID string `json:"agent_id"`
	RunID string `json:"run_id"`
	Service string `json:"service"`
	ResourceRef string `json:"resource_ref"`
	SourceID string `json:"source_id"`
	Source string `json:"source"`
	SourceVersion string `json:"source_version"`
	SHA256 string `json:"sha256"`
	AttestationRef string `json:"attestation_ref"`
	TrustLevel string `json:"trust_level"`
	ObservedFrom time.Time `json:"observed_from"`
	ObservedTo time.Time `json:"observed_to"`
	ObservedAt time.Time `json:"observed_at"`
	CollectedAt time.Time `json:"collected_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevocationState string `json:"revocation_state"`
}

// CapabilityRef is published and versioned by Agent Control Plane.
// Endpoint, credential and executor configuration are intentionally absent.
type CapabilityRef struct {
	ID string `json:"id"`
	Version string `json:"version"`
	ContractSHA256 string `json:"contract_sha256"`
	InputSchemaRef string `json:"input_schema_ref"`
	OutputSchemaRef string `json:"output_schema_ref"`
	EffectClass string `json:"effect_class"`
	Idempotency string `json:"idempotency"`
	TenantScoped bool `json:"tenant_scoped"`
}

type ReplanContext struct {
	ParentDecisionID string `json:"parent_decision_id"`
	Sequence int `json:"sequence"`
	MaxReplans int `json:"max_replans"`
	Trigger string `json:"trigger"`
	PriorDisposition string `json:"prior_disposition"`
}

type Request struct {
	SchemaVersion string `json:"schema_version"`
	Identity Identity `json:"identity"`
	InvocationID string `json:"invocation_id"`
	Input Input `json:"input"`
	Constraints Constraints `json:"constraints"`
	Versions VersionSet `json:"versions"`
	ContextSnapshot SnapshotRef `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef `json:"capability_snapshot"`
	Capabilities []CapabilityRef `json:"capabilities"`
	Evidence []EvidenceRef `json:"evidence_refs"`
	Replan *ReplanContext `json:"replan,omitempty"`
}

type EvidenceBinding struct {
	SourceID string `json:"source_id"`
	Ref string `json:"ref"`
}

func evidenceBindingKey(binding EvidenceBinding) string {
	return binding.SourceID + "\\x00" + binding.Ref
}

type PlanStep struct {
	StepID string `json:"step_id"`
	Kind string `json:"kind"`
	Capability CapabilityRef `json:"capability"`
	TargetRef string `json:"target_ref"`
	InputSchemaRef string `json:"input_schema_ref"`
	OutputSchemaRef string `json:"output_schema_ref"`
	EvidenceRefs []EvidenceBinding `json:"evidence_refs"`
	ReadOnly bool `json:"read_only"`
}

type PlanCandidate struct {
	PlanID string `json:"plan_id"`
	SchemaVersion string `json:"schema_version"`
	Steps []PlanStep `json:"steps"`
	PlanHash string `json:"plan_hash"`
}

type Record struct {
	DecisionID string `json:"decision_id"`
	TenantID string `json:"tenant_id"`
	SubjectID string `json:"subject_id"`
	AgentID string `json:"agent_id"`
	SessionID string `json:"session_id"`
	RunID string `json:"run_id"`
	InvocationID string `json:"invocation_id"`
	RequestSHA256 string `json:"request_sha256"`
	StrategyVersion string `json:"strategy_version"`
	PromptVersion string `json:"prompt_version"`
	ModelProfile string `json:"model_profile"`
	CapabilityCatalogVersion string `json:"capability_catalog_version"`
	Status string `json:"status"`
	ReasonCodes []string `json:"reason_codes"`
	ParentDecisionID string `json:"parent_decision_id,omitempty"`
	ReplanSequence int `json:"replan_sequence"`
	MaxReplans int `json:"max_replans"`
	ContextSnapshot SnapshotRef `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef `json:"capability_snapshot"`
	Evidence []EvidenceRef `json:"evidence_refs"`
	Plan PlanCandidate `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

func validOpaque(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s &&
		!strings.ContainsAny(s, "\x00\r\n\t ")
}

func validSnapshot(s SnapshotRef) bool {
	return validOpaque(s.ID) && validOpaque(s.Version) && digestRe.MatchString(s.SHA256) &&
		validOpaque(s.Source) && validOpaque(s.AttestationRef) && s.TrustLevel == "attested" &&
		!s.IssuedAt.IsZero() && s.ExpiresAt.After(s.IssuedAt)
}

func validEvidence(e EvidenceRef, req Request) bool {
	return validOpaque(e.Ref) &&
		(e.EvidenceType == "metrics" || e.EvidenceType == "logs" || e.EvidenceType == "traces" || e.EvidenceType == "change" || e.EvidenceType == "slo") &&
		semverRe.MatchString(e.SchemaVersion) &&
		nameRe.MatchString(e.TenantID) && e.AgentID == req.Identity.AgentID && e.RunID == req.Identity.RunID &&
		e.Service == req.Input.Service && validOpaque(e.ResourceRef) && validOpaque(e.SourceID) &&
		validOpaque(e.Source) && validOpaque(e.SourceVersion) && digestRe.MatchString(e.SHA256) &&
		validOpaque(e.AttestationRef) && e.TrustLevel == "attested" &&
		!e.ObservedFrom.IsZero() && !e.ObservedTo.Before(e.ObservedFrom) &&
		!e.ObservedAt.IsZero() && !e.ObservedAt.Before(e.ObservedFrom) && !e.ObservedAt.After(e.ObservedTo) &&
		!e.CollectedAt.IsZero() &&
		!e.CollectedAt.Before(e.ObservedTo) && e.ExpiresAt.After(e.CollectedAt) &&
		e.RevocationState == "active"
}

func (c CapabilityRef) Validate(catalogVersion string) error {
	if !nameRe.MatchString(c.ID) || !semverRe.MatchString(c.Version) ||
		!digestRe.MatchString(c.ContractSHA256) || !validOpaque(c.InputSchemaRef) ||
		!validOpaque(c.OutputSchemaRef) || c.EffectClass != "read_only" ||
		c.Idempotency != "safe" || !c.TenantScoped {
		return fmt.Errorf("invalid or non-read-only capability binding: %s", c.ID)
	}
	_ = catalogVersion // Version is pinned per capability; catalog version is pinned by SnapshotRef.
	return nil
}

func (r Request) Validate() error {
	if r.SchemaVersion != SchemaVersion || !nameRe.MatchString(r.Identity.AgentID) ||
		!nameRe.MatchString(r.Identity.SessionID) || !nameRe.MatchString(r.Identity.RunID) ||
		!nameRe.MatchString(r.InvocationID) {
		return fmt.Errorf("%w: schema, identity or invocation_id", ErrInvalidRequest)
	}
	if r.Input.Objective != "sre_incident_triage" || !nameRe.MatchString(r.Input.Service) ||
		(r.Input.Signal != "latency" && r.Input.Signal != "errors" && r.Input.Signal != "saturation") {
		return fmt.Errorf("%w: unsupported SRE objective or input", ErrInvalidRequest)
	}
	if r.Constraints.DeadlineMS < 100 || r.Constraints.DeadlineMS > 120000 ||
		r.Constraints.MaxTokens < 1 || r.Constraints.MaxTokens > 8192 ||
		r.Constraints.MaxCostMicros < 0 || r.Constraints.MaxCostMicros > 10000000 ||
		r.Constraints.MaxCandidates < 1 || r.Constraints.MaxCandidates > 3 {
		return fmt.Errorf("%w: invalid resource constraints", ErrInvalidRequest)
	}
	if r.Versions.CapabilityCatalogVersion == "" || r.Versions.StrategyVersion != PolicyVersion ||
		r.Versions.PromptVersion != "none" || r.Versions.ModelProfile != "rule-only" ||
		r.CapabilitySnapshot.Version != r.Versions.CapabilityCatalogVersion {
		return fmt.Errorf("%w: unsupported or mismatched version set", ErrInvalidRequest)
	}
	if !validSnapshot(r.ContextSnapshot) || !validSnapshot(r.CapabilitySnapshot) {
		return fmt.Errorf("%w: invalid snapshot reference or attestation metadata", ErrInvalidRequest)
	}
	if r.Capabilities == nil || r.Evidence == nil {
		return fmt.Errorf("%w: capabilities and evidence_refs must be explicit arrays", ErrInvalidRequest)
	}
	if len(r.Capabilities) > 32 || len(r.Evidence) > 32 {
		return fmt.Errorf("%w: too many capability or evidence references", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(r.Capabilities))
	for _, capability := range r.Capabilities {
		if err := capability.Validate(r.Versions.CapabilityCatalogVersion); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
		if _, ok := seen[capability.ID]; ok {
			return fmt.Errorf("%w: duplicate capability %s", ErrInvalidRequest, capability.ID)
		}
		seen[capability.ID] = struct{}{}
	}
	seenEvidence := make(map[string]struct{}, len(r.Evidence))
	for _, evidence := range r.Evidence {
		if !validEvidence(evidence, r) {
			return fmt.Errorf("%w: invalid evidence reference", ErrInvalidRequest)
		}
		// A source reference identifies one immutable observation. Repeating it
		// must not inflate evidence coverage or create ambiguous provenance.
		evidenceKey := evidence.SourceID + "\x00" + evidence.Ref
		if _, exists := seenEvidence[evidenceKey]; exists {
			return fmt.Errorf("%w: duplicate evidence reference", ErrInvalidRequest)
		}
		seenEvidence[evidenceKey] = struct{}{}
	}
	if r.Replan != nil {
		p := r.Replan
		if !decisionIDRe.MatchString(p.ParentDecisionID) || p.Sequence < 1 ||
			p.MaxReplans < 1 || p.MaxReplans > 3 || p.Sequence > p.MaxReplans ||
			p.Trigger != "STEP_FAILED" || p.PriorDisposition != "RETRYABLE_FAILURE" {
			// UNKNOWN and Guard-denied operations are deliberately not replannable here.
			return fmt.Errorf("%w: unsafe or exhausted replan context", ErrInvalidRequest)
		}
	}
	return nil
}

type AuthorityVerifier interface {
	// VerifyDecisionInputs must independently verify tenant/run ownership,
	// immutable snapshot digests, signatures, source versions, expiry and revocation.
	VerifyDecisionInputs(context.Context, Principal, Request) error
}

type Store interface {
	GetByInvocation(context.Context, string, string) (Record, error)
	SaveOrGet(context.Context, Record) (Record, bool, error)
	GetByDecisionID(context.Context, string, string, string, string) (Record, error)
	ListByRun(context.Context, string, string, string, string, *DecisionCursor, int) ([]Record, error)
}

type MemoryStore struct {
	mu sync.Mutex
	byKey map[string]Record
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{byKey: make(map[string]Record)} }

func memoryInvocationKey(tenantID, invocationID string) string {
	return digest(struct{ TenantID, InvocationID string }{tenantID, invocationID})
}

func (s *MemoryStore) GetByInvocation(ctx context.Context, tenantID, invocationID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	key := memoryInvocationKey(tenantID, invocationID)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byKey[key]
	if !ok {
		return Record{}, ErrNotFound
	}
	return clone(record), nil
}

func (s *MemoryStore) SaveOrGet(ctx context.Context, r Record) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	key := memoryInvocationKey(r.TenantID, r.InvocationID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byKey[key]; ok {
		if old.RequestSHA256 != r.RequestSHA256 {
			return Record{}, false, ErrConflict
		}
		return clone(old), false, nil
	}
	s.byKey[key] = clone(r)
	return clone(r), true, nil
}

type Service struct {
	store Store
	authority AuthorityVerifier
	strategy Strategy
	now func() time.Time
}

func NewService(store Store, authority AuthorityVerifier) *Service {
	return NewServiceWithStrategy(store, authority, SREReadOnlyStrategy{})
}

// NewServiceWithStrategy injects a replaceable decision policy while keeping
// persistence, identity, authority verification, and idempotency in the core.
func NewServiceWithStrategy(store Store, authority AuthorityVerifier, strategy Strategy) *Service {
	if strategy == nil {
		strategy = SREReadOnlyStrategy{}
	}
	return &Service{store: store, authority: authority, strategy: strategy, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Decide(ctx context.Context, principal Principal, req Request) (Record, bool, error) {
	if err := principal.Validate(); err != nil {
		return Record{}, false, err
	}
	// Validate the minimum trusted lookup scope before consulting the ledger.
	// Full request validation follows only when this is a new invocation, so
	// any changed payload under an existing invocation deterministically conflicts.
	if !nameRe.MatchString(req.InvocationID) ||
		!nameRe.MatchString(req.Identity.AgentID) ||
		!nameRe.MatchString(req.Identity.SessionID) {
		return Record{}, false, fmt.Errorf("%w: invocation_id or identity", ErrInvalidRequest)
	}
	if req.Identity.AgentID != principal.AgentID || req.Identity.SessionID != principal.SessionID {
		return Record{}, false, ErrUnauthorized
	}
	if s.store == nil {
		return Record{}, false, ErrStoreUnavailable
	}

	fingerprint := digest(struct {
		Principal Principal
		Request Request
	}{principal, req})

	// An exact retry of a completed invocation returns its immutable historical
	// result before current evidence freshness/attestation is re-evaluated.
	// Current Principal and Agent/Session bindings are checked above; this
	// read-only replay is never authorization and cannot bypass EngageGuard.
	existing, lookupErr := s.store.GetByInvocation(ctx, principal.TenantID, req.InvocationID)
	if lookupErr == nil {
		if existing.RequestSHA256 != fingerprint {
			return Record{}, false, ErrConflict
		}
		return clone(existing), false, nil
	}
	if !errors.Is(lookupErr, ErrNotFound) {
		return Record{}, false, lookupErr
	}

	if err := req.Validate(); err != nil {
		return Record{}, false, err
	}
	for _, evidence := range req.Evidence {
		if evidence.TenantID != principal.TenantID {
			return Record{}, false, ErrUnauthorized
		}
	}
	if s.strategy == nil || req.Versions.StrategyVersion != s.strategy.Version() {
		return Record{}, false, fmt.Errorf("%w: strategy version unavailable", ErrInvalidRequest)
	}
	if s.authority == nil {
		return Record{}, false, ErrAuthorityUnavailable
	}
	if err := s.authority.VerifyDecisionInputs(ctx, principal, req); err != nil {
		if errors.Is(err, ErrAuthorityUnavailable) {
			return Record{}, false, err
		}
		return Record{}, false, fmt.Errorf("%w: %v", ErrAuthorityRejected, err)
	}

	decisionID := "dec_" + digest(struct{ TenantID, InvocationID string }{principal.TenantID, req.InvocationID})
	record := Record{
		DecisionID: decisionID, TenantID: principal.TenantID, SubjectID: principal.SubjectID,
		AgentID: principal.AgentID, SessionID: principal.SessionID, RunID: req.Identity.RunID,
		InvocationID: req.InvocationID, RequestSHA256: fingerprint,
		StrategyVersion: req.Versions.StrategyVersion, PromptVersion: req.Versions.PromptVersion,
		ModelProfile: req.Versions.ModelProfile, CapabilityCatalogVersion: req.Versions.CapabilityCatalogVersion,
		Status: StatusProposed, ReasonCodes: []string{}, ContextSnapshot: req.ContextSnapshot,
		CapabilitySnapshot: req.CapabilitySnapshot, Evidence: append([]EvidenceRef{}, req.Evidence...),
		Plan: PlanCandidate{PlanID: "plan_" + digest(struct{ DecisionID string }{decisionID})[:32], SchemaVersion: SchemaVersion, Steps: []PlanStep{}},
		CreatedAt: s.now(),
	}
	if req.Replan != nil {
		record.ParentDecisionID = req.Replan.ParentDecisionID
		record.ReplanSequence = req.Replan.Sequence
		record.MaxReplans = req.Replan.MaxReplans
	}
	// Strategies receive detached request slices so an implementation cannot
	// mutate already-verified evidence or capabilities before output validation.
	result := s.strategy.Plan(cloneRequest(req), decisionID)
	result.ReasonCodes = append([]string{}, result.ReasonCodes...)
	result.Steps = append([]PlanStep{}, result.Steps...)
	if err := validateStrategyResult(req, result); err != nil {
		return Record{}, false, fmt.Errorf("%w: unsafe strategy output", ErrInvalidRequest)
	}
	record.Status = result.Status
	record.ReasonCodes = append([]string{}, result.ReasonCodes...)
	record.Plan.Steps = append([]PlanStep{}, result.Steps...)
	record.Plan.PlanHash = planHash(record.Plan)
	return s.store.SaveOrGet(ctx, record)
}

func findCapability(capabilities []CapabilityRef, id string) (CapabilityRef, bool) {
	for _, capability := range capabilities {
		if capability.ID == id {
			return capability, true
		}
	}
	return CapabilityRef{}, false
}

func planHash(plan PlanCandidate) string {
	plan.PlanHash = ""
	return digest(plan)
}

func digest(value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func cloneRequest(req Request) Request {
	req.Capabilities = append([]CapabilityRef{}, req.Capabilities...)
	req.Evidence = append([]EvidenceRef{}, req.Evidence...)
	if req.Replan != nil {
		replan := *req.Replan
		req.Replan = &replan
	}
	return req
}

func clone(record Record) Record {
	record.ReasonCodes = append([]string{}, record.ReasonCodes...)
	record.Evidence = append([]EvidenceRef{}, record.Evidence...)
	record.Plan.Steps = append([]PlanStep{}, record.Plan.Steps...)
	return record
}
