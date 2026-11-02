// Package decision implements a side-effect-free, policy-first Decision Plane.
// It never issues authorization permits or executes proposed steps.
package decision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/avaargsh/agent-decision/internal/auth"
)

const (
	RequestSchemaVersion = "decision.v1"
	PolicyVersion        = "sre-readonly-v1"
	RecordSchemaVersion  = "decision.v1"
	PlanSchemaVersion    = "decision.v1"
	StatusProposed       = "PROPOSED"
	StatusAbstained      = "ABSTAINED"
)

var (
	ErrConflict             = errors.New("idempotency key reused with different request")
	ErrNotFound             = errors.New("decision record not found")
	ErrAuthorityUnavailable = errors.New("authoritative verifier unavailable")
	ErrNotAuthorized        = errors.New("principal is not authorized for this decision request")
	ErrAuthorityRejected    = errors.New("authoritative evidence verification rejected the request")
	ErrInvalidRequest       = errors.New("invalid decision request")
	nameRe                  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	digestRe                = regexp.MustCompile(`^[a-f0-9]{64}$`)
	semverRe                = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	decisionIDRe            = regexp.MustCompile(`^dec_[a-f0-9]{64}$`)
)

type Identity struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id"`
}

type Input struct {
	Objective string `json:"objective"`
	Service   string `json:"service"`
	Signal    string `json:"signal"`
}

type Constraints struct {
	DeadlineMS    int   `json:"deadline_ms"`
	MaxTokens     int   `json:"max_tokens"`
	MaxCostMicros int64 `json:"max_cost_micros"`
	MaxCandidates int   `json:"max_candidates"`
}

type Versions struct {
	CapabilityCatalogVersion string `json:"capability_catalog_version"`
	StrategyVersion          string `json:"strategy_version"`
	PromptVersion            string `json:"prompt_version"`
	ModelProfile             string `json:"model_profile"`
}

type SnapshotRef struct {
	ID             string    `json:"id"`
	Version        string    `json:"version"`
	SHA256         string    `json:"sha256"`
	Source         string    `json:"source"`
	AttestationRef string    `json:"attestation_ref"`
	TrustLevel     string    `json:"trust_level"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type CapabilityRef struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	ContractSHA256  string `json:"contract_sha256"`
	InputSchemaRef  string `json:"input_schema_ref"`
	OutputSchemaRef string `json:"output_schema_ref"`
	EffectClass     string `json:"effect_class"`
	Idempotency     string `json:"idempotency"`
	TenantScoped    bool   `json:"tenant_scoped"`
}

type EvidenceRef struct {
	Ref            string    `json:"ref"`
	Source         string    `json:"source"`
	SourceVersion  string    `json:"source_version"`
	SHA256         string    `json:"sha256"`
	AttestationRef string    `json:"attestation_ref"`
	TrustLevel     string    `json:"trust_level"`
	ObservedAt     time.Time `json:"observed_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Replan struct {
	ParentDecisionID string `json:"parent_decision_id"`
	Sequence         int    `json:"sequence"`
	MaxReplans       int    `json:"max_replans"`
	Trigger          string `json:"trigger"`
	PriorDisposition string `json:"prior_disposition"`
}

// Request is the versioned DecisionRequest v1 contract. Tenant identity is
// intentionally absent: it is derived from an authenticated principal.
type Request struct {
	SchemaVersion      string          `json:"schema_version"`
	Identity           Identity        `json:"identity"`
	IdempotencyKey     string          `json:"idempotency_key"`
	Input              Input           `json:"input"`
	Constraints        Constraints     `json:"constraints"`
	Versions           Versions        `json:"versions"`
	ContextSnapshot    SnapshotRef     `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef     `json:"capability_snapshot"`
	Capabilities       []CapabilityRef `json:"capabilities"`
	Evidence           []EvidenceRef   `json:"evidence_refs"`
	Replan             *Replan         `json:"replan,omitempty"`
}

type PlanStep struct {
	StepID          string        `json:"step_id"`
	Kind            string        `json:"kind"`
	Capability      CapabilityRef `json:"capability"`
	TargetRef       string        `json:"target_ref"`
	InputSchemaRef  string        `json:"input_schema_ref"`
	OutputSchemaRef string        `json:"output_schema_ref"`
	ReadOnly        bool          `json:"read_only"`
}

type PlanCandidate struct {
	PlanID        string     `json:"plan_id"`
	SchemaVersion string     `json:"schema_version"`
	Steps         []PlanStep `json:"steps"`
	PlanHash      string     `json:"plan_hash"`
}

type Record struct {
	SchemaVersion      string          `json:"schema_version"`
	DecisionID         string          `json:"decision_id"`
	TenantID           string          `json:"tenant_id"`
	Subject            string          `json:"subject"`
	Identity           Identity        `json:"identity"`
	IdempotencyKey     string          `json:"idempotency_key"`
	Input              Input           `json:"input"`
	Constraints        Constraints     `json:"constraints"`
	Versions           Versions        `json:"versions"`
	Capabilities       []CapabilityRef `json:"capabilities"`
	RequestSHA256      string          `json:"request_sha256"`
	PolicyVersion      string          `json:"policy_version"`
	Status             string          `json:"status"`
	Reason             string          `json:"reason,omitempty"`
	ContextSnapshot    SnapshotRef     `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef     `json:"capability_snapshot"`
	Evidence           []EvidenceRef   `json:"evidence_refs"`
	ParentDecisionID   string          `json:"parent_decision_id,omitempty"`
	ReplanSequence     int             `json:"replan_sequence,omitempty"`
	Plan               *PlanCandidate  `json:"plan,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
}

// AuthorityVerifier must bind the authenticated principal to the ACP Run and
// independently verify snapshots, capabilities, evidence hashes, attestations,
// validity windows, revocation and source versions. A nil verifier fails closed.
type AuthorityVerifier interface {
	Verify(context.Context, auth.Principal, Request) error
}

func validIdentifier(value string) bool { return nameRe.MatchString(value) }

func boundedString(value string, maximum int) bool { return value != "" && len(value) <= maximum }

func validSnapshot(snapshot SnapshotRef) bool {
	return boundedString(snapshot.ID, 256) && boundedString(snapshot.Version, 256) &&
		digestRe.MatchString(snapshot.SHA256) && boundedString(snapshot.Source, 256) &&
		boundedString(snapshot.AttestationRef, 256) && snapshot.TrustLevel == "attested" &&
		!snapshot.IssuedAt.IsZero() && snapshot.ExpiresAt.After(snapshot.IssuedAt)
}

func validCapability(capability CapabilityRef) bool {
	return boundedString(capability.ID, 128) && semverRe.MatchString(capability.Version) &&
		digestRe.MatchString(capability.ContractSHA256) && boundedString(capability.InputSchemaRef, 256) &&
		boundedString(capability.OutputSchemaRef, 256) && capability.EffectClass == "read_only" &&
		capability.Idempotency == "safe" && capability.TenantScoped
}

func validEvidence(evidence EvidenceRef) bool {
	return boundedString(evidence.Ref, 256) && boundedString(evidence.Source, 256) &&
		boundedString(evidence.SourceVersion, 256) && digestRe.MatchString(evidence.SHA256) &&
		boundedString(evidence.AttestationRef, 256) && evidence.TrustLevel == "attested" &&
		!evidence.ObservedAt.IsZero() && evidence.ExpiresAt.After(evidence.ObservedAt)
}

func normalizeRequest(request Request) Request {
	request.ContextSnapshot.IssuedAt = request.ContextSnapshot.IssuedAt.UTC()
	request.ContextSnapshot.ExpiresAt = request.ContextSnapshot.ExpiresAt.UTC()
	request.CapabilitySnapshot.IssuedAt = request.CapabilitySnapshot.IssuedAt.UTC()
	request.CapabilitySnapshot.ExpiresAt = request.CapabilitySnapshot.ExpiresAt.UTC()
	for i := range request.Evidence {
		request.Evidence[i].ObservedAt = request.Evidence[i].ObservedAt.UTC()
		request.Evidence[i].ExpiresAt = request.Evidence[i].ExpiresAt.UTC()
	}
	sort.Slice(request.Capabilities, func(i, j int) bool { return request.Capabilities[i].ID < request.Capabilities[j].ID })
	sort.Slice(request.Evidence, func(i, j int) bool {
		if request.Evidence[i].Ref == request.Evidence[j].Ref {
			return request.Evidence[i].SHA256 < request.Evidence[j].SHA256
		}
		return request.Evidence[i].Ref < request.Evidence[j].Ref
	})
	return request
}

func (request Request) Validate() error {
	if request.SchemaVersion != RequestSchemaVersion {
		return errors.New("schema_version must be decision.v1")
	}
	if !boundedString(request.Identity.AgentID, 128) || !boundedString(request.Identity.SessionID, 128) || !boundedString(request.Identity.RunID, 128) {
		return errors.New("identity agent_id, session_id and run_id must be valid bounded identifiers")
	}
	if !validIdentifier(request.IdempotencyKey) {
		return errors.New("invalid idempotency_key")
	}
	if request.Input.Objective != "sre_incident_triage" || !validIdentifier(request.Input.Service) ||
		(request.Input.Signal != "latency" && request.Input.Signal != "errors" && request.Input.Signal != "saturation") {
		return errors.New("invalid SRE decision input")
	}
	if request.Constraints.DeadlineMS < 100 || request.Constraints.DeadlineMS > 120000 ||
		request.Constraints.MaxTokens < 1 || request.Constraints.MaxTokens > 8192 ||
		request.Constraints.MaxCostMicros < 0 || request.Constraints.MaxCostMicros > 10000000 ||
		request.Constraints.MaxCandidates < 1 || request.Constraints.MaxCandidates > 3 {
		return errors.New("decision constraints are outside supported bounds")
	}
	if !boundedString(request.Versions.CapabilityCatalogVersion, 128) || request.Versions.StrategyVersion != PolicyVersion ||
		request.Versions.PromptVersion != "none" || request.Versions.ModelProfile != "rule-only" {
		return errors.New("unsupported decision strategy or model version")
	}
	if !validSnapshot(request.ContextSnapshot) || !validSnapshot(request.CapabilitySnapshot) {
		return errors.New("invalid attested snapshot reference")
	}
	if request.Capabilities == nil || request.Evidence == nil {
		return errors.New("capabilities and evidence_refs must be arrays")
	}
	if len(request.Capabilities) > 32 || len(request.Evidence) > 32 {
		return errors.New("too many capability or evidence references")
	}
	seenCapabilities := make(map[string]struct{}, len(request.Capabilities))
	for _, capability := range request.Capabilities {
		if !validCapability(capability) {
			return errors.New("invalid or non-read-only capability reference")
		}
		if _, exists := seenCapabilities[capability.ID]; exists {
			return fmt.Errorf("duplicate capability reference: %s", capability.ID)
		}
		seenCapabilities[capability.ID] = struct{}{}
	}
	seenEvidence := make(map[string]struct{}, len(request.Evidence))
	for _, evidence := range request.Evidence {
		if !validEvidence(evidence) {
			return errors.New("invalid attested evidence reference")
		}
		if _, exists := seenEvidence[evidence.Ref]; exists {
			return fmt.Errorf("duplicate evidence reference: %s", evidence.Ref)
		}
		seenEvidence[evidence.Ref] = struct{}{}
	}
	if request.Replan != nil {
		replan := request.Replan
		if !decisionIDRe.MatchString(replan.ParentDecisionID) || replan.Sequence < 1 || replan.MaxReplans < 1 ||
			replan.MaxReplans > 3 || replan.Sequence > replan.MaxReplans || replan.Trigger != "STEP_FAILED" ||
			replan.PriorDisposition != "RETRYABLE_FAILURE" {
			return errors.New("invalid or unbounded replan lineage")
		}
	}
	return nil
}

func digest(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func requestDigest(principal auth.Principal, request Request) string {
	return digest(struct {
		TenantID string  `json:"tenant_id"`
		Subject  string  `json:"subject"`
		AgentID  string  `json:"agent_id"`
		Request  Request `json:"request"`
	}{TenantID: principal.TenantID, Subject: principal.Subject, AgentID: principal.AgentID, Request: request})
}

func cloneRecord(record Record) Record {
	record.Evidence = append([]EvidenceRef{}, record.Evidence...)
	record.Capabilities = append([]CapabilityRef{}, record.Capabilities...)
	if record.Plan != nil {
		plan := *record.Plan
		plan.Steps = append([]PlanStep{}, record.Plan.Steps...)
		record.Plan = &plan
	}
	return record
}

type Store interface {
	SaveOrGet(context.Context, Record) (Record, bool, error)
	GetByID(context.Context, string, string, string) (Record, error)
}

type memoryKey struct{ tenantID, key string }

type decisionLookupKey struct {
	tenantID, agentID, decisionID string
}

type MemoryStore struct {
	mu    sync.RWMutex
	byKey map[memoryKey]Record
	byID  map[decisionLookupKey]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byKey: make(map[memoryKey]Record), byID: make(map[decisionLookupKey]Record)}
}

func (store *MemoryStore) SaveOrGet(ctx context.Context, record Record) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	key := memoryKey{tenantID: record.TenantID, key: record.IdempotencyKey}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.byKey[key]; ok {
		if existing.RequestSHA256 != record.RequestSHA256 {
			return Record{}, false, ErrConflict
		}
		return cloneRecord(existing), false, nil
	}
	store.byKey[key] = cloneRecord(record)
	store.byID[decisionLookupKey{tenantID: record.TenantID, agentID: record.Identity.AgentID, decisionID: record.DecisionID}] = cloneRecord(record)
	return cloneRecord(record), true, nil
}

func (store *MemoryStore) GetByID(ctx context.Context, tenantID, agentID, decisionID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	record, ok := store.byID[decisionLookupKey{tenantID: tenantID, agentID: agentID, decisionID: decisionID}]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

type Service struct {
	store    Store
	verifier AuthorityVerifier
	now      func() time.Time
}

func NewService(store Store, verifier AuthorityVerifier) *Service {
	return &Service{store: store, verifier: verifier, now: func() time.Time { return time.Now().UTC() }}
}

func (service *Service) Decide(ctx context.Context, principal auth.Principal, request Request) (Record, bool, error) {
	request = normalizeRequest(request)
	if !validIdentifier(principal.TenantID) || principal.Subject == "" || len(principal.Subject) > 256 || !validIdentifier(principal.AgentID) {
		return Record{}, false, ErrNotAuthorized
	}
	if err := request.Validate(); err != nil {
		return Record{}, false, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if request.Identity.AgentID != principal.AgentID {
		return Record{}, false, ErrNotAuthorized
	}
	if service.verifier == nil {
		return Record{}, false, ErrAuthorityUnavailable
	}
	if err := service.verifier.Verify(ctx, principal, request); err != nil {
		if errors.Is(err, ErrNotAuthorized) || errors.Is(err, ErrAuthorityRejected) || errors.Is(err, ErrAuthorityUnavailable) {
			return Record{}, false, err
		}
		return Record{}, false, fmt.Errorf("%w: %v", ErrAuthorityUnavailable, err)
	}

	record := Record{
		SchemaVersion:      RecordSchemaVersion,
		DecisionID:         "dec_" + digest(struct{ TenantID, Key string }{principal.TenantID, request.IdempotencyKey}),
		TenantID:           principal.TenantID,
		Subject:            principal.Subject,
		Identity:           request.Identity,
		IdempotencyKey:     request.IdempotencyKey,
		Input:              request.Input,
		Constraints:        request.Constraints,
		Versions:           request.Versions,
		Capabilities:       append([]CapabilityRef{}, request.Capabilities...),
		RequestSHA256:      requestDigest(principal, request),
		PolicyVersion:      PolicyVersion,
		ContextSnapshot:    request.ContextSnapshot,
		CapabilitySnapshot: request.CapabilitySnapshot,
		Evidence:           append([]EvidenceRef{}, request.Evidence...),
		CreatedAt:          service.now(),
	}
	if request.Replan != nil {
		record.ParentDecisionID = request.Replan.ParentDecisionID
		record.ReplanSequence = request.Replan.Sequence
	}

	capabilities := make(map[string]CapabilityRef, len(request.Capabilities))
	for _, capability := range request.Capabilities {
		capabilities[capability.ID] = capability
	}
	required := []struct{ kind, capabilityID string }{
		{"OBSERVE_METRICS", "sre.metrics.read"},
		{"INSPECT_LOGS", "sre.logs.read"},
		{"CORRELATE_CHANGE", "sre.changes.read"},
	}
	if len(request.Evidence) == 0 {
		record.Status = StatusAbstained
		record.Reason = "INSUFFICIENT_EVIDENCE"
	} else {
		steps := make([]PlanStep, 0, len(required))
		for _, item := range required {
			capability, ok := capabilities[item.capabilityID]
			if !ok {
				record.Status = StatusAbstained
				record.Reason = "REQUIRED_CAPABILITY_MISSING"
				steps = nil
				break
			}
			steps = append(steps, PlanStep{
				StepID:          "step_" + digest(struct{ DecisionID, Kind string }{record.DecisionID, item.kind}),
				Kind:            item.kind,
				Capability:      capability,
				TargetRef:       request.Input.Service,
				InputSchemaRef:  capability.InputSchemaRef,
				OutputSchemaRef: capability.OutputSchemaRef,
				ReadOnly:        true,
			})
		}
		if record.Reason == "" {
			candidate := PlanCandidate{
				PlanID:        "plan_" + digest(struct{ DecisionID, RequestSHA256 string }{record.DecisionID, record.RequestSHA256}),
				SchemaVersion: PlanSchemaVersion,
				Steps:         steps,
			}
			candidate.PlanHash = digest(candidate)
			record.Status = StatusProposed
			record.Plan = &candidate
		}
	}
	return service.store.SaveOrGet(ctx, record)
}

func (service *Service) Get(ctx context.Context, principal auth.Principal, agentID, decisionID string) (Record, error) {
	if !validIdentifier(principal.TenantID) || principal.Subject == "" || !validIdentifier(principal.AgentID) ||
		agentID != principal.AgentID || !decisionIDRe.MatchString(decisionID) {
		return Record{}, ErrNotFound
	}
	return service.store.GetByID(ctx, principal.TenantID, agentID, decisionID)
}
