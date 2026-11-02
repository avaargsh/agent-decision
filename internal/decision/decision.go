// Package decision implements a side-effect-free SRE decision planner.
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
	"sync"
	"time"
)

const PolicyVersion = "sre-readonly-v1"
const (
	StatusProposed  = "PROPOSED"
	StatusAbstained = "ABSTAINED"
)

var ErrConflict = errors.New("idempotency key reused with different request")
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var digestRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

type SnapshotRef struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}
type EvidenceRef struct {
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}
type Request struct {
	TenantID       string        `json:"tenant_id"`
	IdempotencyKey string        `json:"idempotency_key"`
	RunID          string        `json:"run_id"`
	Service        string        `json:"service"`
	Signal         string        `json:"signal"`
	Snapshot       SnapshotRef   `json:"context_snapshot"`
	Capability     SnapshotRef   `json:"capability_snapshot"`
	Evidence       []EvidenceRef `json:"evidence_refs"`
}
type PlanStep struct {
	Kind       string `json:"kind"`
	Capability string `json:"capability"`
	TargetRef  string `json:"target_ref"`
	ReadOnly   bool   `json:"read_only"`
}
type Record struct {
	DecisionID         string        `json:"decision_id"`
	TenantID           string        `json:"tenant_id"`
	IdempotencyKey     string        `json:"idempotency_key"`
	RunID              string        `json:"run_id"`
	RequestSHA256      string        `json:"request_sha256"`
	PolicyVersion      string        `json:"policy_version"`
	Status             string        `json:"status"`
	Reason             string        `json:"reason,omitempty"`
	ContextSnapshot    SnapshotRef   `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef   `json:"capability_snapshot"`
	Evidence           []EvidenceRef `json:"evidence_refs"`
	Plan               []PlanStep    `json:"plan"`
	CreatedAt          time.Time     `json:"created_at"`
}

func validRef(ref, sha string) bool {
	return len(ref) > 0 && len(ref) <= 256 && digestRe.MatchString(sha)
}
func (r Request) Validate() error {
	if !nameRe.MatchString(r.TenantID) || !nameRe.MatchString(r.IdempotencyKey) || !nameRe.MatchString(r.RunID) || !nameRe.MatchString(r.Service) {
		return errors.New("tenant_id, idempotency_key, run_id, service must be valid bounded identifiers")
	}
	if r.Signal != "latency" && r.Signal != "errors" && r.Signal != "saturation" {
		return errors.New("signal must be latency, errors, or saturation")
	}
	if !validRef(r.Snapshot.ID, r.Snapshot.SHA256) {
		return errors.New("invalid immutable context_snapshot reference")
	}
	if !validRef(r.Capability.ID, r.Capability.SHA256) {
		return errors.New("invalid ACP capability_snapshot reference")
	}
	if len(r.Evidence) > 32 {
		return errors.New("too many evidence references")
	}
	for _, e := range r.Evidence {
		if !validRef(e.Ref, e.SHA256) {
			return errors.New("invalid evidence reference")
		}
	}
	return nil
}
func digest(x any) string {
	b, _ := json.Marshal(x)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func clone(r Record) Record {
	r.Plan = append([]PlanStep(nil), r.Plan...)
	r.Evidence = append([]EvidenceRef(nil), r.Evidence...)
	return r
}

type Store interface {
	SaveOrGet(context.Context, Record) (Record, bool, error)
}
type MemoryStore struct {
	mu    sync.Mutex
	byKey map[string]Record
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{byKey: make(map[string]Record)} }
func (s *MemoryStore) SaveOrGet(ctx context.Context, r Record) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	key := digest(struct{ TenantID, Key string }{r.TenantID, r.IdempotencyKey})
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
	now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) Decide(ctx context.Context, req Request) (Record, bool, error) {
	if err := req.Validate(); err != nil {
		return Record{}, false, fmt.Errorf("invalid decision request: %w", err)
	}
	// A caller-provided immutable reference is NOT proof its contents were verified.
	record := Record{DecisionID: "dec_" + digest(struct{ TenantID, Key string }{req.TenantID, req.IdempotencyKey}), TenantID: req.TenantID, IdempotencyKey: req.IdempotencyKey,
		RunID: req.RunID, RequestSHA256: digest(req), PolicyVersion: PolicyVersion, ContextSnapshot: req.Snapshot, CapabilitySnapshot: req.Capability, Evidence: append([]EvidenceRef(nil), req.Evidence...), CreatedAt: s.now()}
	if len(req.Evidence) == 0 {
		record.Status = StatusAbstained
		record.Reason = "INSUFFICIENT_EVIDENCE"
		record.Plan = []PlanStep{}
	} else {
		record.Status = StatusProposed
		record.Plan = []PlanStep{
			{Kind: "OBSERVE_METRICS", Capability: "sre.metrics.read", TargetRef: req.Service, ReadOnly: true},
			{Kind: "INSPECT_LOGS", Capability: "sre.logs.read", TargetRef: req.Service, ReadOnly: true},
			{Kind: "CORRELATE_CHANGE", Capability: "sre.changes.read", TargetRef: req.Service, ReadOnly: true},
		}
	}
	return s.store.SaveOrGet(ctx, record)
}
