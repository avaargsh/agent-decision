package decision

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestVerifyCommittedProposalReconstructsFullRecord(t *testing.T) {
	p, req := testPrincipal(), validRequest()
	stored, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), p, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedProposal(p, req, stored); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Record)
	}{
		{"changed policy", func(r *Record) { r.StrategyVersion = "other" }},
		{"changed subject", func(r *Record) { r.SubjectID = "other" }},
		{"changed evidence", func(r *Record) { r.Evidence[0].SHA256 = strings.Repeat("f", 64) }},
		{"changed request hash", func(r *Record) { r.RequestSHA256 = strings.Repeat("f", 64) }},
		{"changed plan and recomputed hash", func(r *Record) {
			r.Plan.Steps[0].TargetRef = "other-service"
			r.Plan.PlanHash = planHash(r.Plan)
		}},
		{"changed plan ID and recomputed hash", func(r *Record) {
			r.Plan.PlanID = "other-plan"
			r.Plan.PlanHash = planHash(r.Plan)
		}},
		{"changed outcome", func(r *Record) { r.Status = StatusAbstained }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := clone(stored)
			tc.mutate(&tampered)
			if err := verifyCommittedProposal(p, req, tampered); !errors.Is(err, ErrAuthorityRejected) {
				t.Fatalf("tampered committed record was not rejected: %v", err)
			}
		})
	}
	req.Evidence = []EvidenceRef{}
	abstained, _, err := NewService(NewMemoryStore(), allowAuthority{}).Decide(context.Background(), p, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedProposal(p, req, abstained); !errors.Is(err, ErrAuthorityRejected) {
		t.Fatal("abstention incorrectly granted continuation")
	}
}
