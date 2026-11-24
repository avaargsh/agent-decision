package evaluationdataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func validTestManifest(now time.Time) Manifest {
	approved := now.Add(-48 * time.Hour)
	windowFrom := now.Add(-72 * time.Hour)
	windowTo := now.Add(-70 * time.Hour)
	return Manifest{
		SchemaVersion: ManifestSchemaV1,
		DatasetID: "sre-incidents-pilot",
		DatasetKind: DatasetKindHumanAdjudicatedSRE,
		Authorization: Authorization{
			SourceOwner: "source-owner-01",
			GrantRef: "grant-2026-001",
			GrantSHA256: testDigest("grant-artifact"),
			ApprovedAt: approved,
			ExpiresAt: now.Add(30 * 24 * time.Hour),
			ScopeSHA256: testDigest("approved-scope"),
			DeidentificationRef: "deid-attestation-001",
			DeidentificationSHA256: testDigest("deidentification-attestation"),
			DeidentifiedAt: approved.Add(time.Hour),
		},
		Cases: []Case{validTestCase("case-dev-001", SplitDevelopment, "incident-dev-001", "evidence-dev-001", now, windowFrom, windowTo)},
	}
}

func validTestCase(id string, split Split, incident string, artifact string, now, from, to time.Time) Case {
	label := testDigest("final-label-" + id)
	return Case{
		CaseID: id,
		Split: split,
		IncidentRef: incident,
		EvidenceSHA256: testDigest(artifact),
		ObservationFrom: from,
		ObservationTo: to,
		Adjudication: Adjudication{
			ReviewerIDs: []string{"reviewer-a", "reviewer-b"},
			IndependentLabelSHA256: []string{label, label},
			Consensus: true,
			FinalLabelSHA256: label,
			AdjudicatedAt: to.Add(time.Hour),
		},
	}
}

func TestValidateManifestSeparatesSplitsAndReportsCohortReadiness(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	manifest.Cases = append(manifest.Cases,
		validTestCase("case-gold-001", SplitGold, "incident-gold-001", "evidence-gold-001", now, now.Add(-72*time.Hour), now.Add(-70*time.Hour)),
		validTestCase("case-holdout-001", SplitHoldout, "incident-holdout-001", "evidence-holdout-001", now, now.Add(-72*time.Hour), now.Add(-70*time.Hour)),
	)
	report, err := ValidateManifest(manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.DatasetID != manifest.DatasetID || report.CaseCount != 3 ||
		report.DevelopmentCount != 1 || report.GoldCount != 1 || report.HoldoutCount != 1 {
		t.Fatalf("unexpected split counts: %+v", report)
	}
	if report.CohortSizeReady || len(report.ReadinessBlockers) != 2 {
		t.Fatalf("small pilot must not be represented as benchmark-ready: %+v", report)
	}
	if !report.ProvenanceReferencesComplete {
		t.Fatalf("valid provenance references should be reported complete: %+v", report)
	}
}

func TestValidateManifestMarksOnlyThresholdSizedCohortsReady(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	for i := 0; i < MinimumGoldCasesForCohortReadiness; i++ {
		id := fmt.Sprintf("case-gold-%03d", i+1)
		manifest.Cases = append(manifest.Cases, validTestCase(id, SplitGold,
			fmt.Sprintf("incident-gold-%03d", i+1), fmt.Sprintf("evidence-gold-%03d", i+1),
			now, now.Add(-72*time.Hour), now.Add(-70*time.Hour)))
	}
	for i := 0; i < MinimumHoldoutCasesForCohortReadiness; i++ {
		id := fmt.Sprintf("case-holdout-%03d", i+1)
		manifest.Cases = append(manifest.Cases, validTestCase(id, SplitHoldout,
			fmt.Sprintf("incident-holdout-%03d", i+1), fmt.Sprintf("evidence-holdout-%03d", i+1),
			now, now.Add(-72*time.Hour), now.Add(-70*time.Hour)))
	}
	report, err := ValidateManifest(manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CohortSizeReady || len(report.ReadinessBlockers) != 0 ||
		report.GoldCount != MinimumGoldCasesForCohortReadiness ||
		report.HoldoutCount != MinimumHoldoutCasesForCohortReadiness {
		t.Fatalf("expected cohort-size gate to pass at documented thresholds: %+v", report)
	}
}

func TestValidateManifestRejectsInvalidAuthorizationAndReviewProvenance(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	base := validTestManifest(now)
	tests := []struct {
		name string
		mutate func(*Manifest)
	}{
		{"expired_grant", func(m *Manifest) { m.Authorization.ExpiresAt = now }},
		{"future_grant", func(m *Manifest) { m.Authorization.ApprovedAt = now.Add(time.Minute) }},
		{"missing_grant_ref", func(m *Manifest) { m.Authorization.GrantRef = "" }},
		{"invalid_scope_digest", func(m *Manifest) { m.Authorization.ScopeSHA256 = "sha256:bad" }},
		{"missing_deidentification_attestation", func(m *Manifest) { m.Authorization.DeidentificationRef = "" }},
		{"deidentification_before_approval", func(m *Manifest) { m.Authorization.DeidentifiedAt = m.Authorization.ApprovedAt.Add(-time.Minute) }},
		{"duplicate_reviewers", func(m *Manifest) { m.Cases[0].Adjudication.ReviewerIDs[1] = m.Cases[0].Adjudication.ReviewerIDs[0] }},
		{"missing_independent_review", func(m *Manifest) { m.Cases[0].Adjudication.IndependentLabelSHA256 = m.Cases[0].Adjudication.IndependentLabelSHA256[:1] }},
		{"consensus_label_mismatch", func(m *Manifest) { m.Cases[0].Adjudication.IndependentLabelSHA256[1] = testDigest("different-label") }},
		{"consensus_with_adjudicator", func(m *Manifest) { m.Cases[0].Adjudication.AdjudicatorID = "reviewer-c" }},
		{"disagreement_without_adjudicator", func(m *Manifest) {
			m.Cases[0].Adjudication.Consensus = false
			m.Cases[0].Adjudication.IndependentLabelSHA256[1] = testDigest("different-label")
		}},
		{"adjudicator_is_reviewer", func(m *Manifest) {
			m.Cases[0].Adjudication.Consensus = false
			m.Cases[0].Adjudication.IndependentLabelSHA256[1] = testDigest("different-label")
			m.Cases[0].Adjudication.AdjudicatorID = m.Cases[0].Adjudication.ReviewerIDs[0]
		}},
		{"adjudication_before_observation_end", func(m *Manifest) { m.Cases[0].Adjudication.AdjudicatedAt = m.Cases[0].ObservationTo.Add(-time.Second) }},
		{"unknown_split", func(m *Manifest) { m.Cases[0].Split = "TRAIN_AND_TEST" }},
		{"invalid_artifact_digest", func(m *Manifest) { m.Cases[0].EvidenceSHA256 = "not-a-digest" }},
		{"empty_cases", func(m *Manifest) { m.Cases = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.Cases = append([]Case(nil), base.Cases...)
			candidate.Cases[0].Adjudication.ReviewerIDs = append([]string(nil), base.Cases[0].Adjudication.ReviewerIDs...)
			candidate.Cases[0].Adjudication.IndependentLabelSHA256 = append([]string(nil), base.Cases[0].Adjudication.IndependentLabelSHA256...)
			tc.mutate(&candidate)
			if _, err := ValidateManifest(candidate, now); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("expected ErrInvalidManifest, got %v", err)
			}
		})
	}
}

func TestValidateManifestRejectsCrossSplitLeakageAndDuplicateCases(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	base := validTestManifest(now)
	gold := validTestCase("case-gold-001", SplitGold, "incident-gold-001", "evidence-gold-001", now, now.Add(-72*time.Hour), now.Add(-70*time.Hour))
	holdout := validTestCase("case-holdout-001", SplitHoldout, "incident-holdout-001", "evidence-holdout-001", now, now.Add(-72*time.Hour), now.Add(-70*time.Hour))
	tests := []struct {
		name string
		cases []Case
	}{
		{"duplicate_case_id", []Case{base.Cases[0], base.Cases[0]}},
		{"same_incident_across_splits", []Case{gold, func() Case { c := holdout; c.IncidentRef = gold.IncidentRef; return c }()}},
		{"same_artifact_across_splits", []Case{gold, func() Case { c := holdout; c.EvidenceSHA256 = gold.EvidenceSHA256; return c }()}},
		{"same_incident_within_split", []Case{gold, func() Case { c := holdout; c.Split = SplitGold; c.IncidentRef = gold.IncidentRef; return c }()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := base
			manifest.Cases = tc.cases
			if _, err := ValidateManifest(manifest, now); !errors.Is(err, ErrDatasetLeakage) {
				t.Fatalf("expected ErrDatasetLeakage, got %v", err)
			}
		})
	}
}

func TestParseManifestRejectsDuplicateKeysUnknownFieldsAndTrailingJSON(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := strings.TrimSuffix(string(encoded), "}") + `,"unexpected":true}`
	duplicate := strings.Replace(string(encoded), `"dataset_id":"sre-incidents-pilot"`,
		`"dataset_id":"first","dataset_id":"second"`, 1)
	for _, tc := range []struct{name, raw string}{
		{"duplicate_key", duplicate},
		{"nested_duplicate_key", strings.Replace(string(encoded), `"source_owner":"source-owner-01"`, `"source_owner":"first","source_owner":"second"`, 1)},
		{"unknown_field", withUnknown},
		{"trailing_json", string(encoded) + `{}`},
		{"invalid_json", `{"schema_version":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseManifest([]byte(tc.raw), now); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("expected ErrInvalidManifest, got %v", err)
			}
		})
	}
	if _, _, err := ParseManifest(bytes.Repeat([]byte("x"), MaximumManifestBytes+1), now); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("oversized manifest must fail closed, got %v", err)
	}
}

func TestParseManifestReturnsExactRawManifestDigest(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, report, err := ParseManifest(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.ManifestSHA256 != testDigest(string(raw)) {
		t.Fatalf("manifest digest mismatch: got %s", report.ManifestSHA256)
	}
}


func TestSplitUseKeepsGoldAndHoldoutOutOfTraining(t *testing.T) {
	if err := ValidateSplitUse(SplitDevelopment, PurposeTraining); err != nil {
		t.Fatalf("development split should be available for training: %v", err)
	}
	for _, split := range []Split{SplitGold, SplitHoldout} {
		if err := ValidateSplitUse(split, PurposeTraining); !errors.Is(err, ErrSplitUseDenied) {
			t.Fatalf("%s must be denied for training, got %v", split, err)
		}
		if err := ValidateSplitUse(split, PurposeEvaluation); err != nil {
			t.Fatalf("%s should be available for evaluation: %v", split, err)
		}
	}
	if err := ValidateSplitUse(Split("UNKNOWN"), PurposeEvaluation); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unknown split must fail closed, got %v", err)
	}
}

func TestValidateManifestAcceptsThirdReviewerResolution(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	adjudication := &manifest.Cases[0].Adjudication
	adjudication.Consensus = false
	adjudication.IndependentLabelSHA256[1] = testDigest("second-reviewer-label")
	adjudication.AdjudicatorID = "reviewer-c"
	adjudication.FinalLabelSHA256 = testDigest("adjudicated-final-label")
	if _, err := ValidateManifest(manifest, now); err != nil {
		t.Fatalf("valid third-reviewer resolution rejected: %v", err)
	}
}

func TestVerifyAuthorizationArtifactsChecksExactBytes(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	grant := []byte("source-owner grant bytes")
	deidentification := []byte("de-identification attestation bytes")
	manifest.Authorization.GrantSHA256 = testDigest(string(grant))
	manifest.Authorization.DeidentificationSHA256 = testDigest(string(deidentification))
	if err := VerifyAuthorizationArtifacts(manifest, bytes.NewReader(grant), bytes.NewReader(deidentification)); err != nil {
		t.Fatalf("valid authorization artifacts rejected: %v", err)
	}
	if err := VerifyAuthorizationArtifacts(manifest, bytes.NewReader([]byte("tampered")), bytes.NewReader(deidentification)); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("tampered grant must fail closed, got %v", err)
	}
}

func TestVerifyArtifactsChecksExactEvidenceAndLabelBytes(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	evidence := []byte("opaque de-identified evidence bundle")
	labels := []byte("adjudicated label document")
	manifest.Cases[0].EvidenceSHA256 = testDigest(string(evidence))
	manifest.Cases[0].Adjudication.FinalLabelSHA256 = testDigest(string(labels))
	manifest.Cases[0].Adjudication.IndependentLabelSHA256 = []string{
		manifest.Cases[0].Adjudication.FinalLabelSHA256,
		manifest.Cases[0].Adjudication.FinalLabelSHA256,
	}
	evidenceReaders := map[string]io.Reader{"case-dev-001": bytes.NewReader(evidence)}
	labelReaders := map[string]io.Reader{"case-dev-001": bytes.NewReader(labels)}
	if err := VerifyArtifacts(manifest, evidenceReaders, labelReaders); err != nil {
		t.Fatalf("valid artifact bytes rejected: %v", err)
	}
}

func TestVerifyArtifactsRejectsMissingExtraAndMismatchedBytes(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	manifest := validTestManifest(now)
	evidence := []byte("evidence")
	labels := []byte("labels")
	manifest.Cases[0].EvidenceSHA256 = testDigest(string(evidence))
	manifest.Cases[0].Adjudication.FinalLabelSHA256 = testDigest(string(labels))
	manifest.Cases[0].Adjudication.IndependentLabelSHA256 = []string{
		manifest.Cases[0].Adjudication.FinalLabelSHA256,
		manifest.Cases[0].Adjudication.FinalLabelSHA256,
	}
	tests := []struct {
		name string
		evidence map[string]io.Reader
		labels map[string]io.Reader
	}{
		{"missing_evidence", map[string]io.Reader{}, map[string]io.Reader{"case-dev-001": bytes.NewReader(labels)}},
		{"extra_evidence", map[string]io.Reader{"case-dev-001": bytes.NewReader(evidence), "unexpected": bytes.NewReader(evidence)}, map[string]io.Reader{"case-dev-001": bytes.NewReader(labels)}},
		{"missing_labels", map[string]io.Reader{"case-dev-001": bytes.NewReader(evidence)}, map[string]io.Reader{}},
		{"wrong_evidence", map[string]io.Reader{"case-dev-001": bytes.NewReader([]byte("tampered"))}, map[string]io.Reader{"case-dev-001": bytes.NewReader(labels)}},
		{"wrong_labels", map[string]io.Reader{"case-dev-001": bytes.NewReader(evidence)}, map[string]io.Reader{"case-dev-001": bytes.NewReader([]byte("tampered"))}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyArtifacts(manifest, tc.evidence, tc.labels); !errors.Is(err, ErrArtifactIntegrity) {
				t.Fatalf("expected ErrArtifactIntegrity, got %v", err)
			}
		})
	}
}
