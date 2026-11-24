package evaluationdataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

const (
	ManifestSchemaV1 = "sre.incident-dataset-manifest.v1"
	DatasetKindHumanAdjudicatedSRE = "HUMAN_ADJUDICATED_SRE_INCIDENTS"

	MinimumGoldCasesForCohortReadiness = 30
	MinimumHoldoutCasesForCohortReadiness = 20

	MaximumManifestBytes = 1 << 20
	MaximumArtifactBytes = 256 << 20
)

type Split string

type Purpose string

const (
	PurposeTraining   Purpose = "TRAINING"
	PurposeEvaluation Purpose = "EVALUATION"
)

const (
	SplitDevelopment Split = "DEVELOPMENT"
	SplitGold        Split = "GOLD"
	SplitHoldout     Split = "HOLDOUT"
)

var (
	ErrInvalidManifest = errors.New("invalid incident dataset manifest")
	ErrDatasetLeakage  = errors.New("incident dataset split leakage")
	ErrArtifactIntegrity = errors.New("incident dataset artifact integrity failure")
	ErrSplitUseDenied = errors.New("incident dataset split use denied")

	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

type Manifest struct {
	SchemaVersion string        `json:"schema_version"`
	DatasetID     string        `json:"dataset_id"`
	DatasetKind   string        `json:"dataset_kind"`
	Authorization Authorization `json:"authorization"`
	Cases         []Case        `json:"cases"`
}

// Authorization records source-owner permission and de-identification
// provenance. References and digests are required metadata; this package does
// not verify their signatures or replace the production AuthorityVerifier.
type Authorization struct {
	SourceOwner               string    `json:"source_owner"`
	GrantRef                  string    `json:"grant_ref"`
	GrantSHA256               string    `json:"grant_sha256"`
	ApprovedAt                time.Time `json:"approved_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	ScopeSHA256               string    `json:"scope_sha256"`
	DeidentificationRef       string    `json:"deidentification_ref"`
	DeidentificationSHA256    string    `json:"deidentification_sha256"`
	DeidentifiedAt            time.Time `json:"deidentified_at"`
}

type Case struct {
	CaseID          string       `json:"case_id"`
	Split           Split        `json:"split"`
	IncidentRef     string       `json:"incident_ref"`
	EvidenceSHA256  string       `json:"evidence_sha256"`
	ObservationFrom time.Time    `json:"observation_from"`
	ObservationTo   time.Time    `json:"observation_to"`
	Adjudication    Adjudication `json:"adjudication"`
}

type Adjudication struct {
	ReviewerIDs              []string  `json:"reviewer_ids"`
	IndependentLabelSHA256   []string  `json:"independent_label_sha256"`
	Consensus                bool      `json:"consensus"`
	AdjudicatorID            string    `json:"adjudicator_id,omitempty"`
	FinalLabelSHA256         string    `json:"final_label_sha256"`
	AdjudicatedAt            time.Time `json:"adjudicated_at"`
}

type AdmissionReport struct {
	DatasetID                   string   `json:"dataset_id"`
	ManifestSHA256              string   `json:"manifest_sha256,omitempty"`
	CaseCount                   int      `json:"case_count"`
	DevelopmentCount            int      `json:"development_count"`
	GoldCount                   int      `json:"gold_count"`
	HoldoutCount                int      `json:"holdout_count"`
	ProvenanceReferencesComplete bool    `json:"provenance_references_complete"`
	CohortSizeReady             bool     `json:"cohort_size_ready"`
	ReadinessBlockers           []string `json:"readiness_blockers"`
}

// ParseManifest strictly decodes a bounded JSON manifest, rejects duplicate
// keys and unknown fields, validates metadata and returns the digest of the
// exact submitted bytes. It does not authenticate the source-owner grant or
// reviewer identities; those remain external trust-verification gates.
func ParseManifest(raw []byte, now time.Time) (Manifest, AdmissionReport, error) {
	if len(raw) == 0 || len(raw) > MaximumManifestBytes || rejectDuplicateJSONKeys(raw) != nil {
		return Manifest{}, AdmissionReport{}, ErrInvalidManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, AdmissionReport{}, fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, AdmissionReport{}, ErrInvalidManifest
	}
	report, err := ValidateManifest(manifest, now)
	if err != nil {
		return Manifest{}, AdmissionReport{}, err
	}
	sum := sha256.Sum256(raw)
	report.ManifestSHA256 = hex.EncodeToString(sum[:])
	return manifest, report, nil
}

// ValidateManifest checks authorization/de-identification metadata,
// independent-review consistency, immutable artifact references, and
// development/Gold/Holdout split disjointness. Cohort readiness is only a
// sample-count gate; it is not benchmark quality or production acceptance.
func ValidateManifest(manifest Manifest, now time.Time) (AdmissionReport, error) {
	if now.IsZero() || manifest.SchemaVersion != ManifestSchemaV1 ||
		!validIdentifier(manifest.DatasetID) ||
		manifest.DatasetKind != DatasetKindHumanAdjudicatedSRE ||
		len(manifest.Cases) == 0 || len(manifest.Cases) > 10000 {
		return AdmissionReport{}, ErrInvalidManifest
	}
	if !validAuthorization(manifest.Authorization, now) {
		return AdmissionReport{}, ErrInvalidManifest
	}

	report := AdmissionReport{
		DatasetID: manifest.DatasetID,
		CaseCount: len(manifest.Cases),
		ProvenanceReferencesComplete: true,
		ReadinessBlockers: []string{},
	}
	seenCaseIDs := make(map[string]struct{}, len(manifest.Cases))
	seenIncidentRefs := make(map[string]struct{}, len(manifest.Cases))
	seenEvidenceDigests := make(map[string]struct{}, len(manifest.Cases))

	for _, item := range manifest.Cases {
		if !validIdentifier(item.CaseID) || !validIdentifier(item.IncidentRef) ||
			!validSHA256(item.EvidenceSHA256) ||
			item.ObservationFrom.IsZero() || item.ObservationTo.IsZero() ||
			!item.ObservationTo.After(item.ObservationFrom) ||
			!validAdjudication(item.Adjudication, item.ObservationTo, now) {
			return AdmissionReport{}, ErrInvalidManifest
		}
		switch item.Split {
		case SplitDevelopment:
			report.DevelopmentCount++
		case SplitGold:
			report.GoldCount++
		case SplitHoldout:
			report.HoldoutCount++
		default:
			return AdmissionReport{}, ErrInvalidManifest
		}

		if _, exists := seenCaseIDs[item.CaseID]; exists {
			return AdmissionReport{}, fmt.Errorf("%w: duplicate case id", ErrDatasetLeakage)
		}
		if _, exists := seenIncidentRefs[item.IncidentRef]; exists {
			return AdmissionReport{}, fmt.Errorf("%w: incident appears more than once", ErrDatasetLeakage)
		}
		if _, exists := seenEvidenceDigests[item.EvidenceSHA256]; exists {
			return AdmissionReport{}, fmt.Errorf("%w: evidence artifact appears more than once", ErrDatasetLeakage)
		}
		seenCaseIDs[item.CaseID] = struct{}{}
		seenIncidentRefs[item.IncidentRef] = struct{}{}
		seenEvidenceDigests[item.EvidenceSHA256] = struct{}{}
	}

	if report.DevelopmentCount == 0 {
		report.ReadinessBlockers = append(report.ReadinessBlockers, "DEVELOPMENT_CASES_BELOW_MINIMUM")
	}
	if report.GoldCount < MinimumGoldCasesForCohortReadiness {
		report.ReadinessBlockers = append(report.ReadinessBlockers, "GOLD_CASES_BELOW_MINIMUM")
	}
	if report.HoldoutCount < MinimumHoldoutCasesForCohortReadiness {
		report.ReadinessBlockers = append(report.ReadinessBlockers, "HOLDOUT_CASES_BELOW_MINIMUM")
	}
	sort.Strings(report.ReadinessBlockers)
	report.CohortSizeReady = len(report.ReadinessBlockers) == 0
	return report, nil
}

// ValidateSplitUse keeps Gold and Holdout data out of training/tuning paths.
// Callers must enforce this check before exposing split artifacts to a consumer.
func ValidateSplitUse(split Split, purpose Purpose) error {
	switch purpose {
	case PurposeTraining:
		if split == SplitDevelopment {
			return nil
		}
		return ErrSplitUseDenied
	case PurposeEvaluation:
		switch split {
		case SplitDevelopment, SplitGold, SplitHoldout:
			return nil
		default:
			return ErrInvalidManifest
		}
	default:
		return ErrInvalidManifest
	}
}

// VerifyAuthorizationArtifacts checks the exact grant and de-identification
// attestation bytes referenced by the manifest. Signature and signer trust
// verification remain the responsibility of the production authority layer.
func VerifyAuthorizationArtifacts(manifest Manifest, grant, deidentification io.Reader) error {
	if !validSHA256(manifest.Authorization.GrantSHA256) ||
		!validSHA256(manifest.Authorization.DeidentificationSHA256) ||
		verifyReaderDigest(grant, manifest.Authorization.GrantSHA256) != nil ||
		verifyReaderDigest(deidentification, manifest.Authorization.DeidentificationSHA256) != nil {
		return ErrArtifactIntegrity
	}
	return nil
}

// VerifyArtifacts streams the exact evidence and final-label bytes for every
// case and compares their SHA-256 digests. Both maps must contain exactly one
// non-nil reader per case; missing or extra artifacts fail closed.
func VerifyArtifacts(manifest Manifest, evidence, labels map[string]io.Reader) error {
	if len(manifest.Cases) == 0 || len(evidence) != len(manifest.Cases) || len(labels) != len(manifest.Cases) {
		return ErrArtifactIntegrity
	}
	seen := make(map[string]struct{}, len(manifest.Cases))
	for _, item := range manifest.Cases {
		if !validIdentifier(item.CaseID) || !validSHA256(item.EvidenceSHA256) ||
			!validSHA256(item.Adjudication.FinalLabelSHA256) {
			return ErrArtifactIntegrity
		}
		if _, exists := seen[item.CaseID]; exists {
			return ErrArtifactIntegrity
		}
		seen[item.CaseID] = struct{}{}
		if err := verifyReaderDigest(evidence[item.CaseID], item.EvidenceSHA256); err != nil {
			return fmt.Errorf("%w: evidence bytes for %s", ErrArtifactIntegrity, item.CaseID)
		}
		if err := verifyReaderDigest(labels[item.CaseID], item.Adjudication.FinalLabelSHA256); err != nil {
			return fmt.Errorf("%w: label bytes for %s", ErrArtifactIntegrity, item.CaseID)
		}
	}
	for id := range evidence {
		if _, exists := seen[id]; !exists {
			return ErrArtifactIntegrity
		}
	}
	for id := range labels {
		if _, exists := seen[id]; !exists {
			return ErrArtifactIntegrity
		}
	}
	return nil
}

func validAuthorization(authorization Authorization, now time.Time) bool {
	return validIdentifier(authorization.SourceOwner) &&
		validIdentifier(authorization.GrantRef) &&
		validSHA256(authorization.GrantSHA256) &&
		!authorization.ApprovedAt.IsZero() && !authorization.ApprovedAt.After(now) &&
		!authorization.ExpiresAt.IsZero() && authorization.ExpiresAt.After(now) &&
		authorization.ExpiresAt.After(authorization.ApprovedAt) &&
		validSHA256(authorization.ScopeSHA256) &&
		validIdentifier(authorization.DeidentificationRef) &&
		validSHA256(authorization.DeidentificationSHA256) &&
		!authorization.DeidentifiedAt.IsZero() &&
		!authorization.DeidentifiedAt.Before(authorization.ApprovedAt) &&
		!authorization.DeidentifiedAt.After(now)
}

func validAdjudication(adjudication Adjudication, observationTo, now time.Time) bool {
	if len(adjudication.ReviewerIDs) != 2 || len(adjudication.IndependentLabelSHA256) != 2 ||
		!validIdentifier(adjudication.ReviewerIDs[0]) ||
		!validIdentifier(adjudication.ReviewerIDs[1]) ||
		adjudication.ReviewerIDs[0] == adjudication.ReviewerIDs[1] ||
		!validSHA256(adjudication.IndependentLabelSHA256[0]) ||
		!validSHA256(adjudication.IndependentLabelSHA256[1]) ||
		!validSHA256(adjudication.FinalLabelSHA256) ||
		adjudication.AdjudicatedAt.IsZero() ||
		adjudication.AdjudicatedAt.Before(observationTo) ||
		adjudication.AdjudicatedAt.After(now) {
		return false
	}
	if adjudication.Consensus {
		return adjudication.IndependentLabelSHA256[0] == adjudication.IndependentLabelSHA256[1] &&
			adjudication.FinalLabelSHA256 == adjudication.IndependentLabelSHA256[0] &&
			adjudication.AdjudicatorID == ""
	}
	return adjudication.IndependentLabelSHA256[0] != adjudication.IndependentLabelSHA256[1] &&
		validIdentifier(adjudication.AdjudicatorID) &&
		adjudication.AdjudicatorID != adjudication.ReviewerIDs[0] &&
		adjudication.AdjudicatorID != adjudication.ReviewerIDs[1]
}

func verifyReaderDigest(reader io.Reader, expected string) error {
	if reader == nil {
		return ErrArtifactIntegrity
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(reader, MaximumArtifactBytes+1))
	if err != nil || n > MaximumArtifactBytes || hex.EncodeToString(hash.Sum(nil)) != expected {
		return ErrArtifactIntegrity
	}
	return nil
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidManifest
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidManifest
			}
			if _, exists := seen[key]; exists {
				return ErrInvalidManifest
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidManifest
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidManifest
		}
	default:
		return ErrInvalidManifest
	}
	return nil
}
