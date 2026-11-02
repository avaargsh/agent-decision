package decision

// This file reconstructs the retired Decision Lab's SLO sample / policy
// consistency checks as a bounded, read-only Go helper. These are untrusted
// external claims until an independent source verifier authenticates them.
// This package never approves, executes, or advances an Agent Run.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

const (
	maxSLOPolicyBytes = 64 * 1024
	maxSLORawBytes = 2 * 1024 * 1024
	maxSLOSampleCount = 1_000_000
)

type SLOSampleClaim struct {
	Phase string
	SourceID string
	QuerySHA256 string
	WindowStart string
	WindowEnd string
	SamplesSHA256 string
	SampleCount int
}

// SLOReplayInput carries externally supplied claims, not certified telemetry.
// The owning AuthorityVerifier must separately authenticate the observer,
// digest-bearing metadata and threshold policy before trusting their origin.
type SLOReplayInput struct {
	PolicyBytes []byte
	ExpectedPolicySHA256 string
	Claims []SLOSampleClaim
	RawSamples [][]byte
}

type SLOReplayPhaseReport struct {
	Phase string `json:"phase"`
	SampleCount int `json:"sample_count"`
	MaxErrorRatio float64 `json:"max_error_ratio"`
	MaxSampleGapSeconds float64 `json:"max_sample_gap_seconds"`
}

type SLOReplayReport struct {
	PolicySHA256 string `json:"policy_sha256"`
	TotalSamples int `json:"total_samples"`
	Phases []SLOReplayPhaseReport `json:"phases"`
	HealthyClaimConsistent bool `json:"healthy_claim_consistent"`
	SourceIndependentlyAuthenticated bool `json:"source_independently_authenticated"`
	PolicyIndependentlyAuthenticated bool `json:"policy_independently_authenticated"`
	ExternalExecutionVerified bool `json:"external_execution_verified"`
	StagingAccepted bool `json:"staging_accepted"`
	Authorized bool `json:"authorized"`
}

type replayPolicy struct {
	SchemaVersion string `json:"schema_version"`
	Metric string `json:"metric"`
	Aggregation string `json:"aggregation"`
	SourceID string `json:"source_id"`
	QuerySHA256 string `json:"query_sha256"`
	MaxErrorRatio *float64 `json:"max_error_ratio"`
	MaximumSampleGapSeconds *int `json:"maximum_sample_gap_seconds"`
	MinimumSamplesPerPhase *int `json:"minimum_samples_per_phase"`
}

type replayRow struct {
	At string `json:"at"`
	Value *float64 `json:"value"`
}

type replayBundle struct {
	SchemaVersion string `json:"schema_version"`
	Phase string `json:"phase"`
	SourceID string `json:"source_id"`
	QuerySHA256 string `json:"query_sha256"`
	WindowStart string `json:"window_start"`
	WindowEnd string `json:"window_end"`
	Samples []replayRow `json:"samples"`
}

func replaySHA256(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func replayDigestValid(s string) bool {
	if len(s) != 64 { return false }
	for _, b := range []byte(s) {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') { return false }
	}
	return true
}

// decodeSLOStrict rejects duplicate JSON fields recursively, unknown schema
// fields, trailing tokens, nonfinite JSON constants, and invalid exponents.
func decodeSLOStrict(raw []byte, output any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil { return err }
		mark, isDelim := token.(json.Delim)
		if !isDelim { return nil }
		switch mark {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil { return err }
				key, ok := keyToken.(string)
				if !ok { return errors.New("object key must be a string") }
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate SLO JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil { return err }
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil { return err }
			}
			_, err := dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", mark)
		}
	}
	if err := walk(); err != nil { return fmt.Errorf("invalid SLO JSON: %w", err) }
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid SLO JSON trailing token")
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(output); err != nil { return fmt.Errorf("invalid SLO schema: %w", err) }
	if _, err := typed.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid SLO JSON trailing token")
	}
	return nil
}

func replayTimestamp(s string) (time.Time, error) {
	if s == "" { return time.Time{}, errors.New("missing SLO observation timestamp") }
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil { return time.Time{}, fmt.Errorf("SLO timestamp must include timezone: %w", err) }
	return parsed.UTC(), nil
}

func replayBoundedSourceID(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s
}

// ReplaySLOHealth applies only deterministic consistency checks. It cannot
// authenticate a claimed source, signed receipt, metadata authority, policy
// custody, or real staging execution.
func ReplaySLOHealth(input SLOReplayInput) (SLOReplayReport, error) {
	fail := func(reason string) (SLOReplayReport, error) {
		return SLOReplayReport{}, fmt.Errorf("SLO replay rejected: %s", reason)
	}
	if len(input.Claims) != 2 || len(input.RawSamples) != 2 {
		return fail("exactly two observation phases are required")
	}
	if len(input.PolicyBytes) == 0 || len(input.PolicyBytes) > maxSLOPolicyBytes ||
		!replayDigestValid(input.ExpectedPolicySHA256) {
		return fail("policy size or digest invalid")
	}
	// Own immutable snapshots; a caller may reuse or mutate Go byte slices.
	policyRaw := append([]byte(nil), input.PolicyBytes...)
	claims := append([]SLOSampleClaim(nil), input.Claims...)
	raws := make([][]byte, 2)
	for i := range raws {
		if len(input.RawSamples[i]) == 0 || len(input.RawSamples[i]) > maxSLORawBytes {
			return fail("sample bundle size invalid")
		}
		raws[i] = append([]byte(nil), input.RawSamples[i]...)
	}
	if replaySHA256(policyRaw) != input.ExpectedPolicySHA256 {
		return fail("policy SHA-256 does not match independently supplied pin")
	}
	var policy replayPolicy
	if err := decodeSLOStrict(policyRaw, &policy); err != nil {
		return SLOReplayReport{}, err
	}
	if policy.SchemaVersion != "sre-slo-health-threshold/v1" ||
		policy.Metric != "error_ratio" || policy.Aggregation != "all_samples_lte" ||
		!replayBoundedSourceID(policy.SourceID) || !replayDigestValid(policy.QuerySHA256) {
		return fail("unsupported or invalid threshold policy")
	}
	if policy.MaxErrorRatio == nil || math.IsNaN(*policy.MaxErrorRatio) ||
		math.IsInf(*policy.MaxErrorRatio, 0) ||
		*policy.MaxErrorRatio < 0 || *policy.MaxErrorRatio > 1 ||
		policy.MaximumSampleGapSeconds == nil ||
		*policy.MaximumSampleGapSeconds < 1 || *policy.MaximumSampleGapSeconds > 86400 ||
		policy.MinimumSamplesPerPhase == nil ||
		*policy.MinimumSamplesPerPhase < 2 ||
		*policy.MinimumSamplesPerPhase > maxSLOSampleCount {
		return fail("invalid maximum error ratio, gap or minimum sample count")
	}
	report := SLOReplayReport{
		PolicySHA256: input.ExpectedPolicySHA256,
		Phases: make([]SLOReplayPhaseReport, 0, 2),
	}
	for i, phase := range []string{"observation_passed", "verified_recovered"} {
		claim := claims[i]
		if claim.Phase != phase || claim.SourceID != policy.SourceID ||
			claim.QuerySHA256 != policy.QuerySHA256 ||
			!replayDigestValid(claim.SamplesSHA256) ||
			claim.SampleCount < 2 || claim.SampleCount > maxSLOSampleCount {
			return fail("observation identity or signed claim shape mismatch")
		}
		if replaySHA256(raws[i]) != claim.SamplesSHA256 {
			return fail("raw sample SHA-256 mismatch")
		}
		var bundle replayBundle
		if err := decodeSLOStrict(raws[i], &bundle); err != nil {
			return SLOReplayReport{}, err
		}
		if bundle.SchemaVersion != "sre-slo-raw-samples/v1" ||
			bundle.Phase != claim.Phase || bundle.SourceID != claim.SourceID ||
			bundle.QuerySHA256 != claim.QuerySHA256 ||
			bundle.WindowStart != claim.WindowStart || bundle.WindowEnd != claim.WindowEnd {
			return fail("raw sample metadata differs from observer claim")
		}
		if len(bundle.Samples) != claim.SampleCount ||
			len(bundle.Samples) < *policy.MinimumSamplesPerPhase {
			return fail("sample count too small or mismatched")
		}
		from, err := replayTimestamp(claim.WindowStart)
		if err != nil { return SLOReplayReport{}, err }
		to, err := replayTimestamp(claim.WindowEnd)
		if err != nil { return SLOReplayReport{}, err }
		if !to.After(from) { return fail("observation window must be positive") }
		previous := time.Time{}
		maxGap := 0.0
		maxErrorRatio := 0.0
		for j, row := range bundle.Samples {
			if row.Value == nil || math.IsNaN(*row.Value) || math.IsInf(*row.Value, 0) ||
				*row.Value < 0 || *row.Value > 1 {
				return fail("sample error ratio outside finite [0,1]")
			}
			t, err := replayTimestamp(row.At)
			if err != nil { return SLOReplayReport{}, err }
			if t.Before(from) || t.After(to) || (j > 0 && !t.After(previous)) {
				return fail("sample timestamps outside bound or not increasing")
			}
			if j == 0 && !t.Equal(from) {
				return fail("sample series must begin at window start")
			}
			if j > 0 {
				gap := t.Sub(previous).Seconds()
				if gap > maxGap { maxGap = gap }
			}
			if *row.Value > maxErrorRatio { maxErrorRatio = *row.Value }
			previous = t
		}
		if !previous.Equal(to) || maxGap > float64(*policy.MaximumSampleGapSeconds) ||
			maxErrorRatio > *policy.MaxErrorRatio {
			return fail("observation coverage, gap or error ratio contradicts healthy claim")
		}
		report.TotalSamples += len(bundle.Samples)
		report.Phases = append(report.Phases, SLOReplayPhaseReport{
			Phase: phase, SampleCount: len(bundle.Samples),
			MaxErrorRatio: maxErrorRatio, MaxSampleGapSeconds: maxGap,
		})
	}
	report.HealthyClaimConsistent = true
	// The remaining report booleans deliberately retain their zero values:
	// no source/policy authentication, external execution or authorization.
	return report, nil
}
