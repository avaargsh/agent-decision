package decision

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// These are reconstructed acceptance behaviors from the retired Decision Lab
// SRE sample/threshold verifier, not copied legacy source or live telemetry.
func replayJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil { t.Fatal(err) }
	return raw
}

func replaySHA(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func replayFixture(t *testing.T) SLOReplayInput {
	t.Helper()
	policy := map[string]any{
		"schema_version": "sre-slo-health-threshold/v1",
		"metric": "error_ratio",
		"aggregation": "all_samples_lte",
		"source_id": "observer-staging",
		"query_sha256": strings.Repeat("d", 64),
		"max_error_ratio": 0.02,
		"maximum_sample_gap_seconds": 15,
		"minimum_samples_per_phase": 3,
	}
	policyRaw := replayJSON(t, policy)
	input := SLOReplayInput{
		PolicyBytes: policyRaw, ExpectedPolicySHA256: replaySHA(policyRaw),
		Claims: make([]SLOSampleClaim, 0, 2),
		RawSamples: make([][]byte, 0, 2),
	}
	start := time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC)
	for _, phase := range []string{"observation_passed", "verified_recovered"} {
		claim := SLOSampleClaim{
			Phase: phase, SourceID: "observer-staging",
			QuerySHA256: strings.Repeat("d", 64),
			WindowStart: start.Format(time.RFC3339Nano),
			WindowEnd: start.Add(20*time.Second).Format(time.RFC3339Nano),
			SampleCount: 3,
		}
		rows := []map[string]any{}
		for _, offset := range []int{0, 10, 20} {
			rows = append(rows, map[string]any{
				"at": start.Add(time.Duration(offset)*time.Second).Format(time.RFC3339Nano),
				"value": 0.01,
			})
		}
		raw := replayJSON(t, map[string]any{
			"schema_version": "sre-slo-raw-samples/v1",
			"phase": claim.Phase, "source_id": claim.SourceID,
			"query_sha256": claim.QuerySHA256,
			"window_start": claim.WindowStart, "window_end": claim.WindowEnd,
			"samples": rows,
		})
		claim.SamplesSHA256 = replaySHA(raw)
		input.Claims = append(input.Claims, claim)
		input.RawSamples = append(input.RawSamples, raw)
	}
	return input
}

func replayChangePolicy(t *testing.T, input *SLOReplayInput, key string, value any) {
	t.Helper()
	var policy map[string]any
	if err := json.Unmarshal(input.PolicyBytes, &policy); err != nil { t.Fatal(err) }
	policy[key] = value
	input.PolicyBytes = replayJSON(t, policy)
	input.ExpectedPolicySHA256 = replaySHA(input.PolicyBytes)
}

func TestLegacySLOReplayHealthyClaimIsOnlyArithmetic(t *testing.T) {
	input := replayFixture(t)
	report, err := ReplaySLOHealth(input)
	if err != nil { t.Fatal(err) }
	if !report.HealthyClaimConsistent || report.Authorized ||
		report.SourceIndependentlyAuthenticated || report.PolicyIndependentlyAuthenticated ||
		report.ExternalExecutionVerified || report.StagingAccepted {
		t.Fatalf("read-only provenance/authority claims: %+v", report)
	}
	if report.PolicySHA256 != input.ExpectedPolicySHA256 || report.TotalSamples != 6 ||
		len(report.Phases) != 2 {
		t.Fatalf("missing exact policy/digest/sample evidence: %+v", report)
	}
	for _, p := range report.Phases {
		if p.SampleCount != 3 || p.MaxErrorRatio != 0.01 ||
			p.MaxSampleGapSeconds != 10 {
			t.Fatalf("incorrect phase recomputation: %+v", p)
		}
	}
}

func TestLegacySLOReplayFailsClosed(t *testing.T) {
	cases := []struct{
		name string
		mutate func(*testing.T,*SLOReplayInput)
	}{
		{"policy digest substitution", func(t *testing.T, in *SLOReplayInput) { in.ExpectedPolicySHA256 = strings.Repeat("0",64) }},
		{"raw sample substitution", func(t *testing.T, in *SLOReplayInput) { in.RawSamples[0] = append(in.RawSamples[0], ' ') }},
		{"policy exceeds error threshold", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"max_error_ratio",0.005) }},
		{"sample gap exceeds threshold", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"maximum_sample_gap_seconds",5) }},
		{"too few samples", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"minimum_samples_per_phase",4) }},
		{"wrong source", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"source_id","attacker") }},
		{"wrong query digest", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"query_sha256",strings.Repeat("f",64)) }},
		{"unsupported metric", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"metric","latency_ms") }},
		{"unsupported aggregation", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"aggregation","average") }},
		{"invalid bool threshold", func(t *testing.T, in *SLOReplayInput) { replayChangePolicy(t,in,"max_error_ratio",true) }},
		{"wrong claim sample count", func(t *testing.T, in *SLOReplayInput) { in.Claims[0].SampleCount = 2 }},
		{"wrong phase order", func(t *testing.T, in *SLOReplayInput) { in.Claims[0],in.Claims[1] = in.Claims[1],in.Claims[0] }},
		{"missing bundle", func(t *testing.T, in *SLOReplayInput) { in.RawSamples = in.RawSamples[:1] }},
		{"duplicate sample key after rehash", func(t *testing.T, in *SLOReplayInput) {
			in.RawSamples[0] = []byte(strings.Replace(string(in.RawSamples[0]), `"phase":"observation_passed"`, `"phase":"wrong","phase":"observation_passed"`,1))
			in.Claims[0].SamplesSHA256 = replaySHA(in.RawSamples[0])
		}},
		{"nonfinite literal after rehash", func(t *testing.T, in *SLOReplayInput) {
			in.RawSamples[0] = []byte(strings.Replace(string(in.RawSamples[0]), `"value":0.01`, `"value":NaN`,1))
			in.Claims[0].SamplesSHA256 = replaySHA(in.RawSamples[0])
		}},
		{"malformed policy duplicate key after rehash", func(t *testing.T, in *SLOReplayInput) {
			in.PolicyBytes = []byte(strings.Replace(string(in.PolicyBytes), `"metric":"error_ratio"`, `"metric":"average","metric":"error_ratio"`,1))
			in.ExpectedPolicySHA256 = replaySHA(in.PolicyBytes)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name,func(t *testing.T){
			in := replayFixture(t)
			tc.mutate(t,&in)
			if _,err:=ReplaySLOHealth(in);err==nil { t.Fatal("must reject unverifiable or unhealthy SLO claim") }
		})
	}
}

func TestLegacySLOReplayRejectsInvalidTimestampWindowAndValue(t *testing.T) {
	for _, tc := range []struct{name string; change func(map[string]any)}{
		{"outside signed window",func(b map[string]any){
			rows:=b["samples"].([]any); rows[0].(map[string]any)["at"]="2026-11-02T00:59:59Z"
		}},
		{"equal sample timestamps",func(b map[string]any){
			rows:=b["samples"].([]any); rows[1].(map[string]any)["at"]=rows[0].(map[string]any)["at"]
		}},
		{"negative error ratio",func(b map[string]any){
			rows:=b["samples"].([]any); rows[1].(map[string]any)["value"]=-0.01
		}},
		{"above unity error ratio",func(b map[string]any){
			rows:=b["samples"].([]any); rows[1].(map[string]any)["value"]=1.2
		}},
		{"claim window mismatch",func(b map[string]any){
			b["window_end"]="2026-11-02T01:00:30Z"
		}},
	}{
		t.Run(tc.name,func(t *testing.T){
			in:=replayFixture(t)
			var bundle map[string]any
			if err:=json.Unmarshal(in.RawSamples[0],&bundle);err!=nil { t.Fatal(err) }
			tc.change(bundle)
			in.RawSamples[0]=replayJSON(t,bundle)
			in.Claims[0].SamplesSHA256=replaySHA(in.RawSamples[0])
			if _,err:=ReplaySLOHealth(in);err==nil {t.Fatal("signed metadata / sample consistency must fail closed")}
		})
	}
}


// encoding/json accepts case-insensitive struct tags; those aliases cannot
// shadow a signed policy or observer sample field even after local rehashing.
func TestSLOReplayRejectsCaseVariantSemanticAliases(t *testing.T) {
	for _, tc := range []struct {
		name string
		field string
		old string
		replacement string
	}{
		{
			name: "policy metric alias bypass",
			field: "policy",
			old: `"metric":"error_ratio"`,
			replacement: `"metric":"latency_ms","Metric":"error_ratio"`,
		},
		{
			name: "signed sample value alias bypass",
			field: "sample",
			old: `"value":0.01`,
			replacement: `"value":0.90,"Value":0.01`,
		},
		{
			name: "signed sample source alias bypass",
			field: "sample",
			old: `"source_id":"observer-staging"`,
			replacement: `"source_id":"wrong-source","Source_ID":"observer-staging"`,
		},
	} {
		t.Run(tc.name,func(t *testing.T) {
			in:=replayFixture(t)
			if tc.field=="policy" {
				orig:=string(in.PolicyBytes)
				if !strings.Contains(orig,tc.old) { t.Fatalf("fixture missing %s",tc.old) }
				in.PolicyBytes=[]byte(strings.Replace(orig,tc.old,tc.replacement,1))
				in.ExpectedPolicySHA256=replaySHA(in.PolicyBytes)
			} else {
				orig:=string(in.RawSamples[0])
				if !strings.Contains(orig,tc.old) { t.Fatalf("fixture missing %s",tc.old) }
				in.RawSamples[0]=[]byte(strings.Replace(orig,tc.old,tc.replacement,1))
				in.Claims[0].SamplesSHA256=replaySHA(in.RawSamples[0])
			}
			if _,err:=ReplaySLOHealth(in);err==nil {
				t.Fatal("case-variant semantic alias must fail closed, including after matching caller SHA-256")
			}
		})
	}
}
