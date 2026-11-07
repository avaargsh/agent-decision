package decision

import (
	"regexp"
	"sort"
)

// Strategy owns decision policy only. It cannot authorize or execute capabilities.
type Strategy interface {
	Version() string
	Plan(Request, string) StrategyResult
}

type StrategyResult struct {
	Status      string
	ReasonCodes []string
	Steps       []PlanStep
}

var (
	reasonCodeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	requiredSREStepKinds = map[string]string{
		"sre.metrics.read":  "OBSERVE_METRICS",
		"sre.logs.read":     "INSPECT_LOGS",
		"sre.changes.read":  "CORRELATE_CHANGE",
	}
)

// SREReadOnlyStrategy creates a deterministic, all-or-nothing investigation plan.
type SREReadOnlyStrategy struct{}

func (SREReadOnlyStrategy) Version() string { return PolicyVersion }

func evidenceSupportsStep(capabilityID, evidenceType string) bool {
	switch capabilityID {
	case "sre.metrics.read":
		return evidenceType == "metrics" || evidenceType == "slo"
	case "sre.logs.read":
		return evidenceType == "logs"
	case "sre.changes.read":
		return evidenceType == "change"
	default:
		return false
	}
}

func evidenceBindingsFor(req Request, capabilityID string) []EvidenceBinding {
	bindings := make([]EvidenceBinding, 0)
	for _, evidence := range req.Evidence {
		if evidenceSupportsStep(capabilityID, evidence.EvidenceType) {
			bindings = append(bindings, EvidenceBinding{SourceID: evidence.SourceID, Ref: evidence.Ref})
		}
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].SourceID == bindings[j].SourceID {
			return bindings[i].Ref < bindings[j].Ref
		}
		return bindings[i].SourceID < bindings[j].SourceID
	})
	return bindings
}

// SREReadOnlyStrategy creates a deterministic, all-or-nothing investigation plan.
// Each read step is bound to evidence of the corresponding source type.
func (SREReadOnlyStrategy) Plan(req Request, decisionID string) StrategyResult {
	result := StrategyResult{
		Status: StatusProposed,
		ReasonCodes: []string{},
		Steps: []PlanStep{},
	}
	required := []struct {
		id string
		kind string
		missingEvidenceReason string
	}{
		{"sre.metrics.read", "OBSERVE_METRICS", "MISSING_REQUIRED_METRICS_EVIDENCE"},
		{"sre.logs.read", "INSPECT_LOGS", "MISSING_REQUIRED_LOGS_EVIDENCE"},
		{"sre.changes.read", "CORRELATE_CHANGE", "MISSING_REQUIRED_CHANGE_EVIDENCE"},
	}
	for _, item := range required {
		capability, ok := findCapability(req.Capabilities, item.id)
		if !ok {
			return StrategyResult{Status: StatusAbstained, ReasonCodes: []string{"MISSING_REQUIRED_CAPABILITY"}, Steps: []PlanStep{}}
		}
		bindings := evidenceBindingsFor(req, item.id)
		if len(bindings) == 0 {
			return StrategyResult{Status: StatusAbstained, ReasonCodes: []string{item.missingEvidenceReason}, Steps: []PlanStep{}}
		}
		result.Steps = append(result.Steps, PlanStep{
			StepID: "step_" + digest(struct {
				DecisionID string
				CapabilityID string
			}{decisionID, item.id})[:24],
			Kind: item.kind,
			Capability: capability,
			TargetRef: req.Input.Service,
			InputSchemaRef: capability.InputSchemaRef,
			OutputSchemaRef: capability.OutputSchemaRef,
			EvidenceRefs: bindings,
			ReadOnly: true,
		})
	}
	return result
}

func validateStrategyResult(req Request, result StrategyResult) error {
	if result.Status != StatusProposed && result.Status != StatusAbstained {
		return ErrInvalidRequest
	}
	seenReasons := make(map[string]struct{}, len(result.ReasonCodes))
	for _, reason := range result.ReasonCodes {
		if !reasonCodeRe.MatchString(reason) {
			return ErrInvalidRequest
		}
		if _, exists := seenReasons[reason]; exists {
			return ErrInvalidRequest
		}
		seenReasons[reason] = struct{}{}
	}
	if result.Status == StatusAbstained {
		if len(result.Steps) != 0 || len(result.ReasonCodes) == 0 {
			return ErrInvalidRequest
		}
		return nil
	}
	// sre-readonly-v1 is intentionally all-or-nothing: all three required
	// investigation steps appear once, with a fixed capability-to-kind mapping.
	if len(result.Steps) != len(requiredSREStepKinds) {
		return ErrInvalidRequest
	}
	evidenceByKey := make(map[string]EvidenceRef, len(req.Evidence))
	for _, evidence := range req.Evidence {
		key := evidenceBindingKey(EvidenceBinding{SourceID: evidence.SourceID, Ref: evidence.Ref})
		evidenceByKey[key] = evidence
	}
	seenSteps := make(map[string]struct{}, len(result.Steps))
	seenCapabilities := make(map[string]struct{}, len(result.Steps))
	for _, step := range result.Steps {
		expectedKind, supported := requiredSREStepKinds[step.Capability.ID]
		if !supported || step.Kind != expectedKind ||
			!validOpaque(step.StepID) || !step.ReadOnly ||
			step.Capability.EffectClass != "read_only" ||
			step.Capability.Idempotency != "safe" || !step.Capability.TenantScoped ||
			step.TargetRef != req.Input.Service ||
			step.InputSchemaRef != step.Capability.InputSchemaRef ||
			step.OutputSchemaRef != step.Capability.OutputSchemaRef {
			return ErrInvalidRequest
		}
		bound, ok := findCapability(req.Capabilities, step.Capability.ID)
		if !ok || digest(bound) != digest(step.Capability) || len(step.EvidenceRefs) == 0 {
			return ErrInvalidRequest
		}
		seenEvidence := make(map[string]struct{}, len(step.EvidenceRefs))
		for _, binding := range step.EvidenceRefs {
			if !validOpaque(binding.SourceID) || !validOpaque(binding.Ref) {
				return ErrInvalidRequest
			}
			key := evidenceBindingKey(binding)
			evidence, exists := evidenceByKey[key]
			if !exists || !evidenceSupportsStep(step.Capability.ID, evidence.EvidenceType) {
				return ErrInvalidRequest
			}
			if _, duplicate := seenEvidence[key]; duplicate {
				return ErrInvalidRequest
			}
			seenEvidence[key] = struct{}{}
		}
		if _, exists := seenSteps[step.StepID]; exists {
			return ErrInvalidRequest
		}
		if _, exists := seenCapabilities[step.Capability.ID]; exists {
			return ErrInvalidRequest
		}
		seenSteps[step.StepID] = struct{}{}
		seenCapabilities[step.Capability.ID] = struct{}{}
	}
	return nil
}
