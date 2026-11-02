package decision

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

// SREReadOnlyStrategy creates a deterministic, all-or-nothing investigation plan.
type SREReadOnlyStrategy struct{}

func (SREReadOnlyStrategy) Version() string { return PolicyVersion }

func (SREReadOnlyStrategy) Plan(req Request, decisionID string) StrategyResult {
	result := StrategyResult{
		Status:      StatusProposed,
		ReasonCodes: []string{},
		Steps:       []PlanStep{},
	}
	if len(req.Evidence) == 0 {
		result.Status = StatusAbstained
		result.ReasonCodes = []string{"INSUFFICIENT_EVIDENCE"}
		return result
	}

	required := []struct {
		id   string
		kind string
	}{
		{"sre.metrics.read", "OBSERVE_METRICS"},
		{"sre.logs.read", "INSPECT_LOGS"},
		{"sre.changes.read", "CORRELATE_CHANGE"},
	}
	for _, item := range required {
		capability, ok := findCapability(req.Capabilities, item.id)
		if !ok {
			result.Status = StatusAbstained
			result.ReasonCodes = []string{"MISSING_REQUIRED_CAPABILITY"}
			result.Steps = []PlanStep{}
			return result
		}
		result.Steps = append(result.Steps, PlanStep{
			StepID: "step_" + digest(struct {
				DecisionID  string
				CapabilityID string
			}{decisionID, item.id})[:24],
			Kind:            item.kind,
			Capability:      capability,
			TargetRef:       req.Input.Service,
			InputSchemaRef:  capability.InputSchemaRef,
			OutputSchemaRef: capability.OutputSchemaRef,
			ReadOnly:        true,
		})
	}
	return result
}
