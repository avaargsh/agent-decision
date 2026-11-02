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

func validateStrategyResult(req Request, result StrategyResult) error {
	if result.Status != StatusProposed && result.Status != StatusAbstained {
		return ErrInvalidRequest
	}
	if result.Status == StatusAbstained {
		if len(result.Steps) != 0 || len(result.ReasonCodes) == 0 {
			return ErrInvalidRequest
		}
		return nil
	}
	if len(result.Steps) == 0 || len(result.Steps) > 3 {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(result.Steps))
	for _, step := range result.Steps {
		if !validOpaque(step.StepID) || !step.ReadOnly ||
			step.Capability.EffectClass != "read_only" ||
			step.Capability.Idempotency != "safe" || !step.Capability.TenantScoped ||
			step.TargetRef != req.Input.Service ||
			step.InputSchemaRef != step.Capability.InputSchemaRef ||
			step.OutputSchemaRef != step.Capability.OutputSchemaRef {
			return ErrInvalidRequest
		}
		bound, ok := findCapability(req.Capabilities, step.Capability.ID)
		if !ok || digest(bound) != digest(step.Capability) {
			return ErrInvalidRequest
		}
		if _, exists := seen[step.StepID]; exists {
			return ErrInvalidRequest
		}
		seen[step.StepID] = struct{}{}
	}
	return nil
}
