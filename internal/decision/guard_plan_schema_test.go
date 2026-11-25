package decision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type guardPlanReceiptSchema struct {
	ID                   string                     `json:"$id"`
	Draft                string                     `json:"$schema"`
	Type                 string                     `json:"type"`
	AdditionalProperties bool                       `json:"additionalProperties"`
	Required             []string                   `json:"required"`
	Properties           map[string]json.RawMessage `json:"properties"`
}

func TestGuardPlanStepReceiptSchemaMatchesGoContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "schemas", "guard-plan-step-receipt.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema guardPlanReceiptSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode receipt schema: %v", err)
	}
	if schema.ID != "urn:avaargsh:agent-decision:guard-plan-step-receipt:v1" ||
		schema.Draft != "https://json-schema.org/draft/2020-12/schema" ||
		schema.Type != "object" || schema.AdditionalProperties {
		t.Fatalf("unexpected receipt schema envelope: %+v", schema)
	}

	goFields := make(map[string]struct{})
	typ := reflect.TypeOf(GuardPlanStepReceipt{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("GuardPlanStepReceipt.%s has no explicit JSON field name", typ.Field(i).Name)
		}
		goFields[tag] = struct{}{}
	}
	if len(schema.Properties) != len(goFields) {
		t.Fatalf("schema property count=%d, Go JSON field count=%d", len(schema.Properties), len(goFields))
	}
	for name := range goFields {
		if _, ok := schema.Properties[name]; !ok {
			t.Errorf("schema omits Go JSON field %q", name)
		}
	}
	required := make(map[string]struct{}, len(schema.Required))
	for _, name := range schema.Required {
		if _, duplicate := required[name]; duplicate {
			t.Errorf("schema repeats required field %q", name)
		}
		required[name] = struct{}{}
		if _, ok := goFields[name]; !ok {
			t.Errorf("schema requires unknown Go JSON field %q", name)
		}
	}
	if len(required) != len(goFields) {
		t.Errorf("required field count=%d, Go JSON field count=%d", len(required), len(goFields))
	}

	assertProperty := func(name string, want map[string]any) {
		t.Helper()
		var got map[string]any
		if err := json.Unmarshal(schema.Properties[name], &got); err != nil {
			t.Fatalf("decode property %q: %v", name, err)
		}
		for key, expected := range want {
			if got[key] != expected {
				t.Errorf("property %q %s=%v, want %v", name, key, got[key], expected)
			}
		}
	}
	assertProperty("schema_version", map[string]any{"const": GuardPlanStepSchema})
	assertProperty("status", map[string]any{"const": "VERIFIED"})
	uuidPattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	for _, name := range []string{"run_id", "run_attempt_id", "turn_id"} {
		assertProperty(name, map[string]any{"type": "string", "minLength": float64(36), "maxLength": float64(36), "pattern": uuidPattern})
	}
	assertProperty("decision_id", map[string]any{"pattern": "^dec_[a-f0-9]{64}$"})
	assertProperty("plan_hash", map[string]any{"pattern": "^[0-9a-f]{64}$"})
	assertProperty("record_sha256", map[string]any{"pattern": "^[0-9a-f]{64}$"})
	assertProperty("step_id", map[string]any{"type": "string", "minLength": float64(1), "maxLength": float64(255)})
	assertProperty("breaker_epoch", map[string]any{"type": "integer", "minimum": float64(1)})
	assertProperty("breaker_version", map[string]any{"type": "integer", "minimum": float64(1)})
}
