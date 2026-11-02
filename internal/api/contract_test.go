package api

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/decision"
)

type jsonSchema map[string]any

func loadSchema(t *testing.T, path string) jsonSchema {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil { t.Fatalf("read schema %s: %v", path, err) }
	var schema jsonSchema
	if err := json.Unmarshal(data, &schema); err != nil { t.Fatalf("decode schema %s: %v", path, err) }
	return schema
}

func schemaTypeMatches(schema jsonSchema, want string) bool {
	switch value := schema["type"].(type) {
	case string:
		return value == want
	case []any:
		for _, candidate := range value {
			if candidate == want { return true }
		}
	}
	return false
}

func resolveSchema(t *testing.T, root jsonSchema, node jsonSchema) jsonSchema {
	t.Helper()
	ref, ok := node["$ref"].(string)
	if !ok { return node }
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) { t.Fatalf("unsupported local schema ref %q", ref) }
	defs, ok := root["$defs"].(map[string]any)
	if !ok { t.Fatalf("schema has no $defs for %q", ref) }
	resolved, ok := defs[strings.TrimPrefix(ref, prefix)].(map[string]any)
	if !ok { t.Fatalf("schema definition %q not found", ref) }
	return resolved
}

func assertGoTypeMatchesSchema(t *testing.T, root jsonSchema, typ reflect.Type, node jsonSchema, path string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer { typ = typ.Elem() }
	node = resolveSchema(t, root, node)

	if typ == reflect.TypeOf(time.Time{}) {
		if !schemaTypeMatches(node, "string") || node["format"] != "date-time" {
			t.Errorf("%s: time.Time must be a date-time string", path)
		}
		return
	}
	if typ.Kind() == reflect.Slice {
		if !schemaTypeMatches(node, "array") { t.Errorf("%s: expected array schema", path); return }
		items, ok := node["items"].(map[string]any)
		if !ok { t.Errorf("%s: array items schema missing", path); return }
		assertGoTypeMatchesSchema(t, root, typ.Elem(), items, path+"[]")
		return
	}
	if typ.Kind() != reflect.Struct {
		want := map[reflect.Kind]string{reflect.String:"string", reflect.Int:"integer", reflect.Int64:"integer", reflect.Bool:"boolean"}[typ.Kind()]
		if want != "" && !schemaTypeMatches(node, want) { t.Errorf("%s: Go %s does not match JSON Schema type %s", path, typ.Kind(), want) }
		return
	}

	properties, ok := node["properties"].(map[string]any)
	if !ok { t.Fatalf("%s: object properties missing", path) }
	if node["additionalProperties"] != false { t.Errorf("%s: object must reject additional properties", path) }
	required := map[string]bool{}
	if fields, ok := node["required"].([]any); ok {
		for _, field := range fields { if name, ok := field.(string); ok { required[name] = true } }
	}
	for i:=0; i<typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" { continue }
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" { name = field.Name }
		child, exists := properties[name]
		if !exists { t.Errorf("%s: Go field %s missing from schema properties", path, name); continue }
		optional := false
		for _, option := range parts[1:] { if option == "omitempty" { optional = true } }
		if required[name] == optional { t.Errorf("%s.%s: required mismatch (omitempty=%v, schema-required=%v)", path, name, optional, required[name]) }
		childSchema, ok := child.(map[string]any)
		if !ok { t.Errorf("%s.%s: invalid property schema", path, name); continue }
		assertGoTypeMatchesSchema(t, root, field.Type, childSchema, path+"."+name)
	}
	for name := range required {
		if _, exists := properties[name]; !exists { t.Errorf("%s: required field %s has no property", path, name) }
	}
}

func TestDecisionJSONSchemasMatchGoContracts(t *testing.T) {
	requestSchema := loadSchema(t, "../../api/schemas/decision-request.schema.json")
	assertGoTypeMatchesSchema(t, requestSchema, reflect.TypeOf(decision.Request{}), requestSchema, "DecisionRequest")

	recordSchema := loadSchema(t, "../../api/schemas/decision-record.schema.json")
	assertGoTypeMatchesSchema(t, recordSchema, reflect.TypeOf(decision.Record{}), recordSchema, "DecisionRecord")
}

func TestEvidenceEnvelopeSchemaIsConsistentAcrossRequestAndRecord(t *testing.T) {
	request := loadSchema(t, "../../api/schemas/decision-request.schema.json")
	record := loadSchema(t, "../../api/schemas/decision-record.schema.json")
	requestDefs := request["$defs"].(map[string]any)
	recordDefs := record["$defs"].(map[string]any)
	requestEvidence := requestDefs["EvidenceRef"]
	recordEvidence := recordDefs["EvidenceRef"]
	if !reflect.DeepEqual(requestEvidence, recordEvidence) {
		t.Fatal("DecisionRequest and DecisionRecord EvidenceRef schemas must be identical")
	}
	evidence := requestEvidence.(map[string]any)
	properties := evidence["properties"].(map[string]any)
	version := properties["schema_version"].(map[string]any)
	if version["pattern"] != StringRawSemverPattern {
		t.Fatalf("unexpected evidence schema_version pattern: %v", version["pattern"])
	}
}

const StringRawSemverPattern = "^[0-9]+\\.[0-9]+\\.[0-9]+$"

func TestOpenAPIContractReferencesVersionedSchemas(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil { t.Fatal(err) }
	spec := string(data)
	for _, required := range []string{
		"openapi: 3.1.0",
		"/v1/decisions:",
		"DecisionRequest",
		"DecisionRecord",
		"DecisionPage",
		"/v1/decisions/{decision_id}",
		"/v1/runs/{run_id}/decisions",
		"decision-request.schema.json",
		"decision-record.schema.json",
		"/healthz:",
		"IDEMPOTENCY_CONFLICT",
	} {
		if !strings.Contains(spec, required) { t.Errorf("OpenAPI contract is missing %q", required) }
	}
}

func TestDecisionPageAndProblemSchemas(t *testing.T) {
	page := loadSchema(t, "../../api/schemas/decision-page.schema.json")
	properties, ok := page["properties"].(map[string]any)
	if !ok {
		t.Fatal("DecisionPage properties missing")
	}
	items, ok := properties["items"].(map[string]any)
	if !ok || items["type"] != "array" {
		t.Fatal("DecisionPage.items must be an array")
	}
	itemSchema, ok := items["items"].(map[string]any)
	if !ok || itemSchema["$ref"] != "./decision-record.schema.json" {
		t.Fatal("DecisionPage.items must reference DecisionRecord")
	}
	required, ok := page["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "items" {
		t.Fatalf("DecisionPage required fields mismatch: %v", required)
	}

	problem := loadSchema(t, "../../api/schemas/problem.schema.json")
	errorSchema := problem["properties"].(map[string]any)["error"].(map[string]any)
	codeSchema := errorSchema["properties"].(map[string]any)["code"].(map[string]any)
	codes, ok := codeSchema["enum"].([]any)
	if !ok {
		t.Fatal("Problem.error.code must enumerate stable error codes")
	}
	seen := map[any]bool{}
	for _, code := range codes {
		seen[code] = true
	}
	for _, code := range []string{"NOT_FOUND", "INVALID_CURSOR", "IDEMPOTENCY_CONFLICT", "STORE_UNAVAILABLE"} {
		if !seen[code] {
			t.Errorf("Problem schema is missing error code %s", code)
		}
	}
}
