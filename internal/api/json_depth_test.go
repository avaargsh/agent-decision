package api

import (
	"strings"
	"testing"
)

func TestValidateJSONObjectsBoundsNestingDepth(t *testing.T) {
	// The request body is bounded to 1 MiB, but deeply nested token streams
	// must also be bounded so untrusted JSON cannot exhaust validator stack.
	for _, tc := range []struct {
		name    string
		payload string
		reject  bool
	}{
		{"max array nesting accepted", strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64), false},
		{"array nesting beyond limit rejected", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), true},
		{"max object nesting accepted", strings.Repeat("{\"a\":", 64) + "0" + strings.Repeat("}", 64), false},
		{"object nesting beyond limit rejected", strings.Repeat("{\"a\":", 65) + "0" + strings.Repeat("}", 65), true},
		{"mixed nesting beyond limit rejected", strings.Repeat("[{\"a\":", 33) + "0" + strings.Repeat("}]", 33), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateJSONObjects([]byte(tc.payload))
			if (err != nil) != tc.reject {
				t.Fatalf("nesting depth reject=%v, got error %v", tc.reject, err)
			}
		})
	}
}
