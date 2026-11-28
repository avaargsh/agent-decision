package api

import (
	"bytes"
	"net/http"
	"testing"
)

func TestHTTPRejectsLossyUnicodeBeforeDecisionPersistence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement []byte
	}{
		{"invalid UTF-8", []byte{'r', 'e', 'f', 0xff}},
		{"unpaired high surrogate", []byte(`ref\uD800`)},
		{"unpaired low surrogate", []byte(`ref\uDC00`)},
		{"high surrogate followed by non-low", []byte(`ref\uD800\u0041`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(resolverFor(apiPrincipal()), apiAuthority{})
			body := bytes.Replace(validBody(), []byte("slo-sample-17"), tc.replacement, 1)
			if w := send(h, body, "application/json"); w.Code != http.StatusBadRequest {
				t.Fatalf("lossy Unicode accepted: %d %s", w.Code, w.Body.String())
			}
			if w := send(h, validBody(), "application/json"); w.Code != http.StatusCreated {
				t.Fatalf("invalid request consumed invocation: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestJSONUnicodeAllowsLosslessEncodings(t *testing.T) {
	for _, body := range []string{
		`{"ref":"中文"}`,
		`{"ref":"\uD83D\uDE00"}`,
		`{"ref":"\uFFFD"}`,
		`{"ref":"�"}`,
		`{"ref":"\\uD800"}`,
		`{"ref":"escaped \" quote"}`,
	} {
		if err := validateJSONObjects([]byte(body)); err != nil {
			t.Errorf("valid JSON %s: %v", body, err)
		}
	}
}
