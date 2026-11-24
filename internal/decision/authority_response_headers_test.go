package decision

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAuthorityClientRequiresExactSingletonResponseHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		contentTypes, cacheControls []string
		reject bool
	}{
		{"canonical", []string{"application/json"}, []string{"no-store"}, false},
		{"duplicate media", []string{"application/json", "application/json"}, []string{"no-store"}, true},
		{"conflicting media", []string{"application/json", "text/plain"}, []string{"no-store"}, true},
		{"conflicting cache", []string{"application/json"}, []string{"no-store", "public"}, true},
		{"duplicate cache", []string{"application/json"}, []string{"no-store", "no-store"}, true},
		{"combined cache", []string{"application/json"}, []string{"no-store, public"}, true},
		{"missing media", nil, []string{"no-store"}, true},
		{"missing cache", []string{"application/json"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &authorityClient{origin: "https://fixture.invalid", client: &http.Client{
				Transport: freshnessTransport(func(*http.Request) (*http.Response, error) {
					h := make(http.Header)
					for _, v := range tc.contentTypes { h.Add("Content-Type", v) }
					for _, v := range tc.cacheControls { h.Add("Cache-Control", v) }
					return &http.Response{StatusCode: http.StatusOK, Header: h,
						Body: io.NopCloser(strings.NewReader("{}"))}, nil
				}),
			}}
			raw, err := client.read(context.Background(), http.MethodGet, "/fixture", nil, 32)
			if tc.reject {
				if !errors.Is(err, ErrAuthorityUnavailable) || raw != nil {
					t.Fatalf("ambiguous response accepted: raw=%q err=%v", raw, err)
				}
			} else if err != nil || string(raw) != "{}" {
				t.Fatalf("canonical response rejected: raw=%q err=%v", raw, err)
			}
		})
	}
}
