package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const testPrincipalID = "00000000-0000-4000-8000-000000000901"

func verificationBody(extra map[string]any) string {
	claims := map[string]any{"iss": "auth-service", "aud": "frontend", "exp": time.Now().Add(time.Hour).Unix()}
	for key, value := range extra {
		claims[key] = value
	}
	data, _ := json.Marshal(map[string]any{"user_id": testPrincipalID, "claims": claims})
	return string(data)
}

func TestAuthVerifierWireAndAccessCredentialBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"legacy-access", 200, verificationBody(nil), nil},
		{"explicit-access", 200, verificationBody(map[string]any{"typ": "access", "purpose": "access"}), nil},
		{"audience-array", 200, verificationBody(map[string]any{"aud": []string{"frontend"}}), nil},
		{"forged", 401, `{"error":"invalid_token"}`, domain.ErrUnauthenticated},
		{"refresh", 200, verificationBody(map[string]any{"typ": "refresh"}), domain.ErrUnauthenticated},
		{"non-access-type", 200, verificationBody(map[string]any{"typ": "signup"}), domain.ErrUnauthenticated},
		{"non-access-purpose", 200, verificationBody(map[string]any{"purpose": "password-reset"}), domain.ErrUnauthenticated},
		{"malformed-type", 200, verificationBody(map[string]any{"typ": 3}), domain.ErrUnauthenticated},
		{"null-purpose", 200, verificationBody(map[string]any{"purpose": nil}), domain.ErrUnauthenticated},
		{"expired", 200, verificationBody(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}), domain.ErrUnauthenticated},
		{"string-expiry", 200, verificationBody(map[string]any{"exp": "99999999999"}), domain.ErrAuthorityUnavailable},
		{"null-expiry", 200, verificationBody(map[string]any{"exp": nil}), domain.ErrAuthorityUnavailable},
		{"invalid-expiry", 200, verificationBody(map[string]any{"exp": 0}), domain.ErrAuthorityUnavailable},
		{"out-of-range-expiry", 200, verificationBody(map[string]any{"exp": 1e100}), domain.ErrAuthorityUnavailable},
		{"empty-issuer", 200, verificationBody(map[string]any{"iss": ""}), domain.ErrAuthorityUnavailable},
		{"wrong-issuer-type", 200, verificationBody(map[string]any{"iss": 42}), domain.ErrAuthorityUnavailable},
		{"empty-audience", 200, verificationBody(map[string]any{"aud": []string{}}), domain.ErrAuthorityUnavailable},
		{"malformed-audience", 200, verificationBody(map[string]any{"aud": []any{"frontend", 3}}), domain.ErrAuthorityUnavailable},
		{"missing-subject", 200, `{"claims":{}}`, domain.ErrAuthorityUnavailable},
		{"malformed-subject", 200, strings.Replace(verificationBody(nil), testPrincipalID, "forged-admin", 1), domain.ErrAuthorityUnavailable},
		{"nil-uuid-subject", 200, strings.Replace(verificationBody(nil), testPrincipalID, "00000000-0000-0000-0000-000000000000", 1), domain.ErrAuthorityUnavailable},
		{"missing-claims", 200, fmt.Sprintf(`{"user_id":%q}`, testPrincipalID), domain.ErrAuthorityUnavailable},
		{"empty-claims", 200, fmt.Sprintf(`{"user_id":%q,"claims":{}}`, testPrincipalID), domain.ErrAuthorityUnavailable},
		{"malformed-json", 200, "{", domain.ErrAuthorityUnavailable},
		{"trailing-json", 200, verificationBody(nil) + "{}", domain.ErrAuthorityUnavailable},
		{"oversized-body", 200, strings.Repeat(" ", maxVerifyResponseBytes+1) + verificationBody(nil), domain.ErrAuthorityUnavailable},
		{"dependency-error", 503, "dependency detail must remain private", domain.ErrAuthorityUnavailable},
		{"unexpected-status", 201, verificationBody(nil), domain.ErrAuthorityUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/auth/verify" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("unexpected Auth verification request")
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("X-User-Role") != "" {
					t.Error("caller headers forwarded to authority")
				}
				var input map[string]string
				if json.NewDecoder(r.Body).Decode(&input) != nil || input["token"] != "synthetic-credential" || len(input) != 1 {
					t.Error("unexpected verification payload")
				}
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer authority.Close()
			verifier, err := NewAuthVerifier(authority.URL + "/api/v1/auth/verify")
			if err != nil {
				t.Fatal(err)
			}
			actor, err := verifier.VerifyAccessToken(context.Background(), "synthetic-credential")
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.want == nil && actor.PrincipalID != testPrincipalID {
				t.Fatal("authority subject was not retained")
			}
			if tc.want != nil && actor.PrincipalID != "" {
				t.Fatal("denial returned an actor")
			}
			if calls.Load() != 1 {
				t.Fatalf("expected one authority request, got %d", calls.Load())
			}
		})
	}
}

func TestAuthVerifierDoesNotFollowRedirectsOrUseFallback(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		_, _ = fmt.Fprint(w, verificationBody(nil))
	}))
	defer target.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, status)
			}))
			defer authority.Close()
			verifier, err := NewAuthVerifier(authority.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.VerifyAccessToken(context.Background(), "synthetic-credential")
			if !errors.Is(err, domain.ErrAuthorityUnavailable) {
				t.Fatalf("redirect did not fail closed: %v", err)
			}
		})
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect forwarded a credential to another endpoint")
	}

	for _, endpoint := range []string{"", target.URL} {
		if endpoint != "" {
			target.Close()
		}
		verifier, err := NewAuthVerifier(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifier.VerifyAccessToken(context.Background(), "synthetic-credential")
		if !errors.Is(err, domain.ErrAuthorityUnavailable) {
			t.Fatalf("missing or offline authority did not fail closed: %v", err)
		}
	}
}

func TestAuthVerifierConfigurationAndTimeout(t *testing.T) {
	for _, endpoint := range []string{"/api/v1/auth/verify", "ftp://authority/verify", "https:///verify", "http://user:pass@authority/verify", "http://authority/verify?fallback=yes", "http://authority/verify?", "http://authority/verify#fragment", " http://authority/verify"} {
		if _, err := NewAuthVerifier(endpoint); err == nil {
			t.Errorf("accepted invalid authority configuration")
		}
	}
	authority := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer authority.Close()
	verifier, err := NewAuthVerifier(authority.URL)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy could receive credentials")
	}
	verifier.client.Timeout = 20 * time.Millisecond
	_, err = verifier.VerifyAccessToken(context.Background(), "synthetic-credential")
	if !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("timeout did not fail closed: %v", err)
	}
}
