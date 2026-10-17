package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const maxVerifyResponseBytes = 64 << 10

// AuthVerifier uses exactly the operator-configured Auth verification endpoint.
// It does not derive authority from caller headers or locally decoded JWTs.
type AuthVerifier struct {
	endpoint string
	client   *http.Client
}

func NewAuthVerifier(endpoint string) (*AuthVerifier, error) {
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" ||
			parsed.ForceQuery || parsed.Fragment != "" || strings.TrimSpace(endpoint) != endpoint {
			return nil, errors.New("AUTH_VERIFY_URL must be an absolute trusted HTTP endpoint without credentials, query or fragment")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &AuthVerifier{
		endpoint: endpoint,
		client: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (v *AuthVerifier) VerifyAccessToken(ctx context.Context, token string) (domain.VerifiedActor, error) {
	if v == nil || v.endpoint == "" {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	body, err := json.Marshal(struct {
		Token string `json:"token"`
	}{Token: token})
	if err != nil {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return domain.VerifiedActor{}, domain.ErrUnauthenticated
	}
	if resp.StatusCode != http.StatusOK {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxVerifyResponseBytes+1))
	if err != nil || len(data) > maxVerifyResponseBytes {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	var result struct {
		UserID string                     `json:"user_id"`
		Claims map[string]json.RawMessage `json:"claims"`
	}
	if err := json.Unmarshal(data, &result); err != nil || !domain.ValidPrincipalID(result.UserID) || result.Claims == nil {
		return domain.VerifiedActor{}, domain.ErrAuthorityUnavailable
	}
	if err := validateAccessClaims(result.Claims, time.Now()); err != nil {
		return domain.VerifiedActor{}, err
	}
	return domain.VerifiedActor{PrincipalID: result.UserID}, nil
}

func validateAccessClaims(claims map[string]json.RawMessage, now time.Time) error {
	for _, key := range []string{"typ", "purpose"} {
		if raw, present := claims[key]; present {
			var value string
			if json.Unmarshal(raw, &value) != nil || value != "access" {
				return domain.ErrUnauthenticated
			}
		}
	}
	// Auth checks configured issuer/audience. These checks reject incomplete or
	// malformed success bodies, without introducing a second authority config.
	var issuer string
	if json.Unmarshal(claims["iss"], &issuer) != nil || strings.TrimSpace(issuer) == "" {
		return domain.ErrAuthorityUnavailable
	}
	var audience string
	if json.Unmarshal(claims["aud"], &audience) != nil || strings.TrimSpace(audience) == "" {
		var audiences []string
		if json.Unmarshal(claims["aud"], &audiences) != nil || len(audiences) == 0 {
			return domain.ErrAuthorityUnavailable
		}
		for _, value := range audiences {
			if strings.TrimSpace(value) == "" {
				return domain.ErrAuthorityUnavailable
			}
		}
	}
	var expiry json.Number
	rawExpiry := claims["exp"]
	if len(rawExpiry) == 0 || rawExpiry[0] == '"' || json.Unmarshal(rawExpiry, &expiry) != nil {
		return domain.ErrAuthorityUnavailable
	}
	expiresAt, err := strconv.ParseFloat(expiry.String(), 64)
	if err != nil || math.IsNaN(expiresAt) || math.IsInf(expiresAt, 0) || expiresAt <= 0 || expiresAt > 253402300799 {
		return domain.ErrAuthorityUnavailable
	}
	if expiresAt <= float64(now.UnixNano())/float64(time.Second) {
		return domain.ErrUnauthenticated
	}
	return nil
}
