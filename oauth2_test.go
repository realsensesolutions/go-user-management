package user

import (
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type mockStateRepo struct{}

func (m *mockStateRepo) StoreState(state, redirectURL string, expiresAt time.Time) error {
	return nil
}

func (m *mockStateRepo) ValidateAndRemoveState(state string) (string, bool) {
	return "", false
}

func (m *mockStateRepo) CleanupExpiredStates() error {
	return nil
}

func fakeOAuth2ConfigFactory() (*oauth2.Config, error) {
	return &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://fake.example.com/oauth2/authorize",
			TokenURL: "https://fake.example.com/oauth2/token",
		},
		RedirectURL: "https://localhost:3000/callback",
		Scopes:      []string{"openid"},
	}, nil
}

func newTestOAuth2Service() *OAuth2Service {
	return &OAuth2Service{
		stateRepo:           &mockStateRepo{},
		oauthConfig:         &OAuthConfig{ClientID: "test-client"},
		oauth2ConfigFactory: fakeOAuth2ConfigFactory,
	}
}

func TestGenerateAuthURL_WithLoginHint_AppendsParam(t *testing.T) {
	svc := newTestOAuth2Service()

	rawURL, err := svc.GenerateAuthURL("https://app.example.com/dashboard", "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	got := parsed.Query().Get("login_hint")
	if got != "alice@example.com" {
		t.Errorf("expected login_hint=%q, got %q", "alice@example.com", got)
	}
}

func TestGenerateAuthURL_WithoutLoginHint_OmitsParam(t *testing.T) {
	svc := newTestOAuth2Service()

	rawURL, err := svc.GenerateAuthURL("https://app.example.com/dashboard", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	if got := parsed.Query().Get("login_hint"); got != "" {
		t.Errorf("expected no login_hint param, got %q", got)
	}
}
