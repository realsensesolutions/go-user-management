package user

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TestInitOIDCProvider_HonorsIssuerURL verifies the migration switch:
// when OAuthConfig.IssuerURL is set, the provider initializes against
// that URL via OIDC discovery instead of synthesizing a Cognito issuer
// from Region/UserPoolID. This is the load-bearing change that lets the
// package work with Authentik / Keycloak / any standards-compliant IdP.
//
// The test stands up an httptest server that serves the bare minimum a
// go-oidc provider needs (discovery doc + JWKS), then signs an ID token
// containing the cognito:* / custom:* claims emitted by the Authentik
// scope mapping in authentik-cloudloto-web-blueprint.yaml and asserts
// the verifier accepts it and threads every custom claim through.
func TestInitOIDCProvider_HonorsIssuerURL(t *testing.T) {
	resetOIDCProviderForTesting()
	t.Cleanup(resetOIDCProviderForTesting)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	const keyID = "test-key-1"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     keyID,
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"end_session_endpoint":   issuer + "/end-session",
			"jwks_uri":               issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	const clientID = "cloudloto-web"
	cfg := &OAuthConfig{
		ClientID:    clientID,
		IssuerURL:   issuer,
		RedirectURI: "https://localhost:3000/oauth2/idpresponse",
		FrontEndURL: "https://localhost:8000",
		Scopes:      []string{"openid", "email", "profile", "cloudloto_web_custom"},

		// Cognito fields intentionally LEFT EMPTY — the whole point of this
		// test is that IssuerURL alone is enough to bootstrap the provider.
		Region:     "",
		UserPoolID: "",
	}

	if _, err := initOIDCProviderFromOAuthConfig(cfg); err != nil {
		t.Fatalf("initOIDCProviderFromOAuthConfig: %v", err)
	}

	// Build a signed ID token whose claims mirror what the Authentik
	// cloudloto_web_custom scope mapping emits at runtime, including the
	// cognito:username bridge that keeps the OIDCClaims.Username field
	// populated for the legacy Cognito JSON tag.
	now := time.Now()
	rawClaims := map[string]any{
		"iss":                       issuer,
		"sub":                       "user-123",
		"aud":                       clientID,
		"exp":                       now.Add(5 * time.Minute).Unix(),
		"iat":                       now.Unix(),
		"email":                     "adrian@example.com",
		"email_verified":            true,
		"given_name":                "Adrian",
		"family_name":               "Test",
		"cognito:username":          "adrian",
		"custom:userRole":           "superadmin",
		"custom:role":               "FieldOfficer",
		"custom:tenantId":           "bp",
		"custom:serviceProviderId":  "inrush",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), keyID),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	rawIDToken, err := jwt.Signed(signer).Claims(rawClaims).Serialize()
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	claims, err := ValidateOIDCTokenFromOAuthConfig(context.Background(), rawIDToken, cfg)
	if err != nil {
		t.Fatalf("ValidateOIDCTokenFromOAuthConfig rejected the Authentik-shaped token: %v", err)
	}

	if claims.Username != "adrian" {
		t.Errorf("expected Username 'adrian' (from cognito:username bridge), got %q", claims.Username)
	}
	if claims.UserRole != "superadmin" {
		t.Errorf("expected UserRole 'superadmin', got %q", claims.UserRole)
	}
	if claims.TenantID != "bp" {
		t.Errorf("expected TenantID 'bp', got %q", claims.TenantID)
	}
	if claims.ServiceProviderID != "inrush" {
		t.Errorf("expected ServiceProviderID 'inrush', got %q", claims.ServiceProviderID)
	}
	if claims.Email != "adrian@example.com" {
		t.Errorf("expected Email 'adrian@example.com', got %q", claims.Email)
	}
	if claims.GivenName != "Adrian" || claims.FamilyName != "Test" {
		t.Errorf("expected name 'Adrian Test', got %q %q", claims.GivenName, claims.FamilyName)
	}
}

// TestInitOIDCProvider_FallsBackToCognito guards the back-compat path:
// when IssuerURL is empty, the provider must still be initialized from
// Region/UserPoolID exactly as before so existing Cognito deployments
// don't regress.
func TestInitOIDCProvider_FallsBackToCognito(t *testing.T) {
	resetOIDCProviderForTesting()
	t.Cleanup(resetOIDCProviderForTesting)

	cfg := &OAuthConfig{
		ClientID:   "any",
		Region:     "us-east-1",
		UserPoolID: "us-east-1_DOESNOTEXIST",
	}

	// We don't expect the discovery call to succeed (the pool is fake)
	// but we DO expect it to attempt to reach the Cognito issuer URL,
	// not panic on the missing IssuerURL field. A network/discovery
	// failure surfaces as a wrapped "failed to create OIDC provider"
	// error, which is the canonical Cognito-mode failure mode.
	_, err := initOIDCProviderFromOAuthConfig(cfg)
	if err == nil {
		t.Fatalf("expected discovery against a fake Cognito pool to fail, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create OIDC provider") {
		t.Errorf("expected Cognito-issuer discovery failure, got: %v", err)
	}
}

// TestValidateOAuthConfig_OIDCMode_DropsCognitoRequirements documents
// the new validation contract: in OIDC mode (IssuerURL set) the
// validator must not demand UserPoolID or Region.
func TestValidateOAuthConfig_OIDCMode_DropsCognitoRequirements(t *testing.T) {
	cfg := &OAuthConfig{
		ClientID:     "cloudloto-web",
		ClientSecret: "secret",
		IssuerURL:    "https://auth.lab.realsense.ca/application/o/cloudloto-web/",
		RedirectURI:  "https://cloudloto-api.lab.realsense.ca/oauth2/idpresponse",
		FrontEndURL:  "https://cloudloto-web.lab.realsense.ca",
		Scopes:       []string{"openid", "email", "profile", "cloudloto_web_custom"},
		// UserPoolID + Region intentionally empty.
	}
	if err := validateOAuthConfig(cfg); err != nil {
		t.Fatalf("expected validateOAuthConfig to accept OIDC-mode config, got: %v", err)
	}
}

// TestValidateOAuthConfig_CognitoMode_StillRequiresPool guards the
// regression direction: an empty IssuerURL must still require the
// Cognito pool/region pair so misconfigured deployments fail fast
// at startup instead of at first login.
func TestValidateOAuthConfig_CognitoMode_StillRequiresPool(t *testing.T) {
	cfg := &OAuthConfig{
		ClientID:     "x",
		ClientSecret: "y",
		RedirectURI:  "https://localhost/cb",
		FrontEndURL:  "https://localhost",
		Scopes:       []string{"openid"},
	}
	err := validateOAuthConfig(cfg)
	if err == nil {
		t.Fatalf("expected validateOAuthConfig to reject Cognito-mode config without UserPoolID, got nil")
	}
	if !strings.Contains(err.Error(), "UserPoolID") {
		t.Errorf("expected error to mention UserPoolID, got: %v", err)
	}
}

// fakeIssuerWithDiscovery stands up a minimal OIDC discovery + JWKS server
// for the auto-discovery tests below. The endSession argument controls
// whether the discovery document advertises end_session_endpoint, which
// is the field LogoutHandler keys on for RP-initiated logout.
func fakeIssuerWithDiscovery(t *testing.T, endSession string) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     "k",
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		}
		if endSession != "" {
			doc["end_session_endpoint"] = endSession
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	return issuer
}

// TestInitOIDCProvider_AutoDiscoversEndSessionEndpoint pins down the
// behavior that prevents the "I forgot OIDC_LOGOUT_URL" class of bug:
// when the provider's discovery document advertises end_session_endpoint
// and OAuthConfig.LogoutURL is empty, init must populate LogoutURL from
// the discovered value so LogoutHandler can do RP-initiated logout
// against Authentik / Keycloak / any standards-compliant IdP without
// any extra env-var plumbing.
func TestInitOIDCProvider_AutoDiscoversEndSessionEndpoint(t *testing.T) {
	resetOIDCProviderForTesting()
	t.Cleanup(resetOIDCProviderForTesting)

	issuer := fakeIssuerWithDiscovery(t, "https://idp.example.com/end-session")

	cfg := &OAuthConfig{
		ClientID:    "cloudloto-web",
		IssuerURL:   issuer,
		RedirectURI: "https://localhost:3000/oauth2/idpresponse",
		FrontEndURL: "https://localhost:8000",
		Scopes:      []string{"openid"},
		// LogoutURL intentionally empty — auto-discovery is what's under test.
	}
	if _, err := initOIDCProviderFromOAuthConfig(cfg); err != nil {
		t.Fatalf("initOIDCProviderFromOAuthConfig: %v", err)
	}
	if want := "https://idp.example.com/end-session"; cfg.LogoutURL != want {
		t.Errorf("expected LogoutURL auto-discovered to %q, got %q", want, cfg.LogoutURL)
	}
}

// TestInitOIDCProvider_ExplicitLogoutURLNotOverwritten guards the
// hard-override path: an operator who configures OIDC_LOGOUT_URL must
// always win against discovery, since the env var is the documented
// escape hatch for IdPs that advertise the wrong endpoint or none at
// all (looking at you, AWS Cognito).
func TestInitOIDCProvider_ExplicitLogoutURLNotOverwritten(t *testing.T) {
	resetOIDCProviderForTesting()
	t.Cleanup(resetOIDCProviderForTesting)

	issuer := fakeIssuerWithDiscovery(t, "https://idp.example.com/discovered")

	cfg := &OAuthConfig{
		ClientID:    "cloudloto-web",
		IssuerURL:   issuer,
		LogoutURL:   "https://idp.example.com/explicit-override",
		RedirectURI: "https://localhost:3000/oauth2/idpresponse",
		FrontEndURL: "https://localhost:8000",
		Scopes:      []string{"openid"},
	}
	if _, err := initOIDCProviderFromOAuthConfig(cfg); err != nil {
		t.Fatalf("initOIDCProviderFromOAuthConfig: %v", err)
	}
	if want := "https://idp.example.com/explicit-override"; cfg.LogoutURL != want {
		t.Errorf("expected explicit LogoutURL %q to be preserved, got %q", want, cfg.LogoutURL)
	}
}

// TestInitOIDCProvider_LogoutURLStaysEmptyWhenIdPSilent guards the
// fail-soft path: when the discovery doc is silent on end_session_endpoint
// (e.g. Cognito or a non-conformant IdP) and the operator did not set
// LogoutURL, init must leave the field empty so LogoutHandler falls
// through to the next branch (Cognito hosted-UI logout, or just clear-
// cookie) instead of synthesizing a bogus URL.
func TestInitOIDCProvider_LogoutURLStaysEmptyWhenIdPSilent(t *testing.T) {
	resetOIDCProviderForTesting()
	t.Cleanup(resetOIDCProviderForTesting)

	issuer := fakeIssuerWithDiscovery(t, "")

	cfg := &OAuthConfig{
		ClientID:    "cloudloto-web",
		IssuerURL:   issuer,
		RedirectURI: "https://localhost:3000/oauth2/idpresponse",
		FrontEndURL: "https://localhost:8000",
		Scopes:      []string{"openid"},
	}
	if _, err := initOIDCProviderFromOAuthConfig(cfg); err != nil {
		t.Fatalf("initOIDCProviderFromOAuthConfig: %v", err)
	}
	if cfg.LogoutURL != "" {
		t.Errorf("expected LogoutURL to stay empty when discovery omits end_session_endpoint, got %q", cfg.LogoutURL)
	}
}

// Sanity check that go-jose v4 jose import is actually used (avoid
// "imported and not used" if a refactor drops the JWT path).
var _ = fmt.Sprintf
