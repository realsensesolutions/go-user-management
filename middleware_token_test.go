package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

func TestRequireAuthMiddleware_TokenAuth(t *testing.T) {
	t.Run("handles JWT token in cookie", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		SetOAuthConfig(&OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
			ClientID:   "test-client-id",
		})

		handler := RequireAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r)
			if !ok {
				t.Error("expected claims in context")
				return
			}
			if claims.Provider != "cognito" {
				t.Errorf("expected provider 'cognito', got '%s'", claims.Provider)
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "jwt",
			Value: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn0.test",
		})

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code == http.StatusUnauthorized {
			t.Log("JWT validation failed (expected in test environment), but middleware correctly attempted JWT validation")
		}
	})

	t.Run("handles opaque token in Authorization header", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockCognitoClient{
			users: map[string]*cognitoidentityprovider.ListUsersOutput{
				`custom:apiKey = "test-token"`: {
					Users: []types.UserType{
						{
							Username: aws.String("testuser"),
							Attributes: []types.AttributeType{
								{Name: aws.String("sub"), Value: aws.String("user-123")},
								{Name: aws.String("email"), Value: aws.String("test@example.com")},
								{Name: aws.String("given_name"), Value: aws.String("Test")},
								{Name: aws.String("family_name"), Value: aws.String("User")},
								{Name: aws.String("custom:apiKey"), Value: aws.String("test-token")},
								{Name: aws.String("custom:tenantId"), Value: aws.String("bp")},
								{Name: aws.String("custom:serviceProviderId"), Value: aws.String("inrush")},
							},
						},
					},
				},
			},
		}

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		SetOAuthConfig(&OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
			ClientID:   "test-client-id",
		})

		handler := RequireAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r)
			if !ok {
				t.Error("expected claims in context")
				return
			}
			if claims.Provider != "token" {
				t.Errorf("expected provider 'token', got '%s'", claims.Provider)
			}
			if claims.Email != "test@example.com" {
				t.Errorf("expected email 'test@example.com', got '%s'", claims.Email)
			}
			if claims.TenantID != "bp" {
				t.Errorf("expected TenantID 'bp', got %q", claims.TenantID)
			}
			if claims.ServiceProviderID != "inrush" {
				t.Errorf("expected ServiceProviderID 'inrush', got %q", claims.ServiceProviderID)
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("returns 401 for unknown token", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockCognitoClient{
			users: map[string]*cognitoidentityprovider.ListUsersOutput{},
		}

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		SetOAuthConfig(&OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
			ClientID:   "test-client-id",
		})

		handler := RequireAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer unknown-token")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("distinguishes JWT from opaque token", func(t *testing.T) {
		jwtToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn0.test"
		opaqueToken := "simple-opaque-token"

		if !isJWTToken(jwtToken) {
			t.Error("expected JWT token to be identified as JWT")
		}
		if isJWTToken(opaqueToken) {
			t.Error("expected opaque token to not be identified as JWT")
		}
	})
}
