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

type mockCognitoClient struct {
	users map[string]*cognitoidentityprovider.ListUsersOutput
}

func (m *mockCognitoClient) ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	filter := aws.ToString(params.Filter)
	if result, ok := m.users[filter]; ok {
		return result, nil
	}
	return &cognitoidentityprovider.ListUsersOutput{Users: []types.UserType{}}, nil
}

func (m *mockCognitoClient) AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (m *mockCognitoClient) AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	return &cognitoidentityprovider.AdminGetUserOutput{}, nil
}

func (m *mockCognitoClient) AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	return &cognitoidentityprovider.AdminCreateUserOutput{}, nil
}

func (m *mockCognitoClient) AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}

func (m *mockCognitoClient) AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func TestFindUserClaimsByToken(t *testing.T) {
	t.Run("returns claims for valid token", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockCognitoClient{
			users: map[string]*cognitoidentityprovider.ListUsersOutput{
				`custom:apiKey = "valid-token"`: {
					Users: []types.UserType{
						{
							Username: aws.String("testuser"),
							Attributes: []types.AttributeType{
								{Name: aws.String("sub"), Value: aws.String("user-123")},
								{Name: aws.String("email"), Value: aws.String("test@example.com")},
								{Name: aws.String("given_name"), Value: aws.String("Test")},
								{Name: aws.String("family_name"), Value: aws.String("User")},
								{Name: aws.String("custom:apiKey"), Value: aws.String("valid-token")},
								{Name: aws.String("custom:role"), Value: aws.String("FieldOfficer")},
								{Name: aws.String("custom:tenantId"), Value: aws.String("bp")},
								{Name: aws.String("custom:serviceProviderId"), Value: aws.String("inrush")},
							},
						},
					},
				},
			},
		}

		SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		ctx := context.Background()
		config := &OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		}

		claims, err := FindUserClaimsByToken(ctx, "valid-token", config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if claims == nil {
			t.Fatal("expected claims, got nil")
		}
		if claims.Email != "test@example.com" {
			t.Errorf("expected email 'test@example.com', got '%s'", claims.Email)
		}
		if claims.Username != "testuser" {
			t.Errorf("expected username 'testuser', got '%s'", claims.Username)
		}
		if claims.Role != "FieldOfficer" {
			t.Errorf("expected role 'FieldOfficer', got '%s'", claims.Role)
		}
		if claims.APIKey != "valid-token" {
			t.Errorf("expected APIKey 'valid-token', got '%s'", claims.APIKey)
		}
		if claims.Provider != "token" {
			t.Errorf("expected provider 'token', got '%s'", claims.Provider)
		}
		if claims.TenantID != "bp" {
			t.Errorf("expected TenantID 'bp', got '%s'", claims.TenantID)
		}
		if claims.ServiceProviderID != "inrush" {
			t.Errorf("expected ServiceProviderID 'inrush', got '%s'", claims.ServiceProviderID)
		}
	})

	t.Run("returns error for unknown token", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockCognitoClient{
			users: map[string]*cognitoidentityprovider.ListUsersOutput{},
		}

		SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		ctx := context.Background()
		config := &OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		}

		claims, err := FindUserClaimsByToken(ctx, "unknown-token", config)
		if err == nil {
			t.Fatal("expected error for unknown token, got nil")
		}
		if claims != nil {
			t.Errorf("expected nil claims, got: %+v", claims)
		}
		if err.Error() != "no user found with token" {
			t.Errorf("expected 'no user found with token', got: %v", err)
		}
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		ctx := context.Background()
		config := &OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		}

		claims, err := FindUserClaimsByToken(ctx, "", config)
		if err == nil {
			t.Fatal("expected error for empty token, got nil")
		}
		if claims != nil {
			t.Errorf("expected nil claims, got: %+v", claims)
		}
		if err.Error() != "token cannot be empty" {
			t.Errorf("expected 'token cannot be empty', got: %v", err)
		}
	})

	t.Run("returns error when multiple users have same token", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockCognitoClient{
			users: map[string]*cognitoidentityprovider.ListUsersOutput{
				`custom:apiKey = "duplicate-token"`: {
					Users: []types.UserType{
						{
							Username: aws.String("user1"),
							Attributes: []types.AttributeType{
								{Name: aws.String("email"), Value: aws.String("user1@example.com")},
							},
						},
						{
							Username: aws.String("user2"),
							Attributes: []types.AttributeType{
								{Name: aws.String("email"), Value: aws.String("user2@example.com")},
							},
						},
					},
				},
			},
		}

		SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		ctx := context.Background()
		config := &OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		}

		claims, err := FindUserClaimsByToken(ctx, "duplicate-token", config)
		if err == nil {
			t.Fatal("expected error for duplicate token, got nil")
		}
		if claims != nil {
			t.Errorf("expected nil claims, got: %+v", claims)
		}
		if err.Error() != "multiple users found with same token" {
			t.Errorf("expected 'multiple users found with same token', got: %v", err)
		}
	})
}

func TestWithUserAWSCredentials(t *testing.T) {
	t.Run("extracts JWT from cookie and puts in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
		req.AddCookie(&http.Cookie{Name: "jwt", Value: "test-jwt-token-from-cookie"})

		ctx := WithUserAWSCredentials(req)

		gotToken := JWTFromContext(ctx)
		if gotToken != "test-jwt-token-from-cookie" {
			t.Errorf("expected JWT 'test-jwt-token-from-cookie', got '%s'", gotToken)
		}
	})

	t.Run("extracts JWT from Authorization Bearer header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
		req.Header.Set("Authorization", "Bearer test-jwt-token-from-header")

		ctx := WithUserAWSCredentials(req)

		gotToken := JWTFromContext(ctx)
		if gotToken != "test-jwt-token-from-header" {
			t.Errorf("expected JWT 'test-jwt-token-from-header', got '%s'", gotToken)
		}
	})

	t.Run("prefers cookie over Authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
		req.AddCookie(&http.Cookie{Name: "jwt", Value: "cookie-token"})
		req.Header.Set("Authorization", "Bearer header-token")

		ctx := WithUserAWSCredentials(req)

		gotToken := JWTFromContext(ctx)
		if gotToken != "cookie-token" {
			t.Errorf("expected cookie token to take precedence, got '%s'", gotToken)
		}
	})

	t.Run("returns original context if no JWT found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/files", nil)

		ctx := WithUserAWSCredentials(req)

		gotToken := JWTFromContext(ctx)
		if gotToken != "" {
			t.Errorf("expected empty JWT when none provided, got '%s'", gotToken)
		}
	})

	t.Run("ignores empty cookie value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
		req.AddCookie(&http.Cookie{Name: "jwt", Value: ""})
		req.Header.Set("Authorization", "Bearer fallback-token")

		ctx := WithUserAWSCredentials(req)

		gotToken := JWTFromContext(ctx)
		if gotToken != "fallback-token" {
			t.Errorf("expected fallback to header when cookie empty, got '%s'", gotToken)
		}
	})

	t.Run("ignores malformed Authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
		req.Header.Set("Authorization", "Basic user:password")

		ctx := WithUserAWSCredentials(req)

		gotToken := JWTFromContext(ctx)
		if gotToken != "" {
			t.Errorf("expected empty JWT for non-Bearer auth, got '%s'", gotToken)
		}
	})
}
