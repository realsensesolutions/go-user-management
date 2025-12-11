package user

import (
	"context"
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
							},
						},
					},
				},
			},
		}

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
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
	})

	t.Run("returns error for unknown token", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockCognitoClient{
			users: map[string]*cognitoidentityprovider.ListUsersOutput{},
		}

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
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

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
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
