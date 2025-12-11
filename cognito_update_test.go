package user

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type mockUpdateCognitoClient struct {
	updateCalls []*cognitoidentityprovider.AdminUpdateUserAttributesInput
}

func (m *mockUpdateCognitoClient) ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	return &cognitoidentityprovider.ListUsersOutput{Users: []types.UserType{}}, nil
}

func (m *mockUpdateCognitoClient) AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	m.updateCalls = append(m.updateCalls, params)
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (m *mockUpdateCognitoClient) AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	return &cognitoidentityprovider.AdminGetUserOutput{}, nil
}

func (m *mockUpdateCognitoClient) AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	return &cognitoidentityprovider.AdminCreateUserOutput{}, nil
}

func (m *mockUpdateCognitoClient) AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}

func (m *mockUpdateCognitoClient) AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func TestUpdateCognitoUserAttributesFromClaims(t *testing.T) {
	t.Run("updates user attributes in Cognito", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockUpdateCognitoClient{
			updateCalls: []*cognitoidentityprovider.AdminUpdateUserAttributesInput{},
		}

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		ctx := context.Background()
		config := &OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		}

		claims := &Claims{
			Email:      "test@example.com",
			GivenName:  "Updated",
			FamilyName: "Name",
			Picture:    "https://example.com/pic.jpg",
			Role:       "FieldOfficer",
			APIKey:     "new-api-key-123",
		}

		err := UpdateCognitoUserAttributesFromClaims(ctx, "testuser", claims, config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(mockClient.updateCalls) != 1 {
			t.Fatalf("expected 1 update call, got %d", len(mockClient.updateCalls))
		}

		updateCall := mockClient.updateCalls[0]
		if aws.ToString(updateCall.UserPoolId) != "us-east-1_test" {
			t.Errorf("expected UserPoolId 'us-east-1_test', got '%s'", aws.ToString(updateCall.UserPoolId))
		}
		if aws.ToString(updateCall.Username) != "testuser" {
			t.Errorf("expected Username 'testuser', got '%s'", aws.ToString(updateCall.Username))
		}

		attributes := updateCall.UserAttributes
		attrMap := make(map[string]string)
		for _, attr := range attributes {
			attrMap[aws.ToString(attr.Name)] = aws.ToString(attr.Value)
		}

		if attrMap["given_name"] != "Updated" {
			t.Errorf("expected given_name 'Updated', got '%s'", attrMap["given_name"])
		}
		if attrMap["family_name"] != "Name" {
			t.Errorf("expected family_name 'Name', got '%s'", attrMap["family_name"])
		}
		if attrMap["picture"] != "https://example.com/pic.jpg" {
			t.Errorf("expected picture 'https://example.com/pic.jpg', got '%s'", attrMap["picture"])
		}
		if attrMap["custom:role"] != "FieldOfficer" {
			t.Errorf("expected custom:role 'FieldOfficer', got '%s'", attrMap["custom:role"])
		}
		if attrMap["custom:apiKey"] != "new-api-key-123" {
			t.Errorf("expected custom:apiKey 'new-api-key-123', got '%s'", attrMap["custom:apiKey"])
		}
	})

	t.Run("handles empty claims gracefully", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockUpdateCognitoClient{
			updateCalls: []*cognitoidentityprovider.AdminUpdateUserAttributesInput{},
		}

		setCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		ctx := context.Background()
		config := &OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		}

		claims := &Claims{}

		err := UpdateCognitoUserAttributesFromClaims(ctx, "testuser", claims, config)
		if err != nil {
			t.Fatalf("expected no error for empty claims, got: %v", err)
		}

		if len(mockClient.updateCalls) != 0 {
			t.Errorf("expected 0 update calls for empty claims, got %d", len(mockClient.updateCalls))
		}
	})

	t.Run("returns error for invalid config", func(t *testing.T) {
		ctx := context.Background()
		claims := &Claims{
			Email: "test@example.com",
		}

		err := UpdateCognitoUserAttributesFromClaims(ctx, "testuser", claims, nil)
		if err == nil {
			t.Fatal("expected error for nil config, got nil")
		}
	})
}

