package user

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type mockInvitationCognitoClient struct {
	createUserCalled   bool
	setPasswordCalled  bool
	createUserInput     *cognitoidentityprovider.AdminCreateUserInput
	setPasswordInput    *cognitoidentityprovider.AdminSetUserPasswordInput
	temporaryPassword   string
}

func (m *mockInvitationCognitoClient) ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	return &cognitoidentityprovider.ListUsersOutput{Users: []types.UserType{}}, nil
}

func (m *mockInvitationCognitoClient) AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	return &cognitoidentityprovider.AdminGetUserOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	m.createUserCalled = true
	m.createUserInput = params
	
	return &cognitoidentityprovider.AdminCreateUserOutput{
		User: &types.UserType{
			Username: aws.String("test@example.com"),
			Attributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String("test@example.com")},
				{Name: aws.String("given_name"), Value: aws.String("Test")},
				{Name: aws.String("family_name"), Value: aws.String("User")},
				{Name: aws.String("custom:role"), Value: aws.String("user")},
			},
		},
	}, nil
}

func (m *mockInvitationCognitoClient) AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	m.setPasswordCalled = true
	m.setPasswordInput = params
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func TestCreateUserWithInvitation(t *testing.T) {
	t.Run("creates user with temporary password", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockInvitationCognitoClient{}

		SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		SetOAuthConfig(&OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		})

		ctx := context.Background()
		req := CreateUserRequest{
			Email:      "test@example.com",
			GivenName:  "Test",
			FamilyName: "User",
			Role:       "user",
		}

		user, tempPassword, err := CreateUserWithInvitation(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user == nil {
			t.Fatal("expected user to be returned")
		}

		if tempPassword == "" {
			t.Fatal("expected temporary password to be returned")
		}

		if len(tempPassword) < 12 {
			t.Errorf("expected password to be at least 12 characters, got %d", len(tempPassword))
		}

		if !mockClient.createUserCalled {
			t.Error("expected AdminCreateUser to be called")
		}

		if !mockClient.setPasswordCalled {
			t.Error("expected AdminSetUserPassword to be called")
		}

		if mockClient.setPasswordInput == nil {
			t.Fatal("expected setPasswordInput to be set")
		}

		if aws.ToString(mockClient.setPasswordInput.Username) != "test@example.com" {
			t.Errorf("expected username to be test@example.com, got %s", aws.ToString(mockClient.setPasswordInput.Username))
		}

		if aws.ToString(mockClient.setPasswordInput.Password) != tempPassword {
			t.Error("expected password in AdminSetUserPassword to match returned password")
		}

		if mockClient.setPasswordInput.Permanent {
			t.Error("expected Permanent to be false (temporary password)")
		}
	})

	t.Run("returns error for empty email", func(t *testing.T) {
		SetOAuthConfig(&OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		})

		ctx := context.Background()
		req := CreateUserRequest{
			Email: "",
		}

		_, _, err := CreateUserWithInvitation(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty email")
		}

		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected error to wrap ErrInvalidInput, got %v", err)
		}
	})

	t.Run("returns error when oauth config not set", func(t *testing.T) {
		SetOAuthConfig(nil)

		ctx := context.Background()
		req := CreateUserRequest{
			Email: "test@example.com",
		}

		_, _, err := CreateUserWithInvitation(ctx, req)
		if err == nil {
			t.Fatal("expected error when oauth config not set")
		}
	})
}

