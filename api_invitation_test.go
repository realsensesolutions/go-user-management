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
	createUserCalled  bool
	setPasswordCalled bool
	deleteUserCalled  bool
	rejectPasswordSet bool
	createUserInput   *cognitoidentityprovider.AdminCreateUserInput
	setPasswordInput  *cognitoidentityprovider.AdminSetUserPasswordInput
	deleteUserInput   *cognitoidentityprovider.AdminDeleteUserInput
	getUserAttributes []types.AttributeType
	temporaryPassword string
}

func (m *mockInvitationCognitoClient) ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	return &cognitoidentityprovider.ListUsersOutput{Users: []types.UserType{}}, nil
}

func (m *mockInvitationCognitoClient) AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	attrs := m.getUserAttributes
	if attrs == nil && m.createUserInput != nil {
		attrs = m.createUserInput.UserAttributes
	}
	return &cognitoidentityprovider.AdminGetUserOutput{
		Username:       params.Username,
		UserAttributes: attrs,
	}, nil
}

func (m *mockInvitationCognitoClient) AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	m.createUserCalled = true
	m.createUserInput = params

	return &cognitoidentityprovider.AdminCreateUserOutput{
		User: &types.UserType{
			Username:   params.Username,
			Attributes: params.UserAttributes,
		},
	}, nil
}

func (m *mockInvitationCognitoClient) AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	m.deleteUserCalled = true
	m.deleteUserInput = params
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	m.setPasswordCalled = true
	m.setPasswordInput = params

	if m.rejectPasswordSet {
		return nil, &types.InvalidPasswordException{
			Message: aws.String("Password did not conform to policy"),
		}
	}

	if params.Password == nil {
		return nil, &types.InvalidPasswordException{
			Message: aws.String("password is required"),
		}
	}

	if err := validateCognitoPassword(*params.Password); err != nil {
		return nil, &types.InvalidPasswordException{
			Message: aws.String(err.Error()),
		}
	}

	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminDisableUser(ctx context.Context, params *cognitoidentityprovider.AdminDisableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDisableUserOutput, error) {
	return &cognitoidentityprovider.AdminDisableUserOutput{}, nil
}

func (m *mockInvitationCognitoClient) AdminEnableUser(ctx context.Context, params *cognitoidentityprovider.AdminEnableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminEnableUserOutput, error) {
	return &cognitoidentityprovider.AdminEnableUserOutput{}, nil
}

func (m *mockInvitationCognitoClient) DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	return &cognitoidentityprovider.DescribeUserPoolOutput{}, nil
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

		if err := validateCognitoPassword(tempPassword); err != nil {
			t.Errorf("expected returned password to satisfy Cognito policy: %v", err)
		}

		if !mockClient.createUserCalled {
			t.Error("expected AdminCreateUser to be called")
		}

		if !mockClient.setPasswordCalled {
			t.Error("expected AdminSetUserPassword to be called")
		}

		if mockClient.deleteUserCalled {
			t.Error("did not expect rollback on happy path")
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

	t.Run("rolls back when password rejected by Cognito policy", func(t *testing.T) {
		originalFactory := cognitoClientFactory
		defer func() { cognitoClientFactory = originalFactory }()

		mockClient := &mockInvitationCognitoClient{
			rejectPasswordSet: true,
		}

		SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
			return mockClient
		})

		SetOAuthConfig(&OAuthConfig{
			UserPoolID: "us-east-1_test",
			Region:     "us-east-1",
		})

		ctx := context.Background()
		req := CreateUserRequest{
			Email:      "orphan@example.com",
			GivenName:  "Orphan",
			FamilyName: "Test",
			Role:       "user",
		}

		user, tempPassword, err := CreateUserWithInvitation(ctx, req)
		if err == nil {
			t.Fatal("expected error when AdminSetUserPassword rejects password")
		}
		if user != nil {
			t.Error("expected nil user when password is rejected")
		}
		if tempPassword != "" {
			t.Error("expected empty temporary password on failure")
		}
		if !mockClient.createUserCalled {
			t.Error("expected AdminCreateUser to be called before rollback")
		}
		if !mockClient.setPasswordCalled {
			t.Error("expected AdminSetUserPassword to be called")
		}
		if !mockClient.deleteUserCalled {
			t.Error("expected AdminDeleteUser to be called for rollback")
		}
		if mockClient.deleteUserInput == nil || aws.ToString(mockClient.deleteUserInput.Username) != "orphan@example.com" {
			t.Errorf("expected rollback delete for orphan@example.com, got %v", mockClient.deleteUserInput)
		}
	})

	t.Run("AdminSetUserPassword mock rejects policy-violating passwords", func(t *testing.T) {
		mockClient := &mockInvitationCognitoClient{}
		ctx := context.Background()

		_, err := mockClient.AdminSetUserPassword(ctx, &cognitoidentityprovider.AdminSetUserPasswordInput{
			Username: aws.String("test@example.com"),
			Password: aws.String("short"),
		})
		if err == nil {
			t.Fatal("expected error for policy-violating password")
		}
		var invalidPw *types.InvalidPasswordException
		if !errors.As(err, &invalidPw) {
			t.Fatalf("expected InvalidPasswordException, got %T: %v", err, err)
		}

		_, err = mockClient.AdminSetUserPassword(ctx, &cognitoidentityprovider.AdminSetUserPasswordInput{
			Username: aws.String("test@example.com"),
			Password: aws.String("NoDigitOrSpecial1"),
		})
		if err == nil {
			t.Fatal("expected error for password missing digit and special")
		}
		if !errors.As(err, &invalidPw) {
			t.Fatalf("expected InvalidPasswordException, got %T: %v", err, err)
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
