package user

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type mockUserMgmtCognitoClient struct {
	disableUserCalled bool
	enableUserCalled  bool
	setPasswordCalled bool
	updateAttrCalled  bool

	disableUserInput *cognitoidentityprovider.AdminDisableUserInput
	enableUserInput  *cognitoidentityprovider.AdminEnableUserInput
	setPasswordInput *cognitoidentityprovider.AdminSetUserPasswordInput
	updateAttrInput  *cognitoidentityprovider.AdminUpdateUserAttributesInput

	disableUserErr error
	enableUserErr  error
	setPasswordErr error
}

func (m *mockUserMgmtCognitoClient) ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	return &cognitoidentityprovider.ListUsersOutput{Users: []types.UserType{}}, nil
}

func (m *mockUserMgmtCognitoClient) AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	m.updateAttrCalled = true
	m.updateAttrInput = params
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (m *mockUserMgmtCognitoClient) AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	return &cognitoidentityprovider.AdminGetUserOutput{
		Username: aws.String("test@example.com"),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("test@example.com")},
			{Name: aws.String("given_name"), Value: aws.String("Test")},
			{Name: aws.String("family_name"), Value: aws.String("User")},
			{Name: aws.String("custom:role"), Value: aws.String("user")},
			{Name: aws.String("custom:serviceProviderId"), Value: aws.String("sp-updated")},
		},
		UserStatus: types.UserStatusTypeConfirmed,
		Enabled:    true,
	}, nil
}

func (m *mockUserMgmtCognitoClient) AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	return &cognitoidentityprovider.AdminCreateUserOutput{}, nil
}

func (m *mockUserMgmtCognitoClient) AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}

func (m *mockUserMgmtCognitoClient) AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	m.setPasswordCalled = true
	m.setPasswordInput = params
	if m.setPasswordErr != nil {
		return nil, m.setPasswordErr
	}
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func (m *mockUserMgmtCognitoClient) AdminDisableUser(ctx context.Context, params *cognitoidentityprovider.AdminDisableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDisableUserOutput, error) {
	m.disableUserCalled = true
	m.disableUserInput = params
	if m.disableUserErr != nil {
		return nil, m.disableUserErr
	}
	return &cognitoidentityprovider.AdminDisableUserOutput{}, nil
}

func (m *mockUserMgmtCognitoClient) AdminEnableUser(ctx context.Context, params *cognitoidentityprovider.AdminEnableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminEnableUserOutput, error) {
	m.enableUserCalled = true
	m.enableUserInput = params
	if m.enableUserErr != nil {
		return nil, m.enableUserErr
	}
	return &cognitoidentityprovider.AdminEnableUserOutput{}, nil
}

func setupMockUserMgmt(t *testing.T) *mockUserMgmtCognitoClient {
	t.Helper()
	originalFactory := cognitoClientFactory
	t.Cleanup(func() { cognitoClientFactory = originalFactory })

	mockClient := &mockUserMgmtCognitoClient{}
	SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
		return mockClient
	})
	SetOAuthConfig(&OAuthConfig{
		UserPoolID: "us-east-1_test",
		Region:     "us-east-1",
	})
	return mockClient
}

func TestDisableUser(t *testing.T) {
	t.Run("disables user successfully", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		ctx := context.Background()

		err := DisableUser(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !mockClient.disableUserCalled {
			t.Error("expected AdminDisableUser to be called")
		}

		if aws.ToString(mockClient.disableUserInput.Username) != "test@example.com" {
			t.Errorf("expected username 'test@example.com', got %q", aws.ToString(mockClient.disableUserInput.Username))
		}

		if aws.ToString(mockClient.disableUserInput.UserPoolId) != "us-east-1_test" {
			t.Errorf("expected user pool ID 'us-east-1_test', got %q", aws.ToString(mockClient.disableUserInput.UserPoolId))
		}
	})

	t.Run("returns error for empty email", func(t *testing.T) {
		_ = setupMockUserMgmt(t)
		ctx := context.Background()

		err := DisableUser(ctx, "")
		if err == nil {
			t.Fatal("expected error for empty email")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("returns error when oauth config not set", func(t *testing.T) {
		SetOAuthConfig(nil)
		ctx := context.Background()

		err := DisableUser(ctx, "test@example.com")
		if err == nil {
			t.Fatal("expected error when oauth config not set")
		}
	})

	t.Run("propagates cognito error", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		mockClient.disableUserErr = errors.New("UserNotFoundException: does not exist")
		ctx := context.Background()

		err := DisableUser(ctx, "nonexistent@example.com")
		if err == nil {
			t.Fatal("expected error from cognito")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})
}

func TestEnableUser(t *testing.T) {
	t.Run("enables user successfully", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		ctx := context.Background()

		err := EnableUser(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !mockClient.enableUserCalled {
			t.Error("expected AdminEnableUser to be called")
		}

		if aws.ToString(mockClient.enableUserInput.Username) != "test@example.com" {
			t.Errorf("expected username 'test@example.com', got %q", aws.ToString(mockClient.enableUserInput.Username))
		}

		if aws.ToString(mockClient.enableUserInput.UserPoolId) != "us-east-1_test" {
			t.Errorf("expected user pool ID 'us-east-1_test', got %q", aws.ToString(mockClient.enableUserInput.UserPoolId))
		}
	})

	t.Run("returns error for empty email", func(t *testing.T) {
		_ = setupMockUserMgmt(t)
		ctx := context.Background()

		err := EnableUser(ctx, "")
		if err == nil {
			t.Fatal("expected error for empty email")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("returns error when oauth config not set", func(t *testing.T) {
		SetOAuthConfig(nil)
		ctx := context.Background()

		err := EnableUser(ctx, "test@example.com")
		if err == nil {
			t.Fatal("expected error when oauth config not set")
		}
	})

	t.Run("propagates cognito error", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		mockClient.enableUserErr = errors.New("UserNotFoundException: does not exist")
		ctx := context.Background()

		err := EnableUser(ctx, "nonexistent@example.com")
		if err == nil {
			t.Fatal("expected error from cognito")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})
}

func TestUpdateServiceProviderID(t *testing.T) {
	t.Run("updates service provider ID successfully", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		ctx := context.Background()

		user, err := UpdateServiceProviderID(ctx, "test@example.com", "sp-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user == nil {
			t.Fatal("expected user to be returned")
		}

		if !mockClient.updateAttrCalled {
			t.Fatal("expected AdminUpdateUserAttributes to be called")
		}

		attrs := mockClient.updateAttrInput.UserAttributes
		found := false
		for _, attr := range attrs {
			if aws.ToString(attr.Name) == "custom:serviceProviderId" && aws.ToString(attr.Value) == "sp-123" {
				found = true
			}
		}
		if !found {
			t.Error("expected custom:serviceProviderId attribute with value 'sp-123'")
		}
	})

	t.Run("returns error for empty email", func(t *testing.T) {
		_ = setupMockUserMgmt(t)
		ctx := context.Background()

		_, err := UpdateServiceProviderID(ctx, "", "sp-123")
		if err == nil {
			t.Fatal("expected error for empty email")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("returns error for empty serviceProviderID", func(t *testing.T) {
		_ = setupMockUserMgmt(t)
		ctx := context.Background()

		_, err := UpdateServiceProviderID(ctx, "test@example.com", "")
		if err == nil {
			t.Fatal("expected error for empty serviceProviderID")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("returns error when oauth config not set", func(t *testing.T) {
		SetOAuthConfig(nil)
		ctx := context.Background()

		_, err := UpdateServiceProviderID(ctx, "test@example.com", "sp-123")
		if err == nil {
			t.Fatal("expected error when oauth config not set")
		}
	})
}

func TestSetUserPassword(t *testing.T) {
	t.Run("sets temporary password successfully", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		ctx := context.Background()

		err := SetUserPassword(ctx, "test@example.com", "TempPass123!", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !mockClient.setPasswordCalled {
			t.Error("expected AdminSetUserPassword to be called")
		}

		if aws.ToString(mockClient.setPasswordInput.Username) != "test@example.com" {
			t.Errorf("expected username 'test@example.com', got %q", aws.ToString(mockClient.setPasswordInput.Username))
		}

		if aws.ToString(mockClient.setPasswordInput.Password) != "TempPass123!" {
			t.Errorf("expected password 'TempPass123!', got %q", aws.ToString(mockClient.setPasswordInput.Password))
		}
	})

	t.Run("returns error for empty email", func(t *testing.T) {
		_ = setupMockUserMgmt(t)
		ctx := context.Background()

		err := SetUserPassword(ctx, "", "TempPass123!", false)
		if err == nil {
			t.Fatal("expected error for empty email")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("returns error when oauth config not set", func(t *testing.T) {
		SetOAuthConfig(nil)
		ctx := context.Background()

		err := SetUserPassword(ctx, "test@example.com", "TempPass123!", false)
		if err == nil {
			t.Fatal("expected error when oauth config not set")
		}
	})

	t.Run("propagates cognito error", func(t *testing.T) {
		mockClient := setupMockUserMgmt(t)
		mockClient.setPasswordErr = errors.New("InvalidParameterException: bad password")
		ctx := context.Background()

		err := SetUserPassword(ctx, "test@example.com", "weak", false)
		if err == nil {
			t.Fatal("expected error from cognito")
		}
	})
}

func TestCognitoUserToUser_UserStatusAndEnabled(t *testing.T) {
	t.Run("maps UserStatus and Enabled fields", func(t *testing.T) {
		cognitoUser := types.UserType{
			Username: aws.String("status-user@example.com"),
			Attributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String("status-user@example.com")},
				{Name: aws.String("custom:userRole"), Value: aws.String("admin")},
			},
			UserStatus: types.UserStatusTypeConfirmed,
			Enabled:    true,
		}

		user, err := cognitoUserToUser(cognitoUser)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.UserStatus != "CONFIRMED" {
			t.Errorf("expected UserStatus 'CONFIRMED', got %q", user.UserStatus)
		}
		if !user.Enabled {
			t.Error("expected Enabled to be true")
		}
	})

	t.Run("maps FORCE_CHANGE_PASSWORD status", func(t *testing.T) {
		cognitoUser := types.UserType{
			Username: aws.String("new-user@example.com"),
			Attributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String("new-user@example.com")},
			},
			UserStatus: types.UserStatusTypeForceChangePassword,
			Enabled:    true,
		}

		user, err := cognitoUserToUser(cognitoUser)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.UserStatus != "FORCE_CHANGE_PASSWORD" {
			t.Errorf("expected UserStatus 'FORCE_CHANGE_PASSWORD', got %q", user.UserStatus)
		}
	})

	t.Run("maps disabled user", func(t *testing.T) {
		cognitoUser := types.UserType{
			Username: aws.String("disabled@example.com"),
			Attributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String("disabled@example.com")},
			},
			UserStatus: types.UserStatusTypeConfirmed,
			Enabled:    false,
		}

		user, err := cognitoUserToUser(cognitoUser)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.Enabled {
			t.Error("expected Enabled to be false")
		}
	})

	t.Run("defaults Enabled to false when zero value", func(t *testing.T) {
		cognitoUser := types.UserType{
			Username: aws.String("default-enabled@example.com"),
			Attributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String("default-enabled@example.com")},
			},
			UserStatus: types.UserStatusTypeConfirmed,
		}

		user, err := cognitoUserToUser(cognitoUser)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.Enabled {
			t.Error("expected Enabled to be false when zero value")
		}
	})
}
