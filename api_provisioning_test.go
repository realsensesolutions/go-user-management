package user

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type mockProvisioningCognitoClient struct {
	createUserInput    *cognitoidentityprovider.AdminCreateUserInput
	setPasswordErr     error
	deleteUserCalled   bool
	deleteUserInput    *cognitoidentityprovider.AdminDeleteUserInput
	getUserAttributes  []types.AttributeType
	getUserErr         error
	adminGetUserCalled bool
}

func (m *mockProvisioningCognitoClient) ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	return &cognitoidentityprovider.ListUsersOutput{Users: []types.UserType{}}, nil
}

func (m *mockProvisioningCognitoClient) AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (m *mockProvisioningCognitoClient) AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	m.adminGetUserCalled = true
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	attrs := m.getUserAttributes
	if attrs == nil {
		attrs = []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String(aws.ToString(params.Username))},
			{Name: aws.String("custom:role"), Value: aws.String("user")},
		}
	}
	return &cognitoidentityprovider.AdminGetUserOutput{
		Username:       params.Username,
		UserAttributes: attrs,
	}, nil
}

func (m *mockProvisioningCognitoClient) AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	m.createUserInput = params
	return &cognitoidentityprovider.AdminCreateUserOutput{
		User: &types.UserType{
			Username:   params.Username,
			Attributes: params.UserAttributes,
		},
	}, nil
}

func (m *mockProvisioningCognitoClient) AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	m.deleteUserCalled = true
	m.deleteUserInput = params
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}

func (m *mockProvisioningCognitoClient) AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	if m.setPasswordErr != nil {
		return nil, m.setPasswordErr
	}
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func (m *mockProvisioningCognitoClient) AdminDisableUser(ctx context.Context, params *cognitoidentityprovider.AdminDisableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDisableUserOutput, error) {
	return &cognitoidentityprovider.AdminDisableUserOutput{}, nil
}

func (m *mockProvisioningCognitoClient) AdminEnableUser(ctx context.Context, params *cognitoidentityprovider.AdminEnableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminEnableUserOutput, error) {
	return &cognitoidentityprovider.AdminEnableUserOutput{}, nil
}

func (m *mockProvisioningCognitoClient) DescribeUserPool(ctx context.Context, params *cognitoidentityprovider.DescribeUserPoolInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	return &cognitoidentityprovider.DescribeUserPoolOutput{}, nil
}

func attributeValue(attrs []types.AttributeType, name string) (string, bool) {
	for _, attr := range attrs {
		if attr.Name != nil && *attr.Name == name && attr.Value != nil {
			return *attr.Value, true
		}
	}
	return "", false
}

func TestCreateUserWithInvitation_HappyPathWithVerification(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{
		getUserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("happy@example.com")},
			{Name: aws.String("custom:role"), Value: aws.String("user")},
		},
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
		Email:      "happy@example.com",
		GivenName:  "Happy",
		FamilyName: "Path",
		Role:       "user",
	}

	user, tempPassword, err := CreateUserWithInvitation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || tempPassword == "" {
		t.Fatal("expected user and temporary password")
	}
	if !mockClient.adminGetUserCalled {
		t.Error("expected AdminGetUser for post-provision verification")
	}
	if mockClient.deleteUserCalled {
		t.Error("did not expect rollback on happy path")
	}
}

func TestCreateUserWithInvitation_RollbackOnPasswordSetFailure(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{
		setPasswordErr: errors.New("InvalidPasswordException: password policy violation"),
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
		Email:      "rollback@example.com",
		GivenName:  "Rollback",
		FamilyName: "Test",
		Role:       "user",
	}

	user, tempPassword, err := CreateUserWithInvitation(ctx, req)
	if err == nil {
		t.Fatal("expected error when AdminSetUserPassword fails")
	}
	if user != nil {
		t.Error("expected nil user on password-set failure")
	}
	if tempPassword != "" {
		t.Error("expected empty temporary password on failure")
	}
	if !mockClient.deleteUserCalled {
		t.Error("expected AdminDeleteUser to be called for rollback")
	}
	if mockClient.deleteUserInput == nil || aws.ToString(mockClient.deleteUserInput.Username) != "rollback@example.com" {
		t.Errorf("expected rollback delete for rollback@example.com, got %v", mockClient.deleteUserInput)
	}
}

func TestCognitoCreateUser_IncludesProvidedCustomAttributes(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{}
	SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
		return mockClient
	})
	SetOAuthConfig(&OAuthConfig{
		UserPoolID: "us-east-1_test",
		Region:     "us-east-1",
	})

	ctx := context.Background()
	req := CreateUserRequest{
		Email:      "attrs@example.com",
		GivenName:  "Custom",
		FamilyName: "User",
		Role:       "admin",
		CustomAttributes: map[string]string{
			"custom:orgId":    "org-42",
			"custom:regionId": "us-west",
		},
	}

	_, err := cognitoCreateUser(ctx, req, GetOAuthConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mockClient.createUserInput == nil {
		t.Fatal("expected AdminCreateUser to be called")
	}

	attrs := mockClient.createUserInput.UserAttributes
	if val, ok := attributeValue(attrs, "custom:orgId"); !ok || val != "org-42" {
		t.Errorf("expected custom:orgId=org-42, got %q ok=%v", val, ok)
	}
	if val, ok := attributeValue(attrs, "custom:regionId"); !ok || val != "us-west" {
		t.Errorf("expected custom:regionId=us-west, got %q ok=%v", val, ok)
	}
}

func TestCognitoCreateUser_OmitsOptionalAttrsWhenEmpty(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{}
	SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
		return mockClient
	})
	SetOAuthConfig(&OAuthConfig{
		UserPoolID: "us-east-1_test",
		Region:     "us-east-1",
	})

	ctx := context.Background()
	req := CreateUserRequest{
		Email:      "plain@example.com",
		GivenName:  "Plain",
		FamilyName: "User",
		Role:       "user",
	}

	_, err := cognitoCreateUser(ctx, req, GetOAuthConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attrs := mockClient.createUserInput.UserAttributes
	if _, ok := attributeValue(attrs, "custom:tenantId"); ok {
		t.Error("expected custom:tenantId to be omitted when empty")
	}
	if _, ok := attributeValue(attrs, "custom:serviceProviderId"); ok {
		t.Error("expected custom:serviceProviderId to be omitted when empty")
	}
}

func TestCreateUserWithInvitation_RollbackOnVerificationFailure(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{
		getUserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("verify-fail@example.com")},
			{Name: aws.String("custom:role"), Value: aws.String("user")},
			{Name: aws.String("custom:tenantId"), Value: aws.String("suncor")},
		},
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
		Email:      "verify-fail@example.com",
		GivenName:  "Verify",
		FamilyName: "Fail",
		Role:       "user",
		CustomAttributes: map[string]string{
			"custom:tenantId":          "suncor",
			"custom:serviceProviderId": "inrush",
		},
	}

	user, _, err := CreateUserWithInvitation(ctx, req)
	if err == nil {
		t.Fatal("expected error when verification fails")
	}
	if user != nil {
		t.Error("expected nil user on verification failure")
	}
	if !mockClient.adminGetUserCalled {
		t.Error("expected AdminGetUser to be called for verification")
	}
	if !mockClient.deleteUserCalled {
		t.Error("expected AdminDeleteUser to be called for rollback")
	}
}

func TestAssertRequiredCustomAttributes_HappyPath(t *testing.T) {
	cognitoUser := &types.UserType{
		Attributes: []types.AttributeType{
			{Name: aws.String("custom:role"), Value: aws.String("admin")},
			{Name: aws.String("custom:tenantId"), Value: aws.String("demo")},
			{Name: aws.String("custom:serviceProviderId"), Value: aws.String("inrush")},
		},
	}
	req := CreateUserRequest{
		Role: "admin",
		CustomAttributes: map[string]string{
			"custom:tenantId":          "demo",
			"custom:serviceProviderId": "inrush",
		},
	}

	if err := assertRequiredCustomAttributes(cognitoUser, req); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestAssertRequiredCustomAttributes_SkipsUnrequestedAttrs(t *testing.T) {
	cognitoUser := &types.UserType{
		Attributes: []types.AttributeType{
			{Name: aws.String("custom:role"), Value: aws.String("user")},
		},
	}
	req := CreateUserRequest{Role: "user"}

	if err := assertRequiredCustomAttributes(cognitoUser, req); err != nil {
		t.Fatalf("expected no error when custom attrs not requested, got %v", err)
	}
}

func TestCognitoCreateUser_NormalizesUnprefixedCustomAttributeKeys(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{}
	SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
		return mockClient
	})
	SetOAuthConfig(&OAuthConfig{
		UserPoolID: "us-east-1_test",
		Region:     "us-east-1",
	})

	ctx := context.Background()
	req := CreateUserRequest{
		Email:      "rawkey@example.com",
		GivenName:  "Raw",
		FamilyName: "Key",
		Role:       "user",
		CustomAttributes: map[string]string{
			"tenantId": "bp",
		},
	}

	_, err := cognitoCreateUser(ctx, req, GetOAuthConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	val, ok := attributeValue(mockClient.createUserInput.UserAttributes, "custom:tenantId")
	if !ok || val != "bp" {
		t.Errorf("expected custom:tenantId=bp, got %q ok=%v", val, ok)
	}
}

func TestCreateUserWithInvitation_CustomAttributesVerifiedOnCreate(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{
		getUserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("attrs@example.com")},
			{Name: aws.String("custom:role"), Value: aws.String("admin")},
			{Name: aws.String("custom:tenantId"), Value: aws.String("suncor")},
			{Name: aws.String("custom:serviceProviderId"), Value: aws.String("inrush")},
		},
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
		Email:      "attrs@example.com",
		GivenName:  "Attrs",
		FamilyName: "User",
		Role:       "admin",
		CustomAttributes: map[string]string{
			"custom:tenantId":          "suncor",
			"custom:serviceProviderId": "inrush",
		},
	}

	user, tempPassword, err := CreateUserWithInvitation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || tempPassword == "" {
		t.Fatal("expected user and temporary password")
	}
	if mockClient.createUserInput == nil {
		t.Fatal("expected AdminCreateUser to be called")
	}
	if val, ok := attributeValue(mockClient.createUserInput.UserAttributes, "custom:tenantId"); !ok || val != "suncor" {
		t.Errorf("expected custom:tenantId on create, got %q ok=%v", val, ok)
	}
	if val, ok := attributeValue(mockClient.createUserInput.UserAttributes, "custom:serviceProviderId"); !ok || val != "inrush" {
		t.Errorf("expected custom:serviceProviderId on create, got %q ok=%v", val, ok)
	}
	if mockClient.deleteUserCalled {
		t.Error("did not expect rollback when custom attributes verified")
	}
}

func TestCreateUserWithInvitation_RollbackOnAdminGetUserFailure(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	getUserErr := errors.New("InternalErrorException: service unavailable")
	mockClient := &mockProvisioningCognitoClient{
		getUserErr: getUserErr,
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
		Email:      "getuser-fail@example.com",
		GivenName:  "GetUser",
		FamilyName: "Fail",
		Role:       "user",
	}

	user, tempPassword, err := CreateUserWithInvitation(ctx, req)
	if err == nil {
		t.Fatal("expected error when AdminGetUser fails")
	}
	if user != nil {
		t.Error("expected nil user on AdminGetUser failure")
	}
	if tempPassword != "" {
		t.Error("expected empty temporary password on failure")
	}
	if !mockClient.adminGetUserCalled {
		t.Error("expected AdminGetUser to be called for verification")
	}
	if !mockClient.deleteUserCalled {
		t.Error("expected AdminDeleteUser to be called for rollback")
	}
	if mockClient.deleteUserInput == nil || aws.ToString(mockClient.deleteUserInput.Username) != "getuser-fail@example.com" {
		t.Errorf("expected rollback delete for getuser-fail@example.com, got %v", mockClient.deleteUserInput)
	}
}

func TestNormalizeCustomAttributes_DedupesEquivalentKeys(t *testing.T) {
	attrs, err := normalizeCustomAttributes(map[string]string{
		"tenantId":        "bp",
		"custom:tenantId": "bp",
	}, "custom:role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attrs) != 1 {
		t.Fatalf("expected 1 deduped attribute, got %d", len(attrs))
	}
	if val, ok := attrs["custom:tenantId"]; !ok || val != "bp" {
		t.Errorf("expected custom:tenantId=bp, got %q ok=%v", val, ok)
	}
}

func TestNormalizeCustomAttributes_RejectsConflictingKeys(t *testing.T) {
	_, err := normalizeCustomAttributes(map[string]string{
		"tenantId":        "bp",
		"custom:tenantId": "suncor",
	}, "custom:role")
	if err == nil {
		t.Fatal("expected error when equivalent keys have different values")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected error to wrap ErrInvalidInput, got %v", err)
	}
}

func TestNormalizeCustomAttributes_RejectsRoleCollision(t *testing.T) {
	_, err := normalizeCustomAttributes(map[string]string{
		"custom:role": "admin",
	}, "custom:role")
	if err == nil {
		t.Fatal("expected error when custom attribute collides with role attribute")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected error to wrap ErrInvalidInput, got %v", err)
	}
}

func TestCognitoCreateUser_RejectsDuplicateCustomAttributeKeys(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockProvisioningCognitoClient{}
	SetCognitoClientFactory(func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
		return mockClient
	})
	SetOAuthConfig(&OAuthConfig{
		UserPoolID: "us-east-1_test",
		Region:     "us-east-1",
	})

	ctx := context.Background()
	req := CreateUserRequest{
		Email:      "dup@example.com",
		GivenName:  "Dup",
		FamilyName: "Key",
		Role:       "user",
		CustomAttributes: map[string]string{
			"tenantId":        "bp",
			"custom:tenantId": "suncor",
		},
	}

	_, err := cognitoCreateUser(ctx, req, GetOAuthConfig())
	if err == nil {
		t.Fatal("expected error when duplicate keys have conflicting values")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected error to wrap ErrInvalidInput, got %v", err)
	}
	if mockClient.createUserInput != nil {
		t.Error("expected AdminCreateUser not to be called on validation failure")
	}
}
