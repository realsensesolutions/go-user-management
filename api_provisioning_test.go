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

func TestCognitoCreateUser_IncludesOptionalTenantAndServiceProviderAttrs(t *testing.T) {
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
		Email:      "tenant@example.com",
		GivenName:  "Tenant",
		FamilyName: "User",
		Role:       "admin",
		CustomAttributes: map[string]string{
			"custom:tenantId":          "suncor",
			"custom:serviceProviderId": "inrush",
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
	if val, ok := attributeValue(attrs, "custom:tenantId"); !ok || val != "suncor" {
		t.Errorf("expected custom:tenantId=suncor, got %q ok=%v", val, ok)
	}
	if val, ok := attributeValue(attrs, "custom:serviceProviderId"); !ok || val != "inrush" {
		t.Errorf("expected custom:serviceProviderId=inrush, got %q ok=%v", val, ok)
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
