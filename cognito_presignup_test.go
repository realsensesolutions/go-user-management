package user

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type mockPreSignUpCognitoClient struct {
	output *cognitoidentityprovider.DescribeUserPoolOutput
	err    error

	// stubs for unused CognitoClient methods
}

func (m *mockPreSignUpCognitoClient) ListUsers(_ context.Context, _ *cognitoidentityprovider.ListUsersInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error) {
	return &cognitoidentityprovider.ListUsersOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminUpdateUserAttributes(_ context.Context, _ *cognitoidentityprovider.AdminUpdateUserAttributesInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminGetUser(_ context.Context, _ *cognitoidentityprovider.AdminGetUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	return &cognitoidentityprovider.AdminGetUserOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminCreateUser(_ context.Context, _ *cognitoidentityprovider.AdminCreateUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	return &cognitoidentityprovider.AdminCreateUserOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminDeleteUser(_ context.Context, _ *cognitoidentityprovider.AdminDeleteUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error) {
	return &cognitoidentityprovider.AdminDeleteUserOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminSetUserPassword(_ context.Context, _ *cognitoidentityprovider.AdminSetUserPasswordInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminDisableUser(_ context.Context, _ *cognitoidentityprovider.AdminDisableUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDisableUserOutput, error) {
	return &cognitoidentityprovider.AdminDisableUserOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) AdminEnableUser(_ context.Context, _ *cognitoidentityprovider.AdminEnableUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminEnableUserOutput, error) {
	return &cognitoidentityprovider.AdminEnableUserOutput{}, nil
}
func (m *mockPreSignUpCognitoClient) DescribeUserPool(_ context.Context, _ *cognitoidentityprovider.DescribeUserPoolInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	return m.output, m.err
}

func TestGetUserPoolPreSignUpARN_ReturnARN(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockPreSignUpCognitoClient{
		output: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &types.UserPoolType{
				LambdaConfig: &types.LambdaConfigType{
					PreSignUp: aws.String("arn:aws:lambda:us-east-1:123:function:auth-inrush-presignup"),
				},
			},
		},
	}
	SetCognitoClientFactory(func(_ context.Context, _ aws.Config, _ string) CognitoClient { return mockClient })
	SetOAuthConfig(&OAuthConfig{UserPoolID: "us-east-1_test", Region: "us-east-1"})

	arn, err := GetUserPoolPreSignUpARN(context.Background(), "us-east-1_test")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if arn != "arn:aws:lambda:us-east-1:123:function:auth-inrush-presignup" {
		t.Errorf("unexpected ARN: %s", arn)
	}
}

func TestGetUserPoolPreSignUpARN_ReturnsEmptyWhenNoPreSignUp(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockPreSignUpCognitoClient{
		output: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &types.UserPoolType{
				LambdaConfig: &types.LambdaConfigType{},
			},
		},
	}
	SetCognitoClientFactory(func(_ context.Context, _ aws.Config, _ string) CognitoClient { return mockClient })
	SetOAuthConfig(&OAuthConfig{UserPoolID: "us-east-1_test", Region: "us-east-1"})

	arn, err := GetUserPoolPreSignUpARN(context.Background(), "us-east-1_test")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if arn != "" {
		t.Errorf("expected empty ARN, got: %s", arn)
	}
}

func TestGetUserPoolPreSignUpARN_ReturnsEmptyWhenLambdaConfigNil(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	mockClient := &mockPreSignUpCognitoClient{
		output: &cognitoidentityprovider.DescribeUserPoolOutput{
			UserPool: &types.UserPoolType{},
		},
	}
	SetCognitoClientFactory(func(_ context.Context, _ aws.Config, _ string) CognitoClient { return mockClient })
	SetOAuthConfig(&OAuthConfig{UserPoolID: "us-east-1_test", Region: "us-east-1"})

	arn, err := GetUserPoolPreSignUpARN(context.Background(), "us-east-1_test")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if arn != "" {
		t.Errorf("expected empty ARN, got: %s", arn)
	}
}

func TestGetUserPoolPreSignUpARN_PropagatesDescribeError(t *testing.T) {
	originalFactory := cognitoClientFactory
	defer func() { cognitoClientFactory = originalFactory }()

	describeErr := errors.New("ResourceNotFoundException")
	mockClient := &mockPreSignUpCognitoClient{err: describeErr}
	SetCognitoClientFactory(func(_ context.Context, _ aws.Config, _ string) CognitoClient { return mockClient })
	SetOAuthConfig(&OAuthConfig{UserPoolID: "us-east-1_test", Region: "us-east-1"})

	_, err := GetUserPoolPreSignUpARN(context.Background(), "us-east-1_test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, describeErr) {
		t.Errorf("expected wrapped describeErr, got: %v", err)
	}
}

func TestGetUserPoolPreSignUpARN_ReturnsErrorWhenUserPoolIDEmpty(t *testing.T) {
	_, err := GetUserPoolPreSignUpARN(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty userPoolID, got nil")
	}
}
