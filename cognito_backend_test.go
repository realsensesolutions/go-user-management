package user

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

func TestCognitoUserToUser_BasicAttributes(t *testing.T) {
	cognitoUser := types.UserType{
		Username: aws.String("test@example.com"),
		Attributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("test@example.com")},
			{Name: aws.String("given_name"), Value: aws.String("John")},
			{Name: aws.String("family_name"), Value: aws.String("Doe")},
			{Name: aws.String("custom:userRole"), Value: aws.String("admin")},
		},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", user.Email)
	}
	if user.GivenName != "John" {
		t.Errorf("expected givenName 'John', got %q", user.GivenName)
	}
	if user.FamilyName != "Doe" {
		t.Errorf("expected familyName 'Doe', got %q", user.FamilyName)
	}
	if user.Role != "admin" {
		t.Errorf("expected role 'admin', got %q", user.Role)
	}
}

func TestCognitoUserToUser_TenantAttributes(t *testing.T) {
	cognitoUser := types.UserType{
		Username: aws.String("tenant-user@example.com"),
		Attributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("tenant-user@example.com")},
			{Name: aws.String("given_name"), Value: aws.String("Alice")},
			{Name: aws.String("family_name"), Value: aws.String("Smith")},
			{Name: aws.String("custom:userRole"), Value: aws.String("user")},
			{Name: aws.String("custom:tenantId"), Value: aws.String("demo")},
			{Name: aws.String("custom:serviceProviderId"), Value: aws.String("realsense")},
		},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Email != "tenant-user@example.com" {
		t.Errorf("expected email 'tenant-user@example.com', got %q", user.Email)
	}
	if user.TenantID != "demo" {
		t.Errorf("expected tenantId 'demo', got %q", user.TenantID)
	}
	if user.ServiceProviderID != "realsense" {
		t.Errorf("expected serviceProviderId 'realsense', got %q", user.ServiceProviderID)
	}
}

func TestCognitoUserToUser_EmptyTenantAttributes(t *testing.T) {
	cognitoUser := types.UserType{
		Username: aws.String("no-tenant@example.com"),
		Attributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("no-tenant@example.com")},
			{Name: aws.String("custom:userRole"), Value: aws.String("superadmin")},
		},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.TenantID != "" {
		t.Errorf("expected empty tenantId, got %q", user.TenantID)
	}
	if user.ServiceProviderID != "" {
		t.Errorf("expected empty serviceProviderId, got %q", user.ServiceProviderID)
	}
}

func TestCognitoUserToUser_DefaultRole(t *testing.T) {
	cognitoUser := types.UserType{
		Username: aws.String("no-role@example.com"),
		Attributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("no-role@example.com")},
		},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Role != "user" {
		t.Errorf("expected default role 'user', got %q", user.Role)
	}
}

func TestCognitoUserToUser_UsernameAsEmailFallback(t *testing.T) {
	cognitoUser := types.UserType{
		Username:   aws.String("fallback@example.com"),
		Attributes: []types.AttributeType{},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Email != "fallback@example.com" {
		t.Errorf("expected email from username 'fallback@example.com', got %q", user.Email)
	}
}

func TestCognitoUserToUser_NoEmailError(t *testing.T) {
	cognitoUser := types.UserType{
		Username:   nil,
		Attributes: []types.AttributeType{},
	}

	_, err := cognitoUserToUser(cognitoUser)
	if err == nil {
		t.Error("expected error for user with no email")
	}
}

func TestCognitoUserToUser_UsernameIsStored(t *testing.T) {
	cognitoUser := types.UserType{
		Username: aws.String("google_123456789"),
		Attributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("test@example.com")},
			{Name: aws.String("given_name"), Value: aws.String("John")},
			{Name: aws.String("family_name"), Value: aws.String("Doe")},
		},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Username != "google_123456789" {
		t.Errorf("expected username 'google_123456789', got %q", user.Username)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", user.Email)
	}
}

func TestCognitoUserToUser_UsernameWithEmailFallback(t *testing.T) {
	cognitoUser := types.UserType{
		Username: aws.String("test@example.com"),
		Attributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String("test@example.com")},
		},
	}

	user, err := cognitoUserToUser(cognitoUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Username != "test@example.com" {
		t.Errorf("expected username 'test@example.com', got %q", user.Username)
	}
}
