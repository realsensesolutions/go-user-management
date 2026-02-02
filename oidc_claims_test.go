package user

import "testing"

func TestOIDCClaimsToClaims_CopiesTenantFields(t *testing.T) {
	oidcClaims := &OIDCClaims{
		Sub:               "sub-123",
		Email:             "test@example.com",
		GivenName:         "Test",
		FamilyName:        "User",
		Username:          "test@example.com",
		UserRole:          "admin",
		TenantID:          "bp",
		ServiceProviderID: "inrush",
	}

	claims := oidcClaimsToClaims(oidcClaims, "user")
	if claims == nil {
		t.Fatal("expected claims, got nil")
	}

	if claims.TenantID != "bp" {
		t.Errorf("expected TenantID 'bp', got %q", claims.TenantID)
	}
	if claims.ServiceProviderID != "inrush" {
		t.Errorf("expected ServiceProviderID 'inrush', got %q", claims.ServiceProviderID)
	}
	if claims.Provider != "cognito" {
		t.Errorf("expected provider 'cognito', got %q", claims.Provider)
	}
}
