package user

import "testing"

func TestGetRoleAttributeName_DefaultWhenNoConfig(t *testing.T) {
	origConfig := oauthConfig
	defer func() { oauthConfig = origConfig }()

	oauthConfig = nil

	got := getRoleAttributeName()
	if got != "custom:role" {
		t.Errorf("expected 'custom:role', got %q", got)
	}
}

func TestGetRoleAttributeName_DefaultWhenEmpty(t *testing.T) {
	origConfig := oauthConfig
	defer func() { oauthConfig = origConfig }()

	oauthConfig = &OAuthConfig{RoleAttributeName: ""}

	got := getRoleAttributeName()
	if got != "custom:role" {
		t.Errorf("expected 'custom:role', got %q", got)
	}
}

func TestGetRoleAttributeName_CustomValue(t *testing.T) {
	origConfig := oauthConfig
	defer func() { oauthConfig = origConfig }()

	oauthConfig = &OAuthConfig{RoleAttributeName: "custom:userRole"}

	got := getRoleAttributeName()
	if got != "custom:userRole" {
		t.Errorf("expected 'custom:userRole', got %q", got)
	}
}
