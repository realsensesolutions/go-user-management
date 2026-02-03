package user

import "testing"

func TestSelectRoleARN(t *testing.T) {
	config := &OAuthConfig{STSRoleARN: "arn:aws:iam::123:role/DefaultRole"}

	tests := []struct {
		name     string
		claims   *OIDCClaims
		expected string
	}{
		{
			name:     "prefers cognito:preferred_role",
			claims:   &OIDCClaims{PreferredRole: "arn:aws:iam::123:role/AdminRole"},
			expected: "arn:aws:iam::123:role/AdminRole",
		},
		{
			name:     "falls back to first role in cognito:roles",
			claims:   &OIDCClaims{Roles: []string{"arn:aws:iam::123:role/EditorRole"}},
			expected: "arn:aws:iam::123:role/EditorRole",
		},
		{
			name:     "falls back to config when no role claims",
			claims:   &OIDCClaims{},
			expected: "arn:aws:iam::123:role/DefaultRole",
		},
		{
			name:     "handles nil claims",
			claims:   nil,
			expected: "arn:aws:iam::123:role/DefaultRole",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectRoleARN(tt.claims, config)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestIsRoleAllowed(t *testing.T) {
	tests := []struct {
		name         string
		roleARN      string
		allowedRoles []string
		expected     bool
	}{
		{
			name:         "role is in allowed list",
			roleARN:      "arn:aws:iam::123:role/AdminRole",
			allowedRoles: []string{"arn:aws:iam::123:role/AdminRole", "arn:aws:iam::123:role/EditorRole"},
			expected:     true,
		},
		{
			name:         "role is not in allowed list",
			roleARN:      "arn:aws:iam::123:role/SuperRole",
			allowedRoles: []string{"arn:aws:iam::123:role/AdminRole", "arn:aws:iam::123:role/EditorRole"},
			expected:     false,
		},
		{
			name:         "empty allowed list",
			roleARN:      "arn:aws:iam::123:role/AdminRole",
			allowedRoles: []string{},
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRoleAllowed(tt.roleARN, tt.allowedRoles)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBuildSessionName(t *testing.T) {
	tests := []struct {
		name     string
		claims   *OIDCClaims
		config   *OAuthConfig
		expected string
	}{
		{
			name:     "uses default when no config session name",
			claims:   &OIDCClaims{Email: "test@example.com"},
			config:   &OAuthConfig{},
			expected: "user-session-test@example.com",
		},
		{
			name:     "uses config session name prefix",
			claims:   &OIDCClaims{Email: "test@example.com"},
			config:   &OAuthConfig{STSSessionName: "my-app"},
			expected: "my-app-test@example.com",
		},
		{
			name:     "handles nil claims",
			claims:   nil,
			config:   &OAuthConfig{STSSessionName: "my-app"},
			expected: "my-app",
		},
		{
			name:     "truncates long session names",
			claims:   &OIDCClaims{Email: "very-long-email-address-that-exceeds-limit@example.com"},
			config:   &OAuthConfig{STSSessionName: "very-long-prefix-name"},
			expected: "very-long-prefix-name-very-long-email-address-that-exceeds-limit", // truncated to 64 chars
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSessionName(tt.claims, tt.config)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}
