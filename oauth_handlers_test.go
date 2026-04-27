package user

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockOAuth2Servicer struct {
	capturedRedirectURL string
	capturedLoginHint   string
	returnURL           string
	returnErr           error
}

func (m *mockOAuth2Servicer) GenerateAuthURL(redirectURL, loginHint string) (string, error) {
	m.capturedRedirectURL = redirectURL
	m.capturedLoginHint = loginHint
	if m.returnURL != "" {
		return m.returnURL, m.returnErr
	}
	return "https://fake.example.com/authorize?state=x", m.returnErr
}

func (m *mockOAuth2Servicer) HandleCallback(code, state string) (*Claims, string, string, error) {
	return nil, "", "", nil
}

func TestLoginHandler_ForwardsLoginHintFromQuery(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		wantLoginHint string
	}{
		{
			name:          "forwards login_hint when present",
			query:         "?redirect_url=/dashboard&login_hint=alice@example.com",
			wantLoginHint: "alice@example.com",
		},
		{
			name:          "passes empty hint when login_hint absent",
			query:         "?redirect_url=/dashboard",
			wantLoginHint: "",
		},
		{
			name:          "passes empty hint when login_hint is empty string",
			query:         "?redirect_url=/dashboard&login_hint=",
			wantLoginHint: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockOAuth2Servicer{}
			h := &OAuth2Handlers{
				oauth2Service: mock,
			}

			req := httptest.NewRequest(http.MethodGet, "/api/auth/login"+tt.query, nil)
			w := httptest.NewRecorder()

			h.LoginHandler(w, req)

			if mock.capturedLoginHint != tt.wantLoginHint {
				t.Errorf("expected loginHint=%q, got %q", tt.wantLoginHint, mock.capturedLoginHint)
			}
		})
	}
}
