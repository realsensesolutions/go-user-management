package user

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// StateRepository interface for OAuth state management
type StateRepository interface {
	StoreState(state string, redirectURL string, expiresAt time.Time) error
	ValidateAndRemoveState(state string) (string, bool)
	CleanupExpiredStates() error
}

// GenerateSecureState generates a cryptographically secure random state parameter
func GenerateSecureState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}