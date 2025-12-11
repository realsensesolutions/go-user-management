package user

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestEncryptedStateRepository(t *testing.T) {
	originalKey := os.Getenv("OAUTH_STATE_ENCRYPTION_KEY")
	defer func() {
		if originalKey != "" {
			os.Setenv("OAUTH_STATE_ENCRYPTION_KEY", originalKey)
		} else {
			os.Unsetenv("OAUTH_STATE_ENCRYPTION_KEY")
		}
	}()

	os.Setenv("OAUTH_STATE_ENCRYPTION_KEY", "test-key-for-testing-purposes-only")
	repo := NewEncryptedStateRepository()

	t.Run("stores and validates state", func(t *testing.T) {
		nonce := "test-nonce-12345"
		redirectURL := "https://example.com/callback"
		expiresAt := time.Now().Add(5 * time.Minute)

		err := repo.StoreState(nonce, redirectURL, expiresAt)
		if err != nil {
			t.Fatalf("expected no error storing state, got: %v", err)
		}

		encryptedState, err := repo.(*EncryptedStateRepository).GenerateEncryptedState(nonce, redirectURL)
		if err != nil {
			t.Fatalf("expected no error generating encrypted state, got: %v", err)
		}

		validatedURL, isValid := repo.ValidateAndRemoveState(encryptedState)
		if !isValid {
			t.Fatal("expected state to be valid")
		}
		if validatedURL != redirectURL {
			t.Errorf("expected redirectURL '%s', got '%s'", redirectURL, validatedURL)
		}
	})

	t.Run("rejects expired state", func(t *testing.T) {
		nonce := "expired-nonce"
		redirectURL := "https://example.com/callback"

		oldRepo := repo.(*EncryptedStateRepository)
		payload := statePayload{
			Timestamp:   time.Now().Add(-10 * time.Minute).Unix(),
			RedirectURL: redirectURL,
			Nonce:       nonce,
		}

		payloadJSON, _ := json.Marshal(payload)
		encryptedState, _ := oldRepo.encrypt(payloadJSON)

		_, isValid := repo.ValidateAndRemoveState(encryptedState)
		if isValid {
			t.Error("expected expired state to be invalid")
		}
	})

	t.Run("rejects invalid encrypted state", func(t *testing.T) {
		_, isValid := repo.ValidateAndRemoveState("invalid-encrypted-state")
		if isValid {
			t.Error("expected invalid state to be rejected")
		}
	})
}

