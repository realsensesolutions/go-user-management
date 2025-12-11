package user

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

type EncryptedStateRepository struct {
	key []byte
}

type statePayload struct {
	Timestamp   int64  `json:"timestamp"`
	RedirectURL string `json:"redirect_url"`
	Nonce       string `json:"nonce"`
}

func NewEncryptedStateRepository() StateRepository {
	key := getOrGenerateStateKey()
	return &EncryptedStateRepository{key: key}
}

func getOrGenerateStateKey() []byte {
	keyEnv := os.Getenv("OAUTH_STATE_ENCRYPTION_KEY")
	if keyEnv != "" {
		keyHash := sha256.Sum256([]byte(keyEnv))
		return keyHash[:]
	}

	log.Printf("⚠️ [EncryptedStateRepo] OAUTH_STATE_ENCRYPTION_KEY not set, using default (not secure for production!)")
	defaultKey := sha256.Sum256([]byte("default-oauth-state-key-change-in-production"))
	return defaultKey[:]
}

func (r *EncryptedStateRepository) StoreState(state string, redirectURL string, expiresAt time.Time) error {
	statePreview := state
	if len(state) > 8 {
		statePreview = state[:8] + "..."
	}
	log.Printf("✅ [EncryptedStateRepo] State prepared for encryption (nonce: %s)", statePreview)
	return nil
}

func (r *EncryptedStateRepository) GenerateEncryptedState(nonce string, redirectURL string) (string, error) {
	payload := statePayload{
		Timestamp:   time.Now().Unix(),
		RedirectURL: redirectURL,
		Nonce:       nonce,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state payload: %w", err)
	}

	return r.encrypt(payloadJSON)
}

func (r *EncryptedStateRepository) ValidateAndRemoveState(state string) (string, bool) {
	decrypted, err := r.decrypt(state)
	if err != nil {
		log.Printf("❌ [EncryptedStateRepo] Failed to decrypt state: %v", err)
		return "", false
	}

	var payload statePayload
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		log.Printf("❌ [EncryptedStateRepo] Failed to unmarshal state payload: %v", err)
		return "", false
	}

	now := time.Now().Unix()
	maxAge := int64(5 * time.Minute / time.Second)

	if now-payload.Timestamp > maxAge {
		log.Printf("❌ [EncryptedStateRepo] State expired (age: %d seconds)", now-payload.Timestamp)
		return "", false
	}

	if payload.Timestamp > now+60 {
		log.Printf("❌ [EncryptedStateRepo] State timestamp is in the future (clock skew?)")
		return "", false
	}

	log.Printf("✅ [EncryptedStateRepo] State validated successfully (age: %d seconds)", now-payload.Timestamp)
	return payload.RedirectURL, true
}

func (r *EncryptedStateRepository) CleanupExpiredStates() error {
	return nil
}

func (r *EncryptedStateRepository) Encrypt(plaintext []byte) (string, error) {
	return r.encrypt(plaintext)
}

func (r *EncryptedStateRepository) encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (r *EncryptedStateRepository) decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

