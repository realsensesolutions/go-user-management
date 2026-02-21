package user

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestHashToken(t *testing.T) {
	tests := []struct {
		name   string
		token1 string
		token2 string
		same   bool
	}{
		{
			name:   "same token produces same hash",
			token1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			token2: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			same:   true,
		},
		{
			name:   "different tokens produce different hashes",
			token1: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload1.signature",
			token2: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload2.signature",
			same:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := hashToken(tt.token1)
			hash2 := hashToken(tt.token2)

			if (hash1 == hash2) != tt.same {
				t.Errorf("hashToken() same=%v, want %v (hash1=%s, hash2=%s)",
					hash1 == hash2, tt.same, hash1, hash2)
			}

			if len(hash1) != 32 {
				t.Errorf("hashToken() should return 32-char hex string, got %d chars", len(hash1))
			}
		})
	}
}

func TestGetCachedCredentials_Miss(t *testing.T) {
	clearSTSCache()

	tokenHash := hashToken("some-token-that-was-never-cached")
	cached := getCachedCredentials(tokenHash)

	if cached != nil {
		t.Errorf("getCachedCredentials() should return nil for cache miss, got %+v", cached)
	}
}

func TestGetCachedCredentials_Hit(t *testing.T) {
	clearSTSCache()

	token := "test-token-for-cache-hit"
	tokenHash := hashToken(token)
	creds := &STSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
		Expiration:      time.Now().Add(1 * time.Hour),
	}

	setCachedCredentials(tokenHash, creds)
	cached := getCachedCredentials(tokenHash)

	if cached == nil {
		t.Fatal("getCachedCredentials() should return cached credentials")
	}

	if cached.AccessKeyID != creds.AccessKeyID {
		t.Errorf("AccessKeyID = %s, want %s", cached.AccessKeyID, creds.AccessKeyID)
	}
	if cached.SecretAccessKey != creds.SecretAccessKey {
		t.Errorf("SecretAccessKey = %s, want %s", cached.SecretAccessKey, creds.SecretAccessKey)
	}
	if cached.SessionToken != creds.SessionToken {
		t.Errorf("SessionToken = %s, want %s", cached.SessionToken, creds.SessionToken)
	}
}

func TestGetCachedCredentials_ExpiredReturnsNil(t *testing.T) {
	clearSTSCache()

	token := "test-token-for-expiration"
	tokenHash := hashToken(token)
	creds := &STSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
		Expiration:      time.Now().Add(3 * time.Minute), // Expires within 5-minute buffer
	}

	setCachedCredentials(tokenHash, creds)
	cached := getCachedCredentials(tokenHash)

	if cached != nil {
		t.Errorf("getCachedCredentials() should return nil for near-expiry credentials, got %+v", cached)
	}
}

func TestGetCachedCredentials_NotExpiredReturnsCredentials(t *testing.T) {
	clearSTSCache()

	token := "test-token-valid-expiration"
	tokenHash := hashToken(token)
	creds := &STSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
		Expiration:      time.Now().Add(10 * time.Minute), // Expires after 5-minute buffer
	}

	setCachedCredentials(tokenHash, creds)
	cached := getCachedCredentials(tokenHash)

	if cached == nil {
		t.Fatal("getCachedCredentials() should return credentials when not near expiry")
	}
}

func TestCacheThreadSafety(t *testing.T) {
	clearSTSCache()

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			token := "test-token"
			tokenHash := hashToken(token)

			creds := &STSCredentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "session-token",
				Expiration:      time.Now().Add(1 * time.Hour),
			}

			setCachedCredentials(tokenHash, creds)
			_ = getCachedCredentials(tokenHash)
		}(i)
	}

	wg.Wait()
}

func TestClearSTSCache(t *testing.T) {
	token := "test-token-to-clear"
	tokenHash := hashToken(token)
	creds := &STSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
		Expiration:      time.Now().Add(1 * time.Hour),
	}

	setCachedCredentials(tokenHash, creds)
	cached := getCachedCredentials(tokenHash)
	if cached == nil {
		t.Fatal("setCachedCredentials should have stored the credentials")
	}

	clearSTSCache()
	cached = getCachedCredentials(tokenHash)
	if cached != nil {
		t.Error("clearSTSCache() should have cleared all cached credentials")
	}
}

type mockSTSClient struct {
	callCount  int32
	expiration time.Time
}

func (m *mockSTSClient) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	atomic.AddInt32(&m.callCount, 1)
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
			SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
			SessionToken:    aws.String("mock-session-token"),
			Expiration:      aws.Time(m.expiration),
		},
	}, nil
}

func createTestJWT(email, role string) string {
	claims := map[string]interface{}{
		"sub":                    "user-123",
		"email":                  email,
		"cognito:preferred_role": role,
		"exp":                    time.Now().Add(1 * time.Hour).Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return header + "." + payload + ".signature"
}

func TestGetSTSCredentials_UsesCacheOnSecondCall(t *testing.T) {
	clearSTSCache()
	defer ResetSTSClientFactory()

	mockClient := &mockSTSClient{
		expiration: time.Now().Add(1 * time.Hour),
	}

	SetSTSClientFactory(func(ctx context.Context, cfg aws.Config) STSClient {
		return mockClient
	})

	token := createTestJWT("test@example.com", "arn:aws:iam::123456789012:role/TestRole")
	oauthConfig := &OAuthConfig{
		Region:     "us-east-1",
		STSRoleARN: "arn:aws:iam::123456789012:role/TestRole",
	}

	ctx := context.Background()

	creds1, err := GetSTSCredentials(ctx, token, oauthConfig)
	if err != nil {
		t.Fatalf("First GetSTSCredentials() failed: %v", err)
	}
	if creds1 == nil {
		t.Fatal("First GetSTSCredentials() returned nil credentials")
	}

	creds2, err := GetSTSCredentials(ctx, token, oauthConfig)
	if err != nil {
		t.Fatalf("Second GetSTSCredentials() failed: %v", err)
	}
	if creds2 == nil {
		t.Fatal("Second GetSTSCredentials() returned nil credentials")
	}

	callCount := atomic.LoadInt32(&mockClient.callCount)
	if callCount != 1 {
		t.Errorf("STS should be called only once (cache hit on second call), got %d calls", callCount)
	}

	if creds1.AccessKeyID != creds2.AccessKeyID {
		t.Error("Second call should return same credentials from cache")
	}
}

func TestGetSTSCredentials_CacheMissOnDifferentTokens(t *testing.T) {
	clearSTSCache()
	defer ResetSTSClientFactory()

	mockClient := &mockSTSClient{
		expiration: time.Now().Add(1 * time.Hour),
	}

	SetSTSClientFactory(func(ctx context.Context, cfg aws.Config) STSClient {
		return mockClient
	})

	token1 := createTestJWT("user1@example.com", "arn:aws:iam::123456789012:role/TestRole")
	token2 := createTestJWT("user2@example.com", "arn:aws:iam::123456789012:role/TestRole")
	oauthConfig := &OAuthConfig{
		Region:     "us-east-1",
		STSRoleARN: "arn:aws:iam::123456789012:role/TestRole",
	}

	ctx := context.Background()

	_, err := GetSTSCredentials(ctx, token1, oauthConfig)
	if err != nil {
		t.Fatalf("First GetSTSCredentials() failed: %v", err)
	}

	_, err = GetSTSCredentials(ctx, token2, oauthConfig)
	if err != nil {
		t.Fatalf("Second GetSTSCredentials() failed: %v", err)
	}

	callCount := atomic.LoadInt32(&mockClient.callCount)
	if callCount != 2 {
		t.Errorf("STS should be called twice (different tokens = cache miss), got %d calls", callCount)
	}
}

func TestGetSTSCredentials_RefetchesExpiredCredentials(t *testing.T) {
	clearSTSCache()
	defer ResetSTSClientFactory()

	mockClient := &mockSTSClient{
		expiration: time.Now().Add(3 * time.Minute),
	}

	SetSTSClientFactory(func(ctx context.Context, cfg aws.Config) STSClient {
		return mockClient
	})

	token := createTestJWT("test@example.com", "arn:aws:iam::123456789012:role/TestRole")
	oauthConfig := &OAuthConfig{
		Region:     "us-east-1",
		STSRoleARN: "arn:aws:iam::123456789012:role/TestRole",
	}

	ctx := context.Background()

	_, err := GetSTSCredentials(ctx, token, oauthConfig)
	if err != nil {
		t.Fatalf("First GetSTSCredentials() failed: %v", err)
	}

	_, err = GetSTSCredentials(ctx, token, oauthConfig)
	if err != nil {
		t.Fatalf("Second GetSTSCredentials() failed: %v", err)
	}

	callCount := atomic.LoadInt32(&mockClient.callCount)
	if callCount != 2 {
		t.Errorf("STS should be called twice (credentials expire within buffer), got %d calls", callCount)
	}
}
