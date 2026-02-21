package user

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

var (
	stsCache      = make(map[string]*cachedCredentials)
	stsCacheMutex sync.RWMutex
)

type cachedCredentials struct {
	creds     *STSCredentials
	expiresAt time.Time
}

const cacheExpirationBuffer = 5 * time.Minute

func getCachedCredentials(tokenHash string) *STSCredentials {
	stsCacheMutex.RLock()
	defer stsCacheMutex.RUnlock()

	cached, exists := stsCache[tokenHash]
	if !exists {
		return nil
	}

	if time.Now().Add(cacheExpirationBuffer).After(cached.expiresAt) {
		return nil
	}

	return cached.creds
}

func setCachedCredentials(tokenHash string, creds *STSCredentials) {
	stsCacheMutex.Lock()
	defer stsCacheMutex.Unlock()

	stsCache[tokenHash] = &cachedCredentials{
		creds:     creds,
		expiresAt: creds.Expiration,
	}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:16])
}

func clearSTSCache() {
	stsCacheMutex.Lock()
	defer stsCacheMutex.Unlock()
	stsCache = make(map[string]*cachedCredentials)
}
