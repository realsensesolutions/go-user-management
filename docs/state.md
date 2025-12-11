# OAuth State Management: Encrypted Stateless Implementation

## Overview

This document explains how symmetric key encryption works and how we use it in `go-user-management` for OAuth state management. Our implementation uses **AES-256-GCM** encryption to create stateless OAuth state tokens that work seamlessly in serverless/Lambda environments.

## How Symmetric Key Encryption Works

**Symmetric key encryption** uses the **same secret key** for both encryption and decryption:

1. **Encryption**: `plaintext + key → ciphertext`
2. **Decryption**: `ciphertext + key → plaintext`

The same secret key is used for both operations, which is why it's called "symmetric."

## Our Implementation: AES-256-GCM

We use **AES-256-GCM** (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode):

- **AES-256**: Industry-standard encryption algorithm with 256-bit keys
- **GCM Mode**: Provides authenticated encryption (confidentiality + integrity)
- **Nonce**: Prevents reuse attacks (same plaintext produces different ciphertext)

### Why AES-256-GCM?

- ✅ **Strong encryption**: AES-256 is considered secure against brute-force attacks
- ✅ **Authenticated**: GCM detects if ciphertext has been tampered with
- ✅ **Nonce-based**: Each encryption uses a random nonce, preventing pattern analysis
- ✅ **Standard**: Widely supported and well-tested

## How We Use It in go-user-management

### 1. Key Derivation

```go
func getOrGenerateStateKey() []byte {
    keyEnv := os.Getenv("OAUTH_STATE_ENCRYPTION_KEY")
    if keyEnv != "" {
        keyHash := sha256.Sum256([]byte(keyEnv))
        return keyHash[:]  // Returns 32 bytes (256 bits)
    }
    // Fallback to default (not secure for production)
}
```

**What happens:**
- Reads `OAUTH_STATE_ENCRYPTION_KEY` from environment variables
- Hashes it with SHA-256 to get exactly 32 bytes (256 bits)
- Ensures consistent key length regardless of input length

**Why SHA-256?**
- Converts any length string → fixed 32-byte key
- Deterministic: same input always produces same key
- One-way: can't reverse hash to get original key

### 2. Encryption Process

```go
func (r *EncryptedStateRepository) encrypt(plaintext []byte) (string, error) {
    // 1. Create AES cipher with our 256-bit key
    block, err := aes.NewCipher(r.key)
    
    // 2. Wrap in GCM mode (adds authentication)
    gcm, err := cipher.NewGCM(block)
    
    // 3. Generate random nonce (prevents reuse attacks)
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    
    // 4. Encrypt: Seal(nonce, nonce, plaintext, additionalData)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    
    // 5. Encode as URL-safe base64 for OAuth state parameter
    return base64.URLEncoding.EncodeToString(ciphertext), nil
}
```

**Step-by-step:**

1. **Create AES cipher**: Initialize AES-256 with our 32-byte key
2. **Wrap in GCM**: GCM mode adds authentication (tamper detection)
3. **Generate nonce**: Random 12-byte nonce (prevents pattern analysis)
4. **Encrypt**: `GCM.Seal()` prepends nonce and encrypts plaintext
5. **Encode**: Base64 URL-safe encoding for use in OAuth URLs

**Output format:**
```
[12-byte nonce][encrypted payload] → base64 encoded
```

### 3. Decryption Process

```go
func (r *EncryptedStateRepository) decrypt(ciphertext string) ([]byte, error) {
    // 1. Decode from base64
    data, err := base64.URLEncoding.DecodeString(ciphertext)
    
    // 2. Create same AES cipher
    block, err := aes.NewCipher(r.key)
    gcm, err := cipher.NewGCM(block)
    
    // 3. Extract nonce from beginning of ciphertext
    nonceSize := gcm.NonceSize()
    nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
    
    // 4. Decrypt and verify authenticity
    plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
    
    return plaintext, nil
}
```

**Step-by-step:**

1. **Decode**: Convert base64 back to bytes
2. **Recreate cipher**: Same AES-GCM cipher with same key
3. **Extract nonce**: First 12 bytes are the nonce
4. **Decrypt**: `GCM.Open()` decrypts and verifies authenticity
   - If tampered: returns error (GCM detects it)
   - If valid: returns original plaintext

## OAuth State Flow

### Step 1: Generate Encrypted State (OAuth Login)

When a user initiates OAuth login (`/api/auth/login`):

```go
// In oauth2.go, GenerateAuthURL()
nonce := GenerateSecureState()  // Random 32-byte nonce
encryptedState := encryptedRepo.GenerateEncryptedState(nonce, redirectURL)
// Returns: base64(encrypted_payload)
```

**Payload structure:**
```json
{
  "timestamp": 1702252800,
  "redirect_url": "https://app.example.com/callback",
  "nonce": "random-secure-nonce-12345"
}
```

This JSON is:
1. Encrypted with AES-256-GCM
2. Base64 URL-encoded
3. Used as OAuth `state` parameter

**Example OAuth URL:**
```
https://cognito-idp.us-east-1.amazonaws.com/oauth2/authorize?
  client_id=xxx&
  redirect_uri=xxx&
  state=xYz9AbC123...  ← Our encrypted state token
```

### Step 2: Validate State (OAuth Callback)

When Cognito redirects back (`/oauth2/idpresponse`):

```go
// In oauth2.go, HandleCallback()
redirectURL, isValid := s.stateRepo.ValidateAndRemoveState(state)
```

**What happens:**

1. **Decrypt**: Decode base64 → decrypt with AES-GCM
2. **Validate timestamp**: Check if state is < 5 minutes old
3. **Check clock skew**: Ensure timestamp isn't in the future
4. **Return redirectURL**: If valid, return the original redirect URL

**Validation logic:**
```go
now := time.Now().Unix()
maxAge := int64(5 * time.Minute / time.Second)

if now - payload.Timestamp > maxAge {
    return "", false  // Expired
}

if payload.Timestamp > now + 60 {
    return "", false  // Clock skew detected
}

return payload.RedirectURL, true  // Valid!
```

## Security Properties

Our implementation provides:

1. **Confidentiality**: Encrypted payload hides `redirectURL` and `nonce`
2. **Integrity**: GCM detects if ciphertext has been tampered with
3. **Freshness**: Timestamp prevents replay attacks (5-minute expiry)
4. **Uniqueness**: Random nonce prevents reuse attacks
5. **Stateless**: No database needed - state is self-contained

## Why This Works for Lambda/Serverless

### Problem with SQLite

SQLite doesn't work well in serverless environments:

- ❌ **Ephemeral instances**: Lambda instances are destroyed after execution
- ❌ **No shared storage**: Multiple Lambda instances can't share SQLite files
- ❌ **Limited /tmp**: Only writable location is `/tmp`, which is cleared between cold starts
- ❌ **Concurrency issues**: SQLite has file locking problems with concurrent access

### Solution: Encrypted State

Our encrypted state approach solves all these problems:

- ✅ **No shared state**: Each Lambda instance can decrypt independently
- ✅ **No database**: State is self-contained in the encrypted token
- ✅ **Scalable**: Works across multiple Lambda instances simultaneously
- ✅ **Fast**: No database lookups - just decrypt and validate

## Complete Example Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User clicks login                                        │
│    → Generate nonce: "abc123..."                           │
│    → Encrypt: {                                             │
│         timestamp: 1702252800,                             │
│         redirectURL: "/dashboard",                         │
│         nonce: "abc123..."                                 │
│       }                                                     │
│    → OAuth state: "xYz9AbC123..." (base64 encrypted blob) │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. User redirected to Cognito                               │
│    → Cognito receives state parameter: "xYz9AbC123..."     │
│    → Cognito stores state temporarily                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Cognito redirects back                                  │
│    → Callback receives same state: "xYz9AbC123..."         │
│    → State parameter passed to HandleCallback()            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Validate state                                           │
│    → Decode base64: "xYz9AbC123..." → bytes                │
│    → Extract nonce: first 12 bytes                          │
│    → Decrypt: bytes → {                                     │
│         timestamp: 1702252800,                             │
│         redirectURL: "/dashboard",                        │
│         nonce: "abc123..."                                 │
│       }                                                     │
│    → Check timestamp: 1702252800 < now < 1702252800 + 300  │
│    → Return redirectURL: "/dashboard"                      │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Required Environment Variable

Set `OAUTH_STATE_ENCRYPTION_KEY` in your environment:

```bash
# Development
export OAUTH_STATE_ENCRYPTION_KEY="my-secret-key-change-in-production"

# Production (recommended: use AWS Secrets Manager or Parameter Store)
export OAUTH_STATE_ENCRYPTION_KEY=$(aws secretsmanager get-secret-value \
  --secret-id oauth-state-encryption-key \
  --query SecretString --output text)
```

### Key Requirements

- **Length**: Any length (will be hashed to 32 bytes)
- **Security**: Use a strong, random secret (32+ bytes recommended)
- **Storage**: Store securely (AWS Secrets Manager, Parameter Store, etc.)
- **Rotation**: Can be rotated by updating env var (existing states will fail, users re-authenticate)

### Default Key (Development Only)

If `OAUTH_STATE_ENCRYPTION_KEY` is not set, a default key is used:

```go
defaultKey := sha256.Sum256([]byte("default-oauth-state-key-change-in-production"))
```

⚠️ **Warning**: The default key is **NOT secure for production**. Always set `OAUTH_STATE_ENCRYPTION_KEY` in production environments.

## Implementation Details

### File Structure

- **`state_encrypted.go`**: Main implementation
  - `EncryptedStateRepository`: State repository interface implementation
  - `encrypt()`: AES-256-GCM encryption
  - `decrypt()`: AES-256-GCM decryption
  - `ValidateAndRemoveState()`: Decrypts and validates state

- **`oauth2.go`**: OAuth2 flow integration
  - `GenerateAuthURL()`: Creates encrypted state token
  - `HandleCallback()`: Validates encrypted state token

### State Payload Structure

```go
type statePayload struct {
    Timestamp   int64  `json:"timestamp"`    // Unix timestamp
    RedirectURL string `json:"redirect_url"` // Where to redirect after auth
    Nonce       string `json:"nonce"`        // Random nonce for uniqueness
}
```

### Encryption Format

```
[12-byte nonce][encrypted JSON payload] → base64 URL-safe encoding
```

- **Nonce**: Random 12 bytes (prepended to ciphertext)
- **Payload**: Encrypted JSON with timestamp, redirectURL, nonce
- **Encoding**: Base64 URL-safe (no padding, safe for URLs)

## Security Considerations

### What's Protected

- ✅ **Redirect URL**: Hidden from attackers
- ✅ **Nonce**: Prevents replay attacks
- ✅ **Timestamp**: Prevents expired state reuse
- ✅ **Tampering**: GCM detects any modifications

### Attack Scenarios

1. **Replay Attack**: Prevented by timestamp (5-minute expiry)
2. **Tampering**: Prevented by GCM authentication
3. **Pattern Analysis**: Prevented by random nonce
4. **Brute Force**: Prevented by AES-256 strength

### Limitations

- **Clock Skew**: States from servers with >60s clock skew will be rejected
- **Key Compromise**: If key is leaked, all states can be decrypted
- **No Revocation**: Can't revoke individual states (expiry handles this)

## Migration from SQLite

### Breaking Changes

- **State Format**: Changed from database lookup to encrypted token
- **Existing States**: SQLite-stored states won't work with encrypted implementation
- **Re-authentication**: Users will need to re-authenticate after migration

### Migration Steps

1. Set `OAUTH_STATE_ENCRYPTION_KEY` environment variable
2. Deploy new code (uses encrypted state by default)
3. Existing OAuth flows will fail gracefully (users re-authenticate)
4. New OAuth flows use encrypted state

### Rollback

If you need to rollback:

1. Remove `OAUTH_STATE_ENCRYPTION_KEY` (falls back to SQLite)
2. Ensure SQLite database is available
3. Deploy previous version

⚠️ **Note**: SQLite fallback was removed in recent versions. Use encrypted state only.

## Testing

### Unit Tests

See `state_encrypted_test.go` for comprehensive test coverage:

- ✅ Encryption/decryption round-trip
- ✅ Expired state rejection
- ✅ Invalid ciphertext rejection
- ✅ Timestamp validation

### Integration Tests

See `routes_integration_test.go` for end-to-end OAuth flow tests.

## References

- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [GCM Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [OAuth 2.0 State Parameter](https://www.rfc-editor.org/rfc/rfc6749#section-10.12)
- [Go crypto/cipher package](https://pkg.go.dev/crypto/cipher)

