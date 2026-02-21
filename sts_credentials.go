package user

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSClient interface for STS operations (exported for testing)
type STSClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

var (
	stsClientFactory func(ctx context.Context, cfg aws.Config) STSClient = defaultSTSClientFactory
)

func defaultSTSClientFactory(ctx context.Context, cfg aws.Config) STSClient {
	return sts.NewFromConfig(cfg)
}

func ResetSTSClientFactory() {
	stsClientFactory = defaultSTSClientFactory
}

func SetSTSClientFactory(factory func(ctx context.Context, cfg aws.Config) STSClient) {
	stsClientFactory = factory
}

// GetSTSCredentials exchanges a Cognito ID token for temporary AWS credentials using STS AssumeRoleWithWebIdentity.
// The role is determined dynamically from the cognito:preferred_role claim in the token,
// with fallback to the configured STSRoleARN if no role claim is present.
// Credentials are cached in-memory to avoid redundant STS calls within the same Lambda instance.
func GetSTSCredentials(ctx context.Context, idToken string, oauthConfig *OAuthConfig) (*STSCredentials, error) {
	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	if idToken == "" {
		return nil, fmt.Errorf("ID token is required")
	}

	tokenHash := hashToken(idToken)
	if cached := getCachedCredentials(tokenHash); cached != nil {
		return cached, nil
	}

	// Parse the JWT to extract claims
	claims, err := parseTokenClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// Determine role ARN: prefer token claim, fallback to config
	roleARN := selectRoleARN(claims, oauthConfig)
	if roleARN == "" {
		return nil, fmt.Errorf("no role ARN available: neither cognito:preferred_role in token nor STSRoleARN configured")
	}

	// Validate the selected role is in the allowed roles (if roles claim exists)
	if len(claims.Roles) > 0 && !isRoleAllowed(roleARN, claims.Roles) {
		return nil, fmt.Errorf("role %s is not in the allowed roles from token", roleARN)
	}

	// Create STS client with anonymous credentials
	// AssumeRoleWithWebIdentity authenticates via the web identity token (JWT), not AWS signature
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(oauthConfig.Region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	stsClient := stsClientFactory(ctx, cfg)

	// Build session name
	sessionName := buildSessionName(claims, oauthConfig)

	// Set duration (default 1 hour)
	duration := oauthConfig.STSDurationSeconds
	if duration == 0 {
		duration = 3600
	}

	// Call STS AssumeRoleWithWebIdentity with the dynamic role
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(idToken),
		DurationSeconds:  aws.Int32(duration),
	}

	result, err := stsClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role with web identity: %w", err)
	}

	if result.Credentials == nil {
		return nil, fmt.Errorf("STS returned no credentials")
	}

	creds := &STSCredentials{
		AccessKeyID:     aws.ToString(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(result.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(result.Credentials.SessionToken),
		Expiration:      aws.ToTime(result.Credentials.Expiration),
	}

	setCachedCredentials(tokenHash, creds)

	return creds, nil
}

// selectRoleARN determines which role ARN to use for STS.
// Priority: 1) cognito:preferred_role from token, 2) first role in cognito:roles, 3) STSRoleARN from config
func selectRoleARN(claims *OIDCClaims, oauthConfig *OAuthConfig) string {
	// First priority: preferred_role from token (set by Cognito based on group precedence)
	if claims != nil && claims.PreferredRole != "" {
		return claims.PreferredRole
	}

	// Second priority: first role from cognito:roles if available
	if claims != nil && len(claims.Roles) > 0 {
		return claims.Roles[0]
	}

	// Fallback: configured role ARN
	return oauthConfig.STSRoleARN
}

// isRoleAllowed checks if the roleARN is in the list of allowed roles from the token.
func isRoleAllowed(roleARN string, allowedRoles []string) bool {
	for _, allowed := range allowedRoles {
		if allowed == roleARN {
			return true
		}
	}
	return false
}

// buildSessionName creates a session name from token claims and config.
func buildSessionName(claims *OIDCClaims, oauthConfig *OAuthConfig) string {
	sessionName := oauthConfig.STSSessionName
	if sessionName == "" {
		sessionName = "user-session"
	}

	// Add email if available
	if claims != nil && claims.Email != "" {
		sanitized := sanitizeSessionName(claims.Email)
		if sanitized != "" {
			sessionName = fmt.Sprintf("%s-%s", sessionName, sanitized)
		}
	}

	// Truncate to max 64 characters (AWS limit)
	if len(sessionName) > 64 {
		sessionName = sessionName[:64]
	}

	return sessionName
}

// sanitizeSessionName removes characters not allowed in AWS session names.
func sanitizeSessionName(s string) string {
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '=' || r == '.' || r == '@' || r == '-' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// parseTokenClaims extracts claims from a JWT without validation (STS validates the token).
func parseTokenClaims(token string) (*OIDCClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode payload (second part)
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims OIDCClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	return &claims, nil
}
