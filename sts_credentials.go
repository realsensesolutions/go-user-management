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

// GetSTSCredentials exchanges a Cognito ID token for temporary AWS credentials using STS AssumeRoleWithWebIdentity.
func GetSTSCredentials(ctx context.Context, idToken string, oauthConfig *OAuthConfig) (*STSCredentials, error) {
	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	if oauthConfig.STSRoleARN == "" {
		return nil, fmt.Errorf("STS role ARN is not configured")
	}

	if idToken == "" {
		return nil, fmt.Errorf("ID token is required")
	}

	// Create STS client
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(oauthConfig.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	// Build session name from token or use default
	sessionName := oauthConfig.STSSessionName
	if sessionName == "" {
		sessionName = "user-session"
	}

	// Extract email from token for session name (best effort, not required)
	claims, err := parseTokenClaims(idToken)
	if err == nil && claims.Email != "" {
		// Sanitize email for session name (only alphanumeric, =, ., @, -)
		sanitized := sanitizeSessionName(claims.Email)
		if sanitized != "" {
			sessionName = fmt.Sprintf("%s-%s", sessionName, sanitized)
		}
	}

	// Truncate session name to max 64 characters (AWS limit)
	if len(sessionName) > 64 {
		sessionName = sessionName[:64]
	}

	// Set duration (default 1 hour)
	duration := oauthConfig.STSDurationSeconds
	if duration == 0 {
		duration = 3600
	}

	// Call STS AssumeRoleWithWebIdentity
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(oauthConfig.STSRoleARN),
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

	return &STSCredentials{
		AccessKeyID:     aws.ToString(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(result.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(result.Credentials.SessionToken),
		Expiration:      aws.ToTime(result.Credentials.Expiration),
	}, nil
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
