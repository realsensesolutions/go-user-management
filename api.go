package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

var oauthConfig *OAuthConfig

func SetOAuthConfig(config *OAuthConfig) {
	oauthConfig = config
}

func GetOAuthConfig() *OAuthConfig {
	return oauthConfig
}

// getRoleAttributeName returns the configured Cognito custom attribute name for user role.
func getRoleAttributeName() string {
	if oauthConfig != nil && oauthConfig.RoleAttributeName != "" {
		return oauthConfig.RoleAttributeName
	}
	return "custom:role"
}

func normalizeCustomAttributeName(name string) string {
	if !strings.HasPrefix(name, "custom:") {
		return "custom:" + name
	}
	return name
}

// normalizeCustomAttributes skips empty values, normalizes keys, dedupes by normalized
// name, and rejects collisions between different raw keys or with the role attribute.
func normalizeCustomAttributes(attrs map[string]string, roleAttrName string) (map[string]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}

	normalized := make(map[string]string)
	rawByNormalized := make(map[string]string)

	keys := make([]string, 0, len(attrs))
	for k, v := range attrs {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, rawKey := range keys {
		val := attrs[rawKey]
		if val == "" {
			continue
		}
		normKey := normalizeCustomAttributeName(rawKey)

		if normKey == roleAttrName {
			return nil, fmt.Errorf("custom attribute %q collides with role attribute %q: %w", rawKey, roleAttrName, ErrInvalidInput)
		}

		if existingVal, exists := normalized[normKey]; exists {
			if existingVal != val {
				return nil, fmt.Errorf("custom attribute keys %q and %q collide on %q with different values: %w", rawByNormalized[normKey], rawKey, normKey, ErrInvalidInput)
			}
			continue
		}

		normalized[normKey] = val
		rawByNormalized[normKey] = rawKey
	}

	return normalized, nil
}

func GetUser(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	cognitoUser, err := cognitoGetUser(ctx, email, oauthConfig)
	if err != nil {
		return nil, err
	}

	return cognitoUserToUser(*cognitoUser)
}

// CreateUser provisions a Cognito user without setting a temporary password.
// Post-create verification and rollback on failure are provided by
// CreateUserWithInvitation only; CreateUser does not verify or roll back.
func CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email is required: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	cognitoUser, err := cognitoCreateUser(ctx, req, oauthConfig)
	if err != nil {
		return nil, err
	}

	return cognitoUserToUser(*cognitoUser)
}

func UpdateProfile(ctx context.Context, email string, update ProfileUpdate) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	attributes := userToCognitoAttributes(nil, &update)
	if len(attributes) == 0 {
		return GetUser(ctx, email)
	}

	err := cognitoUpdateUserAttributes(ctx, email, attributes, oauthConfig)
	if err != nil {
		return nil, err
	}

	return GetUser(ctx, email)
}

func UpdateRole(ctx context.Context, email string, role string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if role == "" {
		return nil, fmt.Errorf("role cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	attributes := []types.AttributeType{
		{
			Name:  aws.String(getRoleAttributeName()),
			Value: aws.String(role),
		},
	}

	if err := cognitoUpdateUserAttributes(ctx, email, attributes, oauthConfig); err != nil {
		return nil, err
	}

	return GetUser(ctx, email)
}

// UpdateTenantID updates the user's custom:tenantId attribute in Cognito.
// This requires the user to logout and login again to get a fresh JWT with the new tenant.
func UpdateTenantID(ctx context.Context, email string, tenantID string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if tenantID == "" {
		return nil, fmt.Errorf("tenantID cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	attributes := []types.AttributeType{
		{
			Name:  aws.String("custom:tenantId"),
			Value: aws.String(tenantID),
		},
	}

	err := cognitoUpdateUserAttributes(ctx, email, attributes, oauthConfig)
	if err != nil {
		return nil, err
	}

	return GetUser(ctx, email)
}

// DisableUser disables a user account in Cognito.
func DisableUser(ctx context.Context, email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return fmt.Errorf("oauth config is not set")
	}

	return cognitoDisableUser(ctx, email, oauthConfig)
}

// EnableUser re-enables a disabled user account in Cognito.
func EnableUser(ctx context.Context, email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return fmt.Errorf("oauth config is not set")
	}

	return cognitoEnableUser(ctx, email, oauthConfig)
}

// UpdateServiceProviderID updates the user's custom:serviceProviderId attribute in Cognito.
func UpdateServiceProviderID(ctx context.Context, email string, serviceProviderID string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if serviceProviderID == "" {
		return nil, fmt.Errorf("serviceProviderID cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	attributes := []types.AttributeType{
		{
			Name:  aws.String("custom:serviceProviderId"),
			Value: aws.String(serviceProviderID),
		},
	}

	err := cognitoUpdateUserAttributes(ctx, email, attributes, oauthConfig)
	if err != nil {
		return nil, err
	}

	return GetUser(ctx, email)
}

// SetUserPassword sets a user's password in Cognito.
// If permanent is false, the user must change it on next login (FORCE_CHANGE_PASSWORD state).
func SetUserPassword(ctx context.Context, email string, password string, permanent bool) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return fmt.Errorf("oauth config is not set")
	}

	return cognitoSetUserPassword(ctx, email, password, permanent, oauthConfig)
}

func DeleteUser(ctx context.Context, email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return fmt.Errorf("oauth config is not set")
	}

	return cognitoDeleteUser(ctx, email, oauthConfig)
}

func ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 60 {
		limit = 60
	}
	if offset < 0 {
		offset = 0
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	var allUsers []types.UserType
	var paginationToken *string
	limit32 := int32(limit + offset)

	for {
		users, nextToken, err := cognitoListUsers(ctx, limit32, paginationToken, oauthConfig)
		if err != nil {
			return nil, err
		}

		allUsers = append(allUsers, users...)

		if nextToken == nil || len(allUsers) >= limit+offset {
			break
		}

		paginationToken = nextToken
	}

	if offset > 0 && len(allUsers) > offset {
		allUsers = allUsers[offset:]
	}
	if len(allUsers) > limit {
		allUsers = allUsers[:limit]
	}

	result := make([]*User, 0, len(allUsers))
	for _, cognitoUser := range allUsers {
		user, err := cognitoUserToUser(cognitoUser)
		if err != nil {
			continue
		}
		result = append(result, user)
	}

	return result, nil
}

func GenerateAPIKey(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	apiKey := generateSecureAPIKey()
	err := UpdateAPIKey(ctx, email, apiKey)
	if err != nil {
		return "", err
	}

	return apiKey, nil
}

func GetAPIKey(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	user, err := GetUser(ctx, email)
	if err != nil {
		return "", err
	}

	return user.APIKey, nil
}

func RotateAPIKey(ctx context.Context, email string) (string, error) {
	return GenerateAPIKey(ctx, email)
}

func UpdateAPIKey(ctx context.Context, email string, apiKey string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if apiKey == "" {
		return fmt.Errorf("apiKey cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return fmt.Errorf("oauth config is not set")
	}

	attrName := tokenAttributeName
	if !strings.HasPrefix(attrName, "custom:") {
		attrName = "custom:" + attrName
	}

	attributes := []types.AttributeType{
		{
			Name:  aws.String(attrName),
			Value: aws.String(apiKey),
		},
	}

	return cognitoUpdateUserAttributes(ctx, email, attributes, oauthConfig)
}

func ValidateAPIKey(ctx context.Context, apiKey string) (*User, error) {
	if apiKey == "" {
		return nil, ErrInvalidAPIKey
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is not set")
	}

	filter := fmt.Sprintf("%s = \"%s\"", tokenAttributeName, apiKey)
	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(oauthConfig.UserPoolID),
		Filter:     aws.String(filter),
		Limit:      aws.Int32(2),
	}

	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return nil, err
	}

	result, err := client.ListUsers(ctx, input)
	if err != nil {
		return nil, wrapCognitoError(err, "ListUsers")
	}

	if len(result.Users) == 0 {
		return nil, ErrInvalidAPIKey
	}

	if len(result.Users) > 1 {
		return nil, fmt.Errorf("multiple users found with same API key")
	}

	return cognitoUserToUser(result.Users[0])
}

func FindUserByToken(ctx context.Context, token string) (*Claims, error) {
	return FindUserClaimsByToken(ctx, token, oauthConfig)
}

func CreateUserWithInvitation(ctx context.Context, req CreateUserRequest) (*User, string, error) {
	if req.Email == "" {
		return nil, "", fmt.Errorf("email is required: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return nil, "", fmt.Errorf("oauth config is not set")
	}

	_, err := cognitoCreateUser(ctx, req, oauthConfig)
	if err != nil {
		return nil, "", err
	}

	rollback := func() {
		if delErr := cognitoDeleteUser(ctx, req.Email, oauthConfig); delErr != nil {
			log.Printf("⚠️ [Cognito] rollback AdminDeleteUser failed for %s: %v", req.Email, delErr)
		}
	}

	tempPassword, err := generateSecureTemporaryPassword()
	if err != nil {
		rollback()
		return nil, "", fmt.Errorf("failed to generate temporary password: %w", err)
	}

	err = cognitoSetTemporaryPassword(ctx, req.Email, tempPassword, oauthConfig)
	if err != nil {
		rollback()
		return nil, "", fmt.Errorf("failed to set temporary password: %w", err)
	}

	verifiedUser, err := cognitoGetUser(ctx, req.Email, oauthConfig)
	if err != nil {
		rollback()
		return nil, "", fmt.Errorf("failed to verify user after provisioning: %w", err)
	}

	if err := assertRequiredCustomAttributes(verifiedUser, req); err != nil {
		rollback()
		return nil, "", fmt.Errorf("provisioning verification: %w", err)
	}

	user, err := cognitoUserToUser(*verifiedUser)
	if err != nil {
		rollback()
		return nil, "", fmt.Errorf("failed to convert verified user: %w", err)
	}

	return user, tempPassword, nil
}

func assertRequiredCustomAttributes(cognitoUser *types.UserType, req CreateUserRequest) error {
	if cognitoUser == nil {
		return fmt.Errorf("provisioning verification failed: user is nil")
	}

	attrs := make(map[string]string, len(cognitoUser.Attributes))
	for _, attr := range cognitoUser.Attributes {
		if attr.Name != nil && attr.Value != nil {
			attrs[*attr.Name] = *attr.Value
		}
	}

	roleAttr := getRoleAttributeName()
	expectedRole := req.Role
	if expectedRole == "" {
		expectedRole = "user"
	}
	if got, ok := attrs[roleAttr]; !ok || got != expectedRole {
		return fmt.Errorf("provisioning verification failed: missing or incorrect %s", roleAttr)
	}

	if len(req.CustomAttributes) > 0 {
		normAttrs, err := normalizeCustomAttributes(req.CustomAttributes, roleAttr)
		if err != nil {
			return fmt.Errorf("provisioning verification failed: %w", err)
		}
		keys := make([]string, 0, len(normAttrs))
		for k := range normAttrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, attrName := range keys {
			expected := normAttrs[attrName]
			if got, ok := attrs[attrName]; !ok || got != expected {
				return fmt.Errorf("provisioning verification failed: missing or incorrect %s", attrName)
			}
		}
	}

	return nil
}

// ResetTemporaryPassword generates a new temporary password for an existing Cognito user.
// This is useful for resending invitation emails — the user must still change the password on first login.
func ResetTemporaryPassword(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("email cannot be empty: %w", ErrInvalidInput)
	}

	if oauthConfig == nil {
		return "", fmt.Errorf("oauth config is not set")
	}

	tempPassword, err := generateSecureTemporaryPassword()
	if err != nil {
		return "", fmt.Errorf("failed to generate temporary password: %w", err)
	}

	err = cognitoSetTemporaryPassword(ctx, email, tempPassword, oauthConfig)
	if err != nil {
		return "", fmt.Errorf("failed to set temporary password: %w", err)
	}

	return tempPassword, nil
}

func generateSecureAPIKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate secure random bytes: %v", err))
	}

	return fmt.Sprintf("usr_%s", hex.EncodeToString(bytes))
}
