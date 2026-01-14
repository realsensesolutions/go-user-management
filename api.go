package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
			Name:  aws.String("custom:role"),
			Value: aws.String(role),
		},
	}

	err := cognitoUpdateUserAttributes(ctx, email, attributes, oauthConfig)
	if err != nil {
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

	cognitoUser, err := cognitoCreateUser(ctx, req, oauthConfig)
	if err != nil {
		return nil, "", err
	}

	tempPassword, err := generateSecureTemporaryPassword()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate temporary password: %w", err)
	}

	err = cognitoSetTemporaryPassword(ctx, req.Email, tempPassword, oauthConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to set temporary password: %w", err)
	}

	user, err := cognitoUserToUser(*cognitoUser)
	if err != nil {
		return nil, "", err
	}

	return user, tempPassword, nil
}

func generateSecureAPIKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate secure random bytes: %v", err))
	}

	return fmt.Sprintf("usr_%s", hex.EncodeToString(bytes))
}
