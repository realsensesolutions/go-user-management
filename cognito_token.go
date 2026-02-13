package user

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// CognitoClient interface for Cognito operations (exported for testing)
type CognitoClient interface {
	ListUsers(ctx context.Context, params *cognitoidentityprovider.ListUsersInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUsersOutput, error)
	AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error)
	AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error)
	AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error)
	AdminDeleteUser(ctx context.Context, params *cognitoidentityprovider.AdminDeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDeleteUserOutput, error)
	AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error)
}

var (
	cognitoClientFactory func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient = defaultCognitoClientFactory
)

func defaultCognitoClientFactory(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient {
	return cognitoidentityprovider.NewFromConfig(cfg)
}

func ResetCognitoClientFactory() {
	cognitoClientFactory = defaultCognitoClientFactory
}

func SetCognitoClientFactory(factory func(ctx context.Context, cfg aws.Config, userPoolID string) CognitoClient) {
	cognitoClientFactory = factory
}

const (
	defaultTokenAttributeName = "custom:apiKey"
)

var (
	tokenAttributeName = defaultTokenAttributeName
)

func SetTokenAttributeName(name string) {
	tokenAttributeName = name
}

func GetTokenAttributeName() string {
	return tokenAttributeName
}

func FindUserClaimsByToken(ctx context.Context, token string, oauthConfig *OAuthConfig) (*Claims, error) {
	if token == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	if oauthConfig == nil {
		return nil, fmt.Errorf("oauth config is required")
	}

	if oauthConfig.UserPoolID == "" {
		return nil, fmt.Errorf("userPoolID is required")
	}

	if oauthConfig.Region == "" {
		return nil, fmt.Errorf("region is required")
	}

	cfg, err := loadAWSConfig(ctx, oauthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := cognitoClientFactory(ctx, cfg, oauthConfig.UserPoolID)

	filter := fmt.Sprintf("%s = \"%s\"", tokenAttributeName, token)
	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(oauthConfig.UserPoolID),
		Filter:     aws.String(filter),
		Limit:      aws.Int32(2),
	}

	result, err := client.ListUsers(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query Cognito users: %w", err)
	}

	if len(result.Users) == 0 {
		return nil, fmt.Errorf("no user found with token")
	}

	if len(result.Users) > 1 {
		return nil, fmt.Errorf("multiple users found with same token")
	}

	user := result.Users[0]
	claims, err := cognitoUserToClaims(user, oauthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Cognito user to claims: %w", err)
	}

	return claims, nil
}

func cognitoUserToClaims(cognitoUser types.UserType, oauthConfig *OAuthConfig) (*Claims, error) {
	claims := &Claims{
		Provider: "token",
	}

	var username string
	email := ""
	givenName := ""
	familyName := ""
	picture := ""
	apiKey := ""
	role := ""
	userRole := ""

	for _, attr := range cognitoUser.Attributes {
		switch *attr.Name {
		case "sub":
			claims.Sub = *attr.Value
		case "email":
			email = *attr.Value
			claims.Email = email
		case "given_name":
			givenName = *attr.Value
			claims.GivenName = givenName
		case "family_name":
			familyName = *attr.Value
			claims.FamilyName = familyName
		case "picture":
			picture = *attr.Value
			claims.Picture = picture
		case "custom:apiKey", "custom:api_key":
			apiKey = *attr.Value
			claims.APIKey = apiKey
		case "custom:role":
			role = *attr.Value
			claims.Role = role
		case "custom:userRole":
			userRole = *attr.Value
			claims.UserRole = userRole
		case "custom:tenantId":
			claims.TenantID = *attr.Value
		case "custom:serviceProviderId":
			claims.ServiceProviderID = *attr.Value
		}
	}

	if cognitoUser.Username != nil {
		username = *cognitoUser.Username
		claims.Username = username
	} else if email != "" {
		claims.Username = email
	} else {
		return nil, fmt.Errorf("user has no username or email")
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("user has no email attribute")
	}

	// Before existing fallback: promote UserRole to Role if Role is empty
	if claims.Role == "" && claims.UserRole != "" {
		claims.Role = claims.UserRole
	}

	if claims.Role == "" {
		defaultRole := "user"
		if oauthConfig.CalculateDefaultRole != nil {
			oidcClaims := &OIDCClaims{
				Email:      claims.Email,
				GivenName:  claims.GivenName,
				FamilyName: claims.FamilyName,
				Username:   claims.Username,
			}
			defaultRole = oauthConfig.CalculateDefaultRole(oidcClaims)
		}
		claims.Role = defaultRole
	}

	return claims, nil
}

const jwtContextKey contextKey = "raw_jwt_token"

// ContextWithJWT returns a new context with the JWT token stored for STS credential exchange.
func ContextWithJWT(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, jwtContextKey, token)
}

// JWTFromContext returns the JWT token stored in the context, if any.
func JWTFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(jwtContextKey).(string); ok {
		return token
	}
	return ""
}

// WithUserAWSCredentials extracts JWT from request and returns a context that will use STS credentials for AWS operations. Use this when the operation should run with the user's permissions.
func WithUserAWSCredentials(r *http.Request) context.Context {
	ctx := r.Context()

	// Try JWT cookie first
	if cookie, err := r.Cookie("jwt"); err == nil && cookie.Value != "" {
		return ContextWithJWT(ctx, cookie.Value)
	}

	// Try Authorization Bearer header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return ContextWithJWT(ctx, token)
	}

	return ctx
}

func loadAWSConfig(ctx context.Context, oauthConfig *OAuthConfig) (aws.Config, error) {
	if oauthConfig.Region == "" {
		return aws.Config{}, fmt.Errorf("region is required")
	}

	if token := JWTFromContext(ctx); token != "" {
		stsCreds, err := GetSTSCredentials(ctx, token, oauthConfig)
		if err != nil {
			log.Printf("[loadAWSConfig] STS credential exchange failed, falling back to default chain: %v", err)
		} else {
			return config.LoadDefaultConfig(ctx,
				config.WithRegion(oauthConfig.Region),
				config.WithCredentialsProvider(
					credentials.NewStaticCredentialsProvider(
						stsCreds.AccessKeyID,
						stsCreds.SecretAccessKey,
						stsCreds.SessionToken,
					),
				),
			)
		}
	}

	return config.LoadDefaultConfig(ctx, config.WithRegion(oauthConfig.Region))
}

func UpdateCognitoUserAttributesFromClaims(ctx context.Context, username string, claims *Claims, oauthConfig *OAuthConfig) error {
	if oauthConfig == nil {
		return fmt.Errorf("oauth config is required")
	}

	if oauthConfig.UserPoolID == "" {
		return fmt.Errorf("userPoolID is required")
	}

	if oauthConfig.Region == "" {
		return fmt.Errorf("region is required")
	}

	cfg, err := loadAWSConfig(ctx, oauthConfig)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := cognitoClientFactory(ctx, cfg, oauthConfig.UserPoolID)

	attributes := []types.AttributeType{}

	if claims.GivenName != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("given_name"),
			Value: aws.String(claims.GivenName),
		})
	}

	if claims.FamilyName != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("family_name"),
			Value: aws.String(claims.FamilyName),
		})
	}

	if claims.Picture != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("picture"),
			Value: aws.String(claims.Picture),
		})
	}

	roleValue := claims.UserRole
	if roleValue == "" {
		roleValue = claims.Role
	}
	if roleValue != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String(getRoleAttributeName()),
			Value: aws.String(roleValue),
		})
	}

	if claims.APIKey != "" {
		attrName := tokenAttributeName
		if !strings.HasPrefix(attrName, "custom:") {
			attrName = "custom:" + attrName
		}
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String(attrName),
			Value: aws.String(claims.APIKey),
		})
	}

	if len(attributes) == 0 {
		return nil
	}

	input := &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId:     aws.String(oauthConfig.UserPoolID),
		Username:       aws.String(username),
		UserAttributes: attributes,
	}

	_, err = client.AdminUpdateUserAttributes(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update Cognito user attributes: %w", err)
	}

	return nil
}
