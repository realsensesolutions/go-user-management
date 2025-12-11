package user

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

func getCognitoClient(ctx context.Context, oauthConfig *OAuthConfig) (CognitoClient, error) {
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

	return cognitoClientFactory(ctx, cfg, oauthConfig.UserPoolID), nil
}

func cognitoGetUser(ctx context.Context, email string, oauthConfig *OAuthConfig) (*types.UserType, error) {
	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return nil, err
	}

	input := &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(oauthConfig.UserPoolID),
		Username:   aws.String(email),
	}

	result, err := client.AdminGetUser(ctx, input)
	if err != nil {
		return nil, wrapCognitoError(err, "AdminGetUser")
	}

	user := &types.UserType{
		Username:   result.Username,
		Attributes: result.UserAttributes,
		UserStatus: result.UserStatus,
		Enabled:    result.Enabled,
	}

	return user, nil
}

func cognitoCreateUser(ctx context.Context, req CreateUserRequest, oauthConfig *OAuthConfig) (*types.UserType, error) {
	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return nil, err
	}

	attributes := []types.AttributeType{
		{
			Name:  aws.String("email"),
			Value: aws.String(req.Email),
		},
		{
			Name:  aws.String("email_verified"),
			Value: aws.String("true"),
		},
	}

	if req.GivenName != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("given_name"),
			Value: aws.String(req.GivenName),
		})
	}

	if req.FamilyName != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("family_name"),
			Value: aws.String(req.FamilyName),
		})
	}

	if req.Picture != "" {
		attributes = append(attributes, types.AttributeType{
			Name:  aws.String("picture"),
			Value: aws.String(req.Picture),
		})
	}

	role := req.Role
	if role == "" {
		role = "user"
	}
	attributes = append(attributes, types.AttributeType{
		Name:  aws.String("custom:role"),
		Value: aws.String(role),
	})

	input := &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId:     aws.String(oauthConfig.UserPoolID),
		Username:       aws.String(req.Email),
		UserAttributes: attributes,
		MessageAction:  types.MessageActionTypeSuppress,
	}

	result, err := client.AdminCreateUser(ctx, input)
	if err != nil {
		return nil, wrapCognitoError(err, "AdminCreateUser")
	}

	return result.User, nil
}

func cognitoSetTemporaryPassword(ctx context.Context, email, password string, oauthConfig *OAuthConfig) error {
	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return err
	}

	input := &cognitoidentityprovider.AdminSetUserPasswordInput{
		UserPoolId: aws.String(oauthConfig.UserPoolID),
		Username:   aws.String(email),
		Password:   aws.String(password),
		Permanent:  false,
	}

	_, err = client.AdminSetUserPassword(ctx, input)
	if err != nil {
		return wrapCognitoError(err, "AdminSetUserPassword")
	}

	return nil
}

func cognitoUpdateUserAttributes(ctx context.Context, email string, attributes []types.AttributeType, oauthConfig *OAuthConfig) error {
	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return err
	}

	if len(attributes) == 0 {
		return nil
	}

	input := &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId:     aws.String(oauthConfig.UserPoolID),
		Username:       aws.String(email),
		UserAttributes: attributes,
	}

	_, err = client.AdminUpdateUserAttributes(ctx, input)
	if err != nil {
		return wrapCognitoError(err, "AdminUpdateUserAttributes")
	}

	return nil
}

func cognitoDeleteUser(ctx context.Context, email string, oauthConfig *OAuthConfig) error {
	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return err
	}

	input := &cognitoidentityprovider.AdminDeleteUserInput{
		UserPoolId: aws.String(oauthConfig.UserPoolID),
		Username:   aws.String(email),
	}

	_, err = client.AdminDeleteUser(ctx, input)
	if err != nil {
		return wrapCognitoError(err, "AdminDeleteUser")
	}

	return nil
}

func cognitoListUsers(ctx context.Context, limit int32, paginationToken *string, oauthConfig *OAuthConfig) ([]types.UserType, *string, error) {
	client, err := getCognitoClient(ctx, oauthConfig)
	if err != nil {
		return nil, nil, err
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 60 {
		limit = 60
	}

	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(oauthConfig.UserPoolID),
		Limit:      aws.Int32(limit),
	}

	if paginationToken != nil {
		input.PaginationToken = paginationToken
	}

	result, err := client.ListUsers(ctx, input)
	if err != nil {
		return nil, nil, wrapCognitoError(err, "ListUsers")
	}

	return result.Users, result.PaginationToken, nil
}

func cognitoUserToUser(cognitoUser types.UserType) (*User, error) {
	user := &User{}

	for _, attr := range cognitoUser.Attributes {
		switch *attr.Name {
		case "email":
			user.Email = *attr.Value
		case "given_name":
			user.GivenName = *attr.Value
		case "family_name":
			user.FamilyName = *attr.Value
		case "picture":
			user.Picture = *attr.Value
		case "custom:role":
			user.Role = *attr.Value
		case "custom:apiKey", "custom:api_key":
			user.APIKey = *attr.Value
		}
	}

	if user.Email == "" {
		if cognitoUser.Username != nil {
			user.Email = *cognitoUser.Username
		} else {
			return nil, fmt.Errorf("user has no email attribute")
		}
	}

	if user.Role == "" {
		user.Role = "user"
	}

	return user, nil
}

func userToCognitoAttributes(user *User, update *ProfileUpdate) []types.AttributeType {
	attributes := []types.AttributeType{}

	if update != nil {
		if update.GivenName != nil {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("given_name"),
				Value: aws.String(*update.GivenName),
			})
		}
		if update.FamilyName != nil {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("family_name"),
				Value: aws.String(*update.FamilyName),
			})
		}
		if update.Picture != nil {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("picture"),
				Value: aws.String(*update.Picture),
			})
		}
	} else if user != nil {
		if user.GivenName != "" {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("given_name"),
				Value: aws.String(user.GivenName),
			})
		}
		if user.FamilyName != "" {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("family_name"),
				Value: aws.String(user.FamilyName),
			})
		}
		if user.Picture != "" {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("picture"),
				Value: aws.String(user.Picture),
			})
		}
	}

	return attributes
}

func wrapCognitoError(err error, operation string) error {
	log.Printf("❌ [Cognito] %s failed: %v", operation, err)

	if err != nil {
		if strings.Contains(err.Error(), "UserNotFoundException") || strings.Contains(err.Error(), "does not exist") {
			return fmt.Errorf("%s: %w", operation, ErrUserNotFound)
		}
		if strings.Contains(err.Error(), "UsernameExistsException") || strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("%s: %w", operation, ErrUserAlreadyExists)
		}
		if strings.Contains(err.Error(), "InvalidParameterException") {
			return fmt.Errorf("%s: %w", operation, ErrInvalidInput)
		}
	}

	return fmt.Errorf("%s: %w", operation, err)
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UserNotFoundException") ||
		strings.Contains(err.Error(), "does not exist") ||
		err == ErrUserNotFound
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UsernameExistsException") ||
		strings.Contains(err.Error(), "already exists") ||
		err == ErrUserAlreadyExists
}
