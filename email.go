package user

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

// SESClient interface for SES operations (exported for testing)
type SESClient interface {
	SendEmail(ctx context.Context, params *ses.SendEmailInput, optFns ...func(*ses.Options)) (*ses.SendEmailOutput, error)
}

var sesClientFactory func(ctx context.Context, cfg aws.Config) SESClient = defaultSESClientFactory

func defaultSESClientFactory(ctx context.Context, cfg aws.Config) SESClient {
	return ses.NewFromConfig(cfg)
}

// SetSESClientFactory allows overriding the SES client factory (for testing).
func SetSESClientFactory(factory func(ctx context.Context, cfg aws.Config) SESClient) {
	sesClientFactory = factory
}

// ResetSESClientFactory restores the default SES client factory.
func ResetSESClientFactory() {
	sesClientFactory = defaultSESClientFactory
}

// InvitationEmailRequest contains the data needed to send an invitation email.
type InvitationEmailRequest struct {
	Email        string
	Username     string
	TempPassword string
	Role         string
	LoginURL     string
	AppName      string // Populated from OAuthConfig
}

// SendInvitationEmail sends an email with login credentials to a newly invited user.
func SendInvitationEmail(ctx context.Context, req InvitationEmailRequest) error {
	oauthConfig := GetOAuthConfig()
	if oauthConfig == nil {
		return fmt.Errorf("OAuth config not set")
	}

	if oauthConfig.FromEmail == "" {
		return fmt.Errorf("FromEmail not configured - cannot send invitation email")
	}

	region := oauthConfig.SESRegion
	if region == "" {
		region = oauthConfig.Region
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion(region),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := sesClientFactory(ctx, cfg)

	if req.AppName == "" {
		req.AppName = oauthConfig.AppName
	}
	subject := fmt.Sprintf("Your %s Account Credentials", req.AppName)
	htmlBody := generateInvitationHTML(req)
	textBody := generateInvitationText(req)

	input := &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{req.Email},
		},
		Message: &types.Message{
			Subject: &types.Content{
				Data:    aws.String(subject),
				Charset: aws.String("UTF-8"),
			},
			Body: &types.Body{
				Html: &types.Content{
					Data:    aws.String(htmlBody),
					Charset: aws.String("UTF-8"),
				},
				Text: &types.Content{
					Data:    aws.String(textBody),
					Charset: aws.String("UTF-8"),
				},
			},
		},
		Source: aws.String(oauthConfig.FromEmail),
	}

	_, err = client.SendEmail(ctx, input)
	if err != nil {
		log.Printf("[go-user-management] Failed to send invitation email to %s: %v", req.Email, err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("[go-user-management] Invitation email sent to %s", req.Email)
	return nil
}
