module github.com/realsensesolutions/go-user-management

go 1.23.0

toolchain go1.24.5

require (
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.32.5
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.57.17
	github.com/aws/aws-sdk-go-v2/service/ses v1.34.18
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.5
	github.com/coreos/go-oidc/v3 v3.11.0
	github.com/go-chi/chi/v5 v5.2.2
	golang.org/x/oauth2 v0.24.0
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.5 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.16 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.12 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/crypto v0.27.0 // indirect
)

// Use released go-database package
// replace github.com/realsensesolutions/go-database => ../../infrastructure/go-database
