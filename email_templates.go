package user

import (
	"fmt"
	"html"
)

// generateInvitationHTML generates the HTML email body for invitation emails.
func generateInvitationHTML(req InvitationEmailRequest) string {
	loginURL := req.LoginURL
	if loginURL == "" {
		loginURL = "#"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Your Account Credentials</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f4;">
	<table role="presentation" style="width: 100%%; border-collapse: collapse;">
		<tr>
			<td align="center" style="padding: 40px 0;">
				<table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
					<tr>
						<td style="padding: 40px 40px 20px; text-align: center; background-color: #3B82F6; border-radius: 8px 8px 0 0;">
							<h1 style="margin: 0; color: #ffffff; font-size: 24px;">Welcome to %s</h1>
						</td>
					</tr>
					<tr>
						<td style="padding: 30px 40px;">
							<p style="margin: 0 0 20px; font-size: 16px; line-height: 1.5; color: #333333;">
								An account has been created for you. Use the credentials below to sign in.
							</p>
							<table role="presentation" style="width: 100%%; border-collapse: collapse; margin: 20px 0; background-color: #f8f9fa; border-radius: 6px;">
								<tr>
									<td style="padding: 20px;">
										<table role="presentation" style="width: 100%%; border-collapse: collapse;">
											<tr>
												<td style="padding: 10px 0; border-bottom: 1px solid #eee;">
													<strong>Username:</strong> %s
												</td>
											</tr>
											<tr>
												<td style="padding: 10px 0; border-bottom: 1px solid #eee;">
													<strong>Temporary Password:</strong> %s
												</td>
											</tr>
											<tr>
												<td style="padding: 10px 0;">
													<strong>Role:</strong> %s
												</td>
											</tr>
										</table>
									</td>
								</tr>
							</table>
							<table role="presentation" style="width: 100%%; border-collapse: collapse; margin: 30px 0;">
								<tr>
									<td align="center">
										<a href="%s" style="display: inline-block; padding: 16px 40px; background-color: #3B82F6; color: #ffffff; text-decoration: none; font-weight: bold; border-radius: 6px; font-size: 16px;">
											Sign In
										</a>
									</td>
								</tr>
							</table>
							<div style="margin-top: 30px; padding: 15px; background-color: #FEF3C7; border-radius: 6px; border-left: 4px solid #F59E0B;">
								<p style="margin: 0; font-size: 14px; color: #92400E;">
									<strong>Important:</strong> You will be asked to change your password on first sign-in.
								</p>
							</div>
						</td>
					</tr>
					<tr>
						<td style="padding: 20px 40px; text-align: center; background-color: #f8f9fa; border-radius: 0 0 8px 8px;">
							<p style="margin: 0; font-size: 12px; color: #666666;">
								If the button doesn't work, copy and paste this link: %s
							</p>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</body>
</html>`,
		html.EscapeString(req.AppName),
		html.EscapeString(req.Username),
		html.EscapeString(req.TempPassword),
		html.EscapeString(req.Role),
		html.EscapeString(loginURL),
		html.EscapeString(loginURL),
	)
}

// generateInvitationText generates the plain text email body for invitation emails.
func generateInvitationText(req InvitationEmailRequest) string {
	loginURL := req.LoginURL
	if loginURL == "" {
		loginURL = "(not configured)"
	}

	return fmt.Sprintf(`Welcome to %s!

An account has been created for you. Use the credentials below to sign in.

Username: %s
Temporary Password: %s
Role: %s

Sign in at: %s

IMPORTANT: You will be asked to change your password on first sign-in.

If you did not expect this email, please contact your administrator.
`,
		req.AppName,
		req.Username,
		req.TempPassword,
		req.Role,
		loginURL,
	)
}
