package user

import (
	"fmt"
	"log"
)

// CreateJWTCookie creates a JWT cookie string with proper security settings
func CreateJWTCookie(jwtToken string, maxAge int, cookieDomain string) string {
	var cookie string

	if maxAge > 0 {
		// Create cookie with token
		cookie = fmt.Sprintf("jwt=%s; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=%d", jwtToken, maxAge)
	} else {
		// Clear cookie
		cookie = "jwt=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0;"
		log.Printf("🍪 Clearing cookie")
	}

	log.Printf("🍪 Cookie: %s", func() string {
		if len(cookie) > 100 {
			return cookie[:100] + "..."
		}
		return cookie
	}())

	return cookie
}
