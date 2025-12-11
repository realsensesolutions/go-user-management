package user

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars     = "0123456789"
	specialChars   = "!@#$%^&*"
	allChars       = lowercaseChars + uppercaseChars + digitChars + specialChars
	minPasswordLen = 12
)

func generateSecureTemporaryPassword() (string, error) {
	password := make([]byte, minPasswordLen)

	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

	for i := 0; i < minPasswordLen; i++ {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		password[i] = allChars[charIndex.Int64()]

		char := password[i]
		if !hasLower && containsChar(lowercaseChars, char) {
			hasLower = true
		}
		if !hasUpper && containsChar(uppercaseChars, char) {
			hasUpper = true
		}
		if !hasDigit && containsChar(digitChars, char) {
			hasDigit = true
		}
		if !hasSpecial && containsChar(specialChars, char) {
			hasSpecial = true
		}
	}

	if !hasLower {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(lowercaseChars))))
		password[0] = lowercaseChars[index.Int64()]
	}
	if !hasUpper {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(uppercaseChars))))
		password[1] = uppercaseChars[index.Int64()]
	}
	if !hasDigit {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digitChars))))
		password[2] = digitChars[index.Int64()]
	}
	if !hasSpecial {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(specialChars))))
		password[3] = specialChars[index.Int64()]
	}

	shufflePassword(password)

	return string(password), nil
}

func containsChar(chars string, char byte) bool {
	for i := 0; i < len(chars); i++ {
		if chars[i] == char {
			return true
		}
	}
	return false
}

func shufflePassword(password []byte) {
	for i := len(password) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}
}

