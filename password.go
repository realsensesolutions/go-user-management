package user

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	lowercaseChars     = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars         = "0123456789"
	specialChars       = "!@#$%^&*"
	allChars           = lowercaseChars + uppercaseChars + digitChars + specialChars
	minPasswordLen     = 12
	maxPasswordRetries = 5
)

func validateCognitoPassword(pw string) error {
	if len(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if !passwordContainsFromSet(pw, lowercaseChars) {
		return fmt.Errorf("password must contain a lowercase letter")
	}
	if !passwordContainsFromSet(pw, uppercaseChars) {
		return fmt.Errorf("password must contain an uppercase letter")
	}
	if !passwordContainsFromSet(pw, digitChars) {
		return fmt.Errorf("password must contain a digit")
	}
	if !passwordContainsFromSet(pw, specialChars) {
		return fmt.Errorf("password must contain a special character")
	}
	return nil
}

func passwordContainsFromSet(pw, set string) bool {
	for i := 0; i < len(pw); i++ {
		if containsChar(set, pw[i]) {
			return true
		}
	}
	return false
}

func generateSecureTemporaryPassword() (string, error) {
	for attempt := 0; attempt < maxPasswordRetries; attempt++ {
		pw, err := buildSecureTemporaryPassword()
		if err != nil {
			return "", err
		}
		if err := validateCognitoPassword(pw); err == nil {
			return pw, nil
		}
	}
	return "", fmt.Errorf("failed to generate valid temporary password after %d attempts", maxPasswordRetries)
}

func buildSecureTemporaryPassword() (string, error) {
	slots := make([]byte, minPasswordLen)

	lower, err := randomCharFrom(lowercaseChars)
	if err != nil {
		return "", fmt.Errorf("failed to generate random character: %w", err)
	}
	slots[0] = lower

	upper, err := randomCharFrom(uppercaseChars)
	if err != nil {
		return "", fmt.Errorf("failed to generate random character: %w", err)
	}
	slots[1] = upper

	digit, err := randomCharFrom(digitChars)
	if err != nil {
		return "", fmt.Errorf("failed to generate random character: %w", err)
	}
	slots[2] = digit

	special, err := randomCharFrom(specialChars)
	if err != nil {
		return "", fmt.Errorf("failed to generate random character: %w", err)
	}
	slots[3] = special

	for i := 4; i < minPasswordLen; i++ {
		ch, err := randomCharFrom(allChars)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		slots[i] = ch
	}

	if err := shufflePassword(slots); err != nil {
		return "", fmt.Errorf("failed to shuffle password: %w", err)
	}

	return string(slots), nil
}

func randomCharFrom(chars string) (byte, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	if err != nil {
		return 0, err
	}
	return chars[index.Int64()], nil
}

func containsChar(chars string, char byte) bool {
	for i := 0; i < len(chars); i++ {
		if chars[i] == char {
			return true
		}
	}
	return false
}

func shufflePassword(password []byte) error {
	for i := len(password) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("failed to generate shuffle index: %w", err)
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}
	return nil
}
