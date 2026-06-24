package user

import (
	"strings"
	"testing"
)

func TestGenerateSecureTemporaryPassword_PolicyCompliance(t *testing.T) {
	const iterations = 10_000
	for i := 0; i < iterations; i++ {
		pw, err := generateSecureTemporaryPassword()
		if err != nil {
			t.Fatalf("iteration %d: generateSecureTemporaryPassword: %v", i, err)
		}
		if err := validateCognitoPassword(pw); err != nil {
			t.Fatalf("iteration %d: password %q: %v", i, pw, err)
		}
	}
}

func TestGenerateSecureTemporaryPassword_MinLength(t *testing.T) {
	pw, err := generateSecureTemporaryPassword()
	if err != nil {
		t.Fatalf("generateSecureTemporaryPassword: %v", err)
	}
	if len(pw) < minPasswordLen {
		t.Fatalf("password length %d < min %d", len(pw), minPasswordLen)
	}
}

func TestValidateCognitoPassword_DetectsMissingDigit(t *testing.T) {
	// Simulates the post-patch pre-shuffle state from the original bug: lower at 0,
	// upper at 1, the sole digit was at index 3 but special-char forcing overwrote it.
	pw := "aB!@xxxxxxxx"
	if strings.ContainsAny(pw, digitChars) {
		t.Fatal("test fixture must not contain a digit")
	}
	if err := validateCognitoPassword(pw); err == nil {
		t.Fatalf("expected policy error for password missing digit, got nil for %q", pw)
	}
}

func TestValidateCognitoPassword_AcceptsCompliantPassword(t *testing.T) {
	pw := "aB3!xxxxxxxx"
	if err := validateCognitoPassword(pw); err != nil {
		t.Fatalf("expected nil for compliant password, got %v", err)
	}
}
