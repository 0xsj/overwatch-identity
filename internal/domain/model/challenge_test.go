package model_test

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestNewChallenge(t *testing.T) {
	keyPair := mustGenerateEd25519(t)
	did := mustDIDFromKeyPair(t, keyPair)
	config := model.DefaultChallengeConfig()

	t.Run("creates valid registration challenge", func(t *testing.T) {
		challenge, err := model.NewChallenge(did, model.ChallengePurposeRegister, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if challenge.ID() == "" {
			t.Error("expected non-empty ID")
		}
		if challenge.DID().String() != did.String() {
			t.Errorf("DID mismatch: got %s, want %s", challenge.DID().String(), did.String())
		}
		if challenge.Nonce() == "" {
			t.Error("expected non-empty nonce")
		}
		if challenge.Purpose() != model.ChallengePurposeRegister {
			t.Errorf("purpose mismatch: got %s, want %s", challenge.Purpose(), model.ChallengePurposeRegister)
		}
		if !challenge.IsForRegistration() {
			t.Error("expected IsForRegistration to be true")
		}
		if challenge.IsForAuthentication() {
			t.Error("expected IsForAuthentication to be false")
		}
		if challenge.IsExpired() {
			t.Error("new challenge should not be expired")
		}
	})

	t.Run("creates valid authentication challenge", func(t *testing.T) {
		challenge, err := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if challenge.Purpose() != model.ChallengePurposeAuthenticate {
			t.Errorf("purpose mismatch: got %s, want %s", challenge.Purpose(), model.ChallengePurposeAuthenticate)
		}
		if !challenge.IsForAuthentication() {
			t.Error("expected IsForAuthentication to be true")
		}
	})

	t.Run("rejects nil DID", func(t *testing.T) {
		_, err := model.NewChallenge(nil, model.ChallengePurposeRegister, config)
		if err == nil {
			t.Fatal("expected error for nil DID")
		}
	})

	t.Run("rejects invalid purpose", func(t *testing.T) {
		_, err := model.NewChallenge(did, model.ChallengePurpose("invalid"), config)
		if err == nil {
			t.Fatal("expected error for invalid purpose")
		}
	})
}

func TestChallenge_Validation(t *testing.T) {
	keyPair := mustGenerateEd25519(t)
	did := mustDIDFromKeyPair(t, keyPair)

	t.Run("valid challenge passes validation", func(t *testing.T) {
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

		if err := challenge.Validate(); err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("expired challenge fails validation", func(t *testing.T) {
		// Create challenge that's already expired
		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"test-nonce",
			model.ChallengePurposeRegister,
			types.FromTime(time.Now().Add(-1*time.Hour)), // expired 1 hour ago
			types.FromTime(time.Now().Add(-2*time.Hour)), // created 2 hours ago
		)

		err := challenge.Validate()
		if err == nil {
			t.Fatal("expected validation error for expired challenge")
		}
		if err != domainerror.ErrChallengeExpired {
			t.Errorf("expected ErrChallengeExpired, got: %v", err)
		}
	})

	t.Run("ValidateFor checks DID match", func(t *testing.T) {
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

		// Same DID should pass
		if err := challenge.ValidateFor(did); err != nil {
			t.Errorf("unexpected error for matching DID: %v", err)
		}

		// Different DID should fail
		otherKeyPair := mustGenerateEd25519(t)
		otherDID := mustDIDFromKeyPair(t, otherKeyPair)

		err := challenge.ValidateFor(otherDID)
		if err == nil {
			t.Fatal("expected error for mismatched DID")
		}
		if err != domainerror.ErrChallengeDIDMismatch {
			t.Errorf("expected ErrChallengeDIDMismatch, got: %v", err)
		}

		// Nil DID should fail
		err = challenge.ValidateFor(nil)
		if err == nil {
			t.Fatal("expected error for nil DID")
		}
	})
}

func TestChallenge_Message(t *testing.T) {
	keyPair := mustGenerateEd25519(t)
	did := mustDIDFromKeyPair(t, keyPair)
	challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

	domain := "overwatch.example.com"
	message := challenge.Message(domain)

	// Verify message contains expected components
	if !contains(message, domain) {
		t.Errorf("message should contain domain: %s", domain)
	}
	if !contains(message, did.String()) {
		t.Errorf("message should contain DID: %s", did.String())
	}
	if !contains(message, challenge.Nonce()) {
		t.Errorf("message should contain nonce: %s", challenge.Nonce())
	}
	if !contains(message, "wants you to sign in") {
		t.Error("message should contain sign-in prompt")
	}

	// MessageBytes should match Message
	messageBytes := challenge.MessageBytes(domain)
	if string(messageBytes) != message {
		t.Error("MessageBytes should return same content as Message")
	}
}

func TestChallenge_VerifySignature(t *testing.T) {
	domain := "overwatch.example.com"

	t.Run("valid Ed25519 signature", func(t *testing.T) {
		keyPair := mustGenerateEd25519(t)
		did := mustDIDFromKeyPair(t, keyPair)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

		// Sign the challenge message
		message := challenge.MessageBytes(domain)
		signature, err := keyPair.Sign(message)
		if err != nil {
			t.Fatalf("failed to sign message: %v", err)
		}

		// Verify should succeed
		if err := challenge.VerifySignature(domain, signature); err != nil {
			t.Errorf("signature verification failed: %v", err)
		}
	})

	t.Run("invalid signature rejected", func(t *testing.T) {
		keyPair := mustGenerateEd25519(t)
		did := mustDIDFromKeyPair(t, keyPair)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

		// Use a different key to sign (should fail verification)
		otherKeyPair := mustGenerateEd25519(t)
		message := challenge.MessageBytes(domain)
		badSignature, _ := otherKeyPair.Sign(message)

		err := challenge.VerifySignature(domain, badSignature)
		if err == nil {
			t.Fatal("expected error for invalid signature")
		}
		if err != domainerror.ErrSignatureInvalid {
			t.Errorf("expected ErrSignatureInvalid, got: %v", err)
		}
	})

	t.Run("tampered message rejected", func(t *testing.T) {
		keyPair := mustGenerateEd25519(t)
		did := mustDIDFromKeyPair(t, keyPair)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

		// Sign with correct message
		message := challenge.MessageBytes(domain)
		signature, _ := keyPair.Sign(message)

		// Verify with different domain (tampered message)
		err := challenge.VerifySignature("evil.example.com", signature)
		if err == nil {
			t.Fatal("expected error for tampered domain")
		}
	})

	t.Run("empty signature rejected", func(t *testing.T) {
		keyPair := mustGenerateEd25519(t)
		did := mustDIDFromKeyPair(t, keyPair)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

		err := challenge.VerifySignature(domain, nil)
		if err == nil {
			t.Fatal("expected error for empty signature")
		}
		if err != domainerror.ErrSignatureRequired {
			t.Errorf("expected ErrSignatureRequired, got: %v", err)
		}

		err = challenge.VerifySignature(domain, []byte{})
		if err == nil {
			t.Fatal("expected error for empty signature")
		}
	})

	t.Run("expired challenge rejected before signature check", func(t *testing.T) {
		keyPair := mustGenerateEd25519(t)
		did := mustDIDFromKeyPair(t, keyPair)

		// Create expired challenge
		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"test-nonce",
			model.ChallengePurposeRegister,
			types.FromTime(time.Now().Add(-1*time.Hour)),
			types.FromTime(time.Now().Add(-2*time.Hour)),
		)

		// Even with valid signature, should fail due to expiry
		message := challenge.MessageBytes(domain)
		signature, _ := keyPair.Sign(message)

		err := challenge.VerifySignature(domain, signature)
		if err == nil {
			t.Fatal("expected error for expired challenge")
		}
		if err != domainerror.ErrChallengeExpired {
			t.Errorf("expected ErrChallengeExpired, got: %v", err)
		}
	})
}

func TestChallengePurpose(t *testing.T) {
	t.Run("valid purposes", func(t *testing.T) {
		if !model.ChallengePurposeRegister.IsValid() {
			t.Error("register should be valid")
		}
		if !model.ChallengePurposeAuthenticate.IsValid() {
			t.Error("authenticate should be valid")
		}
	})

	t.Run("invalid purposes", func(t *testing.T) {
		if model.ChallengePurpose("").IsValid() {
			t.Error("empty should be invalid")
		}
		if model.ChallengePurpose("invalid").IsValid() {
			t.Error("invalid should be invalid")
		}
	})

	t.Run("string conversion", func(t *testing.T) {
		if model.ChallengePurposeRegister.String() != "register" {
			t.Error("register string mismatch")
		}
		if model.ChallengePurposeAuthenticate.String() != "authenticate" {
			t.Error("authenticate string mismatch")
		}
	})
}

// Test helpers

func mustGenerateEd25519(t *testing.T) security.KeyPair {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}
	return kp
}

func mustDIDFromKeyPair(t *testing.T, kp security.KeyPair) *security.DID {
	t.Helper()
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID from keypair: %v", err)
	}
	return did
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
