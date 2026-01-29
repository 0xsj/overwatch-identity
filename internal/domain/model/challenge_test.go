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
	t.Run("valid inputs for authentication", func(t *testing.T) {
		did := testDID(t)
		config := model.DefaultChallengeConfig()

		challenge, err := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		if err != nil {
			t.Fatalf("NewChallenge() error = %v", err)
		}
		if challenge == nil {
			t.Fatal("NewChallenge() returned nil")
		}
		if challenge.ID().IsEmpty() {
			t.Error("ID should not be empty")
		}
		if challenge.DID() != did {
			t.Errorf("DID = %v, want %v", challenge.DID(), did)
		}
		if challenge.Purpose() != model.ChallengePurposeAuthenticate {
			t.Errorf("Purpose = %v, want %v", challenge.Purpose(), model.ChallengePurposeAuthenticate)
		}
		if challenge.Nonce() == "" {
			t.Error("Nonce should not be empty")
		}
		if challenge.CreatedAt().IsZero() {
			t.Error("CreatedAt should be set")
		}
		if challenge.ExpiresAt().IsZero() {
			t.Error("ExpiresAt should be set")
		}
		if !challenge.IsValid() {
			t.Error("challenge should be valid")
		}
		if !challenge.IsForAuthentication() {
			t.Error("IsForAuthentication() should return true")
		}
		if challenge.IsForRegistration() {
			t.Error("IsForRegistration() should return false")
		}
	})

	t.Run("valid inputs for registration", func(t *testing.T) {
		did := testDID(t)
		config := model.DefaultChallengeConfig()

		challenge, err := model.NewChallenge(did, model.ChallengePurposeRegister, config)

		if err != nil {
			t.Fatalf("NewChallenge() error = %v", err)
		}
		if challenge.Purpose() != model.ChallengePurposeRegister {
			t.Errorf("Purpose = %v, want %v", challenge.Purpose(), model.ChallengePurposeRegister)
		}
		if !challenge.IsForRegistration() {
			t.Error("IsForRegistration() should return true")
		}
		if challenge.IsForAuthentication() {
			t.Error("IsForAuthentication() should return false")
		}
	})

	t.Run("nil DID", func(t *testing.T) {
		config := model.DefaultChallengeConfig()

		challenge, err := model.NewChallenge(nil, model.ChallengePurposeAuthenticate, config)

		if err == nil {
			t.Fatal("NewChallenge() with nil DID should return error")
		}
		if challenge != nil {
			t.Error("challenge should be nil")
		}
		if err != domainerror.ErrUserDIDRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserDIDRequired)
		}
	})

	t.Run("invalid purpose", func(t *testing.T) {
		did := testDID(t)
		config := model.DefaultChallengeConfig()

		challenge, err := model.NewChallenge(did, model.ChallengePurpose("invalid"), config)

		if err == nil {
			t.Fatal("NewChallenge() with invalid purpose should return error")
		}
		if challenge != nil {
			t.Error("challenge should be nil")
		}
		if err != domainerror.ErrChallengeInvalid {
			t.Errorf("error = %v, want %v", err, domainerror.ErrChallengeInvalid)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		did := testDID(t)
		config := model.ChallengeConfig{
			Domain:            "custom-domain",
			ChallengeDuration: 10 * time.Minute,
			NonceLength:       64,
		}

		challenge, err := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		if err != nil {
			t.Fatalf("NewChallenge() error = %v", err)
		}
		// Nonce should be longer with custom config
		if len(challenge.Nonce()) < 64 {
			t.Errorf("Nonce length = %d, want >= 64", len(challenge.Nonce()))
		}
	})
}

func TestChallenge_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		did := testDID(t)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

		if challenge.IsExpired() {
			t.Error("IsExpired() should return false for new challenge")
		}
	})

	t.Run("expired", func(t *testing.T) {
		did := testDID(t)

		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"somenonce",
			model.ChallengePurposeAuthenticate,
			types.FromTime(time.Now().Add(-time.Hour)), // expired
			types.Now(),
		)

		if !challenge.IsExpired() {
			t.Error("IsExpired() should return true for expired challenge")
		}
	})
}

func TestChallenge_IsValid(t *testing.T) {
	t.Run("valid challenge", func(t *testing.T) {
		did := testDID(t)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

		if !challenge.IsValid() {
			t.Error("IsValid() should return true for new challenge")
		}
	})

	t.Run("expired challenge", func(t *testing.T) {
		did := testDID(t)

		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"somenonce",
			model.ChallengePurposeAuthenticate,
			types.FromTime(time.Now().Add(-time.Hour)),
			types.Now(),
		)

		if challenge.IsValid() {
			t.Error("IsValid() should return false for expired challenge")
		}
	})
}

func TestChallenge_Validate(t *testing.T) {
	t.Run("valid challenge", func(t *testing.T) {
		did := testDID(t)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

		err := challenge.Validate()

		if err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("expired challenge", func(t *testing.T) {
		did := testDID(t)

		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"somenonce",
			model.ChallengePurposeAuthenticate,
			types.FromTime(time.Now().Add(-time.Hour)),
			types.Now(),
		)

		err := challenge.Validate()

		if err != domainerror.ErrChallengeExpired {
			t.Errorf("Validate() error = %v, want %v", err, domainerror.ErrChallengeExpired)
		}
	})
}

func TestChallenge_ValidateFor(t *testing.T) {
	t.Run("matching DID", func(t *testing.T) {
		did := testDID(t)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

		err := challenge.ValidateFor(did)

		if err != nil {
			t.Errorf("ValidateFor() error = %v, want nil", err)
		}
	})

	t.Run("different DID", func(t *testing.T) {
		did1 := testDID(t)
		did2 := testDID(t)
		challenge, _ := model.NewChallenge(did1, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

		err := challenge.ValidateFor(did2)

		if err != domainerror.ErrChallengeDIDMismatch {
			t.Errorf("ValidateFor() error = %v, want %v", err, domainerror.ErrChallengeDIDMismatch)
		}
	})

	t.Run("nil DID", func(t *testing.T) {
		did := testDID(t)
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

		err := challenge.ValidateFor(nil)

		if err != domainerror.ErrChallengeDIDMismatch {
			t.Errorf("ValidateFor() error = %v, want %v", err, domainerror.ErrChallengeDIDMismatch)
		}
	})

	t.Run("expired challenge", func(t *testing.T) {
		did := testDID(t)

		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"somenonce",
			model.ChallengePurposeAuthenticate,
			types.FromTime(time.Now().Add(-time.Hour)),
			types.Now(),
		)

		err := challenge.ValidateFor(did)

		if err != domainerror.ErrChallengeExpired {
			t.Errorf("ValidateFor() error = %v, want %v", err, domainerror.ErrChallengeExpired)
		}
	})
}

func TestChallenge_TimeUntilExpiry(t *testing.T) {
	did := testDID(t)
	config := model.ChallengeConfig{
		Domain:            "test",
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}

	challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

	ttl := challenge.TimeUntilExpiry()

	// Should be close to 5 minutes (allowing some margin for test execution time)
	if ttl < 4*time.Minute || ttl > 5*time.Minute {
		t.Errorf("TimeUntilExpiry() = %v, want ~5 minutes", ttl)
	}
}

func TestChallenge_Message(t *testing.T) {
	did := testDID(t)
	challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())
	domain := "test-domain"

	message := challenge.Message(domain)

	if message == "" {
		t.Error("Message() should not be empty")
	}
	// Verify message contains expected components
	if !containsSubstring(message, domain) {
		t.Errorf("Message should contain domain %q", domain)
	}
	if !containsSubstring(message, did.String()) {
		t.Error("Message should contain DID")
	}
	if !containsSubstring(message, challenge.Nonce()) {
		t.Error("Message should contain nonce")
	}
}

func TestChallenge_MessageBytes(t *testing.T) {
	did := testDID(t)
	challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())
	domain := "test-domain"

	message := challenge.Message(domain)
	messageBytes := challenge.MessageBytes(domain)

	if string(messageBytes) != message {
		t.Errorf("MessageBytes() = %q, want %q", string(messageBytes), message)
	}
}

func TestChallenge_VerifySignature(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		did, kp := testDIDWithKeyPair(t)
		config := model.DefaultChallengeConfig()
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		// Sign the challenge message
		message := challenge.MessageBytes(config.Domain)
		signature, err := kp.Sign(message)
		if err != nil {
			t.Fatalf("failed to sign message: %v", err)
		}

		err = challenge.VerifySignature(config.Domain, signature)

		if err != nil {
			t.Errorf("VerifySignature() error = %v, want nil", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		did := testDID(t)
		config := model.DefaultChallengeConfig()
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		invalidSignature := []byte("invalid-signature")

		err := challenge.VerifySignature(config.Domain, invalidSignature)

		if err != domainerror.ErrSignatureInvalid {
			t.Errorf("VerifySignature() error = %v, want %v", err, domainerror.ErrSignatureInvalid)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		did := testDID(t)
		config := model.DefaultChallengeConfig()
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		err := challenge.VerifySignature(config.Domain, []byte{})

		if err != domainerror.ErrSignatureRequired {
			t.Errorf("VerifySignature() error = %v, want %v", err, domainerror.ErrSignatureRequired)
		}
	})

	t.Run("nil signature", func(t *testing.T) {
		did := testDID(t)
		config := model.DefaultChallengeConfig()
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		err := challenge.VerifySignature(config.Domain, nil)

		if err != domainerror.ErrSignatureRequired {
			t.Errorf("VerifySignature() error = %v, want %v", err, domainerror.ErrSignatureRequired)
		}
	})

	t.Run("expired challenge", func(t *testing.T) {
		did, kp := testDIDWithKeyPair(t)
		config := model.DefaultChallengeConfig()

		challenge := model.ReconstructChallenge(
			types.NewID(),
			did,
			"somenonce",
			model.ChallengePurposeAuthenticate,
			types.FromTime(time.Now().Add(-time.Hour)),
			types.Now(),
		)

		message := challenge.MessageBytes(config.Domain)
		signature, _ := kp.Sign(message)

		err := challenge.VerifySignature(config.Domain, signature)

		if err != domainerror.ErrChallengeExpired {
			t.Errorf("VerifySignature() error = %v, want %v", err, domainerror.ErrChallengeExpired)
		}
	})

	t.Run("wrong key signature", func(t *testing.T) {
		did := testDID(t)
		_, wrongKP := testDIDWithKeyPair(t) // different keypair
		config := model.DefaultChallengeConfig()
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, config)

		// Sign with wrong key
		message := challenge.MessageBytes(config.Domain)
		signature, _ := wrongKP.Sign(message)

		err := challenge.VerifySignature(config.Domain, signature)

		if err != domainerror.ErrSignatureInvalid {
			t.Errorf("VerifySignature() error = %v, want %v", err, domainerror.ErrSignatureInvalid)
		}
	})
}

func TestChallengePurpose_IsValid(t *testing.T) {
	tests := []struct {
		purpose model.ChallengePurpose
		want    bool
	}{
		{model.ChallengePurposeRegister, true},
		{model.ChallengePurposeAuthenticate, true},
		{model.ChallengePurpose("invalid"), false},
		{model.ChallengePurpose(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			if got := tt.purpose.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChallengePurpose_String(t *testing.T) {
	tests := []struct {
		purpose model.ChallengePurpose
		want    string
	}{
		{model.ChallengePurposeRegister, "register"},
		{model.ChallengePurposeAuthenticate, "authenticate"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.purpose.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultChallengeConfig(t *testing.T) {
	config := model.DefaultChallengeConfig()

	if config.Domain != "overwatch-identity" {
		t.Errorf("Domain = %v, want overwatch-identity", config.Domain)
	}
	if config.ChallengeDuration != 5*time.Minute {
		t.Errorf("ChallengeDuration = %v, want 5 minutes", config.ChallengeDuration)
	}
	if config.NonceLength != 32 {
		t.Errorf("NonceLength = %v, want 32", config.NonceLength)
	}
}

func TestReconstructChallenge(t *testing.T) {
	id := types.NewID()
	did := testDID(t)
	nonce := "testnonce123"
	purpose := model.ChallengePurposeRegister
	expiresAt := types.FromTime(time.Now().Add(time.Hour))
	createdAt := types.Now()

	challenge := model.ReconstructChallenge(id, did, nonce, purpose, expiresAt, createdAt)

	if challenge.ID() != id {
		t.Errorf("ID = %v, want %v", challenge.ID(), id)
	}
	if challenge.DID() != did {
		t.Errorf("DID = %v, want %v", challenge.DID(), did)
	}
	if challenge.Nonce() != nonce {
		t.Errorf("Nonce = %v, want %v", challenge.Nonce(), nonce)
	}
	if challenge.Purpose() != purpose {
		t.Errorf("Purpose = %v, want %v", challenge.Purpose(), purpose)
	}
	if challenge.ExpiresAt() != expiresAt {
		t.Errorf("ExpiresAt = %v, want %v", challenge.ExpiresAt(), expiresAt)
	}
	if challenge.CreatedAt() != createdAt {
		t.Errorf("CreatedAt = %v, want %v", challenge.CreatedAt(), createdAt)
	}
}

// Helper functions

func testDIDWithKeyPair(t *testing.T) (*security.DID, security.KeyPair) {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}
	return did, kp
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && searchSubstring(s, substr)))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
