//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0xsj/overwatch-pkg/security"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

func TestPing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Ping(ctx, &identityv1.PingRequest{})
	if err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	if resp.Message != "pong" {
		t.Errorf("expected 'pong', got '%s'", resp.Message)
	}
}

func TestRegistrationFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate a new keypair for this test user
	keyPair, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	did, err := security.DIDFromKeyPair(keyPair)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	// Step 1: Register - request a challenge
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if registerResp.ChallengeId == "" {
		t.Fatal("expected non-empty challenge_id")
	}
	if registerResp.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
	if registerResp.Message == "" {
		t.Fatal("expected non-empty message")
	}
	if registerResp.ExpiresAt == nil {
		t.Fatal("expected non-nil expires_at")
	}

	t.Logf("Registration challenge received: %s", registerResp.ChallengeId)

	// Step 2: Sign the message (directly from server response)
	signature, err := keyPair.Sign([]byte(registerResp.Message))
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Step 3: Verify registration
	verifyResp, err := client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyRegistration failed: %v", err)
	}

	if verifyResp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if verifyResp.User.Did != did.String() {
		t.Errorf("user DID mismatch: got %s, want %s", verifyResp.User.Did, did.String())
	}
	if verifyResp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if verifyResp.RefreshToken == "" {
		t.Fatal("expected non-empty refresh_token")
	}

	t.Logf("User registered: %s", verifyResp.User.Id)
}

func TestAuthenticationFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First, register a new user
	keyPair, did := mustRegisterNewUser(t, ctx)

	// Step 1: Authenticate - request a challenge
	authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if authResp.ChallengeId == "" {
		t.Fatal("expected non-empty challenge_id")
	}
	if authResp.Message == "" {
		t.Fatal("expected non-empty message")
	}

	t.Logf("Authentication challenge received: %s", authResp.ChallengeId)

	// Step 2: Sign the message (directly from server response)
	signature, err := keyPair.Sign([]byte(authResp.Message))
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Step 3: Verify authentication
	verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication failed: %v", err)
	}

	if verifyResp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if verifyResp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if verifyResp.RefreshToken == "" {
		t.Fatal("expected non-empty refresh_token")
	}

	t.Logf("User authenticated: %s", verifyResp.User.Id)
}

func TestRegistrationWithInvalidSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate keypair for registration
	keyPair, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	did, err := security.DIDFromKeyPair(keyPair)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	// Register
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Sign with a DIFFERENT keypair (should fail)
	wrongKeyPair, _ := security.GenerateEd25519()
	wrongSignature, _ := wrongKeyPair.Sign([]byte(registerResp.Message))
	wrongSignatureB64 := base64.StdEncoding.EncodeToString(wrongSignature)

	// Verify should fail
	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   wrongSignatureB64,
	})

	if err == nil {
		t.Fatal("expected error for invalid signature")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Invalid signature correctly rejected: %s", st.Message())
}

func TestAuthenticateUnknownUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate a DID that was never registered
	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	_, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})

	if err == nil {
		t.Fatal("expected error for unknown user")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got: %s", st.Code())
	}

	t.Logf("Unknown user correctly rejected: %s", st.Message())
}

func TestDuplicateRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register a user
	_, did := mustRegisterNewUser(t, ctx)

	// Try to register again with the same DID
	_, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})

	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got: %s", st.Code())
	}

	t.Logf("Duplicate registration correctly rejected: %s", st.Message())
}

// Helper functions

func mustRegisterNewUser(t *testing.T, ctx context.Context) (security.KeyPair, *security.DID) {
	t.Helper()

	keyPair, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	did, err := security.DIDFromKeyPair(keyPair)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	// Register
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Sign the message directly
	signature, err := keyPair.Sign([]byte(registerResp.Message))
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Verify registration
	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyRegistration failed: %v", err)
	}

	return keyPair, did
}
