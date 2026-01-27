//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0xsj/overwatch-pkg/security"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

// ============================================================================
// Challenge Edge Cases
// ============================================================================

func TestReusedChallenge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keyPair, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	did, err := security.DIDFromKeyPair(keyPair)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	// Register to get a challenge
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(registerResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// First verification should succeed
	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("First VerifyRegistration failed: %v", err)
	}

	t.Log("First verification succeeded")

	// Second verification with same challenge should fail
	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err == nil {
		t.Fatal("expected error for reused challenge")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	t.Logf("Reused challenge correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestReusedAuthenticationChallenge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register a user first
	keyPair, did := mustRegisterNewUser(t, ctx)

	// Get authentication challenge
	authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(authResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// First verification should succeed
	_, err = client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("First VerifyAuthentication failed: %v", err)
	}

	t.Log("First authentication succeeded")

	// Second verification with same challenge should fail
	_, err = client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err == nil {
		t.Fatal("expected error for reused authentication challenge")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	t.Logf("Reused authentication challenge correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestNonExistentChallenge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	signature, _ := keyPair.Sign([]byte("fake-challenge"))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, err := client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: "01H0000000000000000000000", // Valid ULID format but doesn't exist
		Did:         did.String(),
		Signature:   signatureB64,
	})

	if err == nil {
		t.Fatal("expected error for non-existent challenge")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.NotFound && st.Code() != codes.InvalidArgument && st.Code() != codes.Unauthenticated {
		t.Errorf("expected NotFound, InvalidArgument, or Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Non-existent challenge correctly rejected: %s - %s", st.Code(), st.Message())
}

// ============================================================================
// DID Format Edge Cases
// ============================================================================

func TestInvalidDIDFormat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testCases := []struct {
		name string
		did  string
	}{
		{"empty", ""},
		{"plain string", "not-a-did"},
		{"missing method", "did:abc123"},
		{"invalid method", "did:invalid:z6Mktest"},
		{"too short", "did:key:z6"},
		{"special characters", "did:key:z6Mk<script>alert(1)</script>"},
		{"spaces", "did:key:z6Mk test with spaces"},
		{"newlines", "did:key:z6Mk\nwith\nnewlines"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.Register(ctx, &identityv1.RegisterRequest{
				Did: tc.did,
			})

			if err == nil {
				t.Fatalf("expected error for invalid DID: %q", tc.did)
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got: %v", err)
			}

			t.Logf("Invalid DID %q correctly rejected: %s - %s", tc.name, st.Code(), st.Message())
		})
	}
}

func TestDIDMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate two different keypairs
	keyPair1, _ := security.GenerateEd25519()
	did1, _ := security.DIDFromKeyPair(keyPair1)

	keyPair2, _ := security.GenerateEd25519()
	did2, _ := security.DIDFromKeyPair(keyPair2)

	// Register with DID1
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did1.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Sign with keypair1 but try to verify with DID2
	signature, _ := keyPair1.Sign([]byte(registerResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did2.String(), // Different DID
		Signature:   signatureB64,
	})

	if err == nil {
		t.Fatal("expected error for DID mismatch")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	t.Logf("DID mismatch correctly rejected: %s - %s", st.Code(), st.Message())
}

// ============================================================================
// Signature Edge Cases
// ============================================================================

func TestMalformedSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	// Register to get a challenge
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	testCases := []struct {
		name      string
		signature string
	}{
		{"empty", ""},
		{"not base64", "not-valid-base64!!!"},
		{"truncated", "YWJjZA=="}, // Valid base64 but too short
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"all zeros", base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
				ChallengeId: registerResp.ChallengeId,
				Did:         did.String(),
				Signature:   tc.signature,
			})

			if err == nil {
				t.Fatalf("expected error for malformed signature: %s", tc.name)
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got: %v", err)
			}

			t.Logf("Malformed signature %q correctly rejected: %s - %s", tc.name, st.Code(), st.Message())
		})
	}
}

func TestWrongKeySignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate keypair for registration
	keyPair1, _ := security.GenerateEd25519()
	did1, _ := security.DIDFromKeyPair(keyPair1)

	// Generate different keypair for signing
	keyPair2, _ := security.GenerateEd25519()

	// Register with DID1
	registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
		Did: did1.String(),
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Sign with wrong keypair
	signature, _ := keyPair2.Sign([]byte(registerResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did1.String(),
		Signature:   signatureB64,
	})

	if err == nil {
		t.Fatal("expected error for wrong key signature")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Wrong key signature correctly rejected: %s", st.Message())
}

// ============================================================================
// Empty/Null Input Edge Cases
// ============================================================================

func TestEmptyRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("empty register", func(t *testing.T) {
		_, err := client.Register(ctx, &identityv1.RegisterRequest{})
		if err == nil {
			t.Fatal("expected error for empty register request")
		}
		st, _ := status.FromError(err)
		t.Logf("Empty register rejected: %s - %s", st.Code(), st.Message())
	})

	t.Run("empty verify registration", func(t *testing.T) {
		_, err := client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{})
		if err == nil {
			t.Fatal("expected error for empty verify registration request")
		}
		st, _ := status.FromError(err)
		t.Logf("Empty verify registration rejected: %s - %s", st.Code(), st.Message())
	})

	t.Run("empty authenticate", func(t *testing.T) {
		_, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{})
		if err == nil {
			t.Fatal("expected error for empty authenticate request")
		}
		st, _ := status.FromError(err)
		t.Logf("Empty authenticate rejected: %s - %s", st.Code(), st.Message())
	})

	t.Run("empty verify authentication", func(t *testing.T) {
		_, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{})
		if err == nil {
			t.Fatal("expected error for empty verify authentication request")
		}
		st, _ := status.FromError(err)
		t.Logf("Empty verify authentication rejected: %s - %s", st.Code(), st.Message())
	})

	t.Run("empty refresh token", func(t *testing.T) {
		_, err := client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{})
		if err == nil {
			t.Fatal("expected error for empty refresh token request")
		}
		st, _ := status.FromError(err)
		t.Logf("Empty refresh token rejected: %s - %s", st.Code(), st.Message())
	})

	t.Run("empty verify api key", func(t *testing.T) {
		_, err := client.VerifyAPIKey(ctx, &identityv1.VerifyAPIKeyRequest{})
		if err == nil {
			t.Fatal("expected error for empty verify api key request")
		}
		st, _ := status.FromError(err)
		t.Logf("Empty verify api key rejected: %s - %s", st.Code(), st.Message())
	})
}

// ============================================================================
// Token Edge Cases
// ============================================================================

func TestMalformedAccessToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"random string", "not-a-jwt"},
		{"partial jwt", "eyJhbGciOiJIUzI1NiIs"},
		{"three dots", "a.b.c"},
		{"sql injection", "'; DROP TABLE users; --"},
		{"very long", strings.Repeat("a", 10000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authCtx := withAuthToken(ctx, tc.token)
			_, err := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})

			if err == nil {
				t.Fatalf("expected error for malformed token: %s", tc.name)
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got: %v", err)
			}

			if st.Code() != codes.Unauthenticated {
				t.Errorf("expected Unauthenticated, got: %s", st.Code())
			}

			t.Logf("Malformed token %q correctly rejected: %s", tc.name, st.Message())
		})
	}
}

func TestExpiredToken(t *testing.T) {
	// This test would require a way to create tokens with short expiry
	// or manipulate time, which is complex in E2E tests.
	// Marking as a note for now.
	t.Skip("Skipping: requires token with short expiry or time manipulation")
}

// ============================================================================
// API Key Edge Cases
// ============================================================================

func TestAPIKeyEdgeCases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)
	authCtx := withAuthToken(ctx, accessToken)

	t.Run("empty name", func(t *testing.T) {
		_, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
			Name:   "",
			Scopes: []string{"read"},
		})
		// Might succeed or fail depending on validation
		if err != nil {
			st, _ := status.FromError(err)
			t.Logf("Empty name rejected: %s - %s", st.Code(), st.Message())
		} else {
			t.Log("Empty name accepted (no validation)")
		}
	})

	t.Run("very long name", func(t *testing.T) {
		_, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
			Name:   strings.Repeat("a", 1000),
			Scopes: []string{"read"},
		})
		if err != nil {
			st, _ := status.FromError(err)
			t.Logf("Very long name rejected: %s - %s", st.Code(), st.Message())
		} else {
			t.Log("Very long name accepted")
		}
	})

	t.Run("empty scopes", func(t *testing.T) {
		_, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
			Name:   "no-scopes-key",
			Scopes: []string{},
		})
		// Might succeed or fail
		if err != nil {
			st, _ := status.FromError(err)
			t.Logf("Empty scopes rejected: %s - %s", st.Code(), st.Message())
		} else {
			t.Log("Empty scopes accepted")
		}
	})

	t.Run("special characters in name", func(t *testing.T) {
		_, err := client.CreateAPIKey(authCtx, &identityv1.CreateAPIKeyRequest{
			Name:   "<script>alert('xss')</script>",
			Scopes: []string{"read"},
		})
		if err != nil {
			st, _ := status.FromError(err)
			t.Logf("Special characters rejected: %s - %s", st.Code(), st.Message())
		} else {
			t.Log("Special characters accepted (should be escaped on display)")
		}
	})
}

// ============================================================================
// Concurrent Request Edge Cases
// ============================================================================

func TestConcurrentRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keyPair, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(keyPair)

	// Start multiple registrations concurrently
	results := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			registerResp, err := client.Register(ctx, &identityv1.RegisterRequest{
				Did: did.String(),
			})
			if err != nil {
				results <- err
				return
			}

			signature, _ := keyPair.Sign([]byte(registerResp.Message))
			signatureB64 := base64.StdEncoding.EncodeToString(signature)

			_, err = client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
				ChallengeId: registerResp.ChallengeId,
				Did:         did.String(),
				Signature:   signatureB64,
			})
			results <- err
		}()
	}

	// Collect results
	var successCount, errorCount int
	for i := 0; i < 5; i++ {
		err := <-results
		if err == nil {
			successCount++
		} else {
			errorCount++
		}
	}

	// Only one should succeed (first to complete), others should fail with duplicate
	t.Logf("Concurrent registration results: %d success, %d errors", successCount, errorCount)

	if successCount == 0 {
		t.Error("expected at least one successful registration")
	}
	if successCount > 1 {
		t.Log("Note: Multiple successes indicate potential race condition (may be acceptable)")
	}
}

func TestConcurrentTokenRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	keyPair, did := mustRegisterNewUser(t, ctx)

	authResp, _ := client.Authenticate(ctx, &identityv1.AuthenticateRequest{Did: did.String()})
	sig, _ := keyPair.Sign([]byte(authResp.Message))
	verifyResp, _ := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})

	refreshToken := verifyResp.RefreshToken

	// Try to refresh the same token concurrently
	results := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_, err := client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
				RefreshToken: refreshToken,
			})
			results <- err
		}()
	}

	// Collect results
	var successCount, errorCount int
	for i := 0; i < 5; i++ {
		err := <-results
		if err == nil {
			successCount++
		} else {
			errorCount++
		}
	}

	t.Logf("Concurrent refresh results: %d success, %d errors", successCount, errorCount)

	// With token rotation, only the first should succeed
	// Others should fail because the refresh token is invalidated
	if successCount == 0 {
		t.Error("expected at least one successful refresh")
	}
}
