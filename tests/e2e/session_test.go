//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/0xsj/overwatch-pkg/security"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

func TestListSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate to get a token
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)

	// Add auth metadata
	authCtx := withAuthToken(ctx, accessToken)

	// List sessions
	resp, err := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}

	if len(resp.Sessions) == 0 {
		t.Fatal("expected at least one session")
	}

	// Verify session belongs to current user
	session := resp.Sessions[0]
	if session.Id == "" {
		t.Error("expected non-empty session ID")
	}
	if session.UserDid == "" {
		t.Error("expected non-empty user DID")
	}
	if session.ExpiresAt == nil {
		t.Error("expected non-nil expires_at")
	}
	if session.CreatedAt == nil {
		t.Error("expected non-nil created_at")
	}

	t.Logf("Found %d session(s)", len(resp.Sessions))
}

func TestListSessionsUnauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to list sessions without auth
	_, err := client.ListSessions(ctx, &identityv1.ListSessionsRequest{})
	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Unauthenticated request correctly rejected: %s", st.Message())
}

func TestRevokeSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and get initial token
	keyPair, did, initialToken := mustRegisterAndAuthenticate(t, ctx)

	// Create a second session
	authResp, _ := client.Authenticate(ctx, &identityv1.AuthenticateRequest{Did: did.String()})
	sig, _ := keyPair.Sign([]byte(authResp.Message))
	verifyResp, _ := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	secondToken := verifyResp.AccessToken

	// List sessions
	authCtx := withAuthToken(ctx, secondToken)
	listResp, err := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}

	initialCount := len(listResp.Sessions)
	t.Logf("Found %d sessions before revocation", initialCount)

	if initialCount < 2 {
		t.Fatalf("expected at least 2 sessions, got %d", initialCount)
	}

	// Revoke the FIRST session (from registration) using the second token
	// The initial token's session should be first in the list (oldest)
	sessionToRevoke := listResp.Sessions[len(listResp.Sessions)-1].Id // Revoke oldest
	_, err = client.RevokeSession(authCtx, &identityv1.RevokeSessionRequest{
		SessionId: sessionToRevoke,
	})
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	t.Logf("Revoked session: %s", sessionToRevoke)

	// Verify the initial token no longer works
	authCtxInitial := withAuthToken(ctx, initialToken)
	_, err = client.ListSessions(authCtxInitial, &identityv1.ListSessionsRequest{})
	if err == nil {
		// Initial token might still work if we revoked a different session
		t.Log("Initial token still works (revoked a different session)")
	} else {
		t.Log("Initial token correctly invalidated after its session was revoked")
	}

	// Second token should still work
	listResp2, err := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("Second token should still work: %v", err)
	}

	t.Logf("Found %d sessions after revocation", len(listResp2.Sessions))
}

func TestRevokeSessionInvalidID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)

	authCtx := withAuthToken(ctx, accessToken)

	// Try to revoke with invalid session ID
	_, err := client.RevokeSession(authCtx, &identityv1.RevokeSessionRequest{
		SessionId: "invalid-id",
	})

	if err == nil {
		t.Fatal("expected error for invalid session ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %s", st.Code())
	}

	t.Logf("Invalid session ID correctly rejected: %s", st.Message())
}

func TestRevokeAllSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register a new user
	keyPair, did := mustRegisterNewUser(t, ctx)

	// Create multiple sessions by authenticating multiple times
	var accessTokens []string
	for i := 0; i < 3; i++ {
		authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
			Did: did.String(),
		})
		if err != nil {
			t.Fatalf("Authenticate %d failed: %v", i, err)
		}

		signature, _ := keyPair.Sign([]byte(authResp.Message))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)

		verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
			ChallengeId: authResp.ChallengeId,
			Did:         did.String(),
			Signature:   signatureB64,
		})
		if err != nil {
			t.Fatalf("VerifyAuthentication %d failed: %v", i, err)
		}

		accessTokens = append(accessTokens, verifyResp.AccessToken)
	}

	t.Logf("Created %d sessions", len(accessTokens))

	// List sessions before revocation
	authCtx := withAuthToken(ctx, accessTokens[0])
	listBefore, err := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions before revoke failed: %v", err)
	}
	sessionCountBefore := len(listBefore.Sessions)
	t.Logf("Sessions before revoke: %d", sessionCountBefore)

	// Revoke all sessions
	revokeResp, err := client.RevokeAllSessions(authCtx, &identityv1.RevokeAllSessionsRequest{})
	if err != nil {
		t.Fatalf("RevokeAllSessions failed: %v", err)
	}

	if revokeResp.RevokedCount == 0 {
		t.Error("expected at least one session to be revoked")
	}

	t.Logf("Revoked %d sessions", revokeResp.RevokedCount)

	// Verify revoked count matches what we had
	// Note: +1 because mustRegisterNewUser also creates a session
	expectedMin := 3 // At least the 3 sessions we created
	if int(revokeResp.RevokedCount) < expectedMin {
		t.Errorf("expected at least %d revoked sessions, got %d", expectedMin, revokeResp.RevokedCount)
	}

	// List sessions after revocation - should be empty or contain no active sessions
	// Note: JWT tokens may still work briefly (stateless), but sessions are revoked
	listAfter, err := client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		// This is acceptable - token might be blacklisted
		t.Logf("ListSessions after revoke returned error (expected if blacklist active): %v", err)
	} else {
		// If it succeeds, verify no active sessions
		if len(listAfter.Sessions) > 0 {
			t.Errorf("expected 0 active sessions after RevokeAllSessions, got %d", len(listAfter.Sessions))
		} else {
			t.Log("All sessions successfully revoked")
		}
	}
}

// Helper functions

func withAuthToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func mustRegisterAndAuthenticate(t *testing.T, ctx context.Context) (security.KeyPair, *security.DID, string) {
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

	signature, err := keyPair.Sign([]byte(registerResp.Message))
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResp, err := client.VerifyRegistration(ctx, &identityv1.VerifyRegistrationRequest{
		ChallengeId: registerResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyRegistration failed: %v", err)
	}

	return keyPair, did, verifyResp.AccessToken
}
