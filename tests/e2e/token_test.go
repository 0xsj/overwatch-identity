//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

func TestRefreshToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate to get tokens
	keyPair, did := mustRegisterNewUser(t, ctx)

	// Authenticate to get access and refresh tokens
	authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(authResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication failed: %v", err)
	}

	originalAccessToken := verifyResp.AccessToken
	refreshToken := verifyResp.RefreshToken

	t.Logf("Original access token: %s...", originalAccessToken[:20])

	// Refresh the token
	refreshResp, err := client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	if refreshResp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if refreshResp.RefreshToken == "" {
		t.Fatal("expected non-empty refresh_token")
	}
	if refreshResp.AccessTokenExpiresAt == nil {
		t.Fatal("expected non-nil access_token_expires_at")
	}

	// New access token should be different
	if refreshResp.AccessToken == originalAccessToken {
		t.Error("expected new access token to be different from original")
	}

	t.Logf("New access token: %s...", refreshResp.AccessToken[:20])

	// New access token should work
	authCtx := withAuthToken(ctx, refreshResp.AccessToken)
	_, err = client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("New access token should work: %v", err)
	}

	t.Log("New access token works correctly")
}

func TestRefreshTokenWithInvalidToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	})

	if err == nil {
		t.Fatal("expected error for invalid refresh token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	// Could be Unauthenticated or NotFound depending on implementation
	if st.Code() != codes.Unauthenticated && st.Code() != codes.NotFound {
		t.Errorf("expected Unauthenticated or NotFound, got: %s", st.Code())
	}

	t.Logf("Invalid refresh token correctly rejected: %s", st.Message())
}

func TestRefreshTokenWithEmptyToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: "",
	})

	if err == nil {
		t.Fatal("expected error for empty refresh token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	t.Logf("Empty refresh token correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestRevokeToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	keyPair, did := mustRegisterNewUser(t, ctx)

	authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(authResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication failed: %v", err)
	}

	accessToken := verifyResp.AccessToken
	refreshToken := verifyResp.RefreshToken

	// Verify access token works before revocation
	authCtx := withAuthToken(ctx, accessToken)
	_, err = client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("Access token should work before revocation: %v", err)
	}

	t.Log("Access token works before revocation")

	// Revoke the token (requires authentication)
	_, err = client.RevokeToken(authCtx, &identityv1.RevokeTokenRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	t.Log("Token revoked successfully")

	// Access token should no longer work (session is revoked)
	_, err = client.ListSessions(authCtx, &identityv1.ListSessionsRequest{})
	if err == nil {
		t.Fatal("Access token should not work after revocation")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %s", st.Code())
	}

	t.Logf("Access token correctly invalidated after revocation: %s", st.Message())

	// Refresh token should also no longer work
	_, err = client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	if err == nil {
		t.Fatal("Refresh token should not work after revocation")
	}

	t.Log("Refresh token correctly invalidated after revocation")
}

func TestRevokeTokenWithInvalidToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Need to be authenticated to call RevokeToken
	_, _, accessToken := mustRegisterAndAuthenticate(t, ctx)

	authCtx := withAuthToken(ctx, accessToken)
	_, err := client.RevokeToken(authCtx, &identityv1.RevokeTokenRequest{
		RefreshToken: "invalid-refresh-token",
	})

	if err == nil {
		t.Fatal("expected error for invalid refresh token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}

	t.Logf("Invalid token revocation correctly rejected: %s - %s", st.Code(), st.Message())
}

func TestRefreshTokenRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Register and authenticate
	keyPair, did := mustRegisterNewUser(t, ctx)

	authResp, err := client.Authenticate(ctx, &identityv1.AuthenticateRequest{
		Did: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	signature, _ := keyPair.Sign([]byte(authResp.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResp, err := client.VerifyAuthentication(ctx, &identityv1.VerifyAuthenticationRequest{
		ChallengeId: authResp.ChallengeId,
		Did:         did.String(),
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication failed: %v", err)
	}

	originalRefreshToken := verifyResp.RefreshToken

	// Refresh to get new tokens
	refreshResp, err := client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: originalRefreshToken,
	})
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	newRefreshToken := refreshResp.RefreshToken

	// New refresh token should be different (rotation)
	if newRefreshToken == originalRefreshToken {
		t.Error("expected refresh token to be rotated (different from original)")
	}

	t.Log("Refresh token rotated successfully")

	// Original refresh token should no longer work (if rotation invalidates old token)
	_, err = client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: originalRefreshToken,
	})
	if err == nil {
		t.Log("Note: Original refresh token still works (rotation doesn't invalidate old token)")
	} else {
		t.Log("Original refresh token correctly invalidated after rotation")
	}

	// New refresh token should work
	_, err = client.RefreshToken(ctx, &identityv1.RefreshTokenRequest{
		RefreshToken: newRefreshToken,
	})
	if err != nil {
		t.Fatalf("New refresh token should work: %v", err)
	}

	t.Log("New refresh token works correctly")
}
