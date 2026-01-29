package e2e

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	natsadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/nats"
	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	appcommand "github.com/0xsj/overwatch-identity/internal/app/command"
	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/tests/testutil/mocks"
)

func TestRevokeTokenFlow_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	challengeConfig := model.ChallengeConfig{
		Domain:            "test-domain",
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}
	sessionConfig := model.DefaultSessionConfig()

	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)
	verifyAuthHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)
	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.>")
	defer cleanup()

	// Create and authenticate user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResult, _ := verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	refreshToken := verifyResult.RefreshToken

	// Drain authentication events
	time.Sleep(50 * time.Millisecond)
	drainMessages(msgChan)

	// Revoke token (logout)
	result, err := revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: refreshToken,
	})

	if err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	if result.SessionID == "" {
		t.Error("SessionID should not be empty")
	}

	// Verify session is revoked
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(sessions) != 0 {
		t.Errorf("Expected 0 active sessions, got %d", len(sessions))
	}

	// Verify cache invalidated
	if sessionCache.Calls.Delete == 0 {
		t.Error("Session cache Delete should have been called")
	}

	// Verify event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeSessionRevoked] {
		t.Error("Missing session.revoked event")
	}
}

func TestRevokeTokenFlow_InvalidToken(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	_, err := revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: "invalid-refresh-token",
	})

	if err != domainerror.ErrSessionNotFound {
		t.Errorf("RevokeToken() error = %v, want %v", err, domainerror.ErrSessionNotFound)
	}
}

func TestRevokeTokenFlow_EmptyToken(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	_, err := revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: "",
	})

	if err != domainerror.ErrRefreshTokenRequired {
		t.Errorf("RevokeToken() error = %v, want %v", err, domainerror.ErrRefreshTokenRequired)
	}
}

func TestRevokeTokenFlow_AlreadyRevoked(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	challengeConfig := model.ChallengeConfig{
		Domain:            "test-domain",
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}
	sessionConfig := model.DefaultSessionConfig()

	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)
	verifyAuthHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)
	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	// Create and authenticate user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResult, _ := verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	refreshToken := verifyResult.RefreshToken

	// Revoke first time
	result1, err := revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: refreshToken,
	})
	if err != nil {
		t.Fatalf("First RevokeToken() error = %v", err)
	}

	// Revoke second time (should be idempotent)
	result2, err := revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: refreshToken,
	})

	if err != nil {
		t.Errorf("Second RevokeToken() error = %v, want nil (idempotent)", err)
	}

	// Both should return same session ID
	if result1.SessionID != result2.SessionID {
		t.Errorf("Session IDs should match: %v != %v", result1.SessionID, result2.SessionID)
	}
}

func TestRevokeTokenFlow_RefreshTokenCannotBeUsedAfterRevoke(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	challengeConfig := model.ChallengeConfig{
		Domain:            "test-domain",
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}
	sessionConfig := model.DefaultSessionConfig()

	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)
	verifyAuthHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)
	refreshTokenHandler := appcommand.NewRefreshTokenHandler(userRepo, sessionRepo, tokenService, publisher, sessionConfig)
	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	// Create and authenticate user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResult, _ := verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	refreshToken := verifyResult.RefreshToken

	// Revoke the token
	_, _ = revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: refreshToken,
	})

	// Try to use the refresh token
	_, err := refreshTokenHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: refreshToken,
	})

	if err != domainerror.ErrSessionRevoked {
		t.Errorf("RefreshToken() after revoke error = %v, want %v", err, domainerror.ErrSessionRevoked)
	}
}

func TestRevokeTokenFlow_DoesNotAffectOtherSessions(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	challengeConfig := model.ChallengeConfig{
		Domain:            "test-domain",
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}
	sessionConfig := model.DefaultSessionConfig()

	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)
	verifyAuthHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)
	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Create 3 sessions
	var refreshTokens []string
	for i := 0; i < 3; i++ {
		authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
		signature, _ := kp.Sign([]byte(authResult.Message))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)

		verifyResult, _ := verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
			DID:         did.String(),
			ChallengeID: authResult.ChallengeID,
			Signature:   signatureB64,
			TenantID:    types.None[types.ID](),
		})
		refreshTokens = append(refreshTokens, verifyResult.RefreshToken)
	}

	// Verify 3 active sessions
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(sessions) != 3 {
		t.Fatalf("Expected 3 sessions, got %d", len(sessions))
	}

	// Revoke only the first token
	_, _ = revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: refreshTokens[0],
	})

	// Should have 2 active sessions
	activeSessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(activeSessions) != 2 {
		t.Errorf("Expected 2 active sessions, got %d", len(activeSessions))
	}
}

func TestRevokeTokenFlow_LogoutFlow(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionCache := mocks.NewSessionCache()

	challengeConfig := model.ChallengeConfig{
		Domain:            "test-domain",
		ChallengeDuration: 5 * time.Minute,
		NonceLength:       32,
	}
	sessionConfig := model.DefaultSessionConfig()

	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)
	verifyAuthHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)
	refreshTokenHandler := appcommand.NewRefreshTokenHandler(userRepo, sessionRepo, tokenService, publisher, sessionConfig)
	revokeTokenHandler := appcommand.NewRevokeTokenHandler(sessionRepo, sessionCache, tokenService, publisher)

	// Create and authenticate user (login)
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	verifyResult, _ := verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	// User is now logged in with tokens
	accessToken := verifyResult.AccessToken
	refreshToken := verifyResult.RefreshToken

	// Verify access token is valid
	claims, err := tokenService.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("Access token should be valid: %v", err)
	}
	if claims.UserID != user.ID() {
		t.Errorf("Claims UserID = %v, want %v", claims.UserID, user.ID())
	}

	// Simulate some activity - refresh token
	refreshResult, _ := refreshTokenHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: refreshToken,
	})
	newRefreshToken := refreshResult.RefreshToken

	// User decides to logout
	_, err = revokeTokenHandler.Handle(ctx, command.RevokeToken{
		RefreshToken: newRefreshToken,
	})
	if err != nil {
		t.Fatalf("Logout (RevokeToken) error = %v", err)
	}

	// Session is now revoked - refresh should fail
	_, err = refreshTokenHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: newRefreshToken,
	})
	if err != domainerror.ErrSessionRevoked {
		t.Errorf("Refresh after logout error = %v, want %v", err, domainerror.ErrSessionRevoked)
	}

	// Note: Access token may still be "valid" cryptographically until it expires
	// In a real system, you'd check against a blacklist or session validity
}
