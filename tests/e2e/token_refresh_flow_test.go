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
)

func TestTokenRefreshFlow_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

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
	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

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

	// Drain authentication events
	time.Sleep(50 * time.Millisecond)
	drainMessages(msgChan)

	originalAccessToken := verifyResult.AccessToken
	originalRefreshToken := verifyResult.RefreshToken

	// Refresh token
	refreshResult, err := refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: originalRefreshToken,
	})

	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	// Verify new tokens issued
	if refreshResult.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if refreshResult.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
	if refreshResult.AccessToken == originalAccessToken {
		t.Error("New access token should be different from original")
	}
	if refreshResult.RefreshToken == originalRefreshToken {
		t.Error("New refresh token should be different from original")
	}

	// Verify new access token is valid
	claims, err := tokenService.ValidateAccessToken(refreshResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}
	if claims.UserID != user.ID() {
		t.Errorf("Token UserID = %v, want %v", claims.UserID, user.ID())
	}

	// Verify event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeTokenRefreshed] {
		t.Error("Missing token.refreshed event")
	}
}

func TestTokenRefreshFlow_InvalidRefreshToken(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionConfig := model.DefaultSessionConfig()

	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

	_, err := refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: "invalid-refresh-token",
	})

	if err != domainerror.ErrRefreshTokenInvalid {
		t.Errorf("RefreshToken() error = %v, want %v", err, domainerror.ErrRefreshTokenInvalid)
	}
}

func TestTokenRefreshFlow_EmptyRefreshToken(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)
	sessionConfig := model.DefaultSessionConfig()

	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

	_, err := refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: "",
	})

	if err != domainerror.ErrRefreshTokenInvalid {
		t.Errorf("RefreshToken() error = %v, want %v", err, domainerror.ErrRefreshTokenInvalid)
	}
}

func TestTokenRefreshFlow_RevokedSession(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

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
	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

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

	// Revoke the session directly
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	sessionRepo.RevokeByID(ctx, sessions[0].ID())

	// Try to refresh with revoked session
	_, err := refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: verifyResult.RefreshToken,
	})

	if err != domainerror.ErrSessionRevoked {
		t.Errorf("RefreshToken() error = %v, want %v", err, domainerror.ErrSessionRevoked)
	}
}

func TestTokenRefreshFlow_SuspendedUser(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

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
	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

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

	// Suspend the user
	user.Suspend()
	userRepo.Update(ctx, user)

	// Try to refresh with suspended user
	_, err := refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: verifyResult.RefreshToken,
	})

	if err != domainerror.ErrUserSuspended {
		t.Errorf("RefreshToken() error = %v, want %v", err, domainerror.ErrUserSuspended)
	}
}

func TestTokenRefreshFlow_OldRefreshTokenInvalidAfterRefresh(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

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
	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

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

	originalRefreshToken := verifyResult.RefreshToken

	// Refresh once - this invalidates the original refresh token
	_, err := refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: originalRefreshToken,
	})
	if err != nil {
		t.Fatalf("First refresh failed: %v", err)
	}

	// Try to use the old refresh token again
	_, err = refreshHandler.Handle(ctx, command.RefreshToken{
		RefreshToken: originalRefreshToken,
	})

	if err != domainerror.ErrRefreshTokenInvalid {
		t.Errorf("RefreshToken() with old token error = %v, want %v", err, domainerror.ErrRefreshTokenInvalid)
	}
}

func TestTokenRefreshFlow_MultipleRefreshes(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

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
	refreshHandler := appcommand.NewRefreshTokenHandler(
		userRepo, sessionRepo, tokenService, publisher, sessionConfig,
	)

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

	currentRefreshToken := verifyResult.RefreshToken

	// Refresh multiple times in succession
	for i := 0; i < 5; i++ {
		refreshResult, err := refreshHandler.Handle(ctx, command.RefreshToken{
			RefreshToken: currentRefreshToken,
		})
		if err != nil {
			t.Fatalf("Refresh %d failed: %v", i, err)
		}

		if refreshResult.RefreshToken == currentRefreshToken {
			t.Errorf("Refresh %d: new token should be different", i)
		}

		currentRefreshToken = refreshResult.RefreshToken
	}

	// Verify still only 1 session
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session after multiple refreshes, got %d", len(sessions))
	}
}
