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

func TestRevokeSessionFlow_Success(t *testing.T) {
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
	revokeSessionHandler := appcommand.NewRevokeSessionHandler(sessionRepo, sessionCache, publisher)

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

	_, _ = verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	// Get the session
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}
	sessionID := sessions[0].ID()

	// Drain authentication events
	time.Sleep(50 * time.Millisecond)
	drainMessages(msgChan)

	// Revoke the session
	_, err := revokeSessionHandler.Handle(ctx, command.RevokeSession{
		SessionID: sessionID,
		UserID:    user.ID(),
		Reason:    "user logout",
	})

	if err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	// Verify session is revoked
	revokedSession, err := sessionRepo.FindByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if !revokedSession.IsRevoked() {
		t.Error("Session should be revoked")
	}

	// Verify no active sessions
	activeSessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(activeSessions) != 0 {
		t.Errorf("Expected 0 active sessions, got %d", len(activeSessions))
	}

	// Verify cache Delete was called
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

func TestRevokeSessionFlow_SessionNotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	sessionCache := mocks.NewSessionCache()

	revokeSessionHandler := appcommand.NewRevokeSessionHandler(sessionRepo, sessionCache, publisher)

	_, err := revokeSessionHandler.Handle(ctx, command.RevokeSession{
		SessionID: types.NewID(),
		UserID:    types.NewID(),
		Reason:    "test",
	})

	if err != domainerror.ErrSessionNotFound {
		t.Errorf("RevokeSession() error = %v, want %v", err, domainerror.ErrSessionNotFound)
	}
}

func TestRevokeSessionFlow_EmptySessionID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	sessionCache := mocks.NewSessionCache()

	revokeSessionHandler := appcommand.NewRevokeSessionHandler(sessionRepo, sessionCache, publisher)

	var emptySessionID types.ID
	_, err := revokeSessionHandler.Handle(ctx, command.RevokeSession{
		SessionID: emptySessionID,
		UserID:    types.NewID(),
		Reason:    "test",
	})

	if err != domainerror.ErrSessionIDRequired {
		t.Errorf("RevokeSession() error = %v, want %v", err, domainerror.ErrSessionIDRequired)
	}
}

func TestRevokeSessionFlow_WrongUser(t *testing.T) {
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
	revokeSessionHandler := appcommand.NewRevokeSessionHandler(sessionRepo, sessionCache, publisher)

	// Create and authenticate user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, _ = verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	// Get the session
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	sessionID := sessions[0].ID()

	// Try to revoke with different user ID
	otherUserID := types.NewID()
	_, err := revokeSessionHandler.Handle(ctx, command.RevokeSession{
		SessionID: sessionID,
		UserID:    otherUserID,
		Reason:    "test",
	})

	if err != domainerror.ErrSessionNotFound {
		t.Errorf("RevokeSession() with wrong user error = %v, want %v", err, domainerror.ErrSessionNotFound)
	}
}

func TestRevokeSessionFlow_AlreadyRevoked(t *testing.T) {
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
	revokeSessionHandler := appcommand.NewRevokeSessionHandler(sessionRepo, sessionCache, publisher)

	// Create and authenticate user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, _ = verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	// Get the session
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	sessionID := sessions[0].ID()

	// Revoke first time
	_, _ = revokeSessionHandler.Handle(ctx, command.RevokeSession{
		SessionID: sessionID,
		UserID:    user.ID(),
		Reason:    "first revoke",
	})

	// Try to revoke again
	_, err := revokeSessionHandler.Handle(ctx, command.RevokeSession{
		SessionID: sessionID,
		UserID:    user.ID(),
		Reason:    "second revoke",
	})

	if err != domainerror.ErrSessionRevoked {
		t.Errorf("RevokeSession() already revoked error = %v, want %v", err, domainerror.ErrSessionRevoked)
	}
}

func TestRevokeAllSessionsFlow_Success(t *testing.T) {
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
	revokeAllHandler := appcommand.NewRevokeAllSessionsHandler(sessionRepo, sessionCache, publisher)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.>")
	defer cleanup()

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Create multiple sessions (simulate multiple devices)
	for i := 0; i < 5; i++ {
		authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did.String()})
		signature, _ := kp.Sign([]byte(authResult.Message))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)

		_, _ = verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
			DID:         did.String(),
			ChallengeID: authResult.ChallengeID,
			Signature:   signatureB64,
			TenantID:    types.None[types.ID](),
		})
	}

	// Verify 5 sessions exist
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(sessions) != 5 {
		t.Fatalf("Expected 5 sessions, got %d", len(sessions))
	}

	// Drain authentication events
	time.Sleep(50 * time.Millisecond)
	drainMessages(msgChan)

	// Revoke all sessions
	result, err := revokeAllHandler.Handle(ctx, command.RevokeAllSessions{
		UserID: user.ID(),
	})

	if err != nil {
		t.Fatalf("RevokeAllSessions() error = %v", err)
	}

	if result.RevokedCount != 5 {
		t.Errorf("RevokedCount = %d, want 5", result.RevokedCount)
	}

	// Verify no active sessions
	activeSessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(activeSessions) != 0 {
		t.Errorf("Expected 0 active sessions, got %d", len(activeSessions))
	}

	// Verify cache DeleteByUserID was called
	if sessionCache.Calls.DeleteByUserID == 0 {
		t.Error("Session cache DeleteByUserID should have been called")
	}

	// Verify event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeSessionsRevokedAll] {
		t.Error("Missing sessions.revoked_all event")
	}
}

func TestRevokeAllSessionsFlow_EmptyUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	sessionCache := mocks.NewSessionCache()

	revokeAllHandler := appcommand.NewRevokeAllSessionsHandler(sessionRepo, sessionCache, publisher)

	var emptyUserID types.ID
	_, err := revokeAllHandler.Handle(ctx, command.RevokeAllSessions{
		UserID: emptyUserID,
	})

	if err != domainerror.ErrUserIDRequired {
		t.Errorf("RevokeAllSessions() error = %v, want %v", err, domainerror.ErrUserIDRequired)
	}
}

func TestRevokeAllSessionsFlow_NoSessions(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	sessionCache := mocks.NewSessionCache()

	revokeAllHandler := appcommand.NewRevokeAllSessionsHandler(sessionRepo, sessionCache, publisher)

	// Create user without sessions
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Revoke all (none exist)
	result, err := revokeAllHandler.Handle(ctx, command.RevokeAllSessions{
		UserID: user.ID(),
	})

	if err != nil {
		t.Fatalf("RevokeAllSessions() error = %v", err)
	}

	if result.RevokedCount != 0 {
		t.Errorf("RevokedCount = %d, want 0", result.RevokedCount)
	}
}

func TestRevokeAllSessionsFlow_DoesNotAffectOtherUsers(t *testing.T) {
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
	revokeAllHandler := appcommand.NewRevokeAllSessionsHandler(sessionRepo, sessionCache, publisher)

	// Create user 1 with sessions
	kp1, _ := security.GenerateEd25519()
	did1, _ := security.DIDFromKeyPair(kp1)
	user1, _ := model.NewUser(did1)
	userRepo.Create(ctx, user1)

	for i := 0; i < 3; i++ {
		authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did1.String()})
		signature, _ := kp1.Sign([]byte(authResult.Message))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)
		_, _ = verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
			DID:         did1.String(),
			ChallengeID: authResult.ChallengeID,
			Signature:   signatureB64,
			TenantID:    types.None[types.ID](),
		})
	}

	// Create user 2 with sessions
	kp2, _ := security.GenerateEd25519()
	did2, _ := security.DIDFromKeyPair(kp2)
	user2, _ := model.NewUser(did2)
	userRepo.Create(ctx, user2)

	for i := 0; i < 2; i++ {
		authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{DID: did2.String()})
		signature, _ := kp2.Sign([]byte(authResult.Message))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)
		_, _ = verifyAuthHandler.Handle(ctx, command.VerifyAuthentication{
			DID:         did2.String(),
			ChallengeID: authResult.ChallengeID,
			Signature:   signatureB64,
			TenantID:    types.None[types.ID](),
		})
	}

	// Revoke all sessions for user 1
	result, _ := revokeAllHandler.Handle(ctx, command.RevokeAllSessions{
		UserID: user1.ID(),
	})

	if result.RevokedCount != 3 {
		t.Errorf("RevokedCount = %d, want 3", result.RevokedCount)
	}

	// User 1 should have no active sessions
	user1Sessions, _ := sessionRepo.FindActiveByUserID(ctx, user1.ID())
	if len(user1Sessions) != 0 {
		t.Errorf("User 1 should have 0 active sessions, got %d", len(user1Sessions))
	}

	// User 2 should still have sessions
	user2Sessions, _ := sessionRepo.FindActiveByUserID(ctx, user2.ID())
	if len(user2Sessions) != 2 {
		t.Errorf("User 2 should have 2 active sessions, got %d", len(user2Sessions))
	}
}
