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
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

func TestAuthenticationFlow_Success(t *testing.T) {
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
	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.>")
	defer cleanup()

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Step 1: Initiate authentication
	authResult, err := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if authResult.ChallengeID.IsEmpty() {
		t.Error("ChallengeID should not be empty")
	}
	if authResult.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if authResult.Message == "" {
		t.Error("Message should not be empty")
	}

	// Step 2: Sign the challenge message
	signature, err := kp.Sign([]byte(authResult.Message))
	if err != nil {
		t.Fatalf("failed to sign message: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Step 3: Verify authentication
	verifyResult, err := verifyHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication() error = %v", err)
	}

	// Verify result
	if verifyResult.User == nil {
		t.Fatal("User should not be nil")
	}
	if verifyResult.User.ID() != existingUser.ID() {
		t.Errorf("User ID = %v, want %v", verifyResult.User.ID(), existingUser.ID())
	}
	if verifyResult.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if verifyResult.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}

	// Verify session persisted
	sessions, err := sessionRepo.FindActiveByUserID(ctx, existingUser.ID())
	if err != nil {
		t.Fatalf("FindActiveByUserID() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("Expected 1 active session, got %d", len(sessions))
	}

	// Verify challenge consumed
	_, err = challengeRepo.FindByID(ctx, authResult.ChallengeID)
	if err != repository.ErrNotFound {
		t.Errorf("Challenge should be deleted after use, error = %v", err)
	}

	// Verify events published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)

	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeSessionCreated] {
		t.Error("Missing session.created event")
	}
	if !eventTypes[event.EventTypeAuthenticationSucceeded] {
		t.Error("Missing auth.succeeded event")
	}
}

func TestAuthenticationFlow_WithTenant(t *testing.T) {
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
	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Initiate authentication
	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})

	// Sign and verify with tenant
	signature, _ := kp.Sign([]byte(authResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	tenantID := types.NewID()
	verifyResult, err := verifyHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   signatureB64,
		TenantID:    types.Some(tenantID),
	})
	if err != nil {
		t.Fatalf("VerifyAuthentication() error = %v", err)
	}

	// Verify session has tenant
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, existingUser.ID())
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}
	if !sessions[0].TenantID().IsPresent() {
		t.Error("Session should have tenant ID")
	}
	if sessions[0].TenantID().MustGet() != tenantID {
		t.Errorf("Session tenant ID = %v, want %v", sessions[0].TenantID().MustGet(), tenantID)
	}

	// Verify token contains tenant
	claims, err := tokenService.ValidateAccessToken(verifyResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}
	if !claims.TenantID.IsPresent() {
		t.Error("Token should contain tenant ID")
	}
	if claims.TenantID.MustGet() != tenantID {
		t.Errorf("Token tenant ID = %v, want %v", claims.TenantID.MustGet(), tenantID)
	}
}

func TestAuthenticationFlow_UserNotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challengeConfig := model.DefaultChallengeConfig()
	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)

	// Try to authenticate non-existent user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)

	_, err := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})

	if err != domainerror.ErrUserNotFound {
		t.Errorf("Authenticate() error = %v, want %v", err, domainerror.ErrUserNotFound)
	}
}

func TestAuthenticationFlow_UserSuspended(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challengeConfig := model.DefaultChallengeConfig()
	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)

	// Create suspended user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	suspendedUser, _ := model.NewUser(did)
	suspendedUser.Suspend()
	userRepo.Create(ctx, suspendedUser)

	_, err := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})

	if err != domainerror.ErrUserSuspended {
		t.Errorf("Authenticate() error = %v, want %v", err, domainerror.ErrUserSuspended)
	}
}

func TestAuthenticationFlow_InvalidSignature(t *testing.T) {
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
	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Subscribe to events to check for auth failed
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.auth")
	defer cleanup()

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Initiate authentication
	authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})

	// Sign with wrong key
	wrongKP, _ := security.GenerateEd25519()
	wrongSignature, _ := wrongKP.Sign([]byte(authResult.Message))
	wrongSignatureB64 := base64.StdEncoding.EncodeToString(wrongSignature)

	// Verify should fail
	_, err := verifyHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: authResult.ChallengeID,
		Signature:   wrongSignatureB64,
		TenantID:    types.None[types.ID](),
	})

	if err != domainerror.ErrSignatureInvalid {
		t.Errorf("VerifyAuthentication() error = %v, want %v", err, domainerror.ErrSignatureInvalid)
	}

	// Verify auth failed event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeAuthenticationFailed] {
		t.Error("Missing auth.failed event")
	}
}

func TestAuthenticationFlow_ChallengeNotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

	sessionConfig := model.DefaultSessionConfig()

	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		"test-domain", sessionConfig,
	)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	signature, _ := kp.Sign([]byte("some message"))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Verify with non-existent challenge
	_, err := verifyHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: types.NewID(),
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	if err != domainerror.ErrChallengeNotFound {
		t.Errorf("VerifyAuthentication() error = %v, want %v", err, domainerror.ErrChallengeNotFound)
	}
}

func TestAuthenticationFlow_MultipleSessions(t *testing.T) {
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
	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Authenticate 3 times (simulating different devices)
	for i := 0; i < 3; i++ {
		authResult, _ := authenticateHandler.Handle(ctx, command.Authenticate{
			DID: did.String(),
		})

		signature, _ := kp.Sign([]byte(authResult.Message))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)

		_, err := verifyHandler.Handle(ctx, command.VerifyAuthentication{
			DID:         did.String(),
			ChallengeID: authResult.ChallengeID,
			Signature:   signatureB64,
			TenantID:    types.None[types.ID](),
		})
		if err != nil {
			t.Fatalf("VerifyAuthentication() iteration %d error = %v", i, err)
		}
	}

	// Verify 3 active sessions
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, existingUser.ID())
	if len(sessions) != 3 {
		t.Errorf("Expected 3 active sessions, got %d", len(sessions))
	}
}

func TestAuthenticationFlow_ExpiredChallenge(t *testing.T) {
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

	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Create expired challenge directly in DB
	expiredChallengeID := types.NewID()
	_, err := getPool().Exec(ctx, `
		INSERT INTO challenges (id, did, nonce, purpose, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, expiredChallengeID.String(), did.String(), "testnonce", "authenticate",
		time.Now().Add(-time.Hour), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("failed to insert expired challenge: %v", err)
	}

	message := buildChallengeMessage(challengeConfig.Domain, did.String(), "testnonce")
	signature, _ := kp.Sign([]byte(message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, err = verifyHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: expiredChallengeID,
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	if err != domainerror.ErrChallengeExpired {
		t.Errorf("VerifyAuthentication() error = %v, want %v", err, domainerror.ErrChallengeExpired)
	}
}

func TestAuthenticationFlow_WrongChallengePurpose(t *testing.T) {
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

	verifyHandler := appcommand.NewVerifyAuthenticationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Create a registration challenge (wrong purpose)
	registrationChallenge, _ := model.NewChallenge(did, model.ChallengePurposeRegister, challengeConfig)
	challengeRepo.Create(ctx, registrationChallenge)

	message := registrationChallenge.Message(challengeConfig.Domain)
	signature, _ := kp.Sign([]byte(message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Try to use registration challenge for authentication
	_, err := verifyHandler.Handle(ctx, command.VerifyAuthentication{
		DID:         did.String(),
		ChallengeID: registrationChallenge.ID(),
		Signature:   signatureB64,
		TenantID:    types.None[types.ID](),
	})

	if err != domainerror.ErrChallengeInvalid {
		t.Errorf("VerifyAuthentication() error = %v, want %v", err, domainerror.ErrChallengeInvalid)
	}
}

func TestAuthenticationFlow_CleansUpOldChallenges(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challengeConfig := model.DefaultChallengeConfig()
	authenticateHandler := appcommand.NewAuthenticateHandler(userRepo, challengeRepo, challengeConfig)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Authenticate first time
	result1, _ := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})

	// Authenticate second time - should clean up old challenge
	result2, _ := authenticateHandler.Handle(ctx, command.Authenticate{
		DID: did.String(),
	})

	// First challenge should be deleted
	_, err := challengeRepo.FindByID(ctx, result1.ChallengeID)
	if err != repository.ErrNotFound {
		t.Errorf("Old challenge should be deleted, error = %v", err)
	}

	// Second challenge should exist
	_, err = challengeRepo.FindByID(ctx, result2.ChallengeID)
	if err != nil {
		t.Errorf("New challenge should exist, error = %v", err)
	}
}
