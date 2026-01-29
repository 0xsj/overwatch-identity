package e2e

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"
	"github.com/nats-io/nats.go"

	natsadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/nats"
	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	appcommand "github.com/0xsj/overwatch-identity/internal/app/command"
	"github.com/0xsj/overwatch-identity/internal/app/service"
	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

func TestRegistrationFlow_Success(t *testing.T) {
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

	registerHandler := appcommand.NewRegisterUserHandler(userRepo, challengeRepo, challengeConfig)
	verifyHandler := appcommand.NewVerifyRegistrationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.>")
	defer cleanup()

	// Generate keypair for test user
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	// Step 1: Initiate registration
	registerResult, err := registerHandler.Handle(ctx, command.RegisterUser{
		DID: did.String(),
	})
	if err != nil {
		t.Fatalf("RegisterUser() error = %v", err)
	}

	if registerResult.ChallengeID.IsEmpty() {
		t.Error("ChallengeID should not be empty")
	}
	if registerResult.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if registerResult.Message == "" {
		t.Error("Message should not be empty")
	}
	if registerResult.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}

	// Step 2: Sign the challenge message
	signature, err := kp.Sign([]byte(registerResult.Message))
	if err != nil {
		t.Fatalf("failed to sign message: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Step 3: Verify registration
	verifyResult, err := verifyHandler.Handle(ctx, command.VerifyRegistration{
		DID:         did.String(),
		ChallengeID: registerResult.ChallengeID,
		Signature:   signatureB64,
	})
	if err != nil {
		t.Fatalf("VerifyRegistration() error = %v", err)
	}

	// Verify result
	if verifyResult.User == nil {
		t.Fatal("User should not be nil")
	}
	if verifyResult.User.DID().String() != did.String() {
		t.Errorf("User DID = %v, want %v", verifyResult.User.DID().String(), did.String())
	}
	if verifyResult.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if verifyResult.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
	if verifyResult.AccessTokenExpiresAt.IsZero() {
		t.Error("AccessTokenExpiresAt should not be zero")
	}

	// Verify user persisted
	persistedUser, err := userRepo.FindByDID(ctx, did.String())
	if err != nil {
		t.Fatalf("FindByDID() error = %v", err)
	}
	if persistedUser.ID() != verifyResult.User.ID() {
		t.Errorf("Persisted user ID = %v, want %v", persistedUser.ID(), verifyResult.User.ID())
	}

	// Verify session persisted
	sessions, err := sessionRepo.FindActiveByUserID(ctx, verifyResult.User.ID())
	if err != nil {
		t.Fatalf("FindActiveByUserID() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("Expected 1 active session, got %d", len(sessions))
	}

	// Verify challenge consumed
	_, err = challengeRepo.FindByID(ctx, registerResult.ChallengeID)
	if err != repository.ErrNotFound {
		t.Errorf("Challenge should be deleted after use, error = %v", err)
	}

	// Verify events published (give some time for async delivery)
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)

	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeUserRegistered] {
		t.Error("Missing user.registered event")
	}
	if !eventTypes[event.EventTypeSessionCreated] {
		t.Error("Missing session.created event")
	}
	if !eventTypes[event.EventTypeAuthenticationSucceeded] {
		t.Error("Missing auth.succeeded event")
	}
}

func TestRegistrationFlow_UserAlreadyExists(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challengeConfig := model.DefaultChallengeConfig()
	registerHandler := appcommand.NewRegisterUserHandler(userRepo, challengeRepo, challengeConfig)

	// Create existing user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	existingUser, _ := model.NewUser(did)
	userRepo.Create(ctx, existingUser)

	// Try to register same DID
	_, err := registerHandler.Handle(ctx, command.RegisterUser{
		DID: did.String(),
	})

	if err != domainerror.ErrUserAlreadyExists {
		t.Errorf("RegisterUser() error = %v, want %v", err, domainerror.ErrUserAlreadyExists)
	}
}

func TestRegistrationFlow_InvalidDID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challengeConfig := model.DefaultChallengeConfig()
	registerHandler := appcommand.NewRegisterUserHandler(userRepo, challengeRepo, challengeConfig)

	_, err := registerHandler.Handle(ctx, command.RegisterUser{
		DID: "invalid-did",
	})

	if err != domainerror.ErrUserDIDRequired {
		t.Errorf("RegisterUser() error = %v, want %v", err, domainerror.ErrUserDIDRequired)
	}
}

func TestRegistrationFlow_InvalidSignature(t *testing.T) {
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

	registerHandler := appcommand.NewRegisterUserHandler(userRepo, challengeRepo, challengeConfig)
	verifyHandler := appcommand.NewVerifyRegistrationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Generate keypair
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)

	// Initiate registration
	registerResult, _ := registerHandler.Handle(ctx, command.RegisterUser{
		DID: did.String(),
	})

	// Sign with wrong key
	wrongKP, _ := security.GenerateEd25519()
	wrongSignature, _ := wrongKP.Sign([]byte(registerResult.Message))
	wrongSignatureB64 := base64.StdEncoding.EncodeToString(wrongSignature)

	// Verify should fail
	_, err := verifyHandler.Handle(ctx, command.VerifyRegistration{
		DID:         did.String(),
		ChallengeID: registerResult.ChallengeID,
		Signature:   wrongSignatureB64,
	})

	if err != domainerror.ErrSignatureInvalid {
		t.Errorf("VerifyRegistration() error = %v, want %v", err, domainerror.ErrSignatureInvalid)
	}
}

func TestRegistrationFlow_ExpiredChallenge(t *testing.T) {
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

	verifyHandler := appcommand.NewVerifyRegistrationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Generate keypair
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)

	// Create expired challenge directly in DB
	expiredChallengeID := types.NewID()
	_, err := getPool().Exec(ctx, `
		INSERT INTO challenges (id, did, nonce, purpose, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, expiredChallengeID.String(), did.String(), "testnonce", "register",
		time.Now().Add(-time.Hour), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("failed to insert expired challenge: %v", err)
	}

	// Build message and sign
	message := buildChallengeMessage(challengeConfig.Domain, did.String(), "testnonce")
	signature, _ := kp.Sign([]byte(message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Verify should fail
	_, err = verifyHandler.Handle(ctx, command.VerifyRegistration{
		DID:         did.String(),
		ChallengeID: expiredChallengeID,
		Signature:   signatureB64,
	})

	if err != domainerror.ErrChallengeExpired {
		t.Errorf("VerifyRegistration() error = %v, want %v", err, domainerror.ErrChallengeExpired)
	}
}

func TestRegistrationFlow_ChallengeNotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")
	tokenService := createTestTokenService(t)

	sessionConfig := model.DefaultSessionConfig()

	verifyHandler := appcommand.NewVerifyRegistrationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		"test-domain", sessionConfig,
	)

	// Generate keypair
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)

	signature, _ := kp.Sign([]byte("some message"))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Verify with non-existent challenge
	_, err := verifyHandler.Handle(ctx, command.VerifyRegistration{
		DID:         did.String(),
		ChallengeID: types.NewID(), // Non-existent
		Signature:   signatureB64,
	})

	if err != domainerror.ErrChallengeNotFound {
		t.Errorf("VerifyRegistration() error = %v, want %v", err, domainerror.ErrChallengeNotFound)
	}
}

func TestRegistrationFlow_DIDMismatch(t *testing.T) {
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

	registerHandler := appcommand.NewRegisterUserHandler(userRepo, challengeRepo, challengeConfig)
	verifyHandler := appcommand.NewVerifyRegistrationHandler(
		userRepo, sessionRepo, challengeRepo, tokenService, publisher,
		challengeConfig.Domain, sessionConfig,
	)

	// Generate two different keypairs
	kp1, _ := security.GenerateEd25519()
	did1, _ := security.DIDFromKeyPair(kp1)

	kp2, _ := security.GenerateEd25519()
	did2, _ := security.DIDFromKeyPair(kp2)

	// Register with did1
	registerResult, _ := registerHandler.Handle(ctx, command.RegisterUser{
		DID: did1.String(),
	})

	// Try to verify with did2
	signature, _ := kp2.Sign([]byte(registerResult.Message))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	_, err := verifyHandler.Handle(ctx, command.VerifyRegistration{
		DID:         did2.String(), // Different DID
		ChallengeID: registerResult.ChallengeID,
		Signature:   signatureB64,
	})

	if err != domainerror.ErrChallengeDIDMismatch {
		t.Errorf("VerifyRegistration() error = %v, want %v", err, domainerror.ErrChallengeDIDMismatch)
	}
}

func TestRegistrationFlow_CleansUpOldChallenges(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challengeConfig := model.DefaultChallengeConfig()
	registerHandler := appcommand.NewRegisterUserHandler(userRepo, challengeRepo, challengeConfig)

	// Generate keypair
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)

	// Register first time - creates challenge
	result1, _ := registerHandler.Handle(ctx, command.RegisterUser{
		DID: did.String(),
	})

	// Register second time - should clean up old challenge
	result2, _ := registerHandler.Handle(ctx, command.RegisterUser{
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

// --- Helpers ---

func createTestTokenService(t *testing.T) service.TokenService {
	t.Helper()

	// Generate a random signing key for tests
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1) // Simple deterministic key for tests
	}

	tokenService, err := service.NewTokenService(service.TokenConfig{
		SigningKey:          signingKey,
		Issuer:              "test-issuer",
		Audience:            "test-audience",
		AccessTokenDuration: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}

	return tokenService
}

func buildChallengeMessage(domain, did, nonce string) string {
	// Match the format used by Challenge.Message()
	return domain + " authentication challenge\n" +
		"DID: " + did + "\n" +
		"Nonce: " + nonce
}

func extractEventTypes(t *testing.T, messages []*nats.Msg) map[string]bool {
	t.Helper()

	eventTypes := make(map[string]bool)
	for _, msg := range messages {
		var envelope struct {
			EventType string `json:"event_type"`
		}
		if err := json.Unmarshal(msg.Data, &envelope); err != nil {
			t.Logf("failed to unmarshal message: %v", err)
			continue
		}
		eventTypes[envelope.EventType] = true
	}
	return eventTypes
}
