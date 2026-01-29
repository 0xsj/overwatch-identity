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
	appquery "github.com/0xsj/overwatch-identity/internal/app/query"
	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/tests/testutil/mocks"
)

// --- GetUser Tests ---

func TestGetUserQuery_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserHandler := appquery.NewGetUserHandler(userRepo, userCache)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Query user
	result, err := getUserHandler.Handle(ctx, query.GetUser{
		UserID: user.ID(),
	})

	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if result.User == nil {
		t.Fatal("User should not be nil")
	}
	if result.User.ID() != user.ID() {
		t.Errorf("User ID = %v, want %v", result.User.ID(), user.ID())
	}

	// Verify cache was populated
	if userCache.Calls.Set == 0 {
		t.Error("Cache Set should have been called")
	}
}

func TestGetUserQuery_FromCache(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserHandler := appquery.NewGetUserHandler(userRepo, userCache)

	// Create user and seed cache
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)
	userCache.Seed(user)

	// Query user
	result, err := getUserHandler.Handle(ctx, query.GetUser{
		UserID: user.ID(),
	})

	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if result.User.ID() != user.ID() {
		t.Errorf("User ID = %v, want %v", result.User.ID(), user.ID())
	}

	// Verify cache was hit (Get called but Set not called again)
	if userCache.Calls.Get == 0 {
		t.Error("Cache Get should have been called")
	}
}

func TestGetUserQuery_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserHandler := appquery.NewGetUserHandler(userRepo, userCache)

	_, err := getUserHandler.Handle(ctx, query.GetUser{
		UserID: types.NewID(),
	})

	if err != domainerror.ErrUserNotFound {
		t.Errorf("GetUser() error = %v, want %v", err, domainerror.ErrUserNotFound)
	}
}

func TestGetUserQuery_EmptyUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserHandler := appquery.NewGetUserHandler(userRepo, userCache)

	var emptyUserID types.ID
	_, err := getUserHandler.Handle(ctx, query.GetUser{
		UserID: emptyUserID,
	})

	if err != domainerror.ErrUserIDRequired {
		t.Errorf("GetUser() error = %v, want %v", err, domainerror.ErrUserIDRequired)
	}
}

// --- GetUserByDID Tests ---

func TestGetUserByDIDQuery_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserByDIDHandler := appquery.NewGetUserByDIDHandler(userRepo, userCache)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Query user
	result, err := getUserByDIDHandler.Handle(ctx, query.GetUserByDID{
		DID: did.String(),
	})

	if err != nil {
		t.Fatalf("GetUserByDID() error = %v", err)
	}
	if result.User == nil {
		t.Fatal("User should not be nil")
	}
	if result.User.DID().String() != did.String() {
		t.Errorf("User DID = %v, want %v", result.User.DID().String(), did.String())
	}
}

func TestGetUserByDIDQuery_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserByDIDHandler := appquery.NewGetUserByDIDHandler(userRepo, userCache)

	_, err := getUserByDIDHandler.Handle(ctx, query.GetUserByDID{
		DID: "did:key:nonexistent",
	})

	if err != domainerror.ErrUserNotFound {
		t.Errorf("GetUserByDID() error = %v, want %v", err, domainerror.ErrUserNotFound)
	}
}

func TestGetUserByDIDQuery_EmptyDID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()

	getUserByDIDHandler := appquery.NewGetUserByDIDHandler(userRepo, userCache)

	_, err := getUserByDIDHandler.Handle(ctx, query.GetUserByDID{
		DID: "",
	})

	if err != domainerror.ErrUserDIDRequired {
		t.Errorf("GetUserByDID() error = %v, want %v", err, domainerror.ErrUserDIDRequired)
	}
}

// --- GetSession Tests ---

func TestGetSessionQuery_Success(t *testing.T) {
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
	getSessionHandler := appquery.NewGetSessionHandler(sessionRepo, sessionCache)

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

	// Query session
	result, err := getSessionHandler.Handle(ctx, query.GetSession{
		SessionID: sessionID,
		UserID:    user.ID(),
	})

	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if result.Session == nil {
		t.Fatal("Session should not be nil")
	}
	if result.Session.ID() != sessionID {
		t.Errorf("Session ID = %v, want %v", result.Session.ID(), sessionID)
	}
}

func TestGetSessionQuery_WrongUser(t *testing.T) {
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
	getSessionHandler := appquery.NewGetSessionHandler(sessionRepo, sessionCache)

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

	// Query session with wrong user
	_, err := getSessionHandler.Handle(ctx, query.GetSession{
		SessionID: sessionID,
		UserID:    types.NewID(), // Wrong user
	})

	if err != domainerror.ErrSessionNotFound {
		t.Errorf("GetSession() with wrong user error = %v, want %v", err, domainerror.ErrSessionNotFound)
	}
}

func TestGetSessionQuery_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	sessionCache := mocks.NewSessionCache()

	getSessionHandler := appquery.NewGetSessionHandler(sessionRepo, sessionCache)

	_, err := getSessionHandler.Handle(ctx, query.GetSession{
		SessionID: types.NewID(),
		UserID:    types.NewID(),
	})

	if err != domainerror.ErrSessionNotFound {
		t.Errorf("GetSession() error = %v, want %v", err, domainerror.ErrSessionNotFound)
	}
}

// --- ListSessions Tests ---

func TestListSessionsQuery_Success(t *testing.T) {
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
	listSessionsHandler := appquery.NewListSessionsHandler(sessionRepo)

	// Create user with multiple sessions
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

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

	// List sessions
	result, err := listSessionsHandler.Handle(ctx, query.ListSessions{
		UserID:     user.ID(),
		Limit:      10,
		Offset:     0,
		ActiveOnly: false,
	})

	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(result.Sessions) != 5 {
		t.Errorf("Sessions count = %d, want 5", len(result.Sessions))
	}
	if result.TotalCount != 5 {
		t.Errorf("TotalCount = %d, want 5", result.TotalCount)
	}
}

func TestListSessionsQuery_ActiveOnly(t *testing.T) {
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
	listSessionsHandler := appquery.NewListSessionsHandler(sessionRepo)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Create 3 active sessions
	for i := 0; i < 3; i++ {
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

	// Revoke 1 session
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	sessionRepo.RevokeByID(ctx, sessions[0].ID())

	// List active sessions only
	result, err := listSessionsHandler.Handle(ctx, query.ListSessions{
		UserID:     user.ID(),
		Limit:      10,
		Offset:     0,
		ActiveOnly: true,
	})

	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(result.Sessions) != 2 {
		t.Errorf("Active sessions count = %d, want 2", len(result.Sessions))
	}
}

func TestListSessionsQuery_Pagination(t *testing.T) {
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
	listSessionsHandler := appquery.NewListSessionsHandler(sessionRepo)

	// Create user with 5 sessions
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

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

	// Page 1
	result1, _ := listSessionsHandler.Handle(ctx, query.ListSessions{
		UserID: user.ID(),
		Limit:  2,
		Offset: 0,
	})
	if len(result1.Sessions) != 2 {
		t.Errorf("Page 1 count = %d, want 2", len(result1.Sessions))
	}
	if result1.TotalCount != 5 {
		t.Errorf("TotalCount = %d, want 5", result1.TotalCount)
	}

	// Page 2
	result2, _ := listSessionsHandler.Handle(ctx, query.ListSessions{
		UserID: user.ID(),
		Limit:  2,
		Offset: 2,
	})
	if len(result2.Sessions) != 2 {
		t.Errorf("Page 2 count = %d, want 2", len(result2.Sessions))
	}

	// Page 3
	result3, _ := listSessionsHandler.Handle(ctx, query.ListSessions{
		UserID: user.ID(),
		Limit:  2,
		Offset: 4,
	})
	if len(result3.Sessions) != 1 {
		t.Errorf("Page 3 count = %d, want 1", len(result3.Sessions))
	}
}

func TestListSessionsQuery_EmptyUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	sessionRepo := postgres.NewSessionRepository(getPool())
	listSessionsHandler := appquery.NewListSessionsHandler(sessionRepo)

	var emptyUserID types.ID
	_, err := listSessionsHandler.Handle(ctx, query.ListSessions{
		UserID: emptyUserID,
	})

	if err != domainerror.ErrUserIDRequired {
		t.Errorf("ListSessions() error = %v, want %v", err, domainerror.ErrUserIDRequired)
	}
}

// --- GetAPIKey Tests ---

func TestGetAPIKeyQuery_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	getAPIKeyHandler := appquery.NewGetAPIKeyHandler(apiKeyRepo)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Query API key
	result, err := getAPIKeyHandler.Handle(ctx, query.GetAPIKey{
		APIKeyID: createResult.APIKey.ID(),
		UserID:   user.ID(),
	})

	if err != nil {
		t.Fatalf("GetAPIKey() error = %v", err)
	}
	if result.APIKey == nil {
		t.Fatal("APIKey should not be nil")
	}
	if result.APIKey.ID() != createResult.APIKey.ID() {
		t.Errorf("APIKey ID = %v, want %v", result.APIKey.ID(), createResult.APIKey.ID())
	}
}

func TestGetAPIKeyQuery_WrongUser(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	getAPIKeyHandler := appquery.NewGetAPIKeyHandler(apiKeyRepo)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Query with wrong user
	_, err := getAPIKeyHandler.Handle(ctx, query.GetAPIKey{
		APIKeyID: createResult.APIKey.ID(),
		UserID:   types.NewID(), // Wrong user
	})

	if err != domainerror.ErrAPIKeyNotFound {
		t.Errorf("GetAPIKey() with wrong user error = %v, want %v", err, domainerror.ErrAPIKeyNotFound)
	}
}

// --- ListAPIKeys Tests ---

func TestListAPIKeysQuery_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	listAPIKeysHandler := appquery.NewListAPIKeysHandler(apiKeyRepo)

	// Create user with multiple API keys
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	for i := 0; i < 5; i++ {
		createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
			UserID:    user.ID(),
			Name:      "Test Key",
			Scopes:    []string{"read:users"},
			TenantID:  types.None[types.ID](),
			ExpiresAt: types.None[types.Timestamp](),
		})
	}

	// List API keys
	result, err := listAPIKeysHandler.Handle(ctx, query.ListAPIKeys{
		UserID:     user.ID(),
		Limit:      10,
		Offset:     0,
		ActiveOnly: false,
		TenantID:   types.None[types.ID](),
	})

	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(result.APIKeys) != 5 {
		t.Errorf("APIKeys count = %d, want 5", len(result.APIKeys))
	}
	if result.TotalCount != 5 {
		t.Errorf("TotalCount = %d, want 5", result.TotalCount)
	}
}

func TestListAPIKeysQuery_ActiveOnly(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)
	listAPIKeysHandler := appquery.NewListAPIKeysHandler(apiKeyRepo)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Create 3 API keys
	var apiKeyIDs []types.ID
	for i := 0; i < 3; i++ {
		result, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
			UserID:    user.ID(),
			Name:      "Test Key",
			Scopes:    []string{"read:users"},
			TenantID:  types.None[types.ID](),
			ExpiresAt: types.None[types.Timestamp](),
		})
		apiKeyIDs = append(apiKeyIDs, result.APIKey.ID())
	}

	// Revoke 1
	revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: apiKeyIDs[0],
		UserID:   user.ID(),
	})

	// List active only
	result, err := listAPIKeysHandler.Handle(ctx, query.ListAPIKeys{
		UserID:     user.ID(),
		Limit:      10,
		Offset:     0,
		ActiveOnly: true,
		TenantID:   types.None[types.ID](),
	})

	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(result.APIKeys) != 2 {
		t.Errorf("Active APIKeys count = %d, want 2", len(result.APIKeys))
	}
}

// --- VerifyAPIKey Tests ---

func TestVerifyAPIKeyQuery_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	verifyAPIKeyHandler := appquery.NewVerifyAPIKeyHandler(apiKeyRepo, userRepo, publisher)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Verify API key
	result, err := verifyAPIKeyHandler.Handle(ctx, query.VerifyAPIKey{
		Key: createResult.Secret,
	})

	if err != nil {
		t.Fatalf("VerifyAPIKey() error = %v", err)
	}
	if result.APIKey == nil {
		t.Fatal("APIKey should not be nil")
	}
	if result.User == nil {
		t.Fatal("User should not be nil")
	}
	if result.APIKey.ID() != createResult.APIKey.ID() {
		t.Errorf("APIKey ID = %v, want %v", result.APIKey.ID(), createResult.APIKey.ID())
	}
	if result.User.ID() != user.ID() {
		t.Errorf("User ID = %v, want %v", result.User.ID(), user.ID())
	}

	// Verify usage was recorded
	updatedKey, _ := apiKeyRepo.FindByID(ctx, createResult.APIKey.ID())
	if !updatedKey.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should be present after verification")
	}
}

func TestVerifyAPIKeyQuery_InvalidKey(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	verifyAPIKeyHandler := appquery.NewVerifyAPIKeyHandler(apiKeyRepo, userRepo, publisher)

	_, err := verifyAPIKeyHandler.Handle(ctx, query.VerifyAPIKey{
		Key: "invalid-api-key",
	})

	if err != domainerror.ErrAPIKeyInvalid {
		t.Errorf("VerifyAPIKey() error = %v, want %v", err, domainerror.ErrAPIKeyInvalid)
	}
}

func TestVerifyAPIKeyQuery_EmptyKey(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	verifyAPIKeyHandler := appquery.NewVerifyAPIKeyHandler(apiKeyRepo, userRepo, publisher)

	_, err := verifyAPIKeyHandler.Handle(ctx, query.VerifyAPIKey{
		Key: "",
	})

	if err != domainerror.ErrAPIKeyInvalid {
		t.Errorf("VerifyAPIKey() error = %v, want %v", err, domainerror.ErrAPIKeyInvalid)
	}
}

func TestVerifyAPIKeyQuery_RevokedKey(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)
	verifyAPIKeyHandler := appquery.NewVerifyAPIKeyHandler(apiKeyRepo, userRepo, publisher)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Revoke the key
	revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: createResult.APIKey.ID(),
		UserID:   user.ID(),
	})

	// Try to verify revoked key
	_, err := verifyAPIKeyHandler.Handle(ctx, query.VerifyAPIKey{
		Key: createResult.Secret,
	})

	if err != domainerror.ErrAPIKeyRevoked {
		t.Errorf("VerifyAPIKey() revoked key error = %v, want %v", err, domainerror.ErrAPIKeyRevoked)
	}
}

func TestVerifyAPIKeyQuery_SuspendedUser(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	verifyAPIKeyHandler := appquery.NewVerifyAPIKeyHandler(apiKeyRepo, userRepo, publisher)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Suspend user
	user.Suspend()
	userRepo.Update(ctx, user)

	// Try to verify key for suspended user
	_, err := verifyAPIKeyHandler.Handle(ctx, query.VerifyAPIKey{
		Key: createResult.Secret,
	})

	if err != domainerror.ErrUserSuspended {
		t.Errorf("VerifyAPIKey() suspended user error = %v, want %v", err, domainerror.ErrUserSuspended)
	}
}
