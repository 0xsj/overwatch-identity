package grpc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0xsj/overwatch-pkg/grpc/middleware"
	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	commonv1 "github.com/0xsj/overwatch-contracts/gen/go/common/v1"
	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
)

// --- Ping Tests ---

func TestHandler_Ping(t *testing.T) {
	handler := NewHandler(HandlerConfig{})

	resp, err := handler.Ping(context.Background(), &identityv1.PingRequest{})

	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if resp.Message != "pong" {
		t.Errorf("Message = %v, want pong", resp.Message)
	}
}

// --- Register Tests ---

func TestHandler_Register(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockRegisterUserHandler{
			result: command.RegisterUserResult{
				ChallengeID: types.NewID(),
				Nonce:       "test-nonce",
				Message:     "Sign this message",
				ExpiresAt:   types.FromTime(time.Now().Add(5 * time.Minute)),
			},
		}

		handler := NewHandler(HandlerConfig{
			RegisterUserHandler: mockHandler,
		})

		resp, err := handler.Register(context.Background(), &identityv1.RegisterRequest{
			Did: "did:key:z6MkTest",
		})

		if err != nil {
			t.Fatalf("Register() error = %v", err)
		}
		if resp.ChallengeId == "" {
			t.Error("ChallengeId should not be empty")
		}
		if resp.Nonce != "test-nonce" {
			t.Errorf("Nonce = %v, want test-nonce", resp.Nonce)
		}
		if resp.Message != "Sign this message" {
			t.Errorf("Message = %v, want Sign this message", resp.Message)
		}
	})

	t.Run("with optional fields", func(t *testing.T) {
		mockHandler := &mockRegisterUserHandler{
			result: command.RegisterUserResult{
				ChallengeID: types.NewID(),
				Nonce:       "nonce",
				Message:     "message",
				ExpiresAt:   types.Now(),
			},
		}

		handler := NewHandler(HandlerConfig{
			RegisterUserHandler: mockHandler,
		})

		email := "test@example.com"
		name := "Test User"
		_, err := handler.Register(context.Background(), &identityv1.RegisterRequest{
			Did:   "did:key:z6MkTest",
			Email: &email,
			Name:  &name,
		})

		if err != nil {
			t.Fatalf("Register() error = %v", err)
		}

		// Verify optional fields were passed
		if !mockHandler.lastCmd.Email.IsPresent() {
			t.Error("Email should be present")
		}
		if !mockHandler.lastCmd.Name.IsPresent() {
			t.Error("Name should be present")
		}
	})

	t.Run("handler error", func(t *testing.T) {
		mockHandler := &mockRegisterUserHandler{
			err: status.Error(codes.AlreadyExists, "user already exists"),
		}

		handler := NewHandler(HandlerConfig{
			RegisterUserHandler: mockHandler,
		})

		_, err := handler.Register(context.Background(), &identityv1.RegisterRequest{
			Did: "did:key:z6MkTest",
		})

		if err == nil {
			t.Fatal("Expected error")
		}
	})
}

// --- VerifyRegistration Tests ---

func TestHandler_VerifyRegistration(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockVerifyRegistrationHandler{
			result: command.VerifyRegistrationResult{
				User:                 user,
				AccessToken:          "access-token",
				RefreshToken:         "refresh-token",
				AccessTokenExpiresAt: types.FromTime(time.Now().Add(15 * time.Minute)),
			},
		}

		handler := NewHandler(HandlerConfig{
			VerifyRegistrationHandler: mockHandler,
		})

		challengeID := types.NewID()
		resp, err := handler.VerifyRegistration(context.Background(), &identityv1.VerifyRegistrationRequest{
			ChallengeId: challengeID.String(),
			Did:         user.DID().String(),
			Signature:   "valid-signature",
		})

		if err != nil {
			t.Fatalf("VerifyRegistration() error = %v", err)
		}
		if resp.AccessToken != "access-token" {
			t.Errorf("AccessToken = %v, want access-token", resp.AccessToken)
		}
		if resp.RefreshToken != "refresh-token" {
			t.Errorf("RefreshToken = %v, want refresh-token", resp.RefreshToken)
		}
		if resp.User == nil {
			t.Error("User should not be nil")
		}
	})

	t.Run("invalid challenge_id", func(t *testing.T) {
		handler := NewHandler(HandlerConfig{})

		_, err := handler.VerifyRegistration(context.Background(), &identityv1.VerifyRegistrationRequest{
			ChallengeId: "invalid-uuid",
			Did:         "did:key:test",
			Signature:   "sig",
		})

		if err == nil {
			t.Fatal("Expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Code = %v, want InvalidArgument", st.Code())
		}
	})
}

// --- Authenticate Tests ---

func TestHandler_Authenticate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockAuthenticateHandler{
			result: command.AuthenticateResult{
				ChallengeID: types.NewID(),
				Nonce:       "auth-nonce",
				Message:     "Sign to authenticate",
				ExpiresAt:   types.FromTime(time.Now().Add(5 * time.Minute)),
			},
		}

		handler := NewHandler(HandlerConfig{
			AuthenticateHandler: mockHandler,
		})

		resp, err := handler.Authenticate(context.Background(), &identityv1.AuthenticateRequest{
			Did: "did:key:z6MkTest",
		})

		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if resp.ChallengeId == "" {
			t.Error("ChallengeId should not be empty")
		}
		if resp.Nonce != "auth-nonce" {
			t.Errorf("Nonce = %v, want auth-nonce", resp.Nonce)
		}
	})
}

// --- VerifyAuthentication Tests ---

func TestHandler_VerifyAuthentication(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockVerifyAuthenticationHandler{
			result: command.VerifyAuthenticationResult{
				User:                 user,
				AccessToken:          "access-token",
				RefreshToken:         "refresh-token",
				AccessTokenExpiresAt: types.FromTime(time.Now().Add(15 * time.Minute)),
			},
		}

		handler := NewHandler(HandlerConfig{
			VerifyAuthenticationHandler: mockHandler,
		})

		challengeID := types.NewID()
		resp, err := handler.VerifyAuthentication(context.Background(), &identityv1.VerifyAuthenticationRequest{
			ChallengeId: challengeID.String(),
			Did:         user.DID().String(),
			Signature:   "valid-signature",
		})

		if err != nil {
			t.Fatalf("VerifyAuthentication() error = %v", err)
		}
		if resp.AccessToken != "access-token" {
			t.Errorf("AccessToken = %v, want access-token", resp.AccessToken)
		}
		if resp.User == nil {
			t.Error("User should not be nil")
		}
	})

	t.Run("with tenant", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockVerifyAuthenticationHandler{
			result: command.VerifyAuthenticationResult{
				User:                 user,
				AccessToken:          "access-token",
				RefreshToken:         "refresh-token",
				AccessTokenExpiresAt: types.Now(),
			},
		}

		handler := NewHandler(HandlerConfig{
			VerifyAuthenticationHandler: mockHandler,
		})

		tenantID := types.NewID().String()
		challengeID := types.NewID()
		_, err := handler.VerifyAuthentication(context.Background(), &identityv1.VerifyAuthenticationRequest{
			ChallengeId: challengeID.String(),
			Did:         user.DID().String(),
			Signature:   "sig",
			TenantId:    &tenantID,
		})

		if err != nil {
			t.Fatalf("VerifyAuthentication() error = %v", err)
		}

		// Verify tenant was passed
		if !mockHandler.lastCmd.TenantID.IsPresent() {
			t.Error("TenantID should be present")
		}
	})
}

// --- RefreshToken Tests ---

func TestHandler_RefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockRefreshTokenHandler{
			result: command.RefreshTokenResult{
				AccessToken:          "new-access-token",
				RefreshToken:         "new-refresh-token",
				AccessTokenExpiresAt: types.FromTime(time.Now().Add(15 * time.Minute)),
			},
		}

		handler := NewHandler(HandlerConfig{
			RefreshTokenHandler: mockHandler,
		})

		resp, err := handler.RefreshToken(context.Background(), &identityv1.RefreshTokenRequest{
			RefreshToken: "old-refresh-token",
		})

		if err != nil {
			t.Fatalf("RefreshToken() error = %v", err)
		}
		if resp.AccessToken != "new-access-token" {
			t.Errorf("AccessToken = %v, want new-access-token", resp.AccessToken)
		}
		if resp.RefreshToken != "new-refresh-token" {
			t.Errorf("RefreshToken = %v, want new-refresh-token", resp.RefreshToken)
		}
	})
}

// --- RevokeToken Tests ---

func TestHandler_RevokeToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockRevokeTokenHandler{
			result: command.RevokeTokenResult{SessionID: "session-123"},
		}

		handler := NewHandler(HandlerConfig{
			RevokeTokenHandler: mockHandler,
		})

		_, err := handler.RevokeToken(context.Background(), &identityv1.RevokeTokenRequest{
			RefreshToken: "token-to-revoke",
		})

		if err != nil {
			t.Fatalf("RevokeToken() error = %v", err)
		}
	})
}

// --- GetCurrentUser Tests ---

func TestHandler_GetCurrentUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockGetUserHandler{
			result: query.GetUserResult{User: user},
		}

		handler := NewHandler(HandlerConfig{
			GetUserHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		resp, err := handler.GetCurrentUser(ctx, &identityv1.GetCurrentUserRequest{})

		if err != nil {
			t.Fatalf("GetCurrentUser() error = %v", err)
		}
		if resp.User == nil {
			t.Error("User should not be nil")
		}
		if resp.User.Id != user.ID().String() {
			t.Errorf("User.Id = %v, want %v", resp.User.Id, user.ID().String())
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		handler := NewHandler(HandlerConfig{})

		_, err := handler.GetCurrentUser(context.Background(), &identityv1.GetCurrentUserRequest{})

		if err == nil {
			t.Fatal("Expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.Unauthenticated {
			t.Errorf("Code = %v, want Unauthenticated", st.Code())
		}
	})
}

// --- GetUser Tests ---

func TestHandler_GetUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockGetUserHandler{
			result: query.GetUserResult{User: user},
		}

		handler := NewHandler(HandlerConfig{
			GetUserHandler: mockHandler,
		})

		resp, err := handler.GetUser(context.Background(), &identityv1.GetUserRequest{
			Id: user.ID().String(),
		})

		if err != nil {
			t.Fatalf("GetUser() error = %v", err)
		}
		if resp.User.Id != user.ID().String() {
			t.Errorf("User.Id = %v, want %v", resp.User.Id, user.ID().String())
		}
	})

	t.Run("invalid id", func(t *testing.T) {
		handler := NewHandler(HandlerConfig{})

		_, err := handler.GetUser(context.Background(), &identityv1.GetUserRequest{
			Id: "invalid-uuid",
		})

		if err == nil {
			t.Fatal("Expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Code = %v, want InvalidArgument", st.Code())
		}
	})
}

// --- GetUserByDID Tests ---

func TestHandler_GetUserByDID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockGetUserByDIDHandler{
			result: query.GetUserByDIDResult{User: user},
		}

		handler := NewHandler(HandlerConfig{
			GetUserByDIDHandler: mockHandler,
		})

		resp, err := handler.GetUserByDID(context.Background(), &identityv1.GetUserByDIDRequest{
			Did: user.DID().String(),
		})

		if err != nil {
			t.Fatalf("GetUserByDID() error = %v", err)
		}
		if resp.User.Did != user.DID().String() {
			t.Errorf("User.Did = %v, want %v", resp.User.Did, user.DID().String())
		}
	})
}

// --- ListSessions Tests ---

func TestHandler_ListSessions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		session := createTestSession(t, user)
		mockHandler := &mockListSessionsHandler{
			result: query.ListSessionsResult{
				Sessions:   []*model.Session{session},
				TotalCount: 1,
			},
		}

		handler := NewHandler(HandlerConfig{
			ListSessionsHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		resp, err := handler.ListSessions(ctx, &identityv1.ListSessionsRequest{})

		if err != nil {
			t.Fatalf("ListSessions() error = %v", err)
		}
		if len(resp.Sessions) != 1 {
			t.Errorf("Sessions count = %d, want 1", len(resp.Sessions))
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		handler := NewHandler(HandlerConfig{})

		_, err := handler.ListSessions(context.Background(), &identityv1.ListSessionsRequest{})

		if err == nil {
			t.Fatal("Expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.Unauthenticated {
			t.Errorf("Code = %v, want Unauthenticated", st.Code())
		}
	})

	t.Run("with pagination", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockListSessionsHandler{
			result: query.ListSessionsResult{Sessions: []*model.Session{}, TotalCount: 0},
		}

		handler := NewHandler(HandlerConfig{
			ListSessionsHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		_, err := handler.ListSessions(ctx, &identityv1.ListSessionsRequest{
			Pagination: &commonv1.PageRequest{
				PageSize: 10,
				Page:     2,
			},
		})

		if err != nil {
			t.Fatalf("ListSessions() error = %v", err)
		}

		// Verify pagination was applied
		if mockHandler.lastQry.Limit != 10 {
			t.Errorf("Limit = %d, want 10", mockHandler.lastQry.Limit)
		}
		if mockHandler.lastQry.Offset != 10 { // (page 2 - 1) * 10
			t.Errorf("Offset = %d, want 10", mockHandler.lastQry.Offset)
		}
	})
}

// --- RevokeSession Tests ---

func TestHandler_RevokeSession(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockRevokeSessionHandler{
			result: command.RevokeSessionResult{},
		}

		handler := NewHandler(HandlerConfig{
			RevokeSessionHandler: mockHandler,
		})

		userID := types.NewID()
		sessionID := types.NewID()
		ctx := contextWithAuth(userID)

		_, err := handler.RevokeSession(ctx, &identityv1.RevokeSessionRequest{
			SessionId: sessionID.String(),
		})

		if err != nil {
			t.Fatalf("RevokeSession() error = %v", err)
		}
	})

	t.Run("invalid session_id", func(t *testing.T) {
		handler := NewHandler(HandlerConfig{})

		userID := types.NewID()
		ctx := contextWithAuth(userID)

		_, err := handler.RevokeSession(ctx, &identityv1.RevokeSessionRequest{
			SessionId: "invalid-uuid",
		})

		if err == nil {
			t.Fatal("Expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Code = %v, want InvalidArgument", st.Code())
		}
	})
}

// --- RevokeAllSessions Tests ---

func TestHandler_RevokeAllSessions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockRevokeAllSessionsHandler{
			result: command.RevokeAllSessionsResult{RevokedCount: 5},
		}

		handler := NewHandler(HandlerConfig{
			RevokeAllSessionsHandler: mockHandler,
		})

		userID := types.NewID()
		ctx := contextWithAuth(userID)

		resp, err := handler.RevokeAllSessions(ctx, &identityv1.RevokeAllSessionsRequest{})

		if err != nil {
			t.Fatalf("RevokeAllSessions() error = %v", err)
		}
		if resp.RevokedCount != 5 {
			t.Errorf("RevokedCount = %d, want 5", resp.RevokedCount)
		}
	})
}

// --- CreateAPIKey Tests ---

func TestHandler_CreateAPIKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users"},
			types.None[types.ID](),
			types.None[types.Timestamp](),
		)

		mockHandler := &mockCreateAPIKeyHandler{
			result: command.CreateAPIKeyResult{
				APIKey: apiKeyResult.APIKey,
				Secret: "sk_test_secret",
			},
		}

		handler := NewHandler(HandlerConfig{
			CreateAPIKeyHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		resp, err := handler.CreateAPIKey(ctx, &identityv1.CreateAPIKeyRequest{
			Name:   "Test Key",
			Scopes: []string{"read:users"},
		})

		if err != nil {
			t.Fatalf("CreateAPIKey() error = %v", err)
		}
		if resp.Key != "sk_test_secret" {
			t.Errorf("Key = %v, want sk_test_secret", resp.Key)
		}
		if resp.ApiKey == nil {
			t.Error("ApiKey should not be nil")
		}
	})
}

// --- GetAPIKey Tests ---

func TestHandler_GetAPIKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users"},
			types.None[types.ID](),
			types.None[types.Timestamp](),
		)

		mockHandler := &mockGetAPIKeyHandler{
			result: query.GetAPIKeyResult{APIKey: apiKeyResult.APIKey},
		}

		handler := NewHandler(HandlerConfig{
			GetAPIKeyHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		resp, err := handler.GetAPIKey(ctx, &identityv1.GetAPIKeyRequest{
			Id: apiKeyResult.APIKey.ID().String(),
		})

		if err != nil {
			t.Fatalf("GetAPIKey() error = %v", err)
		}
		if resp.ApiKey == nil {
			t.Error("ApiKey should not be nil")
		}
	})

	t.Run("invalid id", func(t *testing.T) {
		handler := NewHandler(HandlerConfig{})

		userID := types.NewID()
		ctx := contextWithAuth(userID)

		_, err := handler.GetAPIKey(ctx, &identityv1.GetAPIKeyRequest{
			Id: "invalid-uuid",
		})

		if err == nil {
			t.Fatal("Expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument {
			t.Errorf("Code = %v, want InvalidArgument", st.Code())
		}
	})
}

// --- ListAPIKeys Tests ---

func TestHandler_ListAPIKeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users"},
			types.None[types.ID](),
			types.None[types.Timestamp](),
		)

		mockHandler := &mockListAPIKeysHandler{
			result: query.ListAPIKeysResult{
				APIKeys:    []*model.APIKey{apiKeyResult.APIKey},
				TotalCount: 1,
			},
		}

		handler := NewHandler(HandlerConfig{
			ListAPIKeysHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		resp, err := handler.ListAPIKeys(ctx, &identityv1.ListAPIKeysRequest{})

		if err != nil {
			t.Fatalf("ListAPIKeys() error = %v", err)
		}
		if len(resp.ApiKeys) != 1 {
			t.Errorf("ApiKeys count = %d, want 1", len(resp.ApiKeys))
		}
	})
}

// --- RevokeAPIKey Tests ---

func TestHandler_RevokeAPIKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockHandler := &mockRevokeAPIKeyHandler{
			result: command.RevokeAPIKeyResult{},
		}

		handler := NewHandler(HandlerConfig{
			RevokeAPIKeyHandler: mockHandler,
		})

		userID := types.NewID()
		apiKeyID := types.NewID()
		ctx := contextWithAuth(userID)

		_, err := handler.RevokeAPIKey(ctx, &identityv1.RevokeAPIKeyRequest{
			Id: apiKeyID.String(),
		})

		if err != nil {
			t.Fatalf("RevokeAPIKey() error = %v", err)
		}
	})
}

// --- VerifyAPIKey Tests ---

func TestHandler_VerifyAPIKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users"},
			types.None[types.ID](),
			types.None[types.Timestamp](),
		)

		mockHandler := &mockVerifyAPIKeyHandler{
			result: query.VerifyAPIKeyResult{
				APIKey: apiKeyResult.APIKey,
				User:   user,
			},
		}

		handler := NewHandler(HandlerConfig{
			VerifyAPIKeyHandler: mockHandler,
		})

		resp, err := handler.VerifyAPIKey(context.Background(), &identityv1.VerifyAPIKeyRequest{
			Key: "sk_test_secret",
		})

		if err != nil {
			t.Fatalf("VerifyAPIKey() error = %v", err)
		}
		if resp.ApiKey == nil {
			t.Error("ApiKey should not be nil")
		}
		if resp.User == nil {
			t.Error("User should not be nil")
		}
	})
}

// --- UpdateUser Tests ---

func TestHandler_UpdateUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		user := createTestUser(t)
		mockHandler := &mockUpdateUserHandler{
			result: command.UpdateUserResult{
				User:          user,
				UpdatedFields: []string{"email"},
			},
		}

		handler := NewHandler(HandlerConfig{
			UpdateUserHandler: mockHandler,
		})

		ctx := contextWithAuth(user.ID())
		email := "new@example.com"
		resp, err := handler.UpdateUser(ctx, &identityv1.UpdateUserRequest{
			Email: &email,
		})

		if err != nil {
			t.Fatalf("UpdateUser() error = %v", err)
		}
		if resp.User == nil {
			t.Error("User should not be nil")
		}
	})
}

// --- Test Helpers ---

func createTestUser(t *testing.T) *model.User {
	t.Helper()
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	return user
}

func createTestSession(t *testing.T, user *model.User) *model.Session {
	t.Helper()
	session, _ := model.NewSession(
		user.ID(),
		user.DID(),
		types.None[types.ID](),
		"hash",
		model.DefaultSessionConfig(),
	)
	return session
}

func contextWithAuth(userID types.ID) context.Context {
	authInfo := &middleware.AuthInfo{
		Subject: userID.String(),
		Claims: map[string]any{
			"user_id": userID,
		},
	}
	return middleware.SetAuthInfo(context.Background(), authInfo)
}

// --- Mock Handlers ---

type mockRegisterUserHandler struct {
	result  command.RegisterUserResult
	err     error
	lastCmd command.RegisterUser
}

func (m *mockRegisterUserHandler) Handle(ctx context.Context, cmd command.RegisterUser) (command.RegisterUserResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockVerifyRegistrationHandler struct {
	result  command.VerifyRegistrationResult
	err     error
	lastCmd command.VerifyRegistration
}

func (m *mockVerifyRegistrationHandler) Handle(ctx context.Context, cmd command.VerifyRegistration) (command.VerifyRegistrationResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockAuthenticateHandler struct {
	result  command.AuthenticateResult
	err     error
	lastCmd command.Authenticate
}

func (m *mockAuthenticateHandler) Handle(ctx context.Context, cmd command.Authenticate) (command.AuthenticateResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockVerifyAuthenticationHandler struct {
	result  command.VerifyAuthenticationResult
	err     error
	lastCmd command.VerifyAuthentication
}

func (m *mockVerifyAuthenticationHandler) Handle(ctx context.Context, cmd command.VerifyAuthentication) (command.VerifyAuthenticationResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockRefreshTokenHandler struct {
	result  command.RefreshTokenResult
	err     error
	lastCmd command.RefreshToken
}

func (m *mockRefreshTokenHandler) Handle(ctx context.Context, cmd command.RefreshToken) (command.RefreshTokenResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockRevokeTokenHandler struct {
	result  command.RevokeTokenResult
	err     error
	lastCmd command.RevokeToken
}

func (m *mockRevokeTokenHandler) Handle(ctx context.Context, cmd command.RevokeToken) (command.RevokeTokenResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockRevokeSessionHandler struct {
	result  command.RevokeSessionResult
	err     error
	lastCmd command.RevokeSession
}

func (m *mockRevokeSessionHandler) Handle(ctx context.Context, cmd command.RevokeSession) (command.RevokeSessionResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockRevokeAllSessionsHandler struct {
	result  command.RevokeAllSessionsResult
	err     error
	lastCmd command.RevokeAllSessions
}

func (m *mockRevokeAllSessionsHandler) Handle(ctx context.Context, cmd command.RevokeAllSessions) (command.RevokeAllSessionsResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockCreateAPIKeyHandler struct {
	result  command.CreateAPIKeyResult
	err     error
	lastCmd command.CreateAPIKey
}

func (m *mockCreateAPIKeyHandler) Handle(ctx context.Context, cmd command.CreateAPIKey) (command.CreateAPIKeyResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockRevokeAPIKeyHandler struct {
	result  command.RevokeAPIKeyResult
	err     error
	lastCmd command.RevokeAPIKey
}

func (m *mockRevokeAPIKeyHandler) Handle(ctx context.Context, cmd command.RevokeAPIKey) (command.RevokeAPIKeyResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockUpdateUserHandler struct {
	result  command.UpdateUserResult
	err     error
	lastCmd command.UpdateUser
}

func (m *mockUpdateUserHandler) Handle(ctx context.Context, cmd command.UpdateUser) (command.UpdateUserResult, error) {
	m.lastCmd = cmd
	return m.result, m.err
}

type mockGetUserHandler struct {
	result  query.GetUserResult
	err     error
	lastQry query.GetUser
}

func (m *mockGetUserHandler) Handle(ctx context.Context, qry query.GetUser) (query.GetUserResult, error) {
	m.lastQry = qry
	return m.result, m.err
}

type mockGetUserByDIDHandler struct {
	result  query.GetUserByDIDResult
	err     error
	lastQry query.GetUserByDID
}

func (m *mockGetUserByDIDHandler) Handle(ctx context.Context, qry query.GetUserByDID) (query.GetUserByDIDResult, error) {
	m.lastQry = qry
	return m.result, m.err
}

type mockGetSessionHandler struct {
	result  query.GetSessionResult
	err     error
	lastQry query.GetSession
}

func (m *mockGetSessionHandler) Handle(ctx context.Context, qry query.GetSession) (query.GetSessionResult, error) {
	m.lastQry = qry
	return m.result, m.err
}

type mockListSessionsHandler struct {
	result  query.ListSessionsResult
	err     error
	lastQry query.ListSessions
}

func (m *mockListSessionsHandler) Handle(ctx context.Context, qry query.ListSessions) (query.ListSessionsResult, error) {
	m.lastQry = qry
	return m.result, m.err
}

type mockGetAPIKeyHandler struct {
	result  query.GetAPIKeyResult
	err     error
	lastQry query.GetAPIKey
}

func (m *mockGetAPIKeyHandler) Handle(ctx context.Context, qry query.GetAPIKey) (query.GetAPIKeyResult, error) {
	m.lastQry = qry
	return m.result, m.err
}

type mockListAPIKeysHandler struct {
	result  query.ListAPIKeysResult
	err     error
	lastQry query.ListAPIKeys
}

func (m *mockListAPIKeysHandler) Handle(ctx context.Context, qry query.ListAPIKeys) (query.ListAPIKeysResult, error) {
	m.lastQry = qry
	return m.result, m.err
}

type mockVerifyAPIKeyHandler struct {
	result  query.VerifyAPIKeyResult
	err     error
	lastQry query.VerifyAPIKey
}

func (m *mockVerifyAPIKeyHandler) Handle(ctx context.Context, qry query.VerifyAPIKey) (query.VerifyAPIKeyResult, error) {
	m.lastQry = qry
	return m.result, m.err
}
