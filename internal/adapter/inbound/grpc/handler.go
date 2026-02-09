package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/0xsj/overwatch-pkg/types"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
)

// Handler implements identityv1.IdentityServiceServer.
type Handler struct {
	identityv1.UnimplementedIdentityServiceServer

	// Command handlers
	registerUserHandler          command.RegisterUserHandler
	verifyRegistrationHandler    command.VerifyRegistrationHandler
	authenticateHandler          command.AuthenticateHandler
	verifyAuthenticationHandler  command.VerifyAuthenticationHandler
	refreshTokenHandler          command.RefreshTokenHandler
	revokeTokenHandler           command.RevokeTokenHandler
	revokeSessionHandler         command.RevokeSessionHandler
	revokeAllSessionsHandler     command.RevokeAllSessionsHandler
	createAPIKeyHandler          command.CreateAPIKeyHandler
	revokeAPIKeyHandler          command.RevokeAPIKeyHandler
	updateUserHandler            command.UpdateUserHandler
	authenticateWithOAuthHandler command.AuthenticateWithOAuthHandler
	linkOAuthProviderHandler     command.LinkOAuthProviderHandler
	unlinkOAuthProviderHandler   command.UnlinkOAuthProviderHandler

	// Query handlers
	getUserHandler                  query.GetUserHandler
	getUserByDIDHandler             query.GetUserByDIDHandler
	getSessionHandler               query.GetSessionHandler
	listSessionsHandler             query.ListSessionsHandler
	getAPIKeyHandler                query.GetAPIKeyHandler
	listAPIKeysHandler              query.ListAPIKeysHandler
	verifyAPIKeyHandler             query.VerifyAPIKeyHandler
	getOAuthAuthorizationURLHandler query.GetOAuthAuthorizationURLHandler
	listLinkedProvidersHandler      query.ListLinkedProvidersHandler
}

// HandlerConfig holds all the handlers needed by the gRPC handler.
type HandlerConfig struct {
	RegisterUserHandler             command.RegisterUserHandler
	VerifyRegistrationHandler       command.VerifyRegistrationHandler
	AuthenticateHandler             command.AuthenticateHandler
	VerifyAuthenticationHandler     command.VerifyAuthenticationHandler
	RefreshTokenHandler             command.RefreshTokenHandler
	RevokeTokenHandler              command.RevokeTokenHandler
	RevokeSessionHandler            command.RevokeSessionHandler
	RevokeAllSessionsHandler        command.RevokeAllSessionsHandler
	CreateAPIKeyHandler             command.CreateAPIKeyHandler
	RevokeAPIKeyHandler             command.RevokeAPIKeyHandler
	UpdateUserHandler               command.UpdateUserHandler
	AuthenticateWithOAuthHandler    command.AuthenticateWithOAuthHandler
	LinkOAuthProviderHandler        command.LinkOAuthProviderHandler
	UnlinkOAuthProviderHandler      command.UnlinkOAuthProviderHandler
	GetUserHandler                  query.GetUserHandler
	GetUserByDIDHandler             query.GetUserByDIDHandler
	GetSessionHandler               query.GetSessionHandler
	ListSessionsHandler             query.ListSessionsHandler
	GetAPIKeyHandler                query.GetAPIKeyHandler
	ListAPIKeysHandler              query.ListAPIKeysHandler
	VerifyAPIKeyHandler             query.VerifyAPIKeyHandler
	GetOAuthAuthorizationURLHandler query.GetOAuthAuthorizationURLHandler
	ListLinkedProvidersHandler      query.ListLinkedProvidersHandler
}

// NewHandler creates a new gRPC handler.
func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{
		registerUserHandler:             cfg.RegisterUserHandler,
		verifyRegistrationHandler:       cfg.VerifyRegistrationHandler,
		authenticateHandler:             cfg.AuthenticateHandler,
		verifyAuthenticationHandler:     cfg.VerifyAuthenticationHandler,
		refreshTokenHandler:             cfg.RefreshTokenHandler,
		revokeTokenHandler:              cfg.RevokeTokenHandler,
		revokeSessionHandler:            cfg.RevokeSessionHandler,
		revokeAllSessionsHandler:        cfg.RevokeAllSessionsHandler,
		createAPIKeyHandler:             cfg.CreateAPIKeyHandler,
		revokeAPIKeyHandler:             cfg.RevokeAPIKeyHandler,
		updateUserHandler:               cfg.UpdateUserHandler,
		authenticateWithOAuthHandler:    cfg.AuthenticateWithOAuthHandler,
		linkOAuthProviderHandler:        cfg.LinkOAuthProviderHandler,
		unlinkOAuthProviderHandler:      cfg.UnlinkOAuthProviderHandler,
		getUserHandler:                  cfg.GetUserHandler,
		getUserByDIDHandler:             cfg.GetUserByDIDHandler,
		getSessionHandler:               cfg.GetSessionHandler,
		listSessionsHandler:             cfg.ListSessionsHandler,
		getAPIKeyHandler:                cfg.GetAPIKeyHandler,
		listAPIKeysHandler:              cfg.ListAPIKeysHandler,
		verifyAPIKeyHandler:             cfg.VerifyAPIKeyHandler,
		getOAuthAuthorizationURLHandler: cfg.GetOAuthAuthorizationURLHandler,
		listLinkedProvidersHandler:      cfg.ListLinkedProvidersHandler,
	}
}

// Health

func (h *Handler) Ping(ctx context.Context, req *identityv1.PingRequest) (*identityv1.PingResponse, error) {
	return &identityv1.PingResponse{Message: "pong"}, nil
}

// Registration
func (h *Handler) Register(ctx context.Context, req *identityv1.RegisterRequest) (*identityv1.RegisterResponse, error) {
	cmd := command.RegisterUser{
		DID:   req.Did,
		Email: toOptionalString(req.Email),
		Name:  toOptionalString(req.Name),
	}

	result, err := h.registerUserHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.RegisterResponse{
		ChallengeId: result.ChallengeID.String(),
		Nonce:       result.Nonce,
		Message:     result.Message,
		ExpiresAt:   timestamppb.New(result.ExpiresAt.Time()),
	}, nil
}

func (h *Handler) VerifyRegistration(ctx context.Context, req *identityv1.VerifyRegistrationRequest) (*identityv1.VerifyRegistrationResponse, error) {
	challengeID, err := types.ParseID(req.ChallengeId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid challenge_id")
	}

	cmd := command.VerifyRegistration{
		ChallengeID: challengeID,
		DID:         req.Did,
		Signature:   req.Signature,
	}

	result, err := h.verifyRegistrationHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.VerifyRegistrationResponse{
		User:                 toProtoUser(result.User),
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		AccessTokenExpiresAt: timestamppb.New(result.AccessTokenExpiresAt.Time()),
	}, nil
}

// Authentication

func (h *Handler) Authenticate(ctx context.Context, req *identityv1.AuthenticateRequest) (*identityv1.AuthenticateResponse, error) {
	cmd := command.Authenticate{
		DID: req.Did,
	}

	result, err := h.authenticateHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.AuthenticateResponse{
		ChallengeId: result.ChallengeID.String(),
		Nonce:       result.Nonce,
		Message:     result.Message,
		ExpiresAt:   timestamppb.New(result.ExpiresAt.Time()),
	}, nil
}

func (h *Handler) VerifyAuthentication(ctx context.Context, req *identityv1.VerifyAuthenticationRequest) (*identityv1.VerifyAuthenticationResponse, error) {
	challengeID, err := types.ParseID(req.ChallengeId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid challenge_id")
	}

	cmd := command.VerifyAuthentication{
		ChallengeID: challengeID,
		DID:         req.Did,
		Signature:   req.Signature,
		TenantID:    toOptionalTenantID(req.TenantId),
	}

	result, err := h.verifyAuthenticationHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.VerifyAuthenticationResponse{
		User:                 toProtoUser(result.User),
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		AccessTokenExpiresAt: timestamppb.New(result.AccessTokenExpiresAt.Time()),
	}, nil
}

// Token Management

func (h *Handler) RefreshToken(ctx context.Context, req *identityv1.RefreshTokenRequest) (*identityv1.RefreshTokenResponse, error) {
	cmd := command.RefreshToken{
		RefreshToken: req.RefreshToken,
	}

	result, err := h.refreshTokenHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.RefreshTokenResponse{
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		AccessTokenExpiresAt: timestamppb.New(result.AccessTokenExpiresAt.Time()),
	}, nil
}

func (h *Handler) RevokeToken(ctx context.Context, req *identityv1.RevokeTokenRequest) (*identityv1.RevokeTokenResponse, error) {
	cmd := command.RevokeToken{
		RefreshToken: req.RefreshToken,
	}

	_, err := h.revokeTokenHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.RevokeTokenResponse{}, nil
}

// Session Management

func (h *Handler) ListSessions(ctx context.Context, req *identityv1.ListSessionsRequest) (*identityv1.ListSessionsResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	limit := 20
	offset := 0
	if req.Pagination != nil {
		if req.Pagination.PageSize > 0 {
			limit = int(req.Pagination.PageSize)
		}
		if req.Pagination.Page > 0 {
			offset = int(req.Pagination.Page-1) * limit
		}
		// Cursor-based pagination alternative
		if req.Pagination.Cursor != nil && *req.Pagination.Cursor != "" {
			// Parse cursor as offset for simplicity
			// In production, decode cursor properly
		}
	}

	qry := query.ListSessions{
		UserID:     userID,
		ActiveOnly: true,
		Limit:      limit,
		Offset:     offset,
	}

	result, err := h.listSessionsHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.ListSessionsResponse{
		Sessions: toProtoSessions(result.Sessions),
	}, nil
}

func (h *Handler) RevokeSession(ctx context.Context, req *identityv1.RevokeSessionRequest) (*identityv1.RevokeSessionResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	sessionID, err := types.ParseID(req.SessionId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session_id")
	}

	cmd := command.RevokeSession{
		SessionID: sessionID,
		UserID:    userID,
		Reason:    "user requested",
	}

	_, err = h.revokeSessionHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.RevokeSessionResponse{}, nil
}

func (h *Handler) RevokeAllSessions(ctx context.Context, req *identityv1.RevokeAllSessionsRequest) (*identityv1.RevokeAllSessionsResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	cmd := command.RevokeAllSessions{
		UserID: userID,
	}

	result, err := h.revokeAllSessionsHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.RevokeAllSessionsResponse{
		RevokedCount: int32(result.RevokedCount),
	}, nil
}

// API Key Management

func (h *Handler) CreateAPIKey(ctx context.Context, req *identityv1.CreateAPIKeyRequest) (*identityv1.CreateAPIKeyResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	cmd := command.CreateAPIKey{
		UserID:    userID,
		Name:      req.Name,
		Scopes:    req.Scopes,
		TenantID:  toOptionalTenantID(req.TenantId),
		ExpiresAt: toOptionalTimestamp(req.ExpiresAt),
	}

	result, err := h.createAPIKeyHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.CreateAPIKeyResponse{
		ApiKey: toProtoAPIKey(result.APIKey),
		Key:    result.Secret,
	}, nil
}

func (h *Handler) GetAPIKey(ctx context.Context, req *identityv1.GetAPIKeyRequest) (*identityv1.GetAPIKeyResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	apiKeyID, err := types.ParseID(req.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid id")
	}

	qry := query.GetAPIKey{
		APIKeyID: apiKeyID,
		UserID:   userID,
	}

	result, err := h.getAPIKeyHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.GetAPIKeyResponse{
		ApiKey: toProtoAPIKey(result.APIKey),
	}, nil
}

func (h *Handler) ListAPIKeys(ctx context.Context, req *identityv1.ListAPIKeysRequest) (*identityv1.ListAPIKeysResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	limit := 20
	offset := 0
	if req.Pagination != nil {
		if req.Pagination.PageSize > 0 {
			limit = int(req.Pagination.PageSize)
		}
		if req.Pagination.Page > 0 {
			offset = int(req.Pagination.Page-1) * limit
		}
	}

	qry := query.ListAPIKeys{
		UserID:     userID,
		TenantID:   types.None[types.ID](),
		ActiveOnly: true,
		Limit:      limit,
		Offset:     offset,
	}

	result, err := h.listAPIKeysHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.ListAPIKeysResponse{
		ApiKeys: toProtoAPIKeys(result.APIKeys),
	}, nil
}

func (h *Handler) RevokeAPIKey(ctx context.Context, req *identityv1.RevokeAPIKeyRequest) (*identityv1.RevokeAPIKeyResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	apiKeyID, err := types.ParseID(req.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid id")
	}

	cmd := command.RevokeAPIKey{
		APIKeyID: apiKeyID,
		UserID:   userID,
		Reason:   "user requested",
	}

	_, err = h.revokeAPIKeyHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.RevokeAPIKeyResponse{}, nil
}

func (h *Handler) VerifyAPIKey(ctx context.Context, req *identityv1.VerifyAPIKeyRequest) (*identityv1.VerifyAPIKeyResponse, error) {
	qry := query.VerifyAPIKey{
		Key: req.Key,
	}

	result, err := h.verifyAPIKeyHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.VerifyAPIKeyResponse{
		ApiKey: toProtoAPIKey(result.APIKey),
		User:   toProtoUser(result.User),
	}, nil
}

// User Management

func (h *Handler) GetCurrentUser(ctx context.Context, req *identityv1.GetCurrentUserRequest) (*identityv1.GetCurrentUserResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	qry := query.GetUser{
		UserID: userID,
	}

	result, err := h.getUserHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.GetCurrentUserResponse{
		User: toProtoUser(result.User),
	}, nil
}

func (h *Handler) GetUser(ctx context.Context, req *identityv1.GetUserRequest) (*identityv1.GetUserResponse, error) {
	userID, err := types.ParseID(req.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid id")
	}

	qry := query.GetUser{
		UserID: userID,
	}

	result, err := h.getUserHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.GetUserResponse{
		User: toProtoUser(result.User),
	}, nil
}

func (h *Handler) GetUserByDID(ctx context.Context, req *identityv1.GetUserByDIDRequest) (*identityv1.GetUserByDIDResponse, error) {
	qry := query.GetUserByDID{
		DID: req.Did,
	}

	result, err := h.getUserByDIDHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.GetUserByDIDResponse{
		User: toProtoUser(result.User),
	}, nil
}

func (h *Handler) UpdateUser(ctx context.Context, req *identityv1.UpdateUserRequest) (*identityv1.UpdateUserResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	cmd := command.UpdateUser{
		UserID: userID,
		Email:  toOptionalEmail(req.Email),
		Name:   toOptionalString(req.Name),
	}

	result, err := h.updateUserHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.UpdateUserResponse{
		User: toProtoUser(result.User),
	}, nil
}

// OAuth

func (h *Handler) GetOAuthAuthorizationURL(ctx context.Context, req *identityv1.GetOAuthAuthorizationURLRequest) (*identityv1.GetOAuthAuthorizationURLResponse, error) {
	provider, err := fromProtoOAuthProvider(req.Provider)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	var state string
	if req.State != nil {
		state = *req.State
	}

	qry := query.GetOAuthAuthorizationURL{
		Provider:    provider,
		RedirectURI: req.RedirectUri,
		State:       state,
	}

	result, err := h.getOAuthAuthorizationURLHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.GetOAuthAuthorizationURLResponse{
		AuthorizationUrl: result.AuthorizationURL,
		State:            result.State,
	}, nil
}

func (h *Handler) AuthenticateWithOAuth(ctx context.Context, req *identityv1.AuthenticateWithOAuthRequest) (*identityv1.AuthenticateWithOAuthResponse, error) {
	provider, err := fromProtoOAuthProvider(req.Provider)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	cmd := command.AuthenticateWithOAuth{
		Provider:    provider,
		Code:        req.Code,
		RedirectURI: req.RedirectUri,
		TenantID:    toOptionalTenantID(req.TenantId),
	}

	result, err := h.authenticateWithOAuthHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.AuthenticateWithOAuthResponse{
		User:                 toProtoUser(result.User),
		AccessToken:          result.AccessToken,
		RefreshToken:         result.RefreshToken,
		AccessTokenExpiresAt: timestamppb.New(result.AccessTokenExpiresAt.Time()),
		IsNewUser:            result.IsNewUser,
	}, nil
}

func (h *Handler) LinkOAuthProvider(ctx context.Context, req *identityv1.LinkOAuthProviderRequest) (*identityv1.LinkOAuthProviderResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	provider, err := fromProtoOAuthProvider(req.Provider)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	cmd := command.LinkOAuthProvider{
		UserID:      userID,
		Provider:    provider,
		Code:        req.Code,
		RedirectURI: req.RedirectUri,
	}

	result, err := h.linkOAuthProviderHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.LinkOAuthProviderResponse{
		OauthIdentity: toProtoOAuthIdentity(result.OAuthIdentity),
	}, nil
}

func (h *Handler) UnlinkOAuthProvider(ctx context.Context, req *identityv1.UnlinkOAuthProviderRequest) (*identityv1.UnlinkOAuthProviderResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	provider, err := fromProtoOAuthProvider(req.Provider)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	cmd := command.UnlinkOAuthProvider{
		UserID:   userID,
		Provider: provider,
	}

	_, err = h.unlinkOAuthProviderHandler.Handle(ctx, cmd)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &identityv1.UnlinkOAuthProviderResponse{}, nil
}

func (h *Handler) ListLinkedProviders(ctx context.Context, req *identityv1.ListLinkedProvidersRequest) (*identityv1.ListLinkedProvidersResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	qry := query.ListLinkedProviders{
		UserID: userID,
	}

	result, err := h.listLinkedProvidersHandler.Handle(ctx, qry)
	if err != nil {
		return nil, toGRPCError(err)
	}

	providers := make([]*identityv1.OAuthIdentity, len(result.Providers))
	for i, p := range result.Providers {
		providers[i] = toProtoOAuthIdentity(p)
	}

	return &identityv1.ListLinkedProvidersResponse{
		Providers: providers,
	}, nil
}
