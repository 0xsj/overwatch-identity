package grpc

import (
	"context"
	"errors"

	"github.com/0xsj/overwatch-pkg/types"
)

type contextKey string

const (
	userIDKey    contextKey = "user_id"
	userDIDKey   contextKey = "user_did"
	tenantIDKey  contextKey = "tenant_id"
	sessionIDKey contextKey = "session_id"
)

var (
	ErrNoUserIDInContext    = errors.New("no user_id in context")
	ErrNoUserDIDInContext   = errors.New("no user_did in context")
	ErrNoTenantIDInContext  = errors.New("no tenant_id in context")
	ErrNoSessionIDInContext = errors.New("no session_id in context")
)

// WithUserID adds the user ID to the context.
func WithUserID(ctx context.Context, userID types.ID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// WithUserDID adds the user DID to the context.
func WithUserDID(ctx context.Context, did string) context.Context {
	return context.WithValue(ctx, userDIDKey, did)
}

// WithTenantID adds the tenant ID to the context.
func WithTenantID(ctx context.Context, tenantID types.ID) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// WithSessionID adds the session ID to the context.
func WithSessionID(ctx context.Context, sessionID types.ID) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// getUserIDFromContext extracts the user ID from context.
func getUserIDFromContext(ctx context.Context) (types.ID, error) {
	val := ctx.Value(userIDKey)
	if val == nil {
		return "", ErrNoUserIDInContext
	}

	userID, ok := val.(types.ID)
	if !ok {
		return "", ErrNoUserIDInContext
	}

	return userID, nil
}

// getUserDIDFromContext extracts the user DID from context.
func getUserDIDFromContext(ctx context.Context) (string, error) {
	val := ctx.Value(userDIDKey)
	if val == nil {
		return "", ErrNoUserDIDInContext
	}

	did, ok := val.(string)
	if !ok {
		return "", ErrNoUserDIDInContext
	}

	return did, nil
}

// getTenantIDFromContext extracts the tenant ID from context.
func getTenantIDFromContext(ctx context.Context) (types.ID, error) {
	val := ctx.Value(tenantIDKey)
	if val == nil {
		return "", ErrNoTenantIDInContext
	}

	tenantID, ok := val.(types.ID)
	if !ok {
		return "", ErrNoTenantIDInContext
	}

	return tenantID, nil
}

// getSessionIDFromContext extracts the session ID from context.
func getSessionIDFromContext(ctx context.Context) (types.ID, error) {
	val := ctx.Value(sessionIDKey)
	if val == nil {
		return "", ErrNoSessionIDInContext
	}

	sessionID, ok := val.(types.ID)
	if !ok {
		return "", ErrNoSessionIDInContext
	}

	return sessionID, nil
}

// GetUserIDFromContext is the exported version for interceptors.
func GetUserIDFromContext(ctx context.Context) (types.ID, error) {
	return getUserIDFromContext(ctx)
}

// GetTenantIDFromContext is the exported version for interceptors.
func GetTenantIDFromContext(ctx context.Context) (types.ID, error) {
	return getTenantIDFromContext(ctx)
}
