package grpc

import (
	"context"
	"errors"

	"github.com/0xsj/overwatch-pkg/grpc/middleware"
	"github.com/0xsj/overwatch-pkg/types"
)

var (
	ErrNoUserIDInContext    = errors.New("no user_id in context")
	ErrNoUserDIDInContext   = errors.New("no user_did in context")
	ErrNoTenantIDInContext  = errors.New("no tenant_id in context")
	ErrNoSessionIDInContext = errors.New("no session_id in context")
)

// getUserIDFromContext extracts the user ID from auth context.
func getUserIDFromContext(ctx context.Context) (types.ID, error) {
	authInfo := middleware.GetAuthInfo(ctx)
	if authInfo == nil {
		return "", ErrNoUserIDInContext
	}

	userID, ok := authInfo.Claims["user_id"].(types.ID)
	if !ok {
		return "", ErrNoUserIDInContext
	}
	return userID, nil
}

// getUserDIDFromContext extracts the user DID from auth context.
func getUserDIDFromContext(ctx context.Context) (string, error) {
	authInfo := middleware.GetAuthInfo(ctx)
	if authInfo == nil {
		return "", ErrNoUserDIDInContext
	}

	did, ok := authInfo.Claims["did"].(string)
	if !ok {
		return "", ErrNoUserDIDInContext
	}
	return did, nil
}

// getTenantIDFromContext extracts the tenant ID from auth context.
func getTenantIDFromContext(ctx context.Context) (types.ID, error) {
	authInfo := middleware.GetAuthInfo(ctx)
	if authInfo == nil {
		return "", ErrNoTenantIDInContext
	}

	tenantID, ok := authInfo.Claims["tenant_id"].(types.ID)
	if !ok {
		return "", ErrNoTenantIDInContext
	}
	return tenantID, nil
}

// getSessionIDFromContext extracts the session ID from auth context.
func getSessionIDFromContext(ctx context.Context) (types.ID, error) {
	authInfo := middleware.GetAuthInfo(ctx)
	if authInfo == nil {
		return "", ErrNoSessionIDInContext
	}

	sessionID, ok := authInfo.Claims["session_id"].(types.ID)
	if !ok {
		return "", ErrNoSessionIDInContext
	}
	return sessionID, nil
}

// GetUserIDFromContext is the exported version for use outside this package.
func GetUserIDFromContext(ctx context.Context) (types.ID, error) {
	return getUserIDFromContext(ctx)
}

// GetUserDIDFromContext is the exported version for use outside this package.
func GetUserDIDFromContext(ctx context.Context) (string, error) {
	return getUserDIDFromContext(ctx)
}

// GetTenantIDFromContext is the exported version for use outside this package.
func GetTenantIDFromContext(ctx context.Context) (types.ID, error) {
	return getTenantIDFromContext(ctx)
}

// GetSessionIDFromContext is the exported version for use outside this package.
func GetSessionIDFromContext(ctx context.Context) (types.ID, error) {
	return getSessionIDFromContext(ctx)
}
