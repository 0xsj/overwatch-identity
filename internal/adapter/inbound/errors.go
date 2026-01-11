package grpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// toGRPCError converts domain errors to gRPC status errors.
func toGRPCError(err error) error {
	if err == nil {
		return nil
	}

	// Repository errors
	if errors.Is(err, repository.ErrNotFound) {
		return status.Error(codes.NotFound, "resource not found")
	}

	// User errors
	if errors.Is(err, domainerror.ErrUserNotFound) {
		return status.Error(codes.NotFound, "user not found")
	}
	if errors.Is(err, domainerror.ErrUserAlreadyExists) {
		return status.Error(codes.AlreadyExists, "user already exists")
	}
	if errors.Is(err, domainerror.ErrUserSuspended) {
		return status.Error(codes.PermissionDenied, "user is suspended")
	}
	if errors.Is(err, domainerror.ErrUserIDRequired) {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	if errors.Is(err, domainerror.ErrUserDIDRequired) {
		return status.Error(codes.InvalidArgument, "did is required")
	}

	// Session errors
	if errors.Is(err, domainerror.ErrSessionNotFound) {
		return status.Error(codes.NotFound, "session not found")
	}
	if errors.Is(err, domainerror.ErrSessionExpired) {
		return status.Error(codes.Unauthenticated, "session has expired")
	}
	if errors.Is(err, domainerror.ErrSessionRevoked) {
		return status.Error(codes.Unauthenticated, "session has been revoked")
	}
	if errors.Is(err, domainerror.ErrSessionIDRequired) {
		return status.Error(codes.InvalidArgument, "session_id is required")
	}

	// Challenge errors
	if errors.Is(err, domainerror.ErrChallengeNotFound) {
		return status.Error(codes.NotFound, "challenge not found")
	}
	if errors.Is(err, domainerror.ErrChallengeExpired) {
		return status.Error(codes.DeadlineExceeded, "challenge has expired")
	}
	if errors.Is(err, domainerror.ErrChallengeDIDMismatch) {
		return status.Error(codes.InvalidArgument, "challenge DID mismatch")
	}

	// Token errors
	if errors.Is(err, domainerror.ErrTokenInvalid) {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	if errors.Is(err, domainerror.ErrTokenExpired) {
		return status.Error(codes.Unauthenticated, "token has expired")
	}
	if errors.Is(err, domainerror.ErrRefreshTokenInvalid) {
		return status.Error(codes.Unauthenticated, "invalid refresh token")
	}
	if errors.Is(err, domainerror.ErrRefreshTokenRequired) {
		return status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Signature errors
	if errors.Is(err, domainerror.ErrSignatureInvalid) {
		return status.Error(codes.Unauthenticated, "invalid signature")
	}
	if errors.Is(err, domainerror.ErrSignatureRequired) {
		return status.Error(codes.InvalidArgument, "signature is required")
	}

	// API Key errors
	if errors.Is(err, domainerror.ErrAPIKeyNotFound) {
		return status.Error(codes.NotFound, "api key not found")
	}
	if errors.Is(err, domainerror.ErrAPIKeyRevoked) {
		return status.Error(codes.PermissionDenied, "api key has been revoked")
	}
	if errors.Is(err, domainerror.ErrAPIKeyExpired) {
		return status.Error(codes.PermissionDenied, "api key has expired")
	}
	if errors.Is(err, domainerror.ErrAPIKeyInvalid) {
		return status.Error(codes.Unauthenticated, "invalid api key")
	}
	if errors.Is(err, domainerror.ErrAPIKeyNameRequired) {
		return status.Error(codes.InvalidArgument, "api key name is required")
	}

	// Default: internal error
	return status.Error(codes.Internal, "internal error")
}
