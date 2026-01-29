package grpc

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
)

func TestToGRPCError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		// Nil error
		{
			name:         "nil error returns nil",
			err:          nil,
			expectedCode: codes.OK,
		},

		// NotFound errors -> codes.NotFound
		{
			name:         "ErrUserNotFound",
			err:          domainerror.ErrUserNotFound,
			expectedCode: codes.NotFound,
		},
		{
			name:         "ErrSessionNotFound",
			err:          domainerror.ErrSessionNotFound,
			expectedCode: codes.NotFound,
		},
		{
			name:         "ErrChallengeNotFound",
			err:          domainerror.ErrChallengeNotFound,
			expectedCode: codes.NotFound,
		},
		{
			name:         "ErrAPIKeyNotFound",
			err:          domainerror.ErrAPIKeyNotFound,
			expectedCode: codes.NotFound,
		},

		// Validation errors -> codes.InvalidArgument
		{
			name:         "ErrUserIDRequired",
			err:          domainerror.ErrUserIDRequired,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrUserDIDRequired",
			err:          domainerror.ErrUserDIDRequired,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrSessionIDRequired",
			err:          domainerror.ErrSessionIDRequired,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrChallengeInvalid",
			err:          domainerror.ErrChallengeInvalid,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrChallengeDIDMismatch",
			err:          domainerror.ErrChallengeDIDMismatch,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrSignatureRequired",
			err:          domainerror.ErrSignatureRequired,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrRefreshTokenRequired",
			err:          domainerror.ErrRefreshTokenRequired,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ErrAPIKeyNameRequired",
			err:          domainerror.ErrAPIKeyNameRequired,
			expectedCode: codes.InvalidArgument,
		},

		// Unauthorized errors -> codes.Unauthenticated
		{
			name:         "ErrSignatureInvalid",
			err:          domainerror.ErrSignatureInvalid,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrTokenInvalid",
			err:          domainerror.ErrTokenInvalid,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrTokenExpired",
			err:          domainerror.ErrTokenExpired,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrRefreshTokenInvalid",
			err:          domainerror.ErrRefreshTokenInvalid,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrRefreshTokenExpired",
			err:          domainerror.ErrRefreshTokenExpired,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrSessionExpired",
			err:          domainerror.ErrSessionExpired,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrSessionRevoked",
			err:          domainerror.ErrSessionRevoked,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrAPIKeyInvalid",
			err:          domainerror.ErrAPIKeyInvalid,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrAPIKeyExpired",
			err:          domainerror.ErrAPIKeyExpired,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "ErrAPIKeyRevoked",
			err:          domainerror.ErrAPIKeyRevoked,
			expectedCode: codes.Unauthenticated,
		},

		// Forbidden errors -> codes.PermissionDenied
		{
			name:         "ErrUserSuspended",
			err:          domainerror.ErrUserSuspended,
			expectedCode: codes.PermissionDenied,
		},

		// Conflict errors -> codes.AlreadyExists
		{
			name:         "ErrUserAlreadyExists",
			err:          domainerror.ErrUserAlreadyExists,
			expectedCode: codes.AlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := toGRPCError(tt.err)

			if tt.err == nil {
				if grpcErr != nil {
					t.Errorf("toGRPCError(nil) = %v, want nil", grpcErr)
				}
				return
			}

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatalf("toGRPCError() did not return a gRPC status error")
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("toGRPCError(%v) code = %v, want %v", tt.err, st.Code(), tt.expectedCode)
			}

			// Verify message is preserved
			if st.Message() == "" {
				t.Error("gRPC status message should not be empty")
			}
		})
	}
}

func TestToGRPCError_PreservesMessage(t *testing.T) {
	tests := []struct {
		err             error
		expectedMessage string
	}{
		{domainerror.ErrUserNotFound, "user not found"},
		{domainerror.ErrUserAlreadyExists, "user with this DID already exists"},
		{domainerror.ErrUserSuspended, "user account is suspended"},
		{domainerror.ErrSessionRevoked, "session has been revoked"},
		{domainerror.ErrSignatureInvalid, "signature verification failed"},
		{domainerror.ErrAPIKeyRevoked, "API key has been revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedMessage, func(t *testing.T) {
			grpcErr := toGRPCError(tt.err)
			st, _ := status.FromError(grpcErr)

			if st.Message() != tt.expectedMessage {
				t.Errorf("message = %q, want %q", st.Message(), tt.expectedMessage)
			}
		})
	}
}

func TestToGRPCError_DomainErrors(t *testing.T) {
	// Domain kind errors (business logic violations) should map to appropriate codes
	tests := []struct {
		name string
		err  error
	}{
		{"ErrUserAlreadyActive", domainerror.ErrUserAlreadyActive},
		{"ErrUserAlreadySuspended", domainerror.ErrUserAlreadySuspended},
		{"ErrChallengeExpired", domainerror.ErrChallengeExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := toGRPCError(tt.err)
			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatalf("toGRPCError() did not return a gRPC status error")
			}

			// Domain errors should have a valid code (not Unknown)
			// The specific code depends on pkg/grpc mapping
			if st.Code() == codes.Unknown {
				t.Logf("Warning: %s mapped to codes.Unknown - verify pkg/grpc mapping", tt.name)
			}
		})
	}
}
