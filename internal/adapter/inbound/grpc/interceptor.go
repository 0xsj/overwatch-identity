package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/0xsj/overwatch-pkg/grpc/middleware"
	"github.com/0xsj/overwatch-pkg/log"

	"github.com/0xsj/overwatch-identity/internal/app/service"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// ErrSessionRevoked is returned when the session associated with a token has been revoked.
var ErrSessionRevoked = errors.New("session revoked")

// PublicMethods defines methods that don't require authentication.
var PublicMethods = map[string]bool{
	"/identity.v1.IdentityService/Ping":                 true,
	"/identity.v1.IdentityService/Register":             true,
	"/identity.v1.IdentityService/VerifyRegistration":   true,
	"/identity.v1.IdentityService/Authenticate":         true,
	"/identity.v1.IdentityService/VerifyAuthentication": true,
	"/identity.v1.IdentityService/RefreshToken":         true,
	"/identity.v1.IdentityService/VerifyAPIKey":         true,
	"/identity.v1.IdentityService/GetUser":              true,
	"/identity.v1.IdentityService/GetUserByDID":         true,
	"/grpc.health.v1.Health/Check":                      true,
	"/grpc.health.v1.Health/Watch":                      true,
}

// Claim keys for auth context.
const (
	ClaimKeyUserID    = "user_id"
	ClaimKeyUserDID   = "did"
	ClaimKeySessionID = "session_id"
	ClaimKeyTenantID  = "tenant_id"
)

// NewAuthenticator creates an Authenticator that validates tokens using the TokenService.
func NewAuthenticator(tokenService service.TokenService, sessionRepo repository.SessionRepository) middleware.Authenticator {
	return middleware.AuthenticatorFunc(func(ctx context.Context, token string) (*middleware.AuthInfo, error) {
		// Validate JWT signature and claims
		claims, err := tokenService.ValidateAccessToken(token)
		if err != nil {
			return nil, err
		}

		// Check if session is still valid (not revoked)
		session, err := sessionRepo.FindByID(ctx, claims.SessionID)
		if err != nil {
			return nil, ErrSessionRevoked
		}

		if err := session.Validate(); err != nil {
			// Session is revoked or expired
			return nil, ErrSessionRevoked
		}

		authInfo := &middleware.AuthInfo{
			Token:   token,
			Scheme:  middleware.BearerScheme,
			Subject: claims.UserID.String(),
			Claims:  make(map[string]any),
		}

		// Store as types.ID so type assertions work in context.go
		authInfo.Claims[ClaimKeyUserID] = claims.UserID
		authInfo.Claims[ClaimKeyUserDID] = claims.DID
		authInfo.Claims[ClaimKeySessionID] = claims.SessionID

		if claims.TenantID.IsPresent() {
			authInfo.Claims[ClaimKeyTenantID] = claims.TenantID.MustGet()
		}

		return authInfo, nil
	})
}

// NewAuthInterceptors creates unary and stream auth interceptors.
func NewAuthInterceptors(tokenService service.TokenService, sessionRepo repository.SessionRepository) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	authenticator := NewAuthenticator(tokenService, sessionRepo)

	cfg := middleware.AuthConfig{
		Header:          middleware.AuthorizationHeader,
		Scheme:          middleware.BearerScheme,
		Authenticator:   authenticator,
		SkipMethods:     PublicMethods,
		SkipHealthCheck: true,
		Optional:        false,
	}

	return middleware.UnaryServerAuthWithConfig(cfg), middleware.StreamServerAuthWithConfig(cfg)
}

// BuildUnaryInterceptors builds the complete unary interceptor chain with correct order.
func BuildUnaryInterceptors(logger log.Logger, tokenService service.TokenService, sessionRepo repository.SessionRepository) []grpc.UnaryServerInterceptor {
	unaryAuth, _ := NewAuthInterceptors(tokenService, sessionRepo)

	return []grpc.UnaryServerInterceptor{
		middleware.UnaryServerRecoveryWithLogger(logger), // 1. Outermost - catch panics
		middleware.UnaryServerRequestID(),                // 2. Generate/extract request ID
		middleware.UnaryServerLogging(logger),            // 3. Log with request ID
		unaryAuth,                                        // 4. Authentication
	}
}

// BuildStreamInterceptors builds the complete stream interceptor chain with correct order.
func BuildStreamInterceptors(logger log.Logger, tokenService service.TokenService, sessionRepo repository.SessionRepository) []grpc.StreamServerInterceptor {
	_, streamAuth := NewAuthInterceptors(tokenService, sessionRepo)

	return []grpc.StreamServerInterceptor{
		middleware.StreamServerRecoveryWithLogger(logger), // 1. Outermost - catch panics
		middleware.StreamServerRequestID(),                // 2. Generate/extract request ID
		middleware.StreamServerLogging(logger),            // 3. Log with request ID
		streamAuth,                                        // 4. Authentication
	}
}
