package grpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/0xsj/overwatch-identity/internal/app/service"
)

// AuthInterceptor handles JWT validation for authenticated endpoints.
type AuthInterceptor struct {
	tokenService  service.TokenService
	publicMethods map[string]bool
}

// NewAuthInterceptor creates a new auth interceptor.
func NewAuthInterceptor(tokenService service.TokenService) *AuthInterceptor {
	return &AuthInterceptor{
		tokenService: tokenService,
		publicMethods: map[string]bool{
			"/identity.v1.IdentityService/Ping":                 true,
			"/identity.v1.IdentityService/Register":             true,
			"/identity.v1.IdentityService/VerifyRegistration":   true,
			"/identity.v1.IdentityService/Authenticate":         true,
			"/identity.v1.IdentityService/VerifyAuthentication": true,
			"/identity.v1.IdentityService/RefreshToken":         true,
			"/identity.v1.IdentityService/VerifyAPIKey":         true,
			"/identity.v1.IdentityService/GetUser":              true,
			"/identity.v1.IdentityService/GetUserByDID":         true,
		},
	}
}

// Unary returns a unary server interceptor for authentication.
func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract and validate token
		newCtx, err := i.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		return handler(newCtx, req)
	}
}

// Stream returns a stream server interceptor for authentication.
func (i *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip auth for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Extract and validate token
		newCtx, err := i.authenticate(ss.Context())
		if err != nil {
			return err
		}

		wrapped := &wrappedServerStream{
			ServerStream: ss,
			ctx:          newCtx,
		}

		return handler(srv, wrapped)
	}
}

func (i *AuthInterceptor) authenticate(ctx context.Context) (context.Context, error) {
	token, err := extractBearerToken(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid authorization header")
	}

	claims, err := i.tokenService.ValidateAccessToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	// Add claims to context (already typed correctly)
	ctx = WithUserID(ctx, claims.UserID)
	ctx = WithUserDID(ctx, claims.DID)
	ctx = WithSessionID(ctx, claims.SessionID)

	if claims.TenantID.IsPresent() {
		ctx = WithTenantID(ctx, claims.TenantID.MustGet())
	}

	return ctx, nil
}

func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	authHeader := values[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization format")
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// LoggingInterceptor provides request logging.
type LoggingInterceptor struct {
	logger Logger
}

// Logger interface for logging.
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// NewLoggingInterceptor creates a new logging interceptor.
func NewLoggingInterceptor(logger Logger) *LoggingInterceptor {
	return &LoggingInterceptor{logger: logger}
}

// Unary returns a unary server interceptor for logging.
func (i *LoggingInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		resp, err := handler(ctx, req)

		if err != nil {
			i.logger.Error("gRPC request failed",
				"method", info.FullMethod,
				"error", err.Error(),
			)
		} else {
			i.logger.Info("gRPC request completed",
				"method", info.FullMethod,
			)
		}

		return resp, err
	}
}

// RecoveryInterceptor handles panics.
type RecoveryInterceptor struct {
	logger Logger
}

// NewRecoveryInterceptor creates a new recovery interceptor.
func NewRecoveryInterceptor(logger Logger) *RecoveryInterceptor {
	return &RecoveryInterceptor{logger: logger}
}

// Unary returns a unary server interceptor for panic recovery.
func (i *RecoveryInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				i.logger.Error("panic recovered",
					"method", info.FullMethod,
					"panic", r,
				)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}
