package service

import (
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// TokenService handles JWT token generation and validation.
type TokenService interface {
	// GenerateAccessToken creates a new access token for a user.
	GenerateAccessToken(user *model.User, session *model.Session) (string, types.Timestamp, error)

	// GenerateRefreshToken creates a new refresh token.
	GenerateRefreshToken() (token string, hash string, err error)

	// ValidateAccessToken validates an access token and returns the claims.
	ValidateAccessToken(token string) (*AccessTokenClaims, error)

	// HashRefreshToken hashes a refresh token for storage.
	HashRefreshToken(token string) string
}

// AccessTokenClaims contains the claims embedded in an access token.
type AccessTokenClaims struct {
	UserID    types.ID
	DID       string
	SessionID types.ID
	TenantID  types.Optional[types.ID]
	ExpiresAt types.Timestamp
}

// TokenConfig holds configuration for token generation.
type TokenConfig struct {
	Issuer               string
	Audience             string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SigningKey           []byte
}

// DefaultTokenConfig returns default token configuration.
func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		Issuer:               "overwatch-identity",
		Audience:             "overwatch",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	}
}

// tokenService implements TokenService.
type tokenService struct {
	config TokenConfig
	signer *security.HMACSigner
}

// NewTokenService creates a new TokenService.
func NewTokenService(config TokenConfig) (TokenService, error) {
	signer, err := security.NewHMACSigner(security.AlgorithmHS256, config.SigningKey)
	if err != nil {
		return nil, err
	}

	return &tokenService{
		config: config,
		signer: signer,
	}, nil
}

func (s *tokenService) GenerateAccessToken(user *model.User, session *model.Session) (string, types.Timestamp, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(s.config.AccessTokenDuration)

	claims := security.NewClaims().
		WithSubject(user.ID().String()).
		WithIssuer(s.config.Issuer).
		WithAudience(s.config.Audience).
		WithIssuedAt(now).
		WithExpirationTime(expiresAt).
		WithRandomJWTID().
		Set("did", user.DID().String()).
		Set("session_id", session.ID().String())

	// Add tenant if present
	if session.TenantID().IsPresent() {
		claims.Set("tenant_id", session.TenantID().MustGet().String())
	}

	token, err := security.SignJWT(claims, s.signer)
	if err != nil {
		return "", types.Timestamp{}, err
	}

	return token, types.FromTime(expiresAt), nil
}

func (s *tokenService) GenerateRefreshToken() (string, string, error) {
	// Generate a random token
	token, err := security.RandomBase64URL(32)
	if err != nil {
		return "", "", err
	}

	// Hash it for storage
	hash := security.SHA256Hex([]byte(token))

	return token, hash, nil
}

func (s *tokenService) ValidateAccessToken(token string) (*AccessTokenClaims, error) {
	opts := security.JWTVerifyOptions{
		ValidateExpiration: true,
		ValidateNotBefore:  true,
		ExpectedIssuer:     s.config.Issuer,
		ExpectedAudience:   s.config.Audience,
	}

	jwt, err := security.VerifyJWTWithOptions(token, s.signer, opts)
	if err != nil {
		return nil, err
	}

	// Extract subject (user ID)
	userID, err := types.ParseID(jwt.Claims.Subject)
	if err != nil {
		return nil, security.ErrInvalidToken("invalid subject")
	}

	// Extract DID
	did, ok := jwt.Claims.GetString("did")
	if !ok {
		return nil, security.ErrInvalidToken("missing did claim")
	}

	// Extract session ID
	sessionIDStr, ok := jwt.Claims.GetString("session_id")
	if !ok {
		return nil, security.ErrInvalidToken("missing session_id claim")
	}
	sessionID, err := types.ParseID(sessionIDStr)
	if err != nil {
		return nil, security.ErrInvalidToken("invalid session_id")
	}

	result := &AccessTokenClaims{
		UserID:    userID,
		DID:       did,
		SessionID: sessionID,
		ExpiresAt: types.FromTime(jwt.Claims.ExpirationTime.Time),
	}

	// Extract optional tenant
	if tenantIDStr, ok := jwt.Claims.GetString("tenant_id"); ok {
		tenantID, err := types.ParseID(tenantIDStr)
		if err == nil {
			result.TenantID = types.Some(tenantID)
		}
	}

	return result, nil
}

func (s *tokenService) HashRefreshToken(token string) string {
	return security.SHA256Hex([]byte(token))
}
