package cache

import (
	"context"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// SessionCache defines the interface for session caching.
// Used to avoid database lookups for session validation on every request.
type SessionCache interface {
	// Get retrieves a session from the cache.
	// Returns nil if not found (cache miss).
	Get(ctx context.Context, sessionID types.ID) (*model.Session, error)

	// Set stores a session in the cache with TTL.
	Set(ctx context.Context, session *model.Session, ttl time.Duration) error

	// Delete removes a session from the cache.
	Delete(ctx context.Context, sessionID types.ID) error

	// DeleteByUserID removes all cached sessions for a user.
	DeleteByUserID(ctx context.Context, userID types.ID) error

	// Exists checks if a session exists in the cache.
	Exists(ctx context.Context, sessionID types.ID) (bool, error)
}

// UserCache defines the interface for user caching.
// Used to cache frequently accessed user data.
type UserCache interface {
	// Get retrieves a user from the cache.
	Get(ctx context.Context, userID types.ID) (*model.User, error)

	// GetByDID retrieves a user from the cache by DID.
	GetByDID(ctx context.Context, did string) (*model.User, error)

	// Set stores a user in the cache with TTL.
	Set(ctx context.Context, user *model.User, ttl time.Duration) error

	// Delete removes a user from the cache.
	Delete(ctx context.Context, userID types.ID) error

	// DeleteByDID removes a user from the cache by DID.
	DeleteByDID(ctx context.Context, did string) error
}

// TokenBlacklist defines the interface for blacklisting revoked tokens.
// Used to invalidate tokens before their natural expiration.
type TokenBlacklist interface {
	// Add adds a token to the blacklist with TTL.
	// TTL should match the token's remaining lifetime.
	Add(ctx context.Context, tokenID string, ttl time.Duration) error

	// IsBlacklisted checks if a token is blacklisted.
	IsBlacklisted(ctx context.Context, tokenID string) (bool, error)

	// Remove removes a token from the blacklist.
	Remove(ctx context.Context, tokenID string) error
}
