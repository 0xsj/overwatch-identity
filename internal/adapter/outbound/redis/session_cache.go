package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
)

const (
	sessionKeyPrefix     = "identity:session:"
	sessionUserKeyPrefix = "identity:user_sessions:"
	defaultSessionTTL    = 24 * time.Hour
)

// sessionCache implements cache.SessionCache.
type sessionCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewSessionCache creates a new SessionCache.
func NewSessionCache(client *redis.Client, ttl time.Duration) cache.SessionCache {
	if ttl == 0 {
		ttl = defaultSessionTTL
	}
	return &sessionCache{
		client: client,
		ttl:    ttl,
	}
}

func (c *sessionCache) Get(ctx context.Context, sessionID types.ID) (*model.Session, error) {
	key := sessionKey(sessionID)

	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("failed to get session from cache: %w", err)
	}

	var cached cachedSession
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return cached.toModel()
}

func (c *sessionCache) Set(ctx context.Context, session *model.Session, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.ttl
	}

	cached := newCachedSession(session)
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := sessionKey(session.ID())
	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set session in cache: %w", err)
	}

	// Also track session ID under user's session set
	userKey := userSessionsKey(session.UserID())
	if err := c.client.SAdd(ctx, userKey, session.ID().String()).Err(); err != nil {
		return fmt.Errorf("failed to add session to user set: %w", err)
	}
	c.client.Expire(ctx, userKey, ttl)

	return nil
}

func (c *sessionCache) Delete(ctx context.Context, sessionID types.ID) error {
	key := sessionKey(sessionID)
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session from cache: %w", err)
	}
	return nil
}

func (c *sessionCache) DeleteByUserID(ctx context.Context, userID types.ID) error {
	userKey := userSessionsKey(userID)

	// Get all session IDs for this user
	sessionIDs, err := c.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete all session keys
	if len(sessionIDs) > 0 {
		keys := make([]string, len(sessionIDs)+1)
		for i, sid := range sessionIDs {
			keys[i] = sessionKeyPrefix + sid
		}
		keys[len(sessionIDs)] = userKey

		if err := c.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete user sessions: %w", err)
		}
	}

	return nil
}

func (c *sessionCache) Exists(ctx context.Context, sessionID types.ID) (bool, error) {
	key := sessionKey(sessionID)
	count, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}
	return count > 0, nil
}

// Key helpers

func sessionKey(id types.ID) string {
	return sessionKeyPrefix + id.String()
}

func userSessionsKey(userID types.ID) string {
	return sessionUserKeyPrefix + userID.String()
}

// Cached session structure for JSON serialization

type cachedSession struct {
	ID               string  `json:"id"`
	UserID           string  `json:"user_id"`
	UserDID          string  `json:"user_did"`
	TenantID         *string `json:"tenant_id,omitempty"`
	RefreshTokenHash string  `json:"refresh_token_hash"`
	ExpiresAt        int64   `json:"expires_at"`
	CreatedAt        int64   `json:"created_at"`
	RevokedAt        *int64  `json:"revoked_at,omitempty"`
}

func newCachedSession(s *model.Session) cachedSession {
	cached := cachedSession{
		ID:               s.ID().String(),
		UserID:           s.UserID().String(),
		UserDID:          s.UserDID().String(),
		RefreshTokenHash: s.RefreshTokenHash(),
		ExpiresAt:        s.ExpiresAt().Time().Unix(),
		CreatedAt:        s.CreatedAt().Time().Unix(),
	}

	if s.TenantID().IsPresent() {
		tid := s.TenantID().MustGet().String()
		cached.TenantID = &tid
	}

	if s.RevokedAt().IsPresent() {
		ra := s.RevokedAt().MustGet().Time().Unix()
		cached.RevokedAt = &ra
	}

	return cached
}

func (c cachedSession) toModel() (*model.Session, error) {
	id, err := types.ParseID(c.ID)
	if err != nil {
		return nil, err
	}

	userID, err := types.ParseID(c.UserID)
	if err != nil {
		return nil, err
	}

	userDID, err := parseSecurityDID(c.UserDID)
	if err != nil {
		return nil, err
	}

	var tenantID types.Optional[types.ID]
	if c.TenantID != nil {
		tid, err := types.ParseID(*c.TenantID)
		if err == nil {
			tenantID = types.Some(tid)
		}
	}

	var revokedAt types.Optional[types.Timestamp]
	if c.RevokedAt != nil {
		revokedAt = types.Some(types.FromTime(time.Unix(*c.RevokedAt, 0)))
	}

	return model.ReconstructSession(
		id,
		userID,
		userDID,
		tenantID,
		c.RefreshTokenHash,
		types.FromTime(time.Unix(c.ExpiresAt, 0)),
		types.FromTime(time.Unix(c.CreatedAt, 0)),
		revokedAt,
	), nil
}
