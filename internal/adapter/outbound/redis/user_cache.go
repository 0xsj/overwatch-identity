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
	userKeyPrefix    = "identity:user:"
	userDIDKeyPrefix = "identity:user_did:"
	defaultUserTTL   = 1 * time.Hour
)

// userCache implements cache.UserCache.
type userCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewUserCache creates a new UserCache.
func NewUserCache(client *redis.Client, ttl time.Duration) cache.UserCache {
	if ttl == 0 {
		ttl = defaultUserTTL
	}
	return &userCache{
		client: client,
		ttl:    ttl,
	}
}

func (c *userCache) Get(ctx context.Context, userID types.ID) (*model.User, error) {
	key := userKey(userID)

	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("failed to get user from cache: %w", err)
	}

	var cached cachedUser
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return cached.toModel()
}

func (c *userCache) GetByDID(ctx context.Context, did string) (*model.User, error) {
	// First, get the user ID from the DID index
	didKey := userDIDKey(did)
	userID, err := c.client.Get(ctx, didKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("failed to get user ID from DID index: %w", err)
	}

	// Then fetch the user by ID
	id, err := types.ParseID(userID)
	if err != nil {
		return nil, nil // Invalid ID in cache, treat as miss
	}

	return c.Get(ctx, id)
}

func (c *userCache) Set(ctx context.Context, user *model.User, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.ttl
	}

	cached := newCachedUser(user)
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	// Set user data
	key := userKey(user.ID())
	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set user in cache: %w", err)
	}

	// Set DID index
	didKey := userDIDKey(user.DID().String())
	if err := c.client.Set(ctx, didKey, user.ID().String(), ttl).Err(); err != nil {
		return fmt.Errorf("failed to set user DID index: %w", err)
	}

	return nil
}

func (c *userCache) Delete(ctx context.Context, userID types.ID) error {
	// First try to get the user to find its DID
	user, err := c.Get(ctx, userID)
	if err != nil {
		return err
	}

	key := userKey(userID)
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete user from cache: %w", err)
	}

	// Also delete DID index if we found the user
	if user != nil {
		didKey := userDIDKey(user.DID().String())
		c.client.Del(ctx, didKey)
	}

	return nil
}

func (c *userCache) DeleteByDID(ctx context.Context, did string) error {
	// Get user ID from DID index
	didKey := userDIDKey(did)
	userID, err := c.client.Get(ctx, didKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // Not in cache
		}
		return fmt.Errorf("failed to get user ID from DID index: %w", err)
	}

	// Delete both keys
	key := userKeyPrefix + userID
	if err := c.client.Del(ctx, key, didKey).Err(); err != nil {
		return fmt.Errorf("failed to delete user from cache: %w", err)
	}

	return nil
}

// Key helpers

func userKey(id types.ID) string {
	return userKeyPrefix + id.String()
}

func userDIDKey(did string) string {
	return userDIDKeyPrefix + did
}

// Cached user structure for JSON serialization

type cachedUser struct {
	ID        string  `json:"id"`
	DID       string  `json:"did"`
	Email     *string `json:"email,omitempty"`
	Name      *string `json:"name,omitempty"`
	Status    string  `json:"status"`
	CreatedAt int64   `json:"created_at"`
	UpdatedAt int64   `json:"updated_at"`
}

func newCachedUser(u *model.User) cachedUser {
	cached := cachedUser{
		ID:        u.ID().String(),
		DID:       u.DID().String(),
		Status:    u.Status().String(),
		CreatedAt: u.CreatedAt().Time().Unix(),
		UpdatedAt: u.UpdatedAt().Time().Unix(),
	}

	if u.Email().IsPresent() {
		email := u.Email().MustGet().String()
		cached.Email = &email
	}

	if u.Name().IsPresent() {
		name := u.Name().MustGet()
		cached.Name = &name
	}

	return cached
}

func (c cachedUser) toModel() (*model.User, error) {
	id, err := types.ParseID(c.ID)
	if err != nil {
		return nil, err
	}

	did, err := parseSecurityDID(c.DID)
	if err != nil {
		return nil, err
	}

	var email types.Optional[types.Email]
	if c.Email != nil {
		e, err := types.NewEmail(*c.Email)
		if err == nil {
			email = types.Some(e)
		}
	}

	var name types.Optional[string]
	if c.Name != nil {
		name = types.Some(*c.Name)
	}

	return model.ReconstructUser(
		id,
		did,
		email,
		name,
		model.UserStatus(c.Status),
		types.FromTime(time.Unix(c.CreatedAt, 0)),
		types.FromTime(time.Unix(c.UpdatedAt, 0)),
	), nil
}
