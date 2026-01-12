package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
)

const (
	tokenBlacklistKeyPrefix = "identity:blacklist:"
)

// tokenBlacklist implements cache.TokenBlacklist.
type tokenBlacklist struct {
	client *redis.Client
}

// NewTokenBlacklist creates a new TokenBlacklist.
func NewTokenBlacklist(client *redis.Client) cache.TokenBlacklist {
	return &tokenBlacklist{
		client: client,
	}
}

func (b *tokenBlacklist) Add(ctx context.Context, tokenID string, ttl time.Duration) error {
	if tokenID == "" {
		return nil
	}

	key := blacklistKey(tokenID)

	// Value doesn't matter, we just check existence
	if err := b.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("failed to add token to blacklist: %w", err)
	}

	return nil
}

func (b *tokenBlacklist) IsBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}

	key := blacklistKey(tokenID)

	count, err := b.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}

	return count > 0, nil
}

func (b *tokenBlacklist) Remove(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return nil
	}

	key := blacklistKey(tokenID)

	if err := b.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to remove token from blacklist: %w", err)
	}

	return nil
}

// Key helper

func blacklistKey(tokenID string) string {
	return tokenBlacklistKeyPrefix + tokenID
}
