package integration

import (
	"testing"
	"time"

	redisadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/redis"
)

func TestTokenBlacklist_AddAndCheck(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	tokenID := "token-123"

	// Should not be blacklisted initially
	blacklisted, err := blacklist.IsBlacklisted(ctx, tokenID)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if blacklisted {
		t.Error("Token should not be blacklisted initially")
	}

	// Add to blacklist
	err = blacklist.Add(ctx, tokenID, time.Hour)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Should be blacklisted now
	blacklisted, err = blacklist.IsBlacklisted(ctx, tokenID)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !blacklisted {
		t.Error("Token should be blacklisted after Add")
	}
}

func TestTokenBlacklist_AddWithTTL(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	tokenID := "expiring-token"

	// Add with short TTL
	err := blacklist.Add(ctx, tokenID, 1*time.Second)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Should be blacklisted
	blacklisted, _ := blacklist.IsBlacklisted(ctx, tokenID)
	if !blacklisted {
		t.Error("Token should be blacklisted immediately")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Should no longer be blacklisted
	blacklisted, _ = blacklist.IsBlacklisted(ctx, tokenID)
	if blacklisted {
		t.Error("Token should not be blacklisted after TTL expires")
	}
}

func TestTokenBlacklist_Remove(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	tokenID := "removable-token"

	// Add to blacklist
	blacklist.Add(ctx, tokenID, time.Hour)

	// Verify blacklisted
	blacklisted, _ := blacklist.IsBlacklisted(ctx, tokenID)
	if !blacklisted {
		t.Fatal("Token should be blacklisted")
	}

	// Remove from blacklist
	err := blacklist.Remove(ctx, tokenID)
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	// Verify no longer blacklisted
	blacklisted, _ = blacklist.IsBlacklisted(ctx, tokenID)
	if blacklisted {
		t.Error("Token should not be blacklisted after Remove")
	}
}

func TestTokenBlacklist_RemoveNonExistent(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	// Remove non-existent should not error
	err := blacklist.Remove(ctx, "non-existent-token")

	if err != nil {
		t.Errorf("Remove() non-existent error = %v, want nil", err)
	}
}

func TestTokenBlacklist_EmptyTokenID(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	// Add empty token should not error
	err := blacklist.Add(ctx, "", time.Hour)
	if err != nil {
		t.Errorf("Add() empty token error = %v, want nil", err)
	}

	// Check empty token should return false
	blacklisted, err := blacklist.IsBlacklisted(ctx, "")
	if err != nil {
		t.Errorf("IsBlacklisted() empty token error = %v", err)
	}
	if blacklisted {
		t.Error("Empty token should not be considered blacklisted")
	}

	// Remove empty token should not error
	err = blacklist.Remove(ctx, "")
	if err != nil {
		t.Errorf("Remove() empty token error = %v, want nil", err)
	}
}

func TestTokenBlacklist_MultipleTokens(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	tokens := []string{"token-1", "token-2", "token-3"}

	// Add all tokens
	for _, token := range tokens {
		blacklist.Add(ctx, token, time.Hour)
	}

	// Verify all blacklisted
	for _, token := range tokens {
		blacklisted, _ := blacklist.IsBlacklisted(ctx, token)
		if !blacklisted {
			t.Errorf("Token %s should be blacklisted", token)
		}
	}

	// Remove one
	blacklist.Remove(ctx, "token-2")

	// Verify state
	blacklisted1, _ := blacklist.IsBlacklisted(ctx, "token-1")
	if !blacklisted1 {
		t.Error("token-1 should still be blacklisted")
	}

	blacklisted2, _ := blacklist.IsBlacklisted(ctx, "token-2")
	if blacklisted2 {
		t.Error("token-2 should not be blacklisted after Remove")
	}

	blacklisted3, _ := blacklist.IsBlacklisted(ctx, "token-3")
	if !blacklisted3 {
		t.Error("token-3 should still be blacklisted")
	}
}

func TestTokenBlacklist_LongTokenID(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	// JWT-like long token ID
	longTokenID := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"

	// Add and verify
	err := blacklist.Add(ctx, longTokenID, time.Hour)
	if err != nil {
		t.Fatalf("Add() long token error = %v", err)
	}

	blacklisted, err := blacklist.IsBlacklisted(ctx, longTokenID)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !blacklisted {
		t.Error("Long token should be blacklisted")
	}
}

func TestTokenBlacklist_SpecialCharacters(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	blacklist := redisadapter.NewTokenBlacklist(getRedisClient())

	// Token with special characters
	specialToken := "token:with:colons/and/slashes+and+plus"

	err := blacklist.Add(ctx, specialToken, time.Hour)
	if err != nil {
		t.Fatalf("Add() special token error = %v", err)
	}

	blacklisted, _ := blacklist.IsBlacklisted(ctx, specialToken)
	if !blacklisted {
		t.Error("Special token should be blacklisted")
	}
}
