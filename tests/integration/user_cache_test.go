package integration

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	redisadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/redis"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestUserCache_SetAndGet(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)
	user := createTestUser(t)

	// Set in cache
	err := cache.Set(ctx, user, 0)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get from cache
	retrieved, err := cache.Get(ctx, user.ID())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved user should not be nil")
	}
	if retrieved.ID() != user.ID() {
		t.Errorf("ID = %v, want %v", retrieved.ID(), user.ID())
	}
	if retrieved.DID().String() != user.DID().String() {
		t.Errorf("DID = %v, want %v", retrieved.DID().String(), user.DID().String())
	}
	if retrieved.Status() != user.Status() {
		t.Errorf("Status = %v, want %v", retrieved.Status(), user.Status())
	}
}

func TestUserCache_GetByDID(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)
	user := createTestUser(t)

	// Set in cache
	cache.Set(ctx, user, 0)

	// Get by DID
	retrieved, err := cache.GetByDID(ctx, user.DID().String())
	if err != nil {
		t.Fatalf("GetByDID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved user should not be nil")
	}
	if retrieved.ID() != user.ID() {
		t.Errorf("ID = %v, want %v", retrieved.ID(), user.ID())
	}
}

func TestUserCache_GetCacheMiss(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Get non-existent user
	retrieved, err := cache.Get(ctx, types.NewID())

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Retrieved user should be nil for cache miss")
	}
}

func TestUserCache_GetByDIDCacheMiss(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Get by non-existent DID
	retrieved, err := cache.GetByDID(ctx, "did:key:nonexistent")

	if err != nil {
		t.Fatalf("GetByDID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Retrieved user should be nil for cache miss")
	}
}

func TestUserCache_SetWithCustomTTL(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)
	user := createTestUser(t)

	// Set with short TTL
	err := cache.Set(ctx, user, 1*time.Second)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify exists
	retrieved, _ := cache.Get(ctx, user.ID())
	if retrieved == nil {
		t.Error("User should exist immediately after set")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Verify expired
	retrieved, _ = cache.Get(ctx, user.ID())
	if retrieved != nil {
		t.Error("User should be expired")
	}
}

func TestUserCache_Delete(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)
	user := createTestUser(t)

	// Set and verify
	cache.Set(ctx, user, 0)
	retrieved, _ := cache.Get(ctx, user.ID())
	if retrieved == nil {
		t.Fatal("User should exist before delete")
	}

	// Delete
	err := cache.Delete(ctx, user.ID())
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted by ID
	retrieved, _ = cache.Get(ctx, user.ID())
	if retrieved != nil {
		t.Error("User should not exist after delete")
	}

	// Verify DID index also deleted
	retrieved, _ = cache.GetByDID(ctx, user.DID().String())
	if retrieved != nil {
		t.Error("User should not be retrievable by DID after delete")
	}
}

func TestUserCache_DeleteByDID(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)
	user := createTestUser(t)

	// Set and verify
	cache.Set(ctx, user, 0)

	// Delete by DID
	err := cache.DeleteByDID(ctx, user.DID().String())
	if err != nil {
		t.Fatalf("DeleteByDID() error = %v", err)
	}

	// Verify deleted by both ID and DID
	retrieved, _ := cache.Get(ctx, user.ID())
	if retrieved != nil {
		t.Error("User should not exist after DeleteByDID")
	}

	retrieved, _ = cache.GetByDID(ctx, user.DID().String())
	if retrieved != nil {
		t.Error("User should not be retrievable by DID after DeleteByDID")
	}
}

func TestUserCache_DeleteNonExistent(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Delete non-existent should not error
	err := cache.Delete(ctx, types.NewID())

	if err != nil {
		t.Errorf("Delete() non-existent error = %v, want nil", err)
	}
}

func TestUserCache_DeleteByDIDNonExistent(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Delete non-existent should not error
	err := cache.DeleteByDID(ctx, "did:key:nonexistent")

	if err != nil {
		t.Errorf("DeleteByDID() non-existent error = %v, want nil", err)
	}
}

func TestUserCache_WithEmail(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Create user with email
	user := createTestUser(t)
	email, _ := types.NewEmail("test@example.com")
	user.SetEmail(email)

	// Set and retrieve
	cache.Set(ctx, user, 0)
	retrieved, _ := cache.Get(ctx, user.ID())

	if !retrieved.Email().IsPresent() {
		t.Fatal("Email should be present")
	}
	if retrieved.Email().MustGet().String() != "test@example.com" {
		t.Errorf("Email = %v, want test@example.com", retrieved.Email().MustGet().String())
	}
}

func TestUserCache_WithName(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Create user with name
	user := createTestUser(t)
	user.SetName("Alice")

	// Set and retrieve
	cache.Set(ctx, user, 0)
	retrieved, _ := cache.Get(ctx, user.ID())

	if !retrieved.Name().IsPresent() {
		t.Fatal("Name should be present")
	}
	if retrieved.Name().MustGet() != "Alice" {
		t.Errorf("Name = %v, want Alice", retrieved.Name().MustGet())
	}
}

func TestUserCache_SuspendedUser(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)

	// Create suspended user
	user := createTestUser(t)
	user.Suspend()

	// Set and retrieve
	cache.Set(ctx, user, 0)
	retrieved, _ := cache.Get(ctx, user.ID())

	if retrieved.Status() != model.UserStatusSuspended {
		t.Errorf("Status = %v, want %v", retrieved.Status(), model.UserStatusSuspended)
	}
}

func TestUserCache_UpdateUser(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewUserCache(getRedisClient(), time.Hour)
	user := createTestUser(t)

	// Set initial user
	cache.Set(ctx, user, 0)

	// Update user
	email, _ := types.NewEmail("updated@example.com")
	user.SetEmail(email)
	user.SetName("Updated Name")

	// Set again (update)
	cache.Set(ctx, user, 0)

	// Retrieve and verify
	retrieved, _ := cache.Get(ctx, user.ID())
	if retrieved.Email().MustGet().String() != "updated@example.com" {
		t.Errorf("Email = %v, want updated@example.com", retrieved.Email().MustGet().String())
	}
	if retrieved.Name().MustGet() != "Updated Name" {
		t.Errorf("Name = %v, want Updated Name", retrieved.Name().MustGet())
	}
}

// --- Helper ---

func createTestUser(t *testing.T) *model.User {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	user, err := model.NewUser(did)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}
