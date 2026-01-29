package integration

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	redisadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/redis"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestSessionCache_SetAndGet(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)

	// Create a session
	session := createTestSession(t)

	// Set in cache
	err := cache.Set(ctx, session, 0)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get from cache
	retrieved, err := cache.Get(ctx, session.ID())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved session should not be nil")
	}
	if retrieved.ID() != session.ID() {
		t.Errorf("ID = %v, want %v", retrieved.ID(), session.ID())
	}
	if retrieved.UserID() != session.UserID() {
		t.Errorf("UserID = %v, want %v", retrieved.UserID(), session.UserID())
	}
	if retrieved.UserDID().String() != session.UserDID().String() {
		t.Errorf("UserDID = %v, want %v", retrieved.UserDID().String(), session.UserDID().String())
	}
	if retrieved.RefreshTokenHash() != session.RefreshTokenHash() {
		t.Errorf("RefreshTokenHash = %v, want %v", retrieved.RefreshTokenHash(), session.RefreshTokenHash())
	}
}

func TestSessionCache_GetCacheMiss(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)

	// Get non-existent session
	retrieved, err := cache.Get(ctx, types.NewID())

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Retrieved session should be nil for cache miss")
	}
}

func TestSessionCache_SetWithCustomTTL(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)
	session := createTestSession(t)

	// Set with short TTL
	err := cache.Set(ctx, session, 1*time.Second)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify exists
	exists, _ := cache.Exists(ctx, session.ID())
	if !exists {
		t.Error("Session should exist immediately after set")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Verify expired
	retrieved, _ := cache.Get(ctx, session.ID())
	if retrieved != nil {
		t.Error("Session should be expired")
	}
}

func TestSessionCache_Delete(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)
	session := createTestSession(t)

	// Set and verify
	cache.Set(ctx, session, 0)
	exists, _ := cache.Exists(ctx, session.ID())
	if !exists {
		t.Fatal("Session should exist before delete")
	}

	// Delete
	err := cache.Delete(ctx, session.ID())
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted
	exists, _ = cache.Exists(ctx, session.ID())
	if exists {
		t.Error("Session should not exist after delete")
	}
}

func TestSessionCache_DeleteNonExistent(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)

	// Delete non-existent should not error
	err := cache.Delete(ctx, types.NewID())

	if err != nil {
		t.Errorf("Delete() non-existent error = %v, want nil", err)
	}
}

func TestSessionCache_DeleteByUserID(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	userID := types.NewID()

	// Create multiple sessions for same user
	var sessionIDs []types.ID
	for i := 0; i < 3; i++ {
		session, _ := model.NewSession(
			userID,
			did,
			types.None[types.ID](),
			"hash"+string(rune('A'+i)),
			model.DefaultSessionConfig(),
		)
		cache.Set(ctx, session, 0)
		sessionIDs = append(sessionIDs, session.ID())
	}

	// Verify all exist
	for _, sid := range sessionIDs {
		exists, _ := cache.Exists(ctx, sid)
		if !exists {
			t.Fatalf("Session %v should exist", sid)
		}
	}

	// Delete by user ID
	err := cache.DeleteByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("DeleteByUserID() error = %v", err)
	}

	// Verify all deleted
	for _, sid := range sessionIDs {
		exists, _ := cache.Exists(ctx, sid)
		if exists {
			t.Errorf("Session %v should not exist after DeleteByUserID", sid)
		}
	}
}

func TestSessionCache_DeleteByUserID_DoesNotAffectOtherUsers(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)

	// Create user 1 sessions
	kp1, _ := security.GenerateEd25519()
	did1, _ := security.DIDFromKeyPair(kp1)
	userID1 := types.NewID()

	session1, _ := model.NewSession(userID1, did1, types.None[types.ID](), "hash1", model.DefaultSessionConfig())
	cache.Set(ctx, session1, 0)

	// Create user 2 sessions
	kp2, _ := security.GenerateEd25519()
	did2, _ := security.DIDFromKeyPair(kp2)
	userID2 := types.NewID()

	session2, _ := model.NewSession(userID2, did2, types.None[types.ID](), "hash2", model.DefaultSessionConfig())
	cache.Set(ctx, session2, 0)

	// Delete user 1 sessions
	cache.DeleteByUserID(ctx, userID1)

	// User 1 session should be deleted
	exists1, _ := cache.Exists(ctx, session1.ID())
	if exists1 {
		t.Error("User 1 session should be deleted")
	}

	// User 2 session should still exist
	exists2, _ := cache.Exists(ctx, session2.ID())
	if !exists2 {
		t.Error("User 2 session should still exist")
	}
}

func TestSessionCache_Exists(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)
	session := createTestSession(t)

	// Should not exist initially
	exists, err := cache.Exists(ctx, session.ID())
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Session should not exist initially")
	}

	// Set and verify
	cache.Set(ctx, session, 0)

	exists, err = cache.Exists(ctx, session.ID())
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Session should exist after Set")
	}
}

func TestSessionCache_WithTenant(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)

	// Create session with tenant
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	userID := types.NewID()
	tenantID := types.NewID()

	session, _ := model.NewSession(userID, did, types.Some(tenantID), "hash", model.DefaultSessionConfig())

	// Set and retrieve
	cache.Set(ctx, session, 0)
	retrieved, _ := cache.Get(ctx, session.ID())

	if !retrieved.TenantID().IsPresent() {
		t.Fatal("TenantID should be present")
	}
	if retrieved.TenantID().MustGet() != tenantID {
		t.Errorf("TenantID = %v, want %v", retrieved.TenantID().MustGet(), tenantID)
	}
}

func TestSessionCache_RevokedSession(t *testing.T) {
	flushRedis(t)
	ctx := getContext()

	cache := redisadapter.NewSessionCache(getRedisClient(), time.Hour)
	session := createTestSession(t)

	// Revoke the session
	session.Revoke()

	// Set and retrieve
	cache.Set(ctx, session, 0)
	retrieved, _ := cache.Get(ctx, session.ID())

	if !retrieved.IsRevoked() {
		t.Error("Retrieved session should be revoked")
	}
	if !retrieved.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be present")
	}
}

// --- Helper ---

func createTestSession(t *testing.T) *model.Session {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}

	session, err := model.NewSession(
		types.NewID(),
		did,
		types.None[types.ID](),
		"refreshtokenhash123",
		model.DefaultSessionConfig(),
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	return session
}
