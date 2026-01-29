package persistence

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

func TestAPIKeyRepository_Create(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey

	err := apiKeyRepo.Create(ctx, apiKey)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify by reading back
	found, err := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != apiKey.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), apiKey.ID())
	}
	if found.UserID() != user.ID() {
		t.Errorf("UserID = %v, want %v", found.UserID(), user.ID())
	}
	if found.Name() != apiKey.Name() {
		t.Errorf("Name = %v, want %v", found.Name(), apiKey.Name())
	}
}

func TestAPIKeyRepository_Create_WithTenantAndExpiry(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	tenantID := types.NewID()
	expiresAt := types.FromTime(time.Now().Add(24 * time.Hour))

	apiKeyWithSecret, _ := model.NewAPIKey(
		user.ID(),
		"Tenant Key",
		[]string{"read:users"},
		types.Some(tenantID),
		types.Some(expiresAt),
	)
	apiKey := apiKeyWithSecret.APIKey

	err := apiKeyRepo.Create(ctx, apiKey)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	found, _ := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if !found.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if found.TenantID().MustGet() != tenantID {
		t.Errorf("TenantID = %v, want %v", found.TenantID().MustGet(), tenantID)
	}
	if !found.ExpiresAt().IsPresent() {
		t.Error("ExpiresAt should be present")
	}
}

func TestAPIKeyRepository_Update(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	// Record usage
	apiKey.RecordUsage()

	err := apiKeyRepo.Update(ctx, apiKey)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	found, _ := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if !found.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should be present after RecordUsage")
	}
}

func TestAPIKeyRepository_Update_Revoke(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	apiKey.Revoke()
	err := apiKeyRepo.Update(ctx, apiKey)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	found, _ := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if found.Status() != model.APIKeyStatusRevoked {
		t.Errorf("Status = %v, want %v", found.Status(), model.APIKeyStatusRevoked)
	}
	if !found.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be present")
	}
}

func TestAPIKeyRepository_FindByID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	found, err := apiKeyRepo.FindByID(ctx, apiKey.ID())

	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != apiKey.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), apiKey.ID())
	}
}

func TestAPIKeyRepository_FindByID_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	_, err := apiKeyRepo.FindByID(ctx, types.NewID())

	if err != repository.ErrNotFound {
		t.Errorf("FindByID() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestAPIKeyRepository_FindByKeyHash(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	found, err := apiKeyRepo.FindByKeyHash(ctx, apiKey.KeyHash())

	if err != nil {
		t.Fatalf("FindByKeyHash() error = %v", err)
	}
	if found.ID() != apiKey.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), apiKey.ID())
	}
}

func TestAPIKeyRepository_FindByKeyHash_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	_, err := apiKeyRepo.FindByKeyHash(ctx, "nonexistenthash")

	if err != repository.ErrNotFound {
		t.Errorf("FindByKeyHash() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestAPIKeyRepository_FindByPrefix(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	found, err := apiKeyRepo.FindByPrefix(ctx, apiKey.KeyPrefix())

	if err != nil {
		t.Fatalf("FindByPrefix() error = %v", err)
	}
	if found.ID() != apiKey.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), apiKey.ID())
	}
}

func TestAPIKeyRepository_FindByPrefix_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	_, err := apiKeyRepo.FindByPrefix(ctx, "ow_nonex")

	if err != repository.ErrNotFound {
		t.Errorf("FindByPrefix() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestAPIKeyRepository_FindActiveByUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 active API keys
	for i := 0; i < 3; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	// Create 1 revoked API key
	revokedKeyWithSecret := createTestAPIKey(t, user)
	revokedKey := revokedKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, revokedKey)
	apiKeyRepo.RevokeByID(ctx, revokedKey.ID())

	apiKeys, err := apiKeyRepo.FindActiveByUserID(ctx, user.ID())

	if err != nil {
		t.Fatalf("FindActiveByUserID() error = %v", err)
	}
	if len(apiKeys) != 3 {
		t.Errorf("FindActiveByUserID() returned %d keys, want 3", len(apiKeys))
	}
}

func TestAPIKeyRepository_List(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 5 API keys
	for i := 0; i < 5; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	params := repository.DefaultListAPIKeysParams()
	params.Limit = 10
	params.ActiveOnly = false

	apiKeys, err := apiKeyRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(apiKeys) != 5 {
		t.Errorf("List() returned %d keys, want 5", len(apiKeys))
	}
}

func TestAPIKeyRepository_List_WithUserFilter(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user1 := createTestUser(t)
	user2 := createTestUser(t)
	userRepo.Create(ctx, user1)
	userRepo.Create(ctx, user2)

	// Create 3 keys for user1
	for i := 0; i < 3; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user1)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	// Create 2 keys for user2
	for i := 0; i < 2; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user2)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	userID := user1.ID()
	params := repository.DefaultListAPIKeysParams()
	params.UserID = &userID
	params.ActiveOnly = false

	apiKeys, err := apiKeyRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(apiKeys) != 3 {
		t.Errorf("List() returned %d keys, want 3", len(apiKeys))
	}
}

func TestAPIKeyRepository_List_WithStatusFilter(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 active keys
	for i := 0; i < 3; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	// Create 2 revoked keys
	for i := 0; i < 2; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKey := apiKeyWithSecret.APIKey
		apiKeyRepo.Create(ctx, apiKey)
		apiKeyRepo.RevokeByID(ctx, apiKey.ID())
	}

	revokedStatus := model.APIKeyStatusRevoked
	params := repository.DefaultListAPIKeysParams()
	params.Status = &revokedStatus
	params.ActiveOnly = false

	apiKeys, err := apiKeyRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(apiKeys) != 2 {
		t.Errorf("List() returned %d revoked keys, want 2", len(apiKeys))
	}
}

func TestAPIKeyRepository_List_ActiveOnly(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 active keys
	for i := 0; i < 3; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	// Create 2 revoked keys
	for i := 0; i < 2; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKey := apiKeyWithSecret.APIKey
		apiKeyRepo.Create(ctx, apiKey)
		apiKeyRepo.RevokeByID(ctx, apiKey.ID())
	}

	params := repository.DefaultListAPIKeysParams()
	params.ActiveOnly = true

	apiKeys, err := apiKeyRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(apiKeys) != 3 {
		t.Errorf("List() returned %d active keys, want 3", len(apiKeys))
	}
}

func TestAPIKeyRepository_Count(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	for i := 0; i < 5; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	params := repository.DefaultListAPIKeysParams()
	params.ActiveOnly = false

	count, err := apiKeyRepo.Count(ctx, params)

	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 5 {
		t.Errorf("Count() = %d, want 5", count)
	}
}

func TestAPIKeyRepository_RevokeByID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	err := apiKeyRepo.RevokeByID(ctx, apiKey.ID())

	if err != nil {
		t.Fatalf("RevokeByID() error = %v", err)
	}

	found, _ := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if found.Status() != model.APIKeyStatusRevoked {
		t.Errorf("Status = %v, want %v", found.Status(), model.APIKeyStatusRevoked)
	}
	if !found.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be present after revoke")
	}
}

func TestAPIKeyRepository_RevokeAllByUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 keys
	for i := 0; i < 3; i++ {
		apiKeyWithSecret := createTestAPIKey(t, user)
		apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey)
	}

	count, err := apiKeyRepo.RevokeAllByUserID(ctx, user.ID())

	if err != nil {
		t.Fatalf("RevokeAllByUserID() error = %v", err)
	}
	if count != 3 {
		t.Errorf("RevokeAllByUserID() = %d, want 3", count)
	}

	// Verify all revoked
	apiKeys, _ := apiKeyRepo.FindActiveByUserID(ctx, user.ID())
	if len(apiKeys) != 0 {
		t.Errorf("FindActiveByUserID() returned %d keys, want 0", len(apiKeys))
	}
}

func TestAPIKeyRepository_Delete(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	apiKeyWithSecret := createTestAPIKey(t, user)
	apiKey := apiKeyWithSecret.APIKey
	apiKeyRepo.Create(ctx, apiKey)

	err := apiKeyRepo.Delete(ctx, apiKey.ID())

	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = apiKeyRepo.FindByID(ctx, apiKey.ID())
	if err != repository.ErrNotFound {
		t.Errorf("FindByID() after delete error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestAPIKeyRepository_DeleteExpired(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())

	// Create user
	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create API key that expired MORE than 30 days ago
	oldExpiredKey := model.ReconstructAPIKey(
		types.NewID(),
		user.ID(),
		"Old Expired Key",
		"ow_old",
		"oldhash123",
		[]string{"read:users"},
		model.APIKeyStatusActive,
		types.None[types.ID](),
		types.Some(types.FromTime(time.Now().Add(-31*24*time.Hour))), // Expired 31 days ago
		types.None[types.Timestamp](),
		types.FromTime(time.Now().Add(-60*24*time.Hour)), // Created 60 days ago
		types.None[types.Timestamp](),
	)
	apiKeyRepo.Create(ctx, oldExpiredKey)

	// Create API key that expired recently (should NOT be deleted)
	recentlyExpiredKey := model.ReconstructAPIKey(
		types.NewID(),
		user.ID(),
		"Recently Expired Key",
		"ow_rec",
		"recenthash123",
		[]string{"read:users"},
		model.APIKeyStatusActive,
		types.None[types.ID](),
		types.Some(types.FromTime(time.Now().Add(-1*time.Hour))), // Expired 1 hour ago
		types.None[types.Timestamp](),
		types.FromTime(time.Now().Add(-24*time.Hour)),
		types.None[types.Timestamp](),
	)
	apiKeyRepo.Create(ctx, recentlyExpiredKey)

	// Create active API key without expiry (should NOT be deleted)
	activeKey, _ := model.NewAPIKey(
		user.ID(),
		"Active Key",
		[]string{"read:users"},
		types.None[types.ID](),
		types.None[types.Timestamp](),
	)
	apiKeyRepo.Create(ctx, activeKey.APIKey)

	// Delete expired API keys
	count, err := apiKeyRepo.DeleteExpired(ctx)

	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}
	if count != 1 {
		t.Errorf("DeleteExpired() = %d, want 1", count)
	}

	// Verify only the old expired key was deleted
	_, err = apiKeyRepo.FindByID(ctx, oldExpiredKey.ID())
	if err == nil {
		t.Error("Old expired API key should be deleted")
	}

	// Recently expired key should still exist
	_, err = apiKeyRepo.FindByID(ctx, recentlyExpiredKey.ID())
	if err != nil {
		t.Error("Recently expired API key should still exist")
	}

	// Active key should still exist
	_, err = apiKeyRepo.FindByID(ctx, activeKey.APIKey.ID())
	if err != nil {
		t.Error("Active API key should still exist")
	}
}

// --- Helpers ---

func createTestAPIKey(t *testing.T, user *model.User) *model.APIKeyWithSecret {
	t.Helper()
	apiKeyWithSecret, err := model.NewAPIKey(
		user.ID(),
		"Test Key "+types.NewID().String()[:8],
		[]string{"read:users", "write:users"},
		types.None[types.ID](),
		types.None[types.Timestamp](),
	)
	if err != nil {
		t.Fatalf("failed to create test API key: %v", err)
	}
	return apiKeyWithSecret
}
