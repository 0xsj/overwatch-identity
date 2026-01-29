package e2e

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	natsadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/nats"
	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	appcommand "github.com/0xsj/overwatch-identity/internal/app/command"
	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
)

func TestCreateAPIKeyFlow_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.apikey")
	defer cleanup()

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Create API key
	result, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Production Key",
		Scopes:    []string{"read:users", "write:users", "read:events"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	// Verify result
	if result.APIKey == nil {
		t.Fatal("APIKey should not be nil")
	}
	if result.Secret == "" {
		t.Error("Secret should not be empty")
	}
	if result.APIKey.Name() != "Production Key" {
		t.Errorf("Name = %v, want Production Key", result.APIKey.Name())
	}
	if len(result.APIKey.Scopes()) != 3 {
		t.Errorf("Scopes count = %d, want 3", len(result.APIKey.Scopes()))
	}
	if result.APIKey.UserID() != user.ID() {
		t.Errorf("UserID = %v, want %v", result.APIKey.UserID(), user.ID())
	}
	if result.APIKey.Status() != model.APIKeyStatusActive {
		t.Errorf("Status = %v, want %v", result.APIKey.Status(), model.APIKeyStatusActive)
	}

	// Verify persisted
	persistedKey, err := apiKeyRepo.FindByID(ctx, result.APIKey.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if persistedKey.Name() != "Production Key" {
		t.Errorf("Persisted Name = %v, want Production Key", persistedKey.Name())
	}

	// Verify event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeAPIKeyCreated] {
		t.Error("Missing apikey.created event")
	}
}

func TestCreateAPIKeyFlow_WithTenant(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	tenantID := types.NewID()

	// Create API key with tenant
	result, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Tenant Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.Some(tenantID),
		ExpiresAt: types.None[types.Timestamp](),
	})

	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	if !result.APIKey.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if result.APIKey.TenantID().MustGet() != tenantID {
		t.Errorf("TenantID = %v, want %v", result.APIKey.TenantID().MustGet(), tenantID)
	}
}

func TestCreateAPIKeyFlow_WithExpiry(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	expiresAt := types.FromTime(time.Now().Add(30 * 24 * time.Hour)) // 30 days

	// Create API key with expiry
	result, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Temporary Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.Some(expiresAt),
	})

	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	if !result.APIKey.ExpiresAt().IsPresent() {
		t.Error("ExpiresAt should be present")
	}
}

func TestCreateAPIKeyFlow_UserNotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	// Try to create API key for non-existent user
	_, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    types.NewID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	if err != domainerror.ErrUserNotFound {
		t.Errorf("CreateAPIKey() error = %v, want %v", err, domainerror.ErrUserNotFound)
	}
}

func TestCreateAPIKeyFlow_EmptyUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	var emptyUserID types.ID
	_, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    emptyUserID,
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	if err != domainerror.ErrUserIDRequired {
		t.Errorf("CreateAPIKey() error = %v, want %v", err, domainerror.ErrUserIDRequired)
	}
}

func TestCreateAPIKeyFlow_SuspendedUser(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	// Create suspended user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	user.Suspend()
	userRepo.Create(ctx, user)

	// Try to create API key for suspended user
	_, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	if err != domainerror.ErrUserSuspended {
		t.Errorf("CreateAPIKey() error = %v, want %v", err, domainerror.ErrUserSuspended)
	}
}

func TestCreateAPIKeyFlow_MultipleKeys(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Create multiple API keys
	for i := 0; i < 5; i++ {
		_, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
			UserID:    user.ID(),
			Name:      "Key " + string(rune('A'+i)),
			Scopes:    []string{"read:users"},
			TenantID:  types.None[types.ID](),
			ExpiresAt: types.None[types.Timestamp](),
		})
		if err != nil {
			t.Fatalf("CreateAPIKey() iteration %d error = %v", i, err)
		}
	}

	// Verify all keys exist
	keys, err := apiKeyRepo.FindActiveByUserID(ctx, user.ID())
	if err != nil {
		t.Fatalf("FindActiveByUserID() error = %v", err)
	}
	if len(keys) != 5 {
		t.Errorf("Expected 5 API keys, got %d", len(keys))
	}
}

func TestRevokeAPIKeyFlow_Success(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.apikey")
	defer cleanup()

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	apiKeyID := createResult.APIKey.ID()

	// Drain create event
	time.Sleep(50 * time.Millisecond)
	drainMessages(msgChan)

	// Revoke API key
	_, err := revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: apiKeyID,
		UserID:   user.ID(),
		Reason:   "no longer needed",
	})

	if err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	// Verify revoked
	revokedKey, err := apiKeyRepo.FindByID(ctx, apiKeyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if !revokedKey.IsRevoked() {
		t.Error("API key should be revoked")
	}
	if revokedKey.Status() != model.APIKeyStatusRevoked {
		t.Errorf("Status = %v, want %v", revokedKey.Status(), model.APIKeyStatusRevoked)
	}
	if !revokedKey.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be present")
	}

	// Verify no active keys
	activeKeys, _ := apiKeyRepo.FindActiveByUserID(ctx, user.ID())
	if len(activeKeys) != 0 {
		t.Errorf("Expected 0 active keys, got %d", len(activeKeys))
	}

	// Verify event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeAPIKeyRevoked] {
		t.Error("Missing apikey.revoked event")
	}
}

func TestRevokeAPIKeyFlow_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	_, err := revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: types.NewID(),
		UserID:   types.NewID(),
		Reason:   "test",
	})

	if err != domainerror.ErrAPIKeyNotFound {
		t.Errorf("RevokeAPIKey() error = %v, want %v", err, domainerror.ErrAPIKeyNotFound)
	}
}

func TestRevokeAPIKeyFlow_WrongUser(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Try to revoke with different user
	otherUserID := types.NewID()
	_, err := revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: createResult.APIKey.ID(),
		UserID:   otherUserID,
		Reason:   "test",
	})

	if err != domainerror.ErrAPIKeyNotFound {
		t.Errorf("RevokeAPIKey() with wrong user error = %v, want %v", err, domainerror.ErrAPIKeyNotFound)
	}
}

func TestRevokeAPIKeyFlow_AlreadyRevoked(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	apiKeyID := createResult.APIKey.ID()

	// Revoke first time
	_, _ = revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: apiKeyID,
		UserID:   user.ID(),
		Reason:   "first revoke",
	})

	// Try to revoke again
	_, err := revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: apiKeyID,
		UserID:   user.ID(),
		Reason:   "second revoke",
	})

	if err != domainerror.ErrAPIKeyRevoked {
		t.Errorf("RevokeAPIKey() already revoked error = %v, want %v", err, domainerror.ErrAPIKeyRevoked)
	}
}

func TestRevokeAPIKeyFlow_DefaultReason(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	// Create user and API key
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	createResult, _ := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Test Key",
		Scopes:    []string{"read:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})

	// Revoke without reason (should use default)
	_, err := revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: createResult.APIKey.ID(),
		UserID:   user.ID(),
		Reason:   "", // Empty reason
	})

	if err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	// Key should still be revoked
	revokedKey, _ := apiKeyRepo.FindByID(ctx, createResult.APIKey.ID())
	if !revokedKey.IsRevoked() {
		t.Error("API key should be revoked even with empty reason")
	}
}

func TestAPIKeyFlow_FullLifecycle(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Step 1: Create API key
	createResult, err := createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
		UserID:    user.ID(),
		Name:      "Lifecycle Test Key",
		Scopes:    []string{"read:users", "write:users"},
		TenantID:  types.None[types.ID](),
		ExpiresAt: types.None[types.Timestamp](),
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	apiKey := createResult.APIKey
	secret := createResult.Secret

	// Verify key is active
	if !apiKey.IsActive() {
		t.Error("New API key should be active")
	}

	// Step 2: Verify key can be found by hash
	foundKey, err := apiKeyRepo.FindByKeyHash(ctx, apiKey.KeyHash())
	if err != nil {
		t.Fatalf("FindByKeyHash() error = %v", err)
	}
	if foundKey.ID() != apiKey.ID() {
		t.Errorf("Found key ID = %v, want %v", foundKey.ID(), apiKey.ID())
	}

	// Step 3: Verify key can be found by prefix
	foundByPrefix, err := apiKeyRepo.FindByPrefix(ctx, apiKey.KeyPrefix())
	if err != nil {
		t.Fatalf("FindByPrefix() error = %v", err)
	}
	if foundByPrefix.ID() != apiKey.ID() {
		t.Errorf("Found by prefix ID = %v, want %v", foundByPrefix.ID(), apiKey.ID())
	}

	// Step 4: Simulate usage (record last used)
	foundKey.RecordUsage()
	apiKeyRepo.Update(ctx, foundKey)

	updatedKey, _ := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if !updatedKey.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should be present after usage")
	}

	// Step 5: Revoke the key
	_, err = revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
		APIKeyID: apiKey.ID(),
		UserID:   user.ID(),
		Reason:   "lifecycle complete",
	})
	if err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	// Verify final state
	finalKey, _ := apiKeyRepo.FindByID(ctx, apiKey.ID())
	if !finalKey.IsRevoked() {
		t.Error("Final key should be revoked")
	}
	if finalKey.Status() != model.APIKeyStatusRevoked {
		t.Errorf("Final status = %v, want %v", finalKey.Status(), model.APIKeyStatusRevoked)
	}

	// Secret should have been returned only at creation
	if secret == "" {
		t.Error("Secret should have been provided at creation")
	}
}

func TestAPIKeyFlow_DoesNotAffectOtherUsers(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	apiKeyRepo := postgres.NewAPIKeyRepository(getPool())
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	createAPIKeyHandler := appcommand.NewCreateAPIKeyHandler(userRepo, apiKeyRepo, publisher)
	revokeAPIKeyHandler := appcommand.NewRevokeAPIKeyHandler(apiKeyRepo, publisher)

	// Create user 1 with API keys
	kp1, _ := security.GenerateEd25519()
	did1, _ := security.DIDFromKeyPair(kp1)
	user1, _ := model.NewUser(did1)
	userRepo.Create(ctx, user1)

	for i := 0; i < 3; i++ {
		createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
			UserID:    user1.ID(),
			Name:      "User1 Key",
			Scopes:    []string{"read:users"},
			TenantID:  types.None[types.ID](),
			ExpiresAt: types.None[types.Timestamp](),
		})
	}

	// Create user 2 with API keys
	kp2, _ := security.GenerateEd25519()
	did2, _ := security.DIDFromKeyPair(kp2)
	user2, _ := model.NewUser(did2)
	userRepo.Create(ctx, user2)

	for i := 0; i < 2; i++ {
		createAPIKeyHandler.Handle(ctx, command.CreateAPIKey{
			UserID:    user2.ID(),
			Name:      "User2 Key",
			Scopes:    []string{"read:users"},
			TenantID:  types.None[types.ID](),
			ExpiresAt: types.None[types.Timestamp](),
		})
	}

	// Revoke all of user1's keys
	user1Keys, _ := apiKeyRepo.FindActiveByUserID(ctx, user1.ID())
	for _, key := range user1Keys {
		revokeAPIKeyHandler.Handle(ctx, command.RevokeAPIKey{
			APIKeyID: key.ID(),
			UserID:   user1.ID(),
			Reason:   "cleanup",
		})
	}

	// User 1 should have no active keys
	user1ActiveKeys, _ := apiKeyRepo.FindActiveByUserID(ctx, user1.ID())
	if len(user1ActiveKeys) != 0 {
		t.Errorf("User 1 should have 0 active keys, got %d", len(user1ActiveKeys))
	}

	// User 2 should still have keys
	user2ActiveKeys, _ := apiKeyRepo.FindActiveByUserID(ctx, user2.ID())
	if len(user2ActiveKeys) != 2 {
		t.Errorf("User 2 should have 2 active keys, got %d", len(user2ActiveKeys))
	}
}
