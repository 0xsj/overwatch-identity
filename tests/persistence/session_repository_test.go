package persistence

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

func TestSessionRepository_Create(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	// Create user first (foreign key)
	user := createTestUser(t)
	userRepo.Create(ctx, user)

	session := createTestSession(t, user)

	err := sessionRepo.Create(ctx, session)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify by reading back
	found, err := sessionRepo.FindByID(ctx, session.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != session.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), session.ID())
	}
	if found.UserID() != user.ID() {
		t.Errorf("UserID = %v, want %v", found.UserID(), user.ID())
	}
}

func TestSessionRepository_Create_WithTenant(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	tenantID := types.NewID()
	session, _ := model.NewSession(
		user.ID(),
		user.DID(),
		types.Some(tenantID),
		"refreshhash",
		model.DefaultSessionConfig(),
	)

	err := sessionRepo.Create(ctx, session)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	found, _ := sessionRepo.FindByID(ctx, session.ID())
	if !found.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if found.TenantID().MustGet() != tenantID {
		t.Errorf("TenantID = %v, want %v", found.TenantID().MustGet(), tenantID)
	}
}

func TestSessionRepository_Update(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	session := createTestSession(t, user)
	sessionRepo.Create(ctx, session)

	// Refresh the session
	session.Refresh("newhash", 24*time.Hour)

	err := sessionRepo.Update(ctx, session)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	found, _ := sessionRepo.FindByID(ctx, session.ID())
	if found.RefreshTokenHash() != "newhash" {
		t.Errorf("RefreshTokenHash = %v, want newhash", found.RefreshTokenHash())
	}
}

func TestSessionRepository_FindByID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	session := createTestSession(t, user)
	sessionRepo.Create(ctx, session)

	found, err := sessionRepo.FindByID(ctx, session.ID())

	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != session.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), session.ID())
	}
}

func TestSessionRepository_FindByID_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	sessionRepo := postgres.NewSessionRepository(getPool())

	_, err := sessionRepo.FindByID(ctx, types.NewID())

	if err != repository.ErrNotFound {
		t.Errorf("FindByID() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestSessionRepository_FindByRefreshTokenHash(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	session, _ := model.NewSession(
		user.ID(),
		user.DID(),
		types.None[types.ID](),
		"uniquehash123",
		model.DefaultSessionConfig(),
	)
	sessionRepo.Create(ctx, session)

	found, err := sessionRepo.FindByRefreshTokenHash(ctx, "uniquehash123")

	if err != nil {
		t.Fatalf("FindByRefreshTokenHash() error = %v", err)
	}
	if found.ID() != session.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), session.ID())
	}
}

func TestSessionRepository_FindByRefreshTokenHash_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	sessionRepo := postgres.NewSessionRepository(getPool())

	_, err := sessionRepo.FindByRefreshTokenHash(ctx, "nonexistenthash")

	if err != repository.ErrNotFound {
		t.Errorf("FindByRefreshTokenHash() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestSessionRepository_FindActiveByUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 active sessions
	for i := 0; i < 3; i++ {
		session := createTestSession(t, user)
		sessionRepo.Create(ctx, session)
	}

	// Create 1 revoked session
	revokedSession := createTestSession(t, user)
	sessionRepo.Create(ctx, revokedSession)
	sessionRepo.RevokeByID(ctx, revokedSession.ID())

	sessions, err := sessionRepo.FindActiveByUserID(ctx, user.ID())

	if err != nil {
		t.Fatalf("FindActiveByUserID() error = %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("FindActiveByUserID() returned %d sessions, want 3", len(sessions))
	}
}

func TestSessionRepository_List(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 5 sessions
	for i := 0; i < 5; i++ {
		session := createTestSession(t, user)
		sessionRepo.Create(ctx, session)
	}

	params := repository.DefaultListSessionsParams()
	params.Limit = 10
	params.ActiveOnly = false

	sessions, err := sessionRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(sessions) != 5 {
		t.Errorf("List() returned %d sessions, want 5", len(sessions))
	}
}

func TestSessionRepository_List_WithUserFilter(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user1 := createTestUser(t)
	user2 := createTestUser(t)
	userRepo.Create(ctx, user1)
	userRepo.Create(ctx, user2)

	// Create 3 sessions for user1
	for i := 0; i < 3; i++ {
		session := createTestSession(t, user1)
		sessionRepo.Create(ctx, session)
	}

	// Create 2 sessions for user2
	for i := 0; i < 2; i++ {
		session := createTestSession(t, user2)
		sessionRepo.Create(ctx, session)
	}

	userID := user1.ID()
	params := repository.DefaultListSessionsParams()
	params.UserID = &userID
	params.ActiveOnly = false

	sessions, err := sessionRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("List() returned %d sessions, want 3", len(sessions))
	}
}

func TestSessionRepository_List_ActiveOnly(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 active sessions
	for i := 0; i < 3; i++ {
		session := createTestSession(t, user)
		sessionRepo.Create(ctx, session)
	}

	// Create 2 revoked sessions
	for i := 0; i < 2; i++ {
		session := createTestSession(t, user)
		sessionRepo.Create(ctx, session)
		sessionRepo.RevokeByID(ctx, session.ID())
	}

	params := repository.DefaultListSessionsParams()
	params.ActiveOnly = true

	sessions, err := sessionRepo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("List() returned %d active sessions, want 3", len(sessions))
	}
}

func TestSessionRepository_Count(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	for i := 0; i < 5; i++ {
		session := createTestSession(t, user)
		sessionRepo.Create(ctx, session)
	}

	params := repository.DefaultListSessionsParams()
	params.ActiveOnly = false

	count, err := sessionRepo.Count(ctx, params)

	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 5 {
		t.Errorf("Count() = %d, want 5", count)
	}
}

func TestSessionRepository_RevokeByID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	session := createTestSession(t, user)
	sessionRepo.Create(ctx, session)

	err := sessionRepo.RevokeByID(ctx, session.ID())

	if err != nil {
		t.Fatalf("RevokeByID() error = %v", err)
	}

	found, _ := sessionRepo.FindByID(ctx, session.ID())
	if !found.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be present after revoke")
	}
}

func TestSessionRepository_RevokeAllByUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create 3 sessions
	for i := 0; i < 3; i++ {
		session := createTestSession(t, user)
		sessionRepo.Create(ctx, session)
	}

	count, err := sessionRepo.RevokeAllByUserID(ctx, user.ID())

	if err != nil {
		t.Fatalf("RevokeAllByUserID() error = %v", err)
	}
	if count != 3 {
		t.Errorf("RevokeAllByUserID() = %d, want 3", count)
	}

	// Verify all revoked
	sessions, _ := sessionRepo.FindActiveByUserID(ctx, user.ID())
	if len(sessions) != 0 {
		t.Errorf("FindActiveByUserID() returned %d sessions, want 0", len(sessions))
	}
}

func TestSessionRepository_DeleteExpired(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	userRepo := postgres.NewUserRepository(getPool())
	sessionRepo := postgres.NewSessionRepository(getPool())

	user := createTestUser(t)
	userRepo.Create(ctx, user)

	// Create active session
	activeSession := createTestSession(t, user)
	sessionRepo.Create(ctx, activeSession)

	// Create expired session via direct SQL (since model won't allow creating expired)
	expiredSession := model.ReconstructSession(
		types.NewID(),
		user.ID(),
		user.DID(),
		types.None[types.ID](),
		"expiredhash",
		types.FromTime(time.Now().Add(-time.Hour)), // expired
		types.FromTime(time.Now().Add(-2*time.Hour)),
		types.None[types.Timestamp](),
	)
	// Need to insert directly since Create uses the params
	pool := getPool()
	_, err := pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, user_did, tenant_id, refresh_token_hash, expires_at, created_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, expiredSession.ID().String(), expiredSession.UserID().String(), expiredSession.UserDID().String(),
		nil, expiredSession.RefreshTokenHash(), expiredSession.ExpiresAt().Time(), expiredSession.CreatedAt().Time(), nil)
	if err != nil {
		t.Fatalf("failed to insert expired session: %v", err)
	}

	count, err := sessionRepo.DeleteExpired(ctx)

	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}
	if count != 1 {
		t.Errorf("DeleteExpired() = %d, want 1", count)
	}

	// Active session should still exist
	_, err = sessionRepo.FindByID(ctx, activeSession.ID())
	if err != nil {
		t.Errorf("Active session should still exist: %v", err)
	}
}

// --- Helpers ---

func createTestSession(t *testing.T, user *model.User) *model.Session {
	t.Helper()
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		types.None[types.ID](),
		randomHash(),
		model.DefaultSessionConfig(),
	)
	if err != nil {
		t.Fatalf("failed to create test session: %v", err)
	}
	return session
}

func randomHash() string {
	return types.NewID().String() + types.NewID().String()
}
