package grpc

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// --- toProtoUser Tests ---

func TestToProtoUser(t *testing.T) {
	t.Run("nil user returns nil", func(t *testing.T) {
		result := toProtoUser(nil)
		if result != nil {
			t.Error("expected nil result for nil user")
		}
	})

	t.Run("basic user mapping", func(t *testing.T) {
		user := createTestUser(t)

		result := toProtoUser(user)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != user.ID().String() {
			t.Errorf("Id = %v, want %v", result.Id, user.ID().String())
		}
		if result.Did != user.DID().String() {
			t.Errorf("Did = %v, want %v", result.Did, user.DID().String())
		}
		if result.Email != nil {
			t.Error("Email should be nil for user without email")
		}
		if result.Name != nil {
			t.Error("Name should be nil for user without name")
		}
	})

	t.Run("user with email and name", func(t *testing.T) {
		user := createTestUserWithDetails(t, "test@example.com", "Test User")

		result := toProtoUser(user)

		if result.Email == nil {
			t.Fatal("Email should not be nil")
		}
		if *result.Email != "test@example.com" {
			t.Errorf("Email = %v, want test@example.com", *result.Email)
		}
		if result.Name == nil {
			t.Fatal("Name should not be nil")
		}
		if *result.Name != "Test User" {
			t.Errorf("Name = %v, want Test User", *result.Name)
		}
	})

	t.Run("user status mapping", func(t *testing.T) {
		user := createTestUser(t)

		result := toProtoUser(user)

		// Active by default
		if result.Status.String() != "USER_STATUS_ACTIVE" {
			t.Errorf("Status = %v, want USER_STATUS_ACTIVE", result.Status)
		}
	})

	t.Run("timestamps are set", func(t *testing.T) {
		user := createTestUser(t)

		result := toProtoUser(user)

		if result.CreatedAt == nil {
			t.Error("CreatedAt should not be nil")
		}
		if result.UpdatedAt == nil {
			t.Error("UpdatedAt should not be nil")
		}
	})
}

// --- toProtoSession Tests ---

func TestToProtoSession(t *testing.T) {
	t.Run("nil session returns nil", func(t *testing.T) {
		result := toProtoSession(nil)
		if result != nil {
			t.Error("expected nil result for nil session")
		}
	})

	t.Run("basic session mapping", func(t *testing.T) {
		user := createTestUser(t)
		session := createTestSession(t, user)

		result := toProtoSession(session)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != session.ID().String() {
			t.Errorf("Id = %v, want %v", result.Id, session.ID().String())
		}
		if result.UserId != session.UserID().String() {
			t.Errorf("UserId = %v, want %v", result.UserId, session.UserID().String())
		}
		if result.UserDid != session.UserDID().String() {
			t.Errorf("UserDid = %v, want %v", result.UserDid, session.UserDID().String())
		}
		if result.TenantId != nil {
			t.Error("TenantId should be nil for session without tenant")
		}
	})

	t.Run("session with tenant", func(t *testing.T) {
		user := createTestUser(t)
		tenantID := types.NewID()
		session := createTestSessionWithTenant(t, user, tenantID)

		result := toProtoSession(session)

		if result.TenantId == nil {
			t.Fatal("TenantId should not be nil")
		}
		if *result.TenantId != tenantID.String() {
			t.Errorf("TenantId = %v, want %v", *result.TenantId, tenantID.String())
		}
	})

	t.Run("revoked session has revoked_at", func(t *testing.T) {
		user := createTestUser(t)
		session := createTestSession(t, user)
		session.Revoke() // No argument

		result := toProtoSession(session)

		if result.RevokedAt == nil {
			t.Error("RevokedAt should not be nil for revoked session")
		}
	})
}

// --- toProtoSessions Tests ---

func TestToProtoSessions(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := toProtoSessions([]*model.Session{})
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %d elements", len(result))
		}
	})

	t.Run("multiple sessions", func(t *testing.T) {
		user := createTestUser(t)
		sessions := []*model.Session{
			createTestSession(t, user),
			createTestSession(t, user),
			createTestSession(t, user),
		}

		result := toProtoSessions(sessions)

		if len(result) != 3 {
			t.Errorf("expected 3 sessions, got %d", len(result))
		}
	})
}

// --- toProtoAPIKey Tests ---

func TestToProtoAPIKey(t *testing.T) {
	t.Run("nil apikey returns nil", func(t *testing.T) {
		result := toProtoAPIKey(nil)
		if result != nil {
			t.Error("expected nil result for nil apikey")
		}
	})

	t.Run("basic apikey mapping", func(t *testing.T) {
		user := createTestUser(t)
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users", "write:users"},
			types.None[types.ID](),
			types.None[types.Timestamp](),
		)

		result := toProtoAPIKey(apiKeyResult.APIKey)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != apiKeyResult.APIKey.ID().String() {
			t.Errorf("Id = %v, want %v", result.Id, apiKeyResult.APIKey.ID().String())
		}
		if result.UserId != user.ID().String() {
			t.Errorf("UserId = %v, want %v", result.UserId, user.ID().String())
		}
		if result.Name != "Test Key" {
			t.Errorf("Name = %v, want Test Key", result.Name)
		}
		if len(result.Scopes) != 2 {
			t.Errorf("Scopes count = %d, want 2", len(result.Scopes))
		}
		if result.TenantId != nil {
			t.Error("TenantId should be nil")
		}
		if result.ExpiresAt != nil {
			t.Error("ExpiresAt should be nil")
		}
	})

	t.Run("apikey with tenant and expiry", func(t *testing.T) {
		user := createTestUser(t)
		tenantID := types.NewID()
		expiresAt := types.FromTime(time.Now().Add(24 * time.Hour))
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users"},
			types.Some(tenantID),
			types.Some(expiresAt),
		)

		result := toProtoAPIKey(apiKeyResult.APIKey)

		if result.TenantId == nil {
			t.Fatal("TenantId should not be nil")
		}
		if *result.TenantId != tenantID.String() {
			t.Errorf("TenantId = %v, want %v", *result.TenantId, tenantID.String())
		}
		if result.ExpiresAt == nil {
			t.Fatal("ExpiresAt should not be nil")
		}
	})

	t.Run("revoked apikey has revoked_at", func(t *testing.T) {
		user := createTestUser(t)
		apiKeyResult, _ := model.NewAPIKey(
			user.ID(),
			"Test Key",
			[]string{"read:users"},
			types.None[types.ID](),
			types.None[types.Timestamp](),
		)
		apiKeyResult.APIKey.Revoke()

		result := toProtoAPIKey(apiKeyResult.APIKey)

		if result.RevokedAt == nil {
			t.Error("RevokedAt should not be nil for revoked apikey")
		}
		if result.Status.String() != "API_KEY_STATUS_REVOKED" {
			t.Errorf("Status = %v, want API_KEY_STATUS_REVOKED", result.Status)
		}
	})
}

// --- toProtoAPIKeys Tests ---

func TestToProtoAPIKeys(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := toProtoAPIKeys([]*model.APIKey{})
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %d elements", len(result))
		}
	})

	t.Run("multiple apikeys", func(t *testing.T) {
		user := createTestUser(t)
		apiKeys := make([]*model.APIKey, 3)
		for i := 0; i < 3; i++ {
			result, _ := model.NewAPIKey(
				user.ID(),
				"Key",
				[]string{"read"},
				types.None[types.ID](),
				types.None[types.Timestamp](),
			)
			apiKeys[i] = result.APIKey
		}

		result := toProtoAPIKeys(apiKeys)

		if len(result) != 3 {
			t.Errorf("expected 3 apikeys, got %d", len(result))
		}
	})
}

// --- toOptionalTenantID Tests ---

func TestToOptionalTenantID(t *testing.T) {
	t.Run("nil returns None", func(t *testing.T) {
		result := toOptionalTenantID(nil)
		if result.IsPresent() {
			t.Error("expected None for nil input")
		}
	})

	t.Run("empty string returns None", func(t *testing.T) {
		empty := ""
		result := toOptionalTenantID(&empty)
		if result.IsPresent() {
			t.Error("expected None for empty string")
		}
	})

	t.Run("invalid UUID returns None", func(t *testing.T) {
		invalid := "not-a-uuid"
		result := toOptionalTenantID(&invalid)
		if result.IsPresent() {
			t.Error("expected None for invalid UUID")
		}
	})

	t.Run("valid UUID returns Some", func(t *testing.T) {
		id := types.NewID()
		idStr := id.String()
		result := toOptionalTenantID(&idStr)
		if !result.IsPresent() {
			t.Fatal("expected Some for valid UUID")
		}
		if result.MustGet() != id {
			t.Errorf("ID = %v, want %v", result.MustGet(), id)
		}
	})
}

// --- toOptionalString Tests ---

func TestToOptionalString(t *testing.T) {
	t.Run("nil returns None", func(t *testing.T) {
		result := toOptionalString(nil)
		if result.IsPresent() {
			t.Error("expected None for nil input")
		}
	})

	t.Run("empty string returns None", func(t *testing.T) {
		empty := ""
		result := toOptionalString(&empty)
		if result.IsPresent() {
			t.Error("expected None for empty string")
		}
	})

	t.Run("non-empty string returns Some", func(t *testing.T) {
		value := "test value"
		result := toOptionalString(&value)
		if !result.IsPresent() {
			t.Fatal("expected Some for non-empty string")
		}
		if result.MustGet() != "test value" {
			t.Errorf("value = %v, want test value", result.MustGet())
		}
	})
}

// --- toOptionalEmail Tests ---

func TestToOptionalEmail(t *testing.T) {
	t.Run("nil returns None", func(t *testing.T) {
		result := toOptionalEmail(nil)
		if result.IsPresent() {
			t.Error("expected None for nil input")
		}
	})

	t.Run("empty string returns None", func(t *testing.T) {
		empty := ""
		result := toOptionalEmail(&empty)
		if result.IsPresent() {
			t.Error("expected None for empty string")
		}
	})

	t.Run("invalid email returns None", func(t *testing.T) {
		invalid := "not-an-email"
		result := toOptionalEmail(&invalid)
		if result.IsPresent() {
			t.Error("expected None for invalid email")
		}
	})

	t.Run("valid email returns Some", func(t *testing.T) {
		email := "test@example.com"
		result := toOptionalEmail(&email)
		if !result.IsPresent() {
			t.Fatal("expected Some for valid email")
		}
		if result.MustGet().String() != "test@example.com" {
			t.Errorf("email = %v, want test@example.com", result.MustGet().String())
		}
	})
}

// --- toOptionalTimestamp Tests ---

func TestToOptionalTimestamp(t *testing.T) {
	t.Run("nil returns None", func(t *testing.T) {
		result := toOptionalTimestamp(nil)
		if result.IsPresent() {
			t.Error("expected None for nil input")
		}
	})

	t.Run("valid timestamp returns Some", func(t *testing.T) {
		now := time.Now()
		ts := timestampFromTime(now)
		result := toOptionalTimestamp(ts)
		if !result.IsPresent() {
			t.Fatal("expected Some for valid timestamp")
		}
		// Allow 1 second difference due to conversion
		diff := result.MustGet().Time().Sub(now)
		if diff > time.Second || diff < -time.Second {
			t.Errorf("timestamp difference too large: %v", diff)
		}
	})
}

// --- Test Helpers ---

func createTestUserWithDetails(t *testing.T, email, name string) *model.User {
	t.Helper()
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)

	e, _ := types.NewEmail(email)
	user.SetEmail(e)
	user.SetName(name)

	return user
}

func createTestSessionWithTenant(t *testing.T, user *model.User, tenantID types.ID) *model.Session {
	t.Helper()
	session, _ := model.NewSession(
		user.ID(),
		user.DID(),
		types.Some(tenantID),
		"hash",
		model.DefaultSessionConfig(),
	)
	return session
}

// Helper to create protobuf timestamp
func timestampFromTime(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}
