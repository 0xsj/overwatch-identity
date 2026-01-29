package model_test

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestNewAPIKey(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		userID := types.NewID()
		name := "My API Key"
		scopes := []string{"read:users", "write:users"}
		tenantID := types.None[types.ID]()
		expiresAt := types.None[types.Timestamp]()

		result, err := model.NewAPIKey(userID, name, scopes, tenantID, expiresAt)

		if err != nil {
			t.Fatalf("NewAPIKey() error = %v", err)
		}
		if result == nil {
			t.Fatal("NewAPIKey() returned nil")
		}
		if result.APIKey == nil {
			t.Fatal("APIKey should not be nil")
		}
		if result.Secret == "" {
			t.Error("Secret should not be empty")
		}

		apiKey := result.APIKey
		if apiKey.ID().IsEmpty() {
			t.Error("ID should not be empty")
		}
		if apiKey.UserID() != userID {
			t.Errorf("UserID = %v, want %v", apiKey.UserID(), userID)
		}
		if apiKey.Name() != name {
			t.Errorf("Name = %v, want %v", apiKey.Name(), name)
		}
		if apiKey.Status() != model.APIKeyStatusActive {
			t.Errorf("Status = %v, want %v", apiKey.Status(), model.APIKeyStatusActive)
		}
		if apiKey.KeyPrefix() == "" {
			t.Error("KeyPrefix should not be empty")
		}
		if apiKey.KeyHash() == "" {
			t.Error("KeyHash should not be empty")
		}
		if apiKey.CreatedAt().IsZero() {
			t.Error("CreatedAt should be set")
		}
		if apiKey.RevokedAt().IsPresent() {
			t.Error("RevokedAt should be empty")
		}
		if !apiKey.IsValid() {
			t.Error("apiKey should be valid")
		}
	})

	t.Run("with tenant ID", func(t *testing.T) {
		userID := types.NewID()
		tenantID := types.Some(types.NewID())

		result, err := model.NewAPIKey(userID, "Key", []string{"read"}, tenantID, types.None[types.Timestamp]())

		if err != nil {
			t.Fatalf("NewAPIKey() error = %v", err)
		}
		if !result.APIKey.TenantID().IsPresent() {
			t.Error("TenantID should be present")
		}
		if !result.APIKey.HasTenant() {
			t.Error("HasTenant() should return true")
		}
	})

	t.Run("with expiry", func(t *testing.T) {
		userID := types.NewID()
		expiresAt := types.Some(types.FromTime(time.Now().Add(24 * time.Hour)))

		result, err := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), expiresAt)

		if err != nil {
			t.Fatalf("NewAPIKey() error = %v", err)
		}
		if !result.APIKey.ExpiresAt().IsPresent() {
			t.Error("ExpiresAt should be present")
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		result, err := model.NewAPIKey(types.ID(""), "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		if err == nil {
			t.Fatal("NewAPIKey() with empty userID should return error")
		}
		if result != nil {
			t.Error("result should be nil")
		}
		if err != domainerror.ErrUserIDRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserIDRequired)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		userID := types.NewID()

		result, err := model.NewAPIKey(userID, "", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		if err == nil {
			t.Fatal("NewAPIKey() with empty name should return error")
		}
		if result != nil {
			t.Error("result should be nil")
		}
		if err != domainerror.ErrAPIKeyNameRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrAPIKeyNameRequired)
		}
	})

	t.Run("whitespace only name", func(t *testing.T) {
		userID := types.NewID()

		_, err := model.NewAPIKey(userID, "   ", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		if err == nil {
			t.Fatal("NewAPIKey() with whitespace name should return error")
		}
		if err != domainerror.ErrAPIKeyNameRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrAPIKeyNameRequired)
		}
	})

	t.Run("scopes are normalized", func(t *testing.T) {
		userID := types.NewID()
		scopes := []string{"  READ:USERS  ", "write:users", "READ:USERS"} // duplicates and case

		result, err := model.NewAPIKey(userID, "Key", scopes, types.None[types.ID](), types.None[types.Timestamp]())

		if err != nil {
			t.Fatalf("NewAPIKey() error = %v", err)
		}

		normalizedScopes := result.APIKey.Scopes()
		// Should be deduplicated and lowercased
		if len(normalizedScopes) != 2 {
			t.Errorf("Scopes count = %d, want 2", len(normalizedScopes))
		}
	})
}

func TestAPIKey_Revoke(t *testing.T) {
	t.Run("active key", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
		apiKey := result.APIKey

		err := apiKey.Revoke()

		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		if !apiKey.IsRevoked() {
			t.Error("IsRevoked() should return true")
		}
		if apiKey.Status() != model.APIKeyStatusRevoked {
			t.Errorf("Status = %v, want %v", apiKey.Status(), model.APIKeyStatusRevoked)
		}
		if !apiKey.RevokedAt().IsPresent() {
			t.Error("RevokedAt should be present")
		}
		if apiKey.IsValid() {
			t.Error("IsValid() should return false")
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
		apiKey := result.APIKey
		apiKey.Revoke()

		err := apiKey.Revoke()

		if err == nil {
			t.Fatal("Revoke() on revoked key should return error")
		}
		if err != domainerror.ErrAPIKeyRevoked {
			t.Errorf("error = %v, want %v", err, domainerror.ErrAPIKeyRevoked)
		}
	})
}

func TestAPIKey_RecordUsage(t *testing.T) {
	userID := types.NewID()
	result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
	apiKey := result.APIKey

	if apiKey.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should be empty initially")
	}

	apiKey.RecordUsage()

	if !apiKey.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should be present after RecordUsage()")
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	t.Run("no expiry", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		if result.APIKey.IsExpired() {
			t.Error("IsExpired() should return false for key with no expiry")
		}
	})

	t.Run("future expiry", func(t *testing.T) {
		userID := types.NewID()
		expiresAt := types.Some(types.FromTime(time.Now().Add(24 * time.Hour)))
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), expiresAt)

		if result.APIKey.IsExpired() {
			t.Error("IsExpired() should return false for future expiry")
		}
	})

	t.Run("past expiry", func(t *testing.T) {
		userID := types.NewID()

		apiKey := model.ReconstructAPIKey(
			types.NewID(),
			userID,
			"Key",
			"ow_test_",
			"somehash",
			[]string{"read"},
			model.APIKeyStatusActive,
			types.None[types.ID](),
			types.Some(types.FromTime(time.Now().Add(-time.Hour))), // expired
			types.None[types.Timestamp](),
			types.Now(),
			types.None[types.Timestamp](),
		)

		if !apiKey.IsExpired() {
			t.Error("IsExpired() should return true for past expiry")
		}
	})
}

func TestAPIKey_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *model.APIKey
		want  bool
	}{
		{
			name: "active not expired",
			setup: func() *model.APIKey {
				userID := types.NewID()
				result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
				return result.APIKey
			},
			want: true,
		},
		{
			name: "revoked",
			setup: func() *model.APIKey {
				userID := types.NewID()
				result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
				result.APIKey.Revoke()
				return result.APIKey
			},
			want: false,
		},
		{
			name: "expired",
			setup: func() *model.APIKey {
				userID := types.NewID()
				return model.ReconstructAPIKey(
					types.NewID(),
					userID,
					"Key",
					"ow_test_",
					"somehash",
					[]string{"read"},
					model.APIKeyStatusActive,
					types.None[types.ID](),
					types.Some(types.FromTime(time.Now().Add(-time.Hour))),
					types.None[types.Timestamp](),
					types.Now(),
					types.None[types.Timestamp](),
				)
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey := tt.setup()
			if got := apiKey.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIKey_Validate(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		err := result.APIKey.Validate()

		if err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("revoked key", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
		result.APIKey.Revoke()

		err := result.APIKey.Validate()

		if err != domainerror.ErrAPIKeyRevoked {
			t.Errorf("Validate() error = %v, want %v", err, domainerror.ErrAPIKeyRevoked)
		}
	})

	t.Run("expired key", func(t *testing.T) {
		userID := types.NewID()
		apiKey := model.ReconstructAPIKey(
			types.NewID(),
			userID,
			"Key",
			"ow_test_",
			"somehash",
			[]string{"read"},
			model.APIKeyStatusActive,
			types.None[types.ID](),
			types.Some(types.FromTime(time.Now().Add(-time.Hour))),
			types.None[types.Timestamp](),
			types.Now(),
			types.None[types.Timestamp](),
		)

		err := apiKey.Validate()

		if err != domainerror.ErrAPIKeyExpired {
			t.Errorf("Validate() error = %v, want %v", err, domainerror.ErrAPIKeyExpired)
		}
	})
}

func TestAPIKey_VerifyKey(t *testing.T) {
	t.Run("correct key", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		err := result.APIKey.VerifyKey(result.Secret)

		if err != nil {
			t.Errorf("VerifyKey() error = %v, want nil", err)
		}
	})

	t.Run("incorrect key", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())

		err := result.APIKey.VerifyKey("wrong_key")

		if err != domainerror.ErrAPIKeyInvalid {
			t.Errorf("VerifyKey() error = %v, want %v", err, domainerror.ErrAPIKeyInvalid)
		}
	})

	t.Run("revoked key", func(t *testing.T) {
		userID := types.NewID()
		result, _ := model.NewAPIKey(userID, "Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
		result.APIKey.Revoke()

		err := result.APIKey.VerifyKey(result.Secret)

		if err != domainerror.ErrAPIKeyRevoked {
			t.Errorf("VerifyKey() error = %v, want %v", err, domainerror.ErrAPIKeyRevoked)
		}
	})
}

func TestAPIKey_HasScope(t *testing.T) {
	userID := types.NewID()
	scopes := []string{"read:users", "write:users", "read:*", "*"}
	result, _ := model.NewAPIKey(userID, "Key", scopes, types.None[types.ID](), types.None[types.Timestamp]())
	apiKey := result.APIKey

	tests := []struct {
		scope string
		want  bool
	}{
		{"read:users", true},
		{"write:users", true},
		{"delete:users", true},   // matches * wildcard
		{"read:sources", true},   // matches read:*
		{"write:sources", true},  // matches *
		{"READ:USERS", true},     // case insensitive
		{"  read:users  ", true}, // trimmed
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			if got := apiKey.HasScope(tt.scope); got != tt.want {
				t.Errorf("HasScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestAPIKey_HasAllScopes(t *testing.T) {
	userID := types.NewID()
	scopes := []string{"read:users", "write:users"}
	result, _ := model.NewAPIKey(userID, "Key", scopes, types.None[types.ID](), types.None[types.Timestamp]())
	apiKey := result.APIKey

	tests := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"all present", []string{"read:users", "write:users"}, true},
		{"subset", []string{"read:users"}, true},
		{"empty", []string{}, true},
		{"missing one", []string{"read:users", "delete:users"}, false},
		{"all missing", []string{"delete:users"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiKey.HasAllScopes(tt.scopes); got != tt.want {
				t.Errorf("HasAllScopes(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

func TestAPIKey_HasAnyScope(t *testing.T) {
	userID := types.NewID()
	scopes := []string{"read:users", "write:users"}
	result, _ := model.NewAPIKey(userID, "Key", scopes, types.None[types.ID](), types.None[types.Timestamp]())
	apiKey := result.APIKey

	tests := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"all present", []string{"read:users", "write:users"}, true},
		{"one present", []string{"read:users", "delete:users"}, true},
		{"empty", []string{}, true},
		{"none present", []string{"delete:users", "admin"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiKey.HasAnyScope(tt.scopes); got != tt.want {
				t.Errorf("HasAnyScope(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

func TestAPIKeyStatus_IsValid(t *testing.T) {
	tests := []struct {
		status model.APIKeyStatus
		want   bool
	}{
		{model.APIKeyStatusActive, true},
		{model.APIKeyStatusRevoked, true},
		{model.APIKeyStatus("invalid"), false},
		{model.APIKeyStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIKeyStatus_String(t *testing.T) {
	tests := []struct {
		status model.APIKeyStatus
		want   string
	}{
		{model.APIKeyStatusActive, "active"},
		{model.APIKeyStatusRevoked, "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconstructAPIKey(t *testing.T) {
	id := types.NewID()
	userID := types.NewID()
	name := "Test Key"
	keyPrefix := "ow_abc12"
	keyHash := "somehash123"
	scopes := []string{"read:users", "write:users"}
	status := model.APIKeyStatusActive
	tenantID := types.Some(types.NewID())
	expiresAt := types.Some(types.FromTime(time.Now().Add(24 * time.Hour)))
	lastUsedAt := types.Some(types.Now())
	createdAt := types.Now()
	revokedAt := types.None[types.Timestamp]()

	apiKey := model.ReconstructAPIKey(
		id,
		userID,
		name,
		keyPrefix,
		keyHash,
		scopes,
		status,
		tenantID,
		expiresAt,
		lastUsedAt,
		createdAt,
		revokedAt,
	)

	if apiKey.ID() != id {
		t.Errorf("ID = %v, want %v", apiKey.ID(), id)
	}
	if apiKey.UserID() != userID {
		t.Errorf("UserID = %v, want %v", apiKey.UserID(), userID)
	}
	if apiKey.Name() != name {
		t.Errorf("Name = %v, want %v", apiKey.Name(), name)
	}
	if apiKey.KeyPrefix() != keyPrefix {
		t.Errorf("KeyPrefix = %v, want %v", apiKey.KeyPrefix(), keyPrefix)
	}
	if apiKey.KeyHash() != keyHash {
		t.Errorf("KeyHash = %v, want %v", apiKey.KeyHash(), keyHash)
	}
	if len(apiKey.Scopes()) != len(scopes) {
		t.Errorf("Scopes count = %d, want %d", len(apiKey.Scopes()), len(scopes))
	}
	if apiKey.Status() != status {
		t.Errorf("Status = %v, want %v", apiKey.Status(), status)
	}
	if !apiKey.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if !apiKey.ExpiresAt().IsPresent() {
		t.Error("ExpiresAt should be present")
	}
	if !apiKey.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should be present")
	}
	if apiKey.CreatedAt() != createdAt {
		t.Errorf("CreatedAt = %v, want %v", apiKey.CreatedAt(), createdAt)
	}
	if apiKey.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be empty")
	}
}
