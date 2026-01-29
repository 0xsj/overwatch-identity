package model_test

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestNewSession(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		tenantID := types.None[types.ID]()
		refreshTokenHash := "somehash123"
		config := model.DefaultSessionConfig()

		session, err := model.NewSession(userID, userDID, tenantID, refreshTokenHash, config)

		if err != nil {
			t.Fatalf("NewSession() error = %v", err)
		}
		if session == nil {
			t.Fatal("NewSession() returned nil")
		}
		if session.ID().IsEmpty() {
			t.Error("session ID should not be empty")
		}
		if session.UserID() != userID {
			t.Errorf("UserID = %v, want %v", session.UserID(), userID)
		}
		if session.UserDID() != userDID {
			t.Errorf("UserDID = %v, want %v", session.UserDID(), userDID)
		}
		if session.TenantID().IsPresent() {
			t.Error("TenantID should be empty")
		}
		if session.RefreshTokenHash() != refreshTokenHash {
			t.Errorf("RefreshTokenHash = %v, want %v", session.RefreshTokenHash(), refreshTokenHash)
		}
		if session.CreatedAt().IsZero() {
			t.Error("CreatedAt should be set")
		}
		if session.ExpiresAt().IsZero() {
			t.Error("ExpiresAt should be set")
		}
		if session.RevokedAt().IsPresent() {
			t.Error("RevokedAt should be empty")
		}
		if !session.IsValid() {
			t.Error("session should be valid")
		}
	})

	t.Run("with tenant ID", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		tenantID := types.Some(types.NewID())
		refreshTokenHash := "somehash123"
		config := model.DefaultSessionConfig()

		session, err := model.NewSession(userID, userDID, tenantID, refreshTokenHash, config)

		if err != nil {
			t.Fatalf("NewSession() error = %v", err)
		}
		if !session.TenantID().IsPresent() {
			t.Error("TenantID should be present")
		}
		if !session.HasTenant() {
			t.Error("HasTenant() should return true")
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		userDID := testDID(t)
		refreshTokenHash := "somehash123"
		config := model.DefaultSessionConfig()

		session, err := model.NewSession(types.ID(""), userDID, types.None[types.ID](), refreshTokenHash, config)

		if err == nil {
			t.Fatal("NewSession() with empty userID should return error")
		}
		if session != nil {
			t.Error("session should be nil")
		}
		if err != domainerror.ErrUserIDRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserIDRequired)
		}
	})

	t.Run("nil user DID", func(t *testing.T) {
		userID := types.NewID()
		refreshTokenHash := "somehash123"
		config := model.DefaultSessionConfig()

		session, err := model.NewSession(userID, nil, types.None[types.ID](), refreshTokenHash, config)

		if err == nil {
			t.Fatal("NewSession() with nil userDID should return error")
		}
		if session != nil {
			t.Error("session should be nil")
		}
		if err != domainerror.ErrUserDIDRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserDIDRequired)
		}
	})

	t.Run("empty refresh token hash", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		config := model.DefaultSessionConfig()

		session, err := model.NewSession(userID, userDID, types.None[types.ID](), "", config)

		if err == nil {
			t.Fatal("NewSession() with empty refreshTokenHash should return error")
		}
		if session != nil {
			t.Error("session should be nil")
		}
		if err != domainerror.ErrRefreshTokenInvalid {
			t.Errorf("error = %v, want %v", err, domainerror.ErrRefreshTokenInvalid)
		}
	})
}

func TestSession_Revoke(t *testing.T) {
	t.Run("valid session", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())

		err := session.Revoke()

		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		if !session.IsRevoked() {
			t.Error("IsRevoked() should return true")
		}
		if !session.RevokedAt().IsPresent() {
			t.Error("RevokedAt should be present")
		}
		if session.IsValid() {
			t.Error("IsValid() should return false")
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())
		session.Revoke()

		err := session.Revoke()

		if err == nil {
			t.Fatal("Revoke() on revoked session should return error")
		}
		if err != domainerror.ErrSessionRevoked {
			t.Errorf("error = %v, want %v", err, domainerror.ErrSessionRevoked)
		}
	})
}

func TestSession_Refresh(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *model.Session
		newHash     string
		duration    time.Duration
		wantErr     error
		checkResult func(t *testing.T, s *model.Session, originalExpiry types.Timestamp)
	}{
		{
			name: "valid_session",
			setup: func() *model.Session {
				kp, _ := security.GenerateEd25519()
				did, _ := security.DIDFromKeyPair(kp)
				// Create session with SHORT duration so refresh extends it
				config := model.SessionConfig{SessionDuration: 1 * time.Minute}
				session, _ := model.NewSession(
					types.NewID(),
					did,
					types.None[types.ID](),
					"original_hash",
					config,
				)
				return session
			},
			newHash:  "new_refresh_hash",
			duration: 2 * time.Hour, // Longer than original 1 minute
			wantErr:  nil,
			checkResult: func(t *testing.T, s *model.Session, originalExpiry types.Timestamp) {
				if s.RefreshTokenHash() != "new_refresh_hash" {
					t.Errorf("RefreshTokenHash = %v, want new_refresh_hash", s.RefreshTokenHash())
				}
				if !s.ExpiresAt().After(originalExpiry) {
					t.Errorf("ExpiresAt should be extended")
				}
			},
		},
		{
			name: "empty_new_hash",
			setup: func() *model.Session {
				kp, _ := security.GenerateEd25519()
				did, _ := security.DIDFromKeyPair(kp)
				session, _ := model.NewSession(
					types.NewID(),
					did,
					types.None[types.ID](),
					"original_hash",
					model.DefaultSessionConfig(),
				)
				return session
			},
			newHash:  "",
			duration: 2 * time.Hour,
			wantErr:  domainerror.ErrRefreshTokenInvalid,
		},
		{
			name: "revoked_session",
			setup: func() *model.Session {
				kp, _ := security.GenerateEd25519()
				did, _ := security.DIDFromKeyPair(kp)
				session, _ := model.NewSession(
					types.NewID(),
					did,
					types.None[types.ID](),
					"original_hash",
					model.DefaultSessionConfig(),
				)
				session.Revoke()
				return session
			},
			newHash:  "new_hash",
			duration: 2 * time.Hour,
			wantErr:  domainerror.ErrSessionRevoked,
		},
		{
			name: "expired_session",
			setup: func() *model.Session {
				kp, _ := security.GenerateEd25519()
				did, _ := security.DIDFromKeyPair(kp)
				return model.ReconstructSession(
					types.NewID(),
					types.NewID(),
					did,
					types.None[types.ID](),
					"original_hash",
					types.FromTime(time.Now().Add(-1*time.Hour)), // Expired
					types.Now(),
					types.None[types.Timestamp](),
				)
			},
			newHash:  "new_hash",
			duration: 2 * time.Hour,
			wantErr:  domainerror.ErrSessionExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setup()
			originalExpiry := session.ExpiresAt()

			err := session.Refresh(tt.newHash, tt.duration)

			if err != tt.wantErr {
				t.Errorf("Refresh() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkResult != nil && err == nil {
				tt.checkResult(t, session, originalExpiry)
			}
		})
	}
}

func TestSession_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())

		if session.IsExpired() {
			t.Error("IsExpired() should return false for new session")
		}
	})

	t.Run("expired", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)

		session := model.ReconstructSession(
			types.NewID(),
			userID,
			userDID,
			types.None[types.ID](),
			"hash",
			types.FromTime(time.Now().Add(-time.Hour)),
			types.Now(),
			types.None[types.Timestamp](),
		)

		if !session.IsExpired() {
			t.Error("IsExpired() should return true for expired session")
		}
	})
}

func TestSession_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *model.Session
		want  bool
	}{
		{
			name: "valid session",
			setup: func() *model.Session {
				userID := types.NewID()
				userDID, _ := func() (*security.DID, error) {
					kp, _ := security.GenerateEd25519()
					return security.DIDFromKeyPair(kp)
				}()
				session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())
				return session
			},
			want: true,
		},
		{
			name: "revoked session",
			setup: func() *model.Session {
				userID := types.NewID()
				userDID, _ := func() (*security.DID, error) {
					kp, _ := security.GenerateEd25519()
					return security.DIDFromKeyPair(kp)
				}()
				session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())
				session.Revoke()
				return session
			},
			want: false,
		},
		{
			name: "expired session",
			setup: func() *model.Session {
				userID := types.NewID()
				userDID, _ := func() (*security.DID, error) {
					kp, _ := security.GenerateEd25519()
					return security.DIDFromKeyPair(kp)
				}()
				return model.ReconstructSession(
					types.NewID(),
					userID,
					userDID,
					types.None[types.ID](),
					"hash",
					types.FromTime(time.Now().Add(-time.Hour)),
					types.Now(),
					types.None[types.Timestamp](),
				)
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setup()
			if got := session.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_Validate(t *testing.T) {
	t.Run("valid session", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())

		err := session.Validate()

		if err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())
		session.Revoke()

		err := session.Validate()

		if err != domainerror.ErrSessionRevoked {
			t.Errorf("Validate() error = %v, want %v", err, domainerror.ErrSessionRevoked)
		}
	})

	t.Run("expired session", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)

		session := model.ReconstructSession(
			types.NewID(),
			userID,
			userDID,
			types.None[types.ID](),
			"hash",
			types.FromTime(time.Now().Add(-time.Hour)),
			types.Now(),
			types.None[types.Timestamp](),
		)

		err := session.Validate()

		if err != domainerror.ErrSessionExpired {
			t.Errorf("Validate() error = %v, want %v", err, domainerror.ErrSessionExpired)
		}
	})
}

func TestSession_ValidateRefreshToken(t *testing.T) {
	t.Run("valid hash", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "correcthash", model.DefaultSessionConfig())

		err := session.ValidateRefreshToken("correcthash")

		if err != nil {
			t.Errorf("ValidateRefreshToken() error = %v, want nil", err)
		}
	})

	t.Run("invalid hash", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "correcthash", model.DefaultSessionConfig())

		err := session.ValidateRefreshToken("wronghash")

		if err != domainerror.ErrRefreshTokenInvalid {
			t.Errorf("ValidateRefreshToken() error = %v, want %v", err, domainerror.ErrRefreshTokenInvalid)
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		userID := types.NewID()
		userDID := testDID(t)
		session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", model.DefaultSessionConfig())
		session.Revoke()

		err := session.ValidateRefreshToken("hash")

		if err != domainerror.ErrSessionRevoked {
			t.Errorf("ValidateRefreshToken() error = %v, want %v", err, domainerror.ErrSessionRevoked)
		}
	})
}

func TestSession_TimeUntilExpiry(t *testing.T) {
	userID := types.NewID()
	userDID := testDID(t)
	config := model.SessionConfig{SessionDuration: 1 * time.Hour}

	session, _ := model.NewSession(userID, userDID, types.None[types.ID](), "hash", config)

	ttl := session.TimeUntilExpiry()

	// Should be close to 1 hour (allowing some margin for test execution time)
	if ttl < 59*time.Minute || ttl > 1*time.Hour {
		t.Errorf("TimeUntilExpiry() = %v, want ~1 hour", ttl)
	}
}

func TestDefaultSessionConfig(t *testing.T) {
	config := model.DefaultSessionConfig()

	if config.SessionDuration != 7*24*time.Hour {
		t.Errorf("SessionDuration = %v, want 7 days", config.SessionDuration)
	}
}

func TestReconstructSession(t *testing.T) {
	id := types.NewID()
	userID := types.NewID()
	userDID := testDID(t)
	tenantID := types.Some(types.NewID())
	refreshTokenHash := "somehash"
	expiresAt := types.FromTime(time.Now().Add(time.Hour))
	createdAt := types.Now()
	revokedAt := types.Some(types.Now())

	session := model.ReconstructSession(
		id,
		userID,
		userDID,
		tenantID,
		refreshTokenHash,
		expiresAt,
		createdAt,
		revokedAt,
	)

	if session.ID() != id {
		t.Errorf("ID = %v, want %v", session.ID(), id)
	}
	if session.UserID() != userID {
		t.Errorf("UserID = %v, want %v", session.UserID(), userID)
	}
	if session.UserDID() != userDID {
		t.Errorf("UserDID = %v, want %v", session.UserDID(), userDID)
	}
	if !session.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if session.RefreshTokenHash() != refreshTokenHash {
		t.Errorf("RefreshTokenHash = %v, want %v", session.RefreshTokenHash(), refreshTokenHash)
	}
	if session.ExpiresAt() != expiresAt {
		t.Errorf("ExpiresAt = %v, want %v", session.ExpiresAt(), expiresAt)
	}
	if session.CreatedAt() != createdAt {
		t.Errorf("CreatedAt = %v, want %v", session.CreatedAt(), createdAt)
	}
	if !session.RevokedAt().IsPresent() {
		t.Error("RevokedAt should be present")
	}
}
