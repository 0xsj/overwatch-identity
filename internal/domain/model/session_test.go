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
	user := mustCreateTestUser(t)
	config := model.DefaultSessionConfig()

	t.Run("creates valid session", func(t *testing.T) {
		session, err := model.NewSession(
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			"refresh-token-hash",
			config,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if session.ID() == "" {
			t.Error("expected non-empty ID")
		}
		if session.UserID() != user.ID() {
			t.Errorf("UserID mismatch: got %s, want %s", session.UserID(), user.ID())
		}
		if session.UserDID().String() != user.DID().String() {
			t.Errorf("UserDID mismatch: got %s, want %s", session.UserDID().String(), user.DID().String())
		}
		if session.RefreshTokenHash() != "refresh-token-hash" {
			t.Errorf("RefreshTokenHash mismatch: got %s", session.RefreshTokenHash())
		}
		if session.TenantID().IsPresent() {
			t.Error("expected no tenant ID")
		}
		if session.IsExpired() {
			t.Error("new session should not be expired")
		}
		if session.IsRevoked() {
			t.Error("new session should not be revoked")
		}
		if !session.IsValid() {
			t.Error("new session should be valid")
		}
	})

	t.Run("creates session with tenant", func(t *testing.T) {
		tenantID := types.NewID()
		session, err := model.NewSession(
			user.ID(),
			user.DID(),
			types.Some(tenantID),
			"refresh-token-hash",
			config,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !session.TenantID().IsPresent() {
			t.Fatal("expected tenant ID to be present")
		}
		if session.TenantID().MustGet() != tenantID {
			t.Errorf("TenantID mismatch: got %s, want %s", session.TenantID().MustGet(), tenantID)
		}
		if !session.HasTenant() {
			t.Error("HasTenant should return true")
		}
	})

	t.Run("rejects empty user ID", func(t *testing.T) {
		_, err := model.NewSession(
			"", // empty
			user.DID(),
			types.None[types.ID](),
			"refresh-token-hash",
			config,
		)
		if err == nil {
			t.Fatal("expected error for empty user ID")
		}
		if err != domainerror.ErrUserIDRequired {
			t.Errorf("expected ErrUserIDRequired, got: %v", err)
		}
	})

	t.Run("rejects nil DID", func(t *testing.T) {
		_, err := model.NewSession(
			user.ID(),
			nil,
			types.None[types.ID](),
			"refresh-token-hash",
			config,
		)
		if err == nil {
			t.Fatal("expected error for nil DID")
		}
		if err != domainerror.ErrUserDIDRequired {
			t.Errorf("expected ErrUserDIDRequired, got: %v", err)
		}
	})

	t.Run("rejects empty refresh token hash", func(t *testing.T) {
		_, err := model.NewSession(
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			"", // empty
			config,
		)
		if err == nil {
			t.Fatal("expected error for empty refresh token hash")
		}
		if err != domainerror.ErrRefreshTokenInvalid {
			t.Errorf("expected ErrRefreshTokenInvalid, got: %v", err)
		}
	})
}

func TestSession_Validation(t *testing.T) {
	user := mustCreateTestUser(t)

	t.Run("valid session passes validation", func(t *testing.T) {
		session := mustCreateTestSession(t, user)

		if err := session.Validate(); err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("expired session fails validation", func(t *testing.T) {
		session := model.ReconstructSession(
			types.NewID(),
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			"refresh-token-hash",
			types.FromTime(time.Now().Add(-1*time.Hour)), // expired
			types.FromTime(time.Now().Add(-2*time.Hour)), // created
			types.None[types.Timestamp](),                // not revoked
		)

		if !session.IsExpired() {
			t.Error("session should be expired")
		}
		if session.IsValid() {
			t.Error("expired session should not be valid")
		}

		err := session.Validate()
		if err == nil {
			t.Fatal("expected validation error for expired session")
		}
		if err != domainerror.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got: %v", err)
		}
	})

	t.Run("revoked session fails validation", func(t *testing.T) {
		session := model.ReconstructSession(
			types.NewID(),
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			"refresh-token-hash",
			types.FromTime(time.Now().Add(1*time.Hour)), // not expired
			types.FromTime(time.Now().Add(-1*time.Hour)),
			types.Some(types.Now()), // revoked
		)

		if !session.IsRevoked() {
			t.Error("session should be revoked")
		}
		if session.IsValid() {
			t.Error("revoked session should not be valid")
		}

		err := session.Validate()
		if err == nil {
			t.Fatal("expected validation error for revoked session")
		}
		if err != domainerror.ErrSessionRevoked {
			t.Errorf("expected ErrSessionRevoked, got: %v", err)
		}
	})
}

func TestSession_ValidateRefreshToken(t *testing.T) {
	user := mustCreateTestUser(t)
	correctHash := "correct-refresh-token-hash"

	t.Run("correct hash passes validation", func(t *testing.T) {
		session, _ := model.NewSession(
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			correctHash,
			model.DefaultSessionConfig(),
		)

		if err := session.ValidateRefreshToken(correctHash); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("incorrect hash fails validation", func(t *testing.T) {
		session, _ := model.NewSession(
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			correctHash,
			model.DefaultSessionConfig(),
		)

		err := session.ValidateRefreshToken("wrong-hash")
		if err == nil {
			t.Fatal("expected error for incorrect hash")
		}
		if err != domainerror.ErrRefreshTokenInvalid {
			t.Errorf("expected ErrRefreshTokenInvalid, got: %v", err)
		}
	})

	t.Run("expired session fails before hash check", func(t *testing.T) {
		session := model.ReconstructSession(
			types.NewID(),
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			correctHash,
			types.FromTime(time.Now().Add(-1*time.Hour)), // expired
			types.FromTime(time.Now().Add(-2*time.Hour)),
			types.None[types.Timestamp](),
		)

		err := session.ValidateRefreshToken(correctHash)
		if err == nil {
			t.Fatal("expected error for expired session")
		}
		if err != domainerror.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got: %v", err)
		}
	})

	t.Run("revoked session fails before hash check", func(t *testing.T) {
		session := model.ReconstructSession(
			types.NewID(),
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			correctHash,
			types.FromTime(time.Now().Add(1*time.Hour)), // not expired
			types.FromTime(time.Now().Add(-1*time.Hour)),
			types.Some(types.Now()), // revoked
		)

		err := session.ValidateRefreshToken(correctHash)
		if err == nil {
			t.Fatal("expected error for revoked session")
		}
		if err != domainerror.ErrSessionRevoked {
			t.Errorf("expected ErrSessionRevoked, got: %v", err)
		}
	})
}

func TestSession_Revoke(t *testing.T) {
	user := mustCreateTestUser(t)

	t.Run("revokes active session", func(t *testing.T) {
		session := mustCreateTestSession(t, user)

		if session.IsRevoked() {
			t.Fatal("session should not be revoked initially")
		}

		err := session.Revoke()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !session.IsRevoked() {
			t.Error("session should be revoked after Revoke()")
		}
		if !session.RevokedAt().IsPresent() {
			t.Error("RevokedAt should be present after revocation")
		}
		if session.IsValid() {
			t.Error("revoked session should not be valid")
		}
	})

	t.Run("cannot revoke already revoked session", func(t *testing.T) {
		session := mustCreateTestSession(t, user)
		_ = session.Revoke()

		err := session.Revoke()
		if err == nil {
			t.Fatal("expected error when revoking already revoked session")
		}
		if err != domainerror.ErrSessionRevoked {
			t.Errorf("expected ErrSessionRevoked, got: %v", err)
		}
	})
}

func TestSession_Refresh(t *testing.T) {
	user := mustCreateTestUser(t)
	duration := 7 * 24 * time.Hour

	t.Run("refreshes valid session", func(t *testing.T) {
		session := mustCreateTestSession(t, user)
		originalHash := session.RefreshTokenHash()
		originalExpiry := session.ExpiresAt()

		// Wait a tiny bit to ensure time difference
		time.Sleep(1 * time.Millisecond)

		newHash := "new-refresh-token-hash"
		err := session.Refresh(newHash, duration)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if session.RefreshTokenHash() != newHash {
			t.Errorf("hash not updated: got %s, want %s", session.RefreshTokenHash(), newHash)
		}
		if session.RefreshTokenHash() == originalHash {
			t.Error("hash should have changed")
		}
		if !session.ExpiresAt().After(originalExpiry) {
			t.Error("expiry should be extended")
		}
	})

	t.Run("cannot refresh expired session", func(t *testing.T) {
		session := model.ReconstructSession(
			types.NewID(),
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			"old-hash",
			types.FromTime(time.Now().Add(-1*time.Hour)), // expired
			types.FromTime(time.Now().Add(-2*time.Hour)),
			types.None[types.Timestamp](),
		)

		err := session.Refresh("new-hash", duration)
		if err == nil {
			t.Fatal("expected error when refreshing expired session")
		}
		if err != domainerror.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got: %v", err)
		}
	})

	t.Run("cannot refresh revoked session", func(t *testing.T) {
		session := mustCreateTestSession(t, user)
		_ = session.Revoke()

		err := session.Refresh("new-hash", duration)
		if err == nil {
			t.Fatal("expected error when refreshing revoked session")
		}
		if err != domainerror.ErrSessionRevoked {
			t.Errorf("expected ErrSessionRevoked, got: %v", err)
		}
	})

	t.Run("cannot refresh with empty hash", func(t *testing.T) {
		session := mustCreateTestSession(t, user)

		err := session.Refresh("", duration)
		if err == nil {
			t.Fatal("expected error for empty hash")
		}
		if err != domainerror.ErrRefreshTokenInvalid {
			t.Errorf("expected ErrRefreshTokenInvalid, got: %v", err)
		}
	})
}

func TestSession_TimeUntilExpiry(t *testing.T) {
	user := mustCreateTestUser(t)

	t.Run("returns positive duration for active session", func(t *testing.T) {
		session := mustCreateTestSession(t, user)
		remaining := session.TimeUntilExpiry()

		if remaining <= 0 {
			t.Errorf("expected positive duration, got: %v", remaining)
		}
	})

	t.Run("returns negative duration for expired session", func(t *testing.T) {
		session := model.ReconstructSession(
			types.NewID(),
			user.ID(),
			user.DID(),
			types.None[types.ID](),
			"hash",
			types.FromTime(time.Now().Add(-1*time.Hour)), // expired
			types.FromTime(time.Now().Add(-2*time.Hour)),
			types.None[types.Timestamp](),
		)

		remaining := session.TimeUntilExpiry()
		if remaining >= 0 {
			t.Errorf("expected negative duration for expired session, got: %v", remaining)
		}
	})
}

func TestSessionConfig(t *testing.T) {
	t.Run("default config has sensible values", func(t *testing.T) {
		config := model.DefaultSessionConfig()

		if config.SessionDuration <= 0 {
			t.Error("session duration should be positive")
		}
		if config.SessionDuration < 24*time.Hour {
			t.Error("session duration should be at least 1 day")
		}
	})
}

// Test helpers

func mustGenerateTestEd25519(t *testing.T) security.KeyPair {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}
	return kp
}

func mustDIDFromTestKeyPair(t *testing.T, kp security.KeyPair) *security.DID {
	t.Helper()
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID from keypair: %v", err)
	}
	return did
}

func mustCreateTestUser(t *testing.T) *model.User {
	t.Helper()
	kp := mustGenerateTestEd25519(t)
	did := mustDIDFromTestKeyPair(t, kp)

	user, err := model.NewUser(did)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func mustCreateTestSession(t *testing.T, user *model.User) *model.Session {
	t.Helper()
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		types.None[types.ID](),
		"test-refresh-token-hash",
		model.DefaultSessionConfig(),
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	return session
}
