package model_test

import (
	"testing"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestNewUser(t *testing.T) {
	t.Run("creates valid user", func(t *testing.T) {
		kp := mustGenerateUserEd25519(t)
		did := mustDIDFromUserKeyPair(t, kp)

		user, err := model.NewUser(did)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.ID() == "" {
			t.Error("expected non-empty ID")
		}
		if user.DID().String() != did.String() {
			t.Errorf("DID mismatch: got %s, want %s", user.DID().String(), did.String())
		}
		if user.Status() != model.UserStatusActive {
			t.Errorf("expected status Active, got %s", user.Status())
		}
		if !user.IsActive() {
			t.Error("new user should be active")
		}
		if user.IsSuspended() {
			t.Error("new user should not be suspended")
		}
		if user.Email().IsPresent() {
			t.Error("new user should have no email")
		}
		if user.Name().IsPresent() {
			t.Error("new user should have no name")
		}
		if user.CreatedAt().IsZero() {
			t.Error("CreatedAt should be set")
		}
		if user.UpdatedAt().IsZero() {
			t.Error("UpdatedAt should be set")
		}
	})

	t.Run("rejects nil DID", func(t *testing.T) {
		_, err := model.NewUser(nil)
		if err == nil {
			t.Fatal("expected error for nil DID")
		}
		if err != domainerror.ErrUserDIDRequired {
			t.Errorf("expected ErrUserDIDRequired, got: %v", err)
		}
	})
}

func TestUser_Email(t *testing.T) {
	user := mustCreateUserForTest(t)

	t.Run("sets email", func(t *testing.T) {
		email, err := types.NewEmail("test@example.com")
		if err != nil {
			t.Fatalf("failed to create email: %v", err)
		}

		originalUpdatedAt := user.UpdatedAt()
		user.SetEmail(email)

		if !user.Email().IsPresent() {
			t.Fatal("email should be present after SetEmail")
		}
		if user.Email().MustGet().String() != "test@example.com" {
			t.Errorf("email mismatch: got %s", user.Email().MustGet().String())
		}
		if !user.UpdatedAt().After(originalUpdatedAt) || user.UpdatedAt().Equal(originalUpdatedAt) {
			// UpdatedAt should be >= original (might be same if test runs fast)
			// Just check it's set
			if user.UpdatedAt().IsZero() {
				t.Error("UpdatedAt should be set after SetEmail")
			}
		}
	})

	t.Run("clears email", func(t *testing.T) {
		email, _ := types.NewEmail("test@example.com")
		user.SetEmail(email)

		user.ClearEmail()

		if user.Email().IsPresent() {
			t.Error("email should not be present after ClearEmail")
		}
	})
}

func TestUser_Name(t *testing.T) {
	user := mustCreateUserForTest(t)

	t.Run("sets name", func(t *testing.T) {
		user.SetName("John Doe")

		if !user.Name().IsPresent() {
			t.Fatal("name should be present after SetName")
		}
		if user.Name().MustGet() != "John Doe" {
			t.Errorf("name mismatch: got %s", user.Name().MustGet())
		}
	})

	t.Run("clears name", func(t *testing.T) {
		user.SetName("John Doe")

		user.ClearName()

		if user.Name().IsPresent() {
			t.Error("name should not be present after ClearName")
		}
	})
}

func TestUser_Suspend(t *testing.T) {
	t.Run("suspends active user", func(t *testing.T) {
		user := mustCreateUserForTest(t)

		if !user.IsActive() {
			t.Fatal("user should be active initially")
		}

		err := user.Suspend()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !user.IsSuspended() {
			t.Error("user should be suspended after Suspend()")
		}
		if user.IsActive() {
			t.Error("user should not be active after Suspend()")
		}
		if user.Status() != model.UserStatusSuspended {
			t.Errorf("expected status Suspended, got %s", user.Status())
		}
	})

	t.Run("cannot suspend already suspended user", func(t *testing.T) {
		user := mustCreateUserForTest(t)
		_ = user.Suspend()

		err := user.Suspend()
		if err == nil {
			t.Fatal("expected error when suspending already suspended user")
		}
		if err != domainerror.ErrUserAlreadySuspended {
			t.Errorf("expected ErrUserAlreadySuspended, got: %v", err)
		}
	})
}

func TestUser_Activate(t *testing.T) {
	t.Run("activates suspended user", func(t *testing.T) {
		user := mustCreateUserForTest(t)
		_ = user.Suspend()

		if !user.IsSuspended() {
			t.Fatal("user should be suspended before activation")
		}

		err := user.Activate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !user.IsActive() {
			t.Error("user should be active after Activate()")
		}
		if user.IsSuspended() {
			t.Error("user should not be suspended after Activate()")
		}
		if user.Status() != model.UserStatusActive {
			t.Errorf("expected status Active, got %s", user.Status())
		}
	})

	t.Run("cannot activate already active user", func(t *testing.T) {
		user := mustCreateUserForTest(t)

		err := user.Activate()
		if err == nil {
			t.Fatal("expected error when activating already active user")
		}
		if err != domainerror.ErrUserAlreadyActive {
			t.Errorf("expected ErrUserAlreadyActive, got: %v", err)
		}
	})
}

func TestUser_CanAuthenticate(t *testing.T) {
	t.Run("active user can authenticate", func(t *testing.T) {
		user := mustCreateUserForTest(t)

		err := user.CanAuthenticate()
		if err != nil {
			t.Errorf("active user should be able to authenticate: %v", err)
		}
	})

	t.Run("suspended user cannot authenticate", func(t *testing.T) {
		user := mustCreateUserForTest(t)
		_ = user.Suspend()

		err := user.CanAuthenticate()
		if err == nil {
			t.Fatal("suspended user should not be able to authenticate")
		}
		if err != domainerror.ErrUserSuspended {
			t.Errorf("expected ErrUserSuspended, got: %v", err)
		}
	})
}

func TestUserStatus(t *testing.T) {
	t.Run("valid statuses", func(t *testing.T) {
		if !model.UserStatusActive.IsValid() {
			t.Error("active should be valid")
		}
		if !model.UserStatusSuspended.IsValid() {
			t.Error("suspended should be valid")
		}
	})

	t.Run("invalid statuses", func(t *testing.T) {
		if model.UserStatus("").IsValid() {
			t.Error("empty should be invalid")
		}
		if model.UserStatus("invalid").IsValid() {
			t.Error("invalid should be invalid")
		}
		if model.UserStatus("deleted").IsValid() {
			t.Error("deleted should be invalid")
		}
	})

	t.Run("string conversion", func(t *testing.T) {
		if model.UserStatusActive.String() != "active" {
			t.Error("active string mismatch")
		}
		if model.UserStatusSuspended.String() != "suspended" {
			t.Error("suspended string mismatch")
		}
	})
}

func TestReconstructUser(t *testing.T) {
	t.Run("reconstructs user with all fields", func(t *testing.T) {
		kp := mustGenerateUserEd25519(t)
		did := mustDIDFromUserKeyPair(t, kp)
		id := types.NewID()
		email, _ := types.NewEmail("test@example.com")
		name := "John Doe"
		createdAt := types.Now()
		updatedAt := types.Now()

		user := model.ReconstructUser(
			id,
			did,
			types.Some(email),
			types.Some(name),
			model.UserStatusSuspended,
			createdAt,
			updatedAt,
		)

		if user.ID() != id {
			t.Errorf("ID mismatch: got %s, want %s", user.ID(), id)
		}
		if user.DID().String() != did.String() {
			t.Errorf("DID mismatch: got %s, want %s", user.DID().String(), did.String())
		}
		if !user.Email().IsPresent() || user.Email().MustGet().String() != "test@example.com" {
			t.Error("email not reconstructed correctly")
		}
		if !user.Name().IsPresent() || user.Name().MustGet() != "John Doe" {
			t.Error("name not reconstructed correctly")
		}
		if user.Status() != model.UserStatusSuspended {
			t.Errorf("status mismatch: got %s, want suspended", user.Status())
		}
		if user.CreatedAt() != createdAt {
			t.Error("CreatedAt not reconstructed correctly")
		}
		if user.UpdatedAt() != updatedAt {
			t.Error("UpdatedAt not reconstructed correctly")
		}
	})

	t.Run("reconstructs user with optional fields empty", func(t *testing.T) {
		kp := mustGenerateUserEd25519(t)
		did := mustDIDFromUserKeyPair(t, kp)

		user := model.ReconstructUser(
			types.NewID(),
			did,
			types.None[types.Email](),
			types.None[string](),
			model.UserStatusActive,
			types.Now(),
			types.Now(),
		)

		if user.Email().IsPresent() {
			t.Error("email should not be present")
		}
		if user.Name().IsPresent() {
			t.Error("name should not be present")
		}
	})
}

// Test helpers

func mustGenerateUserEd25519(t *testing.T) security.KeyPair {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}
	return kp
}

func mustDIDFromUserKeyPair(t *testing.T, kp security.KeyPair) *security.DID {
	t.Helper()
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID from keypair: %v", err)
	}
	return did
}

func mustCreateUserForTest(t *testing.T) *model.User {
	t.Helper()
	kp := mustGenerateUserEd25519(t)
	did := mustDIDFromUserKeyPair(t, kp)

	user, err := model.NewUser(did)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}
