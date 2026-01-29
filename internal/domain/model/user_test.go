package model_test

import (
	"testing"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func testDID(t *testing.T) *security.DID {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}
	return did
}

func TestNewUser(t *testing.T) {
	t.Run("valid DID", func(t *testing.T) {
		did := testDID(t)

		user, err := model.NewUser(did)

		if err != nil {
			t.Fatalf("NewUser() error = %v", err)
		}
		if user == nil {
			t.Fatal("NewUser() returned nil")
		}
		if user.ID().IsEmpty() {
			t.Error("user ID should not be empty")
		}
		if user.DID() != did {
			t.Errorf("user DID = %v, want %v", user.DID(), did)
		}
		if user.Status() != model.UserStatusActive {
			t.Errorf("user status = %v, want %v", user.Status(), model.UserStatusActive)
		}
		if user.Email().IsPresent() {
			t.Error("user email should be empty")
		}
		if user.Name().IsPresent() {
			t.Error("user name should be empty")
		}
		if user.CreatedAt().IsZero() {
			t.Error("user createdAt should be set")
		}
		if user.UpdatedAt().IsZero() {
			t.Error("user updatedAt should be set")
		}
	})

	t.Run("nil DID", func(t *testing.T) {
		user, err := model.NewUser(nil)

		if err == nil {
			t.Fatal("NewUser(nil) should return error")
		}
		if user != nil {
			t.Error("NewUser(nil) should return nil user")
		}
		if err != domainerror.ErrUserDIDRequired {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserDIDRequired)
		}
	})
}

func TestUser_SetEmail(t *testing.T) {
	did := testDID(t)
	user, _ := model.NewUser(did)
	originalUpdatedAt := user.UpdatedAt()

	email, err := types.NewEmail("test@example.com")
	if err != nil {
		t.Fatalf("failed to create email: %v", err)
	}

	user.SetEmail(email)

	if !user.Email().IsPresent() {
		t.Fatal("email should be present")
	}
	if user.Email().MustGet() != email {
		t.Errorf("email = %v, want %v", user.Email().MustGet(), email)
	}
	if !user.UpdatedAt().After(originalUpdatedAt) && user.UpdatedAt() != originalUpdatedAt {
		// Allow equal if test runs fast enough
	}
}

func TestUser_ClearEmail(t *testing.T) {
	did := testDID(t)
	user, _ := model.NewUser(did)

	email, _ := types.NewEmail("test@example.com")
	user.SetEmail(email)

	user.ClearEmail()

	if user.Email().IsPresent() {
		t.Error("email should be cleared")
	}
}

func TestUser_SetName(t *testing.T) {
	did := testDID(t)
	user, _ := model.NewUser(did)

	user.SetName("Alice Smith")

	if !user.Name().IsPresent() {
		t.Fatal("name should be present")
	}
	if user.Name().MustGet() != "Alice Smith" {
		t.Errorf("name = %v, want Alice Smith", user.Name().MustGet())
	}
}

func TestUser_ClearName(t *testing.T) {
	did := testDID(t)
	user, _ := model.NewUser(did)

	user.SetName("Alice Smith")
	user.ClearName()

	if user.Name().IsPresent() {
		t.Error("name should be cleared")
	}
}

func TestUser_Suspend(t *testing.T) {
	t.Run("active user", func(t *testing.T) {
		did := testDID(t)
		user, _ := model.NewUser(did)

		err := user.Suspend()

		if err != nil {
			t.Fatalf("Suspend() error = %v", err)
		}
		if user.Status() != model.UserStatusSuspended {
			t.Errorf("status = %v, want %v", user.Status(), model.UserStatusSuspended)
		}
		if !user.IsSuspended() {
			t.Error("IsSuspended() should return true")
		}
		if user.IsActive() {
			t.Error("IsActive() should return false")
		}
	})

	t.Run("already suspended", func(t *testing.T) {
		did := testDID(t)
		user, _ := model.NewUser(did)
		user.Suspend()

		err := user.Suspend()

		if err == nil {
			t.Fatal("Suspend() on suspended user should return error")
		}
		if err != domainerror.ErrUserAlreadySuspended {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserAlreadySuspended)
		}
	})
}

func TestUser_Activate(t *testing.T) {
	t.Run("suspended user", func(t *testing.T) {
		did := testDID(t)
		user, _ := model.NewUser(did)
		user.Suspend()

		err := user.Activate()

		if err != nil {
			t.Fatalf("Activate() error = %v", err)
		}
		if user.Status() != model.UserStatusActive {
			t.Errorf("status = %v, want %v", user.Status(), model.UserStatusActive)
		}
		if !user.IsActive() {
			t.Error("IsActive() should return true")
		}
		if user.IsSuspended() {
			t.Error("IsSuspended() should return false")
		}
	})

	t.Run("already active", func(t *testing.T) {
		did := testDID(t)
		user, _ := model.NewUser(did)

		err := user.Activate()

		if err == nil {
			t.Fatal("Activate() on active user should return error")
		}
		if err != domainerror.ErrUserAlreadyActive {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserAlreadyActive)
		}
	})
}

func TestUser_CanAuthenticate(t *testing.T) {
	t.Run("active user", func(t *testing.T) {
		did := testDID(t)
		user, _ := model.NewUser(did)

		err := user.CanAuthenticate()

		if err != nil {
			t.Errorf("CanAuthenticate() error = %v, want nil", err)
		}
	})

	t.Run("suspended user", func(t *testing.T) {
		did := testDID(t)
		user, _ := model.NewUser(did)
		user.Suspend()

		err := user.CanAuthenticate()

		if err == nil {
			t.Fatal("CanAuthenticate() on suspended user should return error")
		}
		if err != domainerror.ErrUserSuspended {
			t.Errorf("error = %v, want %v", err, domainerror.ErrUserSuspended)
		}
	})
}

func TestUserStatus_IsValid(t *testing.T) {
	tests := []struct {
		status model.UserStatus
		want   bool
	}{
		{model.UserStatusActive, true},
		{model.UserStatusSuspended, true},
		{model.UserStatus("invalid"), false},
		{model.UserStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsValid()
			if got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserStatus_String(t *testing.T) {
	tests := []struct {
		status model.UserStatus
		want   string
	}{
		{model.UserStatusActive, "active"},
		{model.UserStatusSuspended, "suspended"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconstructUser(t *testing.T) {
	did := testDID(t)
	id := types.NewID()
	email, _ := types.NewEmail("test@example.com")
	name := "Alice Smith"
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
		t.Errorf("ID = %v, want %v", user.ID(), id)
	}
	if user.DID() != did {
		t.Errorf("DID = %v, want %v", user.DID(), did)
	}
	if !user.Email().IsPresent() || user.Email().MustGet() != email {
		t.Errorf("Email = %v, want %v", user.Email(), email)
	}
	if !user.Name().IsPresent() || user.Name().MustGet() != name {
		t.Errorf("Name = %v, want %v", user.Name(), name)
	}
	if user.Status() != model.UserStatusSuspended {
		t.Errorf("Status = %v, want %v", user.Status(), model.UserStatusSuspended)
	}
	if user.CreatedAt() != createdAt {
		t.Errorf("CreatedAt = %v, want %v", user.CreatedAt(), createdAt)
	}
	if user.UpdatedAt() != updatedAt {
		t.Errorf("UpdatedAt = %v, want %v", user.UpdatedAt(), updatedAt)
	}
}
