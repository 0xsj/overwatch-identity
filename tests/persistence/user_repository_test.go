package persistence

import (
	"testing"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

func TestUserRepository_Create(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)

	err := repo.Create(ctx, user)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify by reading back
	found, err := repo.FindByID(ctx, user.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != user.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), user.ID())
	}
	if found.DID().String() != user.DID().String() {
		t.Errorf("DID = %v, want %v", found.DID().String(), user.DID().String())
	}
}

func TestUserRepository_Create_DuplicateDID(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	did := testDID(t)
	user1, _ := model.NewUser(did)
	user2, _ := model.NewUser(did) // Same DID

	repo.Create(ctx, user1)
	err := repo.Create(ctx, user2)

	if err == nil {
		t.Error("Create() should return error for duplicate DID")
	}
}

func TestUserRepository_Update(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	repo.Create(ctx, user)

	// Update user
	email, _ := types.NewEmail("updated@example.com")
	user.SetEmail(email)
	user.SetName("Updated Name")

	err := repo.Update(ctx, user)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	found, _ := repo.FindByID(ctx, user.ID())
	if !found.Email().IsPresent() || found.Email().MustGet().String() != "updated@example.com" {
		t.Errorf("Email = %v, want updated@example.com", found.Email())
	}
	if !found.Name().IsPresent() || found.Name().MustGet() != "Updated Name" {
		t.Errorf("Name = %v, want Updated Name", found.Name())
	}
}

func TestUserRepository_Update_Status(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	repo.Create(ctx, user)

	user.Suspend()
	err := repo.Update(ctx, user)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	found, _ := repo.FindByID(ctx, user.ID())
	if found.Status() != model.UserStatusSuspended {
		t.Errorf("Status = %v, want %v", found.Status(), model.UserStatusSuspended)
	}
}

func TestUserRepository_FindByID(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	repo.Create(ctx, user)

	found, err := repo.FindByID(ctx, user.ID())

	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != user.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), user.ID())
	}
}

func TestUserRepository_FindByID_NotFound(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	_, err := repo.FindByID(ctx, types.NewID())

	if err != repository.ErrNotFound {
		t.Errorf("FindByID() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestUserRepository_FindByDID(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	repo.Create(ctx, user)

	found, err := repo.FindByDID(ctx, user.DID().String())

	if err != nil {
		t.Fatalf("FindByDID() error = %v", err)
	}
	if found.ID() != user.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), user.ID())
	}
}

func TestUserRepository_FindByDID_NotFound(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	_, err := repo.FindByDID(ctx, "did:key:nonexistent")

	if err != repository.ErrNotFound {
		t.Errorf("FindByDID() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestUserRepository_FindByEmail(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	email, _ := types.NewEmail("findme@example.com")
	user.SetEmail(email)
	repo.Create(ctx, user)

	found, err := repo.FindByEmail(ctx, email)

	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if found.ID() != user.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), user.ID())
	}
}

func TestUserRepository_FindByEmail_NotFound(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	email, _ := types.NewEmail("nonexistent@example.com")
	_, err := repo.FindByEmail(ctx, email)

	if err != repository.ErrNotFound {
		t.Errorf("FindByEmail() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestUserRepository_ExistsByDID(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	repo.Create(ctx, user)

	t.Run("exists", func(t *testing.T) {
		exists, err := repo.ExistsByDID(ctx, user.DID().String())

		if err != nil {
			t.Fatalf("ExistsByDID() error = %v", err)
		}
		if !exists {
			t.Error("ExistsByDID() = false, want true")
		}
	})

	t.Run("not exists", func(t *testing.T) {
		exists, err := repo.ExistsByDID(ctx, "did:key:nonexistent")

		if err != nil {
			t.Fatalf("ExistsByDID() error = %v", err)
		}
		if exists {
			t.Error("ExistsByDID() = true, want false")
		}
	})
}

func TestUserRepository_ExistsByEmail(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	email, _ := types.NewEmail("exists@example.com")
	user.SetEmail(email)
	repo.Create(ctx, user)

	t.Run("exists", func(t *testing.T) {
		exists, err := repo.ExistsByEmail(ctx, email)

		if err != nil {
			t.Fatalf("ExistsByEmail() error = %v", err)
		}
		if !exists {
			t.Error("ExistsByEmail() = false, want true")
		}
	})

	t.Run("not exists", func(t *testing.T) {
		nonExistent, _ := types.NewEmail("notexists@example.com")
		exists, err := repo.ExistsByEmail(ctx, nonExistent)

		if err != nil {
			t.Fatalf("ExistsByEmail() error = %v", err)
		}
		if exists {
			t.Error("ExistsByEmail() = true, want false")
		}
	})
}

func TestUserRepository_List(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	// Create multiple users
	for i := 0; i < 5; i++ {
		user := createTestUser(t)
		repo.Create(ctx, user)
	}

	params := repository.DefaultListUsersParams()
	params.Limit = 10

	users, err := repo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(users) != 5 {
		t.Errorf("List() returned %d users, want 5", len(users))
	}
}

func TestUserRepository_List_WithPagination(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	// Create 5 users
	for i := 0; i < 5; i++ {
		user := createTestUser(t)
		repo.Create(ctx, user)
	}

	params := repository.DefaultListUsersParams()
	params.Limit = 2
	params.Offset = 0

	page1, _ := repo.List(ctx, params)
	if len(page1) != 2 {
		t.Errorf("Page 1 returned %d users, want 2", len(page1))
	}

	params.Offset = 2
	page2, _ := repo.List(ctx, params)
	if len(page2) != 2 {
		t.Errorf("Page 2 returned %d users, want 2", len(page2))
	}

	params.Offset = 4
	page3, _ := repo.List(ctx, params)
	if len(page3) != 1 {
		t.Errorf("Page 3 returned %d users, want 1", len(page3))
	}
}

func TestUserRepository_List_WithStatusFilter(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	// Create 3 active users
	for i := 0; i < 3; i++ {
		user := createTestUser(t)
		repo.Create(ctx, user)
	}

	// Create 2 suspended users
	for i := 0; i < 2; i++ {
		user := createTestUser(t)
		user.Suspend()
		repo.Create(ctx, user)
	}

	activeStatus := model.UserStatusActive
	params := repository.DefaultListUsersParams()
	params.Status = &activeStatus

	users, err := repo.List(ctx, params)

	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(users) != 3 {
		t.Errorf("List() returned %d active users, want 3", len(users))
	}
}

func TestUserRepository_Count(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	// Create 5 users
	for i := 0; i < 5; i++ {
		user := createTestUser(t)
		repo.Create(ctx, user)
	}

	params := repository.DefaultListUsersParams()
	count, err := repo.Count(ctx, params)

	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 5 {
		t.Errorf("Count() = %d, want 5", count)
	}
}

func TestUserRepository_Count_WithStatusFilter(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	// Create 3 active, 2 suspended
	for i := 0; i < 3; i++ {
		user := createTestUser(t)
		repo.Create(ctx, user)
	}
	for i := 0; i < 2; i++ {
		user := createTestUser(t)
		user.Suspend()
		repo.Create(ctx, user)
	}

	suspendedStatus := model.UserStatusSuspended
	params := repository.DefaultListUsersParams()
	params.Status = &suspendedStatus

	count, err := repo.Count(ctx, params)

	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 2 {
		t.Errorf("Count() = %d, want 2", count)
	}
}

func TestUserRepository_Delete(t *testing.T) {
	truncateTables(t)
	repo := postgres.NewUserRepository(getPool())
	ctx := getContext()

	user := createTestUser(t)
	repo.Create(ctx, user)

	err := repo.Delete(ctx, user.ID())

	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted
	_, err = repo.FindByID(ctx, user.ID())
	if err != repository.ErrNotFound {
		t.Errorf("FindByID() after delete error = %v, want %v", err, repository.ErrNotFound)
	}
}

// --- Helpers ---

func createTestUser(t *testing.T) *model.User {
	t.Helper()
	did := testDID(t)
	user, err := model.NewUser(did)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

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
