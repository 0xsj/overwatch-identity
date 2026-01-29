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
	"github.com/0xsj/overwatch-identity/tests/testutil/mocks"
)

func TestUpdateUserFlow_UpdateEmail(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.user")
	defer cleanup()

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Update email
	newEmail, _ := types.NewEmail("newemail@example.com")
	result, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.Some(newEmail),
		Name:   types.None[string](),
	})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	// Verify result
	if result.User == nil {
		t.Fatal("User should not be nil")
	}
	if !result.User.Email().IsPresent() {
		t.Fatal("Email should be present")
	}
	if result.User.Email().MustGet().String() != "newemail@example.com" {
		t.Errorf("Email = %v, want newemail@example.com", result.User.Email().MustGet().String())
	}
	if len(result.UpdatedFields) != 1 || result.UpdatedFields[0] != "email" {
		t.Errorf("UpdatedFields = %v, want [email]", result.UpdatedFields)
	}

	// Verify persisted
	persistedUser, _ := userRepo.FindByID(ctx, user.ID())
	if !persistedUser.Email().IsPresent() || persistedUser.Email().MustGet().String() != "newemail@example.com" {
		t.Errorf("Persisted email = %v, want newemail@example.com", persistedUser.Email())
	}

	// Verify cache invalidated
	if userCache.Calls.Delete == 0 {
		t.Error("Cache Delete should have been called")
	}
	if userCache.Calls.DeleteByDID == 0 {
		t.Error("Cache DeleteByDID should have been called")
	}

	// Verify event published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	eventTypes := extractEventTypes(t, messages)
	if !eventTypes[event.EventTypeUserUpdated] {
		t.Error("Missing user.updated event")
	}
}

func TestUpdateUserFlow_UpdateName(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Update name
	result, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.None[types.Email](),
		Name:   types.Some("Alice Smith"),
	})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	if !result.User.Name().IsPresent() {
		t.Fatal("Name should be present")
	}
	if result.User.Name().MustGet() != "Alice Smith" {
		t.Errorf("Name = %v, want Alice Smith", result.User.Name().MustGet())
	}
	if len(result.UpdatedFields) != 1 || result.UpdatedFields[0] != "name" {
		t.Errorf("UpdatedFields = %v, want [name]", result.UpdatedFields)
	}
}

func TestUpdateUserFlow_UpdateBoth(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Update both email and name
	newEmail, _ := types.NewEmail("both@example.com")
	result, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.Some(newEmail),
		Name:   types.Some("Bob Jones"),
	})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	if result.User.Email().MustGet().String() != "both@example.com" {
		t.Errorf("Email = %v, want both@example.com", result.User.Email().MustGet().String())
	}
	if result.User.Name().MustGet() != "Bob Jones" {
		t.Errorf("Name = %v, want Bob Jones", result.User.Name().MustGet())
	}
	if len(result.UpdatedFields) != 2 {
		t.Errorf("UpdatedFields count = %d, want 2", len(result.UpdatedFields))
	}
}

func TestUpdateUserFlow_NoChanges(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Subscribe to events
	msgChan, cleanup := subscribeAndCollect(t, "overwatch.identity.user")
	defer cleanup()

	// Create user with existing values
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	existingEmail, _ := types.NewEmail("existing@example.com")
	user.SetEmail(existingEmail)
	user.SetName("Existing Name")
	userRepo.Create(ctx, user)

	// Try to update with same values
	result, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.Some(existingEmail),
		Name:   types.Some("Existing Name"),
	})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	// No fields should be updated
	if len(result.UpdatedFields) != 0 {
		t.Errorf("UpdatedFields = %v, want []", result.UpdatedFields)
	}

	// No event should be published
	time.Sleep(100 * time.Millisecond)
	messages := drainMessages(msgChan)
	if len(messages) != 0 {
		t.Error("No event should be published when nothing changed")
	}

	// Cache should not be invalidated
	if userCache.Calls.Delete != 0 {
		t.Error("Cache Delete should not have been called when nothing changed")
	}
}

func TestUpdateUserFlow_UpdateExistingEmail(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Create user with existing email
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	oldEmail, _ := types.NewEmail("old@example.com")
	user.SetEmail(oldEmail)
	userRepo.Create(ctx, user)

	// Update to new email
	newEmail, _ := types.NewEmail("new@example.com")
	result, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.Some(newEmail),
		Name:   types.None[string](),
	})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	if result.User.Email().MustGet().String() != "new@example.com" {
		t.Errorf("Email = %v, want new@example.com", result.User.Email().MustGet().String())
	}
	if len(result.UpdatedFields) != 1 || result.UpdatedFields[0] != "email" {
		t.Errorf("UpdatedFields = %v, want [email]", result.UpdatedFields)
	}
}

func TestUpdateUserFlow_UserNotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	newEmail, _ := types.NewEmail("test@example.com")
	_, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: types.NewID(),
		Email:  types.Some(newEmail),
		Name:   types.None[string](),
	})

	if err != domainerror.ErrUserNotFound {
		t.Errorf("UpdateUser() error = %v, want %v", err, domainerror.ErrUserNotFound)
	}
}

func TestUpdateUserFlow_EmptyUserID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	var emptyUserID types.ID
	newEmail, _ := types.NewEmail("test@example.com")
	_, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: emptyUserID,
		Email:  types.Some(newEmail),
		Name:   types.None[string](),
	})

	if err != domainerror.ErrUserIDRequired {
		t.Errorf("UpdateUser() error = %v, want %v", err, domainerror.ErrUserIDRequired)
	}
}

func TestUpdateUserFlow_NothingProvided(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// Update with nothing
	result, err := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.None[types.Email](),
		Name:   types.None[string](),
	})

	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	// Should return user with no changes
	if result.User == nil {
		t.Fatal("User should not be nil")
	}
	if len(result.UpdatedFields) != 0 {
		t.Errorf("UpdatedFields = %v, want []", result.UpdatedFields)
	}
}

func TestUpdateUserFlow_MultipleUpdates(t *testing.T) {
	truncateTables(t)
	ctx := getContext()

	// Setup
	userRepo := postgres.NewUserRepository(getPool())
	userCache := mocks.NewUserCache()
	publisher := natsadapter.NewEventPublisher(getConn(), "overwatch")

	updateUserHandler := appcommand.NewUpdateUserHandler(userRepo, userCache, publisher)

	// Create user
	kp, _ := security.GenerateEd25519()
	did, _ := security.DIDFromKeyPair(kp)
	user, _ := model.NewUser(did)
	userRepo.Create(ctx, user)

	// First update
	email1, _ := types.NewEmail("first@example.com")
	result1, _ := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.Some(email1),
		Name:   types.Some("First Name"),
	})

	if result1.User.Email().MustGet().String() != "first@example.com" {
		t.Errorf("First update email = %v, want first@example.com", result1.User.Email().MustGet().String())
	}

	// Second update
	email2, _ := types.NewEmail("second@example.com")
	result2, _ := updateUserHandler.Handle(ctx, command.UpdateUser{
		UserID: user.ID(),
		Email:  types.Some(email2),
		Name:   types.Some("Second Name"),
	})

	if result2.User.Email().MustGet().String() != "second@example.com" {
		t.Errorf("Second update email = %v, want second@example.com", result2.User.Email().MustGet().String())
	}
	if result2.User.Name().MustGet() != "Second Name" {
		t.Errorf("Second update name = %v, want Second Name", result2.User.Name().MustGet())
	}

	// Verify final state in DB
	finalUser, _ := userRepo.FindByID(ctx, user.ID())
	if finalUser.Email().MustGet().String() != "second@example.com" {
		t.Errorf("Final email = %v, want second@example.com", finalUser.Email().MustGet().String())
	}
	if finalUser.Name().MustGet() != "Second Name" {
		t.Errorf("Final name = %v, want Second Name", finalUser.Name().MustGet())
	}
}
