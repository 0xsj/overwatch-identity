package command

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// updateUserHandler implements command.UpdateUserHandler.
type updateUserHandler struct {
	userRepo  repository.UserRepository
	userCache cache.UserCache
	publisher messaging.EventPublisher
}

// NewUpdateUserHandler creates a new UpdateUserHandler.
func NewUpdateUserHandler(
	userRepo repository.UserRepository,
	userCache cache.UserCache,
	publisher messaging.EventPublisher,
) command.UpdateUserHandler {
	return &updateUserHandler{
		userRepo:  userRepo,
		userCache: userCache,
		publisher: publisher,
	}
}

func (h *updateUserHandler) Handle(ctx context.Context, cmd command.UpdateUser) (command.UpdateUserResult, error) {
	if cmd.UserID.IsEmpty() {
		return command.UpdateUserResult{}, domainerror.ErrUserIDRequired
	}

	// Find user
	user, err := h.userRepo.FindByID(ctx, cmd.UserID)
	if err != nil {
		return command.UpdateUserResult{}, domainerror.ErrUserNotFound
	}

	// Track updated fields
	var updatedFields []string

	// Update email if provided
	if cmd.Email.IsPresent() {
		email := cmd.Email.MustGet()
		if user.Email().IsEmpty() || user.Email().MustGet() != email {
			user.SetEmail(email)
			updatedFields = append(updatedFields, "email")
		}
	}

	// Update name if provided
	if cmd.Name.IsPresent() {
		name := cmd.Name.MustGet()
		if user.Name().IsEmpty() || user.Name().MustGet() != name {
			user.SetName(name)
			updatedFields = append(updatedFields, "name")
		}
	}

	// If nothing changed, return early
	if len(updatedFields) == 0 {
		return command.UpdateUserResult{
			User:          user,
			UpdatedFields: updatedFields,
		}, nil
	}

	// Persist changes
	if err := h.userRepo.Update(ctx, user); err != nil {
		return command.UpdateUserResult{}, err
	}

	// Invalidate cache
	_ = h.userCache.Delete(ctx, user.ID())
	_ = h.userCache.DeleteByDID(ctx, user.DID().String())

	// Publish event
	_ = h.publisher.Publish(ctx, event.NewUserUpdated(user.ID(), updatedFields))

	return command.UpdateUserResult{
		User:          user,
		UpdatedFields: updatedFields,
	}, nil
}
