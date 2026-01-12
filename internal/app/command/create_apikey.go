package command

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// createAPIKeyHandler implements command.CreateAPIKeyHandler.
type createAPIKeyHandler struct {
	userRepo   repository.UserRepository
	apiKeyRepo repository.APIKeyRepository
	publisher  messaging.EventPublisher
}

// NewCreateAPIKeyHandler creates a new CreateAPIKeyHandler.
func NewCreateAPIKeyHandler(
	userRepo repository.UserRepository,
	apiKeyRepo repository.APIKeyRepository,
	publisher messaging.EventPublisher,
) command.CreateAPIKeyHandler {
	return &createAPIKeyHandler{
		userRepo:   userRepo,
		apiKeyRepo: apiKeyRepo,
		publisher:  publisher,
	}
}

func (h *createAPIKeyHandler) Handle(ctx context.Context, cmd command.CreateAPIKey) (command.CreateAPIKeyResult, error) {
	if cmd.UserID.IsEmpty() {
		return command.CreateAPIKeyResult{}, domainerror.ErrUserIDRequired
	}

	// Verify user exists
	user, err := h.userRepo.FindByID(ctx, cmd.UserID)
	if err != nil {
		return command.CreateAPIKeyResult{}, domainerror.ErrUserNotFound
	}

	// Check if user can perform actions
	if err := user.CanAuthenticate(); err != nil {
		return command.CreateAPIKeyResult{}, err
	}

	// Create API key (generates key and hash internally)
	apiKeyWithSecret, err := model.NewAPIKey(
		cmd.UserID,
		cmd.Name,
		cmd.Scopes,
		cmd.TenantID,
		cmd.ExpiresAt,
	)
	if err != nil {
		return command.CreateAPIKeyResult{}, err
	}

	// Persist API key
	if err := h.apiKeyRepo.Create(ctx, apiKeyWithSecret.APIKey); err != nil {
		return command.CreateAPIKeyResult{}, err
	}

	// Publish event
	_ = h.publisher.Publish(ctx, event.NewAPIKeyCreated(
		apiKeyWithSecret.APIKey.ID(),
		cmd.UserID,
		cmd.Name,
		cmd.Scopes,
		cmd.TenantID,
		cmd.ExpiresAt,
	))

	return command.CreateAPIKeyResult{
		APIKey: apiKeyWithSecret.APIKey,
		Secret: apiKeyWithSecret.Secret,
	}, nil
}
