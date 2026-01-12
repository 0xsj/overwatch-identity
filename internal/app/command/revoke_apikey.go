package command

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// revokeAPIKeyHandler implements command.RevokeAPIKeyHandler.
type revokeAPIKeyHandler struct {
	apiKeyRepo repository.APIKeyRepository
	publisher  messaging.EventPublisher
}

// NewRevokeAPIKeyHandler creates a new RevokeAPIKeyHandler.
func NewRevokeAPIKeyHandler(
	apiKeyRepo repository.APIKeyRepository,
	publisher messaging.EventPublisher,
) command.RevokeAPIKeyHandler {
	return &revokeAPIKeyHandler{
		apiKeyRepo: apiKeyRepo,
		publisher:  publisher,
	}
}

func (h *revokeAPIKeyHandler) Handle(ctx context.Context, cmd command.RevokeAPIKey) (command.RevokeAPIKeyResult, error) {
	if cmd.APIKeyID.IsEmpty() {
		return command.RevokeAPIKeyResult{}, domainerror.ErrAPIKeyNotFound
	}

	// Find API key
	apiKey, err := h.apiKeyRepo.FindByID(ctx, cmd.APIKeyID)
	if err != nil {
		return command.RevokeAPIKeyResult{}, domainerror.ErrAPIKeyNotFound
	}

	// Authorization: user can only revoke their own API keys
	if apiKey.UserID() != cmd.UserID {
		return command.RevokeAPIKeyResult{}, domainerror.ErrAPIKeyNotFound
	}

	// Check if already revoked
	if apiKey.IsRevoked() {
		return command.RevokeAPIKeyResult{}, domainerror.ErrAPIKeyRevoked
	}

	// Revoke API key
	if err := apiKey.Revoke(); err != nil {
		return command.RevokeAPIKeyResult{}, err
	}

	// Persist changes
	if err := h.apiKeyRepo.Update(ctx, apiKey); err != nil {
		return command.RevokeAPIKeyResult{}, err
	}

	// Publish event
	reason := cmd.Reason
	if reason == "" {
		reason = "user requested"
	}
	_ = h.publisher.Publish(ctx, event.NewAPIKeyRevoked(apiKey.ID(), apiKey.UserID(), reason))

	return command.RevokeAPIKeyResult{}, nil
}
