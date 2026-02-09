package command

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

type unlinkOAuthProviderHandler struct {
	oauthRepo repository.OAuthIdentityRepository
	publisher messaging.EventPublisher
}

func NewUnlinkOAuthProviderHandler(
	oauthRepo repository.OAuthIdentityRepository,
	publisher messaging.EventPublisher,
) command.UnlinkOAuthProviderHandler {
	return &unlinkOAuthProviderHandler{
		oauthRepo: oauthRepo,
		publisher: publisher,
	}
}

func (h *unlinkOAuthProviderHandler) Handle(ctx context.Context, cmd command.UnlinkOAuthProvider) (command.UnlinkOAuthProviderResult, error) {
	// 1. Check if linked
	existing, err := h.oauthRepo.FindByUserIDAndProvider(ctx, cmd.UserID, cmd.Provider)
	if err != nil || existing == nil {
		return command.UnlinkOAuthProviderResult{}, domainerror.ErrOAuthNotLinked
	}

	// 2. Guard: don't unlink the last auth method
	// For now, check if user has any other OAuth providers
	// In a more complete implementation, we'd also check if user has a DID challenge capability
	count, err := h.oauthRepo.CountByUserID(ctx, cmd.UserID)
	if err != nil {
		return command.UnlinkOAuthProviderResult{}, err
	}
	if count <= 1 {
		return command.UnlinkOAuthProviderResult{}, domainerror.ErrOAuthLastProvider
	}

	// 3. Delete the link
	if err := h.oauthRepo.DeleteByUserIDAndProvider(ctx, cmd.UserID, cmd.Provider); err != nil {
		return command.UnlinkOAuthProviderResult{}, err
	}

	// 4. Publish event
	_ = h.publisher.Publish(ctx, event.NewOAuthUnlinked(cmd.UserID, string(cmd.Provider)))

	return command.UnlinkOAuthProviderResult{}, nil
}
