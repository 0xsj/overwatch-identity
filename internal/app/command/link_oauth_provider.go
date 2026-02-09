package command

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"

	"github.com/0xsj/overwatch-identity/internal/app/service"
)

type linkOAuthProviderHandler struct {
	oauthRepo    repository.OAuthIdentityRepository
	oauthService service.OAuthService
	publisher    messaging.EventPublisher
}

func NewLinkOAuthProviderHandler(
	oauthRepo repository.OAuthIdentityRepository,
	oauthService service.OAuthService,
	publisher messaging.EventPublisher,
) command.LinkOAuthProviderHandler {
	return &linkOAuthProviderHandler{
		oauthRepo:    oauthRepo,
		oauthService: oauthService,
		publisher:    publisher,
	}
}

func (h *linkOAuthProviderHandler) Handle(ctx context.Context, cmd command.LinkOAuthProvider) (command.LinkOAuthProviderResult, error) {
	// 1. Check if already linked
	existing, err := h.oauthRepo.FindByUserIDAndProvider(ctx, cmd.UserID, cmd.Provider)
	if err == nil && existing != nil {
		return command.LinkOAuthProviderResult{}, domainerror.ErrOAuthAlreadyLinked
	}

	// 2. Exchange code for user info
	userInfo, err := h.oauthService.ExchangeCode(ctx, cmd.Provider, cmd.Code, cmd.RedirectURI)
	if err != nil {
		return command.LinkOAuthProviderResult{}, domainerror.ErrOAuthCodeExchangeFailed
	}

	// 3. Check if this provider account is already linked to another user
	existingOther, err := h.oauthRepo.FindByProviderAndProviderUserID(ctx, cmd.Provider, userInfo.ProviderUserID)
	if err == nil && existingOther != nil {
		return command.LinkOAuthProviderResult{}, domainerror.ErrOAuthAlreadyLinked
	}

	// 4. Create OAuth identity
	oauthIdentity, err := model.NewOAuthIdentity(
		cmd.UserID,
		cmd.Provider,
		userInfo.ProviderUserID,
		userInfo.Email,
		optionalString(userInfo.Name),
		optionalString(userInfo.PictureURL),
	)
	if err != nil {
		return command.LinkOAuthProviderResult{}, err
	}

	if err := h.oauthRepo.Create(ctx, oauthIdentity); err != nil {
		return command.LinkOAuthProviderResult{}, err
	}

	// 5. Publish event
	_ = h.publisher.Publish(ctx, event.NewOAuthLinked(
		cmd.UserID,
		string(cmd.Provider),
		userInfo.ProviderUserID,
		userInfo.Email,
	))

	return command.LinkOAuthProviderResult{
		OAuthIdentity: oauthIdentity,
	}, nil
}
