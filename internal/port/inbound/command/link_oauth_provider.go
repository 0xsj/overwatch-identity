package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// LinkOAuthProvider links an OAuth provider to the current user's account.
type LinkOAuthProvider struct {
	UserID      types.ID
	Provider    model.OAuthProvider
	Code        string
	RedirectURI string
}

func (c LinkOAuthProvider) CommandName() string {
	return "identity.link_oauth_provider"
}

// LinkOAuthProviderResult contains the linked OAuth identity.
type LinkOAuthProviderResult struct {
	OAuthIdentity *model.OAuthIdentity
}

// LinkOAuthProviderHandler handles the LinkOAuthProvider command.
type LinkOAuthProviderHandler interface {
	Handle(ctx context.Context, cmd LinkOAuthProvider) (LinkOAuthProviderResult, error)
}
