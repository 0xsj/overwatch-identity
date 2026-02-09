package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// UnlinkOAuthProvider removes an OAuth provider from the current user's account.
type UnlinkOAuthProvider struct {
	UserID   types.ID
	Provider model.OAuthProvider
}

func (c UnlinkOAuthProvider) CommandName() string {
	return "identity.unlink_oauth_provider"
}

// UnlinkOAuthProviderResult is empty on success.
type UnlinkOAuthProviderResult struct{}

// UnlinkOAuthProviderHandler handles the UnlinkOAuthProvider command.
type UnlinkOAuthProviderHandler interface {
	Handle(ctx context.Context, cmd UnlinkOAuthProvider) (UnlinkOAuthProviderResult, error)
}
