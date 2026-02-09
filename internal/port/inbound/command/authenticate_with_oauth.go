package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// AuthenticateWithOAuth exchanges an OAuth code for tokens.
type AuthenticateWithOAuth struct {
	Provider    model.OAuthProvider
	Code        string
	RedirectURI string
	TenantID    types.Optional[types.ID]
}

func (c AuthenticateWithOAuth) CommandName() string {
	return "identity.authenticate_with_oauth"
}

// AuthenticateWithOAuthResult contains the user, tokens, and whether this is a new user.
type AuthenticateWithOAuthResult struct {
	User                 *model.User
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt types.Timestamp
	IsNewUser            bool
}

// AuthenticateWithOAuthHandler handles the AuthenticateWithOAuth command.
type AuthenticateWithOAuthHandler interface {
	Handle(ctx context.Context, cmd AuthenticateWithOAuth) (AuthenticateWithOAuthResult, error)
}
