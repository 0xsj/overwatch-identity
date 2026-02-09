package query

import (
	"context"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// GetOAuthAuthorizationURL retrieves the OAuth authorization URL for a provider.
type GetOAuthAuthorizationURL struct {
	Provider    model.OAuthProvider
	RedirectURI string
	State       string
}

func (q GetOAuthAuthorizationURL) QueryName() string {
	return "identity.get_oauth_authorization_url"
}

// GetOAuthAuthorizationURLResult contains the authorization URL and state.
type GetOAuthAuthorizationURLResult struct {
	AuthorizationURL string
	State            string
}

// GetOAuthAuthorizationURLHandler handles the GetOAuthAuthorizationURL query.
type GetOAuthAuthorizationURLHandler interface {
	Handle(ctx context.Context, qry GetOAuthAuthorizationURL) (GetOAuthAuthorizationURLResult, error)
}
