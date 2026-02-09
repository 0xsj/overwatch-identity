package query

import (
	"context"

	"github.com/0xsj/overwatch-identity/internal/app/service"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
)

type getOAuthAuthorizationURLHandler struct {
	oauthService service.OAuthService
}

func NewGetOAuthAuthorizationURLHandler(
	oauthService service.OAuthService,
) query.GetOAuthAuthorizationURLHandler {
	return &getOAuthAuthorizationURLHandler{
		oauthService: oauthService,
	}
}

func (h *getOAuthAuthorizationURLHandler) Handle(ctx context.Context, qry query.GetOAuthAuthorizationURL) (query.GetOAuthAuthorizationURLResult, error) {
	state := qry.State
	if state == "" {
		var err error
		state, err = h.oauthService.GenerateState()
		if err != nil {
			return query.GetOAuthAuthorizationURLResult{}, err
		}
	}

	authURL, err := h.oauthService.GetAuthorizationURL(qry.Provider, qry.RedirectURI, state)
	if err != nil {
		return query.GetOAuthAuthorizationURLResult{}, err
	}

	return query.GetOAuthAuthorizationURLResult{
		AuthorizationURL: authURL,
		State:            state,
	}, nil
}
