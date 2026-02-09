package query

import (
	"context"

	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

type listLinkedProvidersHandler struct {
	oauthRepo repository.OAuthIdentityRepository
}

func NewListLinkedProvidersHandler(
	oauthRepo repository.OAuthIdentityRepository,
) query.ListLinkedProvidersHandler {
	return &listLinkedProvidersHandler{
		oauthRepo: oauthRepo,
	}
}

func (h *listLinkedProvidersHandler) Handle(ctx context.Context, qry query.ListLinkedProviders) (query.ListLinkedProvidersResult, error) {
	providers, err := h.oauthRepo.FindByUserID(ctx, qry.UserID)
	if err != nil {
		return query.ListLinkedProvidersResult{}, err
	}

	return query.ListLinkedProvidersResult{
		Providers: providers,
	}, nil
}
