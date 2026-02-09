package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// ListLinkedProviders lists all OAuth providers linked to a user.
type ListLinkedProviders struct {
	UserID types.ID
}

func (q ListLinkedProviders) QueryName() string {
	return "identity.list_linked_providers"
}

// ListLinkedProvidersResult contains the linked OAuth identities.
type ListLinkedProvidersResult struct {
	Providers []*model.OAuthIdentity
}

// ListLinkedProvidersHandler handles the ListLinkedProviders query.
type ListLinkedProvidersHandler interface {
	Handle(ctx context.Context, qry ListLinkedProviders) (ListLinkedProvidersResult, error)
}
