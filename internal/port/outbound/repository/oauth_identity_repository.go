package repository

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// OAuthIdentityRepository manages persistence of OAuth identity records.
type OAuthIdentityRepository interface {
	Create(ctx context.Context, identity *model.OAuthIdentity) error
	FindByID(ctx context.Context, id types.ID) (*model.OAuthIdentity, error)
	FindByProviderAndProviderUserID(ctx context.Context, provider model.OAuthProvider, providerUserID string) (*model.OAuthIdentity, error)
	FindByUserID(ctx context.Context, userID types.ID) ([]*model.OAuthIdentity, error)
	FindByUserIDAndProvider(ctx context.Context, userID types.ID, provider model.OAuthProvider) (*model.OAuthIdentity, error)
	Delete(ctx context.Context, id types.ID) error
	DeleteByUserIDAndProvider(ctx context.Context, userID types.ID, provider model.OAuthProvider) error
	CountByUserID(ctx context.Context, userID types.ID) (int64, error)
}
