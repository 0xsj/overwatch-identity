package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres/sqlc"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

type oauthIdentityRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

func NewOAuthIdentityRepository(pool *pgxpool.Pool) repository.OAuthIdentityRepository {
	return &oauthIdentityRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *oauthIdentityRepository) Create(ctx context.Context, identity *model.OAuthIdentity) error {
	params := toCreateOAuthIdentityParams(identity)
	return r.queries.CreateOAuthIdentity(ctx, params)
}

func (r *oauthIdentityRepository) FindByID(ctx context.Context, id types.ID) (*model.OAuthIdentity, error) {
	row, err := r.queries.FindOAuthIdentityByID(ctx, id.String())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toOAuthIdentityModel(row), nil
}

func (r *oauthIdentityRepository) FindByProviderAndProviderUserID(ctx context.Context, provider model.OAuthProvider, providerUserID string) (*model.OAuthIdentity, error) {
	row, err := r.queries.FindOAuthIdentityByProviderAndProviderUserID(ctx, string(provider), providerUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toOAuthIdentityModel(row), nil
}

func (r *oauthIdentityRepository) FindByUserID(ctx context.Context, userID types.ID) ([]*model.OAuthIdentity, error) {
	rows, err := r.queries.FindOAuthIdentitiesByUserID(ctx, userID.String())
	if err != nil {
		return nil, err
	}

	identities := make([]*model.OAuthIdentity, 0, len(rows))
	for _, row := range rows {
		identities = append(identities, toOAuthIdentityModel(row))
	}
	return identities, nil
}

func (r *oauthIdentityRepository) FindByUserIDAndProvider(ctx context.Context, userID types.ID, provider model.OAuthProvider) (*model.OAuthIdentity, error) {
	row, err := r.queries.FindOAuthIdentityByUserIDAndProvider(ctx, userID.String(), string(provider))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toOAuthIdentityModel(row), nil
}

func (r *oauthIdentityRepository) Delete(ctx context.Context, id types.ID) error {
	return r.queries.DeleteOAuthIdentity(ctx, id.String())
}

func (r *oauthIdentityRepository) DeleteByUserIDAndProvider(ctx context.Context, userID types.ID, provider model.OAuthProvider) error {
	return r.queries.DeleteOAuthIdentityByUserIDAndProvider(ctx, userID.String(), string(provider))
}

func (r *oauthIdentityRepository) CountByUserID(ctx context.Context, userID types.ID) (int64, error) {
	return r.queries.CountOAuthIdentitiesByUserID(ctx, userID.String())
}
