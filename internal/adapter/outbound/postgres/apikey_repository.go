package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres/sqlc"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// apiKeyRepository implements repository.APIKeyRepository.
type apiKeyRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewAPIKeyRepository creates a new APIKeyRepository.
func NewAPIKeyRepository(pool *pgxpool.Pool) repository.APIKeyRepository {
	return &apiKeyRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *apiKeyRepository) Create(ctx context.Context, apiKey *model.APIKey) error {
	params := toCreateAPIKeyParams(apiKey)
	return r.queries.CreateAPIKey(ctx, params)
}

func (r *apiKeyRepository) Update(ctx context.Context, apiKey *model.APIKey) error {
	params := toUpdateAPIKeyParams(apiKey)
	return r.queries.UpdateAPIKey(ctx, params)
}

func (r *apiKeyRepository) FindByID(ctx context.Context, id types.ID) (*model.APIKey, error) {
	row, err := r.queries.FindAPIKeyByID(ctx, id.String())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toAPIKeyModel(row)
}

func (r *apiKeyRepository) FindByKeyHash(ctx context.Context, hash string) (*model.APIKey, error) {
	row, err := r.queries.FindAPIKeyByKeyHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toAPIKeyModel(row)
}

func (r *apiKeyRepository) FindByPrefix(ctx context.Context, prefix string) (*model.APIKey, error) {
	row, err := r.queries.FindAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toAPIKeyModel(row)
}

func (r *apiKeyRepository) FindActiveByUserID(ctx context.Context, userID types.ID) ([]*model.APIKey, error) {
	rows, err := r.queries.FindActiveAPIKeysByUserID(ctx, userID.String())
	if err != nil {
		return nil, err
	}

	apiKeys := make([]*model.APIKey, 0, len(rows))
	for _, row := range rows {
		apiKey, err := toAPIKeyModel(row)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}

func (r *apiKeyRepository) List(ctx context.Context, params repository.ListAPIKeysParams) ([]*model.APIKey, error) {
	var userIDFilter, tenantIDFilter, statusFilter pgtype.Text

	if params.UserID != nil {
		userIDFilter = stringToPgText(params.UserID.String())
	}
	if params.TenantID != nil {
		tenantIDFilter = stringToPgText(params.TenantID.String())
	}
	if params.Status != nil {
		statusFilter = stringToPgText(params.Status.String())
	}

	sqlcParams := sqlc.ListAPIKeysParams{
		Limit:      int32(params.Limit),
		Offset:     int32(params.Offset),
		UserID:     userIDFilter,
		TenantID:   tenantIDFilter,
		Status:     statusFilter,
		ActiveOnly: params.ActiveOnly,
		SortBy:     string(params.SortBy),
		SortOrder:  string(params.SortOrder),
	}

	rows, err := r.queries.ListAPIKeys(ctx, sqlcParams)
	if err != nil {
		return nil, err
	}

	apiKeys := make([]*model.APIKey, 0, len(rows))
	for _, row := range rows {
		apiKey, err := toAPIKeyModel(row)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}

func (r *apiKeyRepository) Count(ctx context.Context, params repository.ListAPIKeysParams) (int64, error) {
	var userIDFilter, tenantIDFilter, statusFilter pgtype.Text

	if params.UserID != nil {
		userIDFilter = stringToPgText(params.UserID.String())
	}
	if params.TenantID != nil {
		tenantIDFilter = stringToPgText(params.TenantID.String())
	}
	if params.Status != nil {
		statusFilter = stringToPgText(params.Status.String())
	}

	sqlcParams := sqlc.CountAPIKeysParams{
		UserID:     userIDFilter,
		TenantID:   tenantIDFilter,
		Status:     statusFilter,
		ActiveOnly: params.ActiveOnly,
	}

	return r.queries.CountAPIKeys(ctx, sqlcParams)
}

func (r *apiKeyRepository) RevokeByID(ctx context.Context, id types.ID) error {
	return r.queries.RevokeAPIKeyByID(ctx, id.String())
}

func (r *apiKeyRepository) RevokeAllByUserID(ctx context.Context, userID types.ID) (int, error) {
	count, err := r.queries.RevokeAllAPIKeysByUserID(ctx, userID.String())
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (r *apiKeyRepository) Delete(ctx context.Context, id types.ID) error {
	return r.queries.DeleteAPIKey(ctx, id.String())
}

func (r *apiKeyRepository) DeleteExpired(ctx context.Context) (int, error) {
	count, err := r.queries.DeleteExpiredAPIKeys(ctx)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
