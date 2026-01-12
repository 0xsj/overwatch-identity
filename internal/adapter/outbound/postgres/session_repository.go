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

// sessionRepository implements repository.SessionRepository.
type sessionRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewSessionRepository creates a new SessionRepository.
func NewSessionRepository(pool *pgxpool.Pool) repository.SessionRepository {
	return &sessionRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *sessionRepository) Create(ctx context.Context, session *model.Session) error {
	params := toCreateSessionParams(session)
	return r.queries.CreateSession(ctx, params)
}

func (r *sessionRepository) Update(ctx context.Context, session *model.Session) error {
	params := toUpdateSessionParams(session)
	return r.queries.UpdateSession(ctx, params)
}

func (r *sessionRepository) FindByID(ctx context.Context, id types.ID) (*model.Session, error) {
	row, err := r.queries.FindSessionByID(ctx, id.String())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toSessionModel(row)
}

func (r *sessionRepository) FindByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	row, err := r.queries.FindSessionByRefreshTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toSessionModel(row)
}

func (r *sessionRepository) FindActiveByUserID(ctx context.Context, userID types.ID) ([]*model.Session, error) {
	rows, err := r.queries.FindActiveSessionsByUserID(ctx, userID.String())
	if err != nil {
		return nil, err
	}

	sessions := make([]*model.Session, 0, len(rows))
	for _, row := range rows {
		session, err := toSessionModel(row)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (r *sessionRepository) List(ctx context.Context, params repository.ListSessionsParams) ([]*model.Session, error) {
	var userIDFilter, tenantIDFilter pgtype.Text

	if params.UserID != nil {
		userIDFilter = stringToPgText(params.UserID.String())
	}
	if params.TenantID != nil {
		tenantIDFilter = stringToPgText(params.TenantID.String())
	}

	sqlcParams := sqlc.ListSessionsParams{
		Limit:      int32(params.Limit),
		Offset:     int32(params.Offset),
		UserID:     userIDFilter,
		TenantID:   tenantIDFilter,
		ActiveOnly: params.ActiveOnly,
		SortBy:     string(params.SortBy),
		SortOrder:  string(params.SortOrder),
	}

	rows, err := r.queries.ListSessions(ctx, sqlcParams)
	if err != nil {
		return nil, err
	}

	sessions := make([]*model.Session, 0, len(rows))
	for _, row := range rows {
		session, err := toSessionModel(row)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (r *sessionRepository) Count(ctx context.Context, params repository.ListSessionsParams) (int64, error) {
	var userIDFilter, tenantIDFilter pgtype.Text

	if params.UserID != nil {
		userIDFilter = stringToPgText(params.UserID.String())
	}
	if params.TenantID != nil {
		tenantIDFilter = stringToPgText(params.TenantID.String())
	}

	sqlcParams := sqlc.CountSessionsParams{
		UserID:     userIDFilter,
		TenantID:   tenantIDFilter,
		ActiveOnly: params.ActiveOnly,
	}

	return r.queries.CountSessions(ctx, sqlcParams)
}

func (r *sessionRepository) RevokeByID(ctx context.Context, id types.ID) error {
	return r.queries.RevokeSessionByID(ctx, id.String())
}

func (r *sessionRepository) RevokeAllByUserID(ctx context.Context, userID types.ID) (int, error) {
	count, err := r.queries.RevokeAllSessionsByUserID(ctx, userID.String())
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) (int, error) {
	count, err := r.queries.DeleteExpiredSessions(ctx)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
