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

// challengeRepository implements repository.ChallengeRepository.
type challengeRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewChallengeRepository creates a new ChallengeRepository.
func NewChallengeRepository(pool *pgxpool.Pool) repository.ChallengeRepository {
	return &challengeRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *challengeRepository) Create(ctx context.Context, challenge *model.Challenge) error {
	params := toCreateChallengeParams(challenge)
	return r.queries.CreateChallenge(ctx, params)
}

func (r *challengeRepository) FindByID(ctx context.Context, id types.ID) (*model.Challenge, error) {
	row, err := r.queries.FindChallengeByID(ctx, id.String())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toChallengeModel(row)
}

func (r *challengeRepository) Delete(ctx context.Context, id types.ID) error {
	return r.queries.DeleteChallenge(ctx, id.String())
}

func (r *challengeRepository) DeleteByDID(ctx context.Context, did string) error {
	return r.queries.DeleteChallengesByDID(ctx, did)
}

func (r *challengeRepository) DeleteExpired(ctx context.Context) (int, error) {
	count, err := r.queries.DeleteExpiredChallenges(ctx)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
