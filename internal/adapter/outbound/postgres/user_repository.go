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

// userRepository implements repository.UserRepository.
type userRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewUserRepository creates a new UserRepository.
func NewUserRepository(pool *pgxpool.Pool) repository.UserRepository {
	return &userRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	params := toCreateUserParams(user)
	return r.queries.CreateUser(ctx, params)
}

func (r *userRepository) Update(ctx context.Context, user *model.User) error {
	params := toUpdateUserParams(user)
	return r.queries.UpdateUser(ctx, params)
}

func (r *userRepository) FindByID(ctx context.Context, id types.ID) (*model.User, error) {
	row, err := r.queries.FindUserByID(ctx, id.String())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toUserModel(row)
}

func (r *userRepository) FindByDID(ctx context.Context, did string) (*model.User, error) {
	row, err := r.queries.FindUserByDID(ctx, did)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toUserModel(row)
}

func (r *userRepository) FindByEmail(ctx context.Context, email types.Email) (*model.User, error) {
	row, err := r.queries.FindUserByEmail(ctx, stringToPgText(email.String()))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toUserModel(row)
}

func (r *userRepository) ExistsByDID(ctx context.Context, did string) (bool, error) {
	return r.queries.ExistsByDID(ctx, did)
}

func (r *userRepository) ExistsByEmail(ctx context.Context, email types.Email) (bool, error) {
	return r.queries.ExistsByEmail(ctx, stringToPgText(email.String()))
}

func (r *userRepository) List(ctx context.Context, params repository.ListUsersParams) ([]*model.User, error) {
	var statusFilter pgtype.Text
	if params.Status != nil {
		statusFilter = stringToPgText(params.Status.String())
	}

	sqlcParams := sqlc.ListUsersParams{
		Limit:     int32(params.Limit),
		Offset:    int32(params.Offset),
		Status:    statusFilter,
		SortBy:    string(params.SortBy),
		SortOrder: string(params.SortOrder),
	}

	rows, err := r.queries.ListUsers(ctx, sqlcParams)
	if err != nil {
		return nil, err
	}

	users := make([]*model.User, 0, len(rows))
	for _, row := range rows {
		user, err := toUserModel(row)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func (r *userRepository) Count(ctx context.Context, params repository.ListUsersParams) (int64, error) {
	var statusFilter pgtype.Text
	if params.Status != nil {
		statusFilter = stringToPgText(params.Status.String())
	}

	return r.queries.CountUsers(ctx, statusFilter)
}

func (r *userRepository) Delete(ctx context.Context, id types.ID) error {
	return r.queries.DeleteUser(ctx, id.String())
}
