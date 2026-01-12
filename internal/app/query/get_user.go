package query

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// getUserHandler implements query.GetUserHandler.
type getUserHandler struct {
	userRepo  repository.UserRepository
	userCache cache.UserCache
}

// NewGetUserHandler creates a new GetUserHandler.
func NewGetUserHandler(
	userRepo repository.UserRepository,
	userCache cache.UserCache,
) query.GetUserHandler {
	return &getUserHandler{
		userRepo:  userRepo,
		userCache: userCache,
	}
}

func (h *getUserHandler) Handle(ctx context.Context, qry query.GetUser) (query.GetUserResult, error) {
	if qry.UserID.IsEmpty() {
		return query.GetUserResult{}, domainerror.ErrUserIDRequired
	}

	// Try cache first
	if h.userCache != nil {
		user, err := h.userCache.Get(ctx, qry.UserID)
		if err == nil && user != nil {
			return query.GetUserResult{User: user}, nil
		}
	}

	// Fallback to repository
	user, err := h.userRepo.FindByID(ctx, qry.UserID)
	if err != nil {
		return query.GetUserResult{}, domainerror.ErrUserNotFound
	}

	// Populate cache
	if h.userCache != nil {
		_ = h.userCache.Set(ctx, user, 0) // Use default TTL
	}

	return query.GetUserResult{User: user}, nil
}
