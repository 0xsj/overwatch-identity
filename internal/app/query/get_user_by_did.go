package query

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/cache"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// getUserByDIDHandler implements query.GetUserByDIDHandler.
type getUserByDIDHandler struct {
	userRepo  repository.UserRepository
	userCache cache.UserCache
}

// NewGetUserByDIDHandler creates a new GetUserByDIDHandler.
func NewGetUserByDIDHandler(
	userRepo repository.UserRepository,
	userCache cache.UserCache,
) query.GetUserByDIDHandler {
	return &getUserByDIDHandler{
		userRepo:  userRepo,
		userCache: userCache,
	}
}

func (h *getUserByDIDHandler) Handle(ctx context.Context, qry query.GetUserByDID) (query.GetUserByDIDResult, error) {
	if qry.DID == "" {
		return query.GetUserByDIDResult{}, domainerror.ErrUserDIDRequired
	}

	// Try cache first
	if h.userCache != nil {
		user, err := h.userCache.GetByDID(ctx, qry.DID)
		if err == nil && user != nil {
			return query.GetUserByDIDResult{User: user}, nil
		}
	}

	// Fallback to repository
	user, err := h.userRepo.FindByDID(ctx, qry.DID)
	if err != nil {
		return query.GetUserByDIDResult{}, domainerror.ErrUserNotFound
	}

	// Populate cache
	if h.userCache != nil {
		_ = h.userCache.Set(ctx, user, 0) // Use default TTL
	}

	return query.GetUserByDIDResult{User: user}, nil
}
