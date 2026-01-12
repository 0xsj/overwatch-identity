package query

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// listAPIKeysHandler implements query.ListAPIKeysHandler.
type listAPIKeysHandler struct {
	apiKeyRepo repository.APIKeyRepository
}

// NewListAPIKeysHandler creates a new ListAPIKeysHandler.
func NewListAPIKeysHandler(
	apiKeyRepo repository.APIKeyRepository,
) query.ListAPIKeysHandler {
	return &listAPIKeysHandler{
		apiKeyRepo: apiKeyRepo,
	}
}

func (h *listAPIKeysHandler) Handle(ctx context.Context, qry query.ListAPIKeys) (query.ListAPIKeysResult, error) {
	if qry.UserID.IsEmpty() {
		return query.ListAPIKeysResult{}, domainerror.ErrUserIDRequired
	}

	// Set defaults
	limit := qry.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := qry.Offset
	if offset < 0 {
		offset = 0
	}

	// Build params
	params := repository.ListAPIKeysParams{
		Limit:      limit,
		Offset:     offset,
		UserID:     &qry.UserID,
		ActiveOnly: qry.ActiveOnly,
		SortBy:     repository.APIKeySortFieldCreatedAt,
		SortOrder:  repository.SortOrderDesc,
	}

	// Add tenant filter if provided
	if qry.TenantID.IsPresent() {
		tenantID := qry.TenantID.MustGet()
		params.TenantID = &tenantID
	}

	// Fetch API keys
	apiKeys, err := h.apiKeyRepo.List(ctx, params)
	if err != nil {
		return query.ListAPIKeysResult{}, err
	}

	// Fetch count
	totalCount, err := h.apiKeyRepo.Count(ctx, params)
	if err != nil {
		return query.ListAPIKeysResult{}, err
	}

	return query.ListAPIKeysResult{
		APIKeys:    apiKeys,
		TotalCount: totalCount,
	}, nil
}
