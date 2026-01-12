package query

import (
	"context"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// getAPIKeyHandler implements query.GetAPIKeyHandler.
type getAPIKeyHandler struct {
	apiKeyRepo repository.APIKeyRepository
}

// NewGetAPIKeyHandler creates a new GetAPIKeyHandler.
func NewGetAPIKeyHandler(
	apiKeyRepo repository.APIKeyRepository,
) query.GetAPIKeyHandler {
	return &getAPIKeyHandler{
		apiKeyRepo: apiKeyRepo,
	}
}

func (h *getAPIKeyHandler) Handle(ctx context.Context, qry query.GetAPIKey) (query.GetAPIKeyResult, error) {
	if qry.APIKeyID.IsEmpty() {
		return query.GetAPIKeyResult{}, domainerror.ErrAPIKeyNotFound
	}

	// Fetch API key
	apiKey, err := h.apiKeyRepo.FindByID(ctx, qry.APIKeyID)
	if err != nil {
		return query.GetAPIKeyResult{}, domainerror.ErrAPIKeyNotFound
	}

	// Authorization: user can only see their own API keys
	if apiKey.UserID() != qry.UserID {
		return query.GetAPIKeyResult{}, domainerror.ErrAPIKeyNotFound
	}

	return query.GetAPIKeyResult{APIKey: apiKey}, nil
}
