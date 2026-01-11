package query

import (
	"context"

	"github.com/0xsj/overwatch-pkg/security"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/query"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// verifyAPIKeyHandler implements query.VerifyAPIKeyHandler.
type verifyAPIKeyHandler struct {
	apiKeyRepo repository.APIKeyRepository
	userRepo   repository.UserRepository
	publisher  messaging.EventPublisher
}

// NewVerifyAPIKeyHandler creates a new VerifyAPIKeyHandler.
func NewVerifyAPIKeyHandler(
	apiKeyRepo repository.APIKeyRepository,
	userRepo repository.UserRepository,
	publisher messaging.EventPublisher,
) query.VerifyAPIKeyHandler {
	return &verifyAPIKeyHandler{
		apiKeyRepo: apiKeyRepo,
		userRepo:   userRepo,
		publisher:  publisher,
	}
}

func (h *verifyAPIKeyHandler) Handle(ctx context.Context, qry query.VerifyAPIKey) (query.VerifyAPIKeyResult, error) {
	if qry.Key == "" {
		return query.VerifyAPIKeyResult{}, domainerror.ErrAPIKeyInvalid
	}

	// Hash the provided key
	keyHash := security.SHA256Hex([]byte(qry.Key))

	// Find API key by hash
	apiKey, err := h.apiKeyRepo.FindByKeyHash(ctx, keyHash)
	if err != nil {
		return query.VerifyAPIKeyResult{}, domainerror.ErrAPIKeyInvalid
	}

	// Validate API key (checks revoked, expired)
	if err := apiKey.Validate(); err != nil {
		return query.VerifyAPIKeyResult{}, err
	}

	// Find associated user
	user, err := h.userRepo.FindByID(ctx, apiKey.UserID())
	if err != nil {
		return query.VerifyAPIKeyResult{}, domainerror.ErrUserNotFound
	}

	// Check if user can authenticate
	if err := user.CanAuthenticate(); err != nil {
		return query.VerifyAPIKeyResult{}, err
	}

	// Record usage
	apiKey.RecordUsage()
	_ = h.apiKeyRepo.Update(ctx, apiKey)

	// Publish usage event (fire and forget)
	_ = h.publisher.Publish(ctx, event.NewAPIKeyUsed(
		apiKey.ID(),
		apiKey.UserID(),
		"", // Endpoint not known at this layer
	))

	return query.VerifyAPIKeyResult{
		APIKey: apiKey,
		User:   user,
	}, nil
}
