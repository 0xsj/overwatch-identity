package query

import (
	"context"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// VerifyAPIKey verifies an API key and returns the associated user.
type VerifyAPIKey struct {
	Key string // The full plaintext API key
}

func (q VerifyAPIKey) QueryName() string {
	return "identity.verify_apikey"
}

// VerifyAPIKeyResult contains the API key and associated user.
type VerifyAPIKeyResult struct {
	APIKey *model.APIKey
	User   *model.User
}

// VerifyAPIKeyHandler handles the VerifyAPIKey query.
type VerifyAPIKeyHandler interface {
	Handle(ctx context.Context, qry VerifyAPIKey) (VerifyAPIKeyResult, error)
}
