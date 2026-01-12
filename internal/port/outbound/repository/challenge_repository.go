package repository

import (
	"context"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// ChallengeRepository defines the interface for challenge persistence.
// Challenges are ephemeral and typically stored in Redis with TTL.
type ChallengeRepository interface {
	// Create persists a new challenge.
	Create(ctx context.Context, challenge *model.Challenge) error

	// FindByID retrieves a challenge by its ID.
	FindByID(ctx context.Context, id types.ID) (*model.Challenge, error)

	// Delete removes a challenge by ID.
	// Should be called after successful verification to prevent replay.
	Delete(ctx context.Context, id types.ID) error

	// DeleteByDID removes all challenges for a DID.
	// Useful for cleanup when a new challenge is created.
	DeleteByDID(ctx context.Context, did string) error

	// DeleteExpired removes all expired challenges.
	// Returns the number of challenges deleted.
	DeleteExpired(ctx context.Context) (int, error)
}
