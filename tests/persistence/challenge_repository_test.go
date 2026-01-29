package persistence

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

func TestChallengeRepository_Create(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challenge := createTestChallenge(t, model.ChallengePurposeAuthenticate)

	err := challengeRepo.Create(ctx, challenge)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify by reading back
	found, err := challengeRepo.FindByID(ctx, challenge.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != challenge.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), challenge.ID())
	}
	if found.DID().String() != challenge.DID().String() {
		t.Errorf("DID = %v, want %v", found.DID().String(), challenge.DID().String())
	}
	if found.Nonce() != challenge.Nonce() {
		t.Errorf("Nonce = %v, want %v", found.Nonce(), challenge.Nonce())
	}
	if found.Purpose() != challenge.Purpose() {
		t.Errorf("Purpose = %v, want %v", found.Purpose(), challenge.Purpose())
	}
}

func TestChallengeRepository_Create_ForRegistration(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challenge := createTestChallenge(t, model.ChallengePurposeRegister)

	err := challengeRepo.Create(ctx, challenge)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	found, _ := challengeRepo.FindByID(ctx, challenge.ID())
	if found.Purpose() != model.ChallengePurposeRegister {
		t.Errorf("Purpose = %v, want %v", found.Purpose(), model.ChallengePurposeRegister)
	}
	if !found.IsForRegistration() {
		t.Error("IsForRegistration() should return true")
	}
}

func TestChallengeRepository_FindByID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challenge := createTestChallenge(t, model.ChallengePurposeAuthenticate)
	challengeRepo.Create(ctx, challenge)

	found, err := challengeRepo.FindByID(ctx, challenge.ID())

	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.ID() != challenge.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), challenge.ID())
	}
}

func TestChallengeRepository_FindByID_NotFound(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	_, err := challengeRepo.FindByID(ctx, types.NewID())

	if err != repository.ErrNotFound {
		t.Errorf("FindByID() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestChallengeRepository_Delete(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	challenge := createTestChallenge(t, model.ChallengePurposeAuthenticate)
	challengeRepo.Create(ctx, challenge)

	err := challengeRepo.Delete(ctx, challenge.ID())

	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted
	_, err = challengeRepo.FindByID(ctx, challenge.ID())
	if err != repository.ErrNotFound {
		t.Errorf("FindByID() after delete error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestChallengeRepository_Delete_NonExistent(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	// Deleting non-existent should not error
	err := challengeRepo.Delete(ctx, types.NewID())

	if err != nil {
		t.Errorf("Delete() non-existent error = %v, want nil", err)
	}
}

func TestChallengeRepository_DeleteByDID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	did := testDID(t)

	// Create 3 challenges for the same DID
	for i := 0; i < 3; i++ {
		challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())
		challengeRepo.Create(ctx, challenge)
	}

	// Create 1 challenge for different DID
	otherDID := testDID(t)
	otherChallenge, _ := model.NewChallenge(otherDID, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())
	challengeRepo.Create(ctx, otherChallenge)

	err := challengeRepo.DeleteByDID(ctx, did.String())

	if err != nil {
		t.Fatalf("DeleteByDID() error = %v", err)
	}

	// Other DID's challenge should still exist
	found, err := challengeRepo.FindByID(ctx, otherChallenge.ID())
	if err != nil {
		t.Errorf("Other challenge should still exist: %v", err)
	}
	if found.ID() != otherChallenge.ID() {
		t.Errorf("ID = %v, want %v", found.ID(), otherChallenge.ID())
	}
}

func TestChallengeRepository_DeleteByDID_NoMatches(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	// Deleting with no matches should not error
	err := challengeRepo.DeleteByDID(ctx, "did:key:nonexistent")

	if err != nil {
		t.Errorf("DeleteByDID() no matches error = %v, want nil", err)
	}
}

func TestChallengeRepository_DeleteExpired(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	// Create active challenge
	activeChallenge := createTestChallenge(t, model.ChallengePurposeAuthenticate)
	challengeRepo.Create(ctx, activeChallenge)

	// Create expired challenge via direct SQL
	pool := getPool()
	expiredID := types.NewID()
	expiredDID := testDID(t)
	_, err := pool.Exec(ctx, `
		INSERT INTO challenges (id, did, nonce, purpose, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, expiredID.String(), expiredDID.String(), "expirednonce", "authenticate",
		time.Now().Add(-time.Hour), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("failed to insert expired challenge: %v", err)
	}

	count, err := challengeRepo.DeleteExpired(ctx)

	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}
	if count != 1 {
		t.Errorf("DeleteExpired() = %d, want 1", count)
	}

	// Active challenge should still exist
	_, err = challengeRepo.FindByID(ctx, activeChallenge.ID())
	if err != nil {
		t.Errorf("Active challenge should still exist: %v", err)
	}

	// Expired challenge should be deleted
	_, err = challengeRepo.FindByID(ctx, expiredID)
	if err != repository.ErrNotFound {
		t.Errorf("Expired challenge should be deleted, error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestChallengeRepository_DeleteExpired_NoneExpired(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	// Create only active challenges
	for i := 0; i < 3; i++ {
		challenge := createTestChallenge(t, model.ChallengePurposeAuthenticate)
		challengeRepo.Create(ctx, challenge)
	}

	count, err := challengeRepo.DeleteExpired(ctx)

	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}
	if count != 0 {
		t.Errorf("DeleteExpired() = %d, want 0", count)
	}
}

func TestChallengeRepository_MultipleChallengesSameDID(t *testing.T) {
	truncateTables(t)
	ctx := getContext()
	challengeRepo := postgres.NewChallengeRepository(getPool())

	did := testDID(t)

	// Create multiple challenges for same DID (allowed - different nonces)
	challenge1, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())
	challenge2, _ := model.NewChallenge(did, model.ChallengePurposeRegister, model.DefaultChallengeConfig())

	err := challengeRepo.Create(ctx, challenge1)
	if err != nil {
		t.Fatalf("Create() challenge1 error = %v", err)
	}

	err = challengeRepo.Create(ctx, challenge2)
	if err != nil {
		t.Fatalf("Create() challenge2 error = %v", err)
	}

	// Both should be retrievable
	found1, _ := challengeRepo.FindByID(ctx, challenge1.ID())
	found2, _ := challengeRepo.FindByID(ctx, challenge2.ID())

	if found1.ID() != challenge1.ID() {
		t.Errorf("Challenge1 ID = %v, want %v", found1.ID(), challenge1.ID())
	}
	if found2.ID() != challenge2.ID() {
		t.Errorf("Challenge2 ID = %v, want %v", found2.ID(), challenge2.ID())
	}
	if found1.Nonce() == found2.Nonce() {
		t.Error("Challenges should have different nonces")
	}
}

// --- Helpers ---

func createTestChallenge(t *testing.T, purpose model.ChallengePurpose) *model.Challenge {
	t.Helper()
	did := testDID(t)
	challenge, err := model.NewChallenge(did, purpose, model.DefaultChallengeConfig())
	if err != nil {
		t.Fatalf("failed to create test challenge: %v", err)
	}
	return challenge
}
