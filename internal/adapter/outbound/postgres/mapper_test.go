package postgres

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres/sqlc"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// --- pgtype helper tests ---

func TestTextToOptionalString(t *testing.T) {
	t.Run("valid text", func(t *testing.T) {
		text := pgtype.Text{String: "hello", Valid: true}

		result := textToOptionalString(text)

		if !result.IsPresent() {
			t.Fatal("result should be present")
		}
		if result.MustGet() != "hello" {
			t.Errorf("result = %v, want hello", result.MustGet())
		}
	})

	t.Run("invalid text", func(t *testing.T) {
		text := pgtype.Text{Valid: false}

		result := textToOptionalString(text)

		if result.IsPresent() {
			t.Error("result should not be present")
		}
	})
}

func TestTextToOptionalEmail(t *testing.T) {
	t.Run("valid email", func(t *testing.T) {
		text := pgtype.Text{String: "test@example.com", Valid: true}

		result := textToOptionalEmail(text)

		if !result.IsPresent() {
			t.Fatal("result should be present")
		}
		if result.MustGet().String() != "test@example.com" {
			t.Errorf("result = %v, want test@example.com", result.MustGet().String())
		}
	})

	t.Run("invalid email format", func(t *testing.T) {
		text := pgtype.Text{String: "not-an-email", Valid: true}

		result := textToOptionalEmail(text)

		if result.IsPresent() {
			t.Error("result should not be present for invalid email")
		}
	})

	t.Run("null text", func(t *testing.T) {
		text := pgtype.Text{Valid: false}

		result := textToOptionalEmail(text)

		if result.IsPresent() {
			t.Error("result should not be present")
		}
	})
}

func TestTextToOptionalID(t *testing.T) {
	t.Run("valid ID", func(t *testing.T) {
		id := types.NewID()
		text := pgtype.Text{String: id.String(), Valid: true}

		result := textToOptionalID(text)

		if !result.IsPresent() {
			t.Fatal("result should be present")
		}
		if result.MustGet() != id {
			t.Errorf("result = %v, want %v", result.MustGet(), id)
		}
	})

	t.Run("null text", func(t *testing.T) {
		text := pgtype.Text{Valid: false}

		result := textToOptionalID(text)

		if result.IsPresent() {
			t.Error("result should not be present")
		}
	})
}

func TestTimestamptzToOptionalTimestamp(t *testing.T) {
	t.Run("valid timestamp", func(t *testing.T) {
		now := time.Now().UTC()
		ts := pgtype.Timestamptz{Time: now, Valid: true}

		result := timestamptzToOptionalTimestamp(ts)

		if !result.IsPresent() {
			t.Fatal("result should be present")
		}
		if !result.MustGet().Time().Equal(now) {
			t.Errorf("result = %v, want %v", result.MustGet().Time(), now)
		}
	})

	t.Run("null timestamp", func(t *testing.T) {
		ts := pgtype.Timestamptz{Valid: false}

		result := timestamptzToOptionalTimestamp(ts)

		if result.IsPresent() {
			t.Error("result should not be present")
		}
	})
}

func TestStringToPgText(t *testing.T) {
	result := stringToPgText("hello")

	if !result.Valid {
		t.Error("result should be valid")
	}
	if result.String != "hello" {
		t.Errorf("result = %v, want hello", result.String)
	}
}

func TestOptionalStringToPgText(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		opt := types.Some("hello")

		result := optionalStringToPgText(opt)

		if !result.Valid {
			t.Error("result should be valid")
		}
		if result.String != "hello" {
			t.Errorf("result = %v, want hello", result.String)
		}
	})

	t.Run("empty", func(t *testing.T) {
		opt := types.None[string]()

		result := optionalStringToPgText(opt)

		if result.Valid {
			t.Error("result should not be valid")
		}
	})
}

func TestOptionalEmailToPgText(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		email, _ := types.NewEmail("test@example.com")
		opt := types.Some(email)

		result := optionalEmailToPgText(opt)

		if !result.Valid {
			t.Error("result should be valid")
		}
		if result.String != "test@example.com" {
			t.Errorf("result = %v, want test@example.com", result.String)
		}
	})

	t.Run("empty", func(t *testing.T) {
		opt := types.None[types.Email]()

		result := optionalEmailToPgText(opt)

		if result.Valid {
			t.Error("result should not be valid")
		}
	})
}

func TestOptionalIDToPgText(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		id := types.NewID()
		opt := types.Some(id)

		result := optionalIDToPgText(opt)

		if !result.Valid {
			t.Error("result should be valid")
		}
		if result.String != id.String() {
			t.Errorf("result = %v, want %v", result.String, id.String())
		}
	})

	t.Run("empty", func(t *testing.T) {
		opt := types.None[types.ID]()

		result := optionalIDToPgText(opt)

		if result.Valid {
			t.Error("result should not be valid")
		}
	})
}

func TestOptionalTimestampToPgTimestamptz(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		ts := types.Now()
		opt := types.Some(ts)

		result := optionalTimestampToPgTimestamptz(opt)

		if !result.Valid {
			t.Error("result should be valid")
		}
		if !result.Time.Equal(ts.Time()) {
			t.Errorf("result = %v, want %v", result.Time, ts.Time())
		}
	})

	t.Run("empty", func(t *testing.T) {
		opt := types.None[types.Timestamp]()

		result := optionalTimestampToPgTimestamptz(opt)

		if result.Valid {
			t.Error("result should not be valid")
		}
	})
}

// --- User mapper tests ---

func TestToUserModel(t *testing.T) {
	did := testDID(t)
	now := time.Now().UTC()
	id := types.NewID()

	row := sqlc.User{
		ID:        id.String(),
		Did:       did.String(),
		Email:     pgtype.Text{String: "test@example.com", Valid: true},
		Name:      pgtype.Text{String: "Alice", Valid: true},
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}

	user, err := toUserModel(row)

	if err != nil {
		t.Fatalf("toUserModel() error = %v", err)
	}
	if user.ID() != id {
		t.Errorf("ID = %v, want %v", user.ID(), id)
	}
	if user.DID().String() != did.String() {
		t.Errorf("DID = %v, want %v", user.DID().String(), did.String())
	}
	if !user.Email().IsPresent() || user.Email().MustGet().String() != "test@example.com" {
		t.Errorf("Email = %v, want test@example.com", user.Email())
	}
	if !user.Name().IsPresent() || user.Name().MustGet() != "Alice" {
		t.Errorf("Name = %v, want Alice", user.Name())
	}
	if user.Status() != model.UserStatusActive {
		t.Errorf("Status = %v, want %v", user.Status(), model.UserStatusActive)
	}
}

func TestToUserModel_NullFields(t *testing.T) {
	did := testDID(t)
	now := time.Now().UTC()
	id := types.NewID()

	row := sqlc.User{
		ID:        id.String(),
		Did:       did.String(),
		Email:     pgtype.Text{Valid: false},
		Name:      pgtype.Text{Valid: false},
		Status:    "suspended",
		CreatedAt: now,
		UpdatedAt: now,
	}

	user, err := toUserModel(row)

	if err != nil {
		t.Fatalf("toUserModel() error = %v", err)
	}
	if user.Email().IsPresent() {
		t.Error("Email should not be present")
	}
	if user.Name().IsPresent() {
		t.Error("Name should not be present")
	}
	if user.Status() != model.UserStatusSuspended {
		t.Errorf("Status = %v, want %v", user.Status(), model.UserStatusSuspended)
	}
}

func TestToUserModel_InvalidID(t *testing.T) {
	row := sqlc.User{
		ID:  "", // invalid
		Did: "did:key:z6MkTest",
	}

	_, err := toUserModel(row)

	if err == nil {
		t.Error("toUserModel() should return error for invalid ID")
	}
}

func TestToUserModel_InvalidDID(t *testing.T) {
	row := sqlc.User{
		ID:  types.NewID().String(),
		Did: "invalid-did",
	}

	_, err := toUserModel(row)

	if err == nil {
		t.Error("toUserModel() should return error for invalid DID")
	}
}

func TestToCreateUserParams(t *testing.T) {
	did := testDID(t)
	user, _ := model.NewUser(did)
	email, _ := types.NewEmail("test@example.com")
	user.SetEmail(email)
	user.SetName("Alice")

	params := toCreateUserParams(user)

	if params.ID != user.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, user.ID().String())
	}
	if params.Did != user.DID().String() {
		t.Errorf("Did = %v, want %v", params.Did, user.DID().String())
	}
	if !params.Email.Valid || params.Email.String != "test@example.com" {
		t.Errorf("Email = %v, want test@example.com", params.Email)
	}
	if !params.Name.Valid || params.Name.String != "Alice" {
		t.Errorf("Name = %v, want Alice", params.Name)
	}
	if params.Status != "active" {
		t.Errorf("Status = %v, want active", params.Status)
	}
}

func TestToUpdateUserParams(t *testing.T) {
	did := testDID(t)
	user, _ := model.NewUser(did)
	email, _ := types.NewEmail("updated@example.com")
	user.SetEmail(email)
	user.SetName("Bob")
	user.Suspend()

	params := toUpdateUserParams(user)

	if params.ID != user.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, user.ID().String())
	}
	if !params.Email.Valid || params.Email.String != "updated@example.com" {
		t.Errorf("Email = %v, want updated@example.com", params.Email)
	}
	if !params.Name.Valid || params.Name.String != "Bob" {
		t.Errorf("Name = %v, want Bob", params.Name)
	}
	if params.Status != "suspended" {
		t.Errorf("Status = %v, want suspended", params.Status)
	}
}

// --- Session mapper tests ---

func TestToSessionModel(t *testing.T) {
	did := testDID(t)
	now := time.Now().UTC()
	id := types.NewID()
	userID := types.NewID()
	tenantID := types.NewID()

	row := sqlc.Session{
		ID:               id.String(),
		UserID:           userID.String(),
		UserDid:          did.String(),
		TenantID:         pgtype.Text{String: tenantID.String(), Valid: true},
		RefreshTokenHash: "somehash",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
		RevokedAt:        pgtype.Timestamptz{Valid: false},
	}

	session, err := toSessionModel(row)

	if err != nil {
		t.Fatalf("toSessionModel() error = %v", err)
	}
	if session.ID() != id {
		t.Errorf("ID = %v, want %v", session.ID(), id)
	}
	if session.UserID() != userID {
		t.Errorf("UserID = %v, want %v", session.UserID(), userID)
	}
	if session.UserDID().String() != did.String() {
		t.Errorf("UserDID = %v, want %v", session.UserDID().String(), did.String())
	}
	if !session.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if session.RefreshTokenHash() != "somehash" {
		t.Errorf("RefreshTokenHash = %v, want somehash", session.RefreshTokenHash())
	}
	if session.RevokedAt().IsPresent() {
		t.Error("RevokedAt should not be present")
	}
}

func TestToSessionModel_WithRevokedAt(t *testing.T) {
	did := testDID(t)
	now := time.Now().UTC()
	revokedAt := now.Add(-time.Minute)

	row := sqlc.Session{
		ID:               types.NewID().String(),
		UserID:           types.NewID().String(),
		UserDid:          did.String(),
		TenantID:         pgtype.Text{Valid: false},
		RefreshTokenHash: "somehash",
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
		RevokedAt:        pgtype.Timestamptz{Time: revokedAt, Valid: true},
	}

	session, err := toSessionModel(row)

	if err != nil {
		t.Fatalf("toSessionModel() error = %v", err)
	}
	if !session.RevokedAt().IsPresent() {
		t.Fatal("RevokedAt should be present")
	}
	if !session.RevokedAt().MustGet().Time().Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", session.RevokedAt().MustGet().Time(), revokedAt)
	}
}

func TestToCreateSessionParams(t *testing.T) {
	did := testDID(t)
	userID := types.NewID()
	tenantID := types.Some(types.NewID())

	session, _ := model.NewSession(userID, did, tenantID, "refreshhash", model.DefaultSessionConfig())

	params := toCreateSessionParams(session)

	if params.ID != session.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, session.ID().String())
	}
	if params.UserID != userID.String() {
		t.Errorf("UserID = %v, want %v", params.UserID, userID.String())
	}
	if params.UserDid != did.String() {
		t.Errorf("UserDid = %v, want %v", params.UserDid, did.String())
	}
	if !params.TenantID.Valid {
		t.Error("TenantID should be valid")
	}
	if params.RefreshTokenHash != "refreshhash" {
		t.Errorf("RefreshTokenHash = %v, want refreshhash", params.RefreshTokenHash)
	}
	if !params.RevokedAt.Valid {
		// New session should not be revoked
	}
}

func TestToUpdateSessionParams(t *testing.T) {
	did := testDID(t)
	userID := types.NewID()

	session, _ := model.NewSession(userID, did, types.None[types.ID](), "oldhash", model.DefaultSessionConfig())
	session.Refresh("newhash", time.Hour)

	params := toUpdateSessionParams(session)

	if params.ID != session.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, session.ID().String())
	}
	if params.RefreshTokenHash != "newhash" {
		t.Errorf("RefreshTokenHash = %v, want newhash", params.RefreshTokenHash)
	}
}

// --- APIKey mapper tests ---

func TestToAPIKeyModel(t *testing.T) {
	now := time.Now().UTC()
	id := types.NewID()
	userID := types.NewID()
	tenantID := types.NewID()
	expiresAt := now.Add(24 * time.Hour)

	row := sqlc.ApiKey{
		ID:         id.String(),
		UserID:     userID.String(),
		Name:       "Test Key",
		KeyPrefix:  "ow_abc12",
		KeyHash:    "somehash",
		Scopes:     []string{"read:users", "write:users"},
		Status:     "active",
		TenantID:   pgtype.Text{String: tenantID.String(), Valid: true},
		ExpiresAt:  pgtype.Timestamptz{Time: expiresAt, Valid: true},
		LastUsedAt: pgtype.Timestamptz{Valid: false},
		CreatedAt:  now,
		RevokedAt:  pgtype.Timestamptz{Valid: false},
	}

	apiKey, err := toAPIKeyModel(row)

	if err != nil {
		t.Fatalf("toAPIKeyModel() error = %v", err)
	}
	if apiKey.ID() != id {
		t.Errorf("ID = %v, want %v", apiKey.ID(), id)
	}
	if apiKey.UserID() != userID {
		t.Errorf("UserID = %v, want %v", apiKey.UserID(), userID)
	}
	if apiKey.Name() != "Test Key" {
		t.Errorf("Name = %v, want Test Key", apiKey.Name())
	}
	if apiKey.KeyPrefix() != "ow_abc12" {
		t.Errorf("KeyPrefix = %v, want ow_abc12", apiKey.KeyPrefix())
	}
	if apiKey.KeyHash() != "somehash" {
		t.Errorf("KeyHash = %v, want somehash", apiKey.KeyHash())
	}
	if len(apiKey.Scopes()) != 2 {
		t.Errorf("Scopes count = %d, want 2", len(apiKey.Scopes()))
	}
	if apiKey.Status() != model.APIKeyStatusActive {
		t.Errorf("Status = %v, want %v", apiKey.Status(), model.APIKeyStatusActive)
	}
	if !apiKey.TenantID().IsPresent() {
		t.Error("TenantID should be present")
	}
	if !apiKey.ExpiresAt().IsPresent() {
		t.Error("ExpiresAt should be present")
	}
	if apiKey.LastUsedAt().IsPresent() {
		t.Error("LastUsedAt should not be present")
	}
	if apiKey.RevokedAt().IsPresent() {
		t.Error("RevokedAt should not be present")
	}
}

func TestToCreateAPIKeyParams(t *testing.T) {
	userID := types.NewID()
	result, _ := model.NewAPIKey(userID, "My Key", []string{"read", "write"}, types.None[types.ID](), types.None[types.Timestamp]())
	apiKey := result.APIKey

	params := toCreateAPIKeyParams(apiKey)

	if params.ID != apiKey.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, apiKey.ID().String())
	}
	if params.UserID != userID.String() {
		t.Errorf("UserID = %v, want %v", params.UserID, userID.String())
	}
	if params.Name != "My Key" {
		t.Errorf("Name = %v, want My Key", params.Name)
	}
	if params.KeyPrefix != apiKey.KeyPrefix() {
		t.Errorf("KeyPrefix = %v, want %v", params.KeyPrefix, apiKey.KeyPrefix())
	}
	if params.KeyHash != apiKey.KeyHash() {
		t.Errorf("KeyHash = %v, want %v", params.KeyHash, apiKey.KeyHash())
	}
	if params.Status != "active" {
		t.Errorf("Status = %v, want active", params.Status)
	}
}

func TestToUpdateAPIKeyParams(t *testing.T) {
	userID := types.NewID()
	result, _ := model.NewAPIKey(userID, "My Key", []string{"read"}, types.None[types.ID](), types.None[types.Timestamp]())
	apiKey := result.APIKey
	apiKey.RecordUsage()
	apiKey.Revoke()

	params := toUpdateAPIKeyParams(apiKey)

	if params.ID != apiKey.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, apiKey.ID().String())
	}
	if params.Name != "My Key" {
		t.Errorf("Name = %v, want My Key", params.Name)
	}
	if params.Status != "revoked" {
		t.Errorf("Status = %v, want revoked", params.Status)
	}
	if !params.LastUsedAt.Valid {
		t.Error("LastUsedAt should be valid")
	}
	if !params.RevokedAt.Valid {
		t.Error("RevokedAt should be valid")
	}
}

// --- Challenge mapper tests ---

func TestToChallengeModel(t *testing.T) {
	did := testDID(t)
	now := time.Now().UTC()
	id := types.NewID()

	row := sqlc.Challenge{
		ID:        id.String(),
		Did:       did.String(),
		Nonce:     "testnonce123",
		Purpose:   "authenticate",
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}

	challenge, err := toChallengeModel(row)

	if err != nil {
		t.Fatalf("toChallengeModel() error = %v", err)
	}
	if challenge.ID() != id {
		t.Errorf("ID = %v, want %v", challenge.ID(), id)
	}
	if challenge.DID().String() != did.String() {
		t.Errorf("DID = %v, want %v", challenge.DID().String(), did.String())
	}
	if challenge.Nonce() != "testnonce123" {
		t.Errorf("Nonce = %v, want testnonce123", challenge.Nonce())
	}
	if challenge.Purpose() != model.ChallengePurposeAuthenticate {
		t.Errorf("Purpose = %v, want %v", challenge.Purpose(), model.ChallengePurposeAuthenticate)
	}
}

func TestToChallengeModel_Register(t *testing.T) {
	did := testDID(t)
	now := time.Now().UTC()

	row := sqlc.Challenge{
		ID:        types.NewID().String(),
		Did:       did.String(),
		Nonce:     "testnonce",
		Purpose:   "register",
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}

	challenge, err := toChallengeModel(row)

	if err != nil {
		t.Fatalf("toChallengeModel() error = %v", err)
	}
	if challenge.Purpose() != model.ChallengePurposeRegister {
		t.Errorf("Purpose = %v, want %v", challenge.Purpose(), model.ChallengePurposeRegister)
	}
}

func TestToCreateChallengeParams(t *testing.T) {
	did := testDID(t)
	challenge, _ := model.NewChallenge(did, model.ChallengePurposeAuthenticate, model.DefaultChallengeConfig())

	params := toCreateChallengeParams(challenge)

	if params.ID != challenge.ID().String() {
		t.Errorf("ID = %v, want %v", params.ID, challenge.ID().String())
	}
	if params.Did != did.String() {
		t.Errorf("Did = %v, want %v", params.Did, did.String())
	}
	if params.Nonce != challenge.Nonce() {
		t.Errorf("Nonce = %v, want %v", params.Nonce, challenge.Nonce())
	}
	if params.Purpose != "authenticate" {
		t.Errorf("Purpose = %v, want authenticate", params.Purpose)
	}
}

// --- Helper ---

func testDID(t *testing.T) *security.DID {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID: %v", err)
	}
	return did
}
