package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres/sqlc"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// pgtype helpers

func textToOptionalString(t pgtype.Text) types.Optional[string] {
	if t.Valid {
		return types.Some(t.String)
	}
	return types.None[string]()
}

func textToOptionalEmail(t pgtype.Text) types.Optional[types.Email] {
	if t.Valid {
		email, err := types.NewEmail(t.String)
		if err == nil {
			return types.Some(email)
		}
	}
	return types.None[types.Email]()
}

func textToOptionalID(t pgtype.Text) types.Optional[types.ID] {
	if t.Valid {
		id, err := types.ParseID(t.String)
		if err == nil {
			return types.Some(id)
		}
	}
	return types.None[types.ID]()
}

func timestamptzToOptionalTimestamp(t pgtype.Timestamptz) types.Optional[types.Timestamp] {
	if t.Valid {
		return types.Some(types.FromTime(t.Time))
	}
	return types.None[types.Timestamp]()
}

func stringToPgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

func optionalStringToPgText(o types.Optional[string]) pgtype.Text {
	if o.IsPresent() {
		return pgtype.Text{String: o.MustGet(), Valid: true}
	}
	return pgtype.Text{Valid: false}
}

func optionalEmailToPgText(o types.Optional[types.Email]) pgtype.Text {
	if o.IsPresent() {
		return pgtype.Text{String: o.MustGet().String(), Valid: true}
	}
	return pgtype.Text{Valid: false}
}

func optionalIDToPgText(o types.Optional[types.ID]) pgtype.Text {
	if o.IsPresent() {
		return pgtype.Text{String: o.MustGet().String(), Valid: true}
	}
	return pgtype.Text{Valid: false}
}

func optionalTimestampToPgTimestamptz(o types.Optional[types.Timestamp]) pgtype.Timestamptz {
	if o.IsPresent() {
		return pgtype.Timestamptz{Time: o.MustGet().Time(), Valid: true}
	}
	return pgtype.Timestamptz{Valid: false}
}

// User mappers

func toUserModel(row sqlc.User) (*model.User, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	did, err := security.ParseDID(row.Did)
	if err != nil {
		return nil, err
	}

	return model.ReconstructUser(
		id,
		did,
		textToOptionalEmail(row.Email),
		textToOptionalString(row.Name),
		model.UserStatus(row.Status),
		types.FromTime(row.CreatedAt),
		types.FromTime(row.UpdatedAt),
	), nil
}

func toCreateUserParams(user *model.User) sqlc.CreateUserParams {
	return sqlc.CreateUserParams{
		ID:        user.ID().String(),
		Did:       user.DID().String(),
		Email:     optionalEmailToPgText(user.Email()),
		Name:      optionalStringToPgText(user.Name()),
		Status:    user.Status().String(),
		CreatedAt: user.CreatedAt().Time(),
		UpdatedAt: user.UpdatedAt().Time(),
	}
}

func toUpdateUserParams(user *model.User) sqlc.UpdateUserParams {
	return sqlc.UpdateUserParams{
		ID:        user.ID().String(),
		Email:     optionalEmailToPgText(user.Email()),
		Name:      optionalStringToPgText(user.Name()),
		Status:    user.Status().String(),
		UpdatedAt: user.UpdatedAt().Time(),
	}
}

// Session mappers

func toSessionModel(row sqlc.Session) (*model.Session, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	userID, err := types.ParseID(row.UserID)
	if err != nil {
		return nil, err
	}

	userDID, err := security.ParseDID(row.UserDid)
	if err != nil {
		return nil, err
	}

	return model.ReconstructSession(
		id,
		userID,
		userDID,
		textToOptionalID(row.TenantID),
		row.RefreshTokenHash,
		types.FromTime(row.ExpiresAt),
		types.FromTime(row.CreatedAt),
		timestamptzToOptionalTimestamp(row.RevokedAt),
	), nil
}

func toCreateSessionParams(session *model.Session) sqlc.CreateSessionParams {
	return sqlc.CreateSessionParams{
		ID:               session.ID().String(),
		UserID:           session.UserID().String(),
		UserDid:          session.UserDID().String(),
		TenantID:         optionalIDToPgText(session.TenantID()),
		RefreshTokenHash: session.RefreshTokenHash(),
		ExpiresAt:        session.ExpiresAt().Time(),
		CreatedAt:        session.CreatedAt().Time(),
		RevokedAt:        optionalTimestampToPgTimestamptz(session.RevokedAt()),
	}
}

func toUpdateSessionParams(session *model.Session) sqlc.UpdateSessionParams {
	return sqlc.UpdateSessionParams{
		ID:               session.ID().String(),
		RefreshTokenHash: session.RefreshTokenHash(),
		ExpiresAt:        session.ExpiresAt().Time(),
		RevokedAt:        optionalTimestampToPgTimestamptz(session.RevokedAt()),
	}
}

// APIKey mappers

func toAPIKeyModel(row sqlc.ApiKey) (*model.APIKey, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	userID, err := types.ParseID(row.UserID)
	if err != nil {
		return nil, err
	}

	return model.ReconstructAPIKey(
		id,
		userID,
		row.Name,
		row.KeyPrefix,
		row.KeyHash,
		row.Scopes,
		model.APIKeyStatus(row.Status),
		textToOptionalID(row.TenantID),
		timestamptzToOptionalTimestamp(row.ExpiresAt),
		timestamptzToOptionalTimestamp(row.LastUsedAt),
		types.FromTime(row.CreatedAt),
		timestamptzToOptionalTimestamp(row.RevokedAt),
	), nil
}

func toCreateAPIKeyParams(apiKey *model.APIKey) sqlc.CreateAPIKeyParams {
	return sqlc.CreateAPIKeyParams{
		ID:         apiKey.ID().String(),
		UserID:     apiKey.UserID().String(),
		Name:       apiKey.Name(),
		KeyPrefix:  apiKey.KeyPrefix(),
		KeyHash:    apiKey.KeyHash(),
		Scopes:     apiKey.Scopes(),
		Status:     apiKey.Status().String(),
		TenantID:   optionalIDToPgText(apiKey.TenantID()),
		ExpiresAt:  optionalTimestampToPgTimestamptz(apiKey.ExpiresAt()),
		LastUsedAt: optionalTimestampToPgTimestamptz(apiKey.LastUsedAt()),
		CreatedAt:  apiKey.CreatedAt().Time(),
		RevokedAt:  optionalTimestampToPgTimestamptz(apiKey.RevokedAt()),
	}
}

func toUpdateAPIKeyParams(apiKey *model.APIKey) sqlc.UpdateAPIKeyParams {
	return sqlc.UpdateAPIKeyParams{
		ID:         apiKey.ID().String(),
		Name:       apiKey.Name(),
		Scopes:     apiKey.Scopes(),
		Status:     apiKey.Status().String(),
		LastUsedAt: optionalTimestampToPgTimestamptz(apiKey.LastUsedAt()),
		RevokedAt:  optionalTimestampToPgTimestamptz(apiKey.RevokedAt()),
	}
}

// Challenge mappers

func toChallengeModel(row sqlc.Challenge) (*model.Challenge, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	did, err := security.ParseDID(row.Did)
	if err != nil {
		return nil, err
	}

	return model.ReconstructChallenge(
		id,
		did,
		row.Nonce,
		model.ChallengePurpose(row.Purpose),
		types.FromTime(row.ExpiresAt),
		types.FromTime(row.CreatedAt),
	), nil
}

func toCreateChallengeParams(challenge *model.Challenge) sqlc.CreateChallengeParams {
	return sqlc.CreateChallengeParams{
		ID:        challenge.ID().String(),
		Did:       challenge.DID().String(),
		Nonce:     challenge.Nonce(),
		Purpose:   challenge.Purpose().String(),
		ExpiresAt: challenge.ExpiresAt().Time(),
		CreatedAt: challenge.CreatedAt().Time(),
	}
}
