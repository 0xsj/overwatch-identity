package postgres

import (
	"database/sql"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// UserRow represents a user row in the database.
type UserRow struct {
	ID        string
	DID       string
	Email     sql.NullString
	Name      sql.NullString
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SessionRow represents a session row in the database.
type SessionRow struct {
	ID               string
	UserID           string
	UserDID          string
	TenantID         sql.NullString
	RefreshTokenHash string
	ExpiresAt        time.Time
	CreatedAt        time.Time
	RevokedAt        sql.NullTime
}

// APIKeyRow represents an API key row in the database.
type APIKeyRow struct {
	ID         string
	UserID     string
	Name       string
	KeyPrefix  string
	KeyHash    string
	Scopes     []string
	Status     string
	TenantID   sql.NullString
	ExpiresAt  sql.NullTime
	LastUsedAt sql.NullTime
	CreatedAt  time.Time
	RevokedAt  sql.NullTime
}

// ChallengeRow represents a challenge row in the database.
type ChallengeRow struct {
	ID        string
	DID       string
	Nonce     string
	Purpose   string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// ToUserModel converts a UserRow to a domain User.
func ToUserModel(row UserRow) (*model.User, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	did, err := security.ParseDID(row.DID)
	if err != nil {
		return nil, err
	}

	var email types.Optional[types.Email]
	if row.Email.Valid {
		e, err := types.NewEmail(row.Email.String)
		if err == nil {
			email = types.Some(e)
		}
	}

	var name types.Optional[string]
	if row.Name.Valid {
		name = types.Some(row.Name.String)
	}

	return model.ReconstructUser(
		id,
		did,
		email,
		name,
		model.UserStatus(row.Status),
		types.FromTime(row.CreatedAt),
		types.FromTime(row.UpdatedAt),
	), nil
}

// ToUserRow converts a domain User to a UserRow.
func ToUserRow(user *model.User) UserRow {
	row := UserRow{
		ID:        user.ID().String(),
		DID:       user.DID().String(),
		Status:    user.Status().String(),
		CreatedAt: user.CreatedAt().Time(),
		UpdatedAt: user.UpdatedAt().Time(),
	}

	if user.Email().IsPresent() {
		row.Email = sql.NullString{
			String: user.Email().MustGet().String(),
			Valid:  true,
		}
	}

	if user.Name().IsPresent() {
		row.Name = sql.NullString{
			String: user.Name().MustGet(),
			Valid:  true,
		}
	}

	return row
}

// ToSessionModel converts a SessionRow to a domain Session.
func ToSessionModel(row SessionRow) (*model.Session, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	userID, err := types.ParseID(row.UserID)
	if err != nil {
		return nil, err
	}

	userDID, err := security.ParseDID(row.UserDID)
	if err != nil {
		return nil, err
	}

	var tenantID types.Optional[types.ID]
	if row.TenantID.Valid {
		tid, err := types.ParseID(row.TenantID.String)
		if err == nil {
			tenantID = types.Some(tid)
		}
	}

	var revokedAt types.Optional[types.Timestamp]
	if row.RevokedAt.Valid {
		revokedAt = types.Some(types.FromTime(row.RevokedAt.Time))
	}

	return model.ReconstructSession(
		id,
		userID,
		userDID,
		tenantID,
		row.RefreshTokenHash,
		types.FromTime(row.ExpiresAt),
		types.FromTime(row.CreatedAt),
		revokedAt,
	), nil
}

// ToSessionRow converts a domain Session to a SessionRow.
func ToSessionRow(session *model.Session) SessionRow {
	row := SessionRow{
		ID:               session.ID().String(),
		UserID:           session.UserID().String(),
		UserDID:          session.UserDID().String(),
		RefreshTokenHash: session.RefreshTokenHash(),
		ExpiresAt:        session.ExpiresAt().Time(),
		CreatedAt:        session.CreatedAt().Time(),
	}

	if session.TenantID().IsPresent() {
		row.TenantID = sql.NullString{
			String: session.TenantID().MustGet().String(),
			Valid:  true,
		}
	}

	if session.RevokedAt().IsPresent() {
		row.RevokedAt = sql.NullTime{
			Time:  session.RevokedAt().MustGet().Time(),
			Valid: true,
		}
	}

	return row
}

// ToAPIKeyModel converts an APIKeyRow to a domain APIKey.
func ToAPIKeyModel(row APIKeyRow) (*model.APIKey, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	userID, err := types.ParseID(row.UserID)
	if err != nil {
		return nil, err
	}

	var tenantID types.Optional[types.ID]
	if row.TenantID.Valid {
		tid, err := types.ParseID(row.TenantID.String)
		if err == nil {
			tenantID = types.Some(tid)
		}
	}

	var expiresAt types.Optional[types.Timestamp]
	if row.ExpiresAt.Valid {
		expiresAt = types.Some(types.FromTime(row.ExpiresAt.Time))
	}

	var lastUsedAt types.Optional[types.Timestamp]
	if row.LastUsedAt.Valid {
		lastUsedAt = types.Some(types.FromTime(row.LastUsedAt.Time))
	}

	var revokedAt types.Optional[types.Timestamp]
	if row.RevokedAt.Valid {
		revokedAt = types.Some(types.FromTime(row.RevokedAt.Time))
	}

	return model.ReconstructAPIKey(
		id,
		userID,
		row.Name,
		row.KeyPrefix,
		row.KeyHash,
		row.Scopes,
		model.APIKeyStatus(row.Status),
		tenantID,
		expiresAt,
		lastUsedAt,
		types.FromTime(row.CreatedAt),
		revokedAt,
	), nil
}

// ToAPIKeyRow converts a domain APIKey to an APIKeyRow.
func ToAPIKeyRow(apiKey *model.APIKey) APIKeyRow {
	row := APIKeyRow{
		ID:        apiKey.ID().String(),
		UserID:    apiKey.UserID().String(),
		Name:      apiKey.Name(),
		KeyPrefix: apiKey.KeyPrefix(),
		KeyHash:   apiKey.KeyHash(),
		Scopes:    apiKey.Scopes(),
		Status:    apiKey.Status().String(),
		CreatedAt: apiKey.CreatedAt().Time(),
	}

	if apiKey.TenantID().IsPresent() {
		row.TenantID = sql.NullString{
			String: apiKey.TenantID().MustGet().String(),
			Valid:  true,
		}
	}

	if apiKey.ExpiresAt().IsPresent() {
		row.ExpiresAt = sql.NullTime{
			Time:  apiKey.ExpiresAt().MustGet().Time(),
			Valid: true,
		}
	}

	if apiKey.LastUsedAt().IsPresent() {
		row.LastUsedAt = sql.NullTime{
			Time:  apiKey.LastUsedAt().MustGet().Time(),
			Valid: true,
		}
	}

	if apiKey.RevokedAt().IsPresent() {
		row.RevokedAt = sql.NullTime{
			Time:  apiKey.RevokedAt().MustGet().Time(),
			Valid: true,
		}
	}

	return row
}

// ToChallengeModel converts a ChallengeRow to a domain Challenge.
func ToChallengeModel(row ChallengeRow) (*model.Challenge, error) {
	id, err := types.ParseID(row.ID)
	if err != nil {
		return nil, err
	}

	did, err := security.ParseDID(row.DID)
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

// ToChallengeRow converts a domain Challenge to a ChallengeRow.
func ToChallengeRow(challenge *model.Challenge) ChallengeRow {
	return ChallengeRow{
		ID:        challenge.ID().String(),
		DID:       challenge.DID().String(),
		Nonce:     challenge.Nonce(),
		Purpose:   challenge.Purpose().String(),
		ExpiresAt: challenge.ExpiresAt().Time(),
		CreatedAt: challenge.CreatedAt().Time(),
	}
}
