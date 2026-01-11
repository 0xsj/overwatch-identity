package error

import (
	"github.com/0xsj/overwatch-pkg/errors"
)

// Domain error codes
const (
	// User errors
	CodeUserNotFound         errors.Code = "USER_NOT_FOUND"
	CodeUserAlreadyExists    errors.Code = "USER_ALREADY_EXISTS"
	CodeUserIDRequired       errors.Code = "USER_ID_REQUIRED"
	CodeUserDIDRequired      errors.Code = "USER_DID_REQUIRED"
	CodeUserAlreadyActive    errors.Code = "USER_ALREADY_ACTIVE"
	CodeUserAlreadySuspended errors.Code = "USER_ALREADY_SUSPENDED"
	CodeUserSuspended        errors.Code = "USER_SUSPENDED"

	// Session errors
	CodeSessionNotFound   errors.Code = "SESSION_NOT_FOUND"
	CodeSessionExpired    errors.Code = "SESSION_EXPIRED"
	CodeSessionRevoked    errors.Code = "SESSION_REVOKED"
	CodeSessionIDRequired errors.Code = "SESSION_ID_REQUIRED"

	// Challenge errors
	CodeChallengeNotFound    errors.Code = "CHALLENGE_NOT_FOUND"
	CodeChallengeExpired     errors.Code = "CHALLENGE_EXPIRED"
	CodeChallengeInvalid     errors.Code = "CHALLENGE_INVALID"
	CodeChallengeDIDMismatch errors.Code = "CHALLENGE_DID_MISMATCH"

	// Signature errors
	CodeSignatureInvalid  errors.Code = "SIGNATURE_INVALID"
	CodeSignatureRequired errors.Code = "SIGNATURE_REQUIRED"

	// Token errors
	CodeTokenInvalid         errors.Code = "TOKEN_INVALID"
	CodeTokenExpired         errors.Code = "TOKEN_EXPIRED"
	CodeRefreshTokenInvalid  errors.Code = "REFRESH_TOKEN_INVALID"
	CodeRefreshTokenExpired  errors.Code = "REFRESH_TOKEN_EXPIRED"
	CodeRefreshTokenRequired errors.Code = "REFRESH_TOKEN_REQUIRED"

	// API Key errors
	CodeAPIKeyNotFound     errors.Code = "API_KEY_NOT_FOUND"
	CodeAPIKeyInvalid      errors.Code = "API_KEY_INVALID"
	CodeAPIKeyExpired      errors.Code = "API_KEY_EXPIRED"
	CodeAPIKeyRevoked      errors.Code = "API_KEY_REVOKED"
	CodeAPIKeyNameRequired errors.Code = "API_KEY_NAME_REQUIRED"
)

// User errors
var (
	ErrUserNotFound = errors.New(errors.KindNotFound, CodeUserNotFound, "user not found")

	ErrUserAlreadyExists = errors.New(errors.KindConflict, CodeUserAlreadyExists, "user with this DID already exists")

	ErrUserIDRequired = errors.New(errors.KindValidation, CodeUserIDRequired, "user ID is required")

	ErrUserDIDRequired = errors.New(errors.KindValidation, CodeUserDIDRequired, "user DID is required")

	ErrUserAlreadyActive = errors.New(errors.KindDomain, CodeUserAlreadyActive, "user is already active")

	ErrUserAlreadySuspended = errors.New(errors.KindDomain, CodeUserAlreadySuspended, "user is already suspended")

	ErrUserSuspended = errors.New(errors.KindForbidden, CodeUserSuspended, "user account is suspended")
)

// Session errors
var (
	ErrSessionNotFound = errors.New(errors.KindNotFound, CodeSessionNotFound, "session not found")

	ErrSessionExpired = errors.New(errors.KindUnauthorized, CodeSessionExpired, "session has expired")

	ErrSessionRevoked = errors.New(errors.KindUnauthorized, CodeSessionRevoked, "session has been revoked")

	ErrSessionIDRequired = errors.New(errors.KindValidation, CodeSessionIDRequired, "session ID is required")
)

// Challenge errors
var (
	ErrChallengeNotFound = errors.New(errors.KindNotFound, CodeChallengeNotFound, "challenge not found")

	ErrChallengeExpired = errors.New(errors.KindDomain, CodeChallengeExpired, "challenge has expired")

	ErrChallengeInvalid = errors.New(errors.KindValidation, CodeChallengeInvalid, "challenge is invalid")

	ErrChallengeDIDMismatch = errors.New(errors.KindValidation, CodeChallengeDIDMismatch, "challenge DID does not match request DID")
)

// Signature errors
var (
	ErrSignatureInvalid = errors.New(errors.KindUnauthorized, CodeSignatureInvalid, "signature verification failed")

	ErrSignatureRequired = errors.New(errors.KindValidation, CodeSignatureRequired, "signature is required")
)

// Token errors
var (
	ErrTokenInvalid = errors.New(errors.KindUnauthorized, CodeTokenInvalid, "token is invalid")

	ErrTokenExpired = errors.New(errors.KindUnauthorized, CodeTokenExpired, "token has expired")

	ErrRefreshTokenInvalid = errors.New(errors.KindUnauthorized, CodeRefreshTokenInvalid, "refresh token is invalid")

	ErrRefreshTokenExpired = errors.New(errors.KindUnauthorized, CodeRefreshTokenExpired, "refresh token has expired")

	ErrRefreshTokenRequired = errors.New(errors.KindValidation, CodeRefreshTokenRequired, "refresh token is required")
)

// API Key errors
var (
	ErrAPIKeyNotFound = errors.New(errors.KindNotFound, CodeAPIKeyNotFound, "API key not found")

	ErrAPIKeyInvalid = errors.New(errors.KindUnauthorized, CodeAPIKeyInvalid, "API key is invalid")

	ErrAPIKeyExpired = errors.New(errors.KindUnauthorized, CodeAPIKeyExpired, "API key has expired")

	ErrAPIKeyRevoked = errors.New(errors.KindUnauthorized, CodeAPIKeyRevoked, "API key has been revoked")

	ErrAPIKeyNameRequired = errors.New(errors.KindValidation, CodeAPIKeyNameRequired, "API key name is required")
)

// Helper functions

func UserNotFound(id string) *errors.Error {
	return errors.NotFoundf("user %s not found", id)
}

func UserNotFoundByDID(did string) *errors.Error {
	return errors.NotFoundf("user with DID %s not found", did)
}

func SessionNotFound(id string) *errors.Error {
	return errors.NotFoundf("session %s not found", id)
}

func ChallengeNotFound(id string) *errors.Error {
	return errors.NotFoundf("challenge %s not found", id)
}

func APIKeyNotFound(id string) *errors.Error {
	return errors.NotFoundf("API key %s not found", id)
}
