package grpc

import (
	"github.com/0xsj/overwatch-pkg/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// User mappers

func toProtoUser(user *model.User) *identityv1.User {
	if user == nil {
		return nil
	}

	protoUser := &identityv1.User{
		Id:        user.ID().String(),
		Did:       user.DID().String(),
		Status:    toProtoUserStatus(user.Status()),
		CreatedAt: timestamppb.New(user.CreatedAt().Time()),
		UpdatedAt: timestamppb.New(user.UpdatedAt().Time()),
	}

	if user.Email().IsPresent() {
		email := user.Email().MustGet().String()
		protoUser.Email = &email
	}

	if user.Name().IsPresent() {
		name := user.Name().MustGet()
		protoUser.Name = &name
	}

	return protoUser
}

func toProtoUserStatus(status model.UserStatus) identityv1.UserStatus {
	switch status {
	case model.UserStatusActive:
		return identityv1.UserStatus_USER_STATUS_ACTIVE
	case model.UserStatusSuspended:
		return identityv1.UserStatus_USER_STATUS_SUSPENDED
	default:
		return identityv1.UserStatus_USER_STATUS_UNSPECIFIED
	}
}

// Session mappers

func toProtoSession(session *model.Session) *identityv1.Session {
	if session == nil {
		return nil
	}

	protoSession := &identityv1.Session{
		Id:               session.ID().String(),
		UserId:           session.UserID().String(),
		UserDid:          session.UserDID().String(),
		RefreshTokenHash: session.RefreshTokenHash(),
		ExpiresAt:        timestamppb.New(session.ExpiresAt().Time()),
		CreatedAt:        timestamppb.New(session.CreatedAt().Time()),
	}

	if session.TenantID().IsPresent() {
		tenantID := session.TenantID().MustGet().String()
		protoSession.TenantId = &tenantID
	}

	if session.RevokedAt().IsPresent() {
		protoSession.RevokedAt = timestamppb.New(session.RevokedAt().MustGet().Time())
	}

	return protoSession
}

func toProtoSessions(sessions []*model.Session) []*identityv1.Session {
	result := make([]*identityv1.Session, len(sessions))
	for i, s := range sessions {
		result[i] = toProtoSession(s)
	}
	return result
}

// APIKey mappers

func toProtoAPIKey(apiKey *model.APIKey) *identityv1.APIKey {
	if apiKey == nil {
		return nil
	}

	protoKey := &identityv1.APIKey{
		Id:        apiKey.ID().String(),
		UserId:    apiKey.UserID().String(),
		Name:      apiKey.Name(),
		KeyPrefix: apiKey.KeyPrefix(),
		Scopes:    apiKey.Scopes(),
		Status:    toProtoAPIKeyStatus(apiKey.Status()),
		CreatedAt: timestamppb.New(apiKey.CreatedAt().Time()),
	}

	if apiKey.TenantID().IsPresent() {
		tenantID := apiKey.TenantID().MustGet().String()
		protoKey.TenantId = &tenantID
	}

	if apiKey.ExpiresAt().IsPresent() {
		protoKey.ExpiresAt = timestamppb.New(apiKey.ExpiresAt().MustGet().Time())
	}

	if apiKey.LastUsedAt().IsPresent() {
		protoKey.LastUsedAt = timestamppb.New(apiKey.LastUsedAt().MustGet().Time())
	}

	if apiKey.RevokedAt().IsPresent() {
		protoKey.RevokedAt = timestamppb.New(apiKey.RevokedAt().MustGet().Time())
	}

	return protoKey
}

func toProtoAPIKeys(apiKeys []*model.APIKey) []*identityv1.APIKey {
	result := make([]*identityv1.APIKey, len(apiKeys))
	for i, k := range apiKeys {
		result[i] = toProtoAPIKey(k)
	}
	return result
}

func toProtoAPIKeyStatus(status model.APIKeyStatus) identityv1.APIKeyStatus {
	switch status {
	case model.APIKeyStatusActive:
		return identityv1.APIKeyStatus_API_KEY_STATUS_ACTIVE
	case model.APIKeyStatusRevoked:
		return identityv1.APIKeyStatus_API_KEY_STATUS_REVOKED
	default:
		return identityv1.APIKeyStatus_API_KEY_STATUS_UNSPECIFIED
	}
}

// Request mappers

func toOptionalTenantID(tenantID *string) types.Optional[types.ID] {
	if tenantID == nil || *tenantID == "" {
		return types.None[types.ID]()
	}
	id, err := types.ParseID(*tenantID)
	if err != nil {
		return types.None[types.ID]()
	}
	return types.Some(id)
}

func toOptionalTimestamp(ts *timestamppb.Timestamp) types.Optional[types.Timestamp] {
	if ts == nil {
		return types.None[types.Timestamp]()
	}
	return types.Some(types.FromTime(ts.AsTime()))
}

func toOptionalString(s *string) types.Optional[string] {
	if s == nil || *s == "" {
		return types.None[string]()
	}
	return types.Some(*s)
}

func toOptionalEmail(s *string) types.Optional[types.Email] {
	if s == nil || *s == "" {
		return types.None[types.Email]()
	}
	email, err := types.NewEmail(*s)
	if err != nil {
		return types.None[types.Email]()
	}
	return types.Some(email)
}
