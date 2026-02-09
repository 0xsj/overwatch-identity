package model

import (
	"fmt"

	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
)

// OAuthProvider represents a supported OAuth provider.
type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
)

func (p OAuthProvider) String() string {
	return string(p)
}

func (p OAuthProvider) IsValid() bool {
	switch p {
	case OAuthProviderGoogle:
		return true
	default:
		return false
	}
}

// OAuthIdentity represents a linked OAuth provider for a user.
type OAuthIdentity struct {
	id             types.ID
	userID         types.ID
	provider       OAuthProvider
	providerUserID string
	email          string
	name           types.Optional[string]
	pictureURL     types.Optional[string]
	createdAt      types.Timestamp
	updatedAt      types.Timestamp
}

// NewOAuthIdentity creates a new OAuthIdentity.
func NewOAuthIdentity(
	userID types.ID,
	provider OAuthProvider,
	providerUserID string,
	email string,
	name types.Optional[string],
	pictureURL types.Optional[string],
) (*OAuthIdentity, error) {
	if userID.IsEmpty() {
		return nil, domainerror.ErrUserIDRequired
	}
	if !provider.IsValid() {
		return nil, domainerror.ErrOAuthProviderInvalid
	}
	if providerUserID == "" {
		return nil, domainerror.ErrOAuthProviderUserIDRequired
	}
	if email == "" {
		return nil, domainerror.ErrOAuthEmailRequired
	}

	now := types.Now()

	return &OAuthIdentity{
		id:             types.NewID(),
		userID:         userID,
		provider:       provider,
		providerUserID: providerUserID,
		email:          email,
		name:           name,
		pictureURL:     pictureURL,
		createdAt:      now,
		updatedAt:      now,
	}, nil
}

// ReconstructOAuthIdentity creates an OAuthIdentity from persisted data.
func ReconstructOAuthIdentity(
	id types.ID,
	userID types.ID,
	provider OAuthProvider,
	providerUserID string,
	email string,
	name types.Optional[string],
	pictureURL types.Optional[string],
	createdAt types.Timestamp,
	updatedAt types.Timestamp,
) *OAuthIdentity {
	return &OAuthIdentity{
		id:             id,
		userID:         userID,
		provider:       provider,
		providerUserID: providerUserID,
		email:          email,
		name:           name,
		pictureURL:     pictureURL,
		createdAt:      createdAt,
		updatedAt:      updatedAt,
	}
}

// Getters

func (o *OAuthIdentity) ID() types.ID                       { return o.id }
func (o *OAuthIdentity) UserID() types.ID                   { return o.userID }
func (o *OAuthIdentity) Provider() OAuthProvider            { return o.provider }
func (o *OAuthIdentity) ProviderUserID() string             { return o.providerUserID }
func (o *OAuthIdentity) Email() string                      { return o.email }
func (o *OAuthIdentity) Name() types.Optional[string]       { return o.name }
func (o *OAuthIdentity) PictureURL() types.Optional[string] { return o.pictureURL }
func (o *OAuthIdentity) CreatedAt() types.Timestamp         { return o.createdAt }
func (o *OAuthIdentity) UpdatedAt() types.Timestamp         { return o.updatedAt }

// SyntheticDID generates a deterministic DID for an OAuth user.
// Format: did:web:oauth.overwatch:{provider}:{provider_user_id}
func SyntheticDIDForOAuth(provider OAuthProvider, providerUserID string) string {
	return fmt.Sprintf("did:web:oauth.overwatch:%s:%s", provider, providerUserID)
}
