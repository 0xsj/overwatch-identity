package command

import (
	"context"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	domainerror "github.com/0xsj/overwatch-identity/internal/domain/error"
	"github.com/0xsj/overwatch-identity/internal/domain/event"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/inbound/command"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/messaging"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"

	"github.com/0xsj/overwatch-identity/internal/app/service"
)

type authenticateWithOAuthHandler struct {
	userRepo      repository.UserRepository
	sessionRepo   repository.SessionRepository
	oauthRepo     repository.OAuthIdentityRepository
	tokenService  service.TokenService
	oauthService  service.OAuthService
	publisher     messaging.EventPublisher
	sessionConfig model.SessionConfig
}

func NewAuthenticateWithOAuthHandler(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	oauthRepo repository.OAuthIdentityRepository,
	tokenService service.TokenService,
	oauthService service.OAuthService,
	publisher messaging.EventPublisher,
	sessionConfig model.SessionConfig,
) command.AuthenticateWithOAuthHandler {
	return &authenticateWithOAuthHandler{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		oauthRepo:     oauthRepo,
		tokenService:  tokenService,
		oauthService:  oauthService,
		publisher:     publisher,
		sessionConfig: sessionConfig,
	}
}

func (h *authenticateWithOAuthHandler) Handle(ctx context.Context, cmd command.AuthenticateWithOAuth) (command.AuthenticateWithOAuthResult, error) {
	// 1. Exchange authorization code for user info
	userInfo, err := h.oauthService.ExchangeCode(ctx, cmd.Provider, cmd.Code, cmd.RedirectURI)
	if err != nil {
		return command.AuthenticateWithOAuthResult{}, domainerror.ErrOAuthCodeExchangeFailed
	}

	// 2. Look up existing OAuth identity
	existingOAuth, err := h.oauthRepo.FindByProviderAndProviderUserID(ctx, cmd.Provider, userInfo.ProviderUserID)

	isNewUser := false
	var user *model.User

	if err == nil && existingOAuth != nil {
		// Existing OAuth identity found — load user
		user, err = h.userRepo.FindByID(ctx, existingOAuth.UserID())
		if err != nil {
			return command.AuthenticateWithOAuthResult{}, domainerror.ErrUserNotFound
		}
	} else {
		// No existing OAuth identity — check for email collision
		if userInfo.Email != "" {
			existingUser, emailErr := h.userRepo.FindByEmail(ctx, types.Email(userInfo.Email))
			if emailErr == nil && existingUser != nil {
				return command.AuthenticateWithOAuthResult{}, domainerror.ErrOAuthEmailCollision
			}
		}

		// Create synthetic DID for the OAuth user
		syntheticDIDStr := model.SyntheticDIDForOAuth(cmd.Provider, userInfo.ProviderUserID)
		syntheticDID, parseErr := security.ParseDID(syntheticDIDStr)
		if parseErr != nil {
			return command.AuthenticateWithOAuthResult{}, parseErr
		}

		// Create new user
		user, err = model.NewUser(syntheticDID)
		if err != nil {
			return command.AuthenticateWithOAuthResult{}, err
		}

		// Set email and name from OAuth
		if userInfo.Email != "" {
			email, emailErr := types.NewEmail(userInfo.Email)
			if emailErr == nil {
				user.SetEmail(email)
			}
		}
		if userInfo.Name != "" {
			user.SetName(userInfo.Name)
		}

		// Persist user
		if err := h.userRepo.Create(ctx, user); err != nil {
			return command.AuthenticateWithOAuthResult{}, err
		}

		// Create OAuth identity record
		oauthIdentity, oauthErr := model.NewOAuthIdentity(
			user.ID(),
			cmd.Provider,
			userInfo.ProviderUserID,
			userInfo.Email,
			optionalString(userInfo.Name),
			optionalString(userInfo.PictureURL),
		)
		if oauthErr != nil {
			return command.AuthenticateWithOAuthResult{}, oauthErr
		}

		if err := h.oauthRepo.Create(ctx, oauthIdentity); err != nil {
			return command.AuthenticateWithOAuthResult{}, err
		}

		isNewUser = true

		// Publish registration + OAuth linked events
		regEvents := []event.Event{
			event.NewUserRegistered(
				user.ID(),
				user.DID().String(),
				optionalEmailString(user.Email()),
				user.Name(),
			),
			event.NewOAuthLinked(
				user.ID(),
				string(cmd.Provider),
				userInfo.ProviderUserID,
				userInfo.Email,
			),
		}
		_ = h.publisher.PublishAll(ctx, regEvents)
	}

	// 3. Check if user can authenticate
	if err := user.CanAuthenticate(); err != nil {
		return command.AuthenticateWithOAuthResult{}, err
	}

	// 4. Generate refresh token
	refreshToken, refreshTokenHash, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		return command.AuthenticateWithOAuthResult{}, err
	}

	// 5. Create session
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		cmd.TenantID,
		refreshTokenHash,
		h.sessionConfig,
	)
	if err != nil {
		return command.AuthenticateWithOAuthResult{}, err
	}

	if err := h.sessionRepo.Create(ctx, session); err != nil {
		return command.AuthenticateWithOAuthResult{}, err
	}

	// 6. Generate access token
	accessToken, accessTokenExpiresAt, err := h.tokenService.GenerateAccessToken(user, session)
	if err != nil {
		return command.AuthenticateWithOAuthResult{}, err
	}

	// 7. Publish session + auth events
	authEvents := []event.Event{
		event.NewSessionCreated(
			session.ID(),
			user.ID(),
			user.DID().String(),
			cmd.TenantID,
		),
		event.NewAuthenticationSucceeded(
			user.ID(),
			user.DID().String(),
			session.ID(),
			event.AuthMethodOAuthGoogle,
		),
	}
	_ = h.publisher.PublishAll(ctx, authEvents)

	return command.AuthenticateWithOAuthResult{
		User:                 user,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenExpiresAt: accessTokenExpiresAt,
		IsNewUser:            isNewUser,
	}, nil
}

func optionalString(s string) types.Optional[string] {
	if s == "" {
		return types.None[string]()
	}
	return types.Some(s)
}

func optionalEmailString(email types.Optional[types.Email]) types.Optional[string] {
	if email.IsPresent() {
		return types.Some(string(email.MustGet()))
	}
	return types.None[string]()
}
