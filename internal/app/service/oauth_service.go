package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

// OAuthUserInfo represents user information obtained from an OAuth provider.
type OAuthUserInfo struct {
	ProviderUserID string
	Email          string
	Name           string
	PictureURL     string
}

// OAuthService handles OAuth provider interactions.
type OAuthService interface {
	// GetAuthorizationURL generates the OAuth authorization URL for the provider.
	GetAuthorizationURL(provider model.OAuthProvider, redirectURI string, state string) (string, error)

	// ExchangeCode exchanges an authorization code for user info.
	ExchangeCode(ctx context.Context, provider model.OAuthProvider, code string, redirectURI string) (*OAuthUserInfo, error)

	// GenerateState generates a random state parameter for CSRF protection.
	GenerateState() (string, error)
}

// OAuthConfig holds configuration for OAuth providers.
type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
}

// oauthService implements OAuthService using standard HTTP client.
type oauthService struct {
	config OAuthConfig
	client *http.Client
}

// NewOAuthService creates a new OAuthService.
func NewOAuthService(config OAuthConfig) OAuthService {
	return &oauthService{
		config: config,
		client: &http.Client{},
	}
}

func (s *oauthService) GetAuthorizationURL(provider model.OAuthProvider, redirectURI string, state string) (string, error) {
	switch provider {
	case model.OAuthProviderGoogle:
		return s.googleAuthorizationURL(redirectURI, state), nil
	default:
		return "", fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

func (s *oauthService) ExchangeCode(ctx context.Context, provider model.OAuthProvider, code string, redirectURI string) (*OAuthUserInfo, error) {
	switch provider {
	case model.OAuthProviderGoogle:
		return s.googleExchangeCode(ctx, code, redirectURI)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

func (s *oauthService) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Google OAuth implementation

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleUserURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
)

func (s *oauthService) googleAuthorizationURL(redirectURI string, state string) string {
	params := url.Values{
		"client_id":     {s.config.GoogleClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	return googleAuthURL + "?" + params.Encode()
}

func (s *oauthService) googleExchangeCode(ctx context.Context, code string, redirectURI string) (*OAuthUserInfo, error) {
	// Exchange code for tokens
	data := url.Values{
		"code":          {code},
		"client_id":     {s.config.GoogleClientID},
		"client_secret": {s.config.GoogleClientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Fetch user info
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := s.client.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userResp.Body)
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", userResp.StatusCode, string(body))
	}

	var googleUser struct {
		ID         string `json:"id"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		PictureURL string `json:"picture"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return &OAuthUserInfo{
		ProviderUserID: googleUser.ID,
		Email:          googleUser.Email,
		Name:           googleUser.Name,
		PictureURL:     googleUser.PictureURL,
	}, nil
}
