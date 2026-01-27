package service_test

import (
	"testing"
	"time"

	"github.com/0xsj/overwatch-pkg/security"
	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/app/service"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func TestNewTokenService(t *testing.T) {
	t.Run("creates service with valid config", func(t *testing.T) {
		cfg := validTokenConfig()
		svc, err := service.NewTokenService(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})

	t.Run("rejects empty signing key", func(t *testing.T) {
		cfg := validTokenConfig()
		cfg.SigningKey = nil

		_, err := service.NewTokenService(cfg)
		if err == nil {
			t.Fatal("expected error for empty signing key")
		}
	})
}

func TestTokenService_GenerateAccessToken(t *testing.T) {
	svc := mustNewTokenService(t)
	user := mustCreateUser(t)
	session := mustCreateSession(t, user)

	t.Run("generates valid access token", func(t *testing.T) {
		token, expiresAt, err := svc.GenerateAccessToken(user, session)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if token == "" {
			t.Error("expected non-empty token")
		}
		if expiresAt.IsZero() {
			t.Error("expected non-zero expiration time")
		}
		if !expiresAt.After(types.Now()) {
			t.Error("expiration should be in the future")
		}
	})

	t.Run("token contains correct claims", func(t *testing.T) {
		token, _, err := svc.GenerateAccessToken(user, session)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Validate and extract claims
		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			t.Fatalf("failed to validate generated token: %v", err)
		}

		if claims.UserID != user.ID() {
			t.Errorf("UserID mismatch: got %s, want %s", claims.UserID, user.ID())
		}
		if claims.DID != user.DID().String() {
			t.Errorf("DID mismatch: got %s, want %s", claims.DID, user.DID().String())
		}
		if claims.SessionID != session.ID() {
			t.Errorf("SessionID mismatch: got %s, want %s", claims.SessionID, session.ID())
		}
	})

	t.Run("token includes tenant when present", func(t *testing.T) {
		tenantID := types.NewID()
		sessionWithTenant := mustCreateSessionWithTenant(t, user, tenantID)

		token, _, err := svc.GenerateAccessToken(user, sessionWithTenant)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		if !claims.TenantID.IsPresent() {
			t.Fatal("expected TenantID to be present")
		}
		if claims.TenantID.MustGet() != tenantID {
			t.Errorf("TenantID mismatch: got %s, want %s", claims.TenantID.MustGet(), tenantID)
		}
	})

	t.Run("token without tenant has empty optional", func(t *testing.T) {
		token, _, err := svc.GenerateAccessToken(user, session)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		if claims.TenantID.IsPresent() {
			t.Error("expected TenantID to be absent")
		}
	})
}

func TestTokenService_ValidateAccessToken(t *testing.T) {
	svc := mustNewTokenService(t)
	user := mustCreateUser(t)
	session := mustCreateSession(t, user)

	t.Run("validates legitimate token", func(t *testing.T) {
		token, _, _ := svc.GenerateAccessToken(user, session)

		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims == nil {
			t.Fatal("expected non-nil claims")
		}
	})

	t.Run("rejects empty token", func(t *testing.T) {
		_, err := svc.ValidateAccessToken("")
		if err == nil {
			t.Fatal("expected error for empty token")
		}
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		_, err := svc.ValidateAccessToken("not.a.valid.jwt")
		if err == nil {
			t.Fatal("expected error for malformed token")
		}
	})

	t.Run("rejects token with invalid signature", func(t *testing.T) {
		// Create token with different signing key
		otherCfg := validTokenConfig()
		otherCfg.SigningKey = []byte("different-secret-key-for-testing")
		otherSvc, _ := service.NewTokenService(otherCfg)

		token, _, _ := otherSvc.GenerateAccessToken(user, session)

		// Try to validate with original service (different key)
		_, err := svc.ValidateAccessToken(token)
		if err == nil {
			t.Fatal("expected error for token signed with different key")
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Create service with very short token duration
		cfg := validTokenConfig()
		cfg.AccessTokenDuration = 1 * time.Millisecond
		shortSvc, _ := service.NewTokenService(cfg)

		token, _, _ := shortSvc.GenerateAccessToken(user, session)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		_, err := shortSvc.ValidateAccessToken(token)
		if err == nil {
			t.Fatal("expected error for expired token")
		}
	})

	t.Run("rejects token with wrong issuer", func(t *testing.T) {
		// Create token with different issuer
		otherCfg := validTokenConfig()
		otherCfg.Issuer = "wrong-issuer"
		otherSvc, _ := service.NewTokenService(otherCfg)

		token, _, _ := otherSvc.GenerateAccessToken(user, session)

		// Original service expects different issuer
		_, err := svc.ValidateAccessToken(token)
		if err == nil {
			t.Fatal("expected error for token with wrong issuer")
		}
	})

	t.Run("rejects token with wrong audience", func(t *testing.T) {
		// Create token with different audience
		otherCfg := validTokenConfig()
		otherCfg.Audience = "wrong-audience"
		otherSvc, _ := service.NewTokenService(otherCfg)

		token, _, _ := otherSvc.GenerateAccessToken(user, session)

		// Original service expects different audience
		_, err := svc.ValidateAccessToken(token)
		if err == nil {
			t.Fatal("expected error for token with wrong audience")
		}
	})
}

func TestTokenService_GenerateRefreshToken(t *testing.T) {
	svc := mustNewTokenService(t)

	t.Run("generates token and hash", func(t *testing.T) {
		token, hash, err := svc.GenerateRefreshToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if token == "" {
			t.Error("expected non-empty token")
		}
		if hash == "" {
			t.Error("expected non-empty hash")
		}
		if token == hash {
			t.Error("token and hash should be different")
		}
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		token1, _, _ := svc.GenerateRefreshToken()
		token2, _, _ := svc.GenerateRefreshToken()

		if token1 == token2 {
			t.Error("consecutive tokens should be unique")
		}
	})

	t.Run("hash is deterministic for same token", func(t *testing.T) {
		token, hash1, _ := svc.GenerateRefreshToken()
		hash2 := svc.HashRefreshToken(token)

		if hash1 != hash2 {
			t.Error("hash should be deterministic")
		}
	})
}

func TestTokenService_HashRefreshToken(t *testing.T) {
	svc := mustNewTokenService(t)

	t.Run("produces consistent hash", func(t *testing.T) {
		token := "test-refresh-token"
		hash1 := svc.HashRefreshToken(token)
		hash2 := svc.HashRefreshToken(token)

		if hash1 != hash2 {
			t.Error("same token should produce same hash")
		}
	})

	t.Run("different tokens produce different hashes", func(t *testing.T) {
		hash1 := svc.HashRefreshToken("token-1")
		hash2 := svc.HashRefreshToken("token-2")

		if hash1 == hash2 {
			t.Error("different tokens should produce different hashes")
		}
	})

	t.Run("hash is not reversible", func(t *testing.T) {
		token := "secret-refresh-token"
		hash := svc.HashRefreshToken(token)

		// Hash should not contain the original token
		if hash == token {
			t.Error("hash should not equal original token")
		}
		if len(hash) < 32 {
			t.Error("hash should be sufficiently long")
		}
	})
}

// Test helpers

func validTokenConfig() service.TokenConfig {
	return service.TokenConfig{
		Issuer:               "overwatch-identity-test",
		Audience:             "overwatch-test",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		SigningKey:           []byte("test-signing-key-at-least-32-bytes-long"),
	}
}

func mustNewTokenService(t *testing.T) service.TokenService {
	t.Helper()
	svc, err := service.NewTokenService(validTokenConfig())
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}
	return svc
}

func mustGenerateEd25519(t *testing.T) security.KeyPair {
	t.Helper()
	kp, err := security.GenerateEd25519()
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}
	return kp
}

func mustDIDFromKeyPair(t *testing.T, kp security.KeyPair) *security.DID {
	t.Helper()
	did, err := security.DIDFromKeyPair(kp)
	if err != nil {
		t.Fatalf("failed to create DID from keypair: %v", err)
	}
	return did
}

func mustCreateUser(t *testing.T) *model.User {
	t.Helper()
	kp := mustGenerateEd25519(t)
	did := mustDIDFromKeyPair(t, kp)

	user, err := model.NewUser(did)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func mustCreateSession(t *testing.T, user *model.User) *model.Session {
	t.Helper()
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		types.None[types.ID](), // no tenant
		"refresh-token-hash",
		model.DefaultSessionConfig(),
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	return session
}

func mustCreateSessionWithTenant(t *testing.T, user *model.User, tenantID types.ID) *model.Session {
	t.Helper()
	session, err := model.NewSession(
		user.ID(),
		user.DID(),
		types.Some(tenantID),
		"refresh-token-hash",
		model.DefaultSessionConfig(),
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	return session
}
