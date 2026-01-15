package service

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/0xsj/overwatch-pkg/provenance"
	"github.com/0xsj/overwatch-pkg/security"

	"github.com/0xsj/overwatch-identity/internal/config"
)

// ServiceIdentityManager manages the service's cryptographic identity.
type ServiceIdentityManager struct {
	identity *provenance.ServiceIdentity
	signer   provenance.Signer
}

// NewServiceIdentityManager creates a new service identity manager from config.
func NewServiceIdentityManager(cfg config.ServiceIdentityConfig) (*ServiceIdentityManager, error) {
	var identity *provenance.ServiceIdentity
	var err error

	// Priority: Base64 key > File path > Generate
	if cfg.PrivateKeyBase64 != "" {
		identity, err = loadIdentityFromBase64(cfg.ID, cfg.Name, cfg.PrivateKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity from base64: %w", err)
		}
	} else if cfg.PrivateKeyPath != "" {
		identity, err = loadIdentityFromFile(cfg.ID, cfg.Name, cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity from file: %w", err)
		}
	} else if cfg.GenerateIfMissing {
		identity, err = provenance.GenerateServiceIdentity(cfg.ID, cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to generate identity: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no service identity configured and generation disabled")
	}

	signer, err := provenance.NewSigner(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &ServiceIdentityManager{
		identity: identity,
		signer:   signer,
	}, nil
}

// Identity returns the service identity.
func (m *ServiceIdentityManager) Identity() *provenance.ServiceIdentity {
	return m.identity
}

// Signer returns the signer for this service.
func (m *ServiceIdentityManager) Signer() provenance.Signer {
	return m.signer
}

// DID returns the service's DID string.
func (m *ServiceIdentityManager) DID() string {
	return m.identity.DID()
}

// ServiceName returns the service name.
func (m *ServiceIdentityManager) ServiceName() string {
	return m.identity.ServiceName()
}

// PublicKeyBase64 returns the base64-encoded public key.
func (m *ServiceIdentityManager) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(m.identity.PublicKey())
}

// loadIdentityFromBase64 loads a service identity from a base64-encoded private key.
func loadIdentityFromBase64(id, name, keyBase64 string) (*provenance.ServiceIdentity, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	keyPair, err := security.NewEd25519FromSeed(keyBytes)
	if err != nil {
		// Try loading as full private key (64 bytes)
		keyPair, err = security.NewEd25519FromPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid Ed25519 key: %w", err)
		}
	}

	return provenance.NewServiceIdentity(id, name, keyPair)
}

// loadIdentityFromFile loads a service identity from a private key file.
func loadIdentityFromFile(id, name, path string) (*provenance.ServiceIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Try base64 first (common format)
	keyBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		// Assume raw bytes
		keyBytes = data
	}

	keyPair, err := security.NewEd25519FromSeed(keyBytes)
	if err != nil {
		keyPair, err = security.NewEd25519FromPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid Ed25519 key in file: %w", err)
		}
	}

	return provenance.NewServiceIdentity(id, name, keyPair)
}

// GenerateAndPrintKey is a helper for generating a new key and printing it.
// Useful for initial setup.
func GenerateAndPrintKey(serviceName string) error {
	identity, err := provenance.GenerateServiceIdentity("temp", serviceName)
	if err != nil {
		return err
	}

	fmt.Printf("Service: %s\n", serviceName)
	fmt.Printf("DID: %s\n", identity.DID())
	fmt.Printf("Public Key (base64): %s\n", base64.StdEncoding.EncodeToString(identity.PublicKey()))
	fmt.Println("\nAdd this to your environment:")
	fmt.Printf("SERVICE_IDENTITY_PRIVATE_KEY=<your-private-key-base64>\n")

	return nil
}
