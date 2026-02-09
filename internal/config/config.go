package config

import (
	"fmt"
	"time"

	config "github.com/0xsj/overwatch-pkg/config"
)

// Config holds all configuration for the identity service.
type Config struct {
	Server          ServerConfig
	Database        DatabaseConfig
	Redis           RedisConfig
	NATS            NATSConfig
	Token           TokenConfig
	OAuth           OAuthConfig
	ServiceIdentity ServiceIdentityConfig
}

// OAuthConfig holds OAuth provider configuration.
type OAuthConfig struct {
	GoogleClientID     string `env:"OAUTH_GOOGLE_CLIENT_ID" default:""`
	GoogleClientSecret string `env:"OAUTH_GOOGLE_CLIENT_SECRET" default:"" sensitive:"true"`
}

// ServerConfig holds gRPC server configuration.
type ServerConfig struct {
	Host              string        `env:"SERVER_HOST" default:"0.0.0.0"`
	Port              int           `env:"SERVER_PORT" default:"50051"`
	EnableReflection  bool          `env:"SERVER_ENABLE_REFLECTION" default:"true"`
	EnableHealthCheck bool          `env:"SERVER_ENABLE_HEALTH_CHECK" default:"true"`
	ShutdownTimeout   time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT" default:"30s"`
}

// DatabaseConfig holds PostgreSQL configuration.
type DatabaseConfig struct {
	Host              string        `env:"DATABASE_HOST" default:"localhost"`
	Port              int           `env:"DATABASE_PORT" default:"5450"`
	User              string        `env:"DATABASE_USER" default:"overwatch"`
	Password          string        `env:"DATABASE_PASSWORD" default:"overwatch" sensitive:"true"`
	Database          string        `env:"DATABASE_NAME" default:"overwatch_identity"`
	SSLMode           string        `env:"DATABASE_SSL_MODE" default:"disable"`
	MaxConns          int           `env:"DATABASE_MAX_CONNS" default:"25"`
	MinConns          int           `env:"DATABASE_MIN_CONNS" default:"5"`
	MaxConnLifetime   time.Duration `env:"DATABASE_MAX_CONN_LIFETIME" default:"1h"`
	MaxConnIdleTime   time.Duration `env:"DATABASE_MAX_CONN_IDLE_TIME" default:"30m"`
	HealthCheckPeriod time.Duration `env:"DATABASE_HEALTH_CHECK_PERIOD" default:"1m"`
}

// RedisConfig holds Redis configuration.
type RedisConfig struct {
	Host         string        `env:"REDIS_HOST" default:"localhost"`
	Port         int           `env:"REDIS_PORT" default:"6390"`
	Password     string        `env:"REDIS_PASSWORD" default:"" sensitive:"true"`
	DB           int           `env:"REDIS_DB" default:"0"`
	PoolSize     int           `env:"REDIS_POOL_SIZE" default:"10"`
	MinIdleConns int           `env:"REDIS_MIN_IDLE_CONNS" default:"5"`
	DialTimeout  time.Duration `env:"REDIS_DIAL_TIMEOUT" default:"5s"`
	ReadTimeout  time.Duration `env:"REDIS_READ_TIMEOUT" default:"3s"`
	WriteTimeout time.Duration `env:"REDIS_WRITE_TIMEOUT" default:"3s"`
}

// NATSConfig holds NATS configuration.
type NATSConfig struct {
	URL           string        `env:"NATS_URL" default:"nats://localhost:4230"`
	SubjectPrefix string        `env:"NATS_SUBJECT_PREFIX" default:"overwatch"`
	MaxReconnects int           `env:"NATS_MAX_RECONNECTS" default:"10"`
	ReconnectWait time.Duration `env:"NATS_RECONNECT_WAIT" default:"2s"`
}

// TokenConfig holds JWT token configuration.
type TokenConfig struct {
	Issuer               string        `env:"TOKEN_ISSUER" default:"overwatch-identity"`
	Audience             string        `env:"TOKEN_AUDIENCE" default:"overwatch"`
	AccessTokenDuration  time.Duration `env:"TOKEN_ACCESS_DURATION" default:"24h"`
	RefreshTokenDuration time.Duration `env:"TOKEN_REFRESH_DURATION" default:"168h"`
	SigningKey           string        `env:"TOKEN_SIGNING_KEY" required:"true" sensitive:"true"`
}

// ServiceIdentityConfig holds service identity configuration.
type ServiceIdentityConfig struct {
	ID                string `env:"SERVICE_IDENTITY_ID" default:"identity-service"`
	Name              string `env:"SERVICE_IDENTITY_NAME" default:"identity"`
	PrivateKeyPath    string `env:"SERVICE_IDENTITY_PRIVATE_KEY_PATH" default:""`
	PrivateKeyBase64  string `env:"SERVICE_IDENTITY_PRIVATE_KEY" default:"" sensitive:"true"`
	GenerateIfMissing bool   `env:"SERVICE_IDENTITY_GENERATE_IF_MISSING" default:"true"`
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := config.Load(cfg, config.WithPrefix("IDENTITY_")); err != nil {
		return nil, err
	}
	return cfg, nil
}

// MustLoad loads configuration and panics on error.
func MustLoad() *Config {
	cfg := &Config{}
	config.MustLoad(cfg, config.WithPrefix("IDENTITY_"))
	return cfg
}

// Address returns the gRPC server address.
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// ConnectionString returns the PostgreSQL connection string.
func (c *DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// Address returns the Redis address.
func (c *RedisConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// HasPrivateKey returns true if a private key is configured.
func (c *ServiceIdentityConfig) HasPrivateKey() bool {
	return c.PrivateKeyBase64 != "" || c.PrivateKeyPath != ""
}
