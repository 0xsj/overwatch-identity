package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	testPool *pgxpool.Pool
	testNC   *nats.Conn
	testCtx  context.Context

	postgresContainer testcontainers.Container
	natsContainer     testcontainers.Container
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	testCtx = ctx

	// Start PostgreSQL container
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("identity_e2e"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		fmt.Printf("failed to start postgres container: %v\n", err)
		os.Exit(1)
	}
	postgresContainer = pgContainer

	// Get PostgreSQL connection string
	pgConnStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Printf("failed to get postgres connection string: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}

	// Connect to PostgreSQL
	pool, err := pgxpool.New(ctx, pgConnStr)
	if err != nil {
		fmt.Printf("failed to connect to postgres: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}
	testPool = pool

	// Run migrations
	if err := runMigrations(ctx, pool); err != nil {
		fmt.Printf("failed to run migrations: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}

	// Start NATS container
	nContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "nats:2.10-alpine",
			ExposedPorts: []string{"4222/tcp"},
			WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		fmt.Printf("failed to start nats container: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}
	natsContainer = nContainer

	// Get NATS connection URL
	natsHost, err := nContainer.Host(ctx)
	if err != nil {
		fmt.Printf("failed to get nats host: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}
	natsPort, err := nContainer.MappedPort(ctx, "4222")
	if err != nil {
		fmt.Printf("failed to get nats port: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}
	natsURL := fmt.Sprintf("nats://%s:%s", natsHost, natsPort.Port())

	// Connect to NATS
	nc, err := nats.Connect(natsURL,
		nats.Timeout(10*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(5),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		fmt.Printf("failed to connect to nats: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}
	testNC = nc

	// Run tests
	code := m.Run()

	// Cleanup
	cleanup(ctx)

	os.Exit(code)
}

func cleanup(ctx context.Context) {
	if testNC != nil {
		testNC.Close()
	}
	if testPool != nil {
		testPool.Close()
	}
	if natsContainer != nil {
		natsContainer.Terminate(ctx)
	}
	if postgresContainer != nil {
		postgresContainer.Terminate(ctx)
	}
}

// runMigrations executes the schema migrations.
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	migrations := []string{
		createUsersTable,
		createSessionsTable,
		createAPIKeysTable,
		createChallengesTable,
	}

	for _, migration := range migrations {
		if _, err := pool.Exec(ctx, migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

// SQL migrations
const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(26) PRIMARY KEY,
    did VARCHAR(512) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_did ON users(did);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
`

const createSessionsTable = `
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(26) PRIMARY KEY,
    user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_did VARCHAR(512) NOT NULL,
    tenant_id VARCHAR(26),
    refresh_token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`

const createAPIKeysTable = `
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(26) PRIMARY KEY,
    user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    tenant_id VARCHAR(26),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);
`

const createChallengesTable = `
CREATE TABLE IF NOT EXISTS challenges (
    id VARCHAR(26) PRIMARY KEY,
    did VARCHAR(512) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_challenges_did ON challenges(did);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);
`

// --- Accessors ---

func getPool() *pgxpool.Pool {
	return testPool
}

func getConn() *nats.Conn {
	return testNC
}

func getContext() context.Context {
	return testCtx
}

// --- Test Helpers ---

// truncateTables clears all data from tables for test isolation.
func truncateTables(t *testing.T) {
	t.Helper()

	tables := []string{"challenges", "api_keys", "sessions", "users"}
	for _, table := range tables {
		_, err := testPool.Exec(testCtx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		if err != nil {
			t.Fatalf("failed to truncate table %s: %v", table, err)
		}
	}
}

// subscribeAndCollect subscribes to a subject and collects messages.
func subscribeAndCollect(t *testing.T, subject string) (chan *nats.Msg, func()) {
	t.Helper()

	msgChan := make(chan *nats.Msg, 100)

	sub, err := testNC.Subscribe(subject, func(msg *nats.Msg) {
		msgChan <- msg
	})
	if err != nil {
		t.Fatalf("failed to subscribe to %s: %v", subject, err)
	}

	cleanup := func() {
		sub.Unsubscribe()
		close(msgChan)
	}

	return msgChan, cleanup
}

// waitForMessage waits for a message with timeout.
func waitForMessage(t *testing.T, msgChan chan *nats.Msg, timeout time.Duration) *nats.Msg {
	t.Helper()

	select {
	case msg := <-msgChan:
		return msg
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for message")
		return nil
	}
}

// drainMessages drains remaining messages from channel.
func drainMessages(msgChan chan *nats.Msg) []*nats.Msg {
	var messages []*nats.Msg
	for {
		select {
		case msg := <-msgChan:
			messages = append(messages, msg)
		default:
			return messages
		}
	}
}
