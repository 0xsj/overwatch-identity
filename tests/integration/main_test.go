package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	testRedisClient *redis.Client
	testCtx         context.Context

	redisContainer testcontainers.Container
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	testCtx = ctx

	// Start Redis container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		fmt.Printf("failed to start redis container: %v\n", err)
		os.Exit(1)
	}
	redisContainer = container

	// Get connection details
	host, err := container.Host(ctx)
	if err != nil {
		fmt.Printf("failed to get redis host: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		fmt.Printf("failed to get redis port: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}

	// Create Redis client
	testRedisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port.Port()),
		Password: "",
		DB:       0,
	})

	// Verify connection
	if err := testRedisClient.Ping(ctx).Err(); err != nil {
		fmt.Printf("failed to connect to redis: %v\n", err)
		cleanup(ctx)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	cleanup(ctx)

	os.Exit(code)
}

func cleanup(ctx context.Context) {
	if testRedisClient != nil {
		testRedisClient.Close()
	}
	if redisContainer != nil {
		redisContainer.Terminate(ctx)
	}
}

// --- Accessors ---

func getRedisClient() *redis.Client {
	return testRedisClient
}

func getContext() context.Context {
	return testCtx
}

// --- Test Helpers ---

// flushRedis clears all data for test isolation.
func flushRedis(t *testing.T) {
	t.Helper()
	if err := testRedisClient.FlushDB(testCtx).Err(); err != nil {
		t.Fatalf("failed to flush redis: %v", err)
	}
}
