package contract

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	testNC  *nats.Conn
	testCtx context.Context
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	testCtx = ctx

	// Start NATS container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "nats:2.10-alpine",
			ExposedPorts: []string{"4222/tcp"},
			WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		fmt.Printf("failed to start NATS container: %v\n", err)
		os.Exit(1)
	}

	// Get connection URL
	host, err := container.Host(ctx)
	if err != nil {
		fmt.Printf("failed to get container host: %v\n", err)
		container.Terminate(ctx)
		os.Exit(1)
	}

	port, err := container.MappedPort(ctx, "4222")
	if err != nil {
		fmt.Printf("failed to get mapped port: %v\n", err)
		container.Terminate(ctx)
		os.Exit(1)
	}

	natsURL := fmt.Sprintf("nats://%s:%s", host, port.Port())

	// Connect to NATS
	nc, err := nats.Connect(natsURL,
		nats.Timeout(10*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(5),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		fmt.Printf("failed to connect to NATS: %v\n", err)
		container.Terminate(ctx)
		os.Exit(1)
	}
	testNC = nc

	// Run tests
	code := m.Run()

	// Cleanup
	nc.Close()
	container.Terminate(ctx)

	os.Exit(code)
}

// getConn returns the test NATS connection.
func getConn() *nats.Conn {
	return testNC
}

// getContext returns the test context.
func getContext() context.Context {
	return testCtx
}

// subscribeAndCollect subscribes to a subject and collects messages.
// Returns a channel that receives messages and a cleanup function.
func subscribeAndCollect(t *testing.T, subject string) (chan *nats.Msg, func()) {
	t.Helper()

	msgChan := make(chan *nats.Msg, 10)

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

// waitForMessage waits for a message on the channel with timeout.
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

// waitForMessageCount waits for n messages on the channel with timeout.
func waitForMessageCount(t *testing.T, msgChan chan *nats.Msg, count int, timeout time.Duration) []*nats.Msg {
	t.Helper()

	messages := make([]*nats.Msg, 0, count)
	deadline := time.After(timeout)

	for len(messages) < count {
		select {
		case msg := <-msgChan:
			messages = append(messages, msg)
		case <-deadline:
			t.Fatalf("timeout waiting for %d messages, got %d", count, len(messages))
			return nil
		}
	}

	return messages
}

// assertNoMessage asserts that no message is received within the timeout.
func assertNoMessage(t *testing.T, msgChan chan *nats.Msg, timeout time.Duration) {
	t.Helper()

	select {
	case msg := <-msgChan:
		t.Fatalf("unexpected message received: %s", string(msg.Data))
	case <-time.After(timeout):
		// Expected - no message
	}
}
