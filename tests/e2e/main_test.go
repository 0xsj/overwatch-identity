//go:build e2e

package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

var (
	client identityv1.IdentityServiceClient
	conn   *grpc.ClientConn
)

func TestMain(m *testing.M) {
	addr := os.Getenv("IDENTITY_GRPC_ADDR")
	if addr == "" {
		addr = "localhost:50051"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	conn, err = grpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		panic("failed to connect to identity service at " + addr + ": " + err.Error())
	}

	client = identityv1.NewIdentityServiceClient(conn)

	// Verify service is responding
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()

	_, err = client.Ping(pingCtx, &identityv1.PingRequest{})
	if err != nil {
		conn.Close()
		panic("identity service not responding: " + err.Error())
	}

	code := m.Run()

	conn.Close()
	os.Exit(code)
}
