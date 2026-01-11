package grpc

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

// ServerConfig holds configuration for the gRPC server.
type ServerConfig struct {
	Host              string
	Port              int
	EnableReflection  bool
	EnableHealthCheck bool
}

// Server wraps the gRPC server.
type Server struct {
	config     ServerConfig
	grpcServer *grpc.Server
	handler    *Handler
	listener   net.Listener
	logger     Logger
}

// NewServer creates a new gRPC server.
func NewServer(
	config ServerConfig,
	handler *Handler,
	interceptors []grpc.UnaryServerInterceptor,
	streamInterceptors []grpc.StreamServerInterceptor,
	logger Logger,
) *Server {
	opts := []grpc.ServerOption{}

	if len(interceptors) > 0 {
		opts = append(opts, grpc.ChainUnaryInterceptor(interceptors...))
	}

	if len(streamInterceptors) > 0 {
		opts = append(opts, grpc.ChainStreamInterceptor(streamInterceptors...))
	}

	grpcServer := grpc.NewServer(opts...)

	return &Server{
		config:     config,
		grpcServer: grpcServer,
		handler:    handler,
		logger:     logger,
	}
}

// Start starts the gRPC server.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	// Register identity service
	identityv1.RegisterIdentityServiceServer(s.grpcServer, s.handler)

	// Register health check service
	if s.config.EnableHealthCheck {
		healthServer := health.NewServer()
		healthServer.SetServingStatus("identity.v1.IdentityService", grpc_health_v1.HealthCheckResponse_SERVING)
		grpc_health_v1.RegisterHealthServer(s.grpcServer, healthServer)
	}

	// Enable reflection for development
	if s.config.EnableReflection {
		reflection.Register(s.grpcServer)
	}

	s.logger.Info("gRPC server starting",
		"address", addr,
		"reflection", s.config.EnableReflection,
		"health_check", s.config.EnableHealthCheck,
	)

	return s.grpcServer.Serve(listener)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("gRPC server stopping")

	stopped := make(chan struct{})

	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("gRPC server force stopping")
		s.grpcServer.Stop()
		return ctx.Err()
	case <-stopped:
		s.logger.Info("gRPC server stopped gracefully")
		return nil
	}
}

// Address returns the server's listening address.
func (s *Server) Address() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// GRPCServer returns the underlying grpc.Server.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}
