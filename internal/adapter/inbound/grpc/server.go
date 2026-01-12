package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	pkggrpc "github.com/0xsj/overwatch-pkg/grpc"
	"github.com/0xsj/overwatch-pkg/log"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
)

// ServerConfig holds configuration for the identity gRPC server.
type ServerConfig struct {
	Host              string
	Port              int
	EnableReflection  bool
	EnableHealthCheck bool
}

// Address returns the server address.
func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Server wraps the pkg grpc.Server for the identity service.
type Server struct {
	server  *pkggrpc.Server
	handler *Handler
	logger  log.Logger
}

// NewServer creates a new identity gRPC server.
func NewServer(
	cfg ServerConfig,
	handler *Handler,
	logger log.Logger,
	interceptors ...grpc.UnaryServerInterceptor,
) (*Server, error) {
	opts := []pkggrpc.ServerOption{
		pkggrpc.WithServerAddress(cfg.Address()),
		pkggrpc.WithServerLogger(logger),
		pkggrpc.WithServerReflection(cfg.EnableReflection),
		pkggrpc.WithServerHealthCheck(cfg.EnableHealthCheck),
	}

	if len(interceptors) > 0 {
		opts = append(opts, pkggrpc.WithUnaryInterceptors(interceptors...))
	}

	server, err := pkggrpc.NewServer(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc server: %w", err)
	}

	return &Server{
		server:  server,
		handler: handler,
		logger:  logger,
	}, nil
}

// RegisterServices registers all identity services with the gRPC server.
func (s *Server) RegisterServices() {
	s.server.RegisterService(
		&identityv1.IdentityService_ServiceDesc,
		s.handler,
	)
}

// Start starts the gRPC server.
func (s *Server) Start(ctx context.Context) error {
	s.RegisterServices()
	return s.server.Start(ctx)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Stop(ctx)
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run() error {
	s.RegisterServices()
	return s.server.Run()
}

// GRPCServer returns the underlying grpc.Server.
func (s *Server) GRPCServer() *grpc.Server {
	return s.server.Server()
}

// Address returns the server's listen address.
func (s *Server) Address() string {
	return s.server.Address()
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	return s.server.IsRunning()
}
