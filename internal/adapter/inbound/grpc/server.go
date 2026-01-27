package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	pkggrpc "github.com/0xsj/overwatch-pkg/grpc"
	"github.com/0xsj/overwatch-pkg/log"

	identityv1 "github.com/0xsj/overwatch-contracts/gen/go/identity/v1"
	"github.com/0xsj/overwatch-identity/internal/app/service"
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

// Validate validates the server configuration.
func (c ServerConfig) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	return nil
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
	tokenService service.TokenService,
	logger log.Logger,
) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid server config: %w", err)
	}

	// Build interceptor chains with correct order
	unaryInterceptors := BuildUnaryInterceptors(logger, tokenService)
	streamInterceptors := BuildStreamInterceptors(logger, tokenService)

	// Create server with options
	server, err := pkggrpc.NewServer(
		pkggrpc.WithServerAddress(cfg.Address()),
		pkggrpc.WithServerLogger(logger),
		pkggrpc.WithServerReflection(cfg.EnableReflection),
		pkggrpc.WithServerHealthCheck(cfg.EnableHealthCheck),
		pkggrpc.WithUnaryInterceptors(unaryInterceptors...),
		pkggrpc.WithStreamInterceptors(streamInterceptors...),
	)
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
	s.logger.Info("starting identity gRPC server",
		log.String("address", s.server.Address()),
	)
	return s.server.Start(ctx)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("stopping identity gRPC server")
	return s.server.Stop(ctx)
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run() error {
	s.RegisterServices()
	s.logger.Info("running identity gRPC server",
		log.String("address", s.server.Address()),
	)
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

// SetServingStatus sets the serving status for health checks.
func (s *Server) SetServingStatus(service string, serving bool) {
	s.server.SetServingStatus(service, serving)
}
