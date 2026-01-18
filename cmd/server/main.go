package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	natsclient "github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/0xsj/overwatch-pkg/log"

	identitygrpc "github.com/0xsj/overwatch-identity/internal/adapter/inbound/grpc"
	natsadapter "github.com/0xsj/overwatch-identity/internal/adapter/outbound/nats"
	"github.com/0xsj/overwatch-identity/internal/adapter/outbound/postgres"
	rediscache "github.com/0xsj/overwatch-identity/internal/adapter/outbound/redis"
	"github.com/0xsj/overwatch-identity/internal/app/command"
	"github.com/0xsj/overwatch-identity/internal/app/query"
	"github.com/0xsj/overwatch-identity/internal/app/service"
	"github.com/0xsj/overwatch-identity/internal/config"
	"github.com/0xsj/overwatch-identity/internal/domain/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger := log.NewPretty(log.DefaultConfig())

	logger.Info("starting identity service",
		log.String("version", "1.0.0"),
		log.String("address", cfg.Server.Address()),
	)

	// Initialize service identity
	identityManager, err := service.NewServiceIdentityManager(cfg.ServiceIdentity)
	if err != nil {
		return fmt.Errorf("failed to initialize service identity: %w", err)
	}

	logger.Info("service identity initialized",
		log.String("service_id", cfg.ServiceIdentity.ID),
		log.String("service_name", cfg.ServiceIdentity.Name),
		log.String("did", identityManager.DID()),
	)

	// Connect to PostgreSQL
	pool, err := connectPostgres(ctx, cfg.Database, logger)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	defer pool.Close()

	// Connect to Redis
	redisClient, err := connectRedis(ctx, cfg.Redis, logger)
	if err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}
	defer redisClient.Close()

	// Connect to NATS
	natsConn, err := connectNATS(cfg.NATS, logger)
	if err != nil {
		return fmt.Errorf("failed to connect to nats: %w", err)
	}
	defer natsConn.Close()

	// Initialize repositories
	userRepo := postgres.NewUserRepository(pool)
	sessionRepo := postgres.NewSessionRepository(pool)
	apiKeyRepo := postgres.NewAPIKeyRepository(pool)
	challengeRepo := postgres.NewChallengeRepository(pool)

	// Initialize caches
	userCache := rediscache.NewUserCache(redisClient, time.Hour)
	sessionCache := rediscache.NewSessionCache(redisClient, 24*time.Hour)
	tokenBlacklist := rediscache.NewTokenBlacklist(redisClient)

	// Initialize event publisher with signing
	eventPublisher, err := natsadapter.NewSignedEventPublisher(
		natsConn,
		cfg.NATS.SubjectPrefix,
		identityManager.Identity(),
	)
	if err != nil {
		return fmt.Errorf("failed to create event publisher: %w", err)
	}

	// Initialize token service
	tokenService, err := service.NewTokenService(service.TokenConfig{
		Issuer:               cfg.Token.Issuer,
		Audience:             cfg.Token.Audience,
		AccessTokenDuration:  cfg.Token.AccessTokenDuration,
		RefreshTokenDuration: cfg.Token.RefreshTokenDuration,
		SigningKey:           []byte(cfg.Token.SigningKey),
	})
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	// Configuration for domain models
	challengeConfig := model.DefaultChallengeConfig()
	sessionConfig := model.DefaultSessionConfig()
	domain := cfg.Token.Issuer

	// Initialize command handlers
	registerUserHandler := command.NewRegisterUserHandler(
		userRepo,
		challengeRepo,
		challengeConfig,
	)
	verifyRegistrationHandler := command.NewVerifyRegistrationHandler(
		userRepo,
		sessionRepo,
		challengeRepo,
		tokenService,
		eventPublisher,
		domain,
		sessionConfig,
	)
	authenticateHandler := command.NewAuthenticateHandler(
		userRepo,
		challengeRepo,
		challengeConfig,
	)
	verifyAuthenticationHandler := command.NewVerifyAuthenticationHandler(
		userRepo,
		sessionRepo,
		challengeRepo,
		tokenService,
		eventPublisher,
		domain,
		sessionConfig,
	)
	refreshTokenHandler := command.NewRefreshTokenHandler(
		userRepo,
		sessionRepo,
		tokenService,
		eventPublisher,
		sessionConfig,
	)
	revokeTokenHandler := command.NewRevokeTokenHandler(
		sessionRepo,
		sessionCache,
		tokenService,
		eventPublisher,
	)
	revokeSessionHandler := command.NewRevokeSessionHandler(
		sessionRepo,
		sessionCache,
		eventPublisher,
	)
	revokeAllSessionsHandler := command.NewRevokeAllSessionsHandler(
		sessionRepo,
		sessionCache,
		eventPublisher,
	)
	createAPIKeyHandler := command.NewCreateAPIKeyHandler(
		userRepo,
		apiKeyRepo,
		eventPublisher,
	)
	revokeAPIKeyHandler := command.NewRevokeAPIKeyHandler(
		apiKeyRepo,
		eventPublisher,
	)
	updateUserHandler := command.NewUpdateUserHandler(
		userRepo,
		userCache,
		eventPublisher,
	)

	// Initialize query handlers
	getUserHandler := query.NewGetUserHandler(userRepo, userCache)
	getUserByDIDHandler := query.NewGetUserByDIDHandler(userRepo, userCache)
	getSessionHandler := query.NewGetSessionHandler(sessionRepo, sessionCache)
	listSessionsHandler := query.NewListSessionsHandler(sessionRepo)
	getAPIKeyHandler := query.NewGetAPIKeyHandler(apiKeyRepo)
	listAPIKeysHandler := query.NewListAPIKeysHandler(apiKeyRepo)
	verifyAPIKeyHandler := query.NewVerifyAPIKeyHandler(apiKeyRepo, userRepo, eventPublisher)

	// tokenBlacklist can be used for token revocation checks if needed
	_ = tokenBlacklist

	// Initialize gRPC handler
	handler := identitygrpc.NewHandler(identitygrpc.HandlerConfig{
		RegisterUserHandler:         registerUserHandler,
		VerifyRegistrationHandler:   verifyRegistrationHandler,
		AuthenticateHandler:         authenticateHandler,
		VerifyAuthenticationHandler: verifyAuthenticationHandler,
		RefreshTokenHandler:         refreshTokenHandler,
		RevokeTokenHandler:          revokeTokenHandler,
		RevokeSessionHandler:        revokeSessionHandler,
		RevokeAllSessionsHandler:    revokeAllSessionsHandler,
		CreateAPIKeyHandler:         createAPIKeyHandler,
		RevokeAPIKeyHandler:         revokeAPIKeyHandler,
		UpdateUserHandler:           updateUserHandler,
		GetUserHandler:              getUserHandler,
		GetUserByDIDHandler:         getUserByDIDHandler,
		GetSessionHandler:           getSessionHandler,
		ListSessionsHandler:         listSessionsHandler,
		GetAPIKeyHandler:            getAPIKeyHandler,
		ListAPIKeysHandler:          listAPIKeysHandler,
		VerifyAPIKeyHandler:         verifyAPIKeyHandler,
	})

	// Initialize interceptors
	authInterceptor := identitygrpc.NewAuthInterceptor(tokenService)
	loggingInterceptor := identitygrpc.NewLoggingInterceptor(newGRPCLogger(logger))
	recoveryInterceptor := identitygrpc.NewRecoveryInterceptor(newGRPCLogger(logger))

	// Initialize gRPC server
	serverCfg := identitygrpc.ServerConfig{
		Host:              cfg.Server.Host,
		Port:              cfg.Server.Port,
		EnableReflection:  cfg.Server.EnableReflection,
		EnableHealthCheck: cfg.Server.EnableHealthCheck,
	}

	server, err := identitygrpc.NewServer(
		serverCfg,
		handler,
		logger,
		recoveryInterceptor.Unary(),
		loggingInterceptor.Unary(),
		authInterceptor.Unary(),
	)
	if err != nil {
		return fmt.Errorf("failed to create grpc server: %w", err)
	}

	// Handle graceful shutdown
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Run()
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("identity service started", log.String("address", serverCfg.Address()))

	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigChan:
		logger.Info("received shutdown signal", log.String("signal", sig.String()))
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer shutdownCancel()

		if err := server.Stop(shutdownCtx); err != nil {
			return fmt.Errorf("failed to stop server: %w", err)
		}

		logger.Info("identity service stopped gracefully")
		return nil
	}
}

func connectPostgres(ctx context.Context, cfg config.DatabaseConfig, logger log.Logger) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.ConnectionString())
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	poolCfg.MaxConns = int32(cfg.MaxConns)
	poolCfg.MinConns = int32(cfg.MinConns)
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.HealthCheckPeriod = cfg.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("connected to postgres",
		log.String("host", cfg.Host),
		log.String("database", cfg.Database),
	)

	return pool, nil
}

func connectRedis(ctx context.Context, cfg config.RedisConfig, logger log.Logger) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Address(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	logger.Info("connected to redis",
		log.String("address", cfg.Address()),
	)

	return client, nil
}

func connectNATS(cfg config.NATSConfig, logger log.Logger) (*natsclient.Conn, error) {
	opts := []natsclient.Option{
		natsclient.MaxReconnects(cfg.MaxReconnects),
		natsclient.ReconnectWait(cfg.ReconnectWait),
		natsclient.DisconnectErrHandler(func(nc *natsclient.Conn, err error) {
			if err != nil {
				logger.Warn("nats disconnected", log.String("error", err.Error()))
			}
		}),
		natsclient.ReconnectHandler(func(nc *natsclient.Conn) {
			logger.Info("nats reconnected", log.String("url", nc.ConnectedUrl()))
		}),
	}

	conn, err := natsclient.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	logger.Info("connected to nats",
		log.String("url", conn.ConnectedUrl()),
	)

	return conn, nil
}

// grpcLogger adapts log.Logger to identitygrpc.Logger interface.
type grpcLogger struct {
	logger log.Logger
}

func newGRPCLogger(logger log.Logger) *grpcLogger {
	return &grpcLogger{logger: logger}
}

func (l *grpcLogger) Info(msg string, fields ...interface{}) {
	l.logger.Info(msg, toLogFields(fields)...)
}

func (l *grpcLogger) Error(msg string, fields ...interface{}) {
	l.logger.Error(msg, toLogFields(fields)...)
}

func toLogFields(fields []interface{}) []log.Field {
	if len(fields) == 0 {
		return nil
	}

	result := make([]log.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		result = append(result, log.Any(key, fields[i+1]))
	}
	return result
}
