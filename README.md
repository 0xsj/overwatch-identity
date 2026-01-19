# Overwatch Identity Service

The Identity service is the **authentication and authorization foundation** for the Overwatch platform. It manages users, sessions, API keys, and cryptographic identities (DIDs). Every actor in the system - human or machine - has an identity rooted here.

## Responsibilities

| What it does | What it doesn't do |
|--------------|-------------------|
| User CRUD and authentication | Business domain logic |
| Session management (create, refresh, revoke) | Data collection or processing |
| API key issuance and validation | Source management |
| DID generation and management | Intelligence analysis |
| Password hashing and verification | Access control policies |
| Emit identity events for audit | |

## Architecture
```
┌──────────────────────────────────────────────────────────────────┐
│                      Identity Service                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                       gRPC API                              │ │
│  │   Users: Create, Get, Update, Delete, List, Authenticate   │ │
│  │   Sessions: Create, Refresh, Revoke, Validate              │ │
│  │   API Keys: Create, Get, Revoke, Validate                  │ │
│  └─────────────────────────────┬──────────────────────────────┘ │
│                                │                                 │
│  ┌─────────────────────────────┴──────────────────────────────┐ │
│  │                  Command / Query Handlers                   │ │
│  │                        (CQRS)                               │ │
│  └─────────────────────────────┬──────────────────────────────┘ │
│                                │                                 │
│         ┌──────────────────────┼──────────────────────┐         │
│         ▼                      ▼                      ▼         │
│  ┌─────────────┐        ┌─────────────┐        ┌─────────────┐  │
│  │  PostgreSQL │        │    Redis    │        │    NATS     │  │
│  │   (store)   │        │  (sessions) │        │  (events)   │  │
│  └─────────────┘        └─────────────┘        └─────────────┘  │
│                                                       │          │
└───────────────────────────────────────────────────────┼──────────┘
                                                        │
                                                        ▼
                                        Ledger, other services
```

## Core Concepts

### Users

Human actors with credentials and profile information.
```json
{
  "id": "01KF0X8HEBWPCCF9ASNGXX7YMM",
  "tenant_id": "01KF0X8HEBWPCCF9ASNGXX7YMN",
  "email": "analyst@agency.gov",
  "username": "jsmith",
  "display_name": "John Smith",
  "role": "analyst",
  "status": "active",
  "did": "did:key:z6MkUserJohnSmith...",
  "created_at": "2026-01-15T12:00:00Z"
}
```

### Sessions

Authenticated user sessions with refresh capability.
```json
{
  "id": "01KF0X8HEBWPCCF9ASNGXX7YMP",
  "user_id": "01KF0X8HEBWPCCF9ASNGXX7YMM",
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_a1b2c3d4e5f6...",
  "expires_at": "2026-01-15T13:00:00Z",
  "refresh_expires_at": "2026-01-22T12:00:00Z",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "created_at": "2026-01-15T12:00:00Z"
}
```

### API Keys

Machine-to-machine authentication for services and integrations.
```json
{
  "id": "01KF0X8HEBWPCCF9ASNGXX7YMQ",
  "user_id": "01KF0X8HEBWPCCF9ASNGXX7YMM",
  "name": "CI/CD Pipeline",
  "key_prefix": "ow_live_abc123",
  "permissions": ["sources:read", "sources:write"],
  "expires_at": "2027-01-15T12:00:00Z",
  "last_used_at": "2026-01-15T12:00:00Z",
  "created_at": "2026-01-15T12:00:00Z"
}
```

### DIDs (Decentralized Identifiers)

Cryptographic identity for signing and verification.
```
did:key:z6MkUserJohnSmith...
        │
        └── Encodes Ed25519 public key
            Used for:
            - Signing events
            - Verifying authorship
            - Provenance chains
```

## User Lifecycle
```
                     ┌──────────┐
                     │ CREATED  │
                     │ (pending)│
                     └────┬─────┘
                          │ verify email
                          ▼
                     ┌──────────┐
        suspend      │  ACTIVE  │      suspend
       ┌─────────────┤          ├─────────────┐
       │             └────┬─────┘             │
       │                  │                   │
       ▼                  │ delete            ▼
  ┌──────────┐            │            ┌──────────┐
  │SUSPENDED │            │            │  LOCKED  │
  │          │            │            │(too many │
  └────┬─────┘            │            │ failures)│
       │ reactivate       │            └────┬─────┘
       │                  │                 │ unlock
       └──────────────────┼─────────────────┘
                          │
                          ▼
                     ┌──────────┐
                     │ DELETED  │
                     │(soft del)│
                     └──────────┘
```

## Authentication Flow

### Password Authentication
```
┌────────┐                    ┌──────────────────┐
│ Client │                    │ Identity Service │
└───┬────┘                    └────────┬─────────┘
    │                                  │
    │ Authenticate(email, password)    │
    │─────────────────────────────────▶│
    │                                  │
    │                    ┌─────────────┴─────────────┐
    │                    │ 1. Find user by email     │
    │                    │ 2. Verify password hash   │
    │                    │ 3. Check user status      │
    │                    │ 4. Generate session       │
    │                    │ 5. Sign tokens with DID   │
    │                    │ 6. Store in Redis         │
    │                    │ 7. Publish user.logged_in │
    │                    └─────────────┬─────────────┘
    │                                  │
    │ Session(access_token, refresh)   │
    │◀─────────────────────────────────│
    │                                  │
```

### Token Refresh
```
┌────────┐                    ┌──────────────────┐
│ Client │                    │ Identity Service │
└───┬────┘                    └────────┬─────────┘
    │                                  │
    │ RefreshSession(refresh_token)    │
    │─────────────────────────────────▶│
    │                                  │
    │                    ┌─────────────┴─────────────┐
    │                    │ 1. Validate refresh token │
    │                    │ 2. Check not revoked      │
    │                    │ 3. Generate new tokens    │
    │                    │ 4. Rotate refresh token   │
    │                    │ 5. Update Redis           │
    │                    │ 6. Publish session.refresh│
    │                    └─────────────┬─────────────┘
    │                                  │
    │ Session(new_access, new_refresh) │
    │◀─────────────────────────────────│
    │                                  │
```

### API Key Validation
```
┌─────────┐                   ┌──────────────────┐
│ Service │                   │ Identity Service │
└────┬────┘                   └────────┬─────────┘
     │                                 │
     │ ValidateAPIKey(key)             │
     │────────────────────────────────▶│
     │                                 │
     │                   ┌─────────────┴─────────────┐
     │                   │ 1. Parse key prefix       │
     │                   │ 2. Lookup by prefix hash  │
     │                   │ 3. Verify key hash        │
     │                   │ 4. Check expiration       │
     │                   │ 5. Check permissions      │
     │                   │ 6. Update last_used_at    │
     │                   └─────────────┬─────────────┘
     │                                 │
     │ APIKey(user_id, permissions)    │
     │◀────────────────────────────────│
     │                                 │
```

## Event Flow

**Publishes to:**
```
# User events
overwatch.identity.user.created
overwatch.identity.user.updated
overwatch.identity.user.deleted
overwatch.identity.user.suspended
overwatch.identity.user.reactivated
overwatch.identity.user.password_changed
overwatch.identity.user.logged_in
overwatch.identity.user.logged_out
overwatch.identity.user.login_failed

# Session events
overwatch.identity.session.created
overwatch.identity.session.refreshed
overwatch.identity.session.revoked
overwatch.identity.session.expired

# API Key events
overwatch.identity.apikey.created
overwatch.identity.apikey.revoked
overwatch.identity.apikey.expired
overwatch.identity.apikey.used
```

**Consumed by:**
- Ledger Service (records all events for audit)
- Other services (for cache invalidation, etc.)

## Provenance

Every event is signed by the Identity service:
```json
{
  "event_id": "01KF0...",
  "event_type": "user.created",
  "occurred_at": "2026-01-15T12:00:00Z",
  "service_signer": {
    "did": "did:key:z6MkIdentityService...",
    "signer_type": "SERVICE",
    "signer_id": "identity-service",
    "signature": "base64..."
  },
  "payload": {
    "user_id": "01KF0...",
    "email": "analyst@agency.gov",
    "role": "analyst"
  }
}
```

Users also have DIDs for signing their own actions:
```json
{
  "event_id": "01KF0...",
  "event_type": "source.created",
  "service_signer": {
    "did": "did:key:z6MkSourceService...",
    "signer_type": "SERVICE"
  },
  "actor_signer": {
    "did": "did:key:z6MkUserJohnSmith...",
    "signer_type": "USER",
    "signer_id": "01KF0..."
  }
}
```

## Database Schema
```sql
-- Users
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT,
    email           TEXT NOT NULL,
    username        TEXT,
    display_name    TEXT,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'viewer',
    status          TEXT NOT NULL DEFAULT 'pending',
    did             TEXT,
    
    failed_login_attempts   INTEGER DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    password_changed_at     TIMESTAMPTZ,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    
    UNIQUE(tenant_id, email),
    UNIQUE(tenant_id, username)
);

-- API Keys
CREATE TABLE api_keys (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT,
    user_id         TEXT NOT NULL REFERENCES users(id),
    name            TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,
    key_hash        TEXT NOT NULL,
    permissions     TEXT[] DEFAULT '{}',
    
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(key_prefix)
);

-- Indexes
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
```

## Redis Schema

Sessions are stored in Redis for fast validation:
```
# Session by access token
session:access:{token_hash} -> {
    "session_id": "01KF0...",
    "user_id": "01KF0...",
    "tenant_id": "01KF0...",
    "role": "analyst",
    "did": "did:key:z6Mk...",
    "expires_at": "2026-01-15T13:00:00Z"
}
TTL: matches token expiry

# Session by refresh token
session:refresh:{token_hash} -> {
    "session_id": "01KF0...",
    "user_id": "01KF0...",
    "access_token_hash": "...",
    "expires_at": "2026-01-22T12:00:00Z"
}
TTL: matches refresh expiry

# User sessions (for revocation)
user:sessions:{user_id} -> SET of session_ids
TTL: none (cleaned up on logout)

# Rate limiting
ratelimit:login:{email_hash} -> count
TTL: 15 minutes
```

## Configuration
```env
# Server
IDENTITY_SERVER_HOST=0.0.0.0
IDENTITY_SERVER_PORT=50051

# Database
IDENTITY_DATABASE_HOST=localhost
IDENTITY_DATABASE_PORT=5450
IDENTITY_DATABASE_USER=overwatch
IDENTITY_DATABASE_PASSWORD=overwatch_dev
IDENTITY_DATABASE_NAME=overwatch_identity
IDENTITY_DATABASE_SSL_MODE=disable

# Redis
IDENTITY_REDIS_HOST=localhost
IDENTITY_REDIS_PORT=6390
IDENTITY_REDIS_PASSWORD=
IDENTITY_REDIS_DB=0

# NATS
IDENTITY_NATS_URL=nats://localhost:4230
IDENTITY_NATS_SUBJECT_PREFIX=overwatch.identity

# Authentication
IDENTITY_AUTH_ACCESS_TOKEN_TTL=1h
IDENTITY_AUTH_REFRESH_TOKEN_TTL=168h
IDENTITY_AUTH_BCRYPT_COST=12
IDENTITY_AUTH_MAX_LOGIN_ATTEMPTS=5
IDENTITY_AUTH_LOCKOUT_DURATION=15m

# Service Identity
IDENTITY_SERVICE_IDENTITY_ID=identity-service
IDENTITY_SERVICE_IDENTITY_NAME=identity
IDENTITY_SERVICE_IDENTITY_GENERATE_IF_MISSING=true
```

## gRPC API
```protobuf
service IdentityService {
  // Health
  rpc Ping(PingRequest) returns (PingResponse);
  
  // ─────────────────────────────────────────────────────────────
  // Users
  // ─────────────────────────────────────────────────────────────
  
  rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
  rpc GetUser(GetUserRequest) returns (GetUserResponse);
  rpc GetUserByEmail(GetUserByEmailRequest) returns (GetUserByEmailResponse);
  rpc UpdateUser(UpdateUserRequest) returns (UpdateUserResponse);
  rpc DeleteUser(DeleteUserRequest) returns (DeleteUserResponse);
  rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
  
  // User status
  rpc SuspendUser(SuspendUserRequest) returns (SuspendUserResponse);
  rpc ReactivateUser(ReactivateUserRequest) returns (ReactivateUserResponse);
  
  // Password
  rpc ChangePassword(ChangePasswordRequest) returns (ChangePasswordResponse);
  rpc ResetPassword(ResetPasswordRequest) returns (ResetPasswordResponse);
  
  // ─────────────────────────────────────────────────────────────
  // Authentication
  // ─────────────────────────────────────────────────────────────
  
  rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse);
  rpc ValidateSession(ValidateSessionRequest) returns (ValidateSessionResponse);
  rpc RefreshSession(RefreshSessionRequest) returns (RefreshSessionResponse);
  rpc RevokeSession(RevokeSessionRequest) returns (RevokeSessionResponse);
  rpc RevokeAllSessions(RevokeAllSessionsRequest) returns (RevokeAllSessionsResponse);
  rpc ListSessions(ListSessionsRequest) returns (ListSessionsResponse);
  
  // ─────────────────────────────────────────────────────────────
  // API Keys
  // ─────────────────────────────────────────────────────────────
  
  rpc CreateAPIKey(CreateAPIKeyRequest) returns (CreateAPIKeyResponse);
  rpc GetAPIKey(GetAPIKeyRequest) returns (GetAPIKeyResponse);
  rpc ListAPIKeys(ListAPIKeysRequest) returns (ListAPIKeysResponse);
  rpc RevokeAPIKey(RevokeAPIKeyRequest) returns (RevokeAPIKeyResponse);
  rpc ValidateAPIKey(ValidateAPIKeyRequest) returns (ValidateAPIKeyResponse);
}
```

## Security Considerations

### Password Handling
```go
// Passwords are hashed with bcrypt
hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// Never stored in plaintext
// Never logged
// Never returned in responses
```

### Token Security
```go
// Access tokens: short-lived, signed JWTs
// - 1 hour default TTL
// - Signed with service Ed25519 key
// - Contains: user_id, tenant_id, role, did

// Refresh tokens: long-lived, opaque
// - 7 day default TTL
// - Stored hashed in Redis
// - Rotated on each refresh
```

### API Key Security
```go
// Keys are generated with crypto/rand
// Format: ow_{env}_{random}
// Example: ow_live_a1b2c3d4e5f6g7h8i9j0

// Only the prefix is stored in plaintext
// Full key is hashed with SHA-256
// Full key shown only once at creation
```

### Rate Limiting
```go
// Login attempts: 5 per 15 minutes per email
// After limit: account locked for 15 minutes
// Lockout duration doubles on repeated violations
```

## Integration with Other Services
```
┌─────────────────────────────────────────────────────────────────┐
│                         Identity Service                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│    Source     │       │   Collector   │       │    Ingest     │
│   Service     │       │    Service    │       │    Service    │
│               │       │               │       │               │
│ Validates     │       │ Validates     │       │ Validates     │
│ user tokens   │       │ API keys      │       │ user DIDs     │
│ before CRUD   │       │ for webhooks  │       │ in provenance │
└───────────────┘       └───────────────┘       └───────────────┘
```

### Validating Requests

Other services call Identity to validate tokens:
```go
// In Source Service
func (s *Server) CreateSource(ctx context.Context, req *pb.CreateSourceRequest) (*pb.CreateSourceResponse, error) {
    // Extract token from metadata
    token := extractToken(ctx)
    
    // Validate with Identity Service
    resp, err := s.identityClient.ValidateSession(ctx, &identity.ValidateSessionRequest{
        AccessToken: token,
    })
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "invalid token")
    }
    
    // Use validated user info
    userID := resp.UserId
    userDID := resp.Did
    
    // Proceed with request...
}
```

## References

- **Protos**: `overwatch-contracts/proto/identity/v1/`
- **Architecture pattern**: Hexagonal architecture with CQRS
- **Provenance signing**: `overwatch-pkg/provenance/`
- **Password hashing**: bcrypt with cost 12
- **Token signing**: Ed25519 (via DID)