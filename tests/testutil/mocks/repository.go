// Package mocks provides mock implementations of ports for testing.
package mocks

import (
	"context"
	"sync"

	"github.com/0xsj/overwatch-pkg/types"

	"github.com/0xsj/overwatch-identity/internal/domain/model"
	"github.com/0xsj/overwatch-identity/internal/port/outbound/repository"
)

// --- UserRepository Mock ---

// UserRepository is a mock implementation of repository.UserRepository.
type UserRepository struct {
	mu sync.RWMutex

	// Storage
	users   map[string]*model.User // by ID
	byDID   map[string]string      // DID -> ID
	byEmail map[string]string      // email -> ID

	// Call tracking
	Calls struct {
		Create        int
		Update        int
		FindByID      int
		FindByDID     int
		FindByEmail   int
		ExistsByDID   int
		ExistsByEmail int
		List          int
		Count         int
		Delete        int
	}

	// Error injection
	Errors struct {
		Create        error
		Update        error
		FindByID      error
		FindByDID     error
		FindByEmail   error
		ExistsByDID   error
		ExistsByEmail error
		List          error
		Count         error
		Delete        error
	}
}

// NewUserRepository creates a new mock UserRepository.
func NewUserRepository() *UserRepository {
	return &UserRepository{
		users:   make(map[string]*model.User),
		byDID:   make(map[string]string),
		byEmail: make(map[string]string),
	}
}

func (m *UserRepository) Create(ctx context.Context, user *model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Create++

	if m.Errors.Create != nil {
		return m.Errors.Create
	}

	id := user.ID().String()
	m.users[id] = user
	m.byDID[user.DID().String()] = id
	if user.Email().IsPresent() {
		m.byEmail[user.Email().MustGet().String()] = id
	}

	return nil
}

func (m *UserRepository) Update(ctx context.Context, user *model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Update++

	if m.Errors.Update != nil {
		return m.Errors.Update
	}

	id := user.ID().String()

	// Remove old email index if exists
	if old, ok := m.users[id]; ok && old.Email().IsPresent() {
		delete(m.byEmail, old.Email().MustGet().String())
	}

	m.users[id] = user
	if user.Email().IsPresent() {
		m.byEmail[user.Email().MustGet().String()] = id
	}

	return nil
}

func (m *UserRepository) FindByID(ctx context.Context, id types.ID) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByID++

	if m.Errors.FindByID != nil {
		return nil, m.Errors.FindByID
	}

	user, ok := m.users[id.String()]
	if !ok {
		return nil, nil
	}
	return user, nil
}

func (m *UserRepository) FindByDID(ctx context.Context, did string) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByDID++

	if m.Errors.FindByDID != nil {
		return nil, m.Errors.FindByDID
	}

	id, ok := m.byDID[did]
	if !ok {
		return nil, nil
	}
	return m.users[id], nil
}

func (m *UserRepository) FindByEmail(ctx context.Context, email types.Email) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByEmail++

	if m.Errors.FindByEmail != nil {
		return nil, m.Errors.FindByEmail
	}

	id, ok := m.byEmail[email.String()]
	if !ok {
		return nil, nil
	}
	return m.users[id], nil
}

func (m *UserRepository) ExistsByDID(ctx context.Context, did string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.ExistsByDID++

	if m.Errors.ExistsByDID != nil {
		return false, m.Errors.ExistsByDID
	}

	_, ok := m.byDID[did]
	return ok, nil
}

func (m *UserRepository) ExistsByEmail(ctx context.Context, email types.Email) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.ExistsByEmail++

	if m.Errors.ExistsByEmail != nil {
		return false, m.Errors.ExistsByEmail
	}

	_, ok := m.byEmail[email.String()]
	return ok, nil
}

func (m *UserRepository) List(ctx context.Context, params repository.ListUsersParams) ([]*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.List++

	if m.Errors.List != nil {
		return nil, m.Errors.List
	}

	var result []*model.User
	for _, user := range m.users {
		if params.Status != nil && user.Status() != *params.Status {
			continue
		}
		result = append(result, user)
	}

	// Apply pagination
	start := params.Offset
	if start > len(result) {
		return []*model.User{}, nil
	}
	end := start + params.Limit
	if end > len(result) {
		end = len(result)
	}

	return result[start:end], nil
}

func (m *UserRepository) Count(ctx context.Context, params repository.ListUsersParams) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.Count++

	if m.Errors.Count != nil {
		return 0, m.Errors.Count
	}

	var count int64
	for _, user := range m.users {
		if params.Status != nil && user.Status() != *params.Status {
			continue
		}
		count++
	}
	return count, nil
}

func (m *UserRepository) Delete(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Delete++

	if m.Errors.Delete != nil {
		return m.Errors.Delete
	}

	user, ok := m.users[id.String()]
	if ok {
		delete(m.byDID, user.DID().String())
		if user.Email().IsPresent() {
			delete(m.byEmail, user.Email().MustGet().String())
		}
		delete(m.users, id.String())
	}

	return nil
}

// Reset clears all data and call counts.
func (m *UserRepository) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = make(map[string]*model.User)
	m.byDID = make(map[string]string)
	m.byEmail = make(map[string]string)
	m.Calls = struct {
		Create        int
		Update        int
		FindByID      int
		FindByDID     int
		FindByEmail   int
		ExistsByDID   int
		ExistsByEmail int
		List          int
		Count         int
		Delete        int
	}{}
	m.Errors = struct {
		Create        error
		Update        error
		FindByID      error
		FindByDID     error
		FindByEmail   error
		ExistsByDID   error
		ExistsByEmail error
		List          error
		Count         error
		Delete        error
	}{}
}

// Seed adds a user directly to the mock storage.
func (m *UserRepository) Seed(user *model.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := user.ID().String()
	m.users[id] = user
	m.byDID[user.DID().String()] = id
	if user.Email().IsPresent() {
		m.byEmail[user.Email().MustGet().String()] = id
	}
}

// --- SessionRepository Mock ---

// SessionRepository is a mock implementation of repository.SessionRepository.
type SessionRepository struct {
	mu sync.RWMutex

	// Storage
	sessions      map[string]*model.Session // by ID
	byRefreshHash map[string]string         // hash -> ID
	byUserID      map[string][]string       // userID -> []ID

	// Call tracking
	Calls struct {
		Create                 int
		Update                 int
		FindByID               int
		FindByRefreshTokenHash int
		FindActiveByUserID     int
		List                   int
		Count                  int
		RevokeByID             int
		RevokeAllByUserID      int
		DeleteExpired          int
	}

	// Error injection
	Errors struct {
		Create                 error
		Update                 error
		FindByID               error
		FindByRefreshTokenHash error
		FindActiveByUserID     error
		List                   error
		Count                  error
		RevokeByID             error
		RevokeAllByUserID      error
		DeleteExpired          error
	}
}

// NewSessionRepository creates a new mock SessionRepository.
func NewSessionRepository() *SessionRepository {
	return &SessionRepository{
		sessions:      make(map[string]*model.Session),
		byRefreshHash: make(map[string]string),
		byUserID:      make(map[string][]string),
	}
}

func (m *SessionRepository) Create(ctx context.Context, session *model.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Create++

	if m.Errors.Create != nil {
		return m.Errors.Create
	}

	id := session.ID().String()
	userID := session.UserID().String()

	m.sessions[id] = session
	m.byRefreshHash[session.RefreshTokenHash()] = id
	m.byUserID[userID] = append(m.byUserID[userID], id)

	return nil
}

func (m *SessionRepository) Update(ctx context.Context, session *model.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Update++

	if m.Errors.Update != nil {
		return m.Errors.Update
	}

	id := session.ID().String()

	// Remove old refresh hash index
	if old, ok := m.sessions[id]; ok {
		delete(m.byRefreshHash, old.RefreshTokenHash())
	}

	m.sessions[id] = session
	m.byRefreshHash[session.RefreshTokenHash()] = id

	return nil
}

func (m *SessionRepository) FindByID(ctx context.Context, id types.ID) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByID++

	if m.Errors.FindByID != nil {
		return nil, m.Errors.FindByID
	}

	session, ok := m.sessions[id.String()]
	if !ok {
		return nil, nil
	}
	return session, nil
}

func (m *SessionRepository) FindByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByRefreshTokenHash++

	if m.Errors.FindByRefreshTokenHash != nil {
		return nil, m.Errors.FindByRefreshTokenHash
	}

	id, ok := m.byRefreshHash[hash]
	if !ok {
		return nil, nil
	}
	return m.sessions[id], nil
}

func (m *SessionRepository) FindActiveByUserID(ctx context.Context, userID types.ID) ([]*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindActiveByUserID++

	if m.Errors.FindActiveByUserID != nil {
		return nil, m.Errors.FindActiveByUserID
	}

	var result []*model.Session
	ids := m.byUserID[userID.String()]
	for _, id := range ids {
		session := m.sessions[id]
		if session.IsValid() {
			result = append(result, session)
		}
	}
	return result, nil
}

func (m *SessionRepository) List(ctx context.Context, params repository.ListSessionsParams) ([]*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.List++

	if m.Errors.List != nil {
		return nil, m.Errors.List
	}

	var result []*model.Session
	for _, session := range m.sessions {
		if params.UserID != nil && session.UserID() != *params.UserID {
			continue
		}
		if params.TenantID != nil && (!session.TenantID().IsPresent() || session.TenantID().MustGet() != *params.TenantID) {
			continue
		}
		if params.ActiveOnly && !session.IsValid() {
			continue
		}
		result = append(result, session)
	}

	// Apply pagination
	start := params.Offset
	if start > len(result) {
		return []*model.Session{}, nil
	}
	end := start + params.Limit
	if end > len(result) {
		end = len(result)
	}

	return result[start:end], nil
}

func (m *SessionRepository) Count(ctx context.Context, params repository.ListSessionsParams) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.Count++

	if m.Errors.Count != nil {
		return 0, m.Errors.Count
	}

	var count int64
	for _, session := range m.sessions {
		if params.UserID != nil && session.UserID() != *params.UserID {
			continue
		}
		if params.TenantID != nil && (!session.TenantID().IsPresent() || session.TenantID().MustGet() != *params.TenantID) {
			continue
		}
		if params.ActiveOnly && !session.IsValid() {
			continue
		}
		count++
	}
	return count, nil
}

func (m *SessionRepository) RevokeByID(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.RevokeByID++

	if m.Errors.RevokeByID != nil {
		return m.Errors.RevokeByID
	}

	session, ok := m.sessions[id.String()]
	if ok {
		session.Revoke()
	}
	return nil
}

func (m *SessionRepository) RevokeAllByUserID(ctx context.Context, userID types.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.RevokeAllByUserID++

	if m.Errors.RevokeAllByUserID != nil {
		return 0, m.Errors.RevokeAllByUserID
	}

	count := 0
	ids := m.byUserID[userID.String()]
	for _, id := range ids {
		session := m.sessions[id]
		if session.IsValid() {
			session.Revoke()
			count++
		}
	}
	return count, nil
}

func (m *SessionRepository) DeleteExpired(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.DeleteExpired++

	if m.Errors.DeleteExpired != nil {
		return 0, m.Errors.DeleteExpired
	}

	count := 0
	for id, session := range m.sessions {
		if session.IsExpired() {
			delete(m.byRefreshHash, session.RefreshTokenHash())
			delete(m.sessions, id)
			count++
		}
	}
	return count, nil
}

// Reset clears all data and call counts.
func (m *SessionRepository) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = make(map[string]*model.Session)
	m.byRefreshHash = make(map[string]string)
	m.byUserID = make(map[string][]string)
	m.Calls = struct {
		Create                 int
		Update                 int
		FindByID               int
		FindByRefreshTokenHash int
		FindActiveByUserID     int
		List                   int
		Count                  int
		RevokeByID             int
		RevokeAllByUserID      int
		DeleteExpired          int
	}{}
	m.Errors = struct {
		Create                 error
		Update                 error
		FindByID               error
		FindByRefreshTokenHash error
		FindActiveByUserID     error
		List                   error
		Count                  error
		RevokeByID             error
		RevokeAllByUserID      error
		DeleteExpired          error
	}{}
}

// Seed adds a session directly to the mock storage.
func (m *SessionRepository) Seed(session *model.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := session.ID().String()
	userID := session.UserID().String()
	m.sessions[id] = session
	m.byRefreshHash[session.RefreshTokenHash()] = id
	m.byUserID[userID] = append(m.byUserID[userID], id)
}

// --- APIKeyRepository Mock ---

// APIKeyRepository is a mock implementation of repository.APIKeyRepository.
type APIKeyRepository struct {
	mu sync.RWMutex

	// Storage
	apiKeys   map[string]*model.APIKey // by ID
	byKeyHash map[string]string        // hash -> ID
	byPrefix  map[string]string        // prefix -> ID
	byUserID  map[string][]string      // userID -> []ID

	// Call tracking
	Calls struct {
		Create             int
		Update             int
		FindByID           int
		FindByKeyHash      int
		FindByPrefix       int
		FindActiveByUserID int
		List               int
		Count              int
		RevokeByID         int
		RevokeAllByUserID  int
		Delete             int
		DeleteExpired      int
	}

	// Error injection
	Errors struct {
		Create             error
		Update             error
		FindByID           error
		FindByKeyHash      error
		FindByPrefix       error
		FindActiveByUserID error
		List               error
		Count              error
		RevokeByID         error
		RevokeAllByUserID  error
		Delete             error
		DeleteExpired      error
	}
}

// NewAPIKeyRepository creates a new mock APIKeyRepository.
func NewAPIKeyRepository() *APIKeyRepository {
	return &APIKeyRepository{
		apiKeys:   make(map[string]*model.APIKey),
		byKeyHash: make(map[string]string),
		byPrefix:  make(map[string]string),
		byUserID:  make(map[string][]string),
	}
}

func (m *APIKeyRepository) Create(ctx context.Context, apiKey *model.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Create++

	if m.Errors.Create != nil {
		return m.Errors.Create
	}

	id := apiKey.ID().String()
	userID := apiKey.UserID().String()

	m.apiKeys[id] = apiKey
	m.byKeyHash[apiKey.KeyHash()] = id
	m.byPrefix[apiKey.KeyPrefix()] = id
	m.byUserID[userID] = append(m.byUserID[userID], id)

	return nil
}

func (m *APIKeyRepository) Update(ctx context.Context, apiKey *model.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Update++

	if m.Errors.Update != nil {
		return m.Errors.Update
	}

	m.apiKeys[apiKey.ID().String()] = apiKey
	return nil
}

func (m *APIKeyRepository) FindByID(ctx context.Context, id types.ID) (*model.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByID++

	if m.Errors.FindByID != nil {
		return nil, m.Errors.FindByID
	}

	apiKey, ok := m.apiKeys[id.String()]
	if !ok {
		return nil, nil
	}
	return apiKey, nil
}

func (m *APIKeyRepository) FindByKeyHash(ctx context.Context, hash string) (*model.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByKeyHash++

	if m.Errors.FindByKeyHash != nil {
		return nil, m.Errors.FindByKeyHash
	}

	id, ok := m.byKeyHash[hash]
	if !ok {
		return nil, nil
	}
	return m.apiKeys[id], nil
}

func (m *APIKeyRepository) FindByPrefix(ctx context.Context, prefix string) (*model.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByPrefix++

	if m.Errors.FindByPrefix != nil {
		return nil, m.Errors.FindByPrefix
	}

	id, ok := m.byPrefix[prefix]
	if !ok {
		return nil, nil
	}
	return m.apiKeys[id], nil
}

func (m *APIKeyRepository) FindActiveByUserID(ctx context.Context, userID types.ID) ([]*model.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindActiveByUserID++

	if m.Errors.FindActiveByUserID != nil {
		return nil, m.Errors.FindActiveByUserID
	}

	var result []*model.APIKey
	ids := m.byUserID[userID.String()]
	for _, id := range ids {
		apiKey := m.apiKeys[id]
		if apiKey.IsValid() {
			result = append(result, apiKey)
		}
	}
	return result, nil
}

func (m *APIKeyRepository) List(ctx context.Context, params repository.ListAPIKeysParams) ([]*model.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.List++

	if m.Errors.List != nil {
		return nil, m.Errors.List
	}

	var result []*model.APIKey
	for _, apiKey := range m.apiKeys {
		if params.UserID != nil && apiKey.UserID() != *params.UserID {
			continue
		}
		if params.TenantID != nil && (!apiKey.TenantID().IsPresent() || apiKey.TenantID().MustGet() != *params.TenantID) {
			continue
		}
		if params.Status != nil && apiKey.Status() != *params.Status {
			continue
		}
		if params.ActiveOnly && !apiKey.IsValid() {
			continue
		}
		result = append(result, apiKey)
	}

	// Apply pagination
	start := params.Offset
	if start > len(result) {
		return []*model.APIKey{}, nil
	}
	end := start + params.Limit
	if end > len(result) {
		end = len(result)
	}

	return result[start:end], nil
}

func (m *APIKeyRepository) Count(ctx context.Context, params repository.ListAPIKeysParams) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.Count++

	if m.Errors.Count != nil {
		return 0, m.Errors.Count
	}

	var count int64
	for _, apiKey := range m.apiKeys {
		if params.UserID != nil && apiKey.UserID() != *params.UserID {
			continue
		}
		if params.TenantID != nil && (!apiKey.TenantID().IsPresent() || apiKey.TenantID().MustGet() != *params.TenantID) {
			continue
		}
		if params.Status != nil && apiKey.Status() != *params.Status {
			continue
		}
		if params.ActiveOnly && !apiKey.IsValid() {
			continue
		}
		count++
	}
	return count, nil
}

func (m *APIKeyRepository) RevokeByID(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.RevokeByID++

	if m.Errors.RevokeByID != nil {
		return m.Errors.RevokeByID
	}

	apiKey, ok := m.apiKeys[id.String()]
	if ok {
		apiKey.Revoke()
	}
	return nil
}

func (m *APIKeyRepository) RevokeAllByUserID(ctx context.Context, userID types.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.RevokeAllByUserID++

	if m.Errors.RevokeAllByUserID != nil {
		return 0, m.Errors.RevokeAllByUserID
	}

	count := 0
	ids := m.byUserID[userID.String()]
	for _, id := range ids {
		apiKey := m.apiKeys[id]
		if apiKey.IsValid() {
			apiKey.Revoke()
			count++
		}
	}
	return count, nil
}

func (m *APIKeyRepository) Delete(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Delete++

	if m.Errors.Delete != nil {
		return m.Errors.Delete
	}

	apiKey, ok := m.apiKeys[id.String()]
	if ok {
		delete(m.byKeyHash, apiKey.KeyHash())
		delete(m.byPrefix, apiKey.KeyPrefix())
		delete(m.apiKeys, id.String())
	}
	return nil
}

func (m *APIKeyRepository) DeleteExpired(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.DeleteExpired++

	if m.Errors.DeleteExpired != nil {
		return 0, m.Errors.DeleteExpired
	}

	count := 0
	for id, apiKey := range m.apiKeys {
		if apiKey.IsExpired() {
			delete(m.byKeyHash, apiKey.KeyHash())
			delete(m.byPrefix, apiKey.KeyPrefix())
			delete(m.apiKeys, id)
			count++
		}
	}
	return count, nil
}

// Reset clears all data and call counts.
func (m *APIKeyRepository) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apiKeys = make(map[string]*model.APIKey)
	m.byKeyHash = make(map[string]string)
	m.byPrefix = make(map[string]string)
	m.byUserID = make(map[string][]string)
	m.Calls = struct {
		Create             int
		Update             int
		FindByID           int
		FindByKeyHash      int
		FindByPrefix       int
		FindActiveByUserID int
		List               int
		Count              int
		RevokeByID         int
		RevokeAllByUserID  int
		Delete             int
		DeleteExpired      int
	}{}
	m.Errors = struct {
		Create             error
		Update             error
		FindByID           error
		FindByKeyHash      error
		FindByPrefix       error
		FindActiveByUserID error
		List               error
		Count              error
		RevokeByID         error
		RevokeAllByUserID  error
		Delete             error
		DeleteExpired      error
	}{}
}

// Seed adds an API key directly to the mock storage.
func (m *APIKeyRepository) Seed(apiKey *model.APIKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := apiKey.ID().String()
	userID := apiKey.UserID().String()
	m.apiKeys[id] = apiKey
	m.byKeyHash[apiKey.KeyHash()] = id
	m.byPrefix[apiKey.KeyPrefix()] = id
	m.byUserID[userID] = append(m.byUserID[userID], id)
}

// --- ChallengeRepository Mock ---

// ChallengeRepository is a mock implementation of repository.ChallengeRepository.
type ChallengeRepository struct {
	mu sync.RWMutex

	// Storage
	challenges map[string]*model.Challenge // by ID
	byDID      map[string][]string         // DID -> []ID

	// Call tracking
	Calls struct {
		Create        int
		FindByID      int
		Delete        int
		DeleteByDID   int
		DeleteExpired int
	}

	// Error injection
	Errors struct {
		Create        error
		FindByID      error
		Delete        error
		DeleteByDID   error
		DeleteExpired error
	}
}

// NewChallengeRepository creates a new mock ChallengeRepository.
func NewChallengeRepository() *ChallengeRepository {
	return &ChallengeRepository{
		challenges: make(map[string]*model.Challenge),
		byDID:      make(map[string][]string),
	}
}

func (m *ChallengeRepository) Create(ctx context.Context, challenge *model.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Create++

	if m.Errors.Create != nil {
		return m.Errors.Create
	}

	id := challenge.ID().String()
	did := challenge.DID().String()

	m.challenges[id] = challenge
	m.byDID[did] = append(m.byDID[did], id)

	return nil
}

func (m *ChallengeRepository) FindByID(ctx context.Context, id types.ID) (*model.Challenge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.Calls.FindByID++

	if m.Errors.FindByID != nil {
		return nil, m.Errors.FindByID
	}

	challenge, ok := m.challenges[id.String()]
	if !ok {
		return nil, nil
	}
	return challenge, nil
}

func (m *ChallengeRepository) Delete(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.Delete++

	if m.Errors.Delete != nil {
		return m.Errors.Delete
	}

	delete(m.challenges, id.String())
	return nil
}

func (m *ChallengeRepository) DeleteByDID(ctx context.Context, did string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.DeleteByDID++

	if m.Errors.DeleteByDID != nil {
		return m.Errors.DeleteByDID
	}

	ids := m.byDID[did]
	for _, id := range ids {
		delete(m.challenges, id)
	}
	delete(m.byDID, did)

	return nil
}

func (m *ChallengeRepository) DeleteExpired(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls.DeleteExpired++

	if m.Errors.DeleteExpired != nil {
		return 0, m.Errors.DeleteExpired
	}

	count := 0
	for id, challenge := range m.challenges {
		if challenge.IsExpired() {
			delete(m.challenges, id)
			count++
		}
	}
	return count, nil
}

// Reset clears all data and call counts.
func (m *ChallengeRepository) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges = make(map[string]*model.Challenge)
	m.byDID = make(map[string][]string)
	m.Calls = struct {
		Create        int
		FindByID      int
		Delete        int
		DeleteByDID   int
		DeleteExpired int
	}{}
	m.Errors = struct {
		Create        error
		FindByID      error
		Delete        error
		DeleteByDID   error
		DeleteExpired error
	}{}
}

// Seed adds a challenge directly to the mock storage.
func (m *ChallengeRepository) Seed(challenge *model.Challenge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := challenge.ID().String()
	did := challenge.DID().String()
	m.challenges[id] = challenge
	m.byDID[did] = append(m.byDID[did], id)
}
