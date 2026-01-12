-- name: CreateAPIKey :exec
INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, scopes, status, tenant_id, expires_at, last_used_at, created_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: UpdateAPIKey :exec
UPDATE api_keys
SET name = $2, scopes = $3, status = $4, last_used_at = $5, revoked_at = $6
WHERE id = $1;

-- name: FindAPIKeyByID :one
SELECT id, user_id, name, key_prefix, key_hash, scopes, status, tenant_id, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE id = $1;

-- name: FindAPIKeyByKeyHash :one
SELECT id, user_id, name, key_prefix, key_hash, scopes, status, tenant_id, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE key_hash = $1;

-- name: FindAPIKeyByPrefix :one
SELECT id, user_id, name, key_prefix, key_hash, scopes, status, tenant_id, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE key_prefix = $1;

-- name: FindActiveAPIKeysByUserID :many
SELECT id, user_id, name, key_prefix, key_hash, scopes, status, tenant_id, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE user_id = $1
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC;

-- name: ListAPIKeys :many
SELECT id, user_id, name, key_prefix, key_hash, scopes, status, tenant_id, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE (sqlc.narg('user_id')::text IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.arg('active_only')::bool = FALSE OR (status = 'active' AND (expires_at IS NULL OR expires_at > NOW())))
ORDER BY
    CASE WHEN sqlc.arg('sort_by') = 'created_at' AND sqlc.arg('sort_order') = 'asc' THEN created_at END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'created_at' AND sqlc.arg('sort_order') = 'desc' THEN created_at END DESC,
    CASE WHEN sqlc.arg('sort_by') = 'last_used_at' AND sqlc.arg('sort_order') = 'asc' THEN last_used_at END ASC NULLS LAST,
    CASE WHEN sqlc.arg('sort_by') = 'last_used_at' AND sqlc.arg('sort_order') = 'desc' THEN last_used_at END DESC NULLS LAST,
    CASE WHEN sqlc.arg('sort_by') = 'name' AND sqlc.arg('sort_order') = 'asc' THEN name END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'name' AND sqlc.arg('sort_order') = 'desc' THEN name END DESC,
    CASE WHEN sqlc.arg('sort_by') = 'expires_at' AND sqlc.arg('sort_order') = 'asc' THEN expires_at END ASC NULLS LAST,
    CASE WHEN sqlc.arg('sort_by') = 'expires_at' AND sqlc.arg('sort_order') = 'desc' THEN expires_at END DESC NULLS LAST,
    created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountAPIKeys :one
SELECT COUNT(*)
FROM api_keys
WHERE (sqlc.narg('user_id')::text IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.arg('active_only')::bool = FALSE OR (status = 'active' AND (expires_at IS NULL OR expires_at > NOW())));

-- name: RevokeAPIKeyByID :exec
UPDATE api_keys
SET status = 'revoked', revoked_at = NOW()
WHERE id = $1 AND status = 'active';

-- name: RevokeAllAPIKeysByUserID :execrows
UPDATE api_keys
SET status = 'revoked', revoked_at = NOW()
WHERE user_id = $1 AND status = 'active';

-- name: DeleteAPIKey :exec
DELETE FROM api_keys
WHERE id = $1;

-- name: DeleteExpiredAPIKeys :execrows
DELETE FROM api_keys
WHERE expires_at IS NOT NULL AND expires_at < NOW() - INTERVAL '30 days';

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = NOW()
WHERE id = $1;