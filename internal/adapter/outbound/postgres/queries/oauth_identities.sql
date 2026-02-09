-- name: CreateOAuthIdentity :exec
INSERT INTO oauth_identities (id, user_id, provider, provider_user_id, email, name, picture_url, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: FindOAuthIdentityByID :one
SELECT id, user_id, provider, provider_user_id, email, name, picture_url, created_at, updated_at
FROM oauth_identities
WHERE id = $1;

-- name: FindOAuthIdentityByProviderAndProviderUserID :one
SELECT id, user_id, provider, provider_user_id, email, name, picture_url, created_at, updated_at
FROM oauth_identities
WHERE provider = $1 AND provider_user_id = $2;

-- name: FindOAuthIdentitiesByUserID :many
SELECT id, user_id, provider, provider_user_id, email, name, picture_url, created_at, updated_at
FROM oauth_identities
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: FindOAuthIdentityByUserIDAndProvider :one
SELECT id, user_id, provider, provider_user_id, email, name, picture_url, created_at, updated_at
FROM oauth_identities
WHERE user_id = $1 AND provider = $2;

-- name: DeleteOAuthIdentity :exec
DELETE FROM oauth_identities
WHERE id = $1;

-- name: DeleteOAuthIdentityByUserIDAndProvider :exec
DELETE FROM oauth_identities
WHERE user_id = $1 AND provider = $2;

-- name: CountOAuthIdentitiesByUserID :one
SELECT COUNT(*)
FROM oauth_identities
WHERE user_id = $1;
