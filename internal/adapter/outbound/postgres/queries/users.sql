-- name: CreateUser :exec
INSERT INTO users (id, did, email, name, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: UpdateUser :exec
UPDATE users
SET email = $2, name = $3, status = $4, updated_at = $5
WHERE id = $1;

-- name: FindUserByID :one
SELECT id, did, email, name, status, created_at, updated_at
FROM users
WHERE id = $1;

-- name: FindUserByDID :one
SELECT id, did, email, name, status, created_at, updated_at
FROM users
WHERE did = $1;

-- name: FindUserByEmail :one
SELECT id, did, email, name, status, created_at, updated_at
FROM users
WHERE email = $1;

-- name: ExistsByDID :one
SELECT EXISTS(SELECT 1 FROM users WHERE did = $1);

-- name: ExistsByEmail :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);

-- name: ListUsers :many
SELECT id, did, email, name, status, created_at, updated_at
FROM users
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY
    CASE WHEN sqlc.arg('sort_by') = 'created_at' AND sqlc.arg('sort_order') = 'asc' THEN created_at END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'created_at' AND sqlc.arg('sort_order') = 'desc' THEN created_at END DESC,
    CASE WHEN sqlc.arg('sort_by') = 'updated_at' AND sqlc.arg('sort_order') = 'asc' THEN updated_at END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'updated_at' AND sqlc.arg('sort_order') = 'desc' THEN updated_at END DESC,
    CASE WHEN sqlc.arg('sort_by') = 'email' AND sqlc.arg('sort_order') = 'asc' THEN email END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'email' AND sqlc.arg('sort_order') = 'desc' THEN email END DESC,
    created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*)
FROM users
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'));

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;