-- name: CreateChallenge :exec
INSERT INTO challenges (id, did, nonce, purpose, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: FindChallengeByID :one
SELECT id, did, nonce, purpose, expires_at, created_at
FROM challenges
WHERE id = $1;

-- name: DeleteChallenge :exec
DELETE FROM challenges
WHERE id = $1;

-- name: DeleteChallengesByDID :exec
DELETE FROM challenges
WHERE did = $1;

-- name: DeleteExpiredChallenges :execrows
DELETE FROM challenges
WHERE expires_at < NOW();