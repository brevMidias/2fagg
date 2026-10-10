CREATE TABLE entries (
  id TEXT PRIMARY KEY NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  operation_hash TEXT NOT NULL,
  token_hash TEXT,
  ciphertext TEXT,
  nonce TEXT,
  key_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK ((status = 'active' AND token_hash IS NOT NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL)
    OR (status = 'revoked' AND token_hash IS NULL AND ciphertext IS NULL AND nonce IS NULL))
);
CREATE UNIQUE INDEX entries_token_hash ON entries(token_hash) WHERE token_hash IS NOT NULL;
