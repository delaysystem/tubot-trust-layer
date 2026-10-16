/**
 * D1 Storage operations for tubot-trust-layer.
 */

import { CACHE_SCHEMA_STATEMENTS } from "./cache";

export interface VaultRecord {
  vaultId: string;
  salt?: string | null;
  iv: string;
  encryptedData: string;
  piiTypes: string[]; // serialized to JSON string in D1
  itemCount: number;
  createdAt: number;
  expiresAt?: number | null;
}

export interface TokenRecord {
  tokenId: string;
  vaultId: string;
  piiType: string;
  iv: string;
  encryptedValue: string;
  createdAt: number;
  expiresAt?: number | null;
}

export const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS pii_vault (
  vault_id TEXT PRIMARY KEY,
  salt TEXT,
  iv TEXT NOT NULL,
  encrypted_data TEXT NOT NULL,
  pii_types TEXT NOT NULL,
  item_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
)`,
  `CREATE TABLE IF NOT EXISTS pii_tokens (
  token_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  pii_type TEXT NOT NULL,
  iv TEXT NOT NULL,
  encrypted_value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  PRIMARY KEY (vault_id, token_id)
)`,
  `CREATE INDEX IF NOT EXISTS idx_pii_tokens_vault ON pii_tokens(vault_id)`,
  `CREATE INDEX IF NOT EXISTS idx_pii_tokens_token_id ON pii_tokens(token_id)`,
  `CREATE INDEX IF NOT EXISTS idx_pii_vault_expires ON pii_vault(expires_at)`,
  ...CACHE_SCHEMA_STATEMENTS,
];

export const SCHEMA_SQL = SCHEMA_STATEMENTS.join(";\n") + ";";

const initializedDatabases = new WeakSet<D1Database>();

/**
 * Initializes the database tables and indexes if they do not exist.
 */
export async function initDatabase(db: D1Database): Promise<void> {
  if (initializedDatabases.has(db)) return;
  for (const stmt of SCHEMA_STATEMENTS) {
    await db.prepare(stmt).run();
  }
  initializedDatabases.add(db);
}

/**
 * Stores a vault record and associated token records atomically in a batch transaction.
 */
export async function storeVaultRecord(
  db: D1Database,
  record: VaultRecord,
  tokens: TokenRecord[] = []
): Promise<void> {
  const vaultStmt = db
    .prepare(
      `INSERT OR REPLACE INTO pii_vault (vault_id, salt, iv, encrypted_data, pii_types, item_count, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.vaultId,
      record.salt ?? null,
      record.iv,
      record.encryptedData,
      JSON.stringify(record.piiTypes),
      record.itemCount,
      record.createdAt,
      record.expiresAt ?? null
    );

  const tokenStmts = tokens.map((token) =>
    db
      .prepare(
        `INSERT OR REPLACE INTO pii_tokens (token_id, vault_id, pii_type, iv, encrypted_value, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        token.tokenId,
        token.vaultId,
        token.piiType,
        token.iv,
        token.encryptedValue,
        token.createdAt,
        token.expiresAt ?? null
      )
  );

  await db.batch([vaultStmt, ...tokenStmts]);
}

/**
 * Retrieves a vault record by its ID, parsing the piiTypes JSON array.
 */
export async function getVaultRecord(
  db: D1Database,
  vaultId: string
): Promise<VaultRecord | null> {
  const row = await db
    .prepare(
      `SELECT vault_id, salt, iv, encrypted_data, pii_types, item_count, created_at, expires_at
       FROM pii_vault WHERE vault_id = ?`
    )
    .bind(vaultId)
    .first<{
      vault_id: string;
      salt: string | null;
      iv: string;
      encrypted_data: string;
      pii_types: string;
      item_count: number;
      created_at: number;
      expires_at: number | null;
    }>();

  if (!row) {
    return null;
  }

  let piiTypes: string[] = [];
  try {
    const parsed = JSON.parse(row.pii_types);
    if (Array.isArray(parsed)) {
      piiTypes = parsed;
    }
  } catch {
    piiTypes = [];
  }

  return {
    vaultId: row.vault_id,
    salt: row.salt ?? null,
    iv: row.iv,
    encryptedData: row.encrypted_data,
    piiTypes,
    itemCount: row.item_count,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? null,
  };
}

/**
 * Retrieves tokens matching the provided token IDs.
 */
export async function getTokens(
  db: D1Database,
  tokenIds: string[]
): Promise<TokenRecord[]> {
  if (!tokenIds || tokenIds.length === 0) {
    return [];
  }

  const placeholders = tokenIds.map(() => "?").join(", ");
  const { results } = await db
    .prepare(
      `SELECT token_id, vault_id, pii_type, iv, encrypted_value, created_at, expires_at
       FROM pii_tokens WHERE token_id IN (${placeholders})`
    )
    .bind(...tokenIds)
    .all<{
      token_id: string;
      vault_id: string;
      pii_type: string;
      iv: string;
      encrypted_value: string;
      created_at: number;
      expires_at: number | null;
    }>();

  return (results || []).map((row) => ({
    tokenId: row.token_id,
    vaultId: row.vault_id,
    piiType: row.pii_type,
    iv: row.iv,
    encryptedValue: row.encrypted_value,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? null,
  }));
}

/**
 * Retrieves all tokens associated with a given vault ID.
 */
export async function getTokensByVaultId(
  db: D1Database,
  vaultId: string
): Promise<TokenRecord[]> {
  const { results } = await db
    .prepare(
      `SELECT token_id, vault_id, pii_type, iv, encrypted_value, created_at, expires_at
       FROM pii_tokens WHERE vault_id = ?`
    )
    .bind(vaultId)
    .all<{
      token_id: string;
      vault_id: string;
      pii_type: string;
      iv: string;
      encrypted_value: string;
      created_at: number;
      expires_at: number | null;
    }>();

  return (results || []).map((row) => ({
    tokenId: row.token_id,
    vaultId: row.vault_id,
    piiType: row.pii_type,
    iv: row.iv,
    encryptedValue: row.encrypted_value,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? null,
  }));
}

/**
 * Deletes a vault record and its associated tokens by vaultId.
 * Returns true if a vault record was found and deleted, false otherwise.
 */
export async function deleteVaultRecord(
  db: D1Database,
  vaultId: string
): Promise<boolean> {
  const deleteTokensStmt = db
    .prepare(`DELETE FROM pii_tokens WHERE vault_id = ?`)
    .bind(vaultId);
  const deleteVaultStmt = db
    .prepare(`DELETE FROM pii_vault WHERE vault_id = ?`)
    .bind(vaultId);

  const results = await db.batch([deleteTokensStmt, deleteVaultStmt]);
  const vaultResult = results[1];
  return Boolean(vaultResult?.meta?.changes && vaultResult.meta.changes > 0);
}

/**
 * Deletes vault and token records where expires_at IS NOT NULL AND expires_at < now.
 * Returns total count of pruned records across both tables.
 */
export async function pruneExpiredRecords(
  db: D1Database,
  now: number = Date.now()
): Promise<number> {
  const pruneTokensStmt = db
    .prepare(
      `DELETE FROM pii_tokens WHERE expires_at IS NOT NULL AND expires_at < ?`
    )
    .bind(now);
  const pruneVaultStmt = db
    .prepare(
      `DELETE FROM pii_vault WHERE expires_at IS NOT NULL AND expires_at < ?`
    )
    .bind(now);

  const results = await db.batch([pruneTokensStmt, pruneVaultStmt]);
  const tokensPruned = results[0]?.meta?.changes ?? 0;
  const vaultPruned = results[1]?.meta?.changes ?? 0;
  return tokensPruned + vaultPruned;
}
