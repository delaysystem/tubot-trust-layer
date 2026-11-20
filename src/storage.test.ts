/// <reference types="bun-types" />
import { describe, expect, it, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import {
  initDatabase,
  storeVaultRecord,
  getVaultRecord,
  getTokens,
  getTokensByVaultId,
  deleteVaultRecord,
  pruneExpiredRecords,
  VaultRecord,
  TokenRecord,
  SCHEMA_SQL,
} from "./storage";

/**
 * Creates an in-memory SQLite implementation of Cloudflare D1Database for testing.
 */
function createMockD1(): D1Database & { sqlite: Database } {
  const sqlite = new Database(":memory:");

  class MockPreparedStatement implements D1PreparedStatement {
    public query: string;
    public params: any[];

    constructor(query: string, params: any[] = []) {
      this.query = query;
      this.params = params;
    }

    bind(...values: any[]): any {
      return new MockPreparedStatement(this.query, values);
    }

    async first<T = unknown>(colName?: string): Promise<T | null> {
      const stmt = sqlite.query(this.query);
      const row = stmt.get(...this.params) as any;
      if (!row) return null;
      if (colName) return (row[colName] as T) ?? null;
      return row as T;
    }

    async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
      const stmt = sqlite.query(this.query);
      const results = (stmt.all(...this.params) as T[]) || [];
      return {
        success: true,
        results,
        meta: {
          changes: 0,
          duration: 0,
          size_after: 0,
          rows_read: results.length,
          rows_written: 0,
          last_row_id: 0,
          changed_db: false,
        },
      };
    }

    async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
      const stmt = sqlite.prepare(this.query);
      const info = stmt.run(...this.params);
      return {
        success: true,
        results: [],
        meta: {
          changes: info.changes,
          duration: 0,
          size_after: 0,
          rows_read: 0,
          rows_written: info.changes,
          last_row_id: Number(info.lastInsertRowid),
          changed_db: info.changes > 0,
        },
      };
    }

    async raw(...args: any[]): Promise<any> {
      return [];
    }
  }

  const d1: any = {
    sqlite,
    prepare(query: string) {
      return new MockPreparedStatement(query);
    },
    async exec(query: string) {
      sqlite.exec(query);
      return { count: 1, duration: 0 };
    },
    async batch(statements: MockPreparedStatement[]) {
      const tx = sqlite.transaction(() => {
        const results: D1Result[] = [];
        for (const s of statements) {
          const stmt = sqlite.prepare(s.query);
          const info = stmt.run(...s.params);
          results.push({
            success: true,
            results: [],
            meta: {
              changes: info.changes,
              duration: 0,
              size_after: 0,
              rows_read: 0,
              rows_written: info.changes,
              last_row_id: Number(info.lastInsertRowid),
              changed_db: info.changes > 0,
            },
          });
        }
        return results;
      });
      return tx();
    },
    withSession() {
      return d1;
    },
    dump() {
      return Promise.resolve(new ArrayBuffer(0));
    },
  };

  return d1 as D1Database & { sqlite: Database };
}

describe("storage.ts", () => {
  let db: D1Database & { sqlite: Database };

  beforeEach(async () => {
    db = createMockD1();
    await initDatabase(db);
  });

  describe("initDatabase", () => {
    it("creates tables and indexes without error", async () => {
      // Check tables exist in sqlite_master
      const tables = db.sqlite
        .query("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as { name: string }[];
      const tableNames = tables.map((t) => t.name);

      expect(tableNames).toContain("pii_vault");
      expect(tableNames).toContain("pii_tokens");

      // Check indexes exist
      const indexes = db.sqlite
        .query("SELECT name FROM sqlite_master WHERE type='index'")
        .all() as { name: string }[];
      const indexNames = indexes.map((i) => i.name);

      expect(indexNames).toContain("idx_pii_tokens_vault");
      expect(indexNames).toContain("idx_pii_vault_expires");
    });

    it("is idempotent when executed multiple times", async () => {
      await expect(initDatabase(db)).resolves.toBeUndefined();
      await expect(initDatabase(db)).resolves.toBeUndefined();
    });

    it("falls back to db.batch if db.exec is not present", async () => {
      const fallbackDb = createMockD1();
      // Remove exec
      (fallbackDb as any).exec = undefined;
      await initDatabase(fallbackDb);

      const tables = fallbackDb.sqlite
        .query("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as { name: string }[];
      const tableNames = tables.map((t) => t.name);
      expect(tableNames).toContain("pii_vault");
      expect(tableNames).toContain("pii_tokens");
    });
  });

  describe("storeVaultRecord and getVaultRecord", () => {
    it("stores and retrieves a complete vault record with tokens", async () => {
      const vaultRecord: VaultRecord = {
        vaultId: "vault-123",
        salt: "salt-base64",
        iv: "iv-base64",
        encryptedData: "encrypted-payload-data",
        piiTypes: ["EMAIL", "NAME", "PHONE"],
        itemCount: 3,
        createdAt: 1700000000000,
        expiresAt: 1700086400000,
      };

      const tokens: TokenRecord[] = [
        {
          tokenId: "token-email-1",
          vaultId: "vault-123",
          piiType: "EMAIL",
          iv: "iv-1",
          encryptedValue: "enc-val-1",
          createdAt: 1700000000000,
          expiresAt: 1700086400000,
        },
        {
          tokenId: "token-name-1",
          vaultId: "vault-123",
          piiType: "NAME",
          iv: "iv-2",
          encryptedValue: "enc-val-2",
          createdAt: 1700000000000,
          expiresAt: 1700086400000,
        },
      ];

      await storeVaultRecord(db, vaultRecord, tokens);

      const retrieved = await getVaultRecord(db, "vault-123");
      expect(retrieved).not.toBeNull();
      expect(retrieved).toEqual({
        vaultId: "vault-123",
        salt: "salt-base64",
        iv: "iv-base64",
        encryptedData: "encrypted-payload-data",
        piiTypes: ["EMAIL", "NAME", "PHONE"],
        itemCount: 3,
        createdAt: 1700000000000,
        expiresAt: 1700086400000,
      });

      // Verify tokens were stored
      const storedTokens = await getTokensByVaultId(db, "vault-123");
      expect(storedTokens.length).toBe(2);
      expect(storedTokens[0].tokenId).toBe("token-email-1");
      expect(storedTokens[1].tokenId).toBe("token-name-1");
    });

    it("stores and retrieves record with null salt and null expiresAt", async () => {
      const record: VaultRecord = {
        vaultId: "vault-nulls",
        salt: null,
        iv: "iv-data",
        encryptedData: "data",
        piiTypes: ["SSN"],
        itemCount: 1,
        createdAt: 1700000000000,
        expiresAt: null,
      };

      await storeVaultRecord(db, record, []);

      const retrieved = await getVaultRecord(db, "vault-nulls");
      expect(retrieved).not.toBeNull();
      expect(retrieved?.salt).toBeNull();
      expect(retrieved?.expiresAt).toBeNull();
      expect(retrieved?.piiTypes).toEqual(["SSN"]);
    });

    it("returns null when vault record is not found", async () => {
      const retrieved = await getVaultRecord(db, "non-existent-vault");
      expect(retrieved).toBeNull();
    });

    it("handles corrupted or invalid JSON in pii_types column gracefully", async () => {
      // Insert raw row with invalid JSON
      db.sqlite
        .prepare(
          `INSERT INTO pii_vault (vault_id, salt, iv, encrypted_data, pii_types, item_count, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run("bad-json-vault", null, "iv", "data", "not-a-json{", 0, 100, null);

      const record = await getVaultRecord(db, "bad-json-vault");
      expect(record).not.toBeNull();
      expect(record?.piiTypes).toEqual([]);
    });
  });

  describe("getTokens and getTokensByVaultId", () => {
    beforeEach(async () => {
      const vault: VaultRecord = {
        vaultId: "vault-multi",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["EMAIL", "NAME"],
        itemCount: 2,
        createdAt: 1000,
      };
      const tokens: TokenRecord[] = [
        {
          tokenId: "tok-1",
          vaultId: "vault-multi",
          piiType: "EMAIL",
          iv: "iv1",
          encryptedValue: "enc1",
          createdAt: 1000,
          expiresAt: null,
        },
        {
          tokenId: "tok-2",
          vaultId: "vault-multi",
          piiType: "NAME",
          iv: "iv2",
          encryptedValue: "enc2",
          createdAt: 1000,
          expiresAt: null,
        },
        {
          tokenId: "tok-3",
          vaultId: "vault-other",
          piiType: "PHONE",
          iv: "iv3",
          encryptedValue: "enc3",
          createdAt: 1000,
          expiresAt: null,
        },
      ];
      await storeVaultRecord(db, vault, tokens);
    });

    it("getTokens returns empty array when given empty tokenIds array", async () => {
      const res = await getTokens(db, []);
      expect(res).toEqual([]);
    });

    it("getTokens retrieves specific tokens by IDs", async () => {
      const res = await getTokens(db, ["tok-1", "tok-3"]);
      expect(res.length).toBe(2);
      const tokenIds = res.map((t) => t.tokenId);
      expect(tokenIds).toContain("tok-1");
      expect(tokenIds).toContain("tok-3");
      expect(tokenIds).not.toContain("tok-2");
    });

    it("getTokens returns empty array when none of the IDs match", async () => {
      const res = await getTokens(db, ["unknown-1", "unknown-2"]);
      expect(res).toEqual([]);
    });

    it("getTokensByVaultId retrieves all tokens for a vault", async () => {
      const res = await getTokensByVaultId(db, "vault-multi");
      expect(res.length).toBe(2);
      expect(res.map((t) => t.tokenId).sort()).toEqual(["tok-1", "tok-2"]);
    });

    it("getTokensByVaultId returns empty array for non-existent vault", async () => {
      const res = await getTokensByVaultId(db, "no-such-vault");
      expect(res).toEqual([]);
    });
  });

  describe("deleteVaultRecord", () => {
    it("deletes vault record and its tokens atomically", async () => {
      const vault: VaultRecord = {
        vaultId: "vault-to-delete",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["SSN"],
        itemCount: 1,
        createdAt: 1000,
      };
      const tokens: TokenRecord[] = [
        {
          tokenId: "tok-del-1",
          vaultId: "vault-to-delete",
          piiType: "SSN",
          iv: "iv",
          encryptedValue: "enc",
          createdAt: 1000,
        },
      ];

      await storeVaultRecord(db, vault, tokens);

      const deleted = await deleteVaultRecord(db, "vault-to-delete");
      expect(deleted).toBe(true);

      // Verify vault is gone
      const record = await getVaultRecord(db, "vault-to-delete");
      expect(record).toBeNull();

      // Verify tokens are gone
      const remainingTokens = await getTokensByVaultId(db, "vault-to-delete");
      expect(remainingTokens).toEqual([]);
    });

    it("returns false when deleting a non-existent vaultId", async () => {
      const deleted = await deleteVaultRecord(db, "does-not-exist");
      expect(deleted).toBe(false);
    });

    it("does not delete tokens belonging to other vaults", async () => {
      const v1: VaultRecord = {
        vaultId: "v1",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["NAME"],
        itemCount: 1,
        createdAt: 1000,
      };
      const v2: VaultRecord = {
        vaultId: "v2",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["NAME"],
        itemCount: 1,
        createdAt: 1000,
      };
      const t1: TokenRecord = {
        tokenId: "t1",
        vaultId: "v1",
        piiType: "NAME",
        iv: "iv",
        encryptedValue: "v1-val",
        createdAt: 1000,
      };
      const t2: TokenRecord = {
        tokenId: "t2",
        vaultId: "v2",
        piiType: "NAME",
        iv: "iv",
        encryptedValue: "v2-val",
        createdAt: 1000,
      };

      await storeVaultRecord(db, v1, [t1]);
      await storeVaultRecord(db, v2, [t2]);

      await deleteVaultRecord(db, "v1");

      const remaining = await getTokens(db, ["t1", "t2"]);
      expect(remaining.length).toBe(1);
      expect(remaining[0].tokenId).toBe("t2");
    });
  });

  describe("pruneExpiredRecords", () => {
    it("deletes records where expires_at < now and returns count of pruned records", async () => {
      const now = 5000;

      // Expired vault + 2 tokens (expiresAt = 4000)
      const expiredVault: VaultRecord = {
        vaultId: "expired-vault",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["EMAIL"],
        itemCount: 2,
        createdAt: 1000,
        expiresAt: 4000,
      };
      const expiredTokens: TokenRecord[] = [
        {
          tokenId: "exp-tok-1",
          vaultId: "expired-vault",
          piiType: "EMAIL",
          iv: "iv",
          encryptedValue: "val1",
          createdAt: 1000,
          expiresAt: 4000,
        },
        {
          tokenId: "exp-tok-2",
          vaultId: "expired-vault",
          piiType: "EMAIL",
          iv: "iv",
          encryptedValue: "val2",
          createdAt: 1000,
          expiresAt: 4000,
        },
      ];

      // Active vault + 1 token (expiresAt = 6000)
      const activeVault: VaultRecord = {
        vaultId: "active-vault",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["NAME"],
        itemCount: 1,
        createdAt: 1000,
        expiresAt: 6000,
      };
      const activeTokens: TokenRecord[] = [
        {
          tokenId: "active-tok-1",
          vaultId: "active-vault",
          piiType: "NAME",
          iv: "iv",
          encryptedValue: "val",
          createdAt: 1000,
          expiresAt: 6000,
        },
      ];

      // Indefinite vault (expiresAt = null)
      const indefiniteVault: VaultRecord = {
        vaultId: "indefinite-vault",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["PHONE"],
        itemCount: 0,
        createdAt: 1000,
        expiresAt: null,
      };

      await storeVaultRecord(db, expiredVault, expiredTokens);
      await storeVaultRecord(db, activeVault, activeTokens);
      await storeVaultRecord(db, indefiniteVault, []);

      // Prune with now = 5000 (expired vault + 2 expired tokens = 3 records)
      const prunedCount = await pruneExpiredRecords(db, now);
      expect(prunedCount).toBe(3);

      // Verify expired records are gone
      expect(await getVaultRecord(db, "expired-vault")).toBeNull();
      expect(await getTokensByVaultId(db, "expired-vault")).toEqual([]);

      // Verify active records remain
      expect(await getVaultRecord(db, "active-vault")).not.toBeNull();
      const activeToks = await getTokensByVaultId(db, "active-vault");
      expect(activeToks.length).toBe(1);

      // Verify indefinite records remain
      expect(await getVaultRecord(db, "indefinite-vault")).not.toBeNull();
    });

    it("returns 0 when no records are expired", async () => {
      const vault: VaultRecord = {
        vaultId: "fresh-vault",
        iv: "iv",
        encryptedData: "enc",
        piiTypes: ["EMAIL"],
        itemCount: 0,
        createdAt: 1000,
        expiresAt: 10000,
      };
      await storeVaultRecord(db, vault, []);

      const pruned = await pruneExpiredRecords(db, 2000);
      expect(pruned).toBe(0);
    });
  });
});
