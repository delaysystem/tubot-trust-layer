/// <reference types="bun-types" />
import { describe, expect, it } from "bun:test";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  decryptPii,
  decryptRecordMap,
  deriveKey,
  encryptPii,
  encryptRecordMap,
  generateEncryptionKey,
} from "./crypto";

describe("crypto.ts", () => {
  describe("generateEncryptionKey", () => {
    it("generates a 256-bit AES-GCM key exported as URL-safe base64", async () => {
      const keyStr = await generateEncryptionKey();
      expect(typeof keyStr).toBe("string");
      // 32 bytes in unpadded base64url is 43 characters
      expect(keyStr.length).toBe(43);
      // Must only contain URL-safe base64 characters
      expect(/^[A-Za-z0-9_-]+$/.test(keyStr)).toBe(true);

      // Decoded bytes must be exactly 32 bytes (256 bits)
      const bytes = base64ToBytes(keyStr);
      expect(bytes.length).toBe(32);
    });

    it("generates distinct keys across multiple calls", async () => {
      const key1 = await generateEncryptionKey();
      const key2 = await generateEncryptionKey();
      expect(key1).not.toBe(key2);
    });
  });

  describe("deriveKey", () => {
    it("directly imports 32-byte URL-safe base64 key into AES-GCM", async () => {
      const generatedKey = await generateEncryptionKey();
      const { key, salt } = await deriveKey(generatedKey);

      expect(key).toBeDefined();
      expect(key.algorithm.name).toBe("AES-GCM");
      expect((key.algorithm as any).length).toBe(256);
      expect(salt).toBe("");

      // Key must be functional for encryption/decryption
      const plaintext = "direct-import-test";
      const { ciphertext, iv } = await encryptPii(plaintext, key);
      const decrypted = await decryptPii(ciphertext, iv, key);
      expect(decrypted).toBe(plaintext);
    });

    it("directly imports 32-byte standard base64 key with padding", async () => {
      const raw32 = crypto.getRandomValues(new Uint8Array(32));
      const b64 = bytesToBase64(raw32);
      expect(b64.length).toBe(44);

      const { key } = await deriveKey(b64);
      expect(key.algorithm.name).toBe("AES-GCM");

      const plaintext = "standard-base64-test";
      const { ciphertext, iv } = await encryptPii(plaintext, key);
      const decrypted = await decryptPii(ciphertext, iv, key);
      expect(decrypted).toBe(plaintext);
    });

    it("derives AES-GCM key from passphrase using PBKDF2 with random salt", async () => {
      const passphrase = "super-secret-user-passphrase";
      const result = await deriveKey(passphrase);

      expect(result.key).toBeDefined();
      expect(result.key.algorithm.name).toBe("AES-GCM");
      expect((result.key.algorithm as any).length).toBe(256);
      expect(typeof result.salt).toBe("string");
      expect(result.salt.length).toBeGreaterThan(0);

      // Verify salt decodes to 16 bytes
      const saltBytes = base64ToBytes(result.salt);
      expect(saltBytes.length).toBe(16);
    });

    it("derives identical key deterministically when given same passphrase and salt", async () => {
      const passphrase = "deterministic-passphrase";
      const initial = await deriveKey(passphrase);

      // Re-derive with salt as base64 string
      const rederived1 = await deriveKey(passphrase, initial.salt);
      // Re-derive with salt as Uint8Array
      const rederived2 = await deriveKey(passphrase, base64ToBytes(initial.salt));

      const plaintext = "secret-payload-roundtrip";
      const enc = await encryptPii(plaintext, initial.key);

      const dec1 = await decryptPii(enc.ciphertext, enc.iv, rederived1.key);
      const dec2 = await decryptPii(enc.ciphertext, enc.iv, rederived2.key);

      expect(dec1).toBe(plaintext);
      expect(dec2).toBe(plaintext);
    });

    it("derives different keys with different passphrases and same salt", async () => {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const res1 = await deriveKey("passphrase-one", salt);
      const res2 = await deriveKey("passphrase-two", salt);

      const enc = await encryptPii("secret", res1.key);
      await expect(decryptPii(enc.ciphertext, enc.iv, res2.key)).rejects.toThrow(
        /Decryption failed/
      );
    });

    it("derives different keys with same passphrase and different salts", async () => {
      const passphrase = "same-passphrase";
      const res1 = await deriveKey(passphrase);
      const res2 = await deriveKey(passphrase);

      const enc = await encryptPii("secret", res1.key);
      await expect(decryptPii(enc.ciphertext, enc.iv, res2.key)).rejects.toThrow(
        /Decryption failed/
      );
    });
  });

  describe("encryptPii and decryptPii", () => {
    it("encrypts and decrypts UTF-8 plaintext correctly", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const plaintext = "John Doe, SSN: 000-12-3456, Email: john@example.com";
      const enc = await encryptPii(plaintext, key);

      expect(enc.ciphertext).toBeDefined();
      expect(enc.iv).toBeDefined();
      // IV must decode to 12 bytes
      expect(base64ToBytes(enc.iv).length).toBe(12);

      const decrypted = await decryptPii(enc.ciphertext, enc.iv, key);
      expect(decrypted).toBe(plaintext);
    });

    it("generates unique IV and ciphertext for identical plaintext", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const plaintext = "identical-plaintext";
      const enc1 = await encryptPii(plaintext, key);
      const enc2 = await encryptPii(plaintext, key);

      expect(enc1.iv).not.toBe(enc2.iv);
      expect(enc1.ciphertext).not.toBe(enc2.ciphertext);

      expect(await decryptPii(enc1.ciphertext, enc1.iv, key)).toBe(plaintext);
      expect(await decryptPii(enc2.ciphertext, enc2.iv, key)).toBe(plaintext);
    });

    it("supports multi-byte characters and emojis", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const unicodeText = "Hello 世界! 🔐 Привет 🚀 12345 €";
      const enc = await encryptPii(unicodeText, key);
      const decrypted = await decryptPii(enc.ciphertext, enc.iv, key);
      expect(decrypted).toBe(unicodeText);
    });

    it("supports empty string plaintext", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const enc = await encryptPii("", key);
      const decrypted = await decryptPii(enc.ciphertext, enc.iv, key);
      expect(decrypted).toBe("");
    });

    it("throws descriptive error when ciphertext is tampered", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const enc = await encryptPii("legitimate-data", key);
      const tamperedBytes = base64ToBytes(enc.ciphertext);
      tamperedBytes[0] ^= 0xff; // Flip bits
      const tamperedCiphertext = bytesToBase64(tamperedBytes);

      await expect(
        decryptPii(tamperedCiphertext, enc.iv, key)
      ).rejects.toThrow(/Decryption failed/);
    });

    it("throws descriptive error when IV is tampered", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const enc = await encryptPii("legitimate-data", key);
      const tamperedIvBytes = base64ToBytes(enc.iv);
      tamperedIvBytes[0] ^= 0xff;
      const tamperedIv = bytesToBase64(tamperedIvBytes);

      await expect(
        decryptPii(enc.ciphertext, tamperedIv, key)
      ).rejects.toThrow(/Decryption failed/);
    });

    it("throws descriptive error when decrypted with wrong key", async () => {
      const keyStr1 = await generateEncryptionKey();
      const keyStr2 = await generateEncryptionKey();
      const { key: key1 } = await deriveKey(keyStr1);
      const { key: key2 } = await deriveKey(keyStr2);

      const enc = await encryptPii("secret-message", key1);
      await expect(decryptPii(enc.ciphertext, enc.iv, key2)).rejects.toThrow(
        /Decryption failed/
      );
    });
  });

  describe("encryptRecordMap and decryptRecordMap", () => {
    it("encrypts and decrypts record map dictionary roundtrip", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const tokenMap: Record<string, string> = {
        "[NAME_1]": "Alice Johnson",
        "[EMAIL_1]": "alice@corp.internal",
        "[PHONE_1]": "+1-555-0199",
        "[CREDIT_CARD_1]": "4111111111111111",
      };

      const encrypted = await encryptRecordMap(tokenMap, key);
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.iv).toBeDefined();

      const decrypted = await decryptRecordMap(
        encrypted.encryptedData,
        encrypted.iv,
        key
      );
      expect(decrypted).toEqual(tokenMap);
    });

    it("handles empty record map {}", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      const emptyMap: Record<string, string> = {};
      const encrypted = await encryptRecordMap(emptyMap, key);
      const decrypted = await decryptRecordMap(
        encrypted.encryptedData,
        encrypted.iv,
        key
      );
      expect(decrypted).toEqual({});
    });

    it("throws descriptive error when decrypted data is not valid JSON", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      // Encrypt raw non-JSON text
      const enc = await encryptPii("this is not json { [", key);

      await expect(
        decryptRecordMap(enc.ciphertext, enc.iv, key)
      ).rejects.toThrow(/Failed to parse decrypted record map as JSON/);
    });

    it("throws error when decrypted JSON is not an object", async () => {
      const keyStr = await generateEncryptionKey();
      const { key } = await deriveKey(keyStr);

      // Encrypt an array
      const enc = await encryptPii(JSON.stringify(["item1", "item2"]), key);

      await expect(
        decryptRecordMap(enc.ciphertext, enc.iv, key)
      ).rejects.toThrow(/not a valid JSON object/);
    });
  });

  describe("base64 helper utilities", () => {
    it("converts bytes to standard base64 and back", () => {
      const original = new Uint8Array([0, 1, 2, 253, 254, 255, 62, 63]);
      const b64 = bytesToBase64(original);
      const restored = base64ToBytes(b64);
      expect(restored).toEqual(original);
    });

    it("converts bytes to URL-safe base64 and back", () => {
      // 251, 254, 255 produces + / characters in standard base64
      const original = new Uint8Array([251, 254, 255, 250, 240]);
      const urlSafe = bytesToBase64Url(original);
      expect(urlSafe).not.toContain("+");
      expect(urlSafe).not.toContain("/");
      expect(urlSafe).not.toContain("=");

      const restored = base64ToBytes(urlSafe);
      expect(restored).toEqual(original);
    });
  });
});
