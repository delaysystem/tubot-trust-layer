/**
 * Cryptography utilities for tubot-trust-layer using Web Crypto API.
 */

export interface EncryptionResult {
  ciphertext: string;
  iv: string;
}

export interface EncryptedRecordMap {
  encryptedData: string;
  iv: string;
}

export interface KeyDerivationResult {
  key: CryptoKey;
  salt: string;
}

/**
 * Converts a Uint8Array or ArrayBuffer to standard base64 string.
 */
export function bytesToBase64(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < u8.length; i++) {
    binary += String.fromCharCode(u8[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Uint8Array or ArrayBuffer to URL-safe base64 string (RFC 4648 §5).
 */
export function bytesToBase64Url(bytes: Uint8Array | ArrayBuffer): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Converts a base64 or URL-safe base64 string to a Uint8Array.
 */
export function base64ToBytes(base64: string): Uint8Array {
  let b64 = base64.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Checks whether an input string is a valid base64/base64url encoded 32-byte key.
 */
function tryDecode32ByteKey(input: string): Uint8Array | null {
  if (typeof input !== "string") {
    return null;
  }
  const trimmed = input.trim();
  // 32 bytes in base64: 43 chars (unpadded urlsafe) or 44 chars (padded)
  if (trimmed.length !== 43 && trimmed.length !== 44) {
    return null;
  }
  if (!/^[A-Za-z0-9+/_-]+=*$/.test(trimmed)) {
    return null;
  }
  try {
    const bytes = base64ToBytes(trimmed);
    if (bytes.length === 32) {
      return bytes;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Generates a cryptographically secure 256-bit AES-GCM key exported as URL-safe base64.
 */
export async function generateEncryptionKey(): Promise<string> {
  const key = (await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  )) as CryptoKey;
  const rawKey = (await crypto.subtle.exportKey("raw", key)) as ArrayBuffer;
  return bytesToBase64Url(rawKey);
}

/**
 * Derives or imports a 256-bit AES-GCM key.
 * - If passphraseOrKey is already a 32-byte (256-bit) base64 string, imports it directly.
 * - Otherwise, derives a 256-bit AES-GCM key using PBKDF2 (SHA-256, 100,000 iterations, 16-byte random salt).
 * Returns the derived key and base64-encoded salt.
 */
export async function deriveKey(
  passphraseOrKey: string,
  salt?: Uint8Array | string
): Promise<KeyDerivationResult> {
  const directKeyBytes = tryDecode32ByteKey(passphraseOrKey);

  if (directKeyBytes) {
    const key = await crypto.subtle.importKey(
      "raw",
      directKeyBytes,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    let saltStr = "";
    if (salt) {
      saltStr = typeof salt === "string" ? salt : bytesToBase64(salt);
    }
    return { key, salt: saltStr };
  }

  // Derive key using PBKDF2
  let saltBytes: Uint8Array;
  if (!salt) {
    saltBytes = crypto.getRandomValues(new Uint8Array(16));
  } else if (typeof salt === "string") {
    saltBytes = base64ToBytes(salt);
  } else {
    saltBytes = salt;
  }

  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphraseOrKey),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return {
    key: derivedKey,
    salt: bytesToBase64(saltBytes),
  };
}

/**
 * Encrypts plaintext string using AES-GCM with a fresh 12-byte random IV and 128-bit tag.
 * Returns base64 ciphertext and base64 IV.
 */
export async function encryptPii(
  plaintext: string,
  key: CryptoKey
): Promise<EncryptionResult> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedPlaintext = new TextEncoder().encode(plaintext);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    encodedPlaintext
  );

  return {
    ciphertext: bytesToBase64(ciphertextBuf),
    iv: bytesToBase64(iv),
  };
}

/**
 * Decrypts base64 ciphertext using AES-GCM with given base64 IV and key.
 * Verifies 128-bit authentication tag. Throws descriptive error on failure.
 */
export async function decryptPii(
  ciphertext: string,
  iv: string,
  key: CryptoKey
): Promise<string> {
  try {
    const cipherBytes = base64ToBytes(ciphertext);
    const ivBytes = base64ToBytes(iv);

    const decryptedBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
      key,
      cipherBytes
    );

    return new TextDecoder().decode(decryptedBuf);
  } catch (err) {
    throw new Error(
      `Decryption failed: invalid ciphertext, authentication tag mismatch, or wrong key (${
        err instanceof Error ? err.message : String(err)
      })`
    );
  }
}

/**
 * Serializes a dictionary of { [token]: rawValue } to JSON and encrypts via AES-GCM.
 */
export async function encryptRecordMap(
  map: Record<string, string>,
  key: CryptoKey
): Promise<EncryptedRecordMap> {
  const serialized = JSON.stringify(map);
  const { ciphertext, iv } = await encryptPii(serialized, key);
  return {
    encryptedData: ciphertext,
    iv,
  };
}

/**
 * Decrypts encrypted record map and parses JSON dictionary.
 */
export async function decryptRecordMap(
  encryptedData: string,
  iv: string,
  key: CryptoKey
): Promise<Record<string, string>> {
  const decrypted = await decryptPii(encryptedData, iv, key);
  try {
    const parsed = JSON.parse(decrypted);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("Decrypted record map is not a valid JSON object");
    }
    return parsed as Record<string, string>;
  } catch (err) {
    throw new Error(
      `Failed to parse decrypted record map as JSON: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }
}
