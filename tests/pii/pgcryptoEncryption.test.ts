import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  computeAddressHash,
  computeAddressHashes,
  pgpDecryptAddressColumn,
  pgpEncryptAddressParam,
  buildEncryptedAddressFilter,
  PGCRYPTO_KEY_MIN_LENGTH,
  PGP_MESSAGE_PREFIX,
  validatePgcryptoKey,
  validatePgcryptoKeySet,
  isPgpEncrypted,
  isRedactedTombstone,
  detectAddressEncryptionState,
  AddressEncryptionState,
  redactPiiForAddress,
  DEFAULT_ERASURE_TOMBSTONE,
  type PgcryptoKeySet,
  type RedactionResult,
} from '../../src/pii/pgcryptoEncryption.js';
import { streamSelectColumns } from '../../src/db/queries/streams.js';

describe('PGCrypto PII encryption helpers', () => {
  const address = 'GDRXE2BQUC3AZ7D3G7BMNJ4XOSXHG6YKO4IZ3Y4S7HNW3F4AWMRI6ZIY';
  const key = 'a'.repeat(32);
  const previousKey = 'b'.repeat(32);

  it('computes a stable hex digest for address hashing', () => {
    const hash = computeAddressHash(address, key);
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(computeAddressHash(address, key)).toBe(hash);
  });

  it('produces different hashes for different keys', () => {
    const first = computeAddressHash(address, key);
    const second = computeAddressHash(address, previousKey);
    expect(first).not.toBe(second);
  });

  it('computes current and previous hash versions', () => {
    const hashes = computeAddressHashes(address, { current: key, previous: previousKey });
    expect(hashes.current).toHaveLength(64);
    expect(hashes.previous).toHaveLength(64);
    expect(hashes.current).not.toBe(hashes.previous);
  });

  it('omits previous hash when no previous key is provided', () => {
    const hashes = computeAddressHashes(address, { current: key });
    expect(hashes.current).toHaveLength(64);
    expect(hashes.previous).toBeUndefined();
  });

  it('builds pgcrypto encryption SQL with param placeholders', () => {
    expect(pgpEncryptAddressParam(2, 5)).toContain('$2');
    expect(pgpEncryptAddressParam(2, 5)).toContain('$5');
    expect(pgpEncryptAddressParam(2, 5)).toContain('pgp_sym_encrypt(');
  });

  it('builds pgcrypto decryption SQL with optional previous key', () => {
    expect(pgpDecryptAddressColumn('sender_address', 1)).toContain('decrypt_stream_address(sender_address, $1, NULL)');
    expect(pgpDecryptAddressColumn('recipient_address', 1, 2)).toContain('decrypt_stream_address(recipient_address, $1, $2)');
  });

  it('builds a hashed address filter with plaintext fallback', () => {
    const expr = buildEncryptedAddressFilter('sender_address', 2, 3, 4);
    expect(expr).toContain('sender_address_hash = $3');
    expect(expr).toContain('sender_address_hash = $4');
    expect(expr).toContain('sender_address = $2');
  });

  it('builds a hashed address filter with only the current hash (no rotation)', () => {
    const expr = buildEncryptedAddressFilter('recipient_address', 1, 2);
    expect(expr).toContain('recipient_address_hash = $2');
    // No previous hash clause when previousHashParamIndex is omitted
    expect(expr).not.toMatch(/recipient_address_hash = \$3/);
    expect(expr).toContain('recipient_address = $1');
  });

  // ── PGCRYPTO_KEY_MIN_LENGTH constant ──────────────────────────────────────

  it('exports a minimum key length of 32', () => {
    expect(PGCRYPTO_KEY_MIN_LENGTH).toBe(32);
  });

  // ── PGP_MESSAGE_PREFIX sentinel ───────────────────────────────────────────

  it('exports the PGP message prefix sentinel used by the DB function', () => {
    expect(PGP_MESSAGE_PREFIX).toBe('-----BEGIN PGP MESSAGE-----');
  });

  // ── streamSelectColumns SQL shape (encryption ENABLED) ────────────────────
  //
  // These tests lock down the exact SQL fragment that getById, getByEvent,
  // findWithCursor, and find all depend on.  Regression here means addresses
  // would be returned as ciphertext to callers.

  describe('streamSelectColumns — encryption enabled', () => {
    it('wraps sender_address with decrypt_stream_address using current key only', () => {
      const cols = streamSelectColumns(2);
      expect(cols).toContain('decrypt_stream_address(sender_address, $2, NULL) AS sender_address');
    });

    it('wraps recipient_address with decrypt_stream_address using current key only', () => {
      const cols = streamSelectColumns(2);
      expect(cols).toContain('decrypt_stream_address(recipient_address, $2, NULL) AS recipient_address');
    });

    it('includes both previous key args when rotation is active', () => {
      const cols = streamSelectColumns(2, 3);
      expect(cols).toContain('decrypt_stream_address(sender_address, $2, $3) AS sender_address');
      expect(cols).toContain('decrypt_stream_address(recipient_address, $2, $3) AS recipient_address');
    });

    it('uses parameter index $2 for key and $1 for id — matching getById contract', () => {
      // getById builds: params = [id, currentKey, ?previousKey]
      // and calls streamSelectColumns(2, 3?) where 2 = index of currentKey in params
      const colsNoPrev = streamSelectColumns(2);
      expect(colsNoPrev).toContain('$2');
      expect(colsNoPrev).not.toContain('$3');

      const colsWithPrev = streamSelectColumns(2, 3);
      expect(colsWithPrev).toContain('$2');
      expect(colsWithPrev).toContain('$3');
    });

    it('includes all non-address columns unchanged', () => {
      const cols = streamSelectColumns(2);
      for (const col of [
        'id', 'amount', 'streamed_amount', 'remaining_amount',
        'rate_per_second', 'start_time', 'end_time', 'status',
        'contract_id', 'transaction_hash', 'event_index',
        'created_at', 'updated_at',
      ]) {
        expect(cols).toContain(col);
      }
    });

    it('does not contain a bare undecorated sender_address or recipient_address column', () => {
      // A bare column reference would mean ciphertext leaks to the app layer
      const cols = streamSelectColumns(2);
      // Strip the decrypt_stream_address() wrappers, then confirm the raw
      // column names don't appear outside of them
      const stripped = cols.replace(/decrypt_stream_address\([^)]+\) AS \w+/g, '');
      expect(stripped).not.toMatch(/\bsender_address\b/);
      expect(stripped).not.toMatch(/\brecipient_address\b/);
    });
  });

  // ── streamSelectColumns SQL shape (encryption DISABLED / no key) ──────────
  //
  // When PGCRYPTO_KEY is absent the repository layer throws before any SQL is
  // built (resolvePgcryptoKeys fails closed).  These tests confirm the SQL
  // helper itself still produces a consistent structure regardless of caller
  // choice of param index, so the helper is not the source of silent failures.

  describe('streamSelectColumns — encryption disabled (helper-level contract)', () => {
    it('still produces a decrypt_stream_address wrapper regardless of key index value', () => {
      // Even if a caller somehow passed an arbitrary index, the SQL shape
      // is deterministic — decryption is always attempted in SQL.
      // The guard against missing keys lives in resolvePgcryptoKeys(), not here.
      const cols = streamSelectColumns(99);
      expect(cols).toContain('decrypt_stream_address(sender_address, $99, NULL)');
      expect(cols).toContain('decrypt_stream_address(recipient_address, $99, NULL)');
    });

    it('is a pure function — same inputs always produce the same SQL fragment', () => {
      expect(streamSelectColumns(2)).toBe(streamSelectColumns(2));
      expect(streamSelectColumns(2, 3)).toBe(streamSelectColumns(2, 3));
      expect(streamSelectColumns(2)).not.toBe(streamSelectColumns(2, 3));
    });
  });
});

// ── Key validation (legal-hold + failure-recovery prerequisites) ────────────

describe('PGCrypto key validation', () => {
  it('rejects non-string keys', () => {
    expect(validatePgcryptoKey(null as unknown as string)).toEqual({
      valid: false,
      reason: 'key must be a string',
    });
    expect(validatePgcryptoKey(123 as unknown as string)).toEqual({
      valid: false,
      reason: 'key must be a string',
    });
  });

  it('rejects keys shorter than PGCRYPTO_KEY_MIN_LENGTH', () => {
    const short = 'a'.repeat(31);
    const result = validatePgcryptoKey(short);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('at least 32 characters');
    expect(result.reason).toContain('got 31');
  });

  it('accepts keys exactly at PGCRYPTO_KEY_MIN_LENGTH boundary', () => {
    const boundary = 'k'.repeat(PGCRYPTO_KEY_MIN_LENGTH);
    expect(validatePgcryptoKey(boundary)).toEqual({ valid: true });
  });

  it('accepts keys longer than PGCRYPTO_KEY_MIN_LENGTH', () => {
    const longKey = 'x'.repeat(64);
    expect(validatePgcryptoKey(longKey)).toEqual({ valid: true });
  });

  it('validates keyset with current+previous independently', () => {
    const good = 'a'.repeat(32);
    const bad = 'short';
    const validBoth = validatePgcryptoKeySet({ current: good, previous: good });
    expect(validBoth.current.valid).toBe(true);
    expect(validBoth.previous?.valid).toBe(true);

    const badPrevious = validatePgcryptoKeySet({ current: good, previous: bad });
    expect(badPrevious.current.valid).toBe(true);
    expect(badPrevious.previous?.valid).toBe(false);

    const noPrev = validatePgcryptoKeySet({ current: good });
    expect(noPrev.current.valid).toBe(true);
    expect(noPrev.previous).toBeUndefined();
  });
});

// ── Encryption state detection ──────────────────────────────────────────────

describe('Encryption state detection (plaintext / encrypted / redacted / mismatch)', () => {
  const address = 'GDRXE2BQUC3AZ7D3G7BMNJ4XOSXHG6YKO4IZ3Y4S7HNW3F4AWMRI6ZIY';
  const key = 'a'.repeat(32);
  const previousKey = 'b'.repeat(32);
  const keys: PgcryptoKeySet = { current: key, previous: previousKey };
  const ciphertext = PGP_MESSAGE_PREFIX + '...ciphertext_blob...';

  it('classifies a null value as REDACTED (tombstone written)', () => {
    expect(
      detectAddressEncryptionState(null, null, keys)
    ).toBe(AddressEncryptionState.REDACTED);
  });

  it('classifies a GDPR tombstone with null hash as REDACTED', () => {
    expect(
      detectAddressEncryptionState(DEFAULT_ERASURE_TOMBSTONE, null, keys)
    ).toBe(AddressEncryptionState.REDACTED);
  });

  it('classifies a retention tombstone with null hash as REDACTED', () => {
    expect(
      detectAddressEncryptionState('[REDACTED:DATA_RETENTION]', null, keys)
    ).toBe(AddressEncryptionState.REDACTED);
  });

  it('classifies tombstone with non-null hash as HASH_MISMATCH (invariant violation)', () => {
    const leftoverHash = computeAddressHash(address, key);
    expect(
      detectAddressEncryptionState(DEFAULT_ERASURE_TOMBSTONE, leftoverHash, keys)
    ).toBe(AddressEncryptionState.HASH_MISMATCH);
  });

  it('classifies a PGP-prefixed value with correct current-key hash as ENCRYPTED', () => {
    const hash = computeAddressHash(address, key);
    expect(
      detectAddressEncryptionState(ciphertext, hash, keys, address)
    ).toBe(AddressEncryptionState.ENCRYPTED);
  });

  it('classifies a PGP-prefixed value with correct previous-key hash as ENCRYPTED (key rotation)', () => {
    const prevHash = computeAddressHash(address, previousKey);
    expect(
      detectAddressEncryptionState(ciphertext, prevHash, keys, address)
    ).toBe(AddressEncryptionState.ENCRYPTED);
  });

  it('classifies PGP-prefixed value with empty hash as HASH_MISMATCH (backfill incomplete)', () => {
    expect(
      detectAddressEncryptionState(ciphertext, '', keys, address)
    ).toBe(AddressEncryptionState.HASH_MISMATCH);
  });

  it('classifies PGP-prefixed value with stale hash as HASH_MISMATCH', () => {
    const wrongHash = computeAddressHash('different-address', key);
    expect(
      detectAddressEncryptionState(ciphertext, wrongHash, keys, address)
    ).toBe(AddressEncryptionState.HASH_MISMATCH);
  });

  it('classifies a plaintext value with matching hash as PLAINTEXT (legacy row)', () => {
    const hash = computeAddressHash(address, key);
    expect(
      detectAddressEncryptionState(address, hash, keys, address)
    ).toBe(AddressEncryptionState.PLAINTEXT);
  });

  it('classifies a plaintext value without a hash as PLAINTEXT (pre-migration row)', () => {
    expect(
      detectAddressEncryptionState(address, '', keys, address)
    ).toBe(AddressEncryptionState.PLAINTEXT);
  });

  it('classifies plaintext value with mismatched hash as HASH_MISMATCH', () => {
    const wrongHash = computeAddressHash('wrong-address', key);
    expect(
      detectAddressEncryptionState(address, wrongHash, keys, address)
    ).toBe(AddressEncryptionState.HASH_MISMATCH);
  });

  it('isPgpEncrypted returns true only for PGP-prefixed strings', () => {
    expect(isPgpEncrypted(ciphertext)).toBe(true);
    expect(isPgpEncrypted(address)).toBe(false);
    expect(isPgpEncrypted(null)).toBe(false);
    expect(isPgpEncrypted(undefined)).toBe(false);
    expect(isPgpEncrypted(DEFAULT_ERASURE_TOMBSTONE)).toBe(false);
  });

  it('isRedactedTombstone recognises both GDPR and retention tombstones', () => {
    expect(isRedactedTombstone(DEFAULT_ERASURE_TOMBSTONE)).toBe(true);
    expect(isRedactedTombstone('[REDACTED:DATA_RETENTION]')).toBe(true);
    expect(isRedactedTombstone(address)).toBe(false);
    expect(isRedactedTombstone(null)).toBe(false);
  });
});

// ── redactPiiForAddress — legal-hold, encrypted, partial, key-failure cases ─

interface MockDbRow {
  id: string;
  sender_address: string | null;
  recipient_address: string | null;
  sender_address_hash: string | null;
  recipient_address_hash: string | null;
  legal_hold: boolean;
}

function createMockExecutor(initialRows: MockDbRow[]) {
  const rows: MockDbRow[] = initialRows.map((r) => ({ ...r }));
  const queries: { sql: string; params: unknown[] }[] = [];

  const executor = {
    query: vi.fn(async (sql: string, params?: unknown[]) => {
      queries.push({ sql, params: params ?? [] });
      const trimmed = sql.trim();

      if (trimmed.startsWith('SELECT') && /COUNT\(\*\)/.test(trimmed)) {
        const purgeable = rows.filter((r) => matchesAddress(r, params!, 'purgeable')).length;
        const held = rows.filter((r) => matchesAddress(r, params!, 'held')).length;
        return { rows: [{ purgeable: String(purgeable), held: String(held) }] };
      }

      if (trimmed.startsWith('UPDATE streams')) {
        let updated = 0;
        for (const r of rows) {
          if (matchesAddress(r, params!, 'purgeable') && !r.legal_hold) {
            r.sender_address = params![0] as string;
            r.recipient_address = params![0] as string;
            r.sender_address_hash = null;
            r.recipient_address_hash = null;
            updated++;
          }
        }
        return { rowCount: updated, rows: [] };
      }

      return { rows: [], rowCount: 0 };
    }),
    getRows: () => rows.map((r) => ({ ...r })),
    getQueries: () => queries,
  };
  return executor;
}

function matchesAddress(r: MockDbRow, params: unknown[], mode: 'purgeable' | 'held'): boolean {
  if (mode === 'held' && !r.legal_hold) return false;
  if (mode === 'purgeable' && r.legal_hold) return false;

  const plaintext = params[1] as string;
  const senderHashCur = params[2] as string | undefined;
  const recipientHashCur = params[3] as string | undefined;
  const senderHashPrev = params[4] as string | undefined;
  const recipientHashPrev = params[5] as string | undefined;

  if (r.sender_address === plaintext) return true;
  if (r.recipient_address === plaintext) return true;

  if (senderHashCur !== undefined && r.sender_address_hash === senderHashCur) return true;
  if (recipientHashCur !== undefined && r.recipient_address_hash === recipientHashCur) return true;
  if (senderHashPrev !== undefined && r.sender_address_hash === senderHashPrev) return true;
  if (recipientHashPrev !== undefined && r.recipient_address_hash === recipientHashPrev) return true;

  return false;
}

describe('redactPiiForAddress — legal-hold precedence & encrypted-row discovery', () => {
  const target = 'GDRXE2BQUC3AZ7D3G7BMNJ4XOSXHG6YKO4IZ3Y4S7HNW3F4AWMRI6ZIY';
  const other = 'GASTNVUEZKYVTYOOBPECMTCZ2PJG7K4K6B4HMLU345I6RSZ5PME4Z5LL';
  const key = 'a'.repeat(32);
  const previousKey = 'b'.repeat(32);
  const keys: PgcryptoKeySet = { current: key, previous: previousKey };
  const ciphertext = PGP_MESSAGE_PREFIX + 'encrypted_blob_for_tests';
  const targetHashCur = computeAddressHash(target, key);
  const targetHashPrev = computeAddressHash(target, previousKey);
  const tombstone = DEFAULT_ERASURE_TOMBSTONE;

  it('erases plaintext legacy rows without keys (backward compatibility)', async () => {
    const exec = createMockExecutor([
      {
        id: '1',
        sender_address: other,
        recipient_address: target,
        sender_address_hash: '',
        recipient_address_hash: '',
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone);
    expect(result.rowsErased).toBe(1);
    expect(result.rowsSkippedLegalHold).toBe(0);
    expect(result.viaPlaintextMatch).toBe(1);
    expect(result.viaHashMatch).toBe(0);
    const after = exec.getRows()[0]!;
    expect(after.sender_address).toBe(tombstone);
    expect(after.recipient_address).toBe(tombstone);
    expect(after.sender_address_hash).toBeNull();
    expect(after.recipient_address_hash).toBeNull();
  });

  it('discovers and erases ENCRYPTED rows via current-key hash lookup (critical: prev bug would skip these)', async () => {
    const exec = createMockExecutor([
      {
        id: 'enc-1',
        sender_address: ciphertext,
        recipient_address: ciphertext,
        sender_address_hash: computeAddressHash(other, key),
        recipient_address_hash: targetHashCur,
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(1);
    expect(result.viaHashMatch).toBeGreaterThanOrEqual(1);
    const after = exec.getRows()[0]!;
    expect(after.recipient_address).toBe(tombstone);
    expect(after.recipient_address_hash).toBeNull();
  });

  it('discovers ENCRYPTED rows via previous-key hash (key-rotation support)', async () => {
    const exec = createMockExecutor([
      {
        id: 'rot-1',
        sender_address: ciphertext,
        recipient_address: ciphertext,
        sender_address_hash: targetHashPrev,
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(1);
  });

  it('PARTIALLY_ENCRYPTED rows: plaintext sender, encrypted recipient → both redacted', async () => {
    const exec = createMockExecutor([
      {
        id: 'partial-1',
        sender_address: target,
        recipient_address: ciphertext,
        sender_address_hash: targetHashCur,
        recipient_address_hash: targetHashCur,
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(1);
    const after = exec.getRows()[0]!;
    expect(after.sender_address).toBe(tombstone);
    expect(after.recipient_address).toBe(tombstone);
    expect(after.sender_address_hash).toBeNull();
    expect(after.recipient_address_hash).toBeNull();
  });

  it('LEGAL_HOLD precedence: held row is never redacted even if plaintext matches', async () => {
    const exec = createMockExecutor([
      {
        id: 'hold-1',
        sender_address: target,
        recipient_address: other,
        sender_address_hash: targetHashCur,
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: true,
      },
      {
        id: 'free-1',
        sender_address: target,
        recipient_address: other,
        sender_address_hash: targetHashCur,
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(1);
    expect(result.rowsSkippedLegalHold).toBe(1);

    const rows = exec.getRows();
    const held = rows.find((r) => r.id === 'hold-1')!;
    const free = rows.find((r) => r.id === 'free-1')!;
    // Held row MUST be untouched
    expect(held.sender_address).toBe(target);
    expect(held.sender_address_hash).toBe(targetHashCur);
    // Non-held row MUST be redacted
    expect(free.sender_address).toBe(tombstone);
    expect(free.sender_address_hash).toBeNull();
  });

  it('LEGAL_HOLD precedence: held ENCRYPTED row counted but never overwritten', async () => {
    const exec = createMockExecutor([
      {
        id: 'enc-held',
        sender_address: ciphertext,
        recipient_address: ciphertext,
        sender_address_hash: targetHashCur,
        recipient_address_hash: targetHashCur,
        legal_hold: true,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(0);
    expect(result.rowsSkippedLegalHold).toBe(1);
    const row = exec.getRows()[0]!;
    expect(row.sender_address).toBe(ciphertext);
    expect(row.sender_address_hash).toBe(targetHashCur);
  });

  it('HASH_MISMATCH row (encrypted but wrong hash): still matched via hash or plaintext, redacted with hash cleared', async () => {
    const wrongHash = computeAddressHash(other, key);
    const exec = createMockExecutor([
      {
        id: 'mismatch-1',
        sender_address: ciphertext,
        recipient_address: target,
        sender_address_hash: wrongHash,
        recipient_address_hash: '',
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(1);
    const after = exec.getRows()[0]!;
    expect(after.recipient_address).toBe(tombstone);
    expect(after.recipient_address_hash).toBeNull();
    expect(after.sender_address).toBe(tombstone);
    expect(after.sender_address_hash).toBeNull();
  });

  it('already-redacted rows are not re-matched (idempotency)', async () => {
    const exec = createMockExecutor([
      {
        id: 'done-1',
        sender_address: tombstone,
        recipient_address: tombstone,
        sender_address_hash: null,
        recipient_address_hash: null,
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(0);
    expect(result.rowsSkippedLegalHold).toBe(0);
  });

  it('FAILED-KEY scenario: when no keys supplied, falls back to plaintext-only match (legacy safety)', async () => {
    const exec = createMockExecutor([
      {
        id: 'plain',
        sender_address: target,
        recipient_address: other,
        sender_address_hash: targetHashCur,
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: false,
      },
      {
        id: 'enc-invisible-without-keys',
        sender_address: ciphertext,
        recipient_address: ciphertext,
        sender_address_hash: targetHashCur,
        recipient_address_hash: targetHashCur,
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone);
    expect(result.rowsErased).toBe(1);
    expect(result.viaPlaintextMatch).toBe(1);
    expect(result.viaHashMatch).toBe(0);
    const rows = exec.getRows();
    const plain = rows.find((r) => r.id === 'plain')!;
    const encRow = rows.find((r) => r.id === 'enc-invisible-without-keys')!;
    expect(plain.sender_address).toBe(tombstone);
    // Encrypted row MUST NOT be matched without keys (caller opt-in semantics preserved)
    expect(encRow.sender_address).toBe(ciphertext);
  });

  it('mixed set: held + encrypted + plaintext all reported correctly (audit evidence)', async () => {
    const exec = createMockExecutor([
      {
        id: 'a',
        sender_address: target,
        recipient_address: other,
        sender_address_hash: targetHashCur,
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: false,
      },
      {
        id: 'b',
        sender_address: ciphertext,
        recipient_address: ciphertext,
        sender_address_hash: targetHashCur,
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: false,
      },
      {
        id: 'c',
        sender_address: other,
        recipient_address: ciphertext,
        sender_address_hash: computeAddressHash(other, key),
        recipient_address_hash: targetHashPrev,
        legal_hold: false,
      },
      {
        id: 'd-held',
        sender_address: target,
        recipient_address: ciphertext,
        sender_address_hash: targetHashCur,
        recipient_address_hash: targetHashCur,
        legal_hold: true,
      },
      {
        id: 'e-other',
        sender_address: other,
        recipient_address: other,
        sender_address_hash: computeAddressHash(other, key),
        recipient_address_hash: computeAddressHash(other, key),
        legal_hold: false,
      },
    ]);
    const result = await redactPiiForAddress(exec, target, tombstone, keys);
    expect(result.rowsErased).toBe(3);
    expect(result.rowsSkippedLegalHold).toBe(1);
    expect(result.rowsErased + result.rowsSkippedLegalHold).toBe(4);

    const d = exec.getRows().find((r) => r.id === 'd-held')!;
    expect(d.sender_address).toBe(target);
    expect(d.legal_hold).toBe(true);
    const e = exec.getRows().find((r) => r.id === 'e-other')!;
    expect(e.sender_address).toBe(other);
  });
});
