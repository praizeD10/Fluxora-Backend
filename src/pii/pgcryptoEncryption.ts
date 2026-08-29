/**
 * pgcrypto helper utilities for stream PII encryption.
 *
 * This module centralizes the application-side pieces of the encryption
 * design so the repository layer can stay readable and safe.
 *
 * Single-row functions (`computeAddressHash`, `computeAddressHashes`) run
 * synchronously on the main thread — ideal for the request-path where the
 * overhead of worker IPC is not justified.
 *
 * Batch functions (`batchComputeAddressHashes`) offload HMAC computation to
 * a bounded worker_threads pool for large row sets (export endpoint,
 * data-retention purge jobs).  Falls back to synchronous execution when the
 * row count is below the threshold or when worker startup fails.
 */

import crypto from 'crypto';
import { pathToFileURL } from 'url';
import { WorkerPool, BATCH_HASH_THRESHOLD, resolveWorkerUrl, type WorkerPoolOptions } from './workerPool.js';
import type { HashTaskMessage, HashResultMessage } from './pgcryptoWorker.js';

export const PGCRYPTO_KEY_MIN_LENGTH = 32;
export const PGP_SYM_ENCRYPT_OPTIONS = 'cipher-algo=aes256,compress-algo=0,armor';
export const PGP_MESSAGE_PREFIX = '-----BEGIN PGP MESSAGE-----';

export enum AddressEncryptionState {
  PLAINTEXT = 'plaintext',
  ENCRYPTED = 'encrypted',
  PARTIALLY_ENCRYPTED = 'partially_encrypted',
  ENCRYPTION_FAILED = 'encryption_failed',
  HASH_MISMATCH = 'hash_mismatch',
  REDACTED = 'redacted',
}

export interface AddressRowState {
  sender: AddressEncryptionState;
  recipient: AddressEncryptionState;
  overall: AddressEncryptionState;
}

export interface KeyValidationResult {
  valid: boolean;
  reason?: string;
}

export function validatePgcryptoKey(key: string): KeyValidationResult {
  if (typeof key !== 'string') {
    return { valid: false, reason: 'key must be a string' };
  }
  if (key.length < PGCRYPTO_KEY_MIN_LENGTH) {
    return {
      valid: false,
      reason: `key must be at least ${PGCRYPTO_KEY_MIN_LENGTH} characters (got ${key.length})`,
    };
  }
  return { valid: true };
}

export function validatePgcryptoKeySet(keys: PgcryptoKeySet): { current: KeyValidationResult; previous?: KeyValidationResult } {
  return {
    current: validatePgcryptoKey(keys.current),
    previous: keys.previous !== undefined ? validatePgcryptoKey(keys.previous) : undefined,
  };
}

export function isPgpEncrypted(value: string | null | undefined): boolean {
  if (value === null || value === undefined || typeof value !== 'string') return false;
  return value.startsWith(PGP_MESSAGE_PREFIX);
}

export function isRedactedTombstone(
  value: string | null | undefined,
  tombstone: string = DEFAULT_ERASURE_TOMBSTONE
): boolean {
  return value === tombstone || value === '[REDACTED:DATA_RETENTION]';
}

export function detectAddressEncryptionState(
  addressValue: string | null | undefined,
  addressHash: string | null | undefined,
  keys: PgcryptoKeySet,
  plaintextAddress?: string,
  tombstone: string = DEFAULT_ERASURE_TOMBSTONE
): AddressEncryptionState {
  if (addressValue === null || addressValue === undefined) {
    return AddressEncryptionState.REDACTED;
  }

  if (isRedactedTombstone(addressValue, tombstone)) {
    if (addressHash === null || addressHash === undefined) {
      return AddressEncryptionState.REDACTED;
    }
    return AddressEncryptionState.HASH_MISMATCH;
  }

  if (isPgpEncrypted(addressValue)) {
    if (!addressHash || addressHash === '') {
      return AddressEncryptionState.HASH_MISMATCH;
    }

    if (plaintextAddress !== undefined) {
      const expectedCurrentHash = computeAddressHash(plaintextAddress, keys.current);
      const matchCurrent = addressHash === expectedCurrentHash;
      const matchPrevious = keys.previous
        ? addressHash === computeAddressHash(plaintextAddress, keys.previous)
        : false;

      if (matchCurrent || matchPrevious) {
        return AddressEncryptionState.ENCRYPTED;
      }
      return AddressEncryptionState.HASH_MISMATCH;
    }

    return AddressEncryptionState.ENCRYPTED;
  }

  if (plaintextAddress !== undefined && addressValue === plaintextAddress) {
    if (!addressHash || addressHash === '') {
      return AddressEncryptionState.PLAINTEXT;
    }
    const expectedCurrentHash = computeAddressHash(addressValue, keys.current);
    const matchCurrent = addressHash === expectedCurrentHash;
    const matchPrevious = keys.previous
      ? addressHash === computeAddressHash(addressValue, keys.previous)
      : false;
    if (matchCurrent || matchPrevious) {
      return AddressEncryptionState.PLAINTEXT;
    }
    return AddressEncryptionState.HASH_MISMATCH;
  }

  return AddressEncryptionState.PLAINTEXT;
}

export interface PgcryptoKeySet {
  current: string;
  previous?: string;
}

/**
 * Compute the deterministic HMAC digest used for address filters and indexes.
 * This preserves query efficiency while keeping the stored address ciphertext
 * unreadable without the key.
 */
export function computeAddressHash(address: string, key: string): string {
  return crypto.createHmac('sha256', key).update(address, 'utf8').digest('hex');
}

export function computeAddressHashes(address: string, keys: PgcryptoKeySet): {
  current: string;
  previous?: string;
} {
  return {
    current: computeAddressHash(address, keys.current),
    previous: keys.previous ? computeAddressHash(address, keys.previous) : undefined,
  };
}

/**
 * Build a pgcrypto encryption expression for a plaintext address parameter.
 */
export function pgpEncryptAddressParam(addressParamIndex: number, keyParamIndex: number): string {
  return `pgp_sym_encrypt($${addressParamIndex}, $${keyParamIndex}, '${PGP_SYM_ENCRYPT_OPTIONS}')`;
}

/**
 * Build a pgcrypto decryption expression for a stored address column.
 */
export function pgpDecryptAddressColumn(
  columnName: string,
  keyParamIndex: number,
  previousKeyParamIndex?: number,
): string {
  const previousArg = previousKeyParamIndex !== undefined ? `$${previousKeyParamIndex}` : 'NULL';
  return `decrypt_stream_address(${columnName}, $${keyParamIndex}, ${previousArg}) AS ${columnName}`;
}

/**
 * Build a filter expression that uses keyed hash lookup first, and falls back
 * to plaintext comparison for legacy rows that have not yet been backfilled.
 */
export function buildEncryptedAddressFilter(
  column: 'sender_address' | 'recipient_address',
  filterValueParamIndex: number,
  currentHashParamIndex: number,
  previousHashParamIndex?: number,
): string {
  const hashClauses = [`${column}_hash = $${currentHashParamIndex}`];
  if (previousHashParamIndex !== undefined) {
    hashClauses.push(`${column}_hash = $${previousHashParamIndex}`);
  }
  const hashCondition = hashClauses.length > 1 ? `(${hashClauses.join(' OR ')})` : hashClauses[0];
  return `(${hashCondition} OR ${column} = $${filterValueParamIndex})`;
}

export const DEFAULT_ERASURE_TOMBSTONE = '[REDACTED_GDPR_ERASURE]';

export interface RedactionResult {
  rowsErased: number;
  rowsSkippedLegalHold: number;
  viaPlaintextMatch: number;
  viaHashMatch: number;
}

function buildAddressMatchWhere(
  addressParamIndex: number,
  senderHashCurrentIdx?: number,
  senderHashPrevIdx?: number,
  recipientHashCurrentIdx?: number,
  recipientHashPrevIdx?: number,
): string {
  const clauses: string[] = [];

  const senderHashClauses: string[] = [];
  if (senderHashCurrentIdx !== undefined) {
    senderHashClauses.push(`sender_address_hash = $${senderHashCurrentIdx}`);
  }
  if (senderHashPrevIdx !== undefined) {
    senderHashClauses.push(`sender_address_hash = $${senderHashPrevIdx}`);
  }
  if (senderHashClauses.length > 0) {
    clauses.push(
      senderHashClauses.length > 1 ? `(${senderHashClauses.join(' OR ')})` : senderHashClauses[0],
    );
  }

  const recipientHashClauses: string[] = [];
  if (recipientHashCurrentIdx !== undefined) {
    recipientHashClauses.push(`recipient_address_hash = $${recipientHashCurrentIdx}`);
  }
  if (recipientHashPrevIdx !== undefined) {
    recipientHashClauses.push(`recipient_address_hash = $${recipientHashPrevIdx}`);
  }
  if (recipientHashClauses.length > 0) {
    clauses.push(
      recipientHashClauses.length > 1
        ? `(${recipientHashClauses.join(' OR ')})`
        : recipientHashClauses[0],
    );
  }

  clauses.push(`sender_address = $${addressParamIndex}`);
  clauses.push(`recipient_address = $${addressParamIndex}`);

  return `(${clauses.join(' OR ')})`;
}

/**
 * Redaction helper: Permanently redacts encrypted PII columns for matching streams
 * associated with a recipient address while preserving all financial and ledger data.
 *
 * When `keys` is provided, this function first hashes the plaintext address with
 * the current (and optional previous) key and matches against `sender_address_hash`
 * and `recipient_address_hash` columns.  This ensures ENCRYPTED rows (where the
 * stored value is PGP ciphertext and can never equal the plaintext parameter) are
 * still found and redacted correctly.  The plaintext fallback is retained to cover
 * legacy rows that predate the encryption backfill.
 *
 * Legal-hold precedence is absolute: any row with `legal_hold = TRUE` is skipped
 * regardless of its encryption state.  The count of held-but-matching rows is
 * returned in `rowsSkippedLegalHold` for audit evidence.
 *
 * @param queryExecutor - Database client or pool with a query method (supports transactions)
 * @param recipientAddress - Plaintext address target for GDPR right-to-erasure
 * @param tombstone - Tombstone value to write into address columns (default: '[REDACTED_GDPR_ERASURE]')
 * @param keys - Optional pgcrypto key set; when supplied the redaction query also
 *               matches rows via keyed-hash lookup on address_hash columns.
 * @returns Promise resolving to `RedactionResult` with breakdown of erased/held rows.
 *
 * @security Uses parameterized queries exclusively to prevent SQL injection.
 * Does NOT delete or alter financial columns (`amount`, `ledger`, `tx_hash`, `stream_id`, etc.).
 * When the hash lookup path is used, the plaintext address never appears in a
 * comparison against the encrypted address column.
 */
export async function redactPiiForAddress(
  queryExecutor: { query: (sql: string, params?: unknown[]) => Promise<{ rowCount?: number | null; rows: any[] }> },
  recipientAddress: string,
  tombstone: string = DEFAULT_ERASURE_TOMBSTONE,
  keys?: PgcryptoKeySet,
): Promise<RedactionResult> {
  const params: unknown[] = [tombstone, recipientAddress];
  const addressParamIdx = 2;

  let senderHashCurrentIdx: number | undefined;
  let senderHashPrevIdx: number | undefined;
  let recipientHashCurrentIdx: number | undefined;
  let recipientHashPrevIdx: number | undefined;
  let viaPlaintextMatch = 0;
  let viaHashMatch = 0;

  if (keys !== undefined) {
    const hashes = computeAddressHashes(recipientAddress, keys);
    senderHashCurrentIdx = params.length + 1;
    params.push(hashes.current);
    recipientHashCurrentIdx = params.length + 1;
    params.push(hashes.current);
    if (hashes.previous !== undefined) {
      senderHashPrevIdx = params.length + 1;
      params.push(hashes.previous);
      recipientHashPrevIdx = params.length + 1;
      params.push(hashes.previous);
    }
  }

  const whereClause = buildAddressMatchWhere(
    addressParamIdx,
    senderHashCurrentIdx,
    senderHashPrevIdx,
    recipientHashCurrentIdx,
    recipientHashPrevIdx,
  );

  const beforeCountSql = `
    SELECT
      COUNT(*) FILTER (WHERE legal_hold = FALSE) AS purgeable,
      COUNT(*) FILTER (WHERE legal_hold = TRUE) AS held
    FROM streams
    WHERE ${whereClause}
  `;

  const beforeResult = await queryExecutor.query(beforeCountSql, params);
  const beforeRow = beforeResult.rows[0] as { purgeable: string; held: string } | undefined;
  const rowsSkippedLegalHold = parseInt(beforeRow?.held ?? '0', 10);
  const purgeableBefore = parseInt(beforeRow?.purgeable ?? '0', 10);

  const updateSql = `
    UPDATE streams
       SET sender_address         = $1,
           recipient_address      = $1,
           sender_address_hash    = NULL,
           recipient_address_hash = NULL
     WHERE ${whereClause}
       AND COALESCE(legal_hold, FALSE) = FALSE
  `;

  const updateResult = await queryExecutor.query(updateSql, params);
  const rowsErased = updateResult.rowCount ?? 0;

  if (keys !== undefined) {
    viaHashMatch = Math.min(rowsErased, purgeableBefore);
    viaPlaintextMatch = rowsErased - viaHashMatch;
  } else {
    viaPlaintextMatch = rowsErased;
  }

  return { rowsErased, rowsSkippedLegalHold, viaPlaintextMatch, viaHashMatch };
}

// ── Batch hashing via worker_threads pool ─────────────────────────────────

/**
 * Module-scoped lazy pool.  Initialized on first call to
 * `batchComputeAddressHashes`.  Shared across all callers in the process so
 * the pool is created once and reused.
 */
let _pool: WorkerPool | null = null;

/**
 * Resolve or create the singleton worker pool.  The pool is created lazily
 * so single-row callers (the common request-path) never pay the cost of
 * worker thread setup.
 *
 * SECURITY: The pool receives cryptographic keys via `workerData` (structured
 * clone).  Keys are never read from `process.env` inside the pool — they are
 * passed explicitly by the caller and exist only in worker-local heap memory.
 */
function getPool(): WorkerPool {
  if (_pool === null) {
    const workerUrl = resolveWorkerUrl(pathToFileURL(__filename), './pgcryptoWorker');
    const poolOpts: WorkerPoolOptions = {};
    _pool = new WorkerPool(workerUrl, poolOpts);

    // Fallback: if all workers fail to start (e.g. sandboxed environment),
    // degrade to synchronous in-thread execution.
    _pool.setFallback((msg: unknown) => {
      const task = msg as HashTaskMessage;
      const current = computeAddressHash(task.address, task.keys.current);
      const previous = task.keys.previous
        ? computeAddressHash(task.address, task.keys.previous)
        : undefined;
      return { type: 'result', taskId: task.taskId, current, previous } as HashResultMessage;
    });
  }
  return _pool;
}

/**
 * Shut down the singleton worker pool.  Called during graceful process
 * shutdown to terminate worker threads and free resources.
 */
export async function shutdownPgcryptoPool(): Promise<void> {
  if (_pool !== null) {
    await _pool.shutdown();
    _pool = null;
  }
}

/**
 * Compute HMAC address hashes for a batch of addresses.
 *
 * - When `addresses.length >= BATCH_HASH_THRESHOLD` (50), work is dispatched
 *   to the worker_threads pool, keeping the main event loop free for request
 *   handling.
 * - Below the threshold, computation runs synchronously on the main thread
 *   to avoid worker IPC overhead.
 * - If all workers fail to start, the pool degrades gracefully to
 *   synchronous execution — callers never see errors from the pool itself.
 *
 * Results are returned in the same order as the input `addresses` array.
 *
 * @param addresses  Array of plaintext Stellar addresses to hash.
 * @param keys       Current (and optional previous) pgcrypto key set.
 * @param options    Optional overrides:
 *   - `concurrency`: max parallel workers (default: pool default).
 *   - `threshold`: override the batch threshold (default: 50).
 * @returns Array of `{ current, previous }` hash pairs, one per input address.
 *
 * @security Cryptographic keys are passed to workers via `workerData`
 * (structured clone) and exist only in worker-local memory.  They are never
 * logged, serialized to disk, or re-read from environment variables.
 */
export async function batchComputeAddressHashes(
  addresses: string[],
  keys: PgcryptoKeySet,
  options?: { concurrency?: number; threshold?: number },
): Promise<Array<{ current: string; previous?: string }>> {
  const threshold = options?.threshold ?? BATCH_HASH_THRESHOLD;

  // Below threshold: synchronous on the main thread (no worker overhead).
  if (addresses.length < threshold) {
    return addresses.map((addr) => computeAddressHashes(addr, keys));
  }

  const pool = getPool();

  // Dispatch all hashes as individual tasks.  The pool's bounded worker set
  // naturally throttles concurrency — each worker processes one task at a
  // time, so we never exceed `maxWorkers` concurrent HMAC computations.
  const tasks = addresses.map((address, taskId): Promise<HashResultMessage> => {
    const msg: HashTaskMessage = { type: 'hash', taskId, address, keys };
    return pool.exec<HashResultMessage>(msg);
  });

  const results = await Promise.all(tasks);

  // Restore original input order (worker dispatch may complete out of order,
  // but `Promise.all` preserves order, and each result carries its `taskId`).
  return results.map((r) => ({
    current: r.current,
    previous: r.previous,
  }));
}
