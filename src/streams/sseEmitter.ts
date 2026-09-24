import { EventEmitter } from 'node:events';

import type { StreamEventRecord } from '../db/types.js';
import {
  sseLiveSubscribersGauge,
  sseEventListenersGauge,
  sseSubscriberErrorsTotal,
  sseBackpressureDropsTotal,
} from '../metrics/businessMetrics.js';
import { logger } from '../lib/logger.js';

export const SSE_STREAM_UPDATE_EVENT = 'stream_update';

/**
 * The SSE event type emitted for deliberate server-side connection closure.
 *
 * Clients that receive `event: close` should inspect `data.reason` to decide
 * whether to reconnect immediately (e.g. `max_duration`) or back off
 * (e.g. `server_shutdown`).  This string is the single source of truth — both
 * the emitter (`streams.ts`) and the test suite import it from here.
 *
 * @security The payload carries only the reason enum — no stream data or user
 *   information is included.
 */
export const SSE_CLOSE_EVENT = 'close';

/**
 * Canonical reason strings embedded in the `event: close` data payload.
 * Keeping them here prevents silent divergence between the route and tests.
 */
export const SSE_CLOSE_REASONS = {
  /** The connection reached its configured max-duration limit. */
  MAX_DURATION: 'max_duration',
  /** The server is shutting down and instructing clients to stop reconnecting. */
  SERVER_SHUTDOWN: 'server_shutdown',
  /** The connection's per-connection buffer exceeded the backpressure cap. */
  BACKPRESSURE: 'backpressure',
} as const;

export type SseCloseReason = (typeof SSE_CLOSE_REASONS)[keyof typeof SSE_CLOSE_REASONS];

/**
 * Maximum number of events buffered per SSE connection before backpressure drop.
 *
 * When a slow consumer's buffer exceeds this threshold, the connection is
 * severed with a `backpressure` close reason to prevent unbounded memory
 * growth (DoS vector). Clients should reconnect with exponential backoff.
 *
 * Default: 1000 events. Override via `SSE_MAX_BUFFERED_EVENTS` env var.
 */
export const SSE_MAX_BUFFERED_EVENTS = parseInt(
  process.env.SSE_MAX_BUFFERED_EVENTS || '1000',
  10,
);

// Central EventEmitter to handle SSE broadcast subscriptions locally.
export const sseEventBus = new EventEmitter();

// Defensive baseline for non-route listeners. Live SSE route fan-out below uses
// one shared dispatcher listener, so EventEmitter listener count does not grow
// linearly with active SSE connections.
sseEventBus.setMaxListeners(1000);

export interface LiveSseStreamUpdateEvent {
  streamId: string;
  eventId: string;
  payload: unknown;
  correlationId?: string;
}

export type SseStreamSubscriber = (event: LiveSseStreamUpdateEvent) => void;

// ── Per-stream event ring buffer ───────────────────────────────────────────────

/**
 * Maximum number of recent events retained per stream in the in-process ring
 * buffer. Events older than this cap are evicted (oldest first).
 *
 * This bounds memory at `SSE_REPLAY_BUFFER_SIZE × (average event size)` per
 * active stream. At ~1 KB per event the default 200-event cap costs at most
 * ~200 KB per stream, which is acceptable given the O(1) eviction policy.
 *
 * Override via `SSE_REPLAY_BUFFER_SIZE` env var (positive integer).
 */
export const SSE_REPLAY_BUFFER_SIZE = (() => {
  const raw = parseInt(process.env.SSE_REPLAY_BUFFER_SIZE ?? '200', 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 200;
})();

/**
 * Thrown when a client resumes with a `Last-Event-ID` that has already been
 * evicted from the ring buffer. The client must re-fetch full stream state
 * rather than attempting incremental resumption.
 *
 * The route handler surfaces this as an `event: error` SSE frame with code
 * `SSE_REPLAY_EXPIRED` so clients can distinguish it from other errors and
 * fall through to the persistent event store.
 */
export class SseReplayExpiredError extends Error {
  readonly code = 'SSE_REPLAY_EXPIRED' as const;
  constructor(public readonly afterEventId: string) {
    super(
      `Replay cursor '${afterEventId}' is beyond the in-process retention window; ` +
      `resync from the event store`,
    );
    this.name = 'SseReplayExpiredError';
  }
}

/** Ring buffer keyed by streamId, storing recent live events in insertion order. */
const replayBufferByStreamId = new Map<string, LiveSseStreamUpdateEvent[]>();

/**
 * Append a live event to the per-stream ring buffer, evicting the oldest entry
 * when the buffer is full. O(1) amortized: eviction is a single `shift()` on
 * a pre-bounded array.
 *
 * Called by `dispatchLiveSseEvent` before fan-out, so the event is always
 * in the buffer before any subscriber callback can observe it.
 */
function bufferLiveEvent(event: LiveSseStreamUpdateEvent): void {
  let buf = replayBufferByStreamId.get(event.streamId);
  if (!buf) {
    buf = [];
    replayBufferByStreamId.set(event.streamId, buf);
  }
  buf.push(event);
  if (buf.length > SSE_REPLAY_BUFFER_SIZE) {
    buf.shift(); // evict oldest
  }
}

/**
 * Return all buffered events for `streamId` that were emitted strictly after
 * the event identified by `afterEventId`, in emission order.
 *
 * @throws {SseReplayExpiredError} when `afterEventId` is not present in the
 *   buffer — it has been evicted and the client must resync from the persistent
 *   event store.
 *
 * Returns an empty array (no error) when `afterEventId` is the most recent
 * buffered event — there are no new events to replay.
 */
export function replayFromBuffer(
  streamId: string,
  afterEventId: string,
): LiveSseStreamUpdateEvent[] {
  const buf = replayBufferByStreamId.get(streamId);

  // No buffer → either the stream has never emitted in this process lifetime,
  // or the process was restarted. Treat as expiry so callers fall through to
  // the persistent event store.
  if (!buf || buf.length === 0) {
    throw new SseReplayExpiredError(afterEventId);
  }

  const idx = buf.findIndex((e) => e.eventId === afterEventId);
  if (idx === -1) {
    throw new SseReplayExpiredError(afterEventId);
  }

  // Everything strictly after the cursor position.
  return buf.slice(idx + 1);
}

// ── Live subscriber fan-out ───────────────────────────────────────────────────

const liveSubscribersByStreamId = new Map<string, Set<SseStreamSubscriber>>();

function totalLiveSubscriberCount(): number {
  let total = 0;
  for (const subscribers of liveSubscribersByStreamId.values()) {
    total += subscribers.size;
  }
  return total;
}

function dispatchLiveSseEvent(event: LiveSseStreamUpdateEvent): void {
  if (!event || typeof event.streamId !== 'string') return;

  // Buffer before fan-out so subscribers racing with a replay call always
  // see a consistent ordering — buffer.push happens before any subscriber
  // can observe the event, preventing a gap between replay and live delivery.
  bufferLiveEvent(event);

  const subscribers = liveSubscribersByStreamId.get(event.streamId);
  if (!subscribers || subscribers.size === 0) return;

  // Snapshot before iterating so a subscriber can disconnect during delivery
  // without mutating the Set currently being traversed.
  for (const subscriber of Array.from(subscribers)) {
    try {
      subscriber(event);
    } catch (err) {
      // Isolate one failing connection from the rest of the stream fan-out.
      sseSubscriberErrorsTotal.inc({ reason: 'subscriber_callback_throw' });

      const error = err instanceof Error ? err : new Error(String(err));

      // Security: do not log SSE payload. Only log streamId + error identity.
      logger.error('SSE subscriber callback threw', event.correlationId, {
        streamId: event.streamId,
        subscriberError: {
          name: error.name,
          message: error.message,
        },
      });
    }
  }
}

function isDispatchAttached(): boolean {
  return sseEventBus.listeners(SSE_STREAM_UPDATE_EVENT).includes(dispatchLiveSseEvent);
}

function ensureDispatchAttached(): void {
  if (!isDispatchAttached()) {
    sseEventBus.on(SSE_STREAM_UPDATE_EVENT, dispatchLiveSseEvent);
    sseEventListenersGauge.set(Math.max(0, sseEventBus.listenerCount(SSE_STREAM_UPDATE_EVENT)));
  }
}

function detachDispatchIfIdle(): void {
  if (totalLiveSubscriberCount() === 0) {
    sseEventBus.off(SSE_STREAM_UPDATE_EVENT, dispatchLiveSseEvent);
    sseEventListenersGauge.set(Math.max(0, sseEventBus.listenerCount(SSE_STREAM_UPDATE_EVENT)));
  }
}

/**
 * Register one live SSE subscriber for a stream ID.
 *
 * The process attaches exactly one listener to `sseEventBus` and multiplexes
 * live updates through an in-memory streamId -> subscriber Set. This keeps
 * EventEmitter listener count O(1) while per-event fan-out is O(number of
 * subscribers to the updated stream), not O(all active SSE connections).
 */
export function subscribeToSseStream(
  streamId: string,
  subscriber: SseStreamSubscriber,
): () => void {
  let subscribers = liveSubscribersByStreamId.get(streamId);
  if (!subscribers) {
    subscribers = new Set<SseStreamSubscriber>();
    liveSubscribersByStreamId.set(streamId, subscribers);
  }

  subscribers.add(subscriber);
  ensureDispatchAttached();
  sseLiveSubscribersGauge.set(Math.max(0, totalLiveSubscriberCount()));

  let unsubscribed = false;
  return () => {
    if (unsubscribed) return;
    unsubscribed = true;

    const current = liveSubscribersByStreamId.get(streamId);
    if (!current) return;

    current.delete(subscriber);
    if (current.size === 0) {
      liveSubscribersByStreamId.delete(streamId);
    }
    detachDispatchIfIdle();
    sseLiveSubscribersGauge.set(Math.max(0, totalLiveSubscriberCount()));
  };
}

/**
 * Options for backpressure-aware SSE subscription.
 */
export interface SseBackpressureOptions {
  /** Maximum buffered events before dropping the connection. Default: SSE_MAX_BUFFERED_EVENTS. */
  maxBufferedEvents?: number;
  /** Callback invoked when backpressure triggers a disconnect. Use to send close event and end response. */
  onBackpressureDrop?: (reason: SseCloseReason) => void;
}

/**
 * Register a live SSE subscriber with per-connection backpressure protection.
 *
 * Wraps the subscriber callback with a buffer counter. When the buffer exceeds
 * `maxBufferedEvents`, the connection is dropped via `onBackpressureDrop` and
 * the `sseBackpressureDropsTotal` metric is incremented.
 */
export function subscribeToSseStreamWithBackpressure(
  streamId: string,
  subscriber: SseStreamSubscriber,
  options: SseBackpressureOptions = {},
): () => void {
  const maxBuffered = options.maxBufferedEvents ?? SSE_MAX_BUFFERED_EVENTS;
  let bufferedCount = 0;
  let dropped = false;

  const wrappedSubscriber = (event: LiveSseStreamUpdateEvent) => {
    if (dropped) return;

    bufferedCount++;

    if (bufferedCount > maxBuffered) {
      dropped = true;
      sseBackpressureDropsTotal.inc();

      logger.warn('SSE connection dropped due to backpressure', undefined, {
        streamId,
        bufferedCount,
        maxBuffered,
      });

      options.onBackpressureDrop?.(SSE_CLOSE_REASONS.BACKPRESSURE);
      return;
    }

    try {
      subscriber(event);
      bufferedCount--; // Only decrement on successful delivery
    } catch (err) {
      // Don't decrement — event is still buffered (not drained by slow consumer).
      // Re-throw so upstream error handling (sseSubscriberErrorsTotal) fires.
      throw err;
    }
  };

  return subscribeToSseStream(streamId, wrappedSubscriber);
}

export function getLiveSseSubscriberCount(streamId?: string): number {
  if (streamId !== undefined) {
    return liveSubscribersByStreamId.get(streamId)?.size ?? 0;
  }
  return totalLiveSubscriberCount();
}

// ── Shutdown drain ────────────────────────────────────────────────────────────

interface SseShutdownEntry {
  drain: () => void | Promise<void>;
  forceClose?: (() => void) | undefined;
}

/**
 * Callbacks registered by active SSE response handlers. Each entry holds a
 * drain callback (writes retry:0 and gracefully ends the response) and an
 * optional forceClose callback (destroys the underlying socket) for when
 * the per-connection drain timeout is exceeded.
 */
const sseShutdownCallbacks = new Set<SseShutdownEntry>();

/**
 * Register a shutdown callback for an active SSE response.
 * The returned deregister function must be called when the connection closes
 * normally so the Set does not grow unboundedly.
 */
export function registerSseShutdownCallback(
  drain: () => void | Promise<void>,
  forceClose?: () => void,
): () => void {
  const entry: SseShutdownEntry = { drain, forceClose };
  sseShutdownCallbacks.add(entry);
  return () => sseShutdownCallbacks.delete(entry);
}

/**
 * Run a single callback with a timeout; returns whether it completed before
 * the deadline. Uses Promise.race so a settled guard prevents forceClose from
 * firing after a successful drain and vice versa.
 */
async function raceDrainCallback(
  drain: () => void | Promise<void>,
  forceClose: (() => void) | undefined,
  timeoutMs: number,
): Promise<boolean> {
  let settled = false;

  const drainPromise = (async () => {
    try {
      await drain();
    } catch {
      // Isolate a single failing response from the rest of the drain.
    }
    if (!settled) {
      settled = true;
      return true;
    }
    return true;
  })();

  const timeoutPromise = new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      forceClose?.();
      resolve(false);
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
  });

  return Promise.race([drainPromise, timeoutPromise]);
}

/**
 * Drain all open SSE connections on shutdown.
 *
 * Each registered SSE connection is given up to `timeoutMs` to write a
 * `retry: 0` directive and end gracefully. Connections that do not complete
 * within the per-stream budget are force-closed via their forceClose callback.
 *
 * After all connections are drained, the shared dispatch listener, subscriber
 * state, and replay buffers are torn down.
 */
export async function drainSseEventBus(timeoutMs: number): Promise<void> {
  const entries = Array.from(sseShutdownCallbacks);
  let forceClosed = 0;

  for (const entry of entries) {
    const completed = await raceDrainCallback(entry.drain, entry.forceClose, timeoutMs);
    if (!completed) {
      forceClosed++;
    }
  }

  sseShutdownCallbacks.clear();

  if (forceClosed > 0) {
    logger.warn('SSE connections force-closed during shutdown drain', undefined, {
      forceClosed,
      total: entries.length,
      timeoutMs,
    });
  }

  // Tear down the shared dispatcher and replay state.
  liveSubscribersByStreamId.clear();
  replayBufferByStreamId.clear();
  sseEventBus.off(SSE_STREAM_UPDATE_EVENT, dispatchLiveSseEvent);
  sseLiveSubscribersGauge.set(0);
  sseEventListenersGauge.set(0);
}

export function _resetSseSubscriptionsForTest(): void {
  liveSubscribersByStreamId.clear();
  replayBufferByStreamId.clear();
  sseEventBus.off(SSE_STREAM_UPDATE_EVENT, dispatchLiveSseEvent);
  sseShutdownCallbacks.clear();
  sseLiveSubscribersGauge.set(0);
  sseEventListenersGauge.set(0);
}

/**
 * Derive the canonical stream ID from the chain-level identifiers used by the
 * ingestion path.
 *
 * Format: `stream-{transactionHash}-{eventIndex}`
 *
 * This is the single source of truth for stream ID derivation. Both the SSE
 * matching logic and the ingestion service (`streamEventService`) must import
 * and call this helper so that the format cannot silently diverge.
 */
export function deriveStreamId(transactionHash: string, eventIndex: number): string {
  return `stream-${transactionHash}-${eventIndex}`;
}

/**
 * Checks if a historical or live StreamEventRecord belongs to a specific stream ID.
 *
 * Matching strategy (first match wins):
 * 1. Explicit `id` or `streamId` field inside the event payload.
 * 2. Canonical derivation via `deriveStreamId(event.txHash, event.eventIndex)`.
 */
export function eventMatchesStreamId(event: StreamEventRecord, id: string): boolean {
  if (!event || !id) return false;

  const payload = event.payload;
  if (payload) {
    if (payload.id === id || payload.streamId === id) {
      return true;
    }
  }

  if (event.txHash && typeof event.eventIndex === 'number') {
    if (deriveStreamId(event.txHash, event.eventIndex) === id) return true;
  }

  return false;
}
