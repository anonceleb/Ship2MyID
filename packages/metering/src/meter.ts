/**
 * [Phase 3] Metered API — SHIP2MYID_DEMO_SPEC.md §12: "metered API" is one of
 * the four things that make the platform tier a commerce feature, not just a
 * privacy feature. A merchant integration that can call createShipment an
 * unbounded number of times is a cost and abuse surface, not a product.
 *
 * Fixed-window quota per participant. A real deployment backs this with
 * Redis (the same parity note NonceLedger's docstring makes elsewhere) —
 * this is the in-process shape that call site must satisfy.
 */
export class QuotaExceeded extends Error {}

export class UsageMeter {
  #limit: number;
  #windowMs: number;
  #windows = new Map<string, { windowStart: number; count: number }>();

  constructor(opts: { limit: number; windowMs: number }) {
    this.#limit = opts.limit;
    this.#windowMs = opts.windowMs;
  }

  /**
   * Records one call against `participantId`'s current window, starting a
   * fresh window if the previous one has elapsed. Throws QuotaExceeded
   * rather than silently letting the call through once the limit is hit.
   */
  consume(participantId: string, now = Date.now()): void {
    const w = this.#windows.get(participantId);
    if (!w || now - w.windowStart >= this.#windowMs) {
      this.#windows.set(participantId, { windowStart: now, count: 1 });
      return;
    }
    if (w.count >= this.#limit) {
      throw new QuotaExceeded(`participant ${participantId} exceeded ${this.#limit} calls per ${this.#windowMs}ms window`);
    }
    w.count += 1;
  }

  /** Calls left in the participant's current window — 0 means the next consume() throws. */
  remaining(participantId: string, now = Date.now()): number {
    const w = this.#windows.get(participantId);
    if (!w || now - w.windowStart >= this.#windowMs) return this.#limit;
    return Math.max(0, this.#limit - w.count);
  }
}
