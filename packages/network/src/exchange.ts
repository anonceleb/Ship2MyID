/**
 * [A10] Beckn-shaped async request/callback pairs — `action` / `on_action`.
 *
 * "Beckn pairs every action with a callback... because counterparties are
 * slow, batch-oriented, and occasionally offline. Postal back-ends are all
 * three. A synchronous design would work in the demo and fail on contact
 * with a real operator's overnight batch." — PRIOR_ART_REVIEW.md §2.4
 *
 * This is the primitive that shape needs: a request gets an immediate ack
 * (a transaction id), and the substantive result is delivered later, on the
 * responder's own schedule, via a distinct `callback()` call correlated by
 * that id — not by resolving the original caller's promise. Whether "later"
 * is the next tick or an operator's overnight run is invisible to this
 * class; it exists only to make that decoupling real instead of assumed.
 */
export class UnknownTransaction extends Error {}
export class DuplicateCallback extends Error {}

export type TransactionStatus = "pending" | "fulfilled" | "failed";

let counter = 0;
function nextId(): string {
  counter += 1;
  return `txn_${Date.now().toString(36)}${counter.toString(36)}`;
}

/**
 * `fail()` is the `on_action` nack half — a transaction can settle with an
 * error instead of a result (a merchant over quota, a batch step that
 * threw) without that error escaping into whatever loop is driving
 * settlement and taking unrelated transactions down with it. Before this
 * existed, the only way to report a failure was to throw out of the
 * settlement loop, which — in Platform.processBatch() — silently dropped
 * every transaction queued after the one that failed.
 */
export class AsyncExchange<TResult> {
  #status = new Map<string, TransactionStatus>();
  #results = new Map<string, TResult>();
  #errors = new Map<string, unknown>();
  #resultListeners = new Map<string, Array<(result: TResult) => void>>();
  #errorListeners = new Map<string, Array<(error: unknown) => void>>();

  /** The synchronous half: an ack that a transaction was opened, not an answer. */
  begin(): string {
    const transactionId = nextId();
    this.#status.set(transactionId, "pending");
    return transactionId;
  }

  /**
   * Subscribes to the `on_action` callback for a transaction already begun.
   * If the result already landed, the handler fires immediately — subscribing
   * is never a race against delivery. A transaction that failed instead never
   * calls this handler; use onError() for that outcome.
   */
  onCallback(transactionId: string, handler: (result: TResult) => void): void {
    if (!this.#status.has(transactionId)) throw new UnknownTransaction(transactionId);
    if (this.#status.get(transactionId) === "fulfilled") {
      handler(this.#results.get(transactionId) as TResult);
      return;
    }
    const arr = this.#resultListeners.get(transactionId) ?? [];
    arr.push(handler);
    this.#resultListeners.set(transactionId, arr);
  }

  /** Subscribes to the nack half. Fires immediately if the transaction already failed. */
  onError(transactionId: string, handler: (error: unknown) => void): void {
    if (!this.#status.has(transactionId)) throw new UnknownTransaction(transactionId);
    if (this.#status.get(transactionId) === "failed") {
      handler(this.#errors.get(transactionId));
      return;
    }
    const arr = this.#errorListeners.get(transactionId) ?? [];
    arr.push(handler);
    this.#errorListeners.set(transactionId, arr);
  }

  /**
   * The `on_action` half — delivered whenever the counterparty is ready.
   * Exactly once per transaction: a network can redeliver a message, but a
   * second, distinct result for the same transaction is a protocol
   * violation, not a retry, so this throws rather than silently
   * overwriting the first answer.
   */
  callback(transactionId: string, result: TResult): void {
    if (!this.#status.has(transactionId)) throw new UnknownTransaction(transactionId);
    if (this.#status.get(transactionId) !== "pending") throw new DuplicateCallback(transactionId);
    this.#status.set(transactionId, "fulfilled");
    this.#results.set(transactionId, result);
    const listeners = this.#resultListeners.get(transactionId) ?? [];
    this.#resultListeners.delete(transactionId);
    for (const handler of listeners) handler(result);
  }

  /** The nack half — settles the transaction as failed instead of fulfilled, exactly once. */
  fail(transactionId: string, error: unknown): void {
    if (!this.#status.has(transactionId)) throw new UnknownTransaction(transactionId);
    if (this.#status.get(transactionId) !== "pending") throw new DuplicateCallback(transactionId);
    this.#status.set(transactionId, "failed");
    this.#errors.set(transactionId, error);
    const listeners = this.#errorListeners.get(transactionId) ?? [];
    this.#errorListeners.delete(transactionId);
    for (const handler of listeners) handler(error);
  }

  status(transactionId: string): TransactionStatus | undefined {
    return this.#status.get(transactionId);
  }

  result(transactionId: string): TResult | undefined {
    return this.#results.get(transactionId);
  }
}
