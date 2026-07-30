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

export type TransactionStatus = "pending" | "fulfilled";

let counter = 0;
function nextId(): string {
  counter += 1;
  return `txn_${Date.now().toString(36)}${counter.toString(36)}`;
}

export class AsyncExchange<TResult> {
  #status = new Map<string, TransactionStatus>();
  #results = new Map<string, TResult>();
  #listeners = new Map<string, Array<(result: TResult) => void>>();

  /** The synchronous half: an ack that a transaction was opened, not an answer. */
  begin(): string {
    const transactionId = nextId();
    this.#status.set(transactionId, "pending");
    return transactionId;
  }

  /**
   * Subscribes to the `on_action` callback for a transaction already begun.
   * If the callback already landed, the handler fires immediately with the
   * stored result — subscribing is never a race against delivery.
   */
  onCallback(transactionId: string, handler: (result: TResult) => void): void {
    if (!this.#status.has(transactionId)) throw new UnknownTransaction(transactionId);
    if (this.#status.get(transactionId) === "fulfilled") {
      handler(this.#results.get(transactionId) as TResult);
      return;
    }
    const arr = this.#listeners.get(transactionId) ?? [];
    arr.push(handler);
    this.#listeners.set(transactionId, arr);
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
    if (this.#status.get(transactionId) === "fulfilled") throw new DuplicateCallback(transactionId);
    this.#status.set(transactionId, "fulfilled");
    this.#results.set(transactionId, result);
    const listeners = this.#listeners.get(transactionId) ?? [];
    this.#listeners.delete(transactionId);
    for (const handler of listeners) handler(result);
  }

  status(transactionId: string): TransactionStatus | undefined {
    return this.#status.get(transactionId);
  }

  result(transactionId: string): TResult | undefined {
    return this.#results.get(transactionId);
  }
}
