/**
 * [Phase 4] Webhook delivery — the hosted-HTTP equivalent of the in-process
 * action/on_action pair `packages/network`'s AsyncExchange already provides.
 * A merchant registers one URL and gets back a signing secret; every
 * delivery is HMAC-SHA256 signed over the same canonical JSON
 * `packages/registry` uses to sign request envelopes, so "verify this
 * really came from Ship2MyID" is a five-line check on the receiving end,
 * not a bare shared-secret string compare.
 *
 * Delivery is real, not simulated: an actual `fetch()` POST, with the same
 * at-least-once, bounded-retry posture a production webhook system needs —
 * a receiving endpoint being briefly unreachable is the normal case, not
 * the exception this package should throw an unrecoverable error over.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type WebhookConfig = { url: string; secret: string };

/** What a merchant's endpoint actually receives on a successful checkout — no PII-shaped field, same discipline as CheckoutResult. */
export type CheckoutCompletedPayload = { capabilityId: string; s2id: string };
/** What a merchant's endpoint receives on a rejected checkout — the same message shape TierTooLow/QuotaExceeded already throw with. */
export type CheckoutFailedPayload = { reason: string };

export type WebhookEvent =
  | { event: "checkout.completed"; transactionId: string; at: number; data: CheckoutCompletedPayload }
  | { event: "checkout.failed"; transactionId: string; at: number; data: CheckoutFailedPayload };

export type DeliveryAttempt = {
  event: WebhookEvent;
  attempt: number;
  at: number;
  ok: boolean;
  httpStatus?: number;
  error?: string;
};

export class WebhookDeliveryFailed extends Error {}

export function newWebhookSecret(): string {
  return randomBytes(24).toString("base64url");
}

/** Mirrors packages/registry/src/signing.ts's canonical() exactly — signature stability depends on the same fixed key order. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

export function signWebhookBody(secret: string, event: WebhookEvent): string {
  return createHmac("sha256", secret).update(canonical(event)).digest("base64");
}

/** Length-checked before timingSafeEqual, which throws rather than returning false on a length mismatch. */
export function verifyWebhookSignature(secret: string, event: WebhookEvent, signature: string): boolean {
  const expected = Buffer.from(signWebhookBody(secret, event));
  const got = Buffer.from(signature);
  return expected.length === got.length && timingSafeEqual(expected, got);
}

/**
 * Bounded retry, not silent-drop-and-forget: every attempt is recorded on
 * `history()`, success or failure, so a merchant integration that missed
 * event N can ask "did you even try" instead of only seeing a gap. Only
 * throws once every attempt is exhausted.
 */
export class WebhookDispatcher {
  #maxAttempts: number;
  #delayMs: number;
  #history: DeliveryAttempt[] = [];

  constructor(opts: { maxAttempts?: number; delayMs?: number } = {}) {
    this.#maxAttempts = opts.maxAttempts ?? 3;
    this.#delayMs = opts.delayMs ?? 200;
  }

  history(): readonly DeliveryAttempt[] {
    return this.#history;
  }

  async deliver(config: WebhookConfig, event: WebhookEvent): Promise<DeliveryAttempt> {
    const signature = signWebhookBody(config.secret, event);
    let lastError = "unknown error";
    for (let attempt = 1; attempt <= this.#maxAttempts; attempt++) {
      try {
        const res = await fetch(config.url, {
          method: "POST",
          headers: { "content-type": "application/json", "x-ship2myid-signature": signature },
          body: JSON.stringify(event),
        });
        const record: DeliveryAttempt = { event, attempt, at: Date.now(), ok: res.ok, httpStatus: res.status };
        this.#history.push(record);
        if (res.ok) return record;
        lastError = `http ${res.status}`;
      } catch (err) {
        lastError = (err as Error).message;
        this.#history.push({ event, attempt, at: Date.now(), ok: false, error: lastError });
      }
      if (attempt < this.#maxAttempts) await new Promise((r) => setTimeout(r, this.#delayMs));
    }
    throw new WebhookDeliveryFailed(
      `${event.event} to ${config.url} failed after ${this.#maxAttempts} attempts: ${lastError}`,
    );
  }
}
