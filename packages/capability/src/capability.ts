/**
 * Capability tokens.
 *
 * The central inversion: a merchant never receives an address, encrypted or
 * otherwise. It receives a grant describing an action it may cause, scoped and
 * expiring, which only the vault can act upon.
 *
 * Attenuation (Biscuit/macaroon semantics) lets a holder pass a strictly weaker
 * grant downstream — merchant to courier — with no round trip to us, and with no
 * ability to widen. Caveats accumulate; they never relax.
 */
import { createHmac, randomUUID } from "node:crypto";

export type Caveats = {
  s2id: string;
  purpose: "delivery" | "return" | "redirect";
  maxWeightKg: number;
  carrier: string;
  expiresAt: number;
  singleUse: boolean;
  consentRef: string;
  /** Delivery to an access point needs no address at all — the zero-PII path. */
  destinationKind: "door" | "access-point" | "locker";
};

export type Capability = {
  id: string;
  caveats: Caveats;
  chain: string[]; // attenuation lineage
  mac: string;
};

export class CapabilityBurned extends Error {}
export class CapabilityExpired extends Error {}
export class CapabilityInvalid extends Error {}
export class AttenuationWidened extends Error {}

/**
 * `id` is part of the signed material. Single-use enforcement
 * (NonceLedger.burn) is keyed on `id` alone — a MAC that didn't cover it
 * would let any holder mint an unlimited supply of "single-use" tokens by
 * swapping in a fresh id, since {caveats, chain} would still verify.
 */
function macOf(secret: Buffer, id: string, caveats: Caveats, chain: string[]): string {
  return createHmac("sha256", secret)
    .update(JSON.stringify({ id, caveats, chain }))
    .digest("base64url");
}

export function mint(secret: Buffer, caveats: Caveats): Capability {
  const chain = ["authority"];
  const id = randomUUID();
  return { id, caveats, chain, mac: macOf(secret, id, caveats, chain) };
}

/**
 * The narrowing checks every attenuation path shares: weight, expiry, s2id,
 * and single-use may only ever tighten. Factored out so the return-purpose
 * transition below enforces the identical rule rather than a hand-rolled
 * second check.
 */
function assertNotWidened(next: Caveats, prev: Caveats): void {
  if (next.maxWeightKg > prev.maxWeightKg) throw new AttenuationWidened("maxWeightKg");
  if (next.expiresAt > prev.expiresAt) throw new AttenuationWidened("expiresAt");
  if (next.s2id !== prev.s2id) throw new AttenuationWidened("s2id");
  if (prev.singleUse && !next.singleUse) throw new AttenuationWidened("singleUse");
}

/**
 * Every field may only narrow. This is enforced here rather than trusted,
 * because the returns path is exactly where a naive implementation re-widens a
 * grant and leaks what the happy path protected.
 *
 * `opts.newId` lets a caller (Platform.redirectDelivery) mint the
 * attenuated capability under a fresh id — needed because a redirect is a
 * distinct, independently single-use grant from the one it replaces. The id
 * must be chosen before the MAC is computed, not rewritten after: since
 * `id` is now signed material (see macOf), overwriting it post-hoc would
 * produce a capability whose id and mac disagree and fail verify().
 */
export function attenuate(
  secret: Buffer,
  cap: Capability,
  narrower: Partial<Caveats>,
  by: string,
  opts: { newId?: string } = {},
): Capability {
  const next: Caveats = { ...cap.caveats, ...narrower };
  assertNotWidened(next, cap.caveats);
  if (next.purpose !== cap.caveats.purpose) throw new AttenuationWidened("purpose");
  const chain = [...cap.chain, by];
  const id = opts.newId ?? cap.id;
  return { id, caveats: next, chain, mac: macOf(secret, id, next, chain) };
}

/**
 * The one sanctioned purpose transition: a shipment's return leg (spec
 * §6.2). `attenuate()` itself must keep rejecting *any* purpose change,
 * including this exact one — INV-11 asserts that directly, because generic
 * attenuation by an arbitrary holder ("courier-7") re-purposing a grant is
 * exactly the bug this system exists to prevent. A return is only ever
 * reachable through Platform.createReturn, never through attenuate() itself,
 * so the transition lives in its own function — one that reuses the same
 * assertNotWidened() narrowing rule, so a return still can never exceed the
 * shipment that created it.
 */
export function attenuateToReturn(
  secret: Buffer,
  cap: Capability,
  narrower: Partial<Omit<Caveats, "purpose">>,
  by: string,
): Capability {
  if (cap.caveats.purpose !== "delivery") throw new AttenuationWidened("purpose");
  const next: Caveats = { ...cap.caveats, ...narrower, purpose: "return" };
  assertNotWidened(next, cap.caveats);
  const chain = [...cap.chain, by];
  // A fresh id: a return is a distinct grant, single-use independently of
  // the shipment it descends from — sharing an id would couple their nonce
  // burns and let redeeming one silently invalidate the other. Generated
  // before the MAC, since id is now part of what's signed.
  const id = randomUUID();
  return { id, caveats: next, chain, mac: macOf(secret, id, next, chain) };
}

export function verify(secret: Buffer, cap: Capability, now = Date.now()): void {
  if (macOf(secret, cap.id, cap.caveats, cap.chain) !== cap.mac) throw new CapabilityInvalid("bad mac");
  if (now > cap.caveats.expiresAt) throw new CapabilityExpired(cap.id);
}

/** Single-use enforcement. Redis SETNX in production; a Set here. */
export class NonceLedger {
  #burned = new Set<string>();
  burn(id: string): void {
    if (this.#burned.has(id)) throw new CapabilityBurned(id);
    this.#burned.add(id);
  }
  isBurned(id: string): boolean {
    return this.#burned.has(id);
  }
  /** Consumer-initiated revocation, effective mid-flight. */
  revoke(id: string): void {
    this.#burned.add(id);
  }
}
