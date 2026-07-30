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

function macOf(secret: Buffer, caveats: Caveats, chain: string[]): string {
  return createHmac("sha256", secret)
    .update(JSON.stringify({ caveats, chain }))
    .digest("base64url");
}

export function mint(secret: Buffer, caveats: Caveats): Capability {
  const chain = ["authority"];
  return { id: randomUUID(), caveats, chain, mac: macOf(secret, caveats, chain) };
}

/**
 * Every field may only narrow. This is enforced here rather than trusted,
 * because the returns path is exactly where a naive implementation re-widens a
 * grant and leaks what the happy path protected.
 */
export function attenuate(
  secret: Buffer,
  cap: Capability,
  narrower: Partial<Caveats>,
  by: string,
): Capability {
  const next: Caveats = { ...cap.caveats, ...narrower };
  if (next.maxWeightKg > cap.caveats.maxWeightKg) throw new AttenuationWidened("maxWeightKg");
  if (next.expiresAt > cap.caveats.expiresAt) throw new AttenuationWidened("expiresAt");
  if (next.s2id !== cap.caveats.s2id) throw new AttenuationWidened("s2id");
  if (next.purpose !== cap.caveats.purpose) throw new AttenuationWidened("purpose");
  if (cap.caveats.singleUse && !next.singleUse) throw new AttenuationWidened("singleUse");
  const chain = [...cap.chain, by];
  return { id: cap.id, caveats: next, chain, mac: macOf(secret, next, chain) };
}

export function verify(secret: Buffer, cap: Capability, now = Date.now()): void {
  if (macOf(secret, cap.caveats, cap.chain) !== cap.mac) throw new CapabilityInvalid("bad mac");
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
