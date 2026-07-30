/**
 * [A9] Signed, versioned, hot-reloadable disclosure policy.
 *
 * The spec had "which tier a merchant must vouch before shipping is
 * allowed" as a hardcoded conditional in the platform service. Beckn's ONIX
 * reference checks every request against a signed, network-published Rego
 * policy artifact instead, with the policy hash recorded alongside the
 * decision so a historical grant can be replayed against the exact rules
 * that were in force at the time. — PRIOR_ART_REVIEW.md §2.3
 *
 * This is that shape without dragging an OPA/Rego runtime into a demo: a
 * small typed ruleset, signed by the operator's key the same way a request
 * envelope is (packages/registry/src/signing.ts), content-addressed by its
 * own hash, and swappable at runtime without a restart. What the audit
 * claim actually needs isn't the rule language — it's that every past
 * decision can point at the exact bytes of the policy that made it, which
 * the hash gives for free whether the rules are Rego or one TypeScript
 * field.
 */
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { digestOf } from "../../registry/src/signing.ts";

export class PolicyInvalid extends Error {}
export class PolicyStale extends Error {}

/** Today's one live disclosure rule: the minimum proofing tier (§5) a merchant must have vouched before Platform.createShipment may mint a capability. */
export type DisclosurePolicy = {
  version: number; // monotonic — reload() refuses to go backwards
  minTierToShip: 1 | 2 | 3;
};

export type SignedPolicy = {
  policy: DisclosurePolicy;
  /** sha256(canonical(policy)), base64 — rides along in the consent entry so a decision is replayable against the rules in force when it was made. */
  hash: string;
  signature: string; // base64 ed25519 over `hash`
  signerKeyId: string;
};

function priv(b64: string) {
  return createPrivateKey({ key: Buffer.from(b64, "base64"), type: "pkcs8", format: "der" });
}
function pub(b64: string) {
  return createPublicKey({ key: Buffer.from(b64, "base64"), type: "spki", format: "der" });
}

export function signPolicy(privateKeyB64: string, signerKeyId: string, policy: DisclosurePolicy): SignedPolicy {
  const hash = digestOf(policy);
  const signature = edSign(null, Buffer.from(hash), priv(privateKeyB64)).toString("base64");
  return { policy, hash, signature, signerKeyId };
}

export function verifyPolicy(publicKeyB64: string, signed: SignedPolicy): boolean {
  if (digestOf(signed.policy) !== signed.hash) return false;
  return edVerify(null, Buffer.from(signed.hash), pub(publicKeyB64), Buffer.from(signed.signature, "base64"));
}

/**
 * Holds exactly one active policy plus every policy that was ever active,
 * indexed by hash — so `byHash()` can answer "what did the rules say when
 * this specific decision was made", not just "what do they say now".
 * `reload()` is the hot-reload seam: swapping the active version never
 * mutates or discards history, so a decision recorded five versions ago
 * still resolves to the bytes that actually governed it.
 */
export class PolicyStore {
  #publicKey: string;
  #active: SignedPolicy;
  #history = new Map<string, SignedPolicy>();

  constructor(publicKeyB64: string, initial: SignedPolicy) {
    this.#publicKey = publicKeyB64;
    this.#active = this.#accept(initial);
  }

  /**
   * Frozen, not just verified: `active()`/`byHash()` hand out this exact
   * object by reference, and a caller mutating `.policy` in place would
   * silently change the live disclosure rule with no reload, no version
   * bump, and no signature — defeating the entire point of a signed,
   * versioned artifact. Freezing both levels makes that a thrown TypeError
   * in strict mode instead of a silent bypass.
   */
  #accept(signed: SignedPolicy): SignedPolicy {
    if (!verifyPolicy(this.#publicKey, signed)) {
      throw new PolicyInvalid(`policy v${signed.policy.version} failed signature verification`);
    }
    Object.freeze(signed.policy);
    Object.freeze(signed);
    this.#history.set(signed.hash, signed);
    return signed;
  }

  /** Hot-reload: verified and versioned. Rejects anything that isn't strictly newer than what's active. */
  reload(next: SignedPolicy): void {
    if (next.policy.version <= this.#active.policy.version) {
      throw new PolicyStale(`policy v${next.policy.version} is not newer than active v${this.#active.policy.version}`);
    }
    this.#active = this.#accept(next);
  }

  active(): SignedPolicy {
    return this.#active;
  }

  /** Replay: what were the rules when a past decision recorded this hash? */
  byHash(hash: string): SignedPolicy | undefined {
    return this.#history.get(hash);
  }
}
