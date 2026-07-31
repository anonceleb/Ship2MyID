/**
 * ADAPTER — Dakhil Post, fictional South Asian last-mile operator.
 *
 * Exists to prove the exchange layer isn't hard-coded to postal-meridia's
 * shape, in two ways that are structural, not cosmetic renames:
 *
 *  1. Address format. Meridia buckets by postcode prefix, which assumes a
 *     postcode dense and reliable enough to carry k-anonymity by itself.
 *     Dakhil serves addresses where the postcode is frequently absent or
 *     unreliable — last-mile delivery is landmark- and locality-led, the
 *     same real-world gap AddressPlaintext.placeName exists to cover.
 *     Its geoBucket is derived from placeName/locality first and falls
 *     back to postcode only when neither is present.
 *
 *  2. Key custody. Meridia's IdentityProofingPort trusts a self-asserted
 *     evidence string directly — it is its own trust root. Dakhil holds no
 *     signing key of its own and cannot self-attest a tier: it can only
 *     raise a subject's tier by verifying a signed attestation from a
 *     participant already registered in packages/registry, capped at that
 *     attester's own accreditation tier. It proxies proofing to a trust
 *     root it doesn't control rather than asserting trust itself — the
 *     "operator that can't hold keys" shape the interop claim needs.
 *
 * Deleting this directory must leave packages/core building and green
 * (INV-8), same as postal-meridia.
 */
import type {
  AddressPlaintext,
  SortationPort,
  IdentityProofingPort,
} from "../../../packages/core/src/core.ts";
import { createHash } from "node:crypto";
import { Registry, type SignedEnvelope } from "../../../packages/registry/src/signing.ts";

export class DakhilSortation implements SortationPort {
  async route(address: AddressPlaintext, service: string) {
    // Consumes plaintext transiently; emits a routing code, never an address.
    const geo = address.placeName || address.locality || address.postcode;
    const key = `${geo}|${service}`;
    const code = createHash("sha256").update(key).digest("hex").slice(0, 10).toUpperCase();
    return { sortationCode: `DKH-${code}` };
  }
}

export class NoCustodyKey extends Error {}

/**
 * Holds no signing key of its own — see class docstring above. `evidence`
 * must carry a signed envelope from a participant the shared registry
 * already trusts; a bare claim ("nationalId starts with...") is refused
 * outright rather than evaluated, because Dakhil has no basis to judge one.
 */
export class DakhilIdentity implements IdentityProofingPort {
  #registry: Registry;

  constructor(registry: Registry) {
    this.#registry = registry;
  }

  async proof(_subjectRef: string, evidence: unknown): Promise<1 | 2 | 3> {
    const e = evidence as { envelope?: SignedEnvelope; body?: unknown; requestedTier?: 1 | 2 | 3 };
    if (!e?.envelope || e.body === undefined) {
      throw new NoCustodyKey("dakhil holds no key of its own; evidence must be a signed attestation");
    }
    // Throws SignatureInvalid/ParticipantUnknown/ParticipantSuspended on any defect.
    const attester = this.#registry.verify(e.envelope, e.body);
    const requested = e.requestedTier ?? attester.tier;
    return Math.min(requested, attester.tier) as 1 | 2 | 3;
  }
}

/** Coarse geography from locality/placeName, not postcode structure. */
export function geoBucketFor(address: Pick<AddressPlaintext, "locality" | "placeName" | "postcode">): string {
  const geo = address.placeName || address.locality || address.postcode;
  return `DKH-${geo.slice(0, 2).toUpperCase()}`;
}
