/**
 * ZONE 2 — the platform. Orchestrates, mints capabilities, records consent.
 *
 * Structurally unable to betray the consumer: it holds ciphertext and has no
 * key material, so "the operator becomes a honeypot" is answerable rather than
 * deniable. The honeypot is Zone 1: one service, one job, one audited exit.
 */
import { randomUUID } from "node:crypto";
import { mint, type Capability, type Caveats } from "../../../packages/capability/src/capability.ts";
import { ConsentLedger, type MerchantView } from "../../../packages/core/src/core.ts";
import { Registry, type SignedEnvelope } from "../../../packages/registry/src/signing.ts";
import { deriveS2ID, type RootSecret } from "../../../packages/identity/src/pairwise.ts";

export class TierTooLow extends Error {}

export type ShipmentRequest = {
  s2id: string;
  weightKg: number;
  carrier: string;
  destinationKind: Caveats["destinationKind"];
};

export class Platform {
  #registry: Registry;
  #consent: ConsentLedger;
  #capSecret: Buffer;
  /** Only what Zone 1 chose to project. No ciphertext keys, no addresses. */
  #projections = new Map<string, { geoBucket: string; vouchTier: 1 | 2 | 3 }>();

  constructor(opts: { registry: Registry; consent: ConsentLedger; capSecret: Buffer }) {
    this.#registry = opts.registry;
    this.#consent = opts.consent;
    this.#capSecret = opts.capSecret;
  }

  learnProjection(s2id: string, p: { geoBucket: string; vouchTier: 1 | 2 | 3 }): void {
    this.#projections.set(s2id, p);
  }

  issueS2ID(root: RootSecret, merchantId: string): string {
    this.#registry.lookup(merchantId); // unknown participants get nothing
    return deriveS2ID(root, merchantId);
  }

  /**
   * Every capability is minted against a fresh, per-event consent record.
   * Standing consent is not representable in this API — by design.
   */
  createShipment(
    env: SignedEnvelope,
    req: ShipmentRequest,
    subjectRef: string,
    minTier: 1 | 2 | 3 = 2,
  ): { capability: Capability; merchantView: MerchantView } {
    const merchant = this.#registry.verify(env, req);
    const proj = this.#projections.get(req.s2id);
    if (!proj) throw new Error("unknown s2id");
    if (proj.vouchTier < minTier) throw new TierTooLow(`tier ${proj.vouchTier} < ${minTier}`);

    const consent = this.#consent.append({
      subject: subjectRef,
      grantedTo: merchant.participantId,
      purpose: "delivery",
      scope: ["route-parcel"],
      at: Date.now(),
      expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
    });

    const capability = mint(this.#capSecret, {
      s2id: req.s2id,
      purpose: "delivery",
      maxWeightKg: req.weightKg,
      carrier: req.carrier,
      expiresAt: Date.now() + 14 * 24 * 3600 * 1000,
      singleUse: true,
      consentRef: consent.ref,
      destinationKind: req.destinationKind,
    });

    return {
      capability,
      merchantView: {
        s2id: req.s2id,
        geoBucket: proj.geoBucket,
        verifiedTier: proj.vouchTier,
        serviceLevel: "standard",
        estimatedDelivery: "3-5 days",
      },
    };
  }
}

/**
 * Zone 3 storage, as a merchant would actually keep it. The invariant suite
 * introspects this shape and fails the build if a PII-shaped column appears.
 */
export class MerchantDatabase {
  customers: MerchantView[] = [];
  orders: { orderId: string; s2id: string; capabilityId: string }[] = [];

  save(view: MerchantView, capability: Capability): void {
    if (!this.customers.find((c) => c.s2id === view.s2id)) this.customers.push(view);
    this.orders.push({
      orderId: randomUUID(),
      s2id: view.s2id,
      capabilityId: capability.id,
    });
  }

  columns(): string[] {
    return [
      ...new Set([
        ...this.customers.flatMap((c) => Object.keys(c)),
        ...this.orders.flatMap((o) => Object.keys(o)),
      ]),
    ];
  }
}
