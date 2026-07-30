/**
 * ZONE 2 — the platform. Orchestrates, mints capabilities, records consent.
 *
 * Structurally unable to betray the consumer: it holds ciphertext and has no
 * key material, so "the operator becomes a honeypot" is answerable rather than
 * deniable. The honeypot is Zone 1: one service, one job, one audited exit.
 */
import { randomUUID } from "node:crypto";
import {
  attenuate,
  attenuateToReturn,
  mint,
  NonceLedger,
  type Capability,
  type Caveats,
} from "../../../packages/capability/src/capability.ts";
import { ConsentLedger, type MerchantView } from "../../../packages/core/src/core.ts";
import { Registry, type SignedEnvelope } from "../../../packages/registry/src/signing.ts";
import { deriveS2ID, type RootSecret } from "../../../packages/identity/src/pairwise.ts";

export class TierTooLow extends Error {}
export class UnknownCapability extends Error {}
export class NotAuthorized extends Error {}

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
  /**
   * Own copy, not shared with Vault's — Platform and Vault are different
   * zones/services and in a real deployment would reach a common nonce
   * store (Redis) over the network, not a shared JS reference. What
   * actually gates Vault.resolve() after a revoke in this in-process demo
   * is the shared ConsentLedger below; this ledger exists for parity with
   * that real deployment shape, and so revoke()/refund() reuse the exact
   * same NonceLedger.revoke() a replay burns, rather than inventing a
   * second revocation mechanism.
   */
  #nonces: NonceLedger;
  /** Only what Zone 1 chose to project. No ciphertext keys, no addresses. */
  #projections = new Map<string, { geoBucket: string; vouchTier: 1 | 2 | 3 }>();
  /** capabilityId -> the consentRef it was minted against. Lets revoke()/redirectDelivery() find the record without needing the full capability object. */
  #capabilityConsent = new Map<string, string>();

  constructor(opts: { registry: Registry; consent: ConsentLedger; capSecret: Buffer; nonces?: NonceLedger }) {
    this.#registry = opts.registry;
    this.#consent = opts.consent;
    this.#capSecret = opts.capSecret;
    this.#nonces = opts.nonces ?? new NonceLedger();
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
    this.#capabilityConsent.set(capability.id, consent.ref);

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

  /**
   * §6.2 consumer-initiated return: a single-use, 72-hour, return-direction
   * capability. Minted via attenuateToReturn() — never mint() — so a return
   * structurally cannot exceed the shipment's weight or outlive its
   * validity window; only purpose, expiry, and consentRef change.
   */
  createReturn(shipmentCap: Capability, actorId: string): Capability {
    const original = this.#consent.find(shipmentCap.caveats.consentRef);
    if (!original) throw new UnknownCapability("no consent record for the originating shipment");

    const returnWindowMs = 72 * 3600 * 1000;
    const consent = this.#consent.append({
      subject: original.subject,
      grantedTo: actorId,
      purpose: "return",
      scope: ["return-parcel"],
      at: Date.now(),
      expiresAt: Date.now() + returnWindowMs,
    });

    const returnCap = attenuateToReturn(
      this.#capSecret,
      shipmentCap,
      {
        expiresAt: Math.min(shipmentCap.caveats.expiresAt, Date.now() + returnWindowMs),
        consentRef: consent.ref,
      },
      actorId,
    );
    this.#capabilityConsent.set(returnCap.id, consent.ref);
    return returnCap;
  }

  /**
   * §6.2 revocation: "the consumer taps once and the token is dead
   * mid-flight." Burns the nonce (parity with a shared deployment) and
   * revokes the consent record the capability was minted against — the
   * latter is what actually makes Vault.resolve() reject here, via the
   * same isValidFor() check every resolution already runs. That check's
   * failure and a burned-nonce failure are collapsed onto the same
   * CapabilityBurned class in Vault.resolve() specifically so a merchant
   * cannot catch by error type and tell "already used" apart from
   * "consumer revoked it" — see the docstring on resolve() and
   * tests/invariants/exceptions-error-shape.test.ts.
   */
  revoke(capabilityId: string, subjectRef: string): void {
    const consentRef = this.#capabilityConsent.get(capabilityId);
    if (!consentRef) throw new UnknownCapability(capabilityId);
    const entry = this.#consent.find(consentRef);
    if (!entry || entry.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${capabilityId} does not belong to subject ${subjectRef}`);
    }
    this.#nonces.revoke(capabilityId);
    this.#consent.revoke(consentRef);
  }

  /**
   * §6.2 failed delivery, redirect branch: "issues a fresh capability to a
   * different address; the merchant is never told the destination
   * changed." destinationKind is the one field this path is allowed to
   * change — weight and expiry are carried over unchanged (there is no
   * caller-supplied override for either), so there is no surface here for
   * a redirect to widen anything attenuate() would reject.
   */
  redirectDelivery(cap: Capability, newDestinationKind: Caveats["destinationKind"], subjectRef: string): Capability {
    const original = this.#consent.find(cap.caveats.consentRef);
    if (!original) throw new UnknownCapability("no consent record for this capability");
    if (original.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${cap.id} does not belong to subject ${subjectRef}`);
    }

    const consent = this.#consent.append({
      subject: original.subject,
      grantedTo: original.grantedTo,
      purpose: cap.caveats.purpose,
      scope: ["redirect-parcel"],
      at: Date.now(),
      expiresAt: cap.caveats.expiresAt,
    });

    const attenuated = attenuate(this.#capSecret, cap, { destinationKind: newDestinationKind, consentRef: consent.ref }, subjectRef);
    // A fresh id: a redirect is a distinct grant from the shipment it
    // replaces, single-use independently of it. mac covers {caveats,chain},
    // not id, so this doesn't invalidate the signature.
    const redirected: Capability = { ...attenuated, id: randomUUID() };
    this.#capabilityConsent.set(redirected.id, consent.ref);
    return redirected;
  }

  /**
   * §6.2 refund without return: "zero address exposure. Preferred wherever
   * unit economics allow." Settlement is a Zone 2/billing concern; nothing
   * here calls Vault.resolve() or reads AddressRecord, and there is no
   * vault call added for its own sake — the point of this method is that
   * such a call does not exist.
   */
  refund(cap: Capability, actorId: string): void {
    this.#nonces.revoke(cap.id);
    const consentRef = this.#capabilityConsent.get(cap.id) ?? cap.caveats.consentRef;
    const original = this.#consent.find(consentRef);
    this.#consent.append({
      subject: original?.subject ?? "unknown",
      grantedTo: actorId,
      purpose: "refund",
      scope: ["refund"],
      at: Date.now(),
      expiresAt: Date.now(),
    });
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
