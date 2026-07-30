/**
 * [Phase 3] The merchant SDK — SHIP2MYID_DEMO_SPEC.md §6.3 / §12.
 *
 * "Done when a third party integrates from the published SDK without
 * talking to us." This file is the one thing a merchant integration is
 * meant to import. Registry, Platform, the capability and policy
 * primitives underneath it are implementation detail — a real integration
 * talks to a hosted API, not these classes directly; in this monorepo demo
 * the `Platform` instance stands in for that network hop the same way
 * every other port in this codebase (SortationPort, NotificationPort) is
 * injected rather than assumed. What matters for the Phase 3 claim is that
 * the shape below is the *entire* merchant-facing contract: no address, no
 * name, no phone, ever crosses it — and everything it returns matches
 * §6.3's `{ s2id, capability, geo_bucket, service_level, estimated_delivery }`.
 */
import { signRequest } from "../../registry/src/signing.ts";
import {
  Platform,
  TierTooLow,
  type ShipmentRequest,
} from "../../../services/platform/src/platform.ts";
import { QuotaExceeded } from "../../metering/src/meter.ts";

export { TierTooLow, QuotaExceeded };
export type { ShipmentRequest };

/**
 * What a merchant integration actually receives — deliberately not the
 * internal `MerchantView`. `verifiedHuman` is the "worth more than address
 * data" signal §6.3 calls the real sales pitch: a merchant that only wants
 * to know "is this a real, distinct, tier-checked person" never needs to
 * think about tier numbers at all.
 */
export type CheckoutResult = {
  s2id: string;
  capabilityId: string;
  geoBucket: string;
  serviceLevel: string;
  estimatedDelivery: string;
  verifiedHuman: boolean;
};

export function isVerifiedHuman(tier: 1 | 2 | 3): boolean {
  return tier >= 1;
}

/**
 * A merchant's one credential-bearing handle onto the network. Constructed
 * once per integration with the participant's own signing key — every
 * subsequent call signs its own request, the way `packages/registry`
 * expects, so the merchant never hand-rolls envelope construction.
 */
export class MerchantClient {
  #platform: Platform;
  #participantId: string;
  #keyId: string;
  #privateKey: string;

  constructor(opts: { platform: Platform; participantId: string; keyId: string; privateKey: string }) {
    this.#platform = opts.platform;
    this.#participantId = opts.participantId;
    this.#keyId = opts.keyId;
    this.#privateKey = opts.privateKey;
  }

  /** Drop-in replacement for an address form: sign, submit, get back a routable, PII-free result. Mirrors `<S2IDCheckout/>`'s onGrant payload. */
  checkout(req: ShipmentRequest, subjectRef: string): CheckoutResult {
    const env = signRequest(this.#participantId, this.#keyId, this.#privateKey, req);
    const { capability, merchantView } = this.#platform.createShipment(env, req, subjectRef);
    return {
      s2id: merchantView.s2id,
      capabilityId: capability.id,
      geoBucket: merchantView.geoBucket,
      serviceLevel: merchantView.serviceLevel,
      estimatedDelivery: merchantView.estimatedDelivery,
      verifiedHuman: isVerifiedHuman(merchantView.verifiedTier),
    };
  }

  /** [A10] The same checkout, as the request half of the action/on_action pair — for integrations that can't block on a synchronous mint. */
  requestCheckout(req: ShipmentRequest, subjectRef: string): { transactionId: string } {
    const env = signRequest(this.#participantId, this.#keyId, this.#privateKey, req);
    return this.#platform.requestShipment(env, req, subjectRef);
  }

  /** Subscribes to the on_checkout callback for a transaction requestCheckout() began, curated to the same CheckoutResult shape as checkout(). */
  onCheckoutReady(transactionId: string, handler: (result: CheckoutResult) => void): void {
    this.#platform.onShipmentReady(transactionId, (r) => {
      handler({
        s2id: r.merchantView.s2id,
        capabilityId: r.capability.id,
        geoBucket: r.merchantView.geoBucket,
        serviceLevel: r.merchantView.serviceLevel,
        estimatedDelivery: r.merchantView.estimatedDelivery,
        verifiedHuman: isVerifiedHuman(r.merchantView.verifiedTier),
      });
    });
  }

  /** Subscribes to the on_checkout nack — fires if settlement rejects the request (quota, tier, expired envelope), independently of any other merchant's pending transaction. */
  onCheckoutError(transactionId: string, handler: (error: unknown) => void): void {
    this.#platform.onShipmentError(transactionId, handler);
  }
}
