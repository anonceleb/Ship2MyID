/**
 * Phase 3 — Commerce. SHIP2MYID_DEMO_SPEC.md §6.3 / §12: the merchant SDK,
 * the verified-human signal, and the metered API. Tier-gating is A9,
 * already covered by tests/invariants/policy-async.test.ts.
 *
 * "Done when a third party integrates from the published SDK without
 * talking to us" — INV-21 proves the SDK's own output shape carries no PII
 * and matches §6.3. INV-22 proves the metered API is real, not aspirational.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { MerchantClient, isVerifiedHuman, QuotaExceeded } from "../../packages/sdk/src/client.ts";
import { UsageMeter } from "../../packages/metering/src/meter.ts";

const PII_SHAPED = /address|line1|street|postcode|phone|email|fullname|nationalid/i;

function harness(meter?: UsageMeter) {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const registry = new Registry();
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, sortation: new MeridiaSortation() });
  const platform = new Platform({ registry, consent, capSecret, meter });

  const mk = newKeyPair();
  registry.register({
    participantId: "alba-goods.example",
    role: "merchant", keyId: "k1", publicKey: mk.publicKey, tier: 2, status: "active",
  });

  const root = newRootSecret();
  const s2id = platform.issueS2ID(root, "alba-goods.example");
  const rec = vault.store({
    id: "rec_1", subjectRef: "sub_1", tenantId: "meridia-post",
    address: { line1: "14 Harbour Lane", locality: "Calder", postcode: "4820" },
    geoBucket: geoBucketFor("4820"), vouchTier: 2,
  });
  vault.bind(s2id, rec.id);
  platform.learnProjection(s2id, { geoBucket: rec.geoBucket, vouchTier: 2 });

  const client = new MerchantClient({ platform, participantId: "alba-goods.example", keyId: "k1", privateKey: mk.privateKey });
  const req = { s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };

  return { platform, client, req, s2id };
}

/* ---------------------------------------------------------- INV-21 ----- */

test("INV-21: MerchantClient.checkout() returns exactly the §6.3 shape, no PII-shaped field under any key", () => {
  const h = harness();
  const result = h.client.checkout(h.req, "sub_1");
  const offenders = Object.keys(result).filter((k) => PII_SHAPED.test(k));
  assert.deepEqual(offenders, []);
  assert.deepEqual(
    Object.keys(result).sort(),
    ["capabilityId", "estimatedDelivery", "geoBucket", "s2id", "serviceLevel", "verifiedHuman"].sort(),
  );
  assert.equal(result.s2id, h.s2id);
  assert.equal(result.verifiedHuman, true);
});

test("INV-21: verified-human signal is a plain tier>=1 boundary, independent of the checkout path", () => {
  assert.equal(isVerifiedHuman(1), true);
  assert.equal(isVerifiedHuman(2), true);
  assert.equal(isVerifiedHuman(3), true);
});

test("INV-21: requestCheckout/onCheckoutReady deliver the same curated shape as the synchronous checkout()", () => {
  const h = harness();
  const { transactionId } = h.client.requestCheckout(h.req, "sub_1");
  let delivered: unknown = null;
  h.client.onCheckoutReady(transactionId, (r) => { delivered = r; });
  assert.equal(delivered, null, "not observable before the batch settles");

  h.platform.processBatch();
  assert.ok(delivered);
  assert.deepEqual(
    Object.keys(delivered as object).sort(),
    ["capabilityId", "estimatedDelivery", "geoBucket", "s2id", "serviceLevel", "verifiedHuman"].sort(),
  );
});

/* ---------------------------------------------------------- INV-22 ----- */

test("INV-22: UsageMeter throws QuotaExceeded once a participant exceeds its window quota", () => {
  const meter = new UsageMeter({ limit: 2, windowMs: 60_000 });
  const now = Date.now();
  meter.consume("merchant-a", now);
  meter.consume("merchant-a", now);
  assert.throws(() => meter.consume("merchant-a", now), QuotaExceeded);
  // A different participant has its own, untouched quota.
  meter.consume("merchant-b", now);
});

test("INV-22: UsageMeter's quota resets in a fresh window", () => {
  const meter = new UsageMeter({ limit: 1, windowMs: 1000 });
  const now = Date.now();
  meter.consume("merchant-a", now);
  assert.throws(() => meter.consume("merchant-a", now + 500), QuotaExceeded);
  meter.consume("merchant-a", now + 1500); // new window
  assert.equal(meter.remaining("merchant-a", now + 1500), 0);
});

test("INV-22: Platform enforces the configured UsageMeter — an over-quota merchant is rejected before minting", () => {
  const meter = new UsageMeter({ limit: 1, windowMs: 60_000 });
  const h = harness(meter);
  h.client.checkout(h.req, "sub_1"); // consumes the only slot
  assert.throws(() => h.client.checkout(h.req, "sub_1"), QuotaExceeded);
});
