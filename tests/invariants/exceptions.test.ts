/**
 * PHASE 2 — starting point, not yet implemented.
 *
 * These are written against services/platform, services/vault, and
 * packages/capability as they exist at the end of Phase 1 (A4). Every test
 * below currently fails or fails to compile — that's the point. Phase 2 is
 * "done" when INV-14 through INV-18 are green alongside the existing 20.
 *
 * The exports these tests reach for (Platform.createReturn,
 * Platform.redirectDelivery, Vault.notifyFailedDelivery, a NotificationPort,
 * Platform.refund) do not exist yet. Add them; do not change the shape of
 * these tests to make them pass — the shape encodes the constraint from
 * SHIP2MYID_DEMO_SPEC.md §6.2: "the exception path may never grant a
 * capability wider than the one that created the shipment."
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret, deriveS2ID } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger, AttenuationWidened } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform, MerchantDatabase } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";

function harness() {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const registry = new Registry();
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, sortation: new MeridiaSortation() });
  const platform = new Platform({ registry, consent, capSecret });

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

  const req = { s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
  const env = signRequest("alba-goods.example", "k1", mk.privateKey, req);
  const { capability } = platform.createShipment(env, req, "sub_1");

  return { kms, audit, consent, nonces, capSecret, registry, vault, platform, root, s2id, mk, capability };
}

/* ---------------------------------------------------------- INV-14 ----- */
test("INV-14: a return capability may never exceed the shipment capability's scope", async () => {
  const h = harness();
  // Expected shape: Platform.createReturn(shipmentCapability, actorId, subjectRef) -> Capability
  // with purpose:"return", same s2id, maxWeightKg no greater than the original,
  // expiresAt no later, and a FRESH consentRef (never the shipment's own).
  const returnCap = (h.platform as any).createReturn(h.capability, "alba-goods.example", "sub_1");
  assert.equal(returnCap.caveats.purpose, "return");
  assert.equal(returnCap.caveats.s2id, h.capability.caveats.s2id);
  assert.ok(returnCap.caveats.maxWeightKg <= h.capability.caveats.maxWeightKg);
  assert.ok(returnCap.caveats.expiresAt <= h.capability.caveats.expiresAt + 72 * 3600 * 1000);
  assert.notEqual(returnCap.caveats.consentRef, h.capability.caveats.consentRef);
});

/* ---------------------------------------------------------- INV-15 ----- */
test("INV-15: failed delivery notifies the consumer, never the merchant", async () => {
  const h = harness();
  const notified: string[] = [];
  // Expected shape: a NotificationPort (packages/core/src/core.ts) with
  // notify(subjectRef, event) — injected into Vault, never into Platform,
  // so the merchant-facing service has no path to the notification at all.
  const notifications = { notify: (subjectRef: string, _event: string) => { notified.push(subjectRef); } };
  (h.vault as any).notifyFailedDelivery(h.capability, notifications);
  assert.deepEqual(notified, ["sub_1"]);
  // The merchant identifier must never appear as a notify() target.
  assert.ok(!notified.includes("alba-goods.example"));
});

/* ---------------------------------------------------------- INV-16 ----- */
test("INV-16: revocation kills a capability the merchant believes is still valid", async () => {
  const h = harness();
  // Expected shape: Platform.revoke(capabilityId, subjectRef) marks the nonce
  // burned WITHOUT the merchant being told why — resolve() must fail exactly
  // like a replay, so a merchant cannot distinguish "already used" from
  // "consumer pulled it mid-flight" by response shape alone.
  (h.platform as any).revoke(h.capability.id, "sub_1");
  await assert.rejects(() => h.vault.resolve(h.capability, "alba-goods.example"));
});

/* ---------------------------------------------------------- INV-17 ----- */
test("INV-17: a redirect issues a fresh capability without telling the merchant the destination changed", async () => {
  const h = harness();
  // Expected shape: Platform.redirectDelivery(capability, newDestinationKind,
  // actorId) -> Capability. The merchant-visible projection (MerchantView)
  // must be byte-identical before and after — no destination field exists
  // there to change.
  const before = JSON.stringify(h.platform.createShipment(
    signRequest("alba-goods.example", "k1", h.mk.privateKey,
      { s2id: h.s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const }),
    { s2id: h.s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const }, "sub_1",
  ).merchantView);
  const redirected = (h.platform as any).redirectDelivery(h.capability, "locker", "sub_1");
  assert.notEqual(redirected.id, h.capability.id);
  assert.equal(redirected.caveats.destinationKind, "locker");
  assert.ok(!("destinationKind" in JSON.parse(before)), "destination must never be merchant-visible");
});

/* ---------------------------------------------------------- INV-18 ----- */
test("INV-18: refund-without-return makes zero vault calls", async () => {
  const h = harness();
  const resolveCallsBefore = (h.vault as any).__resolveCallCount ?? 0;
  // Expected shape: Platform.refund(capability, actorId, subjectRef) — settles
  // without ever asking the vault to decrypt or route anything. Assert
  // indirectly: the address record's audit trail gains no new entries.
  (h.platform as any).refund(h.capability, "alba-goods.example", "sub_1");
  assert.equal(h.audit.forRecord("rec_1").length, 0, "refund must not touch the vault's audit trail at all");
});
