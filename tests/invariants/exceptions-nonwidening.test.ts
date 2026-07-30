/**
 * Phase 2 exceptions — the non-widening property, as its own test.
 *
 * SHIP2MYID_DEMO_SPEC.md §6.2: "the exception path may never grant a
 * capability wider than the one that created the shipment." INV-14..18 in
 * exceptions.test.ts exercise each flow's happy path; this file asks the
 * same question the other direction — for createReturn and redirectDelivery
 * (the two flows that mint a new capability), can maxWeightKg or expiresAt
 * ever come out wider than the parent, through the real Platform API or
 * through the lower-level attenuation primitives it's built on?
 *
 * Not renumbered into INV-14..18 — this sits alongside them the same way
 * the A4 label tests sit alongside INV-1..13: a Phase 2 addition, not one
 * of the tests already in the repo.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger, attenuate, attenuateToReturn, AttenuationWidened } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform } from "../../services/platform/src/platform.ts";
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

  return { capSecret, platform, s2id, mk, capability };
}

test("Non-widening: Platform.createReturn's public API exposes no override that could widen maxWeightKg, expiresAt, or destinationKind", () => {
  const h = harness();
  const returnCap = h.platform.createReturn(h.capability, "alba-goods.example");
  assert.ok(returnCap.caveats.maxWeightKg <= h.capability.caveats.maxWeightKg);
  assert.ok(returnCap.caveats.expiresAt <= h.capability.caveats.expiresAt);
  assert.equal(returnCap.caveats.destinationKind, h.capability.caveats.destinationKind);
});

test("Non-widening: Platform.redirectDelivery carries weight and expiry over unchanged — only destinationKind moves", () => {
  const h = harness();
  const redirected = h.platform.redirectDelivery(h.capability, "locker", "sub_1");
  assert.equal(redirected.caveats.maxWeightKg, h.capability.caveats.maxWeightKg);
  assert.equal(redirected.caveats.expiresAt, h.capability.caveats.expiresAt);
  assert.equal(redirected.caveats.destinationKind, "locker");
});

test("Non-widening: the primitive underneath createReturn rejects a widened weight or expiry with AttenuationWidened", () => {
  const h = harness();
  assert.throws(
    () => attenuateToReturn(h.capSecret, h.capability, { maxWeightKg: h.capability.caveats.maxWeightKg + 1 }, "alba-goods.example"),
    AttenuationWidened,
  );
  assert.throws(
    () => attenuateToReturn(h.capSecret, h.capability, { expiresAt: h.capability.caveats.expiresAt + 1 }, "alba-goods.example"),
    AttenuationWidened,
  );
});

test("Non-widening: the primitive underneath redirectDelivery rejects a widened weight or expiry with AttenuationWidened", () => {
  const h = harness();
  assert.throws(
    () => attenuate(h.capSecret, h.capability, { maxWeightKg: h.capability.caveats.maxWeightKg + 1, destinationKind: "locker" }, "sub_1"),
    AttenuationWidened,
  );
  assert.throws(
    () => attenuate(h.capSecret, h.capability, { expiresAt: h.capability.caveats.expiresAt + 1, destinationKind: "locker" }, "sub_1"),
    AttenuationWidened,
  );
});

test("Non-widening: revoke and refund mint no capability at all — nothing for either to widen", () => {
  const h = harness();
  assert.equal(h.platform.revoke(h.capability.id, "sub_1"), undefined);
  const h2 = harness();
  assert.equal(h2.platform.refund(h2.capability, "alba-goods.example"), undefined);
});
