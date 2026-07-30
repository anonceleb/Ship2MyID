/**
 * Remediation for the privacy-invariant-reviewer's Phase 0–3 pass: each test
 * here is the exact bypass the review's proof-of-concept exploited, pinned
 * so it fails loudly if reintroduced. See the review findings for the
 * original PoCs — these are the primitive/service-level equivalents.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger, mint, verify, CapabilityInvalid } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform, NotAuthorized } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { PolicyStore, signPolicy } from "../../packages/policy/src/policy.ts";
import { QuotaExceeded } from "../../packages/metering/src/meter.ts";
import { UsageMeter } from "../../packages/metering/src/meter.ts";

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

/* ------------------------------------------------ Finding 1: id in MAC - */

test("INV-23: the capability MAC covers id — swapping in a fresh id invalidates the signature", () => {
  const secret = randomBytes(32);
  const cap = mint(secret, {
    s2id: "MER-AAAA-BBBB-CCCC", purpose: "delivery", maxWeightKg: 5,
    carrier: "MER-POST", expiresAt: Date.now() + 60_000, singleUse: true,
    consentRef: "cns_x", destinationKind: "door",
  });
  const forged = { ...cap, id: randomUUID() };
  assert.throws(() => verify(secret, forged), CapabilityInvalid);
});

test("INV-23: a spent capability cannot be replayed by swapping its id and resubmitting", async () => {
  const h = harness();
  const routed = await h.vault.resolve(h.capability, "alba-goods.example");
  assert.match(routed.sortationCode, /^MRD-[0-9A-F]{10}$/);

  const forged = { ...h.capability, id: randomUUID() };
  await assert.rejects(() => h.vault.resolve(forged, "alba-goods.example"), CapabilityInvalid);
});

/* --------------------------------------- Finding 2: return/refund owner -*/

test("INV-24: createReturn refuses a subjectRef that isn't the original consent's subject", () => {
  const h = harness();
  assert.throws(
    () => h.platform.createReturn(h.capability, "alba-goods.example", "an-impostor"),
    NotAuthorized,
  );
  // The rightful subject still can.
  const returnCap = h.platform.createReturn(h.capability, "alba-goods.example", "sub_1");
  assert.equal(returnCap.caveats.purpose, "return");
});

test("INV-24: refund refuses a subjectRef that isn't the original consent's subject", () => {
  const h = harness();
  assert.throws(
    () => h.platform.refund(h.capability, "alba-goods.example", "an-impostor"),
    NotAuthorized,
  );
});

/* ------------------------------------------- Finding 3: policy freeze --*/

test("INV-25: the active policy object cannot be mutated in place through the reference active() returns", () => {
  const keys = newKeyPair();
  const initial = signPolicy(keys.privateKey, "op-1", { version: 1, minTierToShip: 2 });
  const store = new PolicyStore(keys.publicKey, initial);

  assert.throws(() => {
    "use strict";
    (store.active().policy as { minTierToShip: number }).minTierToShip = 3;
  }, TypeError);
  assert.equal(store.active().policy.minTierToShip, 2, "policy must be unchanged");
});

/* --------------------------------- Finding 4: batch isolation + meter --*/

test("INV-26: one transaction's failure in processBatch does not silently drop unrelated pending transactions", () => {
  const h = harness();
  const goodReq = { s2id: h.s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
  const goodEnv = signRequest("alba-goods.example", "k1", h.mk.privateKey, goodReq);
  // t2 references an s2id nobody ever learnProjection()'d for — this
  // passes requestShipment()'s synchronous signature/quota checks but
  // throws "unknown s2id" only once processBatch() actually calls
  // createShipment(), which is exactly the class of failure that used to
  // escape the settlement loop and take every later transaction with it.
  const badReq = { s2id: "MER-NEVER-LEARNED-0000", weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
  const badEnv = signRequest("alba-goods.example", "k1", h.mk.privateKey, badReq);

  const t1 = h.platform.requestShipment(goodEnv, goodReq, "sub_1");
  const t2 = h.platform.requestShipment(badEnv, badReq, "sub_1");
  const t3 = h.platform.requestShipment(goodEnv, goodReq, "sub_1");

  const outcomes: Record<string, { ok: boolean }> = {};
  h.platform.onShipmentReady(t1.transactionId, () => { outcomes.t1 = { ok: true }; });
  h.platform.onShipmentError(t2.transactionId, () => { outcomes.t2 = { ok: false }; });
  h.platform.onShipmentReady(t3.transactionId, () => { outcomes.t3 = { ok: true }; });
  h.platform.onShipmentError(t3.transactionId, () => { outcomes.t3 = { ok: false }; });

  h.platform.processBatch();

  assert.ok(outcomes.t1?.ok, "t1 should have succeeded");
  assert.equal(outcomes.t2?.ok, false, "t2 should have failed on the unknown s2id");
  assert.ok(outcomes.t3?.ok, "t3 must not be silently dropped just because t2 failed");
});

test("INV-26: requestShipment is metered at request time, not only at batch settlement", () => {
  const meter = new UsageMeter({ limit: 1, windowMs: 60_000 });
  const h = harness();
  const platform = new Platform({ registry: h.registry, consent: h.consent, capSecret: h.capSecret, meter });
  platform.learnProjection(h.s2id, { geoBucket: "MRD-48", vouchTier: 2 });
  const req = { s2id: h.s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
  const env = signRequest("alba-goods.example", "k1", h.mk.privateKey, req);

  platform.requestShipment(env, req, "sub_1");
  assert.throws(() => platform.requestShipment(env, req, "sub_1"), QuotaExceeded);
});
