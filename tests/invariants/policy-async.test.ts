/**
 * A9 / A10 — signed disclosure policy, and capability minting as an
 * async request/callback pair. Both scheduled for Phase 1 in
 * PRIOR_ART_REVIEW.md §2.3 / §2.4; INV-19 and INV-20 are what "done" means
 * for each.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret, deriveS2ID } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest, SignatureInvalid } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform, MerchantDatabase, TierTooLow } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { PolicyStore, signPolicy, PolicyInvalid, PolicyStale } from "../../packages/policy/src/policy.ts";
import { AsyncExchange, UnknownTransaction, DuplicateCallback } from "../../packages/network/src/exchange.ts";

function harness() {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const registry = new Registry();

  const opKeys = newKeyPair();
  const initialPolicy = signPolicy(opKeys.privateKey, "op-1", { version: 1, minTierToShip: 2 });
  const policy = new PolicyStore(opKeys.publicKey, initialPolicy);

  const vault = new Vault({ kms, audit, consent, nonces, capSecret, sortation: new MeridiaSortation() });
  const platform = new Platform({ registry, consent, capSecret, policy });

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

  return { kms, audit, consent, nonces, capSecret, registry, vault, platform, root, s2id, mk, opKeys, req, env };
}

/* ---------------------------------------------------------- A9 / INV-19 - */

test("INV-19: the disclosure policy that gated a decision is recorded on its consent entry, byte-identical", () => {
  const h = harness();
  const { capability } = h.platform.createShipment(h.env, h.req, "sub_1");
  const entry = h.consent.find(capability.caveats.consentRef)!;
  assert.equal(entry.policyHash, h.platform.policy().active().hash);
});

test("INV-19: a past decision replays against the exact policy in force at the time, even after hot-reload", () => {
  const h = harness();
  const { capability } = h.platform.createShipment(h.env, h.req, "sub_1");
  const entry = h.consent.find(capability.caveats.consentRef)!;
  const decidingPolicy = h.platform.policy().byHash(entry.policyHash!);
  assert.equal(decidingPolicy?.policy.version, 1);
  assert.equal(decidingPolicy?.policy.minTierToShip, 2);

  const next = signPolicy(h.opKeys.privateKey, "op-1", { version: 2, minTierToShip: 3 });
  h.platform.policy().reload(next);

  assert.equal(h.platform.policy().active().policy.version, 2);
  // History is never overwritten by a reload — the old decision still points at v1.
  assert.equal(h.platform.policy().byHash(entry.policyHash!)?.policy.version, 1);
});

test("INV-19: reload refuses a policy that isn't strictly newer than the active one", () => {
  const h = harness();
  const stale = signPolicy(h.opKeys.privateKey, "op-1", { version: 1, minTierToShip: 3 });
  assert.throws(() => h.platform.policy().reload(stale), PolicyStale);
});

test("INV-19: reload refuses a policy that doesn't verify against the operator's key", () => {
  const h = harness();
  const impostor = newKeyPair();
  const forged = signPolicy(impostor.privateKey, "op-evil", { version: 2, minTierToShip: 1 });
  assert.throws(() => h.platform.policy().reload(forged), PolicyInvalid);
});

test("INV-19: tier-gating actually reads from the live policy, not a hardcoded constant", () => {
  const h = harness();
  const tighter = signPolicy(h.opKeys.privateKey, "op-1", { version: 2, minTierToShip: 3 });
  h.platform.policy().reload(tighter);
  // s2id was learned with vouchTier: 2 — now below the reloaded floor of 3.
  assert.throws(() => h.platform.createShipment(h.env, h.req, "sub_1"), TierTooLow);
});

/* --------------------------------------------------------- A10 / INV-20 - */

test("INV-20: requestShipment acks immediately; the capability is not observable before processBatch() runs", () => {
  const h = harness();
  const { transactionId } = h.platform.requestShipment(h.env, h.req, "sub_1");
  assert.ok(transactionId);

  let delivered: unknown = null;
  h.platform.onShipmentReady(transactionId, (result) => { delivered = result; });
  assert.equal(delivered, null, "callback must not fire before the batch settles");

  h.platform.processBatch();
  assert.ok(delivered, "callback must fire once the batch settles");
  assert.equal((delivered as { capability: { caveats: { s2id: string } } }).capability.caveats.s2id, h.s2id);
});

test("INV-20: a bad signature is rejected synchronously by requestShipment, never batched", () => {
  const h = harness();
  const tampered = { ...h.req, weightKg: 999 };
  assert.throws(() => h.platform.requestShipment(h.env, tampered, "sub_1"), SignatureInvalid);
});

test("INV-20: subscribing after the callback already landed still delivers the result — no race to observe it", () => {
  const h = harness();
  const { transactionId } = h.platform.requestShipment(h.env, h.req, "sub_1");
  h.platform.processBatch();

  let delivered: unknown = null;
  h.platform.onShipmentReady(transactionId, (result) => { delivered = result; });
  assert.ok(delivered);
});

test("INV-20: AsyncExchange delivers a callback exactly once per transaction", () => {
  const exchange = new AsyncExchange<{ code: string }>();
  const transactionId = exchange.begin();
  exchange.callback(transactionId, { code: "A" });
  assert.throws(() => exchange.callback(transactionId, { code: "B" }), DuplicateCallback);
  assert.throws(() => exchange.callback("txn_nonexistent", { code: "C" }), UnknownTransaction);
});
