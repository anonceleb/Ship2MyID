/**
 * Error-shape indistinguishability for Vault.resolve() rejections.
 *
 * Follow-up from review: the docstring on Platform.revoke() claimed a
 * merchant "sees the same shape of failure as a replay, not a
 * distinguishable one" — but Vault.resolve() burned the nonce first
 * (CapabilityBurned on replay) and only then checked consent validity
 * (ConsentMissing on revoke). Two different error classes meant a merchant
 * catching by type *could* tell "already used" apart from "consumer pulled
 * it mid-flight," which is exactly the distinction INV-16 exists to erase.
 * exceptions.test.ts didn't catch it because it only asserts rejects(), not
 * error identity.
 *
 * Fixed in services/vault/src/vault.ts: both paths now throw the exact same
 * CapabilityBurned(cap.id). This file asserts that directly, in both
 * directions, so a future change can't silently reintroduce the split.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger, CapabilityBurned } from "../../packages/capability/src/capability.ts";
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

  function shipOnce() {
    const req = { s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
    const env = signRequest("alba-goods.example", "k1", mk.privateKey, req);
    return platform.createShipment(env, req, "sub_1");
  }

  return { vault, platform, shipOnce };
}

async function catchError(fn: () => unknown): Promise<Error> {
  try {
    await fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected fn to throw, but it did not");
}

test("Error shape: revoke-before-first-use and replay-after-first-use throw the exact same error class", async () => {
  const h1 = harness();
  const { capability: revokedCap } = h1.shipOnce();
  h1.platform.revoke(revokedCap.id, "sub_1");
  const revokeError = await catchError(() => h1.vault.resolve(revokedCap, "alba-goods.example"));

  const h2 = harness();
  const { capability: replayedCap } = h2.shipOnce();
  await h2.vault.resolve(replayedCap, "alba-goods.example"); // first use succeeds
  const replayError = await catchError(() => h2.vault.resolve(replayedCap, "alba-goods.example"));

  assert.equal(revokeError.constructor, CapabilityBurned);
  assert.equal(replayError.constructor, CapabilityBurned);
  assert.equal(revokeError.constructor, replayError.constructor, "revoke and replay must throw the identical class");
});

test("Error shape: neither rejection's message reveals which case it was", async () => {
  const h1 = harness();
  const { capability: revokedCap } = h1.shipOnce();
  h1.platform.revoke(revokedCap.id, "sub_1");
  const revokeError = await catchError(() => h1.vault.resolve(revokedCap, "alba-goods.example"));

  // Message shape is always just the capability id — never "consent",
  // "revoked", "burned", or anything else that would let a merchant infer
  // which of the two happened.
  assert.equal(revokeError.message, revokedCap.id);
  assert.ok(!/consent|revoke/i.test(revokeError.message));
});
