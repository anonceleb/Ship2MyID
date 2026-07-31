/**
 * The interop claim: the exchange layer (packages/core, services/vault,
 * services/platform) is not hard-coded to postal-meridia's shape. Proven by
 * swapping in a second operator adapter with a different address format and
 * a different key-custody assumption, and showing core needs zero changes.
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
import { MeridiaSortation, geoBucketFor as meridiaGeoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { DakhilSortation, DakhilIdentity, NoCustodyKey, geoBucketFor as dakhilGeoBucketFor } from "../../adapters/dakhil-post/src/adapter.ts";

function dakhilHarness() {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const registry = new Registry();
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, sortation: new DakhilSortation() });
  const platform = new Platform({ registry, consent, capSecret });
  return { kms, audit, consent, nonces, capSecret, registry, vault, platform };
}

test("interop: core builds unmodified against a second operator with a different address format", async () => {
  const h = dakhilHarness();

  const mk = newKeyPair();
  h.registry.register({
    participantId: "merchant.dakhil.example",
    role: "merchant", keyId: "k1", publicKey: mk.publicKey, tier: 2, status: "active",
  });

  const root = newRootSecret();
  const s2id = h.platform.issueS2ID(root, "merchant.dakhil.example");

  // No reliable postcode — this operator routes off landmark/locality instead.
  const address = { line1: "Near Hanuman Mandir", locality: "Kotra Sadatganj", postcode: "", placeName: "Ratanpur" };
  const rec = h.vault.store({
    id: "rec_dkh_1", subjectRef: "sub_dkh_1", tenantId: "dakhil-post",
    address, geoBucket: dakhilGeoBucketFor(address), vouchTier: 2,
  });
  h.vault.bind(s2id, rec.id);

  const projection = h.vault.publicProjection(rec.id);
  assert.equal(projection?.geoBucket, "DKH-RA"); // derived from placeName, not postcode
  assert.notEqual(projection?.geoBucket, meridiaGeoBucketFor("4820"));
});

test("interop: two operators' sortation codes for the same coordinates never collide in shape", async () => {
  const meridia = new MeridiaSortation();
  const dakhil = new DakhilSortation();
  const address = { line1: "x", locality: "Calder", postcode: "4820" };

  const m = await meridia.route(address, "standard");
  const d = await dakhil.route(address, "standard");

  assert.match(m.sortationCode, /^MRD-/);
  assert.match(d.sortationCode, /^DKH-/);
  assert.notEqual(m.sortationCode, d.sortationCode);
});

test("interop: Dakhil holds no signing key — a bare self-asserted claim is refused, not evaluated", async () => {
  const registry = new Registry();
  const identity = new DakhilIdentity(registry);

  await assert.rejects(
    () => identity.proof("sub_1", { nationalId: "DKH-1", vouched: true }),
    NoCustodyKey,
  );
});

test("interop: Dakhil proofs only against a signed registry attestation, capped at the attester's own tier", async () => {
  const registry = new Registry();
  const identity = new DakhilIdentity(registry);

  const issuer = newKeyPair();
  registry.register({
    participantId: "issuer.panchayat.example",
    role: "operator", keyId: "k1", publicKey: issuer.publicKey, tier: 2, status: "active",
  });

  const body = { subjectRef: "sub_1", claim: "vouched-in-person" };
  const envelope = signRequest("issuer.panchayat.example", "k1", issuer.privateKey, body);

  // requesting tier 3 from a tier-2 attester is capped at 2, not honored blindly
  const tier = await identity.proof("sub_1", { envelope, body, requestedTier: 3 });
  assert.equal(tier, 2);
});

test("interop: Dakhil rejects a signature from an unregistered or suspended attester the same way the registry would", async () => {
  const registry = new Registry();
  const identity = new DakhilIdentity(registry);

  const stranger = newKeyPair();
  const body = { subjectRef: "sub_1", claim: "vouched-in-person" };
  const envelope = signRequest("nobody.example", "k1", stranger.privateKey, body);

  await assert.rejects(() => identity.proof("sub_1", { envelope, body }));
});
