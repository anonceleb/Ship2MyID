/**
 * The privacy claims, executable.
 *
 * "Our privacy claims are eight tests. If they go red, we don't ship. You can
 * read them; they're in the repo." Verifiable beats trustworthy.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms, RecordShredded, TamperDetected, seal, open } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret, deriveS2ID, linkabilityScore } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest, SignatureInvalid } from "../../packages/registry/src/signing.ts";
import { NonceLedger, CapabilityBurned, attenuate, AttenuationWidened, mint } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger, cohortSize, visibleCoResidents, K_ANON_FLOOR } from "../../packages/core/src/core.ts";
import { Vault, AuditPrecondition } from "../../services/vault/src/vault.ts";
import { Platform, MerchantDatabase } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";

const PII_SHAPED = /address|line1|street|postcode|phone|email|fullname|nationalid/i;

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
    participantId: "merchant.meridia.example",
    role: "merchant", keyId: "k1", publicKey: mk.publicKey, tier: 2, status: "active",
  });

  const root = newRootSecret();
  const s2id = platform.issueS2ID(root, "merchant.meridia.example");
  const rec = vault.store({
    id: "rec_1", subjectRef: "sub_1", tenantId: "meridia-post",
    address: { line1: "14 Harbour Lane", locality: "Calder", postcode: "4820" },
    geoBucket: geoBucketFor("4820"), vouchTier: 2,
  });
  vault.bind(s2id, rec.id);
  platform.learnProjection(s2id, { geoBucket: rec.geoBucket, vouchTier: 2 });

  return { kms, audit, consent, nonces, capSecret, registry, vault, platform, root, s2id, mk };
}

async function shipOnce(h: ReturnType<typeof harness>) {
  const req = { s2id: h.s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
  const env = signRequest("merchant.meridia.example", "k1", h.mk.privateKey, req);
  return h.platform.createShipment(env, req, "sub_1");
}

test("INV-1: no merchant-held record may contain an address-shaped field", async () => {
  const h = harness();
  const { capability, merchantView } = await shipOnce(h);
  const db = new MerchantDatabase();
  db.save(merchantView, capability);
  const offenders = db.columns().filter((c) => PII_SHAPED.test(c));
  assert.deepEqual(offenders, [], `merchant DB exposes ${offenders.join(", ")}`);
});

test("INV-2: capability tokens carry no plaintext address under any encoding", async () => {
  const h = harness();
  const { capability } = await shipOnce(h);
  for (const enc of ["utf8", "base64", "hex"] as const) {
    const blob = Buffer.from(JSON.stringify(capability)).toString(enc).toLowerCase();
    assert.ok(!blob.includes("harbour"), `address leaked in ${enc} encoding`);
    assert.ok(!blob.includes("calder"), `locality leaked in ${enc} encoding`);
  }
});

test("INV-3: a spent capability cannot be replayed", async () => {
  const h = harness();
  const { capability } = await shipOnce(h);
  const routed = await h.vault.resolve(capability, "merchant.meridia.example");
  assert.match(routed.sortationCode, /^MRD-[0-9A-F]{10}$/);
  await assert.rejects(
    () => h.vault.resolve(capability, "merchant.meridia.example"),
    CapabilityBurned,
  );
});

test("INV-4: no decryption path exists that skips the audit record", async () => {
  const h = harness();
  const { capability } = await shipOnce(h);
  await assert.rejects(() => h.vault.resolveUnaudited(capability), AuditPrecondition);

  await h.vault.resolve(capability, "merchant.meridia.example");
  const trail = h.audit.forRecord("rec_1");
  assert.equal(trail.length, 1);
  assert.equal(trail[0]!.actor, "merchant.meridia.example");
  assert.equal(trail[0]!.purpose, "delivery");
  assert.ok(trail[0]!.consentRef.startsWith("cns_"), "decryption is bound to a consent record");
});

test("INV-5: two merchants cannot correlate the same consumer", () => {
  const root = newRootSecret();
  const a = deriveS2ID(root, "merchant-a.example");
  const b = deriveS2ID(root, "merchant-b.example");
  assert.notEqual(a, b);
  assert.equal(linkabilityScore(a, b), 0);
  // ...but each merchant still recognises its own returning customer.
  assert.equal(deriveS2ID(root, "merchant-a.example"), a);
});

test("INV-6: crypto-shred renders historical ciphertext permanently unreadable", () => {
  const h = harness();
  assert.equal(h.vault.tryRead("rec_1").locality, "Calder");
  const erased = h.vault.erase("sub_1");
  assert.deepEqual(erased, ["rec_1"]);
  assert.throws(() => h.vault.tryRead("rec_1"), RecordShredded);
});

test("INV-7: no cohort below k=25 is ever exposed to a brand", () => {
  assert.equal(cohortSize(3), 0);
  assert.equal(cohortSize(24), 0);
  assert.equal(cohortSize(K_ANON_FLOOR), K_ANON_FLOOR);
});

test("INV-8: adapters are removable — core has no adapter dependency", async () => {
  const core = await import("../../packages/core/src/core.ts");
  assert.ok(typeof core.cohortSize === "function");
  assert.ok(typeof core.ConsentLedger === "function");
  // Enforced structurally by tools/privacy-lint; asserted here as a smoke check.
});

/* ---- invariants added after reviewing ONDC / UIDAI / Posten practice ---- */

test("INV-9: every inter-participant request is signed and verified (ONDC)", async () => {
  const h = harness();
  const req = { s2id: h.s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };
  const env = signRequest("merchant.meridia.example", "k1", h.mk.privateKey, req);

  // tampering with the body after signing is detected
  assert.throws(
    () => h.registry.verify(env, { ...req, weightKg: 900 }),
    SignatureInvalid,
  );
  // a suspended participant is refused even with a valid signature
  h.registry.suspend("merchant.meridia.example");
  assert.throws(() => h.registry.verify(env, req));
});

test("INV-10: the consent chain is tamper-evident (hash-chained ledger)", async () => {
  const h = harness();
  await shipOnce(h);
  await shipOnce(h);
  assert.equal(h.consent.verifyChain(), -1, "chain should verify clean");
  h.consent.tamperForDemo(0, (e) => { e.purpose = "marketing"; });
  assert.equal(h.consent.verifyChain(), 0, "tampering must be detected at entry 0");
});

test("INV-11: attenuation may narrow a grant but never widen it", () => {
  const secret = randomBytes(32);
  const cap = mint(secret, {
    s2id: "MER-AAAA-BBBB-CCCC", purpose: "delivery", maxWeightKg: 5,
    carrier: "MER-POST", expiresAt: Date.now() + 60_000, singleUse: true,
    consentRef: "cns_x", destinationKind: "door",
  });
  const narrower = attenuate(secret, cap, { maxWeightKg: 2 }, "courier-7");
  assert.equal(narrower.caveats.maxWeightKg, 2);
  assert.throws(() => attenuate(secret, cap, { maxWeightKg: 50 }, "courier-7"), AttenuationWidened);
  assert.throws(() => attenuate(secret, cap, { purpose: "return" }, "courier-7"), AttenuationWidened);
});

test("INV-12: co-residents cannot enumerate each other through a shared address (Posten)", () => {
  const rows = [
    { addressRecordId: "rec_1", subjectRef: "sub_1", barrier: false },
    { addressRecordId: "rec_1", subjectRef: "sub_2", barrier: false },
    { addressRecordId: "rec_1", subjectRef: "sub_3", barrier: true },
  ];
  assert.deepEqual(visibleCoResidents(rows, "sub_1", "rec_1"), ["sub_2"]);
  assert.deepEqual(visibleCoResidents(rows, "sub_3", "rec_1"), [], "barriered resident sees nobody");
});

test("INV-13: ciphertext moved between records fails closed (AAD binding)", () => {
  const kms = new Kms();
  const a = seal(kms, "meridia-post", "rec_a", "14 Harbour Lane");
  assert.throws(() => open(kms, "meridia-post", "rec_b", a), Error);
});
