/**
 * [A4] COSE-signed, offline-verifiable labels — executable claims.
 *
 * These sit alongside INV-1..13 rather than renumbering them: A4 is a Phase 1
 * addition from PRIOR_ART_REVIEW.md, not one of the original thirteen. Same
 * standard applies — if these go red, the label doesn't ship.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { NonceLedger, mint } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { MeridiaSortation } from "../../adapters/postal-meridia/src/adapter.ts";
import { OperatorKeyring } from "../../packages/labels/src/keyring.ts";
import {
  hashContactChannel,
  verifyLabelOffline,
  LabelExpired,
  LabelInvalid,
  LabelKeyUnknown,
} from "../../packages/labels/src/label.ts";

const PII_SHAPED = /address|line1|street|postcode|phone|email|fullname|nationalid/i;

function harness() {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const labelKeyring = new OperatorKeyring();
  labelKeyring.rotate();
  const vault = new Vault({
    kms, audit, consent, nonces, capSecret,
    sortation: new MeridiaSortation(),
    labelKeyring,
  });
  const cap = mint(capSecret, {
    s2id: "MER-7QK4-9XT2-BN5F",
    purpose: "delivery",
    maxWeightKg: 2,
    carrier: "MER-POST",
    expiresAt: Date.now() + 3600_000,
    singleUse: true,
    consentRef: "cns_test",
    destinationKind: "locker",
  });
  return { vault, capSecret, cap };
}

test("A4: a COSE label verifies offline with only cached public keys — no vault, no network", () => {
  const h = harness();
  const label = h.vault.mintLabel(h.cap);
  const claims = verifyLabelOffline(h.vault.labelPublicMaterial(), label.token);
  assert.equal(claims.s2id, h.cap.caveats.s2id);
  assert.equal(claims.capabilityId, h.cap.id);
  assert.equal(claims.carrier, h.cap.caveats.carrier);
});

test("A4: the label carries no address-shaped field under any encoding", () => {
  const h = harness();
  const label = h.vault.mintLabel(h.cap);
  const raw = Buffer.from(label.token, "base64url");
  for (const enc of ["utf8", "base64", "hex"] as const) {
    const blob = raw.toString(enc).toLowerCase();
    assert.ok(!blob.includes("harbour"), `address leaked in ${enc} encoding`);
    assert.ok(!blob.includes("calder"), `locality leaked in ${enc} encoding`);
  }
  const offenders = Object.keys(label.claims).filter((k) => PII_SHAPED.test(k) && k !== "contactChannelHash");
  assert.deepEqual(offenders, [], `label claims expose ${offenders.join(", ")}`);
});

test("A4: a byte-flipped label fails offline verification", () => {
  const h = harness();
  const label = h.vault.mintLabel(h.cap);
  const bytes = Buffer.from(label.token, "base64url");
  bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 0xff;
  assert.throws(
    () => verifyLabelOffline(h.vault.labelPublicMaterial(), bytes.toString("base64url")),
    LabelInvalid,
  );
});

test("A4: a scanner that has not synced a rotated key rejects the new label, then accepts it once synced", () => {
  const h = harness();
  const staleKeys = h.vault.labelPublicMaterial();
  h.vault.rotateLabelKey();
  const label = h.vault.mintLabel(h.cap);

  assert.throws(() => verifyLabelOffline(staleKeys, label.token), LabelKeyUnknown);
  const claims = verifyLabelOffline(h.vault.labelPublicMaterial(), label.token);
  assert.equal(claims.capabilityId, h.cap.id);
});

test("A4: an expired label is rejected offline", () => {
  const h = harness();
  const label = h.vault.mintLabel(h.cap);
  assert.throws(
    () => verifyLabelOffline(h.vault.labelPublicMaterial(), label.token, Date.now() + 30 * 24 * 3600 * 1000),
    LabelExpired,
  );
});

test("A4: a contact channel travels only as a hash, never in the clear (Aadhaar offline-eKYC pattern)", () => {
  const h = harness();
  const channel = "buyer@example.com";
  const label = h.vault.mintLabel(h.cap, { contactChannel: channel });
  assert.equal(label.claims.contactChannelHash, hashContactChannel(channel));

  const raw = Buffer.from(label.token, "base64url");
  for (const enc of ["utf8", "base64", "hex"] as const) {
    assert.ok(!raw.toString(enc).toLowerCase().includes("buyer@example.com"), `contact channel leaked in ${enc}`);
  }
});

test("A4: a label cannot be minted for a capability that fails verification", () => {
  const h = harness();
  const forged = mint(randomBytes(32), h.cap.caveats);
  assert.throws(() => h.vault.mintLabel(forged));
});
