/**
 * A narrated end-to-end run of the Phase 0 ship flow.
 * `npm run demo` — no network, no database, no cloud account.
 */
import { randomBytes } from "node:crypto";
import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret, deriveS2ID } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform, MerchantDatabase } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { verifyLabelOffline } from "../../packages/labels/src/label.ts";

const line = (s = "") => console.log(s);
const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);

const kms = new Kms();
const audit = new AuditLog();
const consent = new ConsentLedger();
const nonces = new NonceLedger();
const capSecret = randomBytes(32);
const registry = new Registry();
const vault = new Vault({ kms, audit, consent, nonces, capSecret, sortation: new MeridiaSortation() });
const platform = new Platform({ registry, consent, capSecret });

step(1, "Two merchants join the network. Each publishes an Ed25519 key.");
for (const id of ["alba-goods.example", "corvid-tools.example"]) {
  const kp = newKeyPair();
  registry.register({ participantId: id, role: "merchant", keyId: "k1", publicKey: kp.publicKey, tier: 2, status: "active" });
  (registry as any)[`_priv_${id}`] = kp.privateKey;
  line(`    registered ${id}`);
}

step(2, "A consumer is vouched by the operator and their address is sealed in Zone 1.");
const root = newRootSecret();
const rec = vault.store({
  id: "rec_1", subjectRef: "sub_1", tenantId: "meridia-post",
  address: { line1: "14 Harbour Lane", locality: "Calder", postcode: "4820" },
  geoBucket: geoBucketFor("4820"), vouchTier: 2,
});
line(`    sealed. ciphertext=${rec.ciphertext.ct.slice(0, 24)}...  geoBucket=${rec.geoBucket}`);

step(3, "The same person gets a DIFFERENT identifier at each merchant.");
const idA = deriveS2ID(root, "alba-goods.example");
const idB = deriveS2ID(root, "corvid-tools.example");
vault.bind(idA, rec.id); vault.bind(idB, rec.id);
platform.learnProjection(idA, { geoBucket: rec.geoBucket, vouchTier: 2 });
line(`    alba-goods sees   ${idA}`);
line(`    corvid-tools sees ${idB}`);
line(`    -> no join key. The two databases cannot be merged on this person.`);

step(4, "Merchant signs an order request; platform verifies and mints a capability.");
const req = { s2id: idA, weightKg: 2, carrier: "MER-POST", destinationKind: "locker" as const };
const env = signRequest("alba-goods.example", "k1", (registry as any)["_priv_alba-goods.example"], req);
const { capability, merchantView } = platform.createShipment(env, req, "sub_1");
line(`    capability ${capability.id}`);
line(`    caveats: ${JSON.stringify(capability.caveats, null, 2).split("\n").join("\n    ")}`);

step(5, "This is the ENTIRE merchant database. Inspect it.");
const db = new MerchantDatabase();
db.save(merchantView, capability);
line(`    columns: ${db.columns().join(", ")}`);
line(`    customers: ${JSON.stringify(db.customers)}`);
line(`    -> no address field exists, and privacy-lint fails the build if one is added.`);

step(6, "The vault mints a COSE-signed label. A handheld scanner verifies it — offline, no network.");
const label = vault.mintLabel(capability);
line(`    label token (base64url COSE_Sign1, ${label.token.length} chars): ${label.token.slice(0, 48)}...`);
const scanned = verifyLabelOffline(vault.labelPublicMaterial(), label.token);
line(`    scanner decoded (public keys only, no vault, no network): ${JSON.stringify(scanned)}`);
line(`    -> signature checks out, nothing address-shaped in the token.`);

step(7, "The operator rotates its signing key. Labels already in the field still verify; a scanner that hasn't synced rejects the new one.");
const staleKeys = vault.labelPublicMaterial();
vault.rotateLabelKey();
const label2 = vault.mintLabel(capability);
try {
  verifyLabelOffline(staleKeys, label2.token);
} catch (e) {
  line(`    scanner with stale keys: ${(e as Error).constructor.name}`);
}
line(`    scanner after syncing: ${JSON.stringify(verifyLabelOffline(vault.labelPublicMaterial(), label2.token))}`);

step(8, "The carrier redeems the capability. The vault routes it.");
const routed = await vault.resolve(capability, "alba-goods.example");
line(`    sortation code: ${routed.sortationCode}`);
line(`    audit trail: ${JSON.stringify(audit.all()[0])}`);

step(9, "Replay the same capability.");
try { await vault.resolve(capability, "alba-goods.example"); }
catch (e) { line(`    rejected: ${(e as Error).constructor.name}`); }

step(10, "Consumer exercises erasure. Watch the historical ciphertext die.");
line(`    before: ${JSON.stringify(vault.tryRead("rec_1"))}`);
vault.erase("sub_1");
try { vault.tryRead("rec_1"); }
catch (e) { line(`    after:  ${(e as Error).constructor.name} — unrecoverable, including from backups`); }

step(11, "Consent chain integrity.");
line(`    verifyChain() = ${consent.verifyChain()} (-1 means intact)`);
consent.tamperForDemo(0, (e) => { e.purpose = "marketing"; });
line(`    after tampering entry 0: verifyChain() = ${consent.verifyChain()}`);
line();
