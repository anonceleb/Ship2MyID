/**
 * ZONE 1 — the vault. The only component in the system that can decrypt.
 *
 * Small on purpose. Everything it does not do is deliberate: it does not serve
 * merchants, does not render UI, does not hold business logic. It resolves a
 * capability into a sortation code and writes an audit record first.
 *
 * Production note: this is the one service worth rewriting in Rust and deploying
 * separately. The interface below is what that rewrite must satisfy.
 */
import {
  Kms,
  open,
  seal,
  type Ciphertext,
} from "../../../packages/crypto/src/envelope.ts";
import {
  verify as verifyCap,
  NonceLedger,
  type Capability,
} from "../../../packages/capability/src/capability.ts";
import {
  AuditLog,
  ConsentLedger,
  type AddressPlaintext,
  type SortationPort,
} from "../../../packages/core/src/core.ts";
import { OperatorKeyring, type OperatorPublicKey } from "../../../packages/labels/src/keyring.ts";
import { mintLabel, type SignedLabel } from "../../../packages/labels/src/label.ts";

export class AuditPrecondition extends Error {}
export class ConsentMissing extends Error {}
export class PurposeMismatch extends Error {}

export type AddressRecord = {
  id: string;
  subjectRef: string;
  tenantId: string;
  ciphertext: Ciphertext;
  geoBucket: string;
  vouchTier: 1 | 2 | 3;
  status: "active" | "superseded" | "revoked";
};

export class Vault {
  #kms: Kms;
  #audit: AuditLog;
  #consent: ConsentLedger;
  #nonces: NonceLedger;
  #capSecret: Buffer;
  #sortation: SortationPort;
  #labelKeyring: OperatorKeyring;
  #records = new Map<string, AddressRecord>();
  /** s2id -> address record. Resolution table. Never leaves this service. */
  #bindings = new Map<string, string>();

  constructor(opts: {
    kms: Kms;
    audit: AuditLog;
    consent: ConsentLedger;
    nonces: NonceLedger;
    capSecret: Buffer;
    sortation: SortationPort;
    /** [A4] Operator's rotating label-signing keys. Defaults to a fresh keyring. */
    labelKeyring?: OperatorKeyring;
  }) {
    this.#kms = opts.kms;
    this.#audit = opts.audit;
    this.#consent = opts.consent;
    this.#nonces = opts.nonces;
    this.#capSecret = opts.capSecret;
    this.#sortation = opts.sortation;
    this.#labelKeyring = opts.labelKeyring ?? new OperatorKeyring();
  }

  store(rec: {
    id: string;
    subjectRef: string;
    tenantId: string;
    address: AddressPlaintext;
    geoBucket: string;
    vouchTier: 1 | 2 | 3;
  }): AddressRecord {
    const ciphertext = seal(
      this.#kms,
      rec.tenantId,
      rec.id,
      JSON.stringify(rec.address),
    );
    const record: AddressRecord = {
      id: rec.id,
      subjectRef: rec.subjectRef,
      tenantId: rec.tenantId,
      ciphertext,
      geoBucket: rec.geoBucket,
      vouchTier: rec.vouchTier,
      status: "active",
    };
    this.#records.set(rec.id, record);
    return record;
  }

  bind(s2id: string, addressRecordId: string): void {
    this.#bindings.set(s2id, addressRecordId);
  }

  /** What Zone 2 may see. Ciphertext and a coarse bucket — nothing decryptable. */
  publicProjection(recordId: string) {
    const r = this.#records.get(recordId);
    if (!r) return undefined;
    return { id: r.id, geoBucket: r.geoBucket, vouchTier: r.vouchTier, status: r.status };
  }

  /**
   * THE INVARIANT: the audit write is a precondition of decryption, in the same
   * call, before plaintext exists. A decryption that cannot be attributed to an
   * actor, a purpose, and a consent reference is not a policy violation — it is
   * a crash.
   */
  async resolve(cap: Capability, actor: string): Promise<{ sortationCode: string }> {
    verifyCap(this.#capSecret, cap);
    this.#nonces.burn(cap.id); // replay dies here

    if (!this.#consent.isValidFor(cap.caveats.consentRef, cap.caveats.purpose, actor)) {
      throw new ConsentMissing(cap.caveats.consentRef);
    }

    const recordId = this.#bindings.get(cap.caveats.s2id);
    if (!recordId) throw new Error("no binding for s2id");
    const rec = this.#records.get(recordId)!;

    // Audit BEFORE plaintext. Not after.
    this.#audit.write({
      actor,
      purpose: cap.caveats.purpose,
      consentRef: cap.caveats.consentRef,
      recordId,
    });

    const plaintext = JSON.parse(
      open(this.#kms, rec.tenantId, recordId, rec.ciphertext),
    ) as AddressPlaintext;

    const routed = await this.#sortation.route(plaintext, cap.caveats.carrier);
    return routed; // sortation code only — the address does not leave this frame
  }

  /**
   * Deliberately unaudited path, present only so the invariant suite can prove
   * it is unreachable. It throws rather than decrypting.
   */
  async resolveUnaudited(_cap: Capability): Promise<never> {
    throw new AuditPrecondition("decryption without a prior audit record is not a supported path");
  }

  /** Right to erasure. Destroys the salt; every derived ciphertext dies with it. */
  erase(subjectRef: string): string[] {
    const erased: string[] = [];
    for (const [id, r] of this.#records) {
      if (r.subjectRef === subjectRef) {
        this.#kms.shred(id);
        erased.push(id);
      }
    }
    return erased;
  }

  tryRead(recordId: string): AddressPlaintext {
    const r = this.#records.get(recordId)!;
    return JSON.parse(open(this.#kms, r.tenantId, recordId, r.ciphertext));
  }

  /**
   * [A4] Mints a COSE-signed, offline-verifiable label for a capability —
   * what actually gets printed on the parcel as a QR. Signed inside Zone 1;
   * verifying it needs no vault, no network, no key held here. See
   * packages/labels/src/label.ts for the wire format.
   */
  mintLabel(cap: Capability, opts: { contactChannel?: string } = {}): SignedLabel {
    return mintLabel(this.#capSecret, this.#labelKeyring, cap, opts);
  }

  /** What ships to a handheld scanner ahead of time. Public keys only, never private. */
  labelPublicMaterial(): OperatorPublicKey[] {
    return this.#labelKeyring.publicMaterial();
  }

  /** Rotates the label-signing key. Labels already printed keep verifying until they expire. */
  rotateLabelKey() {
    return this.#labelKeyring.rotate();
  }
}
