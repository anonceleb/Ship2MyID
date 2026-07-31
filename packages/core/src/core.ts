/**
 * Zone-agnostic domain core.
 *
 * HARD RULE: this file may not import from ../../adapters/** or from any
 * service. tools/privacy-lint enforces it in CI. When the core still builds and
 * tests green with every adapter deleted, the standards-agnostic claim is true;
 * when it doesn't, it isn't.
 */
import { createHash, randomUUID } from "node:crypto";

/* ------------------------------------------------------------------ consent */

export type ConsentEntry = {
  seq: number;
  ref: string;
  subject: string; // root identity ref, never a raw identifier
  grantedTo: string; // participant id
  purpose: string;
  scope: string[];
  at: number;
  expiresAt: number;
  /** [A9] Hash of the disclosure policy in force when this grant was decided — see packages/policy/src/policy.ts. Not every append() is a disclosure decision, so this is optional. */
  policyHash?: string;
  prevHash: string;
  hash: string;
};

/**
 * Append-only, hash-chained consent ledger. Tamper-evidence without a
 * blockchain: rewriting any entry invalidates every hash after it.
 *
 * Consent is per-event and never standing — the record exists so that a later
 * decryption can be attributed to a purpose the consumer actually agreed to.
 */
export class ConsentLedger {
  #entries: ConsentEntry[] = [];
  /**
   * Revoked refs, tracked outside the hash chain itself — same shape as
   * NonceLedger's burned set. Revocation is a side-effect of an event
   * (the consumer pulling a capability mid-flight), not a correction to
   * history, so it must never mutate an existing entry: that would break
   * the entry's own hash and defeat tamper-evidence for the wrong reason.
   */
  #revoked = new Set<string>();

  append(e: Omit<ConsentEntry, "seq" | "ref" | "prevHash" | "hash">): ConsentEntry {
    const prevHash = this.#entries.at(-1)?.hash ?? "genesis";
    const seq = this.#entries.length;
    const ref = `cns_${randomUUID().replace(/-/g, "").slice(0, 20)}`;
    const body = { seq, ref, ...e, prevHash };
    const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    const entry: ConsentEntry = { ...body, hash };
    this.#entries.push(entry);
    return entry;
  }

  find(ref: string): ConsentEntry | undefined {
    return this.#entries.find((x) => x.ref === ref);
  }

  /** Consumer-initiated revocation, effective mid-flight — the consent-side twin of NonceLedger.revoke(). */
  revoke(ref: string): void {
    this.#revoked.add(ref);
  }

  /** Read-only: has this ref been revoked? A merchant status read needs this without the purpose/participant/expiry bundling isValidFor() does. */
  isRevoked(ref: string): boolean {
    return this.#revoked.has(ref);
  }

  isValidFor(ref: string, purpose: string, participantId: string, now = Date.now()): boolean {
    const e = this.find(ref);
    return (
      !!e &&
      !this.#revoked.has(ref) &&
      e.purpose === purpose &&
      e.grantedTo === participantId &&
      now <= e.expiresAt
    );
  }

  /** Returns the index of the first broken link, or -1 when the chain is intact. */
  verifyChain(): number {
    let prevHash = "genesis";
    for (const e of this.#entries) {
      const { hash, ...body } = e;
      const expected = createHash("sha256")
        .update(JSON.stringify({ ...body, prevHash }))
        .digest("hex");
      if (expected !== hash || e.prevHash !== prevHash) return e.seq;
      prevHash = hash;
    }
    return -1;
  }

  /** Test-only seam so the Inspector can demonstrate the chain failing. */
  tamperForDemo(seq: number, mutate: (e: ConsentEntry) => void): void {
    const e = this.#entries[seq];
    if (e) mutate(e);
  }

  entries(): readonly ConsentEntry[] {
    return this.#entries;
  }
}

/* -------------------------------------------------------------------- audit */

export type AuditRecord = {
  id: string;
  actor: string;
  purpose: string;
  consentRef: string;
  recordId: string;
  at: number;
};

export class AuditLog {
  #records: AuditRecord[] = [];
  write(r: Omit<AuditRecord, "id" | "at">): AuditRecord {
    const rec: AuditRecord = { id: randomUUID(), at: Date.now(), ...r };
    this.#records.push(rec);
    return rec;
  }
  forRecord(recordId: string): AuditRecord[] {
    return this.#records.filter((r) => r.recordId === recordId);
  }
  all(): readonly AuditRecord[] {
    return this.#records;
  }
}

/* ------------------------------------------------------------------- ports */

export type AddressPlaintext = {
  line1: string;
  line2?: string;
  locality: string;
  postcode: string;
  /** Nordic-style place-name addressing: no street, and that must not be an error. */
  placeName?: string;
};

export type GeoBucket = string;

export type IdentityProofingPort = {
  /** Returns the tier achieved, never the underlying credential. */
  proof(subjectRef: string, evidence: unknown): Promise<1 | 2 | 3>;
};

export type SortationPort = {
  /** Consumes plaintext transiently, emits a routing code. Never returns an address. */
  route(address: AddressPlaintext, service: string): Promise<{ sortationCode: string }>;
};

/**
 * Failed-delivery notification. §6.2: "platform notifies *consumer* (never
 * the merchant)". Addressed by subjectRef — a root-identity reference — so
 * nothing that reaches this port could be repurposed to notify a merchant
 * participant id by mistake.
 */
export type NotificationPort = {
  notify(subjectRef: string, event: string): void;
};

/* -------------------------------------------------------------- projections */

/**
 * Everything a merchant is ever allowed to hold. There is deliberately no
 * `address` field and no way to add one: Zone 3 storage is shaped by this type.
 */
export type MerchantView = {
  s2id: string;
  geoBucket: GeoBucket;
  verifiedTier: 1 | 2 | 3;
  serviceLevel: string;
  estimatedDelivery: string;
};

/**
 * Household / co-residency barrier, after Posten Norge's address register:
 * several people share an address, and by default they must not be able to
 * enumerate each other through it.
 */
export type Residency = {
  addressRecordId: string;
  subjectRef: string;
  barrier: boolean;
};

export function visibleCoResidents(all: Residency[], viewer: string, addressRecordId: string) {
  const viewerRow = all.find(
    (r) => r.subjectRef === viewer && r.addressRecordId === addressRecordId,
  );
  if (!viewerRow) return [];
  return all
    .filter((r) => r.addressRecordId === addressRecordId && r.subjectRef !== viewer)
    .filter((r) => !r.barrier && !viewerRow.barrier)
    .map((r) => r.subjectRef);
}

/* --------------------------------------------------------------- cohorts */

export const K_ANON_FLOOR = 25;

/** No cohort below k is ever exposed to a brand. Returns 0 or a size >= k. */
export function cohortSize(matching: number): number {
  return matching >= K_ANON_FLOOR ? matching : 0;
}
