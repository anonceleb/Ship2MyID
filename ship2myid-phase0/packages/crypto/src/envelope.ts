/**
 * Envelope encryption + crypto-shredding.
 *
 * Hierarchy (mirrors UIDAI Aadhaar Data Vault key discipline):
 *   root key (HSM/KMS boundary — never exported)
 *     └── tenant DEK (one per postal operator, wrapped by root)
 *           └── record key (HKDF-derived per record — never stored)
 *
 * Deriving record keys rather than storing them is what makes crypto-shredding
 * cheap: erasure destroys one salt, and every ciphertext derived from it becomes
 * permanently unreadable — including copies in immutable event logs and backups.
 */
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const ALG = "chacha20-poly1305";
const KEY_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;

export type Ciphertext = {
  /** Which tenant DEK generation produced this. Enables rotation without re-encrypt. */
  keyId: string;
  /** Per-record salt. Destroying this is the crypto-shred. */
  saltId: string;
  nonce: string;
  ct: string;
  tag: string;
};

/** Thrown when a record's shred salt has been destroyed. Erasure is provable. */
export class RecordShredded extends Error {
  constructor(recordId: string) {
    super(`record ${recordId} has been crypto-shredded; plaintext is unrecoverable`);
  }
}

export class TamperDetected extends Error {}

/**
 * The KMS boundary. In the demo this is in-process; in production the root key
 * lives in an HSM and `wrap`/`unwrap` are remote calls. The interface does not
 * change — which is the point of having it.
 */
export class Kms {
  #root: Buffer;
  #tenantDeks = new Map<string, Buffer>();
  /** recordId -> salt. Deleting an entry here is the erasure primitive. */
  #shredSalts = new Map<string, Buffer>();

  constructor(root?: Buffer) {
    this.#root = root ?? randomBytes(KEY_LEN);
  }

  /** One DEK per tenant. Tenant A's compromise can never read tenant B. */
  dekFor(tenantId: string, generation = 1): { key: Buffer; keyId: string } {
    const keyId = `${tenantId}:g${generation}`;
    let key = this.#tenantDeks.get(keyId);
    if (!key) {
      key = Buffer.from(
        hkdfSync("sha256", this.#root, Buffer.from(keyId), Buffer.from("s2id/tenant-dek"), KEY_LEN),
      );
      this.#tenantDeks.set(keyId, key);
    }
    return { key, keyId };
  }

  mintShredSalt(recordId: string): string {
    const salt = randomBytes(16);
    this.#shredSalts.set(recordId, salt);
    return recordId;
  }

  saltFor(recordId: string): Buffer {
    const salt = this.#shredSalts.get(recordId);
    if (!salt) throw new RecordShredded(recordId);
    return salt;
  }

  /** Right to erasure. Instant, and effective against append-only stores. */
  shred(recordId: string): void {
    this.#shredSalts.delete(recordId);
  }

  hasSalt(recordId: string): boolean {
    return this.#shredSalts.has(recordId);
  }
}

function recordKey(kms: Kms, tenantId: string, recordId: string, generation = 1): Buffer {
  const { key } = kms.dekFor(tenantId, generation);
  const salt = kms.saltFor(recordId);
  return Buffer.from(
    hkdfSync("sha256", key, salt, Buffer.from(`s2id/record/${recordId}`), KEY_LEN),
  );
}

/**
 * AAD binds ciphertext to its record identity. A row copied into another row's
 * slot fails to decrypt rather than silently returning the wrong person's address.
 */
export function seal(
  kms: Kms,
  tenantId: string,
  recordId: string,
  plaintext: string,
  generation = 1,
): Ciphertext {
  if (!kms.hasSalt(recordId)) kms.mintShredSalt(recordId);
  const key = recordKey(kms, tenantId, recordId, generation);
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv(ALG, key, nonce, { authTagLength: TAG_LEN });
  cipher.setAAD(Buffer.from(`${tenantId}|${recordId}`));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    keyId: kms.dekFor(tenantId, generation).keyId,
    saltId: recordId,
    nonce: nonce.toString("base64"),
    ct: ct.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

export function open(
  kms: Kms,
  tenantId: string,
  recordId: string,
  box: Ciphertext,
  generation = 1,
): string {
  const key = recordKey(kms, tenantId, recordId, generation); // throws RecordShredded
  const decipher = createDecipheriv(ALG, key, Buffer.from(box.nonce, "base64"), {
    authTagLength: TAG_LEN,
  });
  decipher.setAAD(Buffer.from(`${tenantId}|${recordId}`));
  decipher.setAuthTag(Buffer.from(box.tag, "base64"));
  try {
    return Buffer.concat([
      decipher.update(Buffer.from(box.ct, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new TamperDetected(`AEAD verification failed for record ${recordId}`);
  }
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
