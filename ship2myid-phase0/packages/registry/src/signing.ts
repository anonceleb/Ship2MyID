/**
 * Network participant registry + request signing.
 *
 * Lifted from ONDC/Beckn: every request between participants is signed with the
 * sender's Ed25519 key and verified against a public key published in a shared
 * registry. Two properties this buys that mTLS alone does not:
 *
 *   1. Non-repudiation. A signed request is evidence, not just an authenticated
 *      channel — it survives past the connection that carried it.
 *   2. Participant identity is a network fact, not a deployment fact. Onboarding
 *      a merchant is a registry entry, not a firewall change.
 *
 * Signature envelope follows the Beckn shape:
 *   keyId="<participant_id>|<key_id>|ed25519", created, expires, digest
 */
import {
  createHash,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";

export type ParticipantRole = "merchant" | "operator" | "brand" | "platform";

export type Participant = {
  participantId: string;
  role: ParticipantRole;
  keyId: string;
  publicKey: string; // base64 raw SPKI
  /** Accreditation tier, after UIDAI's AUA/KUA licensing model. Gates capability scope. */
  tier: 1 | 2 | 3;
  status: "active" | "suspended";
};

export type SignedEnvelope = {
  participantId: string;
  keyId: string;
  created: number;
  expires: number;
  digest: string;
  signature: string;
};

export class SignatureInvalid extends Error {}
export class ParticipantUnknown extends Error {}
export class ParticipantSuspended extends Error {}

export function newKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

function pub(b64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(b64, "base64"), type: "spki", format: "der" });
}
function priv(b64: string): KeyObject {
  return createPrivateKey({ key: Buffer.from(b64, "base64"), type: "pkcs8", format: "der" });
}

export function digestOf(body: unknown): string {
  return createHash("sha256").update(canonical(body)).digest("base64");
}

/** Deterministic JSON. Signature stability depends on key order being fixed. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

function signingString(e: Omit<SignedEnvelope, "signature">): string {
  return `(created): ${e.created}\n(expires): ${e.expires}\ndigest: ${e.digest}`;
}

export function signRequest(
  participantId: string,
  keyId: string,
  privateKeyB64: string,
  body: unknown,
  ttlSeconds = 300,
): SignedEnvelope {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    participantId,
    keyId,
    created,
    expires: created + ttlSeconds,
    digest: digestOf(body),
  };
  const signature = edSign(null, Buffer.from(signingString(base)), priv(privateKeyB64));
  return { ...base, signature: signature.toString("base64") };
}

export class Registry {
  #participants = new Map<string, Participant>();

  register(p: Participant): void {
    this.#participants.set(p.participantId, p);
  }
  lookup(participantId: string): Participant {
    const p = this.#participants.get(participantId);
    if (!p) throw new ParticipantUnknown(participantId);
    return p;
  }
  suspend(participantId: string): void {
    const p = this.lookup(participantId);
    this.#participants.set(participantId, { ...p, status: "suspended" });
  }
  all(): Participant[] {
    return [...this.#participants.values()];
  }

  /** Verifies signature, freshness, body integrity, and participant standing. */
  verify(env: SignedEnvelope, body: unknown, now = Math.floor(Date.now() / 1000)): Participant {
    const p = this.lookup(env.participantId);
    if (p.status !== "active") throw new ParticipantSuspended(env.participantId);
    if (p.keyId !== env.keyId) throw new SignatureInvalid("unknown key id for participant");
    if (now > env.expires) throw new SignatureInvalid("signature expired");
    if (digestOf(body) !== env.digest) throw new SignatureInvalid("body digest mismatch");
    const ok = edVerify(
      null,
      Buffer.from(signingString(env)),
      pub(p.publicKey),
      Buffer.from(env.signature, "base64"),
    );
    if (!ok) throw new SignatureInvalid("bad ed25519 signature");
    return p;
  }
}
