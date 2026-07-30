/**
 * [A4] COSE-signed, offline-verifiable shipping labels.
 *
 * "The label QR is a COSE-signed compact token, offline-verifiable by a
 * handheld scanner with no network. Address appears nowhere in the printed
 * artifact." — SHIP2MYID_DEMO_SPEC.md §6.1
 *
 * A label is a COSE_Sign1 structure (RFC 8152 §4.2), Ed25519-signed by the
 * operator's current rotating key, wrapping claims derived from an
 * already-verified capability. It is minted inside Zone 1 — the vault is the
 * only thing with access to the signing keys — but verifying it needs
 * nothing from Zone 1 at all: a scanner holding only public key material
 * synced ahead of time can check authenticity, freshness, and origin with no
 * network call. That split is the offline-verifiable property.
 *
 * Never present: a street, a name, a phone number. Where a contact channel
 * is relevant (the gifting flow), only its hash travels — the Aadhaar
 * offline-eKYC pattern of "a hash of the registered mobile number", never
 * the number itself.
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { Tagged, decodeCBOR, encodeCBOR } from "./cbor.ts";
import type { OperatorKeyring, OperatorPublicKey } from "./keyring.ts";
import { verify as verifyCap, type Capability } from "../../capability/src/capability.ts";

export class LabelInvalid extends Error {}
export class LabelExpired extends Error {}
export class LabelKeyUnknown extends Error {}

/** COSE algorithm identifier for EdDSA (IANA COSE Algorithms registry). */
const ALG_EDDSA = -8;
/** COSE header labels (RFC 8152 §3.1). */
const HDR_ALG = 1;
const HDR_KID = 4;
/** COSE_Sign1 CBOR tag (RFC 8152 §4.2). */
const COSE_SIGN1_TAG = 18;

/** Claim keys inside the label payload. Small ints, CWT-style — not IANA-registered, this is our own compact private format. */
const CLAIM_S2ID = 1;
const CLAIM_PURPOSE = 2;
const CLAIM_MAX_WEIGHT_KG = 3;
const CLAIM_CARRIER = 4;
const CLAIM_DESTINATION_KIND = 5;
const CLAIM_EXPIRES_AT = 6; // epoch seconds
const CLAIM_CAPABILITY_ID = 7;
const CLAIM_CONTACT_CHANNEL_HASH = 8; // sha256 digest bytes — never the channel itself

export type LabelClaims = {
  s2id: string;
  purpose: string;
  maxWeightKg: number;
  carrier: string;
  destinationKind: string;
  expiresAt: number; // epoch seconds
  capabilityId: string;
  /** sha256 hex of a contact channel (phone/email). The channel itself is never carried. */
  contactChannelHash?: string;
};

export type SignedLabel = {
  /** Base64url COSE_Sign1 bytes — what actually goes into the printed QR. */
  token: string;
  claims: LabelClaims;
  kid: string;
};

export function hashContactChannel(channel: string): string {
  return createHash("sha256").update(channel).digest("hex");
}

function privKeyObj(base64Pkcs8: string) {
  return createPrivateKey({ key: Buffer.from(base64Pkcs8, "base64"), type: "pkcs8", format: "der" });
}
function pubKeyObj(base64Spki: string) {
  return createPublicKey({ key: Buffer.from(base64Spki, "base64"), type: "spki", format: "der" });
}

function claimsToMap(c: LabelClaims): Map<number, unknown> {
  const m = new Map<number, unknown>();
  m.set(CLAIM_S2ID, c.s2id);
  m.set(CLAIM_PURPOSE, c.purpose);
  m.set(CLAIM_MAX_WEIGHT_KG, c.maxWeightKg);
  m.set(CLAIM_CARRIER, c.carrier);
  m.set(CLAIM_DESTINATION_KIND, c.destinationKind);
  m.set(CLAIM_EXPIRES_AT, c.expiresAt);
  m.set(CLAIM_CAPABILITY_ID, c.capabilityId);
  if (c.contactChannelHash) m.set(CLAIM_CONTACT_CHANNEL_HASH, Buffer.from(c.contactChannelHash, "hex"));
  return m;
}

function mapToClaims(m: Map<unknown, unknown>): LabelClaims {
  const contactHash = m.get(CLAIM_CONTACT_CHANNEL_HASH) as Buffer | undefined;
  return {
    s2id: m.get(CLAIM_S2ID) as string,
    purpose: m.get(CLAIM_PURPOSE) as string,
    maxWeightKg: m.get(CLAIM_MAX_WEIGHT_KG) as number,
    carrier: m.get(CLAIM_CARRIER) as string,
    destinationKind: m.get(CLAIM_DESTINATION_KIND) as string,
    expiresAt: m.get(CLAIM_EXPIRES_AT) as number,
    capabilityId: m.get(CLAIM_CAPABILITY_ID) as string,
    ...(contactHash ? { contactChannelHash: contactHash.toString("hex") } : {}),
  };
}

/** RFC 8152 §4.4 Sig_structure for a COSE_Sign1 ("Signature1"). */
function sigStructure(protectedBytes: Buffer, payloadBytes: Buffer): Buffer {
  return encodeCBOR(["Signature1", protectedBytes, Buffer.alloc(0), payloadBytes]);
}

/**
 * Mints a COSE_Sign1 label from an already-verified capability. Refuses to
 * print a label for a capability that doesn't check out — a forged or
 * expired capability never gets a legitimate-looking label.
 */
export function mintLabel(
  capSecret: Buffer,
  keyring: OperatorKeyring,
  cap: Capability,
  opts: { contactChannel?: string } = {},
): SignedLabel {
  verifyCap(capSecret, cap);

  const key = keyring.current();
  const claims: LabelClaims = {
    s2id: cap.caveats.s2id,
    purpose: cap.caveats.purpose,
    maxWeightKg: cap.caveats.maxWeightKg,
    carrier: cap.caveats.carrier,
    destinationKind: cap.caveats.destinationKind,
    expiresAt: Math.floor(cap.caveats.expiresAt / 1000),
    capabilityId: cap.id,
    ...(opts.contactChannel ? { contactChannelHash: hashContactChannel(opts.contactChannel) } : {}),
  };

  const protectedHeader = encodeCBOR(
    new Map<number, unknown>([
      [HDR_ALG, ALG_EDDSA],
      [HDR_KID, Buffer.from(key.kid, "utf8")],
    ]),
  );
  const payload = encodeCBOR(claimsToMap(claims));
  const signature = edSign(null, sigStructure(protectedHeader, payload), privKeyObj(key.privateKey));

  const message = new Tagged(COSE_SIGN1_TAG, [protectedHeader, new Map(), payload, signature]);
  const token = encodeCBOR(message).toString("base64url");
  return { token, claims, kid: key.kid };
}

/**
 * Offline verification. Takes only public key material a scanner cached
 * ahead of time — no vault reference, no consent lookup, no network call.
 * This proves the label is authentic and fresh; it is deliberately not the
 * same check as `Vault.resolve()`, which is the audited, online, single-use
 * redemption path.
 */
export function verifyLabelOffline(
  publicKeys: OperatorPublicKey[],
  token: string,
  now = Date.now(),
): LabelClaims {
  let decoded: unknown;
  try {
    decoded = decodeCBOR(Buffer.from(token, "base64url"));
  } catch {
    throw new LabelInvalid("not a well-formed COSE label");
  }
  if (!(decoded instanceof Tagged) || decoded.tag !== COSE_SIGN1_TAG) {
    throw new LabelInvalid("not a COSE_Sign1 structure");
  }
  const parts = decoded.value;
  if (!Array.isArray(parts) || parts.length !== 4) {
    throw new LabelInvalid("malformed COSE_Sign1 array");
  }
  const [protectedBytes, , payloadBytes, signature] = parts as [Buffer, Map<unknown, unknown>, Buffer, Buffer];

  const header = decodeCBOR(protectedBytes) as Map<unknown, unknown>;
  if (header.get(HDR_ALG) !== ALG_EDDSA) throw new LabelInvalid("unsupported or missing algorithm");
  const kidBytes = header.get(HDR_KID) as Buffer | undefined;
  if (!kidBytes) throw new LabelInvalid("missing key id");
  const kid = kidBytes.toString("utf8");

  const key = publicKeys.find((k) => k.kid === kid);
  if (!key) throw new LabelKeyUnknown(`no cached public key for kid ${kid}`);
  if (now < key.notBefore || now > key.notAfter) {
    throw new LabelKeyUnknown(`key ${kid} is outside its validity window`);
  }

  const ok = edVerify(null, sigStructure(protectedBytes, payloadBytes), pubKeyObj(key.publicKey), signature);
  if (!ok) throw new LabelInvalid("signature verification failed");

  const claims = mapToClaims(decodeCBOR(payloadBytes) as Map<unknown, unknown>);
  if (now > claims.expiresAt * 1000) throw new LabelExpired(claims.capabilityId);
  return claims;
}
