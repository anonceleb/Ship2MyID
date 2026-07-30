/**
 * Pairwise identifiers — the anti-correlation primitive.
 *
 * Modelled directly on UIDAI's UID Token: an identifier that is *stable for a
 * given (person, relying party) pair* but carries no join key across relying
 * parties. Two merchants holding tokens for the same human cannot discover that
 * fact by comparing databases.
 *
 * Stability matters as much as unlinkability: a merchant must be able to
 * recognise a returning customer, or the privacy design costs them the loyalty
 * data they would otherwise refuse to give up.
 */
import { createHmac, randomBytes } from "node:crypto";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32: no I/L/O/U

export type RootSecret = Buffer;

export function newRootSecret(): RootSecret {
  return randomBytes(32);
}

function base32(buf: Buffer, chars: number): string {
  let out = "";
  for (let i = 0; i < chars; i++) out += ALPHABET[buf[i]! % ALPHABET.length];
  return out;
}

/**
 * S2ID = base32(HMAC-SHA256(root_secret, relying_party_id))
 * Deterministic, so no storage is required; irreversible, so possession of an
 * S2ID reveals nothing about the root identity.
 */
export function deriveS2ID(root: RootSecret, relyingPartyId: string, prefix = "MER"): string {
  const mac = createHmac("sha256", root).update(`s2id/pairwise/${relyingPartyId}`).digest();
  const body = base32(mac, 12);
  return `${prefix}-${body.slice(0, 4)}-${body.slice(4, 8)}-${body.slice(8, 12)}`;
}

/**
 * Single-use identifiers for gifting: the sender must be able to address a
 * parcel to someone who has no relationship with the merchant, and must learn
 * nothing reusable in the process.
 */
export function deriveEphemeralS2ID(root: RootSecret, nonce: string, prefix = "GFT"): string {
  return deriveS2ID(root, `ephemeral/${nonce}`, prefix);
}

/**
 * Linkability oracle used by the invariant suite. Returns 0 when two identifiers
 * for the same person share no exploitable structure. Deliberately crude — it
 * exists to fail loudly if someone "optimises" derivation into a shared prefix.
 */
export function linkabilityScore(a: string, b: string): number {
  if (a === b) return 1;
  const sa = a.replace(/-/g, "").slice(3);
  const sb = b.replace(/-/g, "").slice(3);
  let shared = 0;
  for (let i = 0; i < Math.min(sa.length, sb.length); i++) {
    if (sa[i] === sb[i]) shared++;
    else break;
  }
  return shared >= 4 ? shared / sa.length : 0;
}
