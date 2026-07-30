/**
 * ADAPTER — Republic of Meridia postal operator (fictional).
 *
 * Deliberately fictional so the seams where a real operator plugs in are visible
 * rather than assumed. Deleting this directory must leave packages/core building
 * and green (INV-8).
 */
import type {
  AddressPlaintext,
  SortationPort,
  IdentityProofingPort,
} from "../../../packages/core/src/core.ts";
import { createHash } from "node:crypto";

export class MeridiaSortation implements SortationPort {
  async route(address: AddressPlaintext, service: string) {
    // Consumes plaintext transiently; emits a routing code, never an address.
    const key = `${address.postcode}|${address.locality}|${service}`;
    const code = createHash("sha256").update(key).digest("hex").slice(0, 10).toUpperCase();
    return { sortationCode: `MRD-${code}` };
  }
}

export class MeridiaIdentity implements IdentityProofingPort {
  async proof(_subjectRef: string, evidence: unknown): Promise<1 | 2 | 3> {
    const e = evidence as { nationalId?: string; vouched?: boolean; delivered?: boolean };
    if (e?.delivered) return 3;
    if (e?.vouched) return 2;
    if (e?.nationalId?.startsWith("MRD-")) return 1;
    throw new Error("insufficient evidence");
  }
}

/** Coarse geography: guaranteed k>=50 residents per bucket. */
export function geoBucketFor(postcode: string): string {
  return `MRD-${postcode.slice(0, 2)}`;
}
