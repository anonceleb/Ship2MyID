/**
 * Minimal, deterministic CBOR (RFC 8949) codec — just enough of the spec to
 * build genuine COSE_Sign1 structures (RFC 8152) without a dependency. No
 * install, no network, matches the rest of this repo's "runs on a laptop"
 * constraint.
 *
 * Supports: unsigned/negative integers, byte strings, text strings, arrays,
 * integer-keyed maps, and tags. Nothing else is needed for a COSE label —
 * floats, indefinite-length items, and simple values are deliberately absent.
 */

export class Tagged {
  readonly tag: number;
  readonly value: unknown;
  constructor(tag: number, value: unknown) {
    this.tag = tag;
    this.value = value;
  }
}

const MT_UINT = 0;
const MT_NINT = 1;
const MT_BSTR = 2;
const MT_TSTR = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;

function encodeHead(major: number, len: number): Buffer {
  const mb = major << 5;
  if (len < 24) return Buffer.from([mb | len]);
  if (len <= 0xff) return Buffer.from([mb | 24, len]);
  if (len <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = mb | 25;
    b.writeUInt16BE(len, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = mb | 26;
  b.writeUInt32BE(len, 1);
  return b;
}

export function encodeCBOR(value: unknown): Buffer {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const b = Buffer.from(value);
    return Buffer.concat([encodeHead(MT_BSTR, b.length), b]);
  }
  if (typeof value === "string") {
    const b = Buffer.from(value, "utf8");
    return Buffer.concat([encodeHead(MT_TSTR, b.length), b]);
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("cbor: only integers are supported");
    return value >= 0 ? encodeHead(MT_UINT, value) : encodeHead(MT_NINT, -1 - value);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([encodeHead(MT_ARRAY, value.length), ...value.map(encodeCBOR)]);
  }
  if (value instanceof Map) {
    const parts: Buffer[] = [encodeHead(MT_MAP, value.size)];
    for (const [k, v] of value) {
      parts.push(encodeCBOR(k));
      parts.push(encodeCBOR(v));
    }
    return Buffer.concat(parts);
  }
  if (value instanceof Tagged) {
    return Buffer.concat([encodeHead(MT_TAG, value.tag), encodeCBOR(value.value)]);
  }
  throw new Error(`cbor: unsupported value of type ${typeof value}`);
}

function readArg(buf: Buffer, offset: number, ai: number): [number, number] {
  if (ai < 24) return [ai, offset];
  if (ai === 24) return [buf.readUInt8(offset), offset + 1];
  if (ai === 25) return [buf.readUInt16BE(offset), offset + 2];
  if (ai === 26) return [buf.readUInt32BE(offset), offset + 4];
  throw new Error("cbor: unsupported length encoding");
}

function decodeAt(buf: Buffer, offset: number): [unknown, number] {
  if (offset >= buf.length) throw new Error("cbor: unexpected end of input");
  const ib = buf[offset]!;
  const major = ib >> 5;
  const ai = ib & 0x1f;
  const [arg, o] = readArg(buf, offset + 1, ai);
  switch (major) {
    case MT_UINT:
      return [arg, o];
    case MT_NINT:
      return [-1 - arg, o];
    case MT_BSTR:
      return [Buffer.from(buf.subarray(o, o + arg)), o + arg];
    case MT_TSTR:
      return [buf.subarray(o, o + arg).toString("utf8"), o + arg];
    case MT_ARRAY: {
      const out: unknown[] = [];
      let cur = o;
      for (let i = 0; i < arg; i++) {
        const [v, next] = decodeAt(buf, cur);
        out.push(v);
        cur = next;
      }
      return [out, cur];
    }
    case MT_MAP: {
      const out = new Map<unknown, unknown>();
      let cur = o;
      for (let i = 0; i < arg; i++) {
        const [k, ko] = decodeAt(buf, cur);
        const [v, vo] = decodeAt(buf, ko);
        out.set(k, v);
        cur = vo;
      }
      return [out, cur];
    }
    case MT_TAG: {
      const [v, vo] = decodeAt(buf, o);
      return [new Tagged(arg, v), vo];
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

export function decodeCBOR(buf: Buffer): unknown {
  const [value, offset] = decodeAt(buf, 0);
  if (offset !== buf.length) throw new Error("cbor: trailing bytes after top-level item");
  return value;
}
