/**
 * privacy-lint — a CI gate, not a linter suggestion.
 *
 * Two checks:
 *   1. packages/core may not import from adapters/ or services/. This is what
 *      keeps the standards-agnostic claim honest rather than aspirational.
 *   2. No PII-shaped identifier may appear in a Zone 3 (merchant-facing) type
 *      or in any logging call.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("../../", import.meta.url).pathname;

const PII_SHAPED = [
  "address", "line1", "line2", "street", "postcode", "postalcode",
  "fullname", "firstname", "lastname", "phone", "msisdn", "email",
  "nationalid", "dob", "dateofbirth", "latitude", "longitude", "geocode",
];

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (e === "node_modules" || e.startsWith(".")) continue;
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

const failures: string[] = [];

// --- check 1: core purity -------------------------------------------------
for (const f of walk(join(ROOT, "packages/core"))) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(/from\s+["']([^"']+)["']/g)) {
    const spec = m[1]!;
    if (spec.includes("adapters/") || spec.includes("services/")) {
      failures.push(`core purity: ${f} imports ${spec}`);
    }
  }
}

// --- check 2: no PII-shaped fields in Zone 3 projections ------------------
// Every type that is actually handed to a merchant integration, not just the
// original one. A reviewer found this list checked MerchantView alone while
// packages/sdk's CheckoutResult — the type real Phase 3 merchant code
// receives — went unchecked entirely; a PII-shaped field added there passed
// lint clean. Add any new merchant-facing projection type here.
const ZONE3_TYPES: Array<{ file: string; type: string }> = [
  { file: "packages/core/src/core.ts", type: "MerchantView" },
  { file: "packages/sdk/src/client.ts", type: "CheckoutResult" },
  { file: "packages/webhooks/src/webhook.ts", type: "CheckoutCompletedPayload" },
];
for (const { file, type } of ZONE3_TYPES) {
  const src = readFileSync(join(ROOT, file), "utf8");
  const body = src.match(new RegExp(`export type ${type} = \\{([\\s\\S]*?)\\};`))?.[1] ?? "";
  if (!body) {
    failures.push(`zone3 check misconfigured: ${type} not found in ${file}`);
    continue;
  }
  for (const field of body.matchAll(/^\s*(\w+)\??:/gm)) {
    const name = field[1]!.toLowerCase();
    if (PII_SHAPED.some((p) => name.includes(p))) {
      failures.push(`zone3 leakage: ${type}.${field[1]} (${file}) is PII-shaped`);
    }
  }
}

// --- check 3: no raw identifiers in log statements ------------------------
// After UIDAI: operational logs must contain reference keys only, never the
// underlying identifier. This is the rule most systems break by accident.
for (const f of walk(join(ROOT, "packages")).concat(walk(join(ROOT, "services")))) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(/console\.(log|info|warn|error)\(([^)]*)\)/g)) {
    const args = m[2]!.toLowerCase();
    const hit = PII_SHAPED.find((p) => args.includes(p));
    if (hit) failures.push(`log leakage: ${f} logs '${hit}'`);
  }
}

if (failures.length) {
  console.error("privacy-lint FAILED");
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log("privacy-lint PASSED — core is pure, zone 3 is clean, logs carry no identifiers");
