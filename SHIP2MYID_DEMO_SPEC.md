# Ship2MyID — Reference Demo Specification

> **Purpose of this document.** Define a *buildable, demonstrable* implementation of the
> Ship2MyID pitch: a parcel finds a person without the sender ever learning where that
> person lives. Not a pilot, not production, not country-specific. A working model that
> survives an engineer asking "but how does that actually work?"
>
> **Deployment neutrality is deliberate.** No national ID scheme, no named postal
> operator, no jurisdiction is baked into the core. The demo ships with a *fictional*
> country adapter (`Republic of Meridia`) precisely so that the seams where a real
> country plugs in are visible on screen.
>
> **Status:** Draft v1 — reference spec for build.

---

## 1. The claim, reduced to something testable

The pitch makes four promises. A credible demo must make each one *falsifiable on stage*:

| The promise | The demo must show | Fails if |
|---|---|---|
| Ship without an address | A merchant completes an order holding only a token | Any merchant-side record contains a street address |
| Privacy is structural, not policy | The merchant DB is opened live and inspected | Privacy depends on "we promise not to look" |
| Returns still work | A full return round-trip, address never released | The exception path leaks what the happy path protected |
| Brands can still reach buyers | A targeted offer converts to a sale | Targeting requires identifying the buyer |

Everything below exists to serve that table. If a component doesn't help prove a row,
it's scope creep.

**One-line thesis:** *An address is not a string to be shared. It is a capability to be
delegated, narrowly and revocably.*

---

## 2. The central design idea

Most "privacy addressing" designs are a lookup table with access control bolted on. That
is a honeypot with extra steps — and it's the single strongest criticism of the concept.
This design answers it directly.

**Addresses are never *returned*. They are *acted upon*.**

The merchant never receives an address, encrypted or otherwise. The merchant receives a
**capability token** — a signed, scoped, single-use, expiring grant that says:

> *"Bearer may cause one parcel of ≤5kg to be delivered to whoever S2ID `xxxx` resolves
> to, before 2026-08-12T00:00Z, via carrier `MER-POST`. Bearer may not read the target."*

Only the **Resolution Service** — one small, isolated, heavily audited component sitting
inside the operator's trust boundary — can turn that token into a physical routing
instruction. It emits a *sortation code*, not an address, and the plaintext address exists
only in memory, only inside that service, only for the milliseconds required to produce a
carrier manifest.

This single inversion is what makes the demo defensible. Everything else is plumbing.

### The three boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│  ZONE 3 — OPEN            Merchants, brands, public API          │
│  Sees: S2ID tokens, capability grants, demographic cohorts       │
│  Holds: no PII. Ever. Enforced by schema, not by policy.         │
└───────────────────────────┬──────────────────────────────────────┘
                            │  capability tokens only
┌───────────────────────────▼──────────────────────────────────────┐
│  ZONE 2 — PLATFORM        Orchestration, consent, events, audit  │
│  Sees: pseudonymous identifiers, consent records, ciphertext     │
│  Holds: encrypted blobs it cannot decrypt. No key access.        │
└───────────────────────────┬──────────────────────────────────────┘
                            │  redemption requests only
┌───────────────────────────▼──────────────────────────────────────┐
│  ZONE 1 — VAULT           Resolution Service + KMS + address DB  │
│  Sees: plaintext addresses, transiently, on redemption           │
│  Holds: the only decryption path in the system                   │
└──────────────────────────────────────────────────────────────────┘
```

Zone 2 is deliberately *unable* to betray the consumer — it holds ciphertext and no keys.
That's the property that makes the "postal operator becomes a honeypot" critique
answerable: the honeypot is one service with one job and one audited exit.

---

## 3. Core objects

### 3.1 The S2ID

A pseudonymous, per-relationship identifier. **Critically: it is not one ID per person.**

A single global identifier per human is the design mistake that turns a privacy product
into a surveillance product — it lets any two merchants join their datasets on it. Instead:

- **Root identity** — internal, never leaves Zone 1.
- **Pairwise S2ID** — derived per (consumer × merchant) relationship:
  `S2ID = base32(HMAC-SHA256(consumer_root_secret, merchant_id))[0:16]`
  formatted as `MER-7QK4-9XT2-BN5F`.

Merchant A and Merchant B holding tokens for the same person **cannot tell**. That's a
one-line design decision that kills the correlation attack outright, and it's a genuinely
strong thing to demo: show two merchant databases side by side, same buyer, no join key.

A **public handle** (`@ashwin` or a phone/email alias) exists for the gifting use case and
maps to a *fresh, single-use* S2ID per gift — so a gift sender learns nothing reusable.

### 3.2 The address record

```
AddressRecord {
  id               uuid
  root_identity    uuid          // Zone 1 only
  ciphertext       bytea         // AEAD, field-level key
  key_id           text          // KMS key reference
  geo_bucket       text          // "MER-CENTRAL-07" — coarse routing hint, k≥50
  vouch_tier       int           // 1..3, see §5
  vouched_at       timestamptz
  status           enum          // active | superseded | revoked
}
```

`geo_bucket` is the one thing Zone 2 may see. It is coarse enough to be useless for
finding someone (guaranteed ≥50 residents per bucket) and precise enough for capacity
planning and rate estimation. This is what makes the platform tier useful without making
it dangerous.

### 3.3 The capability token

A **Biscuit** token (or macaroon-equivalent) — chosen over plain JWT because it supports
*offline attenuation*: a merchant can hand a courier a strictly weaker version of its own
token without a round-trip to us, and can never widen it.

```
authority:
  s2id("MER-7QK4-9XT2-BN5F");
  purpose("delivery");
  max_weight_kg(5);
  carrier("MER-POST");
  expires(2026-08-12T00:00:00Z);
  single_use(true);
  consent_ref("cns_01J9X...");
check if resolution_service($svc), $svc == "vault-primary";
```

Properties that matter on stage: **scoped** (delivery only, not marketing), **expiring**,
**single-use** (enforced by a Redis nonce burn), **revocable** (consumer taps once and the
token is dead mid-flight), **attenuable**, and **non-readable** (contains no address, no
name, no phone).

### 3.4 The consent record

Every capability is minted against a consent record, and consent is **per-event, never
standing**. The consent ledger is append-only and hash-chained:

```
entry_n.hash = SHA256(entry_{n-1}.hash || canonical_json(entry_n))
```

Tamper-evidence without a blockchain. The demo shows the chain verifying, then shows it
*failing* after a deliberate row edit — a 20-second segment that does more for credibility
than any architecture diagram.

---

## 4. Verifiable credentials, not hand-rolled crypto

The pitch says "prove without revealing." The honest engineering answer in 2026 is **not**
to build custom zero-knowledge circuits for a demo. It is to use the standards that
already solved selective disclosure:

| Need | Standard | Why this one |
|---|---|---|
| Credential format | **W3C Verifiable Credentials 2.0** | The interop target every national ID programme is converging on |
| Selective disclosure | **SD-JWT VC** (IETF) | Reveal `is_over_18` without revealing DOB. Mature, auditable libraries today |
| Unlinkable proofs | **BBS+ signatures** | Roadmap item — same credential, multiple presentations, no correlation |
| Wallet transport | **OpenID4VP / OpenID4VCI** | How real wallets will hand credentials to real merchants |
| Consumer auth | **WebAuthn / passkeys** | No passwords, phishing-resistant, device-bound. Non-negotiable |

**The honest framing for the room:** SD-JWT gives *selective disclosure* today; BBS+ gives
*unlinkability* next. Claiming full ZK in v1 would be the same overreach the original pitch
makes. Under-promise here and the rest of the deck gains credibility.

### Encryption profile

| Layer | Choice | Note |
|---|---|---|
| At rest (fields) | **XChaCha20-Poly1305** AEAD, per-record derived key | AAD binds ciphertext to `record_id` — a swapped row fails to decrypt |
| Key management | **Envelope: KMS root → tenant DEK → record key (HKDF)** | Tenant = operator. One tenant's compromise cannot read another's |
| In transit | **TLS 1.3**, mTLS on the Zone 2→Zone 1 hop | The vault accepts calls from exactly one client identity |
| Library | **Tink** (or libsodium) | Never bespoke crypto. Not once |
| Rotation | DEK every 90d, envelope re-wrap, zero downtime | Record keys derived, so rotation touches wrapping only |
| Deletion | **Crypto-shredding** — destroy the record key | Right-to-erasure that is provable against backups and replicas |

**Crypto-shredding deserves emphasis**: event-sourced systems are notoriously bad at
deletion because events are immutable. Encrypting PII per-record and deleting the *key*
makes erasure real and instant, even in an append-only log. Demonstrating a deletion that
provably works across an immutable event store is a strong differentiator.

### The audit invariant

> **Every decryption writes its audit record *before* the plaintext exists.**

Not after. The audit write is a precondition of the decrypt call, in the same transaction.
A decryption not attributable to an actor, a purpose, and a consent reference is not a
policy violation — it is a crash.

---

## 5. Identity proofing — tiered, and honest about what each tier proves

Deployment-neutral by design; a real country swaps the Tier-1 adapter and nothing else moves.

| Tier | Method | What it *actually* proves | Gates |
|---|---|---|---|
| **0** | Email/phone + passkey | Control of a contact channel | Browsing, wishlists, receiving gifts |
| **1** | National ID / eID credential via OpenID4VCI | A real, distinct person exists | Issuing an S2ID |
| **2** | Operator vouching (address register match, or code-by-post) | Person is *associated* with the address | Activating shipping |
| **3** | Delivery challenge — physical scan at the door | Person *controls* the address | High value, new address |

Tier is an attribute of the **binding**, not the person. Same human, three addresses,
three different tiers. Merchants request a minimum tier; the platform answers yes/no and
never explains why.

**Demo adapter:** `MeridiaIDAdapter` — a mock national eID issuing real SD-JWT VCs from a
demo issuer key. It looks and behaves exactly like a real integration; only the issuer is
fictional. Swapping in a real scheme is a new class implementing `IdentityProofingPort`.

---

## 6. The four flows

### 6.1 Ship (the foundational flow)

```
Merchant                Platform (Zone 2)         Vault (Zone 1)      Carrier
   │  POST /shipments        │                         │                 │
   │  {s2id, weight, svc}    │                         │                 │
   ├────────────────────────►│                         │                 │
   │                         │ ── consent check ─────► │                 │
   │                         │ ◄── granted ─────────── │                 │
   │  ◄── capability token   │                         │                 │
   │      + label QR         │                         │                 │
   │                                                   │                 │
   │  [prints QR. holds no address. cannot.]           │                 │
   │                                                   │                 │
   │  parcel + QR ─────────────────────────────────────────────────────► │
   │                                                   │ ◄── redeem ──── │
   │                                                   │ ── sortation ─► │
   │                                                   │    code only    │
```

The label QR is a **COSE-signed** compact token, offline-verifiable by a handheld scanner
with no network. Address appears nowhere in the printed artifact — a scanned label from
the stage, decoded live, showing only an opaque grant, is the single most persuasive
20 seconds in the demo.

### 6.2 Return — the flow that proves the design

Returns are where naive designs leak, because the merchant "needs" the origin address.
They don't.

- **Consumer-initiated return:** consumer taps → platform mints a *single-use, 72-hour,
  return-direction* capability → consumer drops at any access point → carrier resolves →
  parcel arrives at merchant. The merchant learns nothing except that a parcel arrived.
- **Failed delivery:** carrier notifies platform → platform notifies *consumer* (never the
  merchant) → consumer chooses re-attempt / redirect to locker / cancel. A redirect issues
  a fresh capability to a different address; the merchant is never told the destination
  changed.
- **Refund without return:** zero address exposure. Preferred wherever unit economics allow.

**Design rule:** the exception path may never grant a capability *wider* than the one that
created the shipment. Enforced in code, tested explicitly, and worth demoing as a
deliberate failed attempt.

### 6.3 Commerce — D2C without an address field

A **drop-in checkout component** (`<S2IDCheckout />`) that replaces the address form.
Consumer taps a passkey, picks a saved binding label ("Home", "Office"), done. The merchant
receives `{ s2id, capability, geo_bucket, service_level, estimated_delivery }` and no PII.

Merchant-side value that justifies the integration:
- **Address quality is 100% by construction** — the operator vouched it. Failed-delivery
  rate collapses, which is a real line-item saving, not a privacy talking point.
- **Verified-human signal** — Tier ≥1 is strong anti-fraud, worth more than address data.
- **Instant checkout** — no typing. Conversion lift on mobile is the actual sales pitch.

### 6.4 D2C marketing — inverted, so it doesn't undo the privacy

The original pitch's weakest link: it promises privacy while proposing that postal
operators become "the country's single source of consumer data." Those are in tension. The
demo resolves it by inverting who initiates.

**Consumer-declared intent, not inferred profiles.**

1. Consumer posts a signed **intent**: *"Looking for a 55″ OLED TV, budget band 3, within
   30 days."* Optionally with a cohort attestation (`region_bucket`, `age_band`) via SD-JWT.
2. Intent enters a **matching pool** as a cohort member — never as an individual.
3. Brands bid **into the cohort**, not at a person. A brand sees: *"412 declared intents
   matching TV/premium/MER-CENTRAL this week."* Never a name, never an S2ID, never a count
   small enough to identify (**k-anonymity floor: no cohort below 25 is ever exposed**).
4. The offer is delivered to the consumer's inbox by the platform. The brand learns nothing
   until the consumer *acts*.
5. On conversion, the brand learns: a sale happened, a fresh pairwise S2ID, a capability.

**Why this is the stronger pitch:** intent-declared audiences convert at multiples of
interruption advertising, because the buyer raised their hand. The privacy property isn't a
compliance tax — it's the reason the inventory is valuable. A brand is buying *"people who
told us they want this,"* which is a better product than *"people whose browsing suggests
they might."*

**Non-goal, stated loudly:** no profile building, no behavioural inference, no data
brokerage. Intents expire. The consumer can see and delete every one.

---

## 7. Stack

Chosen for *demo velocity plus architectural honesty* — nothing here needs replacing when
this becomes real, only hardening.

| Layer | Choice | Why |
|---|---|---|
| Monorepo | **Turborepo + pnpm** | Enforces the zone boundaries as package boundaries |
| Language | **TypeScript**, strict, `noUncheckedIndexedAccess` | One language across web, API, and edge |
| Web | **Next.js 15 (App Router) + React 19** | Server components keep PII off the client by default |
| UI | **Tailwind + shadcn/ui + Framer Motion** | Fast to a demo that doesn't look like a demo |
| API | **Hono** on Node, **tRPC** internally, **OpenAPI** externally | Hono runs identically on edge and in-country metal |
| Validation | **Zod**, shared client↔server | One schema, no drift |
| DB | **PostgreSQL 16** + **Drizzle ORM** | Row-Level Security is the enforcement layer, not app code |
| Cache / nonce | **Redis** | Single-use token burn, rate limits |
| Events | **Postgres outbox → NATS JetStream** | Transactional outbox: no lost or phantom events |
| Vault service | **Rust (axum)**, separate binary, separate deploy | Small, auditable, memory-safe. The one component worth writing twice |
| Crypto | **Tink** (TS) / **RustCrypto** (vault) | Never bespoke |
| KMS | **age**-based local KMS for demo; HSM/cloud-KMS interface behind a port | Demo runs offline; production swaps one adapter |
| Credentials | **@sd-jwt/core**, **did:web** issuers | Real standards, real libraries |
| Auth | **WebAuthn / passkeys** (SimpleWebAuthn) | No passwords anywhere in the system |
| Wallet | **PWA**, offline-capable, QR scan/present | Feels native without app-store friction |
| Observability | **OpenTelemetry → Grafana**, PII-scrubbing processor at source | Scrub before egress, never at the vendor |
| Infra | **Docker Compose** (demo) → **Terraform** modules (real) | The whole demo runs on a laptop with no cloud account |
| Tests | **Vitest**, **Playwright**, plus **privacy invariant suite** (§9) | The last one is the interesting one |

**Deliberate choice: the demo runs entirely offline on one machine.** No cloud dependency,
no API key, no network. Conference wifi has killed more demos than bad architecture, and
"it runs on this laptop" is itself a statement about data residency.

---

## 8. Repository shape

```
ship2myid/
├── apps/
│   ├── wallet/            # Consumer PWA — passkeys, consents, intents, returns
│   ├── merchant/          # Demo storefront + <S2IDCheckout /> integration
│   ├── operator/          # Postal operator console — sortation, vouching, audit
│   ├── brand/             # Brand console — cohort bidding, campaign results
│   └── inspector/         # ★ The truth panel — see §10
├── services/
│   ├── platform/          # Zone 2 — orchestration, consent, capability minting
│   └── vault/             # Zone 1 — Rust. Resolution + KMS. The only decrypt path
├── packages/
│   ├── core/              # ★ Zero adapter imports. Enforced by lint rule
│   ├── capability/        # Biscuit minting, attenuation, verification
│   ├── credentials/       # SD-JWT VC issue / present / verify
│   ├── crypto/            # Envelope encryption, HKDF, crypto-shredding
│   ├── events/            # Outbox, event schemas, projections
│   └── contracts/         # OpenAPI + Zod, published as the merchant SDK
├── adapters/
│   ├── identity-meridia/  # Mock national eID — the swappable one
│   ├── postal-meridia/    # Mock operator — address register, sortation, tracking
│   └── payments-stub/     # Demo only. Moves no money
└── tools/
    ├── seed/              # Synthetic population generator (§11)
    └── privacy-lint/      # CI check: does any Zone 3 schema contain a PII column?
```

**The rule that keeps this honest:** `packages/core` may not import from `adapters/`. A
custom ESLint rule fails the build if it does. When `core` still compiles and tests green
with every adapter deleted, the standards-agnostic claim is true. When it doesn't, it isn't.

---

## 9. Privacy invariants — as executable tests

This is the section that separates this from a slide deck. These run in CI on every commit
and are demoed live.

```ts
// tests/invariants/no-pii-escape.spec.ts

test('INV-1: no Zone 3 table may contain an address column', async () => {
  const cols = await introspect(zone3Schema);
  expect(cols.filter(isPiiShaped)).toHaveLength(0);   // static, structural
});

test('INV-2: capability tokens carry no PII under any encoding', async () => {
  const cap = await mintCapability(fixture.order);
  expect(entropyScan(cap)).not.toContainPlaintext(fixture.address);
});

test('INV-3: a spent capability cannot be replayed', async () => {
  await vault.redeem(cap);
  await expect(vault.redeem(cap)).rejects.toThrow(CapabilityBurned);
});

test('INV-4: no decrypt occurs without a prior audit row in the same tx', async () => {
  await expect(vault.resolveUnaudited(cap)).rejects.toThrow(AuditPrecondition);
});

test('INV-5: two merchants cannot correlate the same consumer', async () => {
  const a = await issueS2ID(consumer, merchantA);
  const b = await issueS2ID(consumer, merchantB);
  expect(linkabilityScore(a, b)).toBe(0);
});

test('INV-6: crypto-shred renders all historical events unreadable', async () => {
  await erasure.execute(consumer);
  const events = await eventStore.replayAll(consumer);
  expect(events.every(isUnreadable)).toBe(true);
});

test('INV-7: no cohort below k=25 is ever exposed to a brand', async () => {
  const view = await marketing.cohortView(brand, narrowestQuery);
  expect(view.size === 0 || view.size >= 25).toBe(true);
});

test('INV-8: core compiles and passes with all adapters removed', async () => {
  await expect(buildCore({ adapters: [] })).resolves.toPass();
});
```

**Say this out loud in the demo:** *"Our privacy claims are eight tests. If they go red, we
don't ship. You can read them; they're in the repo."* Verifiable beats trustworthy.

---

## 10. The Inspector — the app that wins the room

A fifth application whose only job is to **try to break the privacy claim in front of the
audience**. Most demos hide the database. This one projects it.

Four live panes:

1. **Merchant's view of the world** — the raw merchant DB, queryable by the audience.
   Someone in the room types `SELECT * FROM customers` and sees tokens, cohorts, and no
   addresses.
2. **Data-flow trace** — every field crossing every zone boundary in the last transaction,
   colour-coded. Nothing red ever crosses upward.
3. **Consent ledger + hash chain** — verifying green; then tamper a row and watch it go red.
4. **Attack console** — pre-built attacks the audience can fire: replay a spent capability,
   correlate two merchants, request a cohort of 3, decrypt without audit, exfiltrate from
   Zone 2 without keys. Each one fails, visibly, with the invariant that stopped it named
   on screen.

The inspector is the product argument. Anyone can *claim* the merchant has no address; only
this shows it, adversarially, with a stranger at the keyboard.

---

## 11. Demo data

100% synthetic, generated, and *stated as such on every screen*. Never real people, never
a real national ID format, not even in a screenshot.

- **~5,000 synthetic residents** of Meridia: plausible name/address distributions,
  realistic household clustering (multiple residents per address — the case that breaks
  naive designs), and a fictional ID format (`MRD-########`) that cannot collide with any
  real scheme.
- **~40 merchants**, 3 brands, 1 postal operator, 12 access points, 4 lockers.
- **Scripted personas:** the frequent buyer, the mover (address changes mid-flight — a
  great demo beat), the gift recipient with no account, the returner, the deleter.
- **Chaos toggles:** failed delivery, carrier outage, revoked consent mid-transit, expired
  capability. A demo that only shows the happy path invites the question you don't want.

---

## 12. Roadmap

**Phase 0 — Skeleton.** Monorepo, zones as packages, envelope crypto, passkey auth, the
privacy-lint rule. *Done when:* an address can be stored and only the vault can read it.

**Phase 1 — Ship it.** S2ID issuance, pairwise derivation, tier 1–2 proofing, capability
minting, COSE label, sortation. *Done when:* a parcel is routed end to end and the merchant
DB provably has no address. **This is the minimum viable demo — everything after is upside.**

**Phase 2 — Exceptions.** Returns, failed delivery, redirect, revocation-in-flight,
refund-without-return. *Done when:* every exception path passes INV-1 and the attenuation
rule.

**Phase 3 — Commerce.** `<S2IDCheckout />`, merchant SDK, verified-human signal, tier-gating,
metered API. *Done when:* a third party integrates from the published SDK without talking
to us.

**Phase 4 — Marketing.** Intent declaration, cohort pool, k-anonymity floor, brand console,
attribution without identity. *Done when:* a brand runs a campaign, converts a sale, and
cannot name a single person it reached.

**Phase 5 — Inspector.** The truth panel and the attack console. *Done when:* an audience
member fails to break it.

**Phase 6 — Interoperability.** Second fictional country (`Kestrel`) with a *deliberately
different* address model — no street names, place-name addressing, à la rural Nordic
practice. *Done when:* adding Kestrel is an adapter, a config entry, and a test suite, with
zero diff in `packages/core`. **This is the phase that proves the platform claim**, and the
second country being structurally awkward is the whole point.

**Phase 7 — Cross-border.** Two operators cooperating without pooling citizen data:
capability handoff at the border, each operator resolving only within its own boundary.
*Done when:* a parcel crosses and neither operator holds the other's address data.

**Beyond:** BBS+ unlinkable presentations, threshold-split vault keys (no single admin can
decrypt alone), offline-first rural resolution, UPU S-series mapping when those standards
settle.

---

## 13. Deliberate non-goals

- **Not a general identity provider.** The S2ID routes parcels and proves narrow attributes.
  It is not "login with Ship2MyID" and it does not compete with national eID — it *consumes* it.
- **Not a carrier.** We route; operators deliver.
- **Not a data broker.** Cohorts serve the consumer's declared intent. They are not an asset.
- **Not standard-setting.** We adapt to schemes as they settle; we don't wait for them or
  try to lead them.
- **Not moving money.** Payments are stubbed. Real payment rails are a licensing question,
  not a demo question.
- **Not country-specific.** Anything jurisdictional that reaches `core` is a defect, not a
  feature.
- **Not claiming full ZK in v1.** Selective disclosure now, unlinkability next, stated plainly.

---

## 14. What "standout" actually means here

Three things make this different from a competent CRUD demo:

1. **The capability inversion.** Addresses are delegated, not shared. It changes the
   security model from "who may read" to "who may act," which is the only version of this
   idea that withstands a hostile architect.
2. **Pairwise identifiers.** The correlation attack — the thing that quietly makes every
   universal-ID scheme a surveillance system — is designed out at the identifier layer, not
   patched at the policy layer.
3. **The Inspector.** The claim is *tested in public, adversarially*. Every competing pitch
   in this space says "trust us, it's private." This one says "here's the database, here's
   the attack console, go ahead."

The pitch this demo makes is not *"we invented a digital address."* It is:

> **An address should be a revocable capability, not a shared secret — and here is a
> working system where the merchant, the platform, and even the operator's own engineers
> cannot see what they don't need.**

---

## 15. Open questions to resolve during build

- **Vault key custody.** Threshold split (Shamir, m-of-n across operator + platform) is more
  defensible than single-custodian, but complicates the demo. Decide before Phase 1.
- **Multi-resident addresses.** Several people, one address, different S2IDs. Resolution is
  fine; *vouching* is subtle. The seed data includes these cases specifically to force it.
- **Address change in flight.** Consumer moves after dispatch. Re-resolution vs. re-issue?
  A great demo beat if handled, an obvious hole if not.
- **Offline scanner trust.** COSE labels verify offline against a rotating operator key.
  Key distribution to handhelds needs a story.
- **Capability leakage.** A capability is bearer-ish. Binding it to a carrier identity
  (mTLS) closes this; confirm it's enforced, not just intended.
- **Intent expiry economics.** How long an intent stays live shapes both cohort sizes and
  the k-anonymity floor. Model it before the brand console is built.

---

## 16. Document map

| Document | Role |
|---|---|
| `SHIP2MYID_DEMO_SPEC.md` (this file) | The authority. Scope, architecture, invariants, roadmap |
| `ADR/` | Decision records. Anything contradicting this file amends it in the same change |
| `packages/contracts/openapi.yaml` | The external contract — generated, never hand-edited |
| `tests/invariants/` | The privacy claims, executable |
