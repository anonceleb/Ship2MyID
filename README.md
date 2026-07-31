# Ship2MyID — Phase 0

[![CI](https://github.com/anonceleb/Ship2MyID/actions/workflows/ci.yml/badge.svg)](https://github.com/anonceleb/Ship2MyID/actions/workflows/ci.yml)

Zone skeleton, envelope crypto, pairwise identifiers, participant registry, capability
tokens, and the executable privacy invariants.

**Runs entirely offline. No install, no database, no cloud account, no network.**
Node ≥ 22.6 only — TypeScript executes via native type stripping.

```bash
npm run verify   # privacy-lint + all invariants (INV-1..26, A4, non-widening)
npm run demo     # narrated end-to-end ship flow
```

## Phase 0 exit criterion

> *An address can be stored, and only the vault can read it.*

Met. Plus four things pulled forward from later phases after the prior-art review:
Ed25519 message signing, the participant registry, the household barrier, and
(now, Phase 1) COSE-signed offline-verifiable labels.

## What's here

```
packages/
  crypto/      envelope encryption (ChaCha20-Poly1305), HKDF record keys, crypto-shredding
  identity/    pairwise S2ID derivation — stable per merchant, unlinkable across merchants
  registry/    Ed25519 request signing + participant registry (ONDC/Beckn shape)
  capability/  scoped, expiring, single-use, attenuable grants
  labels/      [A4] COSE_Sign1 offline-verifiable shipping labels + rotating operator keys
  policy/      [A9] signed, versioned, hot-reloadable disclosure policy
  network/     [A10] Beckn-shaped async request/callback pairs (action/on_action)
  metering/    [Phase 3] per-participant metered API quota
  sdk/         [Phase 3] the published merchant-facing surface — MerchantClient, CheckoutResult
  core/        domain, consent ledger, ports — imports NOTHING from adapters or services
services/
  vault/       ZONE 1 — the only decryption path. Audit is a precondition of plaintext
  platform/    ZONE 2 — orchestration. Holds ciphertext, holds no keys
adapters/
  postal-meridia/  fictional operator. Delete it; core still builds (INV-8)
  dakhil-post/     second fictional operator — different address format (locality/
                   placeName, not postcode) and different key custody (holds no
                   signing key; proofing proxies to packages/registry)
tools/
  privacy-lint/    CI gate: core purity, zone-3 shape, log hygiene
  demo/            narrated walkthrough
docs/schema.sql    target production data model — Postgres + RLS, not wired to any adapter
tests/invariants/  the privacy claims, executable
```

## The invariants

| | Claim |
|---|---|
| INV-1 | No merchant-held record may contain an address-shaped field |
| INV-2 | Capability tokens carry no plaintext address under any encoding |
| INV-3 | A spent capability cannot be replayed |
| INV-4 | No decryption path exists that skips the audit record |
| INV-5 | Two merchants cannot correlate the same consumer |
| INV-6 | Crypto-shred renders historical ciphertext permanently unreadable |
| INV-7 | No cohort below k=25 is ever exposed to a brand |
| INV-8 | Adapters are removable — core has no adapter dependency |
| INV-9 | Every inter-participant request is signed and verified |
| INV-10 | The consent chain is tamper-evident |
| INV-11 | Attenuation may narrow a grant but never widen it |
| INV-12 | Co-residents cannot enumerate each other through a shared address |
| INV-13 | Ciphertext moved between records fails closed |
| INV-14 | A return capability may never exceed the shipment capability's scope |
| INV-15 | Failed delivery notifies the consumer, never the merchant |
| INV-16 | Revocation kills a capability the merchant believes is still valid |
| INV-17 | A redirect issues a fresh capability without telling the merchant the destination changed |
| INV-18 | Refund-without-return makes zero vault calls |

Both CI gates are proven non-vacuous: injecting `address: string` into `MerchantView`
makes privacy-lint exit 1, and each invariant asserts the failure mode as well as the
success path.

**Interop — two operators, not one.** `postal-meridia` alone doesn't prove the
exchange layer is standards-agnostic rather than shaped around one operator's
assumptions. `adapters/dakhil-post` is a second, deliberately different
implementation of the same ports (`SortationPort`, `IdentityProofingPort`):
its `geoBucketFor` buckets by locality/placeName instead of postcode prefix
(built for addresses where the postcode is unreliable or absent), and its
`DakhilIdentity` holds no signing key of its own — it refuses a bare
self-asserted claim outright and can only raise a subject's tier by verifying
a signed attestation against `packages/registry`, capped at the attester's own
tier. `tests/invariants/interop.test.ts` swaps it into `Vault`/`Platform` with
zero changes to either and checks the two operators' outputs never collide.
The technical-effect claim this backs: the system works across operators who
don't trust each other, not just one operator's shape wearing two names.

**[A4] — done.** `packages/labels` mints a COSE_Sign1 label (RFC 8152), Ed25519-signed
by a rotating operator key, over claims derived from an already-verified capability.
`tests/invariants/label.test.ts` proves it offline-verifiable with cached public keys
alone (no vault, no network), rejects tampering and out-of-window keys, expires, and
never carries an address — a contact channel, if present, travels only as a sha256 hash.

**Phase 2 — Exceptions — done.** Returns, failed delivery, revocation, redirect, and
refund (spec §6.2), all built so the exception path can never grant more than the
shipment that created it:

- `Platform.createReturn()` mints via a new `attenuateToReturn()` in
  `packages/capability`, not a fresh `mint()` — narrowing is enforced by the same
  `AttenuationWidened` check `attenuate()` uses, factored into a shared
  `assertNotWidened()`. `attenuate()` itself still rejects *any* purpose change,
  including this one (INV-11) — the transition is reachable only through
  `Platform.createReturn`.
- `NotificationPort` (`packages/core`) + `Vault.notifyFailedDelivery()` — a vault
  method, not a platform one, so the merchant-facing service has no code path to a
  consumer's notification channel at all. Notifies by `subjectRef`, never a merchant id.
- `Platform.revoke()` burns the nonce (`NonceLedger.revoke()`) and revokes the consent
  record a capability was minted against (`ConsentLedger.revoke()`, a new side-set next
  to the hash chain — revocation is a side-effect, not a correction to history). A
  revoked capability fails `Vault.resolve()` through the same `isValidFor()` check a
  replay does, so a merchant can't tell the two apart from the error alone.
- `Platform.redirectDelivery()` changes only `destinationKind`; weight and expiry are
  carried over unchanged (no override exists for either), so there's no surface to widen.
- `Platform.refund()` never calls `Vault.resolve()` — no vault call exists to skip, by
  construction, not because one was suppressed.

`tests/invariants/exceptions-nonwidening.test.ts` asks the non-widening question the
other direction: through the real `Platform` API, and directly against the attenuation
primitives underneath it.

## Known Phase 0 shortcuts

Stated plainly so they don't get mistaken for design:

- **The vault is TypeScript.** The spec calls for Rust, separately deployed. The
  interface is the contract that rewrite must satisfy; the rewrite is Phase 1.
- **In-memory stores.** `docs/schema.sql` is the target production data model,
  RLS included, and the service classes are already shaped as repositories —
  but nothing in this repo consumes it yet. No ORM, no pg client, no
  migrations directory. Wiring a real Postgres adapter behind
  `packages/core`'s ports is Phase 1 work, not done here.
- **KMS is in-process.** `Kms.dekFor` / `saltFor` are the seam where an HSM goes.
- **No SD-JWT yet.** Identity proofing returns a tier through a port; credentials land
  in Phase 1.
- **`linkabilityScore` is a crude oracle.** It exists to fail loudly if someone
  "optimises" derivation into a shared prefix, not to be a formal unlinkability proof.

## Next

Phase 1 remaining: Rust vault, Postgres + RLS, SD-JWT VC issuance, consumer
"what we hold" view. COSE offline labels ([A4]), signed disclosure policies
([A9]), async request/callback capability minting ([A10]), and Phase 2
(Exceptions — returns, failed delivery, revocation, redirect, refund) are done.

Phase 3 (Commerce): the merchant SDK (`packages/sdk` — `MerchantClient`,
`CheckoutResult`), the verified-human signal (`isVerifiedHuman`), and the
metered API (`packages/metering`) are done — INV-21/22. Tier-gating was
already A9. **Not done:** the actual `<S2IDCheckout/>` embeddable UI
widget — this repo has no bundler or frontend framework yet, and faking
one in a static demo page would be worse than stating the gap. What "done"
means here (per SHIP2MYID_DEMO_SPEC.md §12: "a third party integrates from
the published SDK without talking to us") is met at the SDK layer; the
drop-in widget is a thin client over the same `MerchantClient` and is
next.

## Privacy-invariant-reviewer remediation (INV-23..26)

A privacy-invariant-reviewer pass against the Phase 0–3 build found six
findings the 47 tests up to that point didn't cover, all fixed and pinned:

- **The capability MAC didn't cover `id`** — single-use enforcement is keyed
  on `id`, so any holder could swap in a fresh one and replay a "single-use"
  capability indefinitely. Fixed in `packages/capability`; `id` is now signed
  material. INV-23.
- **`createReturn()`/`refund()` had no ownership check** — any caller could
  supply any `actorId` and self-mint a return/refund consent record for
  someone else's shipment. Fixed with the same `subjectRef` check
  `revoke()`/`redirectDelivery()` already had. INV-24.
- **`PolicyStore.active()` returned a live mutable reference** — a caller
  could mutate the disclosure policy in place with no reload, version bump,
  or signature. Fixed with `Object.freeze()`. INV-25.
- **`Platform.processBatch()` had no error isolation** — one merchant's
  quota/tier rejection threw out of the settlement loop and silently
  dropped every later pending transaction. Fixed with per-transaction
  try/catch and a real nack channel (`AsyncExchange.fail()`/`onError()`,
  `Platform.onShipmentError()`). `requestShipment()` is now also metered at
  request time, not only at settlement. INV-26.
- **`operator-flow.html`'s label verification was cosmetic** — it signed
  and verified with the same symmetric HMAC key, and the "scan" step
  re-read an in-memory object rather than the actual encoded token. Now
  uses real Web Crypto Ed25519 (asymmetric — the scanner only ever holds
  the public key), verifies the decoded token string, and the tamper test
  flips a payload byte rather than only the signature.
- **`consumer-flow.html`'s "try to break it" panel was mostly hardcoded
  strings** — only "compare merchants" ran real logic. "Ask for the
  address" now inspects the actual ticket object's keys at runtime;
  "request a cohort" now calls a real `cohortSize()`/`K_ANON_FLOOR` check;
  "replay" now mirrors `NonceLedger.burn()`'s shape instead of a one-shot
  flag.

Also: `tools/privacy-lint` checked `MerchantView` only — the actual Phase 3
merchant-facing type, `CheckoutResult`, went unchecked. It now checks both.
