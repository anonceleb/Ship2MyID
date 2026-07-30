# Ship2MyID — Phase 0

Zone skeleton, envelope crypto, pairwise identifiers, participant registry, capability
tokens, and the executable privacy invariants.

**Runs entirely offline. No install, no database, no cloud account, no network.**
Node ≥ 22.6 only — TypeScript executes via native type stripping.

```bash
npm run verify   # privacy-lint + all invariants (INV-1..22, A4, non-widening)
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
tools/
  privacy-lint/    CI gate: core purity, zone-3 shape, log hygiene
  demo/            narrated walkthrough
db/schema.sql      Postgres with row-level security as the enforcement layer
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
- **In-memory stores.** `db/schema.sql` is the real target, RLS included, and the
  service classes are already shaped as repositories.
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
