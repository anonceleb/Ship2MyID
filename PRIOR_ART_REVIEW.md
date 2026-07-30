# Prior Art Review — ONDC, Aadhaar, Posten Norge

> What three systems operating at national scale already solved, what they got
> wrong, and the eleven amendments they force on the demo spec.
>
> Reviewed before Phase 0 build. Amendments marked **[A1]**–**[A11]** are
> implemented or scheduled.

---

## Why these three, and what each actually teaches

They fail in different directions, which is what makes the set useful:

- **Aadhaar** is the reference implementation of *identifier hygiene at 1.4B scale* —
  and a cautionary tale about privacy features nobody adopts.
- **ONDC/Beckn** is the reference implementation of *protocol-level trust between
  mutually distrusting commercial parties* — and a cautionary tale about protecting
  PII by policy rather than by structure.
- **Posten Norge** is the reference implementation of *the boring operational reality
  of addresses* — the household, the barrier, the locker, the rural address with no
  street name.

---

## 1. Aadhaar / UIDAI — identifier hygiene

### 1.1 UID Token vindicates pairwise identifiers — adopt the exact semantics

The single most important finding. UIDAI already runs the design the spec proposed:
<cite index="34-1">a UID Token is a 72-character alphanumeric string returned by UIDAI, unique for each Aadhaar number for a particular requesting entity, and remaining the same for that Aadhaar number across all authentication requests by that entity.</cite>

That is precisely the property pair the spec needs, and the second half matters as much
as the first: **stable within a relationship, unlinkable across relationships**. A design
that only delivered unlinkability would cost merchants the ability to recognise a
returning customer — which is exactly the objection that kills merchant adoption.

**[A1] — implemented.** `deriveS2ID()` produces a deterministic per-(consumer × merchant)
identifier. Asserted by INV-5, which checks both halves: two merchants score zero
linkability, *and* the same merchant re-deriving gets the same value.

### 1.2 The Aadhaar Data Vault is Zone 1, already mandated

UIDAI's 2017 circular requires regulated entities to store <cite index="27-1">Aadhaar numbers and connected data only in a separate secure database designated as an Aadhaar Data Vault; to encrypt it with keys held in HSM devices not shared with any other entity; to keep the vault in a highly restricted network zone; to reference each Aadhaar number with a key that does not computationally permit reverse engineering; and to use only those reference keys in all business use cases.</cite>

Two refinements the spec did not have:

- **The retrofit clause.** Entities must replace Aadhaar numbers with reference keys in
  *existing* databases — even where already encrypted — and <cite index="29-1">must replace Aadhaar numbers in log databases with the corresponding reference keys, storing only reference keys in logs for future transactions.</cite> Logs are where this leaks in practice.
- **Shared HSM with logical isolation.** The 2025 circular permits sub-entities to use a
  parent's HSM <cite index="27-1">provided the configuration ensures logical isolation for each entity and dedicated crypto keys per entity, and parent entities cannot access data in their sub-entities' vaults.</cite> That is exactly the per-tenant DEK design — validated at national scale.

**[A2] — implemented.** `tools/privacy-lint` now fails the build on any log statement
containing a PII-shaped token. Proven non-vacuous: injecting `address: string` into
`MerchantView` exits 1.

**[A3] — implemented.** Per-tenant DEKs derived from a root that never leaves the KMS
boundary; a tenant's compromise cannot reach another tenant's records.

### 1.3 Offline eKYC — verification without calling the issuer

The offline XML flow is a pre-VC design for exactly the demo's label problem. The holder
downloads a UIDAI-signed XML protected by a self-chosen share code; <cite index="52-1">it contains name, address, photo, gender, DOB, a hash of the registered mobile number, a hash of the email address, and a reference id consisting of the last four digits of the Aadhaar number plus a timestamp</cite> — and <cite index="51-1">it does not disclose the Aadhaar number, even in masked form.</cite> The relying party validates the signature offline.

The Secure QR carries the same idea onto paper: <cite index="44-1">protected information readable only by specific scanners, allowing offline authentication of identity without revealing the Aadhaar number.</cite>

**[A4] — implemented.** `packages/labels` mints a COSE_Sign1 label (RFC 8152), Ed25519
-signed by a rotating operator key (`OperatorKeyring`), over claims derived from an
already-verified capability — never an address. `verifyLabelOffline()` needs only public
key material cached ahead of time: no vault reference, no network call, matching a
sorting-hall handheld's actual connectivity. A contact channel, when present for the
gifting flow, travels as a sha256 hash, never the channel itself.

### 1.4 Limited KYC and purpose limitation

Limited KYC lets a relying party authenticate without receiving the full KYC payload —
answer, not data. And <cite index="32-1">authentication and eKYC data may be used only for the stated purpose for which resident consent was obtained; using KYC data obtained for account opening for credit scoring or marketing without separate consent is prohibited.</cite>

**[A5] — implemented.** `purpose` is a caveat inside the capability, and the vault
refuses to resolve unless the consent ledger holds a matching, unexpired, correctly
scoped record for *that* purpose and *that* participant. A delivery grant cannot be
spent on marketing. INV-11 additionally proves `purpose` cannot be changed by attenuation.

### 1.5 Accreditation tiers, not an open API

The AUA / KUA / Sub-AUA structure means access is licensed, audited, and revocable, with
periodic compliance reporting and licence revocation as the enforcement tail.

**[A6] — implemented.** Participants carry a `tier` and a `status`; `Registry.verify()`
refuses suspended participants outright, and `createShipment` enforces a minimum vouch
tier. Suspension is one registry write — no redeploy, no firewall change.

### 1.6 What NOT to copy

Aadhaar's Virtual ID was the right idea with the wrong ergonomics: a rotating identifier
the consumer had to generate and paste. Adoption never materialised, because a privacy
feature that costs the user a step is a privacy feature that doesn't get used. The same
is true of the offline XML flow, where UIDAI never specified how the holder actually
transmits the file and its share code to the relying party — a gap that pushed people
back to sending photographs of the card.

**The lesson is a design constraint, not a footnote:** *unlinkability must be automatic
and invisible.* The consumer must never see, choose, manage, or paste an S2ID. In this
build derivation is deterministic and server-side; the consumer taps a passkey and a
saved label. Zero steps added.

---

## 2. ONDC / Beckn — protocol-level trust

### 2.1 Sign every request. This replaces the spec's mTLS hand-wave

ONDC treats <cite index="37-1">every request/callback pair as a contract between two parties, requiring that all requests and callbacks are digitally signed by the sender and verified by the receiver, with the network participant signing via the Ed25519 scheme and inserting a base64 signature into the Authorization header</cite>, keyed as `subscriber_id|unique_key_id|ed25519` with `created`, `expires`, and a body digest. Because these are cryptographically signed, <cite index="38-1">open networks like ONDC allow the signed messages to act as proofs admissible in court in disputes, enabled by India's Information Technology Act.</cite>

This is materially better than the transport-level authentication the spec assumed. mTLS
authenticates a *channel*; a signature authenticates a *message* and survives the channel.
For a system whose whole product is "who was allowed to cause what," non-repudiation is
not a nice-to-have.

**[A7] — implemented, moved into Phase 0.** `packages/registry` does Ed25519 signing over
`(created)/(expires)/digest`, verifies against registry-published keys, and rejects on
expiry, digest mismatch, unknown key, or suspended participant. INV-9 proves a
post-signature body tamper is caught.

### 2.2 The registry makes participants a network fact, not a deployment fact

Onboarding a merchant is a registry entry. No firewall rule, no redeploy, no coordination
with the operator's IT change window — which, for a partner whose review cycle is measured
in months, is the difference between a platform and a bilateral integration.

**[A8] — implemented.** `Registry` is the sole authority on participant identity, keys,
tier, and standing.

### 2.3 Policy as a signed, hot-reloadable artifact

Beckn's ONIX reference implementation carries <cite index="35-1">an OPA-based policy checker evaluating Rego policies per request, supporting network-specific policy configs, signed policy artifact verification, manifest-backed policies, and hot-reload</cite>, alongside a network manifest published by a facilitator organisation whose detached signature is verified before use.

The spec had "which demographic attributes may a merchant see" as hardcoded logic. That
is wrong for a system meant to span jurisdictions: disclosure rules are exactly the thing
that varies by country and changes without a software release.

**[A9] — scheduled, Phase 1.** Attribute-disclosure and tier-gating rules become signed
Rego policy artifacts, versioned and hot-reloadable, with the *policy hash recorded in the
audit entry* so any historical decision can be replayed against the rules in force at the
time.

### 2.4 Asynchronous callbacks are the honest shape

Beckn pairs every action with a callback — `search`/`on_search`, `init`/`on_init`,
`confirm`/`on_confirm`. This is not ceremony; it reflects that counterparties are slow,
batch-oriented, and occasionally offline. Postal back-ends are all three.

**[A10] — scheduled, Phase 1.** Capability minting and sortation move to request/callback
pairs. A synchronous design would work in the demo and fail on contact with a real
operator's overnight batch.

### 2.5 Grievance and settlement are protocol layers, not afterthoughts

ONDC treats issue-and-grievance management and reconciliation-and-settlement as
first-class network functions. The spec had a returns flow and no dispute layer at all —
a real gap, since a privacy-preserving system makes disputes *harder*: the merchant
cannot prove where it shipped, because by design it never knew.

**[A11] — scheduled, new Phase 4.5.** A dispute layer where the *operator* attests
delivery to a capability, and that attestation — not an address — is the evidence.
Proof-of-delivery becomes a signed operator statement about a grant.

### 2.6 What NOT to copy — and the strongest positioning line available

ONDC's own strategy paper holds that <cite index="54-1">PII and seller data critical to trade remain siloed within the buyer app and seller app respectively and are protected from third-party access</cite>, while critics note that <cite index="54-1">in the absence of a data protection law, storing consumer data becomes a privacy concern, and how ONDC handles these data points remains unknown</cite>, alongside <cite index="54-1">a lack of clarity on resolution of privacy-related grievances and data breaches within the existing framework.</cite>

That is the whole gap, stated by the incumbent. ONDC's PII protection is **policy-level**:
participants are told to silo data and trusted to do it. This build's protection is
**structural**: the merchant cannot produce an address because no code path exists that
would give it one, and a test fails the build if one is added.

> *"ONDC unbundled commerce and asked participants to please not misuse the data.
> We unbundled commerce and made the data unavailable to misuse."*

One encouraging feasibility signal from the same literature: a Beckn interviewee
<cite index="38-1">implemented a first version demonstrating a small-scale peer-to-peer network in four person-weeks.</cite> Protocol-shaped systems are cheap to prototype precisely because the surface is narrow.

---

## 3. Posten Norge — the operational reality

### 3.1 The household barrier — a solved problem the spec had listed as unsolved

The spec flagged multi-resident addresses as an open question. Posten shipped the answer:
residents log in to check <cite index="17-1">whether they are registered at the correct address and whether everyone in the family or household is listed, including whether anyone is registered at their address who should not be.</cite> And crucially: <cite index="17-1">a resident who does not want others registered at the same address to see their information can contact customer service to have a barrier applied so that those registered at the address cannot see each other's information — a solution desirable for residents of institutions and for persons under guardianship who redirect post to their guardian.</cite>

The named use cases are the point. Shelters, care institutions, guardianship, people
fleeing domestic situations — the barrier is a safety feature, and it is the case where a
naive "household view" causes real harm.

**Adopted.** `visibleCoResidents()` in the core plus a `barrier` column on
`vault.residency`, in Phase 0 rather than deferred. INV-12 proves a barriered resident is
invisible to co-residents *and* sees none of them.

### 3.2 Self-service correction is the trust mechanism

Posten's address register is consumer-inspectable: <cite index="17-1">log in with BankID to check and change the information Posten holds.</cite> Registered data <cite index="17-1">is used to update private and public registers, with an opt-out available.</cite>

Two things worth stealing. First, **inspectability is what makes a central register
tolerable** — a register you can read and correct is a different political object from one
you cannot. Second, **downstream propagation is consented and reversible**, not a silent
default.

**Adopted.** A "what we hold about you" view moves into Phase 1, not Phase 5. Any
propagation of address changes to third parties is an explicit, revocable subscription.

### 3.3 Lockers and access points are the zero-address path

Posten operates <cite index="13-1">over 1,400 post-in-shop points and around 2,000 parcel machines, with automatic redirection to the nearest post-in-shop when a machine is full or the parcel is too large.</cite>

The spec underused this. **A locker delivery needs no address at all** — not an encrypted
one, not a resolved one. It is the privacy-maximal fulfilment path and it already has
national infrastructure and consumer habit behind it in several markets.

**Adopted.** `destinationKind: "door" | "access-point" | "locker"` is a first-class caveat,
and the demo walkthrough ships to a locker by default. Reframing: this isn't a fallback
for failed delivery, it's the *preferred* path, and the pitch should say so.

### 3.4 Rural addressing without street names

<cite index="13-1">In rural Norway there are often no official street names; a local place name takes the place of the street, and sometimes only the recipient's name and the postcode with the town are sufficient. Posten Norge delivers without a street name.</cite>

The spec's Phase 6 "Kestrel" adapter — a second country with place-name addressing — turns
out to describe real Nordic practice rather than a contrived stress test. Keep it, and cite
the precedent: `AddressPlaintext.placeName` is optional in the core, and an address with no
`line1` must not be an error.

### 3.5 The two-brand split

Posten separates the consumer brand from the business/logistics brand (Bring). Different
counterparties, different trust postures, different data appetites. Worth mirroring in how
the consumer wallet and the merchant SDK are presented — the consumer should never feel
they are logging into a merchant's tool.

---

## 4. Consolidated changes to the spec

| # | Change | Source | Status |
|---|---|---|---|
| A1 | Pairwise IDs stable-within / unlinkable-across | Aadhaar UID Token | Phase 0 ✅ |
| A2 | No PII-shaped token in any log, enforced in CI | Aadhaar ADV log clause | Phase 0 ✅ |
| A3 | Per-tenant DEKs, logical isolation | Aadhaar 2025 HSM circular | Phase 0 ✅ |
| A4 | Offline-verifiable label, hashed contact channels | Aadhaar offline eKYC / Secure QR | Phase 1 ✅ |
| A5 | Purpose bound into the capability and checked at resolve | Reg 17(1)(b) | Phase 0 ✅ |
| A6 | Participant accreditation tiers + suspension | AUA/KUA licensing | Phase 0 ✅ |
| A7 | Ed25519 message signing, moved forward from Phase 3 | ONDC/Beckn | Phase 0 ✅ |
| A8 | Registry as the participant authority | ONDC registry | Phase 0 ✅ |
| A9 | Disclosure rules as signed Rego artifacts; policy hash in audit | Beckn ONIX / OPA | Phase 1 |
| A10 | Async request/callback pairs | Beckn action/on_action | Phase 1 |
| A11 | Dispute layer: operator attests delivery to a capability | ONDC IGM/RSF | Phase 4.5 |
| — | Household barrier in the data model from day one | Posten | Phase 0 ✅ |
| — | Consumer-inspectable "what we hold" + correction | Posten / BankID | Phase 1 |
| — | Locker as the preferred, zero-address path | Posten access points | Phase 0 ✅ |

**Net effect on the roadmap:** Phase 0 grew — signing, registry, and the household barrier
moved forward from later phases. That is the right trade. Each is cheap now and expensive
to retrofit, and all three are load-bearing for the claim that this is a *network*, not an
application.

---

## 5. The one thing all three agree on

Aadhaar mandates it, ONDC assumes it, Posten operates on it:

> **The authoritative record is held by exactly one accountable party, and everyone
> else works from a reference key.**

Where this build departs is in the next sentence. Aadhaar says the reference key must not
be reversible *by outsiders*. ONDC says participants must not share PII *as a matter of
policy*. Neither says the merchant must be structurally incapable of obtaining the
underlying value.

That is the gap this demo occupies, and it is narrow enough to be defensible and specific
enough to be tested — which is why the eight-turned-thirteen invariants in
`tests/invariants/` are the actual deliverable, not the architecture diagram.
