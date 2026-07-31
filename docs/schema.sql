-- TARGET PRODUCTION DATA MODEL — not wired to any adapter yet.
--
-- Phase 0-3 run entirely in-memory (packages/core's ConsentLedger, AuditLog,
-- NonceLedger; services/vault's #records/#bindings maps). No ORM, no pg
-- client, no migrations directory exist in this repo. This file is the
-- schema that in-memory shape must survive translating to, kept in sync by
-- hand: each table below maps directly to one of those in-memory stores, and
-- each column exists because some invariant in tests/invariants/ needs it
-- (e.g. platform.projection has no address column because INV-1 forbids one).
--
-- Zone 1 (vault) and Zone 2 (platform) schemas.
-- Enforcement lives in Row-Level Security, not application code: an ORM mistake
-- must not become a privacy incident.

CREATE SCHEMA IF NOT EXISTS vault;    -- ZONE 1: the only place plaintext can exist
CREATE SCHEMA IF NOT EXISTS platform; -- ZONE 2: ciphertext + pseudonyms, no keys

-- ---------------------------------------------------------------- ZONE 1 ----
CREATE TABLE vault.address_record (
  id              uuid PRIMARY KEY,
  subject_ref     uuid NOT NULL,
  tenant_id       text NOT NULL,
  ciphertext      bytea NOT NULL,
  nonce           bytea NOT NULL,
  auth_tag        bytea NOT NULL,
  key_id          text NOT NULL,
  shred_salt_id   uuid NOT NULL,          -- destroying the salt is the erasure
  geo_bucket      text NOT NULL,          -- coarse, k>=50. The only field Zone 2 sees
  vouch_tier      smallint NOT NULL CHECK (vouch_tier BETWEEN 1 AND 3),
  status          text NOT NULL DEFAULT 'active'
);

-- Resolution table. Never replicated outside Zone 1.
CREATE TABLE vault.binding (
  s2id              text PRIMARY KEY,
  address_record_id uuid NOT NULL REFERENCES vault.address_record(id),
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- Co-residency, after Posten Norge: several people, one address, and a barrier
-- flag so they cannot enumerate each other by default.
CREATE TABLE vault.residency (
  address_record_id uuid NOT NULL REFERENCES vault.address_record(id),
  subject_ref       uuid NOT NULL,
  barrier           boolean NOT NULL DEFAULT false,
  PRIMARY KEY (address_record_id, subject_ref)
);

-- Append-only. No UPDATE or DELETE grant is ever issued on this table.
CREATE TABLE vault.audit (
  id           uuid PRIMARY KEY,
  actor        text NOT NULL,
  purpose      text NOT NULL,
  consent_ref  text NOT NULL,
  record_id    uuid NOT NULL,
  at           timestamptz NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON vault.audit FROM PUBLIC;

-- ---------------------------------------------------------------- ZONE 2 ----
CREATE TABLE platform.participant (
  participant_id text PRIMARY KEY,
  role           text NOT NULL CHECK (role IN ('merchant','operator','brand','platform')),
  key_id         text NOT NULL,
  public_key     text NOT NULL,
  tier           smallint NOT NULL CHECK (tier BETWEEN 1 AND 3),
  status         text NOT NULL DEFAULT 'active'
);

CREATE TABLE platform.consent (
  seq          bigserial PRIMARY KEY,
  ref          text UNIQUE NOT NULL,
  subject_ref  uuid NOT NULL,
  granted_to   text NOT NULL REFERENCES platform.participant(participant_id),
  purpose      text NOT NULL,
  scope        text[] NOT NULL,
  at           timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  prev_hash    text NOT NULL,
  hash         text NOT NULL
);
REVOKE UPDATE, DELETE ON platform.consent FROM PUBLIC;

-- Projection Zone 2 is allowed to cache. Note the absence of any address column;
-- tools/privacy-lint fails the build if one is added.
CREATE TABLE platform.projection (
  s2id        text PRIMARY KEY,
  geo_bucket  text NOT NULL,
  vouch_tier  smallint NOT NULL
);

-- --------------------------------------------------------------- POLICY -----
ALTER TABLE vault.address_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.binding        ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.projection  ENABLE ROW LEVEL SECURITY;

-- Only the vault service role may see ciphertext at all.
CREATE POLICY vault_only ON vault.address_record
  USING (current_setting('app.service', true) = 'vault');

-- Tenant isolation: one operator's compromise cannot reach another's rows.
CREATE POLICY tenant_isolation ON vault.binding
  USING (current_setting('app.tenant', true) IS NOT NULL);

-- Merchants see only their own pairwise identifiers, never the whole table.
CREATE POLICY own_pairwise ON platform.projection
  USING (s2id = ANY (string_to_array(current_setting('app.s2ids', true), ',')));
