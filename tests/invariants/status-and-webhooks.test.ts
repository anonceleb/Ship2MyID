/**
 * [Phase 4] Merchant-facing status reads and real webhook delivery.
 *
 * INV-27 covers Platform.getCapabilityStatus(): a merchant pull, ownership
 * checked, exactly three states, never a delivery-progress feed — see the
 * docstring on CapabilityStatus in services/platform/src/platform.ts for
 * why. INV-28 covers packages/webhooks: signatures round-trip and reject
 * tampering, and WebhookDispatcher performs genuine HTTP delivery (a real
 * local server, not a mock) with real retry-on-failure, wired into
 * Platform.processBatch() the same way onShipmentReady()/onShipmentError()
 * already are.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";

import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform, NotAuthorized, UnknownCapability } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { MerchantClient } from "../../packages/sdk/src/client.ts";
import {
  WebhookDispatcher,
  WebhookDeliveryFailed,
  newWebhookSecret,
  signWebhookBody,
  verifyWebhookSignature,
  type WebhookEvent,
} from "../../packages/webhooks/src/webhook.ts";

function harness() {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const registry = new Registry();
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, sortation: new MeridiaSortation() });
  const platform = new Platform({ registry, consent, capSecret });

  const mk = newKeyPair();
  registry.register({
    participantId: "alba-goods.example",
    role: "merchant", keyId: "k1", publicKey: mk.publicKey, tier: 2, status: "active",
  });

  const root = newRootSecret();
  const s2id = platform.issueS2ID(root, "alba-goods.example");
  const rec = vault.store({
    id: "rec_1", subjectRef: "sub_1", tenantId: "meridia-post",
    address: { line1: "14 Harbour Lane", locality: "Calder", postcode: "4820" },
    geoBucket: geoBucketFor("4820"), vouchTier: 2,
  });
  vault.bind(s2id, rec.id);
  platform.learnProjection(s2id, { geoBucket: rec.geoBucket, vouchTier: 2 });

  const client = new MerchantClient({ platform, participantId: "alba-goods.example", keyId: "k1", privateKey: mk.privateKey });
  const req = { s2id, weightKg: 2, carrier: "MER-POST", destinationKind: "door" as const };

  return { platform, registry, consent, mk, client, req, s2id };
}

/* ---------------------------------------------------------- INV-27 ----- */

test("INV-27: a freshly minted capability reads back as issued", () => {
  const h = harness();
  const { capabilityId } = h.client.checkout(h.req, "sub_1");
  const status = h.platform.getCapabilityStatus(capabilityId, "alba-goods.example");
  assert.equal(status, "issued");
});

test("INV-27: a revoked capability reads back as revoked", () => {
  const h = harness();
  const { capabilityId } = h.client.checkout(h.req, "sub_1");
  h.platform.revoke(capabilityId, "sub_1");
  assert.equal(h.platform.getCapabilityStatus(capabilityId, "alba-goods.example"), "revoked");
});

test("INV-27: an expired consent entry reads back as expired", () => {
  const h = harness();
  const { capabilityId } = h.client.checkout(h.req, "sub_1");
  // tamperForDemo is the same test-only seam INV-10's chain-integrity test
  // uses — pushing an entry's expiresAt into the past without waiting out
  // the real 7-day window createShipment() sets.
  const consentRef = [...h.consent.entries()].find((e) => e.grantedTo === "alba-goods.example")!.ref;
  const seq = h.consent.find(consentRef)!.seq;
  h.consent.tamperForDemo(seq, (e) => { e.expiresAt = Date.now() - 1000; });
  assert.equal(h.platform.getCapabilityStatus(capabilityId, "alba-goods.example"), "expired");
});

test("INV-27: a merchant cannot read another merchant's capability status", () => {
  const h = harness();
  const { capabilityId } = h.client.checkout(h.req, "sub_1");
  assert.throws(() => h.platform.getCapabilityStatus(capabilityId, "corvid-tools.example"), NotAuthorized);
});

test("INV-27: an unknown capability id is rejected, not silently reported as some status", () => {
  const h = harness();
  assert.throws(() => h.platform.getCapabilityStatus("cap_never_minted", "alba-goods.example"), UnknownCapability);
});

test("INV-27: MerchantClient.getStatus() is scoped to the client's own participantId by construction", () => {
  const h = harness();
  const { capabilityId } = h.client.checkout(h.req, "sub_1");
  assert.deepEqual(h.client.getStatus(capabilityId), { status: "issued" });

  const otherKeys = newKeyPair();
  h.registry.register({ participantId: "corvid-tools.example", role: "merchant", keyId: "k1", publicKey: otherKeys.publicKey, tier: 2, status: "active" });
  const otherClient = new MerchantClient({ platform: h.platform, participantId: "corvid-tools.example", keyId: "k1", privateKey: otherKeys.privateKey });
  assert.throws(() => otherClient.getStatus(capabilityId), NotAuthorized);
});

/* ---------------------------------------------------------- INV-28 ----- */

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr ? addr.port : 0);
    });
  });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => resolve(body));
  });
}

test("INV-28: a webhook signature verifies against the exact event, and rejects any tampering", () => {
  const secret = newWebhookSecret();
  const event: WebhookEvent = { event: "checkout.completed", transactionId: "txn_1", at: 1000, data: { capabilityId: "cap_1", s2id: "MER-AAAA" } };
  const sig = signWebhookBody(secret, event);
  assert.ok(verifyWebhookSignature(secret, event, sig));

  const tampered: WebhookEvent = { ...event, data: { ...event.data, s2id: "MER-BBBB" } };
  assert.equal(verifyWebhookSignature(secret, tampered, sig), false);
  assert.equal(verifyWebhookSignature("wrong-secret", event, sig), false);
});

test("INV-28: WebhookDispatcher performs a real HTTP delivery, signed, to a real local server", async () => {
  const received: { body: string; signature: string | undefined }[] = [];
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    received.push({ body, signature: req.headers["x-ship2myid-signature"] as string | undefined });
    res.writeHead(200).end("ok");
  });
  const port = await listen(server);
  try {
    const secret = newWebhookSecret();
    const dispatcher = new WebhookDispatcher();
    const event: WebhookEvent = { event: "checkout.completed", transactionId: "txn_2", at: Date.now(), data: { capabilityId: "cap_2", s2id: "MER-CCCC" } };
    const result = await dispatcher.deliver({ url: `http://127.0.0.1:${port}`, secret }, event);

    assert.equal(result.ok, true);
    assert.equal(result.attempt, 1);
    assert.equal(received.length, 1);
    assert.deepEqual(JSON.parse(received[0]!.body), event);
    assert.ok(verifyWebhookSignature(secret, event, received[0]!.signature!), "the signature the server received must verify against the same secret");
  } finally {
    server.close();
  }
});

test("INV-28: WebhookDispatcher retries a failing endpoint and records every attempt", async () => {
  let calls = 0;
  const server = createServer((_req, res) => {
    calls += 1;
    if (calls < 3) { res.writeHead(500).end("try again"); return; }
    res.writeHead(200).end("ok");
  });
  const port = await listen(server);
  try {
    const dispatcher = new WebhookDispatcher({ maxAttempts: 3, delayMs: 5 });
    const event: WebhookEvent = { event: "checkout.completed", transactionId: "txn_3", at: Date.now(), data: { capabilityId: "cap_3", s2id: "MER-DDDD" } };
    const result = await dispatcher.deliver({ url: `http://127.0.0.1:${port}`, secret: newWebhookSecret() }, event);

    assert.equal(result.ok, true);
    assert.equal(result.attempt, 3);
    assert.equal(calls, 3);
    assert.equal(dispatcher.history().length, 3, "the two failed attempts stay on the record, not just the final success");
    assert.equal(dispatcher.history()[0]!.ok, false);
    assert.equal(dispatcher.history()[1]!.ok, false);
  } finally {
    server.close();
  }
});

test("INV-28: WebhookDispatcher throws once every attempt against a dead endpoint is exhausted", async () => {
  const dispatcher = new WebhookDispatcher({ maxAttempts: 2, delayMs: 5 });
  const event: WebhookEvent = { event: "checkout.failed", transactionId: "txn_4", at: Date.now(), data: { reason: "tier 1 < 2" } };
  // Port 1 is reserved and unlistenable — a real, reliably-refused connection.
  await assert.rejects(
    () => dispatcher.deliver({ url: "http://127.0.0.1:1", secret: newWebhookSecret() }, event),
    WebhookDeliveryFailed,
  );
  assert.equal(dispatcher.history().length, 2);
});

test("INV-28: Platform.processBatch() fires the merchant's registered webhook on both a successful and a rejected settlement", async () => {
  const requests: { body: string; signature: string | undefined }[] = [];
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    requests.push({ body, signature: req.headers["x-ship2myid-signature"] as string | undefined });
    res.writeHead(200).end("ok");
  });
  const port = await listen(server);
  try {
    const h = harness();
    const secret = newWebhookSecret();
    h.client.registerWebhook({ url: `http://127.0.0.1:${port}`, secret });

    const goodEnv = signRequest("alba-goods.example", "k1", h.mk.privateKey, h.req);
    const { transactionId: t1 } = h.platform.requestShipment(goodEnv, h.req, "sub_1");

    const badReq = { ...h.req, s2id: "MER-NEVER-LEARNED-0000" };
    const badEnv = signRequest("alba-goods.example", "k1", h.mk.privateKey, badReq);
    const { transactionId: t2 } = h.platform.requestShipment(badEnv, badReq, "sub_1");

    h.platform.processBatch();
    // processBatch() fires webhooks without awaiting delivery (see its
    // docstring) — wait for both POSTs to actually land before asserting.
    for (let i = 0; i < 50 && requests.length < 2; i++) await new Promise((r) => setTimeout(r, 10));

    assert.equal(requests.length, 2);
    const events = requests.map((r) => JSON.parse(r.body) as WebhookEvent);
    const completed = events.find((e) => e.event === "checkout.completed");
    const failed = events.find((e) => e.event === "checkout.failed");
    assert.ok(completed && completed.transactionId === t1);
    assert.ok(failed && failed.transactionId === t2);
    assert.match((failed!.data as { reason: string }).reason, /unknown s2id/);

    for (const r of requests) {
      const ev = JSON.parse(r.body) as WebhookEvent;
      assert.ok(verifyWebhookSignature(secret, ev, r.signature!));
    }
    assert.equal(h.platform.webhookHistory().length, 2);
  } finally {
    server.close();
  }
});
