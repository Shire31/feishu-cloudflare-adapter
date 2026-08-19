import assert from "node:assert/strict";
import { createCipheriv, createHash } from "node:crypto";
import test from "node:test";

import {
  FeishuWebhookError,
  createFeishuChallengeResponse,
  createFeishuWebhookErrorResponse,
  parseFeishuWebhookRequest,
} from "../dist/index.js";

const verificationToken = "verification-token-for-test";
const encryptKey = "encrypt-key-for-test";

test("plain URL verification returns the challenge", async () => {
  const request = jsonRequest({
    type: "url_verification",
    token: verificationToken,
    challenge: "challenge-123",
  });

  const result = await parseFeishuWebhookRequest(request, { verificationToken });
  assert.equal(result.kind, "challenge");
  assert.equal(result.challenge, "challenge-123");

  const response = createFeishuChallengeResponse(result.challenge);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { challenge: "challenge-123" });
});

test("v2 events expose event type, event id, and protocol metadata", async () => {
  const payload = {
    schema: "2.0",
    header: {
      event_id: "evt_123",
      event_type: "im.message.receive_v1",
      create_time: "1787090000000",
      token: verificationToken,
      app_id: "cli_test",
      tenant_key: "tenant_test",
    },
    event: {
      sender: { sender_type: "user" },
      message: { message_id: "om_test", message_type: "text" },
    },
  };

  const result = await parseFeishuWebhookRequest(jsonRequest(payload), {
    verificationToken,
  });

  assert.equal(result.kind, "event");
  assert.equal(result.event.eventType, "im.message.receive_v1");
  assert.equal(result.event.eventId, "evt_123");
  assert.equal(result.event.schema, "2.0");
  assert.equal(result.event.appId, "cli_test");
  assert.equal(result.event.tenantKey, "tenant_test");
  assert.deepEqual(result.event.payload, payload);
});

test("v1 events are still recognized", async () => {
  const payload = {
    token: verificationToken,
    uuid: "evt_v1",
    event: {
      type: "im.message.receive_v1",
      tenant_key: "tenant_v1",
    },
  };

  const result = await parseFeishuWebhookRequest(jsonRequest(payload), {
    verificationToken,
  });

  assert.equal(result.kind, "event");
  assert.equal(result.event.eventType, "im.message.receive_v1");
  assert.equal(result.event.eventId, "evt_v1");
  assert.equal(result.event.tenantKey, "tenant_v1");
});

test("invalid verification token fails closed", async () => {
  await assert.rejects(
    () =>
      parseFeishuWebhookRequest(
        jsonRequest({
          type: "url_verification",
          token: "wrong",
          challenge: "challenge",
        }),
        { verificationToken },
      ),
    (error) =>
      error instanceof FeishuWebhookError &&
      error.status === 401 &&
      error.code === "invalid_verification_token",
  );
});

test("official-SDK-compatible encrypted challenge verifies and decrypts", async () => {
  const plaintext = {
    type: "url_verification",
    token: verificationToken,
    challenge: "encrypted-challenge",
  };
  const signed = encryptedRequest(plaintext, { encryptKey });

  const result = await parseFeishuWebhookRequest(signed.request, {
    verificationToken,
    encryptKey,
    maxTimestampSkewSeconds: 60,
  });

  assert.equal(result.kind, "challenge");
  assert.equal(result.challenge, "encrypted-challenge");
});

test("signature validation is bound to the raw request body", async () => {
  const plaintext = {
    type: "url_verification",
    token: verificationToken,
    challenge: "encrypted-challenge",
  };
  const signed = encryptedRequest(plaintext, { encryptKey });
  const tamperedBody = signed.rawBody.replace(/.$/, (last) => (last === "}" ? " " : "}"));
  const request = new Request("https://example.com/feishu/events", {
    method: "POST",
    headers: signed.headers,
    body: tamperedBody,
  });

  await assert.rejects(
    () => parseFeishuWebhookRequest(request, { verificationToken, encryptKey }),
    (error) =>
      error instanceof FeishuWebhookError &&
      error.status === 401 &&
      error.code === "invalid_signature",
  );
});

test("stale signed requests can be rejected before decryption", async () => {
  const plaintext = {
    type: "url_verification",
    token: verificationToken,
    challenge: "old",
  };
  const signed = encryptedRequest(plaintext, {
    encryptKey,
    timestamp: String(Math.floor(Date.now() / 1000) - 3600),
  });

  await assert.rejects(
    () =>
      parseFeishuWebhookRequest(signed.request, {
        verificationToken,
        encryptKey,
        maxTimestampSkewSeconds: 60,
      }),
    (error) =>
      error instanceof FeishuWebhookError &&
      error.status === 401 &&
      error.code === "stale_timestamp",
  );
});

test("body size is enforced while streaming", async () => {
  const request = jsonRequest({ text: "x".repeat(256) });

  await assert.rejects(
    () => parseFeishuWebhookRequest(request, { maxBodyBytes: 64 }),
    (error) =>
      error instanceof FeishuWebhookError &&
      error.status === 413 &&
      error.code === "body_too_large",
  );
});

test("unknown config keys fail fast instead of silently weakening security", async () => {
  await assert.rejects(
    () =>
      parseFeishuWebhookRequest(jsonRequest({ type: "noop" }), {
        verificationToken,
        maxRequestAgeSeconds: 60,
      }),
    (error) =>
      error instanceof TypeError &&
      error.message === "Unknown Feishu webhook config option: maxRequestAgeSeconds",
  );
});

test("replay-window configuration requires signed requests", async () => {
  await assert.rejects(
    () =>
      parseFeishuWebhookRequest(jsonRequest({ type: "noop" }), {
        verificationToken,
        maxTimestampSkewSeconds: 60,
      }),
    (error) =>
      error instanceof TypeError &&
      error.message === "maxTimestampSkewSeconds requires encryptKey so requests are signed",
  );
});

test("known errors convert to small safe HTTP responses", async () => {
  const response = createFeishuWebhookErrorResponse(
    new FeishuWebhookError(401, "invalid_signature", "secret diagnostic"),
  );
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { ok: false, error: "invalid_signature" });
});

function jsonRequest(payload) {
  return new Request("https://example.com/feishu/events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function encryptedRequest(payload, options) {
  const key = createHash("sha256").update(options.encryptKey).digest();
  const iv = Buffer.from("0123456789abcdef", "utf8");
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
  ]);
  const rawBody = JSON.stringify({
    encrypt: Buffer.concat([iv, ciphertext]).toString("base64"),
  });

  const timestamp = options.timestamp ?? String(Math.floor(Date.now() / 1000));
  const nonce = "nonce-for-test";
  const signature = createHash("sha256")
    .update(`${timestamp}${nonce}${options.encryptKey}${rawBody}`)
    .digest("hex");
  const headers = {
    "content-type": "application/json",
    "x-lark-request-timestamp": timestamp,
    "x-lark-request-nonce": nonce,
    "x-lark-signature": signature,
  };

  return {
    rawBody,
    headers,
    request: new Request("https://example.com/feishu/events", {
      method: "POST",
      headers,
      body: rawBody,
    }),
  };
}
