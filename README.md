# feishu-cloudflare-adapter

Fetch-native Feishu/Lark webhook ingress for Cloudflare Workers and other Web API runtimes.

The library does one job: translate the Feishu/Lark HTTP event protocol into a small, runtime-neutral result without pulling a Node web framework or long-lived WebSocket client into your Worker.

## Why

Feishu's official Node SDK already defines the protocol semantics we want: URL verification, Verification Token checks, optional encrypted event envelopes, v1/v2 event dispatch, and Feishu/Lark request headers. The official Agent Channel SDK adds higher-level messaging abstractions.

Those packages target Node runtimes and Node HTTP adapters. This package keeps the protocol behavior but implements the ingress with only Fetch + Web Crypto, so it can run directly inside a Cloudflare Worker isolate.

It is intentionally **not** a full Feishu SDK. Outbound OpenAPI calls, CardKit, media upload, chat management, and application-specific message normalization belong in higher layers.

## Features

- Cloudflare Workers / Fetch-native `Request` input
- no runtime dependencies
- Feishu/Lark URL verification challenge handling
- Verification Token validation
- `x-lark-signature` validation against the raw request body
- encrypted event envelope support
- AES-256-CBC decryption using Web Crypto
- Feishu/Lark v1 and v2 event-type extraction
- stable `eventId` extraction for downstream idempotency
- streaming request-body size limit
- optional signed-request timestamp skew check
- small safe error responses

## Install

Until an npm release is published:

```bash
npm install github:Shire31/feishu-cloudflare-adapter
```

After an npm release:

```bash
npm install feishu-cloudflare-adapter
```

## Basic Worker usage

```ts
import {
  createFeishuChallengeResponse,
  createFeishuWebhookErrorResponse,
  parseFeishuWebhookRequest,
} from "feishu-cloudflare-adapter";

interface Env {
  FEISHU_VERIFICATION_TOKEN: string;
  FEISHU_ENCRYPT_KEY: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/feishu/events") {
      return new Response("Not found", { status: 404 });
    }

    try {
      const result = await parseFeishuWebhookRequest(request, {
        verificationToken: env.FEISHU_VERIFICATION_TOKEN,
        encryptKey: env.FEISHU_ENCRYPT_KEY,
        maxTimestampSkewSeconds: 300,
      });

      if (result.kind === "challenge") {
        return createFeishuChallengeResponse(result.challenge);
      }

      if (result.event.eventType === "im.message.receive_v1") {
        // Submit to your durable queue / agent runtime here.
        // Keep the Feishu HTTP acknowledgement fast.
      }

      return Response.json({ ok: true });
    } catch (error) {
      return createFeishuWebhookErrorResponse(error);
    }
  },
};
```

## Cloudflare Think pattern

The adapter is deliberately independent of `@cloudflare/think`. A Think integration can map Feishu's `event_id` directly to Think's idempotency key:

```ts
const result = await parseFeishuWebhookRequest(request, config);

if (result.kind === "challenge") {
  return createFeishuChallengeResponse(result.challenge);
}

if (result.event.eventType !== "im.message.receive_v1") {
  return Response.json({ ok: true });
}

const payload = result.event.payload;
const event = payload.event as Record<string, unknown>;
const message = event.message as Record<string, unknown>;
const sender = event.sender as Record<string, unknown>;
const senderId = sender.sender_id as Record<string, unknown>;

const chatId = String(message.chat_id);
const senderOpenId = String(senderId.open_id);
const chatType = String(message.chat_type);
const conversation =
  chatType === "p2p" ? `feishu:dm:${senderOpenId}` : `feishu:chat:${chatId}`;

const agent = await getAgentByName(env.AGENT, conversation);
await agent.acceptFeishuMessage({
  eventId: result.event.eventId!,
  messageId: String(message.message_id),
  chatId,
  content: String(message.content),
});

return Response.json({ ok: true });
```

The important boundary is that the webhook request only verifies, parses, and durably submits the turn. The LLM/tool loop should continue outside the original Feishu request lifetime.

## Protocol behavior

When `encryptKey` is configured, a request is processed in this order:

```text
raw HTTP body
   |
   +-- x-lark-request-timestamp
   +-- x-lark-request-nonce
   +-- x-lark-signature
   |
   v
SHA-256(timestamp + nonce + encryptKey + rawBody)
   |
   v
parse outer JSON
   |
   v
base64(encrypt)
   |
   +-- first 16 bytes: IV
   +-- remaining bytes: ciphertext
   |
   v
SHA-256(encryptKey) -> AES-256-CBC key
   |
   v
Web Crypto decrypt
   |
   v
Verification Token check
   |
   +-- url_verification -> challenge
   |
   +-- event -> v1/v2 event type + event id
```

The AES envelope behavior mirrors the implementation used by Feishu's official Node SDK. The raw-body signature boundary follows Feishu's HTTP callback protocol and avoids re-serializing parsed JSON before verification.

## Security notes

For a production webhook:

- configure both a Verification Token and Encrypt Key;
- store them as Worker secrets, never source-controlled variables;
- keep `maxTimestampSkewSeconds` reasonably small if your callback traffic can tolerate it; it requires `encryptKey` because replay rejection is meaningful only for signed requests;
- use `event.eventId` as a downstream idempotency key because Feishu may retry callbacks;
- acknowledge the webhook quickly and perform long-running agent work durably;
- keep the raw request body intact until signature verification is complete;
- never log decrypted event bodies indiscriminately because they can contain user content and identifiers.

The adapter defaults to a 1 MiB maximum request body. Override `maxBodyBytes` only when you have a concrete need. Configuration is intentionally strict: unknown option names throw a `TypeError` instead of being silently ignored, because a typo in a security option must not weaken verification unnoticed.

## API

### `parseFeishuWebhookRequest(request, config)`

Returns either:

```ts
{ kind: "challenge", challenge, payload }
```

or:

```ts
{
  kind: "event",
  event: {
    eventType,
    eventId,
    schema,
    createTime,
    appId,
    tenantKey,
    payload,
  },
}
```

### `createFeishuChallengeResponse(challenge)`

Returns the exact JSON response expected by Feishu/Lark URL verification.

### `FeishuWebhookError`

Known protocol failures expose a stable `status` and `code` without requiring callers to parse error text.

### `createFeishuWebhookErrorResponse(error)`

Converts a known `FeishuWebhookError` to a small response such as:

```json
{"ok":false,"error":"invalid_signature"}
```

Unknown errors are rethrown.

## Compatibility basis

The implementation is intentionally small and cross-checked against:

- Feishu/Lark official Node SDK (`larksuite/node-sdk`) event dispatcher and AES cipher behavior
- Feishu/Lark official Agent Channel SDK (`larksuite/channel-sdk-node`) webhook/channel model
- Feishu's HTTP event subscription protocol

This project is independent and is not an official Feishu/Lark package.

## Development

```bash
npm install
npm test
npm run check
```

Tests include independent Node `crypto` vectors for encrypted callback generation so the production parser and the test-vector generator do not share the same crypto implementation.

## License

MIT
