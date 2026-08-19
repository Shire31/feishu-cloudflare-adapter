// Fetch-native Feishu/Lark webhook verification, decryption, and event extraction.

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface FeishuWebhookConfig {
  /** Verification Token configured in the Feishu/Lark event subscription. */
  verificationToken?: string;
  /** Encrypt Key configured in the Feishu/Lark event subscription. */
  encryptKey?: string;
  /** Maximum accepted request body size. Defaults to 1 MiB. */
  maxBodyBytes?: number;
  /**
   * Optional replay hardening for signed requests. When set, signed requests
   * whose x-lark-request-timestamp differs by more than this many seconds are rejected.
   */
  maxTimestampSkewSeconds?: number;
}

export interface FeishuWebhookEvent {
  eventType: string;
  eventId?: string;
  schema?: string;
  createTime?: string;
  appId?: string;
  tenantKey?: string;
  /** Decrypted, protocol-level payload exactly as dispatched by Feishu/Lark. */
  payload: Record<string, unknown>;
}

export type FeishuWebhookResult =
  | {
      kind: "challenge";
      challenge: string;
      payload: Record<string, unknown>;
    }
  | {
      kind: "event";
      event: FeishuWebhookEvent;
    };

export class FeishuWebhookError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "FeishuWebhookError";
    this.status = status;
    this.code = code;
  }
}

/**
 * Parse a Feishu/Lark HTTP event callback using Fetch/Web Crypto only.
 *
 * Pipeline:
 * 1. read the raw request body with a size limit;
 * 2. when encryptKey is configured, verify x-lark-signature against the raw body;
 * 3. parse JSON and decrypt an `encrypt` envelope with AES-256-CBC when present;
 * 4. verify the Verification Token when configured;
 * 5. return either a URL-verification challenge or a normalized event envelope.
 */
export async function parseFeishuWebhookRequest(
  request: Request,
  config: FeishuWebhookConfig,
): Promise<FeishuWebhookResult> {
  validateConfig(config);

  if (request.method !== "POST") {
    throw new FeishuWebhookError(405, "method_not_allowed", "Feishu webhook requires POST");
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new FeishuWebhookError(415, "invalid_content_type", "Feishu webhook requires JSON");
  }

  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const rawBody = await readBodyLimited(request, maxBodyBytes);

  if (config.encryptKey) {
    await verifySignature({
      headers: request.headers,
      rawBody,
      encryptKey: config.encryptKey,
      maxTimestampSkewSeconds: config.maxTimestampSkewSeconds,
    });
  }

  const wirePayload = parseJsonObject(decoder.decode(rawBody), "invalid_json");
  const payload = await decryptPayloadIfNeeded(wirePayload, config.encryptKey);
  verifyToken(payload, config.verificationToken);

  if (readString(payload, "type") === "url_verification") {
    const challenge = readString(payload, "challenge");
    if (!challenge) {
      throw new FeishuWebhookError(400, "missing_challenge", "Feishu challenge is missing");
    }
    return { kind: "challenge", challenge, payload };
  }

  const eventType = resolveEventType(payload);
  if (!eventType) {
    throw new FeishuWebhookError(400, "missing_event_type", "Feishu event type is missing");
  }

  const header = readObject(payload, "header");
  return {
    kind: "event",
    event: {
      eventType,
      eventId: resolveEventId(payload),
      schema: readString(payload, "schema"),
      createTime: readString(header ?? payload, "create_time"),
      appId: readString(header ?? payload, "app_id"),
      tenantKey:
        readString(header ?? payload, "tenant_key") ??
        readString(readObject(payload, "event") ?? {}, "tenant_key"),
      payload,
    },
  };
}

/** Return the exact HTTP response Feishu expects for URL verification. */
export function createFeishuChallengeResponse(challenge: string): Response {
  return Response.json({ challenge });
}

/** Convert a known adapter error into a small, non-secret-bearing HTTP response. */
export function createFeishuWebhookErrorResponse(error: unknown): Response {
  if (!(error instanceof FeishuWebhookError)) throw error;
  return Response.json(
    { ok: false, error: error.code },
    {
      status: error.status,
      headers: error.status === 405 ? { allow: "POST" } : undefined,
    },
  );
}

async function verifySignature(input: {
  headers: Headers;
  rawBody: Uint8Array;
  encryptKey: string;
  maxTimestampSkewSeconds?: number;
}): Promise<void> {
  const timestamp = input.headers.get("x-lark-request-timestamp") ?? "";
  const nonce = input.headers.get("x-lark-request-nonce") ?? "";
  const actual = (input.headers.get("x-lark-signature") ?? "").toLowerCase();

  if (!timestamp || !nonce || !actual) {
    throw new FeishuWebhookError(401, "missing_signature", "Feishu signature headers are missing");
  }

  if (input.maxTimestampSkewSeconds !== undefined) {
    const timestampSeconds = Number(timestamp);
    if (!Number.isFinite(timestampSeconds)) {
      throw new FeishuWebhookError(401, "invalid_timestamp", "Feishu signature timestamp is invalid");
    }
    const skewSeconds = Math.abs(Date.now() / 1000 - timestampSeconds);
    if (skewSeconds > input.maxTimestampSkewSeconds) {
      throw new FeishuWebhookError(401, "stale_timestamp", "Feishu signature timestamp is outside the allowed window");
    }
  }

  const prefix = encoder.encode(`${timestamp}${nonce}${input.encryptKey}`);
  const signed = concatBytes(prefix, input.rawBody);
  const expected = toHex(
    new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(signed))),
  );

  if (!constantTimeEqual(expected, actual)) {
    throw new FeishuWebhookError(401, "invalid_signature", "Feishu signature is invalid");
  }
}

async function decryptPayloadIfNeeded(
  wirePayload: Record<string, unknown>,
  encryptKey?: string,
): Promise<Record<string, unknown>> {
  const encrypted = readString(wirePayload, "encrypt");
  if (!encrypted) return wirePayload;
  if (!encryptKey) {
    throw new FeishuWebhookError(
      400,
      "missing_encrypt_key",
      "Encrypted Feishu event requires encrypt key",
    );
  }

  let encryptedBytes: Uint8Array;
  try {
    encryptedBytes = decodeBase64(encrypted);
  } catch {
    throw new FeishuWebhookError(
      400,
      "invalid_encrypted_payload",
      "Feishu encrypted body is invalid base64",
    );
  }

  if (encryptedBytes.byteLength <= 16) {
    throw new FeishuWebhookError(
      400,
      "invalid_encrypted_payload",
      "Feishu encrypted body is too short",
    );
  }

  const keyDigest = await crypto.subtle.digest("SHA-256", encoder.encode(encryptKey));
  const key = await crypto.subtle.importKey(
    "raw",
    keyDigest,
    { name: "AES-CBC" },
    false,
    ["decrypt"],
  );
  const iv = encryptedBytes.slice(0, 16);
  const ciphertext = encryptedBytes.slice(16);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: toArrayBuffer(iv) },
      key,
      toArrayBuffer(ciphertext),
    );
  } catch {
    throw new FeishuWebhookError(
      401,
      "decrypt_failed",
      "Feishu encrypted body could not be decrypted",
    );
  }

  return parseJsonObject(decoder.decode(plaintext), "invalid_decrypted_json");
}

function verifyToken(payload: Record<string, unknown>, verificationToken?: string): void {
  if (!verificationToken) return;

  const header = readObject(payload, "header");
  const actual =
    readString(header ?? {}, "token") ??
    readString(payload, "token") ??
    "";

  if (!constantTimeEqual(actual, verificationToken)) {
    throw new FeishuWebhookError(
      401,
      "invalid_verification_token",
      "Feishu verification token is invalid",
    );
  }
}

function resolveEventType(payload: Record<string, unknown>): string | undefined {
  if (readString(payload, "schema")) {
    return readString(readObject(payload, "header") ?? {}, "event_type");
  }
  return readString(readObject(payload, "event") ?? {}, "type");
}

function resolveEventId(payload: Record<string, unknown>): string | undefined {
  const header = readObject(payload, "header");
  return readString(header ?? {}, "event_id") ?? readString(payload, "uuid");
}

async function readBodyLimited(request: Request, maxBytes: number): Promise<Uint8Array> {
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new FeishuWebhookError(413, "body_too_large", "Feishu webhook body is too large");
  }

  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBytes) {
        await reader.cancel("body_too_large");
        throw new FeishuWebhookError(413, "body_too_large", "Feishu webhook body is too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function parseJsonObject(text: string, code: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new FeishuWebhookError(400, code, "Feishu webhook body is not valid JSON");
  }
  if (!isRecord(value)) {
    throw new FeishuWebhookError(400, code, "Feishu webhook body must be a JSON object");
  }
  return value;
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(left.byteLength + right.byteLength);
  bytes.set(left, 0);
  bytes.set(right, left.byteLength);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

function readObject(
  object: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const value = object[key];
  return isRecord(value) ? value : undefined;
}

function readString(object: Record<string, unknown>, key: string): string | undefined {
  const value = object[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateConfig(config: FeishuWebhookConfig): void {
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new TypeError("maxBodyBytes must be a positive safe integer");
  }
  if (
    config.maxTimestampSkewSeconds !== undefined &&
    (!Number.isFinite(config.maxTimestampSkewSeconds) || config.maxTimestampSkewSeconds < 0)
  ) {
    throw new TypeError("maxTimestampSkewSeconds must be a non-negative finite number");
  }
}
