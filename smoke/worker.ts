// Build-only Worker proving the adapter needs no Node compatibility layer.

import {
  createFeishuChallengeResponse,
  createFeishuWebhookErrorResponse,
  parseFeishuWebhookRequest,
} from "../src/index.js";

interface Env {
  FEISHU_VERIFICATION_TOKEN?: string;
  FEISHU_ENCRYPT_KEY?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ ok: true });
    }
    if (request.method !== "POST" || url.pathname !== "/feishu/events") {
      return new Response("Not found", { status: 404 });
    }

    try {
      const result = await parseFeishuWebhookRequest(request, {
        verificationToken: env.FEISHU_VERIFICATION_TOKEN,
        encryptKey: env.FEISHU_ENCRYPT_KEY,
      });
      if (result.kind === "challenge") {
        return createFeishuChallengeResponse(result.challenge);
      }
      return Response.json({
        ok: true,
        eventType: result.event.eventType,
        eventId: result.event.eventId ?? null,
      });
    } catch (error) {
      return createFeishuWebhookErrorResponse(error);
    }
  },
} satisfies ExportedHandler<Env>;
