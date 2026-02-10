/**
 * ClawBuddy Mailbox — Cloudflare Worker with KV-backed message storage.
 *
 * Routes:
 *   PUT    /channel/:id/handshake        — post responder public key
 *   GET    /channel/:id/handshake        — poll for handshake completion
 *   POST   /channel/:id/messages         — post encrypted message blob
 *   GET    /channel/:id/messages         — poll for messages
 *   DELETE /channel/:id/messages/:seq    — ack/delete a message
 */

const HANDSHAKE_TTL = 60 * 60 * 24 * 7; // 7 days
const MESSAGE_TTL = 60 * 60 * 24 * 30; // 30 days

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    // parts: ["channel", id, "handshake"|"messages", maybe seq]

    if (parts[0] !== "channel" || !parts[1]) {
      return json({ error: "not found" }, 404);
    }

    const channelId = parts[1];
    const resource = parts[2];
    const method = request.method;

    // --- Handshake ---
    if (resource === "handshake") {
      const key = `handshake:${channelId}`;

      if (method === "PUT") {
        const body = await request.json();
        if (!body.public_key) {
          return json({ error: "missing public_key" }, 400);
        }
        await env.MAILBOX.put(key, JSON.stringify(body), {
          expirationTtl: HANDSHAKE_TTL,
        });
        return json({ ok: true });
      }

      if (method === "GET") {
        const val = await env.MAILBOX.get(key);
        if (!val) return json({ error: "not found" }, 404);
        return json(JSON.parse(val));
      }

      return json({ error: "method not allowed" }, 405);
    }

    // --- Messages ---
    if (resource === "messages") {
      const seqParam = parts[3];
      const indexKey = `messages:${channelId}:index`;

      if (method === "POST" && !seqParam) {
        const body = await request.json();
        if (!body.payload) {
          return json({ error: "missing payload" }, 400);
        }

        // Atomic seq increment via index
        const raw = await env.MAILBOX.get(indexKey);
        const index = raw ? JSON.parse(raw) : { next_seq: 1, seqs: [] };
        const seq = index.next_seq;
        index.next_seq = seq + 1;
        index.seqs.push(seq);

        const msgKey = `messages:${channelId}:${seq}`;
        await env.MAILBOX.put(
          msgKey,
          JSON.stringify({ channel_id: channelId, seq, payload: body.payload }),
          { expirationTtl: MESSAGE_TTL }
        );
        await env.MAILBOX.put(indexKey, JSON.stringify(index), {
          expirationTtl: MESSAGE_TTL,
        });

        return json({ ok: true, seq });
      }

      if (method === "GET" && !seqParam) {
        const raw = await env.MAILBOX.get(indexKey);
        if (!raw) return json([]);
        const index = JSON.parse(raw);
        const messages = [];
        for (const seq of index.seqs) {
          const val = await env.MAILBOX.get(`messages:${channelId}:${seq}`);
          if (val) messages.push(JSON.parse(val));
        }
        return json(messages);
      }

      if (method === "DELETE" && seqParam) {
        const seq = parseInt(seqParam, 10);
        await env.MAILBOX.delete(`messages:${channelId}:${seq}`);

        // Remove from index
        const raw = await env.MAILBOX.get(indexKey);
        if (raw) {
          const index = JSON.parse(raw);
          index.seqs = index.seqs.filter((s) => s !== seq);
          await env.MAILBOX.put(indexKey, JSON.stringify(index), {
            expirationTtl: MESSAGE_TTL,
          });
        }

        return json({ ok: true });
      }

      return json({ error: "method not allowed" }, 405);
    }

    return json({ error: "not found" }, 404);
  },
};
