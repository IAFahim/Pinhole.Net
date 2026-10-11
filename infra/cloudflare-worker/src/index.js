// One host, one joiner. Credentials are issued only after an authenticated room
// claim; no public TURN-credential endpoint and no application-payload forwarding.
const CODE = /^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{9}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const MAX_BODY = 8192;

export class ApiError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function json(value, status = 200) {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}
function failure(error) {
  if (!(error instanceof ApiError)) {
    // Stack locations aid diagnosis; messages can contain upstream data or secrets.
    const locations = String(error?.stack ?? "").split("\n").slice(1, 4).join("\n");
    console.error("coordinator_exception", error?.name ?? "Error", locations);
  }
  return json({ error: error instanceof ApiError ? error.code : "service_unavailable" },
    error instanceof ApiError ? error.status : 503);
}
function setting(env, key, fallback, maximum) {
  const value = Number(env[key] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > maximum) throw new ApiError(503, "invalid_configuration");
  return value;
}
function bearer(request) {
  const value = request.headers.get("Authorization") ?? "";
  if (!value.startsWith("Bearer ") || !TOKEN.test(value.slice(7))) throw new ApiError(401, "unauthorized");
  return value.slice(7);
}
async function digest(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
}
function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
async function body(request) {
  if (!request.body) return {};
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY) { await reader.cancel(); throw new ApiError(413, "body_too_large"); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error();
    return parsed;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(400, "invalid_json");
  } finally { reader.releaseLock(); }
}

async function credentials(env) {
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) {
    if (env.TURN_REQUIRED === "false") return { iceServers: [], credentialExpiresAt: null };
    throw new ApiError(503, "turn_not_configured");
  }
  if (!/^[a-f0-9]{32}$/i.test(env.TURN_KEY_ID)) throw new ApiError(503, "turn_not_configured");
  const ttl = setting(env, "TURN_TTL_SECONDS", 86400, 86400);
  let response;
  try { response = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`, {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(8000),
    headers: { "Authorization": `Bearer ${env.TURN_KEY_API_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ ttl })
  }); } catch (error) {
    console.error("turn_request_exception", error?.name ?? "Error");
    throw new ApiError(503, error?.name === "TimeoutError" || error?.name === "AbortError" ? "turn_request_timeout" : "turn_request_failed");
  }
  if (!response.ok) throw new ApiError(503, "turn_unavailable");
  let data;
  try { data = await body(response); } catch { throw new ApiError(503, "turn_unavailable"); }
  if (!Array.isArray(data.iceServers) || data.iceServers.length > 8) throw new ApiError(503, "turn_unavailable");
  const servers = data.iceServers.map(server => {
    const urls = typeof server?.urls === "string" ? [server.urls] : server?.urls;
    if (!Array.isArray(urls) || urls.length > 16 || urls.some(url => typeof url !== "string" || url.length > 1024))
      throw new ApiError(503, "turn_unavailable");
    return { urls, ...(typeof server.username === "string" && typeof server.credential === "string"
      ? { username: server.username, credential: server.credential } : {}) };
  });
  if (!servers.some(server => Array.isArray(server.urls) && server.urls.some(url =>
    /^turn:turn\.cloudflare\.com:(3478|443)\?transport=udp$/i.test(url))
    && typeof server.username === "string" && typeof server.credential === "string"))
    throw new ApiError(503, "turn_unavailable");
  return { iceServers: servers, credentialExpiresAt: Math.floor(Date.now() / 1000) + ttl };
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/health" && request.method === "GET")
        return json({ service: "pinhole-coordinator", version: 1, turnConfigured: Boolean(env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) });
      const match = /^\/v1\/rooms\/([0123456789ABCDEFGHJKMNPQRSTVWXYZ]{9})(?:\/(join|ticket|events))?$/.exec(url.pathname);
      if (!match || !CODE.test(match[1])) throw new ApiError(404, "not_found");
      const action = match[2] ?? "";
      const allowed = action === "" ? ["GET", "PUT", "DELETE"]
        : action === "join" ? ["POST"] : action === "ticket" ? ["PUT"] : ["GET"];
      if (!allowed.includes(request.method)) throw new ApiError(405, "method_not_allowed");
      bearer(request);
      const ip = request.headers.get("CF-Connecting-IP") ?? "local";
      if (!(await env.IP_LIMIT.limit({ key: ip })).success) throw new ApiError(429, "rate_limited");
      const createsRoom = request.method === "PUT" && !match[2];
      const budget = await env.BUDGET.getByName("daily").fetch(new Request("https://budget/consume", {
        method: "POST", body: JSON.stringify({ createsRoom })
      }));
      if (!budget.ok) return budget;
      return await env.ROOMS.getByName(match[1]).fetch(request);
    } catch (error) { return failure(error); }
  }
};

export class PairBudget {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
  fetch(request) {
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        const input = await body(request);
        const day = Math.floor(Date.now() / 86400000);
        let count = await this.ctx.storage.get("count");
        if (!count || count.day !== day) count = { day, requests: 0, rooms: 0 };
        if (count.requests >= setting(this.env, "DAILY_REQUEST_LIMIT", 40000, 40000)
          || input.createsRoom && count.rooms >= setting(this.env, "DAILY_ROOM_LIMIT", 200, 200))
          throw new ApiError(429, "daily_budget_exhausted");
        count.requests++;
        if (input.createsRoom) count.rooms++;
        await this.ctx.storage.put("count", count);
        return json({ ok: true });
      } catch (error) { return failure(error); }
    });
  }
}

export class PairRoom {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
  fetch(request) {
    return this.ctx.blockConcurrencyWhile(async () => {
      try { return await this.handle(request); }
      catch (error) { return failure(error); }
    });
  }
  async handle(request) {
    const url = new URL(request.url);
    const route = /^\/v1\/rooms\/[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{9}(?:\/(join|ticket|events))?$/.exec(url.pathname);
    if (!route) throw new ApiError(404, "not_found");
    const action = route[1] ?? "";
    const token = await digest(bearer(request));
    let room = await this.ctx.storage.get("room");
    if (room && room.expiresAt <= Date.now()) { await this.expire(); room = null; }
    const create = request.method === "PUT" && action === "";
    if (create) {
      await body(request);
      if (room && !equal(room.host, token)) throw new ApiError(409, "code_in_use");
      if (!room) room = { host: token, join: null, hostInvitation: null, joinInvitation: null,
        hostCredentials: null, joinCredentials: null, born: Date.now(), expiresAt: 0 };
      room.hostCredentials ??= await credentials(this.env);
      room.expiresAt = Math.min(Date.now() + setting(this.env, "ROOM_TTL_SECONDS", 300, 3600) * 1000, room.born + 86400000);
      await this.save(room);
      return json({ version: 1, ...room.hostCredentials, peerInvitation: room.joinInvitation, expiresAt: room.expiresAt }, 201);
    }
    if (!room) throw new ApiError(404, "code_expired");
    if (request.method === "POST" && action === "join") {
      await body(request);
      if (equal(room.host, token)) throw new ApiError(409, "self_join");
      if (room.join && !equal(room.join, token)) throw new ApiError(409, "room_full");
      if (!room.hostInvitation) throw new ApiError(425, "host_starting");
      room.joinCredentials ??= await credentials(this.env);
      room.join = token;
      await this.save(room);
      return json({ version: 1, ...room.joinCredentials, peerInvitation: room.hostInvitation, expiresAt: room.expiresAt });
    }
    const role = equal(room.host, token) ? "host" : equal(room.join, token) ? "join" : null;
    if (!role) throw new ApiError(401, "unauthorized");
    const peer = role === "host" ? "joinInvitation" : "hostInvitation";
    if (request.method === "PUT" && action === "ticket") {
      const input = await body(request);
      if (typeof input.invitation !== "string" || input.invitation.length > 4096
        || !/^pinhole1:[A-Za-z0-9_-]{32,}$/.test(input.invitation)) throw new ApiError(400, "invalid_invitation");
      room[role === "host" ? "hostInvitation" : "joinInvitation"] = input.invitation;
      if (role === "host" && !room.joinInvitation)
        room.expiresAt = Math.min(Date.now() + setting(this.env, "ROOM_TTL_SECONDS", 300, 3600) * 1000, room.born + 86400000);
      await this.save(room);
      this.notify(role === "host" ? "join" : "host", input.invitation);
      return json({ version: 1, peerInvitation: room[peer], expiresAt: room.expiresAt });
    }
    if (request.method === "DELETE" && action === "") {
      await this.expire(); return new Response(null, { status: 204 });
    }
    if (request.method === "GET" && action === "events") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") throw new ApiError(400, "websocket_required");
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      for (const old of this.ctx.getWebSockets(role)) { try { old.close(1000, "replaced"); } catch {} }
      this.ctx.acceptWebSocket(server, [role]);
      if (room[peer]) server.send(JSON.stringify({ version: 1, peerInvitation: room[peer] }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (request.method === "GET" && action === "")
      return json({ version: 1, peerInvitation: room[peer], expiresAt: room.expiresAt });
    throw new ApiError(405, "method_not_allowed");
  }
  async save(room) { await this.ctx.storage.put("room", room); await this.ctx.storage.setAlarm(room.expiresAt); }
  notify(role, invitation) {
    for (const socket of this.ctx.getWebSockets(role)) {
      try { socket.send(JSON.stringify({ version: 1, peerInvitation: invitation })); }
      catch { socket.close(1011, "signaling_failed"); }
    }
  }
  async expire() {
    for (const socket of this.ctx.getWebSockets()) { try { socket.close(1000, "room_closed"); } catch {} }
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }
  async alarm() {
    const room = await this.ctx.storage.get("room");
    if (!room || room.expiresAt <= Date.now()) await this.expire();
    else await this.ctx.storage.setAlarm(room.expiresAt);
  }
  webSocketMessage(socket) { socket.close(1008, "http_metadata_only"); }
  webSocketClose(socket, code) { try { socket.close(code, ""); } catch {} }
  webSocketError(socket) { try { socket.close(1011, "signaling_failed"); } catch {} }
}
