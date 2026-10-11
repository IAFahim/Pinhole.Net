import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import gateway, { PairRoom, PairBudget } from "../src/index.js";

const code = "ABCDEFGHJ";
const invitation = "pinhole1:" + "A".repeat(80);
const otherInvitation = "pinhole1:" + "B".repeat(80);
const secret = () => randomBytes(32).toString("base64url");
function context() {
  const values = new Map();
  let tail = Promise.resolve();
  return {
    storage: {
      async get(key) { return values.has(key) ? structuredClone(values.get(key)) : undefined; },
      async put(key, value) { values.set(key, structuredClone(value)); },
      async deleteAll() { values.clear(); },
      async setAlarm(time) { this.alarm = time; },
      async deleteAlarm() { delete this.alarm; }
    },
    blockConcurrencyWhile(fn) { const result = tail.then(fn); tail = result.catch(() => {}); return result; },
    getWebSockets() { return []; }
  };
}
function setup(extra = {}) {
  const ctx = context();
  const env = { TURN_REQUIRED: "false", ...extra };
  return { ctx, env, room: new PairRoom(ctx, env), host: secret(), join: secret() };
}
function request(method, token, suffix = "", data) {
  return new Request(`https://worker/v1/rooms/${code}${suffix}`, {
    method, headers: token ? { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } : {},
    body: data === undefined ? undefined : JSON.stringify(data)
  });
}
async function hostReady(s) {
  assert.equal((await s.room.fetch(request("PUT", s.host, "", {}))).status, 201);
  assert.equal((await s.room.fetch(request("PUT", s.host, "/ticket", { invitation }))).status, 200);
}

test("unauthenticated callers cannot create a room", async () => {
  const s = setup();
  assert.equal((await s.room.fetch(request("PUT", null, "", {}))).status, 401);
  assert.equal(await s.ctx.storage.get("room"), undefined);
});
test("both peers exchange metadata without exposing either management token", async () => {
  const s = setup();
  await hostReady(s);
  const claim = await s.room.fetch(request("POST", s.join, "/join", {}));
  assert.equal(claim.status, 200);
  assert.equal((await claim.json()).peerInvitation, invitation);
  const posted = await s.room.fetch(request("PUT", s.join, "/ticket", { invitation: otherInvitation }));
  assert.equal((await posted.json()).peerInvitation, invitation);
  const text = await (await s.room.fetch(request("GET", s.host))).text();
  assert.equal(JSON.parse(text).peerInvitation, otherInvitation);
  assert.ok(!text.includes(s.host) && !text.includes(s.join));
  const stored = await s.ctx.storage.get("room");
  assert.notEqual(stored.host, s.host);
  assert.notEqual(stored.join, s.join);
});
test("two concurrent joiners cannot both claim a room", async () => {
  const s = setup();
  await hostReady(s);
  const answers = await Promise.all([s.join, secret()].map(token => s.room.fetch(request("POST", token, "/join", {}))));
  assert.deepEqual(answers.map(answer => answer.status).sort(), [200, 409]);
});
test("claims are idempotent but the code admits no third participant", async () => {
  const s = setup();
  await hostReady(s);
  for (let i = 0; i < 2; i++) assert.equal((await s.room.fetch(request("POST", s.join, "/join", {}))).status, 200);
  assert.equal((await s.room.fetch(request("POST", secret(), "/join", {}))).status, 409);
  assert.equal((await s.room.fetch(request("POST", s.host, "/join", {}))).status, 409);
});
test("a stranger cannot read, overwrite or delete a registration", async () => {
  const s = setup();
  await hostReady(s);
  const stranger = secret();
  for (const [method, suffix, data] of [["GET", ""], ["DELETE", ""], ["PUT", "/ticket", { invitation: otherInvitation }]])
    assert.equal((await s.room.fetch(request(method, stranger, suffix, data))).status, 401);
  assert.equal((await s.room.fetch(request("PUT", stranger, "", {}))).status, 409);
  assert.equal((await s.ctx.storage.get("room")).hostInvitation, invitation);
});
test("deleting and expiring a room remove its credentials and invitations", async () => {
  const s = setup();
  await hostReady(s);
  assert.equal((await s.room.fetch(request("DELETE", s.host))).status, 204);
  assert.equal(await s.ctx.storage.get("room"), undefined);
  await hostReady(s);
  const stored = await s.ctx.storage.get("room");
  stored.expiresAt = Date.now() - 1;
  await s.ctx.storage.put("room", stored);
  await s.room.alarm();
  assert.equal((await s.room.fetch(request("POST", s.join, "/join", {}))).status, 404);
});
test("oversized and invalid metadata is rejected without changing the invitation", async () => {
  const s = setup();
  await hostReady(s);
  assert.equal((await s.room.fetch(request("PUT", s.host, "/ticket", { invitation: "x".repeat(9000) }))).status, 413);
  assert.equal((await s.room.fetch(request("PUT", s.host, "/ticket", { invitation: "invalid" }))).status, 400);
  assert.equal((await s.ctx.storage.get("room")).hostInvitation, invitation);
});
test("missing required TURN secrets fail closed with a sanitized error", async () => {
  const s = setup({ TURN_REQUIRED: "true" });
  const answer = await s.room.fetch(request("PUT", s.host, "", {}));
  assert.equal(answer.status, 503);
  assert.deepEqual(await answer.json(), { error: "turn_not_configured" });
  assert.equal(await s.ctx.storage.get("room"), undefined);
});
test("daily request and room budgets stop additional work", async () => {
  const budget = new PairBudget(context(), { DAILY_REQUEST_LIMIT: "2", DAILY_ROOM_LIMIT: "1" });
  const consume = createsRoom => budget.fetch(new Request("https://budget/consume", { method: "POST", body: JSON.stringify({ createsRoom }) }));
  assert.equal((await consume(true)).status, 200);
  assert.equal((await consume(true)).status, 429);
  assert.equal((await consume(false)).status, 200);
  assert.equal((await consume(false)).status, 429);
});
test("wrong-method paths cannot bypass the room-creation budget", async () => {
  let touched = false;
  const env = { IP_LIMIT: { limit() { touched = true; } } };
  const answer = await gateway.fetch(request("PUT", secret(), "/join", {}), env);
  assert.equal(answer.status, 405);
  assert.equal(touched, false);
});

test("TURN credentials are issued separately and cached across retries and polling", async t => {
  let issued = 0;
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.ok(url.startsWith("https://rtc.live.cloudflare.com/v1/turn/keys/"));
    assert.equal(options.redirect, "manual");
    assert.equal(JSON.parse(options.body).ttl, 86400);
    issued++;
    return Response.json({ iceServers: [
      { urls: ["stun:stun.cloudflare.com:3478"] },
      { urls: ["turn:turn.cloudflare.com:3478?transport=udp"], username: `user${issued}`, credential: `password${issued}` }
    ] }, { status: 201 });
  });
  const s = setup({ TURN_KEY_ID: "a".repeat(32), TURN_KEY_API_TOKEN: "test-api-token" });
  await hostReady(s);
  const retried = await s.room.fetch(request("PUT", s.host, "", {}));
  assert.equal((await retried.json()).iceServers[1].username, "user1");
  for (let i = 0; i < 2; i++) {
    const claimed = await s.room.fetch(request("POST", s.join, "/join", {}));
    assert.equal((await claimed.json()).iceServers[1].username, "user2");
  }
  const poll = await (await s.room.fetch(request("GET", s.host))).text();
  assert.ok(!poll.includes("password") && !poll.includes("test-api-token"));
  assert.equal(issued, 2);
});

test("upstream failures and malformed credentials stay private and leave no room", async t => {
  const s = setup({ TURN_KEY_ID: "a".repeat(32), TURN_KEY_API_TOKEN: "test-api-token" });
  t.mock.method(globalThis, "fetch", async () => new Response("private upstream failure", { status: 403 }));
  let answer = await s.room.fetch(request("PUT", s.host, "", {}));
  assert.deepEqual(await answer.json(), { error: "turn_unavailable" });
  t.mock.method(globalThis, "fetch", async () => Response.json({ iceServers: [null] }));
  answer = await s.room.fetch(request("PUT", s.host, "", {}));
  assert.deepEqual(await answer.json(), { error: "turn_unavailable" });
  assert.equal(await s.ctx.storage.get("room"), undefined);
});

test("upstream redirects are rejected before issuing credentials", async t => {
  t.mock.method(globalThis, "fetch", async (_url, options) => {
    assert.equal(options.redirect, "manual");
    return new Response(null, { status: 302, headers: { Location: "https://other.example/" } });
  });
  const s = setup({ TURN_KEY_ID: "a".repeat(32), TURN_KEY_API_TOKEN: "test-api-token" });
  const answer = await s.room.fetch(request("PUT", s.host, "", {}));
  assert.deepEqual(await answer.json(), { error: "turn_unavailable" });
  assert.equal(await s.ctx.storage.get("room"), undefined);
});
