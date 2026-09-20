import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import test from "node:test";
import worker from "../src/index.js";

function db() {
  const stores = new Map();
  const events = new Map();
  return {
    stores,
    events,
    prepare(sql) {
      let args;
      return {
        bind(...values) {
          args = values;
          return this;
        },
        async first() {
          return stores.has(args[0]) ? { store_id: args[0] } : null;
        },
        async run() {
          if (sql.startsWith("INSERT INTO stores")) stores.set(args[0], args);
          if (sql.startsWith("INSERT INTO order_events")) {
            const key = args.slice(0, 3).join(":");
            events.set(key, (events.get(key) || 0) + 1);
          }
        },
      };
    },
  };
}

const base = "https://example.workers.dev";

test("health and install redirect", async () => {
  const health = await worker.fetch(new Request(`${base}/health`), {});
  assert.deepEqual(await health.json(), { status: "ok", service: "nuvemshop-tracking" });
  const start = await worker.fetch(new Request(`${base}/nuvemshop/install`), { APP_ID: "42904" });
  assert.equal(start.status, 302);
  const redirect = new URL(start.headers.get("Location"));
  assert.equal(redirect.pathname, "/apps/42904/authorize");
  assert.equal(redirect.searchParams.get("state"), start.headers.get("Set-Cookie").match(/nuvemshop_oauth_state=([^;]+)/)[1]);
});

test("callback rejects missing state before token exchange", async () => {
  const response = await worker.fetch(new Request(`${base}/nuvemshop/oauth/callback?code=test`), {});
  assert.equal(response.status, 400);
});

test("callback stores encrypted token", async () => {
  const database = db();
  const encryptionKey = randomBytes(32).toString("base64");
  const env = { APP_ID: "42904", CLIENT_SECRET: "test-secret", TOKEN_ENCRYPTION_KEY: encryptionKey, DB: database };
  const start = await worker.fetch(new Request(`${base}/nuvemshop/install`), env);
  const state = new URL(start.headers.get("Location")).searchParams.get("state");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ access_token: "token-value", user_id: 123, scope: "read_orders" });
  try {
    const callback = await worker.fetch(new Request(`${base}/nuvemshop/oauth/callback?code=abc&state=${state}`, {
      headers: { Cookie: `nuvemshop_oauth_state=${state}` },
    }), env);
    assert.equal(callback.status, 200);
    assert.equal(database.stores.size, 1);
    assert.equal(database.stores.get("123")[0], "123");
    assert.notEqual(database.stores.get("123")[2], "token-value");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("webhook verifies signature and records repeated delivery once per order event", async () => {
  const database = db();
  database.stores.set("123", ["123"]);
  const env = { CLIENT_SECRET: "test-secret", DB: database };
  const body = JSON.stringify({ store_id: 123, id: 456, event: "order/paid" });
  const url = `${base}/nuvemshop/webhook`;
  const unauthorized = await worker.fetch(new Request(url, { method: "POST", body }), env);
  assert.equal(unauthorized.status, 401);
  const signature = createHmac("sha256", env.CLIENT_SECRET).update(body).digest("hex");
  for (let i = 0; i < 2; i += 1) {
    const response = await worker.fetch(new Request(url, {
      method: "POST", body,
      headers: { "x-linkedstore-hmac-sha256": signature },
    }), env);
    assert.equal(response.status, 200);
  }
  assert.equal(database.events.size, 1);
  assert.equal(database.events.get("123:456:order/paid"), 2);
});

