const encoder = new TextEncoder();
const decoder = new TextDecoder();
const stateCookie = "nuvemshop_oauth_state";
const callbackPath = "/nuvemshop/oauth/callback";

function json(body, status = 200) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex || "")) return null;
  return Uint8Array.from(hex.match(/.{2}/g), (part) => Number.parseInt(part, 16));
}

function base64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function keyBytes(value) {
  try {
    const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

async function encryptToken(token, keyValue) {
  const bytes = keyBytes(keyValue);
  if (!bytes) throw new Error("TOKEN_ENCRYPTION_KEY must be 32 base64-encoded bytes");
  const key = await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(token));
  return { iv: base64(iv), ciphertext: base64(new Uint8Array(encrypted)) };
}

async function verifyWebhook(body, signature, secret) {
  const expected = hexToBytes(signature);
  if (!expected || !secret) return false;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", key, expected, body);
}

function cookieValue(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const pair = cookies.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return pair?.slice(name.length + 1) || null;
}

function installedResponse(message, status = 200) {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Set-Cookie": `${stateCookie}=; Path=${callbackPath}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`,
    },
  });
}

async function startInstall(env) {
  if (!env.APP_ID) return json({ error: "App ID is not configured" }, 503);
  const state = base64(crypto.getRandomValues(new Uint8Array(24))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const url = new URL(`https://www.nuvemshop.com.br/apps/${env.APP_ID}/authorize`);
  url.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: {
      Location: url.toString(),
      "Cache-Control": "no-store",
      "Set-Cookie": `${stateCookie}=${state}; Path=${callbackPath}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`,
    },
  });
}

async function finishInstall(request, env) {
  const url = new URL(request.url);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (!state || !code || state !== cookieValue(request, stateCookie)) {
    return installedResponse("Instalacao invalida ou expirada. Inicie novamente pelo app.", 400);
  }
  if (!env.APP_ID || !env.CLIENT_SECRET || !env.TOKEN_ENCRYPTION_KEY || !env.DB) {
    return installedResponse("Integracao ainda nao configurada no servidor.", 503);
  }
  try {
    const response = await fetch("https://www.nuvemshop.com.br/apps/authorize/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: env.APP_ID,
        client_secret: env.CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
      }),
    });
    if (!response.ok) return installedResponse("Falha ao autorizar a loja. Tente instalar novamente.", 502);
    const data = await response.json();
    const storeId = String(data.user_id || data.store_id || "");
    if (!/^\d+$/.test(storeId) || !data.access_token || !String(data.scope || "").split(",").includes("read_orders")) {
      return installedResponse("A autorizacao nao incluiu acesso de leitura aos pedidos.", 400);
    }
    const encrypted = await encryptToken(data.access_token, env.TOKEN_ENCRYPTION_KEY);
    await env.DB.prepare(
      "INSERT INTO stores (store_id, token_iv, token_ciphertext, scopes, installed_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(store_id) DO UPDATE SET token_iv = excluded.token_iv, token_ciphertext = excluded.token_ciphertext, scopes = excluded.scopes, installed_at = excluded.installed_at"
    ).bind(storeId, encrypted.iv, encrypted.ciphertext, data.scope, new Date().toISOString()).run();
    return installedResponse("Loja autorizada. A integracao sera concluida apos a configuracao dos webhooks.");
  } catch {
    return installedResponse("Falha ao concluir a instalacao. Tente novamente.", 502);
  }
}

async function receiveWebhook(request, env) {
  if (!env.CLIENT_SECRET || !env.DB) return json({ error: "Server not configured" }, 503);
  const body = await request.arrayBuffer();
  if (body.byteLength > 64 * 1024) return json({ error: "Payload too large" }, 413);
  const valid = await verifyWebhook(body, request.headers.get("x-linkedstore-hmac-sha256"), env.CLIENT_SECRET);
  if (!valid) return json({ error: "Invalid signature" }, 401);
  let event;
  try {
    event = JSON.parse(decoder.decode(body));
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }
  const storeId = String(event.store_id || "");
  const orderId = String(event.id || "");
  if (!/^\d+$/.test(storeId) || !/^\d+$/.test(orderId) || !["order/created", "order/paid"].includes(event.event)) {
    return json({ error: "Unsupported event" }, 400);
  }
  try {
    const store = await env.DB.prepare("SELECT store_id FROM stores WHERE store_id = ?").bind(storeId).first();
    if (!store) return json({ error: "Unknown store" }, 403);
    const now = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO order_events (store_id, order_id, event, first_seen_at, last_seen_at, deliveries) VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(store_id, order_id, event) DO UPDATE SET last_seen_at = excluded.last_seen_at, deliveries = order_events.deliveries + 1"
    ).bind(storeId, orderId, event.event, now, now).run();
    return json({ received: true });
  } catch {
    return json({ error: "Could not persist event" }, 503);
  }
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (request.method === "GET" && pathname === "/health") {
      return json({ status: "ok", service: "nuvemshop-tracking" });
    }
    if (request.method === "GET" && pathname === "/nuvemshop/install") return startInstall(env);
    if (request.method === "GET" && pathname === callbackPath) return finishInstall(request, env);
    if (request.method === "POST" && pathname === "/nuvemshop/webhook") return receiveWebhook(request, env);
    return json({ error: "Not found" }, 404);
  },
};

