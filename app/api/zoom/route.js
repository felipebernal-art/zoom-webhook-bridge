import crypto from "crypto";

function hmacHex(secret, msg) {
  return crypto.createHmac("sha256", secret).update(msg, "utf8").digest("hex");
}

function isTimestampFresh(ts) {
  const n = Number(ts);
  if (!Number.isFinite(n)) return false;
  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - n) <= 300; // 5 minutos
}

export async function POST(req) {
  const ZOOM_WEBHOOK_SECRET = (process.env.ZOOM_WEBHOOK_SECRET || "").trim();
  const GAS_URL = (process.env.GAS_URL || "").trim();

  const rawBody = await req.text();

  let data = {};
  try {
    data = rawBody ? JSON.parse(rawBody) : {};
  } catch {
    return new Response(JSON.stringify({ ok: false, error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  // 1) Validación de URL (Zoom)
  if (data?.event === "endpoint.url_validation") {
    const plainToken = data?.payload?.plainToken;
    if (!plainToken || !ZOOM_WEBHOOK_SECRET) {
      return new Response(JSON.stringify({ ok: false, error: "Missing plainToken/secret" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    const encryptedToken = hmacHex(ZOOM_WEBHOOK_SECRET, plainToken);
    return new Response(JSON.stringify({ plainToken, encryptedToken }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  // 2) Verificación de firma (recomendado)
  const ts = req.headers.get("x-zm-request-timestamp") || "";
  const sig = req.headers.get("x-zm-signature") || "";

  if (ZOOM_WEBHOOK_SECRET && sig.startsWith("v0=") && ts) {
    if (!isTimestampFresh(ts)) {
      return new Response(JSON.stringify({ ok: false, error: "Stale timestamp" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const message = `v0:${ts}:${rawBody}`;
    const expected = "v0=" + hmacHex(ZOOM_WEBHOOK_SECRET, message);
    if (expected !== sig) {
      return new Response(JSON.stringify({ ok: false, error: "Bad signature" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  // 3) Reenviar a Apps Script
  if (!GAS_URL) {
    return new Response(JSON.stringify({ ok: false, error: "Missing GAS_URL" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }

  const r = await fetch(GAS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: rawBody
  });

  return new Response(JSON.stringify({ ok: true, forwardedStatus: r.status }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

export async function GET() {
  return new Response("ok", { status: 200 });
}
