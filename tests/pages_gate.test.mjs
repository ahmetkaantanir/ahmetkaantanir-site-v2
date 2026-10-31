import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../functions/_middleware.js", import.meta.url), "utf8");
const { onRequest } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

const sample = (pathname, opts = {}) => {
  let passedToAssets = false;
  return {
    context: {
      request: new Request("https://dev.ahmetkaantanir.com" + pathname, opts),
      env: {},
      next: () => {
        passedToAssets = true;
        return new Response("PUBLIC", { status: 200 });
      },
    },
    get assetsReached() { return passedToAssets; },
  };
};

test("Flask Python source and sensitive paths never reach the static asset server", async () => {
  for (const pathname of [
    "/app.py", "/soc_api.py", "/soc_engine.py", "/log_engine.py",
    "/analysis.db", "/.env", "/requirements.txt",
    "/tests/test_soc_platform.py", "/datasets/mixed.log",
    "/functions/_middleware.js",
  ]) {
    const item = sample(pathname);
    const response = await onRequest(item.context);
    assert.equal(response.status, 404, pathname);
    assert.equal(item.assetsReached, false, pathname);
  }
});

test("public SOC interface remains available", async () => {
  for (const path of ["/", "/soc", "/soc.js", "/soc.css", "/style.css", "/script.js"]) {
    const item = sample(path);
    const response = await onRequest(item.context);
    assert.equal(response.status, 200, path);
    assert.equal(item.assetsReached, true, path);
  }
});

test("default backend routes to verified Render API instead of SPA fallback", async () => {
  const item = sample("/api/health");
  const prior = globalThis.fetch;
  globalThis.fetch = async (request) => {
    assert.equal(request.url, "https://ahmetkaantanir-site-v2.onrender.com/api/health");
    return new Response('{"status":"ok"}', {
      status: 200, headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const response = await onRequest(item.context);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    assert.equal(item.assetsReached, false);
  } finally {
    globalThis.fetch = prior;
  }
});

test("insecure and recursive API origin configuration is blocked", async () => {
  for (const origin of [
    "http://example.com", "https://dev.ahmetkaantanir.com",
    "https://example.com/path", "https://u:p@example.com",
  ]) {
    const item = sample("/api/health");
    item.context.env.LOG_LAB_BACKEND_ORIGIN = origin;
    const response = await onRequest(item.context);
    assert.equal(response.status, 503);
  }
});

test("API requests are proxied only to configured trusted HTTPS origin", async () => {
  const item = sample("/api/soc/rules?limit=1", {
    headers: { "X-API-Key": "synthetic-secret" },
  });
  item.context.env.LOG_LAB_BACKEND_ORIGIN = "https://backend.example.net";
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async (request) => {
    assert.equal(request.url, "https://backend.example.net/api/soc/rules?limit=1");
    assert.equal(request.headers.get("X-API-Key"), "synthetic-secret");
    return new Response('{"error":"Unauthorized"}', {
      status: 401, headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const response = await onRequest(item.context);
    assert.equal(response.status, 401);
    assert.match(response.headers.get("cache-control"), /no-store/);
    assert.deepEqual(await response.json(), { error: "Unauthorized" });
  } finally {
    globalThis.fetch = savedFetch;
  }
});

test("unexpected public write requests are blocked", async () => {
  const item = sample("/", { method: "POST" });
  const response = await onRequest(item.context);
  assert.equal(response.status, 404);
});
