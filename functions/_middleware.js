/**
 * Cloudflare Pages request gate for Log Intelligence Lab.
 * Only explicitly public frontend assets may be served by Pages.
 * /api/* must be handled by the separate Flask backend, NEVER by SPA fallback.
 * No secrets or private source files are bundled into public assets.
 */
const PUBLIC_PATHS = new Set([
  "/", "/index.html", "/soc", "/soc.html",
  "/script.js", "/style.css", "/soc.js", "/soc.css",
  "/favicon.ico", "/robots.txt",
]);

function jsonError(reason, status) {
  return new Response(JSON.stringify({ status: "unavailable", error: reason }), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}

export async function onRequest(context) {
  const req = context.request;
  const incoming = new URL(req.url);
  let pathname;
  try {
    pathname = decodeURIComponent(incoming.pathname);
  } catch (_) {
    return jsonError("Invalid request path", 400);
  }

  // Fail closed. Cloudflare Pages must not publish backend source, test data,
  // CI configs, credentials or runtime databases from the Git repository.
  if (pathname.startsWith("/api/") || pathname === "/api") {
    const configured = context.env.LOG_LAB_BACKEND_ORIGIN;
    if (typeof configured !== "string" || !configured.trim()) {
      return jsonError("Log analysis backend has not been connected to Cloudflare Pages", 503);
    }
    let backend;
    try {
      backend = new URL(configured);
      if (backend.protocol !== "https:" ||
          backend.username || backend.password ||
          backend.search || backend.hash ||
          (backend.pathname !== "/" && backend.pathname !== "") ||
          backend.hostname === incoming.hostname) {
        throw new Error("Unsafe backend origin");
      }
    } catch (_) {
      return jsonError("The configured backend origin is invalid", 503);
    }

    const target = new URL(pathname + incoming.search, backend);
    const headers = new Headers(req.headers);
    headers.delete("host");
    // The client must still authenticate to protected SOC endpoints.
    // API credentials are only forwarded to the explicitly configured backend.
    const outgoing = new Request(target.toString(), {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "manual",
    });
    try {
      const upstream = await fetch(outgoing);
      const proxyHeaders = new Headers(upstream.headers);
      proxyHeaders.set("Cache-Control", "no-store");
      proxyHeaders.set("X-Content-Type-Options", "nosniff");
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: proxyHeaders,
      });
    } catch (_) {
      return jsonError("Backend unreachable", 502);
    }
  }

  if (!PUBLIC_PATHS.has(pathname) || (req.method !== "GET" && req.method !== "HEAD")) {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }
  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
