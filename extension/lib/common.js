/* Cyber Solutions Link Check: shared, side-effect-free logic.

   Loaded as a classic script by the service worker (importScripts) and by every extension page, and with require() by
   the Node tests in extension/tests. Nothing here touches the DOM or chrome.* APIs, so it can be tested on its own.

   Safety rules this file enforces (each has a test):
   - only http(s) links are ever sent anywhere, and the #fragment never is
   - the server address must be https, or http on this machine, and carries no path or credentials
   - requests send no cookies, no referrer, and never follow a redirect
   - a server answer is trusted only if it has a known verdict; anything else is an error, never "safe"
   - text that came from the server is clamped and is only ever shown as plain text, never parsed as markup */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.CSX = api;
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  const DEFAULT_BACKEND = "http://127.0.0.1:5000";
  const MAX_URL_LENGTH = 2048;        // the same limit the server applies
  const CHECK_TIMEOUT_MS = 15000;     // the server's own lookup deadline is 10 s by default
  const TOKEN_RE = /^[0-9a-f]{32}$/;
  const VERDICT_CODES = ["malicious", "suspicious", "no_known_threat", "unable_to_verify"];
  const SEVERITIES = ["high", "medium", "low", "info"];
  const SOURCE_STATUSES = ["hit", "clear", "skipped", "error"];
  const LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]"];
  const DEFAULT_SETTINGS = Object.freeze({ backend: DEFAULT_BACKEND, stripQuery: false });

  /* ---------- text from outside is clamped before it is shown ---------- */
  // Control characters and bidirectional overrides can make text read differently from what it is.
  const UNSAFE_CHARS = /[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
  function clamp(value, max) {
    const text = String(value == null ? "" : value).replace(UNSAFE_CHARS, " ").trim();
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  /* ---------- links ---------- */
  // What a person sees of a link: scheme, host and path only. Query strings and fragments often carry tokens.
  function displayUrl(u) {
    return clamp(u.protocol + "//" + u.host + u.pathname, 200);
  }

  /* Turn whatever the browser handed over into the address that will be sent, or say why it can't be.
     Only web links qualify: javascript:, data:, file:, chrome:, mailto: and friends are refused here, before any request. */
  function prepareLink(raw, options) {
    const stripQuery = !!(options && options.stripQuery);
    const fail = (reason) => ({ ok: false, reason });
    if (typeof raw !== "string" || !raw.trim()) return fail("empty");
    let u;
    try { u = new URL(raw.trim()); } catch (e) { return fail("invalid"); }
    if (u.protocol !== "http:" && u.protocol !== "https:") return fail("not_web_link");
    u.hash = "";                      // a fragment never leaves the browser, with or without the option
    if (stripQuery) u.search = "";
    const url = u.href;
    if (url.length > MAX_URL_LENGTH) return fail("too_long");
    return { ok: true, url, display: displayUrl(u) };
  }

  // The last check before the browser is asked to open something.
  function isWebUrl(raw) {
    try {
      const u = new URL(String(raw));
      return u.protocol === "http:" || u.protocol === "https:";
    } catch (e) { return false; }
  }

  /* ---------- the server this extension talks to ---------- */
  function normalizeBackend(raw) {
    const fail = (reason) => ({ ok: false, reason });
    if (typeof raw !== "string" || !raw.trim()) return fail("empty");
    let u;
    try { u = new URL(raw.trim()); } catch (e) { return fail("invalid"); }
    if (u.protocol !== "https:" && u.protocol !== "http:") return fail("invalid");
    if (u.protocol === "http:" && !LOOPBACK_HOSTS.includes(u.hostname)) return fail("insecure");
    if (u.username || u.password) return fail("credentials");
    if (u.pathname !== "/" || u.search || u.hash) return fail("path");
    return { ok: true, origin: u.origin };
  }

  function sanitizeSettings(raw) {
    const out = Object.assign({}, DEFAULT_SETTINGS);
    if (raw && typeof raw === "object") {
      const b = normalizeBackend(raw.backend);
      if (b.ok) out.backend = b.origin;
      if (typeof raw.stripQuery === "boolean") out.stripQuery = raw.stripQuery;
    }
    return out;
  }

  /* ---------- talking to the server ---------- */
  function buildScanRequest(origin, url) {
    return {
      endpoint: origin + "/scan",
      init: {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ url }),
        credentials: "omit",          // no cookies: the server must not be able to tie checks to a browser
        redirect: "error",            // a server that answers with a redirect is a failure, never followed
        cache: "no-store",
        referrerPolicy: "no-referrer"
      }
    };
  }

  function parseRetryAfter(value) {
    const n = parseInt(value, 10);
    return Number.isFinite(n) && n > 0 && n < 3600 ? n : null;
  }

  /* Accept a server answer only if it has a verdict we know. Unknown or missing means "not understood", which the
     caller shows as an error. It is never mapped to a reassuring result. */
  function normalizeResult(data) {
    if (!data || typeof data !== "object" || !VERDICT_CODES.includes(data.verdict_code)) return null;
    const list = (v) => (Array.isArray(v) ? v : []);
    const risk = Number(data.risk_score);
    return {
      verdict_code: data.verdict_code,
      confirmed: data.confirmed === true && data.verdict_code === "malicious",
      summary: clamp(data.summary, 400),
      hostname: clamp(data.hostname, 255),
      risk_score: Number.isFinite(risk) ? risk : null,
      lookup_sent_query: data.lookup_sent_query === true,
      evidence: list(data.evidence).slice(0, 12).filter((e) => e && typeof e === "object").map((e) => ({
        source: clamp(e.source, 80),
        detail: clamp(e.detail, 300),
        severity: SEVERITIES.includes(e.severity) ? e.severity : "info",
        code: e.code ? clamp(e.code, 40) : null
      })),
      sources: list(data.sources).slice(0, 8).filter((s) => s && typeof s === "object").map((s) => ({
        name: clamp(s.name, 80),
        status: SOURCE_STATUSES.includes(s.status) ? s.status : "error"
      }))
    };
  }

  /* Ask the server about one link. Resolves to {ok: true, result} or {ok: false, code, ...}; it never throws and never
     reports a failure as a verdict. `fetchImpl` is injected so the tests can use a fake. */
  async function checkLink(fetchImpl, origin, url, options) {
    const opts = options || {};
    const timeoutMs = opts.timeoutMs || CHECK_TIMEOUT_MS;
    const { endpoint, init } = buildScanRequest(origin, url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const failure = (code, extra) => Object.assign({ ok: false, code }, extra || {});
    try {
      let res;
      try {
        res = await fetchImpl(endpoint, Object.assign({}, init, { signal: controller.signal }));
      } catch (e) {
        return failure(controller.signal.aborted ? "timeout" : "network");
      }
      let data = null;
      try { data = await res.json(); } catch (e) { data = null; }
      const requestId = data && typeof data.request_id === "string" && /^[0-9a-f]{8}$/.test(data.request_id) ? data.request_id : null;
      if (res.status === 429) return failure("rate_limited", { retryAfter: parseRetryAfter(res.headers.get("Retry-After")), requestId });
      if (!res.ok) {
        const known = data && typeof data.code === "string" ? data.code : "";
        if (known === "origin_not_allowed") return failure("origin_not_allowed", { requestId });
        if (known === "invalid_url") return failure("invalid_url", { requestId, serverMessage: clamp(data.error, 200) });
        if (known === "payload_too_large") return failure("too_long", { requestId });
        return failure(res.status >= 500 ? "server_error" : "request_failed", { requestId });
      }
      const result = normalizeResult(data);
      return result ? { ok: true, result } : failure("unexpected_response", { requestId });
    } finally {
      clearTimeout(timer);
    }
  }

  /* Is the server there? A plain GET /health, same restrictions as a check (no cookies, no redirects, a short timeout).
     Resolves to true or false and never throws. */
  async function checkHealth(fetchImpl, origin, options) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), (options && options.timeoutMs) || 5000);
    try {
      const res = await fetchImpl(origin + "/health", {
        method: "GET", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal: controller.signal
      });
      const data = await res.json();
      return res.ok && !!data && data.status === "ok";
    } catch (e) {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  /* Plain-language text for every way a check can fail. `ctx`: {origin, extensionOrigin, retryAfter, requestId, serverMessage}. */
  function friendlyError(code, ctx) {
    const c = ctx || {};
    const ref = c.requestId ? " (reference " + c.requestId + ")" : "";
    switch (code) {
      case "empty":
      case "invalid": return "That doesn't look like a web address, so it wasn't checked.";
      case "not_web_link": return "Only web links (starting with http:// or https://) can be checked.";
      case "too_long": return "That address is too long to check (the limit is " + MAX_URL_LENGTH + " characters).";
      case "network": return "Couldn't reach the Cyber Solutions server" + (c.origin ? " at " + c.origin : "") + ". Check that it is running and that the address in Settings is right.";
      case "timeout": return "The check took too long. Try again in a moment.";
      case "rate_limited": return c.retryAfter ? "Too many checks in a short time. Try again in " + c.retryAfter + " second" + (c.retryAfter === 1 ? "" : "s") + "." : "Too many checks in a short time. Please wait a moment and try again.";
      case "origin_not_allowed": return "The server doesn't allow this extension yet. Add " + (c.extensionOrigin || "this extension's origin") + " to EXTENSION_ORIGINS in the server's .env file and restart it" + ref + ".";
      case "invalid_url": return (c.serverMessage || "The server couldn't accept that address.") + ref;
      case "server_error": return "The server ran into a problem. Try again in a moment" + ref + ".";
      case "unexpected_response": return "The server's answer wasn't in the expected format, so no verdict is shown. Check that the address in Settings points at a Cyber Solutions server" + ref + ".";
      default: return "The check couldn't be completed" + ref + ".";
    }
  }
  // Failures a second attempt could fix.
  const RETRYABLE = ["network", "timeout", "rate_limited", "server_error", "request_failed"];

  /* ---------- how a result is presented ---------- */
  const PRESENTATION = {
    malicious: { level: "danger", label: "Malicious", headline: "A threat database lists this link",
      advice: "Don't sign in, pay or download anything from it. If you already did, change any passwords you entered and run a malware scan." },
    suspicious: { level: "warn", label: "Suspicious", headline: "This link has warning signs",
      advice: "Nothing confirms it is a threat, but its address matches patterns used by phishing and scams. Go to the site yourself instead of using the link." },
    no_known_threat: { level: "ok", label: "No known threat detected", headline: "No known threat found",
      advice: "That isn't a guarantee: new threats take time to be listed." },
    unable_to_verify: { level: "unknown", label: "Unable to verify", headline: "We couldn't verify this link",
      advice: "This is not a safe result. Don't trust the link until it has been checked." }
  };
  const SOURCE_TEXT = { hit: "lists this link", clear: "does not list it", skipped: "not set up on the server", error: "couldn't be checked" };

  function presentResult(result) {
    const base = PRESENTATION[result.verdict_code];
    const notes = [];
    // Shorteners and redirect parameters hide where a link really goes. We check the address we were given, not where it leads.
    if (result.evidence.some((e) => e.code === "shortener" || e.code === "open_redirect")) {
      notes.push("This address can send you somewhere else. Only the address you chose was checked. Where it leads wasn't opened or checked.");
    }
    if (result.sources.some((s) => s.status !== "skipped")) {
      notes.push(result.lookup_sent_query
        ? "The address, including anything after “?”, was sent to the threat databases the server uses."
        : "Anything after “?” was removed before the threat-database lookup.");
    }
    return {
      code: result.verdict_code,
      level: base.level,
      label: base.label,
      headline: base.headline,
      advice: base.advice,
      summary: result.summary,
      confirmed: result.confirmed,
      evidence: result.evidence,
      sourceLines: result.sources.map((s) => s.name + " " + SOURCE_TEXT[s.status]),
      notes,
      openLabel: result.verdict_code === "no_known_threat" ? "Open link" : "Open anyway",
      openNeedsAck: result.verdict_code === "malicious"   // a listed threat needs an explicit "I understand" before the open button works
    };
  }

  /* ---------- short-lived result records (kept in storage.session, i.e. in memory only) ---------- */
  function newToken(cryptoImpl) {
    const bytes = new Uint8Array(16);
    cryptoImpl.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  const recordKey = (token) => "check:" + token;

  // Which saved results to drop: anything older than an hour, and everything beyond the newest `keep`.
  function staleKeys(entries, now, options) {
    const maxAgeMs = (options && options.maxAgeMs) || 60 * 60 * 1000;
    const keep = (options && options.keep) || 20;
    const rows = Object.keys(entries || {}).filter((k) => k.startsWith("check:"))
      .map((k) => ({ key: k, ts: Number(entries[k] && entries[k].ts) || 0 }))
      .sort((a, b) => b.ts - a.ts);
    return rows.filter((r, i) => i >= keep || now - r.ts > maxAgeMs).map((r) => r.key);
  }

  return {
    DEFAULT_BACKEND, MAX_URL_LENGTH, CHECK_TIMEOUT_MS, TOKEN_RE, VERDICT_CODES, DEFAULT_SETTINGS, RETRYABLE,
    clamp, prepareLink, isWebUrl, normalizeBackend, sanitizeSettings, buildScanRequest, normalizeResult,
    checkLink, checkHealth, friendlyError, presentResult, newToken, recordKey, staleKeys
  };
});
