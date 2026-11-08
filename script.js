/* LinkLens frontend: routing, scanner, history, contact form */
const API_BASE = window.location.protocol.startsWith("http") ? "" : "http://127.0.0.1:5000";
const $ = (id) => document.getElementById(id);
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }
};

/* ---------- Safe errors and privacy helpers ---------- */
/* Messages shown to people come from this table and the server's short, fixed messages. Raw exception text,
   status lines and stack details are never displayed. */
const ERRORS = {
  rate_limited: "You’re going a bit fast. Please wait a moment and try again.",
  payload_too_large: "That is too long to send. Please shorten it and try again.",
  unsupported_media_type: "Your browser sent the request in an unexpected format. Reload the page and try again.",
  origin_not_allowed: "This page isn’t allowed to use the scanner from here. Open the scanner from its own address.",
  contact_unavailable: "Messages can’t be received right now. Please try again later.",
  server_error: "Something went wrong on our side. Please try again in a moment.",
  network: "We couldn’t reach the scanner. Check your connection and try again."
};
function reference(data) {
  return data && typeof data.request_id === "string" && /^[0-9a-f]{8}$/.test(data.request_id) ? " (reference " + data.request_id + ")" : "";
}
function safeMessage(res, data) {
  if (res.status === 429) {
    const wait = parseInt(res.headers.get("Retry-After"), 10);
    return Number.isFinite(wait) && wait > 0 && wait < 3600 ? "You’re going a bit fast. Please try again in " + wait + " second" + (wait === 1 ? "" : "s") + "."
                                                              : ERRORS.rate_limited;
  }
  const known = data && ERRORS[data.code];
  if (known) return known + reference(data);
  return res.status >= 500 ? ERRORS.server_error + reference(data) : "That request couldn’t be completed" + reference(data) + ".";
}
/* Keep only scheme + host + path, like the server does: query strings and fragments often carry tokens. */
function redactUrl(raw) {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "https://" + raw);
    return (u.protocol + "//" + u.host + u.pathname).slice(0, 200);
  } catch { return String(raw).split(/[?#]/)[0].slice(0, 200); }
}
let privacyPromise = null;
function loadPrivacy() {
  if (!privacyPromise) {
    privacyPromise = fetch(API_BASE + "/privacy").then(r => r.ok ? r.json() : null).catch(() => null);
  }
  return privacyPromise;
}
const plural = (n, word) => n + " " + word + (n === 1 ? "" : "s");

/* ---------- Routing (hash based) ---------- */
const ROUTES = ["scan", "history", "how", "extension", "contact", "privacy", "home"];
let focusScannerNext = false;

function route() {
  let name = (location.hash.replace(/^#\/?/, "") || "scan");
  if (name === "home") name = "scan";
  const current = ROUTES.includes(name) ? name : "scan";
  document.querySelectorAll(".view").forEach(v => { v.hidden = v.dataset.view !== current; });
  document.querySelectorAll(".tabs a").forEach(a => {
    if (a.dataset.route === current || (current === "scan" && a.dataset.route === "scan")) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.title = (current === "scan" ? "LinkLens · URL Threat Intelligence & Link Scanner"
    : { history: "Dashboard & Scan History", how: "Threat Engine & Architecture", extension: "Browser Extension", contact: "Contact & Security Reporting", privacy: "Privacy & Data Handling" }[current] + " · LinkLens");
  window.scrollTo(0, 0);
  renderStatus();
  if (current === "history") renderHistory();
  if (current === "how") renderEvaluation();
  if (current === "privacy") renderPrivacy();
  if (current === "extension") {
    const extElem = $("extServerOrigin");
    if (extElem) extElem.textContent = location.origin;
  }
  if (current === "scan" && focusScannerNext) $("urlInput").focus();
  focusScannerNext = false;
}
window.addEventListener("hashchange", route);
document.querySelectorAll("[data-focus-scanner]").forEach(a =>
  a.addEventListener("click", () => { focusScannerNext = true; if (location.hash === "#/scan") route(); }));

/* ---------- Theme ---------- */
$("themeToggle").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch {}
});

/* ---------- Scanner ---------- */
const VERDICTS = {
  malicious: { level: "danger", badge: "badge-danger", label: "Malicious", title: "A threat database lists this link",
    text: "Do not open it, sign in, pay or download anything from it. If you already did, change the passwords you may have entered and run a malware scan." },
  suspicious: { level: "warn", badge: "badge-warn", label: "Suspicious", title: "This link has warning signs",
    text: "Nothing confirms this link is a threat, but its address matches patterns used by phishing and scams. Go to the site yourself instead of using the link." },
  no_known_threat: { level: "ok", badge: "badge-ok", label: "No known threat detected", title: "No known threat found",
    text: "The threat database doesn’t list this link and we found no strong warning signs. That isn’t a guarantee: new threats take time to be listed." },
  unable_to_verify: { level: "unknown", badge: "badge-muted", label: "Unable to verify", title: "We couldn’t verify this link",
    text: "The threat database couldn’t be checked, so this is not a safe result. Try again in a moment, and don’t trust the link until it has been checked." }
};
/* Results saved before Stage 2 used these names. Neither was checked against a threat database. */
const LEGACY = { Dangerous: "suspicious", Suspicious: "suspicious", Safe: "unable_to_verify" };
let lastUrl = "";
let lastResult = null;
let scanSeq = 0;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function setFieldError(msg) {
  const e = $("fieldError");
  e.textContent = msg || ""; e.hidden = !msg;
  $("urlInput").setAttribute("aria-invalid", msg ? "true" : "false");
}
function hideOutputs() { $("result").hidden = true; $("unverified").hidden = true; setFieldError(""); }

function showUnverified(text) {
  $("unverified").dataset.level = "unknown";
  $("unverifiedText").textContent = text;
  $("unverified").hidden = false;
}

const URL_ANALYSIS = "URL analysis";
const RISK_METER_MAX = 6; // a score of 3 or more is "Suspicious"; the meter is full at 6

function evidenceItem(ev) {
  const li = el("li", "ev ev-" + (ev.source !== URL_ANALYSIS ? (ev.severity === "high" ? "confirmed" : "medium") : ev.severity || "low"));
  li.append(el("span", "ev-text", ev.detail));
  if (ev.source === URL_ANALYSIS && ev.points) li.append(el("b", "ev-points", "+" + ev.points));
  if (ev.source !== URL_ANALYSIS) li.append(el("span", "ev-src", "Source: " + ev.source));
  if (ev.source === URL_ANALYSIS && ev.code) li.append(el("span", "ev-code", "rule: " + ev.code.replace(/_/g, " ")));
  return li;
}
function sourceNote(src, text) { return el("li", "ev ev-low", src.name + ": " + text); }

function showResult(data) {
  const code = VERDICTS[data.verdict_code] ? data.verdict_code : "unable_to_verify";
  const cfg = VERDICTS[code];
  const sources = Array.isArray(data.sources) ? data.sources : [];
  const evidence = Array.isArray(data.evidence) ? data.evidence : [];
  const hits = sources.filter(x => x.status === "hit");
  const clear = sources.filter(x => x.status === "clear");
  const failed = sources.filter(x => x.status === "error" || x.status === "skipped");
  const r = $("result");
  r.dataset.level = cfg.level;
  lastResult = data;
  $("scannedAt").textContent = data.scanned_at && !isNaN(new Date(data.scanned_at)) ? "Scanned " + new Date(data.scanned_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" }) : "";
  $("copyResult").textContent = "Copy summary"; delete $("copyResult").dataset.state;

  $("verdictBadge").className = "badge " + cfg.badge;
  $("verdictBadge").textContent = cfg.label;
  const tag = $("confirmedTag");
  tag.hidden = false;
  tag.className = "tag " + (data.confirmed ? "tag-confirmed" : "tag-heuristic");
  tag.textContent = data.confirmed ? "Confirmed by threat intelligence"
    : data.basis === "threat_database" ? "Threat database reports risk, not confirmed"
    : code === "suspicious" ? "Heuristic warning, not confirmed"
    : code === "no_known_threat" ? "Not listed in " + clear.map(x => x.name).join(", ")
    : "Lookup failed";
  $("verdictTitle").textContent = cfg.title;
  $("verdictText").textContent = cfg.text;
  $("resultUrl").textContent = data.normalized_url || data.url;

  const score = Number(data.risk_score) || 0;
  $("methodText").textContent = data.basis === "threat_database"
    ? "Decided by: a threat-database result (source shown below)."
    : data.basis === "url_structure"
      ? "Decided by: URL-structure rules only (risk score " + score + "; Suspicious starts at 3). No threat database confirmed this."
      : code === "no_known_threat"
        ? "Decided by: no threat-database listing, and a URL-structure score of " + score + " (below 3)."
        : "No threat database answered. URL-structure score: " + score + " (Suspicious starts at 3).";
  $("scoreNum").textContent = score;
  $("meterFill").style.width = "0%";
  requestAnimationFrame(() => { $("meterFill").style.width = Math.min(100, Math.round(score / RISK_METER_MAX * 100)) + "%"; });

  // Threat-intelligence section: one entry per source, so a failed lookup is always visible.
  const iBadge = $("intelStatus");
  const iList = $("intelList");
  iList.replaceChildren(...evidence.filter(e => e.source !== URL_ANALYSIS && e.severity !== "info").map(evidenceItem));
  if (hits.length) {
    iBadge.className = "badge badge-sm " + (data.confirmed ? "badge-danger" : "badge-warn");
    iBadge.textContent = data.confirmed ? "Threat found" : "Risk reported";
    $("intelSummary").textContent = (data.confirmed ? "Confirmed by " : "Reported by ") + hits.map(x => x.name).join(", ") + ":";
  } else if (clear.length) {
    iBadge.className = "badge badge-sm badge-ok"; iBadge.textContent = "Not listed";
    $("intelSummary").textContent = "Checked " + clear.map(x => x.name).join(", ")
      + (data.scanned_at ? " at " + new Date(data.scanned_at).toLocaleTimeString() : "") + ". It doesn’t list this address.";
  } else {
    iBadge.className = "badge badge-sm badge-muted"; iBadge.textContent = "Not checked";
    $("intelSummary").textContent = "No threat database could be checked, so nothing here is a safe result.";
  }
  if (!hits.length) clear.forEach(x => iList.append(sourceNote(x, "not listed.")));
  failed.forEach(x => iList.append(sourceNote(x, (x.status === "skipped" ? "not used. " : "could not be checked. ") + x.detail)));

  // Heuristic section (URL structure)
  const heur = evidence.filter(e => e.source === URL_ANALYSIS && e.severity !== "info");
  $("heurList").replaceChildren(...heur.map(evidenceItem));
  $("heurSummary").textContent = heur.length
    ? "Pattern checks on the address itself. These are warnings, not proof of a threat."
    : "No warning signs found in the address.";
  evidence.filter(e => e.source === URL_ANALYSIS && e.severity === "info")
    .forEach(e => $("heurList").append(el("li", "ev ev-low", e.detail)));

  $("methodText").textContent += data.lookup_sent_query === false
    ? " The part of the address after “?” was not sent to threat databases."
    : "";
  $("hostLine").textContent = data.hostname
    ? "Site read as: " + data.hostname
      + (data.registered_domain && data.registered_domain !== data.hostname ? " · main domain " + data.registered_domain : "")
    : "";
  $("rescanBtn").hidden = !(sources.some(x => x.status === "error") && !hits.length); // retrying only helps after a real failure
  r.hidden = false;
  r.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

/* Earlier versions saved the full address, including ?query. Clean any such entries once. */
(function migrateLocalHistory() {
  const list = store.get("scanHistory", []);
  if (list.some(x => x && typeof x.url === "string" && /[?#]/.test(x.url))) {
    store.set("scanHistory", list.map(x => (x && typeof x.url === "string" ? { ...x, url: redactUrl(x.url) } : x)));
  }
})();

const trimEvidence = (items) => (Array.isArray(items) ? items : []).slice(0, 12).map(e => ({
  source: String(e.source || "").slice(0, 60), severity: String(e.severity || "").slice(0, 12),
  detail: String(e.detail || "").replace(/[?#]\S*/g, "").slice(0, 300),
  ...(e.code ? { code: String(e.code).slice(0, 40) } : {}), ...(Number.isInteger(e.points) ? { points: e.points } : {})
}));
function saveHistory(data) {
  const list = store.get("scanHistory", []);
  const checks = (Array.isArray(data.sources) ? data.sources : []).slice(0, 6)
    .map(c => ({ name: String(c.name || "").slice(0, 60), status: String(c.status || "").slice(0, 12), detail: String(c.detail || "").slice(0, 160) }));
  list.unshift({ url: redactUrl(data.normalized_url || data.url), code: data.verdict_code, score: data.risk_score, confirmed: !!data.confirmed,
    at: Date.now(), hits: checks.filter(c => c.status === "hit").map(c => c.name), evidence: trimEvidence(data.evidence), checks });
  store.set("scanHistory", list.slice(0, 50));
}

async function scan(raw) {
  const url = (raw || "").trim();
  hideOutputs();
  const problem = !url ? "Enter a URL to scan."
    : url.length > 2048 ? "That link is too long to scan (the limit is 2048 characters)."
    : /\s/.test(url) ? "Remove the spaces from the link, then try again."
    : /^[a-z][a-z0-9+.-]*:\/\//i.test(url) && !/^https?:\/\//i.test(url) ? "Only http:// and https:// links can be scanned."
    : "";
  if (problem) { setFieldError(problem); $("urlInput").focus(); return; }
  lastUrl = url;
  const seq = ++scanSeq;
  $("loading").hidden = false; $("scanBtn").disabled = true;
  $("loadingText").textContent = "Scanning…";
  const slowTimer = setTimeout(() => { $("loadingText").textContent = "Still checking. Threat databases can take a few seconds…"; }, 3500);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000); // server waits at most ~8s for the threat service
  try {
    const res = await fetch(API_BASE + "/scan", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }), signal: ctrl.signal
    });
    const data = await res.json().catch(() => ({}));
    if (seq !== scanSeq) return;
    if (res.status === 429) { showUnverified(safeMessage(res, data) + " This is not a safe result."); return; }
    if (res.status === 400 && data.code === "invalid_url" && typeof data.error === "string") {
      setFieldError(data.error.slice(0, 200)); $("urlInput").focus(); return;
    }
    if (!res.ok || !data.verdict_code) { showUnverified(safeMessage(res, data) + " This is not a safe result."); return; }
    saveHistory(data);
    showResult(data);
  } catch (err) {
    if (seq !== scanSeq) return;
    showUnverified(err.name === "AbortError"
      ? "The scanner took too long to answer. This is not a safe result. Try again in a moment."
      : ERRORS.network + " This is not a safe result.");
  } finally {
    clearTimeout(timer); clearTimeout(slowTimer);
    if (seq === scanSeq) { $("loading").hidden = true; $("scanBtn").disabled = false; }
  }
}

$("scanForm").addEventListener("submit", e => { e.preventDefault(); scan($("urlInput").value); });
$("retryBtn").addEventListener("click", () => scan(lastUrl));
$("rescanBtn").addEventListener("click", () => scan(lastUrl));
$("scanAnother").addEventListener("click", () => { hideOutputs(); $("urlInput").value = ""; $("urlInput").focus(); });
if ($("tryExample")) {
  $("tryExample").addEventListener("click", () => {
    $("urlInput").value = "https://paypal-secure-login.com/verify";
    focusScannerNext = false;
    location.hash = "#/scan";
    scan($("urlInput").value);
  });
}
document.querySelectorAll("[data-sample]").forEach(btn => {
  btn.addEventListener("click", () => {
    const sample = btn.dataset.sample;
    if (!sample) return;
    $("urlInput").value = sample;
    focusScannerNext = false;
    location.hash = "#/scan";
    scan(sample);
  });
});

/* ---------- Measured accuracy (How it works page) ---------- */
const pct1 = (x) => x == null ? "n/a" : (x * 100).toFixed(1) + "%";
const pctCI = (x, ci) => x == null ? "n/a" : pct1(x) + (ci && ci[0] != null ? " (" + Math.round(ci[0] * 100) + "–" + Math.round(ci[1] * 100) + "%)" : "");
const SPLIT_LABEL = {
  holdout: "Holdout (not used to tune the rules)",
  dev: "Dev (used to tune the rules, so optimistic)"
};
function spotsText(list) {
  return list.map(x => x.category.replace(/-/g, " ") + " (" + x.wrong + " of " + x.total + ")").join(", ");
}
let evalSeq = 0;
async function renderEvaluation() {
  const box = $("evalBox");
  if (!box) return;
  const seq = ++evalSeq;
  let data = null;
  try {
    const res = await fetch(API_BASE + "/evaluation");
    if (res.ok) data = await res.json();
  } catch { /* shown below as unavailable */ }
  if (seq !== evalSeq) return;
  if (!data || !data.available) {
    box.replaceChildren(el("p", null, "No measured results are available from this server" + (data ? " yet" : " (it could not be reached)") +
      ". Until they are, treat the address checks as unmeasured. Run python evaluate.py --report to produce them."));
    return;
  }
  const nodes = [];
  if (data.stale) {
    const warn = el("div", "alert alert-error", "These figures were measured on an earlier version of the rules and may no longer be accurate. Run python evaluate.py --report to refresh them.");
    warn.setAttribute("role", "note");
    nodes.push(warn);
  }
  nodes.push(el("p", null, data.scope));

  const order = Object.keys(data.splits).sort((a, b) => (a === "holdout" ? -1 : b === "holdout" ? 1 : a.localeCompare(b)));
  const table = el("table", "table");
  const head = el("tr");
  ["Test set", "Links", "Precision", "Recall", "F1", "False alarms"].forEach(t => head.append(el("th", null, t)));
  const thead = el("thead");
  thead.append(head);
  table.append(thead);
  const body = el("tbody");
  order.forEach(name => {
    const m = data.splits[name];
    const tr = el("tr");
    [SPLIT_LABEL[name] || name, m.n + " (" + m.positives + " phishing)", pctCI(m.precision, m.precision_ci), pctCI(m.recall, m.recall_ci),
      pct1(m.f1), pctCI(m.fpr, m.fpr_ci)].forEach(t => tr.append(el("td", null, t)));
    body.append(tr);
  });
  table.append(body);
  const wrap = el("div", "table-wrap"); wrap.append(table);
  nodes.push(wrap);
  nodes.push(el("p", "help", "Brackets are 95% confidence ranges; with this few links they are wide. “False alarms” is the share of legitimate links that were flagged Suspicious. Recall is the share of the phishing links that were flagged."));

  const list = el("ul");
  list.append(el("li", null, "The phishing links in the test set are invented examples that follow known phishing patterns. They are not a sample of real attacks, so recall here is likely higher than it would be on real ones."));
  list.append(el("li", null, "The legitimate links are real, well-known sites."));
  list.append(el("li", null, "Precision depends on how common phishing is. Even a false-alarm rate of a few percent means most “Suspicious” flags on everyday links would be false alarms when phishing is rare. That is why “Suspicious” is a warning, not a verdict."));
  nodes.push(list);

  const weak = data.weak_spots && (data.weak_spots.holdout || data.weak_spots[order[0]]);
  if (weak && (weak.missed.length || weak.false_alarms.length)) {
    const which = data.weak_spots.holdout ? "holdout" : order[0];
    nodes.push(el("h3", null, "Where it falls short (" + which + " set)"));
    const w = el("ul");
    if (weak.missed.length) w.append(el("li", null, "Phishing it missed: " + spotsText(weak.missed) + "."));
    if (weak.false_alarms.length) w.append(el("li", null, "Legitimate links it flagged: " + spotsText(weak.false_alarms) + "."));
    nodes.push(w);
  }
  nodes.push(el("p", "help", "Dataset " + data.dataset.file + " (" + data.dataset.rows + " links, fingerprint " + data.dataset.sha256 + "…). Measured with Python " +
    data.environment.python + " and tldextract " + data.environment.tldextract + ". These figures cover the address checks only, not the threat-database lookups."));
  box.replaceChildren(...nodes);
}

/* ---------- Dashboard and history ---------- */
const BADGE = { malicious: "badge-danger", suspicious: "badge-warn", no_known_threat: "badge-ok", unable_to_verify: "badge-muted" };
const VERDICT_ORDER = ["malicious", "suspicious", "no_known_threat", "unable_to_verify"];
const CODE_BY_LABEL = Object.fromEntries(Object.entries(VERDICTS).map(([code, v]) => [v.label, code]));
const KNOWN_SOURCES = ["Google Safe Browsing", "URLhaus"];
const PAGE_SIZE = 25;
const H = { mode: "server", items: [], total: 0, seq: 0, local: [], shown: PAGE_SIZE, hasAny: false, sourceKey: "" };

function ago(ts) {
  const s = Math.max(1, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return new Date(ts).toLocaleDateString();
}
const fmtWhen = (ts) => new Date(ts).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/* Both the server's records and this browser's own copy are turned into one shape, so one renderer serves both. */
function fromServer(x) {
  return {
    id: x.id, at: Date.parse(x.scanned_at), url: String(x.url),
    code: VERDICTS[x.verdict_code] ? x.verdict_code : (CODE_BY_LABEL[x.verdict] || "unable_to_verify"),
    confirmed: !!x.confirmed, score: Number.isInteger(x.risk_score) ? x.risk_score : null,
    hits: Array.isArray(x.threat_sources) ? x.threat_sources : [],
    evidence: Array.isArray(x.evidence) ? x.evidence : [], checks: Array.isArray(x.sources) ? x.sources : []
  };
}
function fromLocal(x) {
  return {
    id: null, at: Number(x.at) || Date.now(), url: String(x.url || ""),
    code: VERDICTS[x.code] ? x.code : (LEGACY[x.status] || "unable_to_verify"),
    confirmed: !!x.confirmed, score: Number.isInteger(x.score) ? x.score : null,
    hits: Array.isArray(x.hits) ? x.hits : [], evidence: Array.isArray(x.evidence) ? x.evidence : [],
    checks: Array.isArray(x.checks) ? x.checks : []
  };
}
const localRecords = () => store.get("scanHistory", []).filter(x => x && typeof x.url === "string").map(fromLocal);

/* ----- filters ----- */
function readFilters() {
  return {
    q: $("fSearch").value.trim(),
    verdicts: [...$("historyFilters").querySelectorAll('input[name="verdict"]:checked')].map(i => i.value),
    source: $("fSource").value, days: $("fDays").value, sort: $("fSort").value, confirmed: $("fConfirmed").checked
  };
}
const isFiltered = (f) => !!(f.q || f.verdicts.length || f.source || f.days || f.confirmed);
function queryString(f, extra) {
  const p = new URLSearchParams();
  if (f.q) p.set("q", f.q);
  if (f.verdicts.length) p.set("verdict", f.verdicts.join(","));
  if (f.source) p.set("source", f.source);
  if (f.days) p.set("days", f.days);
  if (f.confirmed) p.set("confirmed", "1");
  if (f.sort !== "newest") p.set("sort", f.sort);
  Object.entries(extra || {}).forEach(([k, v]) => p.set(k, v));
  return p.toString();
}
function applyLocal(records, f) {
  const q = f.q.toLowerCase(), since = f.days ? Date.now() - Number(f.days) * 86400000 : 0;
  const out = records.filter(r =>
    (!q || r.url.toLowerCase().includes(q) || VERDICTS[r.code].label.toLowerCase().includes(q) || r.hits.some(h => h.toLowerCase().includes(q))) &&
    (!f.verdicts.length || f.verdicts.includes(r.code)) && (!f.source || r.hits.includes(f.source)) &&
    r.at >= since && (!f.confirmed || r.confirmed));
  if (f.sort === "oldest") out.sort((a, b) => a.at - b.at);
  else if (f.sort === "risk") out.sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || b.at - a.at);
  else out.sort((a, b) => b.at - a.at);
  return out;
}
function localStats(records) {
  const by = Object.fromEntries(VERDICT_ORDER.map(c => [c, 0])), src = {}, perDay = {};
  let confirmed = 0, last = 0;
  const dayKey = (d) => d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
  records.forEach(r => {
    by[r.code]++; confirmed += r.confirmed ? 1 : 0; last = Math.max(last, r.at);
    r.hits.forEach(h => { src[h] = (src[h] || 0) + 1; });
    const b = perDay[dayKey(new Date(r.at))] || (perDay[dayKey(new Date(r.at))] = [0, 0]);
    b[0]++; b[1] += (r.code === "malicious" || r.code === "suspicious") ? 1 : 0;
  });
  const by_day = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    const [scans, flagged] = perDay[dayKey(d)] || [0, 0];
    by_day.push({ date: dayKey(d), scans, flagged });
  }
  return { total: records.length, by_verdict: by, flagged: by.malicious + by.suspicious, confirmed,
    last_scan: last ? new Date(last).toISOString() : null, by_day,
    threat_sources: Object.entries(src).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5).map(([name, count]) => ({ name, count })) };
}

/* ----- dashboard panels ----- */
const SEGMENT_CLASS = { malicious: "seg-danger", suspicious: "seg-warn", no_known_threat: "seg-ok", unable_to_verify: "seg-muted" };
function renderStats(s) {
  $("statTotal").textContent = s.total;
  $("statFlagged").textContent = s.flagged;
  $("statConfirmed").textContent = s.confirmed;
  $("statLast").textContent = s.last_scan ? ago(Date.parse(s.last_scan)) : "None yet";
  $("statLast").title = s.last_scan ? fmtWhen(Date.parse(s.last_scan)) : "";

  const bar = $("verdictBar");
  bar.replaceChildren(...VERDICT_ORDER.filter(c => s.by_verdict[c] > 0).map(c => {
    const seg = el("span", "stack-seg " + SEGMENT_CLASS[c]);
    seg.style.width = (s.by_verdict[c] / s.total * 100) + "%";
    return seg;
  }));
  $("verdictLegend").replaceChildren(...VERDICT_ORDER.map(c => {
    const n = s.by_verdict[c] || 0, li = el("li", n ? "" : "legend-zero");
    li.append(el("span", "swatch " + SEGMENT_CLASS[c]), el("span", "legend-name", VERDICTS[c].label),
      el("b", "legend-n", n + (s.total ? " (" + Math.round(n / s.total * 100) + "%)" : "")));
    return li;
  }));

  const max = Math.max(1, ...s.by_day.map(d => d.scans));
  $("dayChart").replaceChildren(...s.by_day.map(d => {
    const day = new Date(d.date + "T00:00:00"); // local midnight; a bare date string would be read as UTC
    const li = el("li", "bar-col");
    const track = el("span", "bar-track");
    const all = el("span", "bar-all"), flag = el("span", "bar-flag");
    all.style.height = (d.scans / max * 100) + "%";
    flag.style.height = (d.flagged / max * 100) + "%";
    track.append(all, flag);
    li.append(track, el("span", "bar-label", String(day.getDate())),
      el("span", "sr-only", day.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" }) + ": " +
        plural(d.scans, "scan") + (d.flagged ? ", " + d.flagged + " flagged" : "")));
    li.title = day.toLocaleDateString(undefined, { day: "numeric", month: "short" }) + ": " + plural(d.scans, "scan") + (d.flagged ? ", " + d.flagged + " flagged" : "");
    return li;
  }));

  $("sourceList").replaceChildren(...s.threat_sources.map(x => {
    const li = el("li"); li.append(el("span", null, x.name), el("b", null, plural(x.count, "link")));
    return li;
  }));
  $("sourceEmpty").hidden = s.threat_sources.length > 0;
  $("dashStats").hidden = s.total === 0;

  const names = [...new Set([...KNOWN_SOURCES, ...s.threat_sources.map(x => x.name)])];
  if (names.join("|") !== H.sourceKey) {  // rebuild the dropdown only when it changed, so the person's choice is kept
    const keep = $("fSource").value;
    $("fSource").replaceChildren(Object.assign(el("option", null, "Any"), { value: "" }),
      ...names.map(n => Object.assign(el("option", null, n), { value: n })));
    $("fSource").value = names.includes(keep) ? keep : "";
    H.sourceKey = names.join("|");
  }
}

/* ----- one scan in the list ----- */
function checkText(c) {
  return c.status === "hit" ? "listed this link. " + (c.detail || "") : c.status === "clear" ? "does not list this link."
    : c.status === "skipped" ? "was not used. " + (c.detail || "") : "could not be checked. " + (c.detail || "");
}
function sourceSummary(r) {
  if (r.hits.length) return "Threat source: " + r.hits.join(", ");
  const clear = r.checks.filter(c => c.status === "clear").map(c => c.name);
  if (clear.length) return "Not listed by " + clear.join(", ");
  return r.checks.length ? "No threat database could be checked" : "";
}
function evidenceBlock(r) {
  const intel = r.evidence.filter(e => e.source !== URL_ANALYSIS && e.severity !== "info");
  const heur = r.evidence.filter(e => e.source === URL_ANALYSIS && e.severity !== "info");
  const notes = r.checks.filter(c => c.status !== "hit");
  if (!intel.length && !heur.length && !notes.length) return null;
  const box = el("details", "h-evidence");
  box.append(el("summary", null, "Evidence" + (intel.length + heur.length ? " (" + (intel.length + heur.length) + ")" : "")));
  const group = (title, nodes) => {
    if (!nodes.length) return;
    box.append(el("h4", null, title));
    const ul = el("ul", "evidence"); ul.append(...nodes); box.append(ul);
  };
  group("Threat databases", [...intel.map(evidenceItem), ...notes.map(c => sourceNote(c, checkText(c)))]);
  group("Warning signs in the address (not confirmed)", heur.map(evidenceItem));
  if (!heur.length && !intel.length) box.append(el("p", "help", "No warning signs were found in the address itself."));
  return box;
}
function historyItem(r) {
  const cfg = VERDICTS[r.code];
  const li = el("li", "h-item"); li.dataset.level = cfg.level;
  const main = el("div", "h-main");
  const top = el("div", "h-top");
  top.append(el("span", "badge " + BADGE[r.code], cfg.label));
  if (r.confirmed) top.append(el("span", "tag tag-confirmed", "Confirmed"));
  if (r.score != null) top.append(el("span", "h-score", "Risk score " + r.score));
  const when = el("time", null, fmtWhen(r.at));
  when.dateTime = new Date(r.at).toISOString();
  const meta = el("div", "h-meta");
  meta.append(when, " (" + ago(r.at) + ")");
  const src = sourceSummary(r);
  if (src) meta.append(" · " + src);
  main.append(top, el("div", "h-url mono", r.url), meta);
  const ev = evidenceBlock(r);
  if (ev) main.append(ev);

  const actions = el("div", "h-actions");
  const again = el("button", "btn btn-outline btn-sm", "Scan again");
  again.type = "button";
  again.addEventListener("click", () => { $("urlInput").value = r.url; location.hash = "#/scan"; scan(r.url); });
  const del = el("button", "btn btn-outline btn-sm btn-danger-outline", "Delete");
  del.type = "button";
  del.setAttribute("aria-label", "Delete the scan of " + r.url);
  del.addEventListener("click", () => deleteScan(r, li));
  actions.append(again, del);
  li.append(main, actions);
  return li;
}

/* ----- loading ----- */
function say(message, kind) {
  const box = $("historyStatus");
  box.textContent = message || ""; box.hidden = !message;
  box.className = "alert" + (kind ? " alert-" + kind : "");
}
function paint(records, total, filtered, appended) {
  const list = $("historyList");
  if (appended) list.append(...appended.map(historyItem)); else list.replaceChildren(...records.map(historyItem));
  $("historyEmpty").hidden = H.hasAny;
  $("historyNoMatch").hidden = !(H.hasAny && filtered && total === 0);
  $("historyCount").textContent = total === 0 ? "" : "Showing " + records.length + " of " + plural(total, filtered ? "matching scan" : "scan") + ".";
  $("historyMore").hidden = records.length >= total;
  $("historyFilters").hidden = !H.hasAny;
  document.querySelector(".list-head").hidden = !H.hasAny;
  $("filterReset").hidden = !filtered;
  $("filtersToggle").hidden = !H.hasAny;
  syncFilterCount();
}
let historyFocusIndex = null;
async function renderHistory(keep) {
  const seq = ++H.seq, f = readFilters(), filtered = isFiltered(f);
  const want = keep ? Math.min(100, Math.max(PAGE_SIZE, H.items.length)) : PAGE_SIZE;
  let data = null, offline = false;
  try {
    const res = await fetch(API_BASE + "/history?" + queryString(f, { limit: want, offset: 0, tz: -new Date().getTimezoneOffset() }));
    if (res.ok) { const d = await res.json(); if (d.enabled) data = d; } else offline = true;
  } catch { offline = true; }
  if (seq !== H.seq) return;
  const priv = await loadPrivacy();
  if (seq !== H.seq) return;

  if (data) {
    H.mode = "server";
    H.items = data.scans.map(fromServer); H.total = data.total; H.hasAny = data.stats.total > 0;
    renderStats(data.stats);
    $("historyNote").textContent = "Saved on the server for " + plural(priv ? priv.history_retention_days : 30, "day") +
      " and visible only to this browser. Only the scheme, site and path are kept, with the evidence behind each verdict.";
  } else {
    H.mode = "local";
    const all = localRecords();
    H.hasAny = all.length > 0;
    const matches = applyLocal(all, f);
    H.shown = keep ? Math.max(H.shown, PAGE_SIZE) : PAGE_SIZE;
    H.total = matches.length; H.items = matches.slice(0, H.shown);
    renderStats(localStats(all));
    $("historyNote").textContent = (offline ? "The server couldn’t be reached, so this shows the scans saved in this browser. " : "") +
      "Your last 50 scans, saved in this browser only. Only the scheme, site and path are kept.";
  }
  say("");
  paint(H.items, H.total, filtered);
  updateExportLinks(f);
  if (historyFocusIndex != null) {
    const target = $("historyList").children[Math.min(historyFocusIndex, H.items.length - 1)];
    (target ? target.querySelector("button") : $("historyCount")).focus();
    historyFocusIndex = null;
  }
}
async function showMore() {
  const f = readFilters(), seq = ++H.seq, filtered = isFiltered(f);
  if (H.mode === "local") {
    H.shown += PAGE_SIZE;
    const before = H.items.length;
    H.items = applyLocal(localRecords(), f).slice(0, H.shown);
    paint(H.items, H.total, filtered, H.items.slice(before));
    return;
  }
  $("historyMore").disabled = true;
  try {
    const res = await fetch(API_BASE + "/history?" + queryString(f, { limit: PAGE_SIZE, offset: H.items.length }));
    const data = await res.json().catch(() => ({}));
    if (seq !== H.seq) return;
    if (!res.ok || !Array.isArray(data.scans)) { say(safeMessage(res, data), "error"); return; }
    const more = data.scans.map(fromServer);
    H.items = H.items.concat(more); H.total = data.total;
    paint(H.items, H.total, filtered, more);
  } catch { say(ERRORS.network, "error"); }
  finally { $("historyMore").disabled = false; }
}

/* ----- delete ----- */
async function deleteScan(r, li) {
  historyFocusIndex = [...$("historyList").children].indexOf(li);
  if (H.mode === "server") {
    try {
      const res = await fetch(API_BASE + "/history/" + encodeURIComponent(r.id), { method: "DELETE" });
      if (!res.ok && res.status !== 404) { historyFocusIndex = null; say(safeMessage(res, await res.json().catch(() => ({}))), "error"); return; }
    } catch { historyFocusIndex = null; say(ERRORS.network, "error"); return; }
  }
  const mine = store.get("scanHistory", []);  // this browser keeps its own copy too
  const at = mine.findIndex(x => x && x.url === r.url && Math.abs((Number(x.at) || 0) - r.at) < 120000);
  if (at >= 0) { mine.splice(at, 1); store.set("scanHistory", mine); }
  await renderHistory(true);
  say("Scan deleted.", "success");
}
$("clearHistory").addEventListener("click", async () => {
  if (!confirm("Delete all of your saved scans from this browser and from the server? This can’t be undone.")) return;
  store.set("scanHistory", []);
  try { await fetch(API_BASE + "/history", { method: "DELETE" }); } catch {}
  resetFilters(false);
  await renderHistory();
  say("All saved scans were deleted.", "success");
});

/* ----- export ----- */
function csvCell(v) {  // a spreadsheet must not run a saved value as a formula
  let t = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(t)) t = "'" + t;
  return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
}
function localExport(kind) {
  const rows = applyLocal(localRecords(), readFilters());
  const out = rows.map(r => ({ scanned_at: new Date(r.at).toISOString(), url: r.url, verdict: VERDICTS[r.code].label, verdict_code: r.code,
    confirmed: r.confirmed, risk_score: r.score, threat_sources: r.hits, evidence: r.evidence, sources: r.checks }));
  const body = kind === "csv"
    ? ["scanned_at,url,verdict,confirmed,risk_score,threat_sources,evidence"].concat(out.map(o => [o.scanned_at, o.url, o.verdict,
        o.confirmed ? "yes" : "no", o.risk_score, o.threat_sources.join("; "), o.evidence.map(e => e.detail).filter(Boolean).join(" | ")].map(csvCell).join(","))).join("\r\n") + "\r\n"
    : JSON.stringify({ exported_at: new Date().toISOString(), count: out.length, scans: out }, null, 2);
  const url = URL.createObjectURL(new Blob([body], { type: kind === "csv" ? "text/csv" : "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: "scan-history." + kind });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function updateExportLinks(f) {
  ["csv", "json"].forEach(kind => {
    $(kind === "csv" ? "exportCsv" : "exportJson").href = API_BASE + "/history/export?" + queryString(f, { format: kind });
  });
}
[["exportCsv", "csv"], ["exportJson", "json"]].forEach(([id, kind]) => $(id).addEventListener("click", e => {
  if (H.mode === "local") { e.preventDefault(); localExport(kind); }
}));

/* ----- filter controls ----- */
function resetFilters(reload = true) {
  $("historyFilters").reset();
  if (reload) renderHistory();
}
let searchTimer = 0;
$("fSearch").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => renderHistory(), 250); });
$("historyFilters").addEventListener("change", () => renderHistory());
$("historyFilters").addEventListener("submit", e => e.preventDefault());
$("filterReset").addEventListener("click", () => resetFilters());
$("noMatchReset").addEventListener("click", () => resetFilters());
$("historyMore").addEventListener("click", showMore);

/* ---------- Contact form ---------- */
const CONTACT_FIELDS = ["name", "email", "message", "consent"];
const EMAIL_RE = /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/;
function showFieldErrors(form, errors) {
  form.querySelectorAll("[data-error-for]").forEach(p => {
    const field = p.dataset.errorFor, msg = errors[field];
    p.textContent = msg || ""; p.hidden = !msg;
    if (form[field]) form[field].setAttribute("aria-invalid", msg ? "true" : "false");
  });
}
function validateContact(form) {
  const v = { name: form.name.value.trim(), email: form.email.value.trim(), message: form.message.value.trim() };
  const errors = {};
  if (!v.name) errors.name = "Enter your name.";
  else if (v.name.length > 100) errors.name = "Keep your name under 100 characters.";
  if (!v.email) errors.email = "Enter your email address so we can reply.";
  else if (v.email.length > 200 || !EMAIL_RE.test(v.email)) errors.email = "Enter a valid email address, like name@example.com.";
  if (v.message.length < 10) errors.message = "Write at least 10 characters so we can help (" + v.message.length + " so far).";
  else if (v.message.length > 2000) errors.message = "Keep your message under 2000 characters (" + v.message.length + " now).";
  if (!form.consent.checked) errors.consent = "Please tick the box to agree to how your message is stored.";
  return { values: v, errors };
}
const messageBox = $("cMessage");
function updateCount() {
  const n = messageBox.value.length, c = $("msgCount");
  c.textContent = n + " / 2000"; c.dataset.near = n >= 1900 ? "true" : "false";
}
messageBox.addEventListener("input", updateCount);
$("contactForm").addEventListener("input", e => {  // clear a field's message as soon as the person fixes it
  const p = e.target.name && document.querySelector('[data-error-for="' + e.target.name + '"]');
  if (p && !p.hidden && validateContact($("contactForm")).errors[e.target.name] === undefined) {
    p.hidden = true; e.target.setAttribute("aria-invalid", "false");
  }
});
loadPrivacy().then(p => { if (p) $("consentDays").textContent = plural(p.contact_retention_days, "day"); });

$("contactForm").addEventListener("submit", async e => {
  e.preventDefault();
  const form = e.target, status = $("contactStatus");
  const { values, errors } = validateContact(form);
  showFieldErrors(form, errors);
  status.hidden = true;
  const first = CONTACT_FIELDS.find(f => errors[f]);
  if (first) { form[first].focus(); return; }

  $("contactBtn").disabled = true;
  try {
    const res = await fetch(API_BASE + "/contact", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...values, consent: true, website: form.website.value })
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 400 && data.fields && typeof data.fields === "object") {  // the server's checks, shown next to the field
      const serverErrors = {};
      CONTACT_FIELDS.forEach(f => { if (typeof data.fields[f] === "string") serverErrors[f] = data.fields[f].slice(0, 200); });
      showFieldErrors(form, serverErrors);
      const f = CONTACT_FIELDS.find(x => serverErrors[x]);
      if (f) form[f].focus();
      return;
    }
    if (!res.ok) throw { res, data };
    const priv = await loadPrivacy();
    status.className = "alert alert-success";
    status.textContent = "Message sent. Thank you, we’ll read it soon." +
      (priv ? " It will be deleted after " + plural(priv.contact_retention_days, "day") + "." : "");
    form.reset(); updateCount(); showFieldErrors(form, {});
  } catch (err) {
    status.className = "alert alert-error";
    status.textContent = "Your message wasn’t sent. " + (err && err.res ? safeMessage(err.res, err.data) : ERRORS.network) +
      " What you typed is still here.";
  } finally {
    status.hidden = false; $("contactBtn").disabled = false;
  }
});

/* ---------- Privacy page ---------- */
let privacySeq = 0;
async function renderPrivacy() {
  const box = $("privacyBox");
  const seq = ++privacySeq;
  const p = await loadPrivacy();
  if (seq !== privacySeq) return;
  const sec = (title, items) => {
    const wrap = document.createElement("div");
    wrap.append(el("h2", null, title));
    const ul = el("ul");
    items.forEach(t => ul.append(el("li", null, t)));
    wrap.append(ul);
    return wrap;
  };
  if (!p) {
    box.replaceChildren(el("p", null, "We couldn’t load this server’s current settings. In general: links you scan are checked by this server and sent to the threat databases it uses; scan history and contact messages are stored only if enabled, and are deleted automatically."));
    return;
  }
  const providers = p.lookup_providers.length ? p.lookup_providers.join(" and ") : null;
  box.replaceChildren(
    sec("When you scan a link", [
      "We never open the link. The address is checked by our own pattern rules on the server.",
      providers
        ? "The address is also sent to " + providers + " to see whether it is listed as a threat. " +
          (p.lookup_sent_query ? "That includes anything after a “?” in the link, so don’t scan links that carry private tokens, like password-reset links."
                               : "The part after “?” or “#” is removed first.") +
          " Those services see this server’s address, not yours."
        : "No threat database is set up on this server, so nothing is sent anywhere and results are limited to the pattern checks."
    ]),
    sec("What is saved when you scan", p.history_enabled ? [
      "Server: the scheme, site and path of each link (never the part after “?”), the verdict, the evidence shown with it (which threat database listed the link and which warning signs the address has) and the time, tied to a random anonymous ID in a cookie. There are no accounts. Other visitors cannot see, export or delete your scans.",
      "They are deleted after " + plural(p.history_retention_days, "day") + ", or straight away when you delete one scan or press “Clear all history”. You can download them first with “Export CSV” or “Export JSON”.",
      "This browser: your last 50 scans (the same trimmed addresses, with their evidence) and your light/dark choice, in local storage. “Clear all history” removes them."
    ] : [
      "Server: nothing. Scan history is switched off.",
      "This browser: your last 50 scans (scheme, site and path only, with their evidence) and your light/dark choice, in local storage. “Clear all history” removes them."
    ]),
    ...(p.extension_enabled ? [sec("Browser extension", [
      "If you use the extension, only the links and pages you pick from its right-click menu are checked. Each address (without the part after “#”) is sent to this server and handled as in “When you scan a link” above.",
      "These checks are not saved in scan history and use no cookie. The extension keeps its settings, and the current result in memory until the browser closes."
    ])] : []),
    sec("Contact form", p.contact_enabled ? [
      "If you send a message we store your name, email address and message, and the time, so we can reply. We don’t store your IP address or browser details.",
      "We do this only if you tick the consent box. Messages are deleted after " + plural(p.contact_retention_days, "day") + ".",
      "To have a message deleted sooner, send us a new message from the same email address and ask."
    ] : ["The contact form is switched off on this server, so no messages are stored."]),
    sec("Cookies and other sites", [
      p.history_enabled ? "One cookie, “cs_client”: a random ID that keeps your scan history separate from other people’s. It is not readable by scripts, isn’t sent to other sites, and lasts " + plural(p.history_retention_days, "day") + "."
                        : "No cookies are used.",
      "No analytics, advertising or tracking. The page loads its fonts from Google Fonts, so Google can see that your browser requested them.",
      "Like any web server, this one may keep an access log with your IP address and the time of each request."
    ])
  );
}

/* ---------- Responsive navigation ---------- */
const siteHeader = document.querySelector(".site-header");
const navToggle = $("navToggle");
function setNav(open, restoreFocus) {
  siteHeader.dataset.navOpen = open ? "true" : "false";
  navToggle.setAttribute("aria-expanded", open ? "true" : "false");
  navToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  if (!open && restoreFocus) navToggle.focus();
}
navToggle.addEventListener("click", () => setNav(siteHeader.dataset.navOpen !== "true"));
document.querySelectorAll(".tabs a").forEach(a => a.addEventListener("click", () => setNav(false)));
document.addEventListener("keydown", e => { if (e.key === "Escape" && siteHeader.dataset.navOpen === "true") setNav(false, true); });
document.addEventListener("click", e => { if (siteHeader.dataset.navOpen === "true" && !siteHeader.contains(e.target)) setNav(false); });
window.addEventListener("hashchange", () => setNav(false));
matchMedia("(min-width: 761px)").addEventListener("change", e => { if (e.matches) setNav(false); });

/* ---------- Landing page: quick scan and live status ---------- */
if ($("heroForm")) {
  $("heroForm").addEventListener("submit", e => {
    e.preventDefault();
    const value = $("heroUrl").value.trim(), err = $("heroError");
    if (!value) {
      err.textContent = "Paste a link to check first."; err.hidden = false;
      $("heroUrl").setAttribute("aria-invalid", "true"); $("heroUrl").focus(); return;
    }
    err.hidden = true; $("heroUrl").setAttribute("aria-invalid", "false");
    $("urlInput").value = value; focusScannerNext = false; location.hash = "#/scan"; scan(value);
  });
}
let statusSeq = 0;
async function renderStatus() {
  const box = $("serviceStatus"), text = $("statusText"), seq = ++statusSeq;
  const set = (state, msg) => { if (seq === statusSeq) { box.dataset.state = state; text.textContent = msg; } };
  const ctrl = new AbortController(), timer = setTimeout(() => ctrl.abort(), 6000);
  try {
    const res = await fetch(API_BASE + "/privacy", { signal: ctrl.signal });
    if (!res.ok) throw new Error("status");
    const info = await res.json();
    const providers = Array.isArray(info.lookup_providers) ? info.lookup_providers.filter(x => typeof x === "string").slice(0, 4) : [];
    if (providers.length) set("ok", "Scanner online. Checks " + providers.join(" and ") + ".");
    else set("warn", "Scanner online, but no threat database is set up on this server. Results use address checks only.");
  } catch { set("down", "Can’t reach the scanner right now. Try again in a moment."); }
  finally { clearTimeout(timer); }
}

/* ---------- Scanner: copy a plain-text summary (query strings are left out, like the saved history) ---------- */
function summaryText(d) {
  const code = VERDICTS[d.verdict_code] ? d.verdict_code : "unable_to_verify";
  const lines = ["LinkLens scan result",
    "Verdict: " + VERDICTS[code].label + (d.confirmed ? " (confirmed by a threat database)" : code === "suspicious" ? " (warning, not confirmed)" : ""),
    "Link: " + redactUrl(d.normalized_url || d.url) + " (anything after “?” or “#” left out)",
    "Risk score: " + (Number(d.risk_score) || 0) + " (Suspicious starts at 3)"];
  if (d.scanned_at) lines.push("Scanned: " + new Date(d.scanned_at).toLocaleString());
  const why = (Array.isArray(d.evidence) ? d.evidence : []).filter(x => x.severity !== "info").slice(0, 8);
  if (why.length) lines.push("Why:", ...why.map(x => "- " + String(x.detail || "").replace(/[?#]\S*/g, "").slice(0, 200) + " [" + String(x.source || "").slice(0, 40) + "]"));
  lines.push("Note: “No known threat” means nothing was found, not that a link is safe.");
  return lines.join("\n");
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* fall back below */ }
  const box = document.createElement("textarea");
  box.value = text; box.setAttribute("readonly", ""); box.className = "sr-only"; document.body.append(box); box.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  box.remove(); return ok;
}
let copyTimer = 0;
$("copyResult").addEventListener("click", async () => {
  if (!lastResult) return;
  const btn = $("copyResult"), ok = await copyText(summaryText(lastResult));
  btn.textContent = ok ? "Copied" : "Couldn’t copy"; btn.dataset.state = ok ? "done" : "";
  $("copyStatus").textContent = ok ? "Summary copied to the clipboard." : "Copying isn’t available here. Select the text on the page instead.";
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => { btn.textContent = "Copy summary"; delete btn.dataset.state; $("copyStatus").textContent = ""; }, 2500);
});

/* ---------- Dashboard: filters fold away on small screens ---------- */
const smallScreen = matchMedia("(max-width: 760px)");
function syncFilterCount() {
  const f = readFilters();
  const n = (f.q ? 1 : 0) + (f.verdicts.length ? 1 : 0) + (f.source ? 1 : 0) + (f.days ? 1 : 0) + (f.confirmed ? 1 : 0) + (f.sort !== "newest" ? 1 : 0);
  const badge = $("filtersCount");
  badge.hidden = n === 0; badge.textContent = n;
}
function setFiltersOpen(open) {
  $("historyFilters").dataset.collapsed = open ? "false" : "true";
  $("filtersToggle").setAttribute("aria-expanded", open ? "true" : "false");
}
$("filtersToggle").addEventListener("click", () => setFiltersOpen($("filtersToggle").getAttribute("aria-expanded") !== "true"));
setFiltersOpen(!smallScreen.matches);
smallScreen.addEventListener("change", e => setFiltersOpen(!e.matches));

route();
