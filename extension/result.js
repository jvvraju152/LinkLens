/* Result window. Shows "Checking…", then the verdict, a clear warning for threats, or a plain error.
   Everything from the server or the link is put on the page as text (textContent), never as HTML. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const token = new URLSearchParams(location.search).get("t") || "";
  const KEY = CSX.recordKey(token);
  const PANELS = ["pending", "error", "done", "gone"];
  let current = null;   // the record on screen
  let view = null;      // its presentation (verdicts only)
  let shown = "";

  function show(name) {
    PANELS.forEach((p) => { $(p).hidden = p !== name; });
    shown = name;
  }
  function li(className, parts) {
    const n = document.createElement("li");
    if (className) n.className = className;
    parts.forEach((p) => {
      if (p.bold) { const b = document.createElement("b"); b.textContent = p.text; n.append(b); }
      else n.append(document.createTextNode(p.text));
    });
    return n;
  }

  function renderPending(rec) {
    show("pending");
    $("pendingUrl").textContent = rec.display || "";
    document.title = "Checking… · Cyber Solutions";
  }

  function renderError(rec) {
    const err = rec.error || {};
    show("error");
    $("errorText").textContent = CSX.friendlyError(err.code, {
      origin: err.origin, extensionOrigin: location.origin, retryAfter: err.retryAfter, requestId: err.requestId, serverMessage: err.serverMessage
    });
    $("errorUrl").hidden = !rec.display;
    $("errorUrl").textContent = rec.display || "";
    $("retryBtn").hidden = !(rec.url && CSX.RETRYABLE.includes(err.code));
    $("settingsBtn").hidden = !["network", "origin_not_allowed", "unexpected_response"].includes(err.code);
    document.title = "Not checked · Cyber Solutions";
    $("errorTitle").focus();
  }

  function renderDone(rec) {
    view = CSX.presentResult(rec.result);
    show("done");
    $("done").dataset.level = view.level;
    const badge = $("badge");
    badge.textContent = view.label;
    badge.className = "badge" + (view.level === "danger" ? " badge-danger" : view.level === "warn" ? " badge-warn" : view.level === "ok" ? " badge-ok" : "");
    $("confirmedTag").hidden = !view.confirmed;
    $("headline").textContent = view.headline;
    $("url").textContent = rec.display || "";
    $("summary").textContent = view.summary;
    $("advice").textContent = view.advice;

    const list = $("evidence");
    list.replaceChildren(...view.evidence.map((e) => li("ev-" + e.severity, [{ text: e.source + ": ", bold: true }, { text: e.detail }])));
    $("evidenceBox").hidden = view.evidence.length === 0;
    $("sourceLine").textContent = view.sourceLines.join(" · ");
    $("notes").replaceChildren(...view.notes.map((n) => li("", [{ text: n }])));

    // A listed threat needs a tick before the open button works; the safe choice (Close) is first and focused.
    $("ackRow").hidden = !view.openNeedsAck;
    $("ack").checked = false;
    $("openBtn").textContent = view.openLabel;
    $("openBtn").disabled = view.openNeedsAck;
    const safeToOpen = view.level === "ok";
    $("openBtn").className = "btn " + (safeToOpen ? "btn-primary" : "btn-outline");
    $("closeBtn").className = "btn " + (safeToOpen ? "btn-outline" : "btn-primary");
    document.title = view.label + " · Cyber Solutions";
    (safeToOpen ? $("headline") : $("closeBtn")).focus();
  }

  function render(rec) {
    current = rec || null;
    if (!rec) { show("gone"); document.title = "Link check · Cyber Solutions"; $("goneTitle").focus(); return; }
    if (rec.state === "pending") return renderPending(rec);
    if (rec.state === "error") return renderError(rec);
    if (rec.state === "done" && rec.result) return renderDone(rec);
    show("gone");
  }

  // Open in the person's ordinary browser window (this one is a small popup), then close the warning.
  async function openInBrowser(url) {
    let windowId = null;
    try {
      const win = await chrome.windows.getLastFocused({ windowTypes: ["normal"] });
      await chrome.tabs.create({ url, windowId: win.id });
      windowId = win.id;
    } catch (e) {
      await chrome.windows.create({ url });
    }
    if (windowId !== null) { try { await chrome.windows.update(windowId, { focused: true }); } catch (e) { /* not essential */ } }
  }

  document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => window.close()));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") window.close(); });
  $("ack").addEventListener("change", () => { $("openBtn").disabled = !$("ack").checked; });
  $("openBtn").addEventListener("click", async () => {
    // Re-checked here, not only when the page was rendered: only http(s) addresses are ever opened.
    if (!current || shown !== "done" || !CSX.isWebUrl(current.url)) return;
    if (view && view.openNeedsAck && !$("ack").checked) return;
    await openInBrowser(current.url);
    window.close();
  });
  $("retryBtn").addEventListener("click", () => {
    $("retryBtn").disabled = true;
    chrome.runtime.sendMessage({ type: "recheck", token }, () => { void chrome.runtime.lastError; $("retryBtn").disabled = false; });
  });
  $("settingsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());

  if (!CSX.TOKEN_RE.test(token)) { render(null); return; }
  chrome.storage.onChanged.addListener((changes, area) => { if (area === "session" && changes[KEY]) render(changes[KEY].newValue); });
  chrome.storage.session.get(KEY).then((o) => render(o[KEY]), () => render(null));
})();
