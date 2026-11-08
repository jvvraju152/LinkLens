/* Settings page: the server address (with the browser permission to reach it), one privacy option, and the
   origin a server has to list. Messages are fixed text; nothing from the network is shown as HTML. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const BACKEND_ERRORS = {
    empty: "Enter the address of your Cyber Solutions server.",
    invalid: "That isn't a valid address. Use something like https://scanner.example.com or http://127.0.0.1:5000.",
    insecure: "Use https:// for a server on another computer. Plain http:// is only allowed on this computer (127.0.0.1 or localhost).",
    credentials: "Leave the username and password out of the address.",
    path: "Use just the server's address, with nothing after it (no path, ? or #)."
  };

  function say(text, kind) {
    const s = $("status");
    s.textContent = text;
    s.className = "alert" + (kind === "error" ? " alert-error" : kind === "success" ? " alert-success" : "");
    s.hidden = false;
  }

  async function load() {
    let stored;
    try { stored = (await chrome.storage.local.get("settings")).settings; } catch (e) { stored = null; }
    return CSX.sanitizeSettings(stored);
  }

  // Reaching a server needs browser permission for that one address. The defaults are granted at install; anything
  // else is asked for here, when the person presses a button.
  async function ensureAccess(origin) {
    const pattern = origin + "/*";
    try {
      if (await chrome.permissions.contains({ origins: [pattern] })) return true;
      return await chrome.permissions.request({ origins: [pattern] });
    } catch (e) {
      return false;
    }
  }
  // Switching servers hands the old permission back, unless it is one of the defaults the manifest declares.
  async function releaseAccess(origin) {
    const pattern = origin + "/*";
    if ((chrome.runtime.getManifest().host_permissions || []).includes(pattern)) return;
    try { await chrome.permissions.remove({ origins: [pattern] }); } catch (e) { /* nothing to release */ }
  }

  function readForm() {
    const parsed = CSX.normalizeBackend($("backend").value);
    if (!parsed.ok) { say(BACKEND_ERRORS[parsed.reason] || BACKEND_ERRORS.invalid, "error"); return null; }
    return parsed.origin;
  }

  $("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const origin = readForm();
    if (!origin) return;
    const previous = (await load()).backend;
    if (!(await ensureAccess(origin))) {
      say("The browser wasn't given permission to contact " + origin + ", so nothing was saved.", "error");
      return;
    }
    await chrome.storage.local.set({ settings: { backend: origin, stripQuery: $("stripQuery").checked } });
    if (previous !== origin) await releaseAccess(previous);
    $("backend").value = origin;
    say("Saved.", "success");
  });

  // A real check of a harmless address, so the whole path is tested: permission, the server's allow-list, the answer.
  $("testBtn").addEventListener("click", async () => {
    const origin = readForm();
    if (!origin) return;
    $("testBtn").disabled = true;
    say("Testing…");
    try {
      if (!(await ensureAccess(origin))) { say("The browser wasn't given permission to contact " + origin + ".", "error"); return; }
      const out = await CSX.checkLink(fetch.bind(globalThis), origin, "https://example.com/");
      if (out.ok) say("Connected. " + origin + " answered a test check of https://example.com/. Save to use it.", "success");
      else say(CSX.friendlyError(out.code, { origin, extensionOrigin: location.origin, retryAfter: out.retryAfter, requestId: out.requestId, serverMessage: out.serverMessage }), "error");
    } finally {
      $("testBtn").disabled = false;
    }
  });

  $("resetBtn").addEventListener("click", () => {
    $("backend").value = CSX.DEFAULT_BACKEND;
    $("stripQuery").checked = false;
    say("Defaults filled in. Press Save to keep them.");
  });

  const envLine = "EXTENSION_ORIGINS=" + location.origin;
  $("envLine").textContent = envLine;
  $("copyBtn").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(envLine); say("Copied."); } catch (e) { say("Couldn't copy. Select the line and copy it by hand.", "error"); }
  });

  load().then((s) => { $("backend").value = s.backend; $("stripQuery").checked = s.stripQuery; });
})();
