/* LinkLens Link Check: service worker.

   What it does: adds two right-click entries, and when one is used it sends that one address to the LinkLens
   server and shows the verdict in a small window.
   What it never does: read or watch your browsing, open a link for you, fetch the link itself, or check anything you
   did not ask about. It has no content scripts and no access to tabs, history or cookies. */
importScripts("lib/common.js");

const MENU_LINK = "cs-check-link";
const MENU_PAGE = "cs-check-page";
const WEB_PATTERNS = ["http://*/*", "https://*/*"];   // the entries only appear for web links and web pages

const ignoreLastError = () => void chrome.runtime.lastError;

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    ignoreLastError();
    chrome.contextMenus.create({
      id: MENU_LINK, title: "Check link with LinkLens", contexts: ["link"], targetUrlPatterns: WEB_PATTERNS
    }, ignoreLastError);
    chrome.contextMenus.create({
      id: MENU_PAGE, title: "Check this page with LinkLens", contexts: ["page"], documentUrlPatterns: WEB_PATTERNS
    }, ignoreLastError);
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  const raw = info.menuItemId === MENU_LINK ? info.linkUrl : info.menuItemId === MENU_PAGE ? info.pageUrl : null;
  if (raw) startCheck(raw).catch((e) => console.error("Link check failed:", e && e.message));
});

// The result window asks for a second attempt by token; nothing else is accepted.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message || message.type !== "recheck" || !CSX.TOKEN_RE.test(String(message.token))) return false;
  runCheck(message.token).then(() => sendResponse({ ok: true }), () => sendResponse({ ok: false }));
  return true;
});

/* ---------- settings and short-lived results ---------- */
async function loadSettings() {
  try {
    const { settings } = await chrome.storage.local.get("settings");
    return CSX.sanitizeSettings(settings);   // a missing or damaged value falls back to the defaults
  } catch (e) {
    return CSX.sanitizeSettings(null);
  }
}

// Results live in storage.session: memory only, gone when the browser closes, and pruned after an hour or 20 results.
async function getRecord(token) {
  const key = CSX.recordKey(token);
  return (await chrome.storage.session.get(key))[key];
}
const saveRecord = (token, record) => chrome.storage.session.set({ [CSX.recordKey(token)]: record });

async function pruneRecords() {
  const stale = CSX.staleKeys(await chrome.storage.session.get(null), Date.now());
  if (stale.length) await chrome.storage.session.remove(stale);
}

/* ---------- the check ---------- */
async function startCheck(raw) {
  const settings = await loadSettings();
  const token = CSX.newToken(crypto);
  await pruneRecords();
  const prepared = CSX.prepareLink(raw, { stripQuery: settings.stripQuery });
  if (!prepared.ok) {
    // Not a web link (or unusable): explain in the window. Nothing is sent anywhere.
    await saveRecord(token, { state: "error", error: { code: prepared.reason }, ts: Date.now() });
    return openResultWindow(token);
  }
  await saveRecord(token, { state: "pending", url: prepared.url, display: prepared.display, ts: Date.now() });
  await openResultWindow(token);   // shown straight away with "Checking…", then updated when the answer arrives
  return runCheck(token);
}

async function runCheck(token) {
  const record = await getRecord(token);
  if (!record || !record.url || !CSX.isWebUrl(record.url)) return;
  const settings = await loadSettings();
  await saveRecord(token, { state: "pending", url: record.url, display: record.display, ts: record.ts });
  const out = await CSX.checkLink(fetch.bind(globalThis), settings.backend, record.url);
  if (!(await getRecord(token))) return;   // pruned meanwhile: don't bring it back
  await saveRecord(token, out.ok
    ? { state: "done", url: record.url, display: record.display, result: out.result, ts: record.ts }
    : { state: "error", url: record.url, display: record.display, ts: record.ts,
        error: { code: out.code, retryAfter: out.retryAfter || null, requestId: out.requestId || null, origin: settings.backend, serverMessage: out.serverMessage || null } });
}

// A small window keeps the page you were on in view. The window's address holds only a random token, never the link.
async function openResultWindow(token) {
  const url = chrome.runtime.getURL("result.html?t=" + token);
  try {
    await chrome.windows.create({ url, type: "popup", width: 520, height: 700, focused: true });
  } catch (e) {
    await chrome.tabs.create({ url });
  }
}
