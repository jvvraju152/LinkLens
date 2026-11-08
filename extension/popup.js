/* Toolbar popup: how to use it, and whether the server answers. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let backend = CSX.DEFAULT_BACKEND;

  $("settingsBtn").addEventListener("click", () => { chrome.runtime.openOptionsPage(); window.close(); });
  $("openBtn").addEventListener("click", () => { if (CSX.isWebUrl(backend)) chrome.tabs.create({ url: backend }); window.close(); });

  chrome.storage.local.get("settings").then((o) => CSX.sanitizeSettings(o.settings), () => CSX.sanitizeSettings(null)).then(async (s) => {
    backend = s.backend;
    const up = await CSX.checkHealth(fetch.bind(globalThis), backend);
    $("dot").className = "status-dot " + (up ? "up" : "down");
    $("serverText").textContent = up ? "Connected to " + backend : "Can't reach " + backend + ". Is the server running? Check Settings.";
  });
})();
