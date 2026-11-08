# Cyber Solutions Link Check (browser extension)

Right-click a link, choose **Check link with Cyber Solutions**, and get the same verdict as the website scanner in a small window beside
your page. Listed threats and suspicious links get a clear warning with the evidence. It reuses the Flask backend (`POST /scan`);
there is no second detection engine.

Works in Chromium browsers (Chrome, Edge, Brave). Manifest V3. Not in a web store; load it from this folder.

## Install

1. Start the server (`python urldetection.py` from the project folder, or use your deployed server).
2. Open `chrome://extensions` (`edge://extensions` in Edge) and turn on **Developer mode**.
3. Choose **Load unpacked** and select this `extension` folder.
4. Right-click a link: **Check link with Cyber Solutions**. Right-click an empty part of a page to check the page itself.

With the default setup there is nothing to configure: the manifest pins a key, so the extension always has the ID
`pooegmoiedafmkppnjmddffjbkdepeke`, and the server lists that ID by default (`EXTENSION_ORIGINS` in `.env.example`).
Open the extension's **Settings** to use a different server, to leave the `?query` out of checks, or to test the connection.

## Permissions

| Permission | Why |
| --- | --- |
| `contextMenus` | the two right-click entries (shown only for `http(s)` links and pages) |
| `storage` | your server address and one option (`storage.local`); the current result (`storage.session`, memory only) |
| host access to `127.0.0.1:5000` and `localhost:5000` | the default local server |
| optional: `https://*/*`, `http://127.0.0.1/*`, `http://localhost/*` | **not granted at install.** Asked for, for the one address you type in Settings, when you press Save. Switching servers hands the old permission back. |

Not requested: tabs, activeTab, scripting, webRequest, history, cookies, downloads, content scripts, or access to the pages you visit.

## What happens when you check a link

1. The browser hands over the address from the menu click. Anything that is not `http(s)` (`javascript:`, `data:`, `file:`, `chrome:`, `mailto:` …)
   is refused in the extension, before any request.
2. The address without its `#fragment` (and without `?query` if you chose that) is sent to **your server only**: no cookies, no referrer,
   a 15 second timeout, and `redirect: "error"`, so a server that answers with a redirect fails the check instead of being followed.
3. The server's answer is accepted only if it has a known verdict. A malformed or unknown answer shows an error, never a reassuring result.
4. The result opens in a small window. The window's address holds a random token, not the link; the link is held in memory only
   (`storage.session`: gone when the browser closes, pruned after an hour or 20 results).
5. Text from the server is shown as text, never as HTML.

## Redirects and navigation

* The extension **never opens or fetches the link it checks.** The server doesn't either (it only queries threat databases, without following redirects).
* A shortener or a redirect hidden in a query parameter can lead somewhere else. Only the address you chose is checked, and the result says so.
* **Open anyway** / **Open link** open the link in your ordinary browser window (not inside the small popup), only after re-checking it is `http(s)`.
  For a listed threat the button stays off until you tick "I understand…". **Close** is the focused default for threats and warnings.
* After you open a link, your browser follows its redirects as usual. That part is outside the extension's control.

## Not automatic, on purpose

It checks only what you pick. Checking every page you visit would need permission to see your browsing and would send it to a server,
which conflicts with asking for minimal permissions. If you want that later, it should be an opt-in using optional permissions.

## Troubleshooting

| Message | Fix |
| --- | --- |
| The server doesn't allow this extension yet | Add the origin shown in Settings to `EXTENSION_ORIGINS` in the server's `.env`, restart the server. |
| Couldn't reach the server | Is it running? Is the address in Settings right? Remote servers must be `https://`. |
| Too many checks | The server's rate limit; wait the number of seconds shown. |

* `lib/common.js` holds all logic that doesn't touch the browser (link and server validation, the API client, result model); everything else is thin glue.
* To publish your own build: remove `"key"` from `manifest.json` (the store assigns the ID), then add the new ID to `EXTENSION_ORIGINS`
  and update `BUNDLED_EXTENSION_ORIGIN` in `detection/settings.py` if you want it to be the default.
* The `EXTENSION_ORIGINS` allow-list keeps websites and other origins off the API. It is **not authentication**: anything that can reach the server can still call `/scan`, within the rate limits.
