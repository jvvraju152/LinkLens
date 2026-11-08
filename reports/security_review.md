# Security review (Stage 4)

A self-review of the code as delivered at the end of Stage 3, the changes made, and the test that pins each one.
It is **not an independent audit.** Beyond the unit tests, the app was run in a real browser (Chromium) to check the
strict CSP, the forms and the error handling, and five protections were deliberately broken one at a time to confirm
a test fails (Retry-After NaN guard, no-redirect setting, per-browser history scoping, CSP, cross-origin check).

## Findings fixed

| # | Finding (before) | Impact | Fix | Pinned by |
|---|---|---|---|---|
| 1 | `/history` returned and `DELETE /history` erased **every visitor's** scans | Privacy breach; any visitor could wipe all history | Per-browser anonymous id in an HttpOnly, SameSite=Strict cookie; only its hash is stored; every read/delete scoped to it; old unscoped rows purged on upgrade | `test_one_browsers_history_is_invisible_to_another`, `…clearing_history_only_clears_your_own`, `…database_stores_only_a_hash…` |
| 2 | Provider calls followed redirects; `X-Goog-Api-Key` / `Auth-Key` headers are not stripped on a cross-host redirect | API key could be sent to another server | `allow_redirects=False`; any 3xx is an error | `test_requests_never_follow_redirects…`, `test_a_redirect_is_an_error…` |
| 3 | `Retry-After: nan` made the cooldown comparison always false | A provider could never be paused, hammering a quota that had said stop | Non-finite values fall back to the default cooldown | `test_retry_after_nan_cannot_switch_the_cooldown_off` |
| 4 | `repr(Config)` printed both API keys | Keys in tracebacks or debug logs | `field(repr=False)`; a log filter also masks configured keys | `test_config_repr_never_contains_api_keys`, `test_secret_filter_scrubs_keys…` |
| 5 | No overall deadline on lookups; a new thread pool per scan | A hung provider held threads; bursts started unbounded threads | One shared 8-worker pool; per-scan deadline; hung lookups reported as errors, never "clear" | `test_scan_returns_by_the_deadline…`, `test_lookup_concurrency_is_bounded` |
| 6 | No protection against a provider that keeps timing out | Every scan waited on a dead service | Circuit breaker: pause after repeated timeouts/5xx, then resume | `test_repeated_timeouts_pause_the_provider…` |
| 7 | Rate limiter kept a deque per address forever; proxy headers undefined | Memory exhaustion; spoofable client address | Bounded keys; `X-Forwarded-For` honoured only when `TRUSTED_PROXY_COUNT` is set; global budget protects provider quotas | `test_limiter_memory_is_bounded…`, `test_spoofed_forwarded_for…`, `test_global_budget…` |
| 8 | CORS via a library with permissive defaults; no origin check on writes | Cross-site requests could trigger scans, messages or history deletion | Own exact-match CORS (the dependency was removed); 403 for unlisted origins on POST/DELETE; `*` and `null` never honoured by default | `test_cross_origin_post_from_unlisted_site…`, `test_wildcard_origin…`, `test_null_origin…` |
| 9 | CSP allowed `unsafe-inline` scripts and styles | Weaker XSS defence | Inline theme script moved to `theme.js`; strict CSP, `frame-ancestors`, `base-uri`, `form-action`, `object-src`, COOP/CORP, Permissions-Policy, optional HSTS | `test_security_headers_present`, `test_page_has_no_inline_script_style_or_event_handlers` |
| 10 | `app = create_app()` ran at import | Importing the module wrote a database | Removed; `wsgi.py` is the deployment entry point | `test_importing_the_module_does_not_create_an_app…` |
| 11 | Debug mode could be combined with a public host; `/health` listed provider setup | Interactive debugger exposed; information disclosure | Refuses to start; `/health` minimal unless `HEALTH_DETAIL=1` | `test_debug_mode_is_refused…`, `test_health_does_not_reveal…` |
| 12 | Raw exception text, status lines and the dev-server hint could reach users | Information leak; confusing messages | One JSON error shape with request ids; frontend shows fixed messages only | `test_unexpected_server_error_leaks_nothing…`, browser run |
| 13 | Contact: no consent, unbounded file, default permissions, project-root location, no retention, no honeypot | Over-collection and indefinite storage of personal data | Consent required; size cap; 0600; `data/`; automatic retention; honeypot; control-character stripping; operator deletion tool | `test_contact_*` |
| 14 | Browser history kept full URLs including `?token=…` | Tokens persisted in local storage | Only scheme+host+path saved; existing entries cleaned on load | browser run (token not present after scan or migration) |
| 15 | Provider responses unbounded; timeouts unvalidated | Memory use; zero/negative/NaN timeouts | 1 MB cap; timeouts clamped to 0.5–15 s | `test_oversized_responses…`, `test_timeouts_are_clamped…` |
| 16 | Over-long pasted links were silently truncated by `maxlength` | A different link scanned than the one pasted | Removed `maxlength`; a clear validation message instead | browser run |

## Known gaps (not fixed here)

* No authentication or authorisation model beyond the anonymous cookie.
* Rate limiting is per process.
* No encryption at rest; no TLS in the app itself.
* The exception message of an unexpected error is written to the server log, which may therefore contain
  data from the request that triggered it.
* Dependencies are version-ranged, not pinned by hash, and were not scanned for known vulnerabilities.
* Sandbox testing used stand-ins for `tldextract` and `pytest` because the environment had no network; run the suite
  with the real packages (`python -m pytest`).

## Stage 5 addendum: history and dashboard

No accounts were introduced; history stays scoped to the anonymous per-browser cookie. New endpoints (`GET /history` filters,
`GET /history/export`, `DELETE /history/<id>`) all filter on the cookie's hash in SQL, so ids cannot be guessed across browsers.
Pinned by `tests/test_history.py` (two-browser isolation for search, stats, export and delete; SQL-injection and LIKE-wildcard
inputs; CSV formula neutralising; same-origin check on delete). Isolation and CSV protections were each removed in turn to confirm a
test fails. Browser run (Chromium): strict CSP kept (styles set through the DOM, no inline markup), no horizontal overflow at 320/390px.
Still true: no authentication, no encryption at rest. Saved evidence is the scanner's fixed wording, but it is stored in addition to the URL.

## Stage 6 addendum: browser extension

New attack surface: an extension that sends links to this API from the browser, and a window that shows results. Threat model and what pins each control.

| # | Risk | Control | Pinned by |
|---|---|---|---|
| 1 | The API's origin check refuses extension requests, tempting a loose fix (allow everything) | A separate exact-match `EXTENSION_ORIGINS` list (`chrome-extension://<32 letters>`; wildcards and other schemes dropped); an allowed extension may use only `/scan` and `/health` | `test_extension.py`: unlisted/lookalike origins 403, `/contact` and `DELETE /history` 403, preflight scoped to `/scan` |
| 2 | Extension checks create history rows under a fresh cookie id each time (no cookie jar) | Extension requests are not saved and set no cookie | `test_extension_checks_are_not_saved_and_issue_no_cookie` |
| 3 | Extension used to dodge rate limits | Same per-address and global limits | `test_extension_checks_count_against_the_same_rate_limit` |
| 4 | Over-broad browser permissions | `contextMenus` + `storage` only; loopback host access by default; other servers per-origin at runtime; no content scripts, tabs, history, cookies | `test_manifest_*` |
| 5 | A hostile or mistaken server answer shown as safe, or as markup | Verdict whitelist (unknown = error), clamped/cleaned text, `textContent` only, no `innerHTML`/`eval` anywhere | `common.test.js` ("unknown or missing verdict…", "clamped"), `test_scripts_never_build_html…` |
| 6 | Redirects: server bounces the request elsewhere; links that hide their destination | `redirect: "error"`, no cookies, no referrer, timeout; the link itself is never fetched; shortener/redirect results carry an explicit "destination not checked" note | `common.test.js`, `test_only_the_shared_client_talks_to_the_network…`, `test_redirect_hiding_links_carry_the_evidence_codes…` |
| 7 | Navigation: `javascript:`/`data:`/`file:` links; opening a threat by accident; opening inside the popup | Non-web schemes refused before any request and again before opening; threats need an explicit tick; Close is the focused default; links open in a normal window | `common.test.js` (scheme table), browser run |
| 8 | Link leaks: fragment/token in the window address, history or logs | Only a random token is in the window address; link in memory-only storage; fragment never sent; optional `?query` removal; display form is scheme+host+path | `common.test.js`, browser run |
| 9 | Server address abuse (plain http to a remote host, credentials, paths) | https required except loopback; no credentials or paths; bad saved settings fall back to defaults | `common.test.js` |

Browser run (Chromium, extension loaded unpacked, local server with stand-in threat checkers): pinned ID verified; threat, clean, shortener and
refused-scheme results; Open-anyway gating and placement; settings validation and end-to-end test; server-refuses-extension and server-down messages.

Known gaps: the allow-list is not authentication; the right-click menu click itself is native browser UI and was not automated (the handler it
calls was run directly); only Chromium was tried (not Edge, Brave or Firefox); the current link is held in session memory for up to an hour; no web-store listing or signing.
