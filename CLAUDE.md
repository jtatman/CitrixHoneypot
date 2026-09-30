# CLAUDE.md

Guidance for Claude Code when working in this repo.

## Purpose

Fork of Bontchev's/MalwareTech's CitrixHoneypot (Twisted HTTPS server emulating a Citrix ADC/Gateway, originally only CVE-2019-19781).
Goal of this fork: a **local-network-only test bed** that imitates recent NetScaler ADC / Gateway (and related Citrix) web surfaces, so
scanners and exploit tooling for recent Citrix CVEs can be observed and logged safely.

Ground rules:
- Emulate *observable behavior* (routes, status codes, headers, response bodies, fingerprints). Never ship working exploit code or
  real payload execution. Attacker input is only ever parsed, logged, and answered with canned responses.
- Never execute, `eval`, shell out with, or write to disk anything derived from request data.
- Bind to a configured local interface; no outbound calls are needed or allowed (no GeoIP downloads, no public-IP lookup).
- Any CVE/route detail added must be traceable to a public advisory or public scanner (cite URL in a comment). Verify before adding; don't guess.

## Layout

```
CitrixHoneypot.py      entry point: argparse + config, Twisted SSL endpoint, Site(Index)
core/protocol.py       Index(Resource): single render() entry point: build Ctx -> dispatch routes -> log/emit event -> respond
core/profile.py        Profile dataclass + YAML loader/validator; `Profile.state(cve)` = explicit override > derived from `build` > vulnerable
core/cvedb.py          fix-version lookup over core/data/cves.json (25 CVEs, vendored from jtatman/citrixscan via tools/extract_cves.py)
core/tls.py            ensure_cert(): self-signed key/cert generated at startup if missing (CN from the profile)
profiles/              <name>.yaml appliance profiles (select with `--profile` / `[honeypot] profile` / env HONEYPOT_PROFILE)
core/routes/           (order matters: the list in routes/__init__.py is match order, catch-alls last) declarative route table (Route/Hit/Ctx in __init__.py; one module per CVE/product family, e.g. cve_2019_19781.py; ioc_probes.py is CVE-agnostic attempt/IOC logging; waf_block.py is the opt-in AppFirewall-mimicry catch-all, registered before cve_2019_19781's broad catch-alls but after everything CVE/IOC-specific)
tests/                 pytest golden tests driving Index.render() with DummyRequest (run from anywhere; conftest chdirs to repo root)
core/tools.py          helpers: url normalisation, IP helpers, event writing, plugin loading
core/config.py         ConfigParser + env-var override (SECTION_OPTION), reads etc/honeypot.cfg.base, etc/honeypot.cfg, ./honeypot.cfg
core/logfile.py        Twisted daily log file + UTC formatting (monkeypatches FileLogObserver)
core/output.py         Output plugin base class
output_plugins/        jsonlog.py (works), mysql.py (works, needs mysqlclient), sqlite.py (EMPTY stub)
responses/             static bodies: login.html, 403.html, smb.conf, gold_star.html
etc/                   honeypot.cfg.base (defaults, do not edit), honeypot-launch.cfg.base
bin/honeypot           start/stop wrapper (venv + authbind)
ssl/                   expects key.pem + cert.pem (gitignored; generation in docs/INSTALL.md)
```

Event dict schema (consumed by all plugins): `eventid` (`citrix.connection` | `citrix.payload`), `timestamp`, `unixtime`, `src_ip`,
`src_port`, `dst_ip`, `dst_port`, `sensor`, `request`, `url`, `message`, and for payloads `body`, `payload`. Since Phase 1 also `cve`, `route_id` (additive; MySQL ignores them). Keep it backward compatible
(MySQL schema in `docs/sql/mysql.sql`) or version it.

## Run / test

```
pip install -r requirements.txt pytest ruff   # MySQL plugin: pip install -r requirements-mysql.txt
pytest -q && ruff check .
openssl req -x509 -newkey rsa:2048 -nodes -keyout ssl/key.pem -out ssl/cert.pem -days 365 -subj /CN=localhost
python CitrixHoneypot.py -a 127.0.0.1 -p 8443
curl -sk 'https://127.0.0.1:8443/vpn/../vpns/cfg/smb.conf'   # note: use --path-as-is
```
CI: `.github/workflows/ci.yml` (ruff + pytest, py3.10/3.12). Add a pytest case with any change to routing.
Caveat: `DummyRequest.setHeader` appends instead of replacing (real Twisted replaces), so use `responseHeaders.addRawHeader` for multi-valued headers.
Default profile is still the legacy `adc-12.1-vulnerable` (kept for parity); use `--profile adc-14.1-73.33-vulnerable` for the modern surface.
Don't `pkill -f` the honeypot from a shell that includes its name in the command line; kill by PID.
Config precedence: env var `SECTION_OPTION` > `honeypot.cfg` > `etc/honeypot.cfg.base`.
Run from repo root: `responses/` and `etc/` are opened via relative paths.

## Code review findings (original state; status noted per item)

Stack: Python 3 (py2 compat cruft remains), Twisted `Resource` with `isLeaf=True`, single 250-line request handler.
CVE-2019-19781 only; the Citrix fingerprint is thin and dated.

Bugs (**FIXED** in Phase 0/1 unless noted):
0. (found later, worst one) `Index.render` was overridden to call `render_GET` for every method, so `render_HEAD`/`render_POST` were dead code and POST
   exploit payloads were never logged as `citrix.payload`. FIXED: one `render()` dispatches on method via the route table.
1. `core/protocol.py` `render_GET`: `if self.struggle_check(...): self.send_response(...)` has no `return` - falls through and sends twice/continues.
2. `render_POST`: `parse_qs(body)['title'][0]` raises `KeyError` on any POST without `title` (500 + lost event); `int(Content-Length)` and
   `.decode('utf-8')` unguarded (non-UTF8 body crashes). Every POST with a body is logged as `citrix.payload`/"Exploit" regardless of path.
3. `send_response`: repeated `setHeader('Set-Cookie', ...)` **overwrites** - only the last cookie is sent. Needs `addRawHeader`/`cookies`.
   Also `Content-Length` is `len(str)` (chars, not bytes), and `Server: Apache` is not what NetScaler sends.
4. Typo `'WARNINg'` log level (type 3 scan). Type 3 (`services.html`) serves `smb.conf` body - probably wrong.
5. `render_HEAD` and `render_GET` duplicate ~50 lines of event building; `render()` maps *all* other methods (PUT/DELETE/custom) to GET.
6. `get_page` uses relative `responses/` path and a class-level dict cache (`page_cache` keys hard-coded).
7. FIXED. `tools.getutctime`/`logfile.myFLOformatTime` use `datetime.utcfromtimestamp` (deprecated in 3.12, removed later) - use `datetime.fromtimestamp(t, timezone.utc)`.
8. (OPEN) `tools.get_real_ip/port` trust `X-Real-IP` / `X-Real-Port` from *any* client (spoofable). Fine only if behind a trusted proxy; make opt-in.
9. FIXED. Logging `request.uri` raw: log-injection risk (newlines) in text log; sanitise/escape.
10. (OPEN) `logfile.py` monkeypatches Twisted internals (`FileLogObserver.emit/formatTime`) - fragile across Twisted versions.
11. FIXED 2026-09-30 (found via nmap's `http-waf-detect` NSE script). `Ctx.raw_segments`/`Ctx.segments` split the raw path on `/`
    without first stripping the query string, so `GET /?x=1` produced `['?x=1']` instead of the empty root segment list the login
    route matches on -- 404 instead of the login page, on completely ordinary traffic (any GET with query params). Predates this
    fork (same flaw in the original `url_path` computation). See `core/routes/__init__.py`'s `Ctx.build`.

Still open / found during Phase 1: type-1 scan (`/vpn/../vpns/`) returns HTTP 200 with a 403 *body* (no `setResponseCode`; check what the
scanners actually key on before changing); HEAD responses report `Content-Length: 0` even where GET has a body; type-3 still serves `smb.conf`.

Packaging / ops (FIXED in Phase 0 except where noted; MySQL plugin py2 shims left, excluded from ruff):
- `requirements.txt`: `setuptools<45` pin, `configparser>=3.5` (py2 backport), unused `geoip2`/`maxminddb` (MySQL plugin only), mysqlclient mandatory
  for install though optional at runtime. No lockfile / `pyproject.toml`.
- `Dockerfile`: unpinned `FROM python`, runs as root, no non-root port strategy, copies whole repo.
- `output_plugins/sqlite.py` is an empty stub; `etc/honeypot.cfg.base` and `docs/TODO.md` list elasticsearch/textlog/hpfeeds as unimplemented.
- Python 2 shims (`try: urllib.parse except ImportError`, `from __future__`) can go.
- Licence is the joke "MalwareTech Public Licence"; keep the header intact.

Fingerprint fidelity gaps (why modern scanners/Shodan-style checks won't treat this as NetScaler):
- Static cookie set with 1999 expiry, `Server: Apache`, no `Via`/`Cache-control` combos real ADC sends, login page is a 2019 stub with no
  `/vpn/index.html` assets (`/vpn/js/...`, `/logon/LogonPoint/...`), no version strings, no `/vpn/pluginlist.xml`, no favicon/`Citrix-Gateway` title.
- Single TLS cert story; no configurable cipher/TLS version profile.

## Modernization roadmap (proposed - confirm with the user before starting each phase)

**Phase 0 - Hygiene (DONE) (no behavior change intended, except bug fixes above)**
- Add `pyproject.toml`, drop py2 shims, pin sane minimums (Twisted>=24, pyOpenSSL, cryptography); make mysqlclient/geoip optional extras.
- Fix bugs 1-6, add pytest + ruff + GitHub Actions; pin Docker base (`python:3.12-slim`), non-root user, `CAP_NET_BIND_SERVICE` or high port.
- Golden-file tests for the existing CVE-2019-19781 responses so refactors can't regress them.

**Phase 1 - Refactor to a route table (DONE except event fields `matched`/`headers`/`body_sha256`/`body_b64`)**
- Replace the if/elif chain with a declarative registry: `Route(method, matcher, cve, handler)` in `core/routes/` (one module per CVE/product family).
- Normalise once (percent-decode, collapse `../`, lowercase where NetScaler does) and hand handlers a parsed request object; centralise event emission.
- Event schema v2: add `cve`, `route_id`, `matched` (bool), `headers` (allow-listed), `body_sha256`, `body_b64` (size-capped). Keep old fields.

**Phase 2 - Profile system ("imitate version X") (DONE: product/build, server header, extra headers, cookies, login page, TLS CN, per-CVE vulnerable/patched/off derived from build; patched = still logged, `patched: true` in event, profile's patched_response served. NOT done: real per-build header/cookie/asset data, gzip MTIME fingerprint)**
- `profiles/<name>.yaml` declares product, build string, headers, cookie set (proper multi-Set-Cookie), TLS cert subject/CN, login page assets, which
  routes are *vulnerable-looking* vs *patched-looking* for that build. Select via `honeypot.cfg` `profile = adc-13.1-49`.
- Lets one test bed emulate pre- and post-patch builds of the same CVE to test scanner discrimination.

**Fingerprint surface to serve (from jtatman/citrixscan, a defensive scanner; MIT; it has version->CVE data but no exploit request examples)**
Scanner probe paths the honeypot should answer like a NetScaler for it to be recognised, then classified by build (Phase 3 prerequisite):
`/vpn/index.html`, `/logon/LogonPoint/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do`, `/oauth/idp/.well-known/openid-configuration`,
`/saml/login`, `/metadata/saml/idp`, `/nitro/v1/config/nsversion`, `/vpn/pluginlist.xml`, `/vpn/js/gateway_login_view.js`,
`/logon/LogonPoint/custom/strings.en.js`, `/epatype`, `/vpn/versioninfo.xml`, `/epa/scripts/win/nsepa_setup.exe`.
Highest-value item: `/vpn/js/rdx/core/lang/rdx_en.json.gz` - the gzip MTIME header field is how scanners (Fox-IT technique) map a host to an exact
build; serve a gzip whose MTIME matches the profile's `build` (citrixscan has a 228-entry timestamp table in `RDX_EN_STAMP_TO_VERSION`).
Also a `NSC_*` cookie / `NSxx: Build y.z` string check (`FIRMWARE_PATTERNS`, `HEADER_PATTERNS`). IoC/webshell paths (`IOC_PATHS`) and management
paths (`MISCONFIG_PATHS`: `/menu/neo`, `/nitro/v1/config/*`, `/gui/`, `/nsconfig/ns.conf`) must NOT look present/unauthenticated on a clean profile.
Also known: the CISA checker only matches the body text `You don't have permission to access /vpns/` (status ignored); nuclei needs status 200 + `[global]`.

**Scanner behaviour research: see `docs/SCANNER_SURFACE.md`** (vigolium, katana, nuclei Citrix templates with per-CVE request and match conditions).
Key takeaways: vigolium has no Citrix modules of its own (its known-issue-scan embeds nuclei) but drops hosts that show a NetScaler WAF fingerprint on 403/429
(`Cneonction`/`nnCoection`, `NSC_` cookies); unknown paths currently return 200 (soft-404 problem); login page lacks Citrix JS markers katana/wappalyzer use.

**Phase 3 - Recent Citrix vulnerability surfaces (STARTED: netscaler-surface fingerprint, patch oracle, 404 default, plus the memory-overread family
below; see docs/SCANNER_SURFACE.md for what remains)** (candidate list from memory of public advisories - verify each against NVD/Citrix
bulletins/public scanner templates such as nuclei/watchTowr before implementing)
- CVE-2019-19781 (done; extend), CVE-2020-8193/8195/8196 "memory-overread family" (DONE) (unauth `/menu/ss`,`/menu/neo`,`/menu/stc`, `/pcidss/report`,
  `/rapi/filedownload` -> fake `/etc/passwd`; fixed versions verified against NVD, advisory CTX276688; 8195/8196 share the state, no distinct public request shape found)
- CVE-2022-27510 / 27518 (Gateway auth bypass / SAML RCE): SKIPPED for now -- no nuclei template and no public write-up gives a
  concrete, safe-to-emulate HTTP request shape (write-ups describe internals, not a PoC). fixed_versions are in core/data/cves.json
  (from citrixscan) for state derivation only; add a route if/when a public detection template appears.
- CVE-2023-3519 "memory-overread family" (DONE) (gateway RCE; `POST /saml/login` -> `SAML Assertion verification failed;`)
- CVE-2023-4966 "CitrixBleed" (DONE) (`GET /oauth/idp/.well-known/openid-configuration` + oversized `Host` -> canned *fake* hex leak matching
  nuclei's extractor regex; `POST /logon/LogonPoint/Authentication/GetUserName` session-replay logging)
- CVE-2023-6549 (DONE) (`GET /nf/auth/startwebview.do` + oversized `Host` -> canned body with the two markers nuclei matches on)
- CVE-2023-6548 (the appliance's own **NSIP/CLIP/SNIP management interface** -- built into every ADC/Gateway box, distinct from
  NetScaler *Console*/ADM, a separate fleet-management product with its own CVEs like 2024-6235; requires authenticated access to it,
  which historically meant either misconfigured internet exposure or an attacker pivoting there after breaching the internal network
  -- see `ioc_probes.py`'s `MISCONFIG_PATHS` for the generic, unauthenticated "is this surface reachable at all" signal we DO emit),
  CVE-2024-8534/8535, CVE-2025-6543/7775/7776/8424:
  RESEARCHED, SKIPPED -- the bar here is "a honeypot fingerprints attempts", not "byte-perfect exploit confirmation" (see the
  CVE-2026-88771 entry above), so this was checked against IOC/threat-intel write-ups (GreyNoise, Mandiant, watchTowr) too, not just
  formal PoC/nuclei coverage. Still nothing: these are memory-corruption/crash-class bugs (DoS or internals-only RCE) where even the
  IOC-focused sources give no network-observable request shape (Mandiant's CVE-2023-3519 IOC scanner, for comparison, is disk/forensic
  artifact hunting on the appliance itself, not a wire-level pattern a honeypot could reproduce). 6548 also requires authenticated
  management-interface access, out of scope for an unauthenticated web honeypot. Their fixed_versions are still in
  core/data/cves.json (from citrixscan) for state derivation. Revisit if a public IOC or detection template ever names a request shape.
- CVE-2024-6235 (NetScaler *Console*, not ADC/Gateway -- different product/port) has a real nuclei template (credential/session-secret
  exposure) but Console isn't emulated by any current profile; candidate for a future Console profile, not implemented.
- CVE-2026-3055 (DONE) (`GET /wsfed/passive?wctx` -> 302 + `NSC_TASS=<base64>` cookie decoding to a fake `wctx=...` leak)
- CTX697096 (2026-09-27, CVE-2026-88771..88778, verified vs the Citrix bulletin): no *exploit* detail public; emulated via the `nsepa.deb`
  patch oracle + build-derived state in core/data/cves_extra.json, PLUS (DONE) CVE-2026-88771 attempt/IOC fingerprinting from GreyNoise's
  2026-09-28 IOC blog (https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation) PLUS watchTowr Labs' detection-artifact
  tool (https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771, verified against the tool's own README): a `${IFS}`
  login command-injection attempt on `/cgi/login` or `/nf/auth/doAuthentication.do`; a GET probe for the published webshell path
  (`/logon/LogonPoint/custom/.ctxs.receiver` or its `receiver.min[.hex].css` alias); and the exact log-poisoning payload string
  (`pitboss PPE unexpectedly died NSPPE;<cmd>;# X`, spoofing an internal NetScaler PPE log line) matched anywhere in a request regardless
  of endpoint, since watchTowr's tool doesn't name which path carries it into the logs -- see core/routes/cve_2026_88771.py. This is the
  pattern the rest of Phase 3 should follow for CVEs with no formal PoC/nuclei template: a honeypot's job is to fingerprint and log a
  *recognisable attempt* (a published IOC, injection technique, or scanner tag), not to prove exploitation with a byte-perfect matcher.
- CVE-2026-8452 (DONE, IOC only) (SAML SP/IdP pre-auth heap overflow -> RCE, distinct from the CTX697096/88771-88778 bulletin, fixed
  14.1-72.61/13.1-63.18, verified against https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452): no
  safe detection-request shape (offsets are hardcoded to one specific build in the public tool), but its README confirms the resulting
  webshell path `/vpn/theme/x.php` -- added to `core/routes/ioc_probes.py`'s `IOC_PATHS`.
- CVE-2020-8193/8195/8196 (DONE, enriched): the route now also captures `X-NITRO-USER`/`X-NITRO-PASS`/`rand_key` header values (when sent)
  into the logged event, and returns HTTP 406 (not 200) on the `/pcidss/report` and `/rapi/filedownload` requests -- both corroborated by
  an independent source, Zeop-CyberSec/citrix_adc_netscaler_lfi (a real Metasploit auxiliary module), not just nuclei's template.
- **GitHub survey, 2026-09-29**: two background research passes catalogued ~59 repos across the full 2010-2026 CVE range (not just the
  handful already cited) -- PoCs, scanners, IOC lists, nuclei templates, and a dedicated "any other Citrix honeypot?" sweep (none found;
  this fork's lineage appears to be the only one). Full catalogs are not checked into the repo (they were scratch research files); the
  actionable, verified findings are folded into the entries above and into `docs/SCANNER_SURFACE.md`.
- **rdx_en_mtime for 14.1-73.x, checked 2026-09-30, correction of an earlier unverified claim**: the survey had reported fox-it/
  citrix-netscaler-triage and securekomodo/citrixInspector as having "more-current" gzip-MTIME tables than citrixscan's, worth
  fetching to fill the 14.1-73.x gap -- that claim was passed through from the subagent's report without independently checking it,
  and turned out to be wrong. Fetched fox-it's actual table (`scan-citrix-netscaler-version.py`, verified directly): it tops out at
  stamp 1762830097 (2025-11-11, version 12.1-55.333); our own vendored `core/data/rdx_en_stamps.json` (from citrixscan) already
  reaches stamp 1773758251 (2026-03-17, version 14.1-66.59) -- i.e. our existing table is *more* current than the one the survey
  said we should fetch. No merge was worth doing. Neither table has 14.1-73.x regardless, because that build was disclosed only
  3 days before this check (CTX697096, 2026-09-27) and no public gzip-timestamp extraction can exist yet for it -- someone has to
  first get a copy of that exact firmware and run the extraction script against it. Not a "not yet done" item; genuinely blocked on
  the data not existing publicly yet. Revisit once a public table adds a 14.1-73.x row.
- CVE-2025-5777 "CitrixBleed 2" (DONE) (`POST /p/u/doAuthentication.do` with valueless `login`), CVE-2025-6543, CVE-2025-7775
- Other products if useful: StoreFront, Citrix Virtual Apps/ADM/SD-WAN and NetScaler Console management UIs (separate profiles, separate ports).
For each: log a `scan` vs `exploit_attempt` classification, respond with a canned vulnerable-looking body, and never process attacker payloads.
All "DONE" memory-overread routes are detection oracles only: the "leaked" bytes are `secrets.token_hex`/`token_urlsafe`, always marked
`HONEYPOT-FAKE-LEAK` in the event log (and usually in the response body/comment too), and no code path reads real process memory.
Per-route `patched=` handlers matter here: a route with no explicit one falls back to a from-scratch not-found `Hit` on a patched build (see the
`dispatch()` comment in `core/routes/__init__.py` - it must NOT `replace()` onto the vulnerable `Hit`, since `data`/`cookies`/`headers` would
otherwise leak through unchanged even though `page`/`status` get overridden).

**WAF mimicry (DONE, opt-in)** -- `core/routes/waf_block.py`, profile feature `waf-mimicry`, profile `adc-14.1-73.33-waf`.
Real NetScaler ADC/Gateway ships an integrated WAF module (Citrix AppFirewall; see CVE-2015-2841, a real bug in it). A raw honeypot
that never blocks textbook SQLi/XSS/command-injection-looking traffic is itself a tell past the "run a script and hope" stage of
attacker, per a user discussion: capturing the *right* traffic (a targeted, intent-revealing probe) is the actual point of a
honeypot, and a plausible generic-block layer is what makes an attacker keep sending that traffic instead of writing the host off in
one request. Mocks only the *observable shape*: 403 + `NS Transaction ID` in the body -- deliberately the exact fingerprint
vigolium's own WAF detector (`pkg/deparos/waf/detector.go`, `citrixNetscalerRule()`, read directly from that repo) checks for
(403/429 + `Cneonction`/`NSC_*` already sent + that body substring). Registered as a catch-all *before*
`cve_2019_19781`'s own broad catch-alls (root-path login, "any POST" payload logging) so generic attack noise on those paths gets
blocked realistically instead of silently absorbed -- but with an explicit carve-out so it never shadows `cve_2019_19781`'s own,
more specific `/vpn/../vpns/...` traversal handling. Every CVE/IOC route is still tried first and always wins on overlap.
**Predicted trade-off, live-tested 2026-09-29, did NOT manifest**: the concern was vigolium's own known-issue-scan treating that exact
403+marker signature as "this host is filtering -- back off" (its `citrixNetscalerRule()` detector, read from that repo). Re-run
against `adc-14.1-73.33-waf`: it made *more* requests (28,710 vs. baseline's 24,000+) over a *longer* run (8m59s vs. 7m33s), with the
WAF layer firing 8,003 times (correctly classified: 6,914 traversal/808 sqli/160 cmdi/121 xss) and zero mention of WAF/edge/pacing in
vigolium's console output. Why: `pkg/knownissuescan/runner.go`'s own comments say that phase runs nuclei as an in-process library with
its own HTTP client, outside `pkg/http.Requester` -- the component the WAF detector is actually wired into (vigolium's *native*
discovery/dynamic-assessment phases). So the risk was real for how the detector is built, just not reachable from nuclei-driven
scanning specifically. katana's crawl was unaffected either way (WAF layer correctly silent on its non-attack-looking traffic). Net
effect observed: realism + a rich, correctly-classified block-event signal, at no measured cost to this scanner's engagement. Not
tested against vigolium's native scan phases (where the detector is actually reachable) or any scanner that does implement WAF-aware
back-off -- see docs/SCANNER_SURFACE.md for the full writeup. Off by default on every other profile; select `adc-14.1-73.33-waf`
explicitly. The signature list (sqli/xss/cmdi/traversal) is a small illustrative subset in the spirit of OWASP CRS's classic rules,
not an exhaustive WAF ruleset. **nmap, 2026-09-30**: `http-waf-detect` (a behavior-diffing NSE script, unrelated to vigolium's
requester-level detector) correctly reports "IDS/IPS/WAF detected" on `adc-14.1-73.33-waf` and stays clean on the non-WAF baseline --
this is the meaningful A/B validation the earlier tools couldn't give (katana never attacks, vigolium's known-issue-scan is
architecturally blind to it). `http-waf-fingerprint` separately identifies "Citrix Netscaler" by name on *both* profiles, since it
keys on the header/cookie fingerprint from Phase 3's older `netscaler-surface` work, not the new block layer. Also see bug 11 above,
found via this testing.

**Phase 4 - Outputs and local-lab ergonomics**
- Implement sqlite (schema file is missing: `docs/sql/sqlite3.sql`), plain JSONL to stdout, optional Elasticsearch/syslog. Remove GeoIP by default.
- Optional plain-HTTP listener, multiple ports (443, 8443, 3010 mgmt), `--profile` and `--tls-profile` CLI flags, health endpoint on localhost only.
- docker-compose with a network-isolated lab (`internal: true` network) to guarantee no egress.

## Conventions
- Python 3.10+, type hints on new code, `ruff`/`black` defaults, 4-space indent; match surrounding style in files you don't refactor.
- New routes ship with a pytest case that replays a public scanner request (fixtures in `tests/fixtures/`).
- Update `CHANGELOG.md` (Keep a Changelog) and bump `__VERSION__` in `CitrixHoneypot.py` and `LABEL version` in `Dockerfile` together.
- Don't edit `etc/*.base` defaults casually; new options go there with comments.
