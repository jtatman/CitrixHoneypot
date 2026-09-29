# What scanners send at a Citrix surface, and what a hit looks like

Research notes for Phase 3. Sources were read on 2026-09-29: `jtatman/citrixscan`, `vigolium/vigolium` (main), `projectdiscovery/katana`,
`projectdiscovery/wappalyzergo` and `projectdiscovery/nuclei-templates` (http/cves, http/technologies). Everything below is a *detection* oracle:
the request a scanner sends and the response that makes it report "vulnerable". The honeypot only needs to reproduce the observable response
with canned data (see the ground rules in `CLAUDE.md`). Not yet tested against the real tools.

## Tools

**vigolium** (Go, agentic + native modules). It has **no Citrix-specific exploit modules**. Its `known-issue-scan` phase embeds the nuclei engine and the
nuclei-templates repo (`pkg/knownissuescan/runner.go`), so Citrix CVE coverage is nuclei's. Its own strength is generic: `lfi_path_traversal`
(confirms by real `/etc/passwd`/`win.ini` content shape, subtracting a baseline), `path_normalization`, `forbidden_bypass`, `host_header_injection`,
`http_method_tampering`, WAF/edge detection with back-off. Its only Citrix awareness is a WAF-block fingerprint (`pkg/deparos/waf/detector.go`,
`citrix_netscaler`), which fires only on **403/429**:
`Cneonction` / `nnCoection` headers (NetScaler's mangled `Connection`), `Via: ...NS-CACHE...`, `Set-Cookie` containing `NSC_`, `ns_af=` or `citrix_ns_id`,
body `NS Transaction ID`. Consequence: a host it believes is already blocking is *dropped rather than scanned* (`knownissuescan/edge.go`), so a honeypot that
answers 403 with that fingerprint would hide the rest of its surface from vigolium. Serve those headers on 200/302, or make it a per-profile choice.

**katana** (crawler, not a scanner). Follows links/JS it finds; `-kf` fetches robots.txt/sitemap.xml; `-td` uses wappalyzergo. Wappalyzer recognises Citrix
only by `scriptSrc` `/ctxs\.core\.min\.js` and JS globals `CTXS.AccessGateway`, `CTXS.WebApiClient`, `AddHeaderAndBarForCitrix` (headless only). It cannot
exploit anything and will only reach `/vpn/../vpns/` style URLs if a page links to them (whether it normalises `..` was not tested). Useful mainly to
feed other tools and to check the surface looks crawlable.

**nuclei templates for Citrix** (what vigolium actually sends). Matchers below are quoted from the templates.

| CVE | Request | Positive when |
|---|---|---|
| 2019-19781 | `GET /vpn/../vpns/cfg/smb.conf` | 200 and body has `[global]` |
| 2020-8191 | `POST /menu/stapp` (form, `appname=` with markup) | 200, `text/html`, payload echoed unescaped |
| 2020-8193 | `POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1` (xml, `X-NITRO-*`); `GET /menu/ss`, `/menu/neo`, `/menu/stc`; `POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd` | body matches `root:.*:0:0:` |
| 2020-8194 | `GET /menu/guiw?nsbrand=1&protocol=...&id=3&nsvpx=phpinfo` (cookie `startupapp=st`) | 200, `application/x-java-jnlp-file`, echoed `<jnlp codebase=` |
| 2023-24488 | `GET /oauth/idp/logout?post_logout_redirect_uri=%0d%0a%0d%0a<script>..` | 302 with injected headers/body echoed |
| 2023-3519 | `POST /saml/login` with `SAMLRequest=` | 200 and body `SAML Assertion verification failed;` |
| 2023-4966 | `GET /oauth/idp/.well-known/openid-configuration` with oversized `Host`; then `POST /logon/LogonPoint/Authentication/GetUserName` (`NSC_AAAC` cookie) | body starts `{"issuer":`; extracts long hex from leaked bytes |
| 2023-5914 | `POST /Citrix/teststoreAuth/SamlTest` (StoreFront) | 200, `text/html`, echoed script + `XmlException` |
| 2023-6549 | `GET /nf/auth/startwebview.do` with oversized `Host` | 200, body has `/nf/auth/webview/done` and `AuthenticationRequirements` |
| 2025-5777 | `POST /p/u/doAuthentication.do` body `login` (no value) | `Content-Type: application/vnd.citrix.authenticateresponse`, non-empty `<InitialValue>` that is not plain base64 |
| 2026-3055 | `POST /saml/login`; `GET /wsfed/passive?wctx` | 302 with `NSC_TASS=<base64>` cookie decoding to `wctx=` |

Also in nuclei-templates but out of the NetScaler scope: XenMobile CVE-2020-8209 (`/jsp/help-sb-download.jsp`), Citrix Hypervisor and XenMobile version pages.

**citrixscan** (see `CLAUDE.md`): version fingerprinting (`rdx_en.json.gz` gzip MTIME), IoC and management paths that must look absent on a clean profile.

## Added 2026-09-29 (after the first pass)

**technion/netscaler_scanner** (fingerprint.sh + citrix-conf-parse.py; MIT-style LICENSE added 2026-09-28). Covers Citrix bulletin **CTX697096**
(published 2026-09-27; verified against the bulletin itself): CVE-2026-88771 (unauthenticated RCE, all deployments), 88772 (DTLS overflow; both
observed exploited in the wild), 88773 (HTTP request smuggling), 88774 (URL-expression policy bypass), 88775/88776/88777 (memory overflows: Gateway/AAA,
Oracle LB, non-HTTP L7), 88778 (TCP ISN prediction). Fixed in 14.1-73.37, 13.1-64.23, 14.1-FIPS 73.37, 13.1-FIPS/NDcPP 13.1-37.279; 12.1 and 13.0 are EOL
and unpatched. The bulletin gives no request-level exploit detail (memory-corruption/DTLS/smuggling), so the only remotely observable oracle is its
unauthenticated **patch check**: `GET /logon/LogonPoint/tmindex.html` must be 200, then the size of `/epa/scripts/linux/nsepa.deb` (ranged GET,
`Content-Range`; HEAD is answered without a length): `11230664` = 14.1-73.33 (vulnerable), `10688726` = 14.1-73.37 or later. Its author warns the size is a
proxy and must be calibrated on a real box. Implemented by the `netscaler-surface` profile feature; `fingerprint.sh` gives the right verdict against both
`adc-14.1-73.*` profiles.

**exploit-db / searchsploit** (`files_exploits.csv` from gitlab.com/exploit-database/exploitdb, 47,160 entries, newest 2026-09-11): 39 Citrix/NetScaler
entries, newest is EDB-52401 (CVE-2025-5777, 2025-08-11). Nothing for 2026, so exploit-db adds no request detail beyond nuclei for the CVEs we already
track. Older items worth knowing: 47901/47902/47913/47930 (CVE-2019-19781), 49038 (Metasploit LFI, CVE-2020-8193 family), 36369 (CVE-2015-2841 NS 10.5
WAF bypass via header pollution), 35180 (CVE-2014-7140 SOAP handler RCE), 47112 (SD-WAN CVE-2019-12989/12991), 42345/42346 (SD-WAN/CloudBridge
CVE-2017-6316), 47561/47951 (StoreFront/XenMobile XXE).

## Live tool run, 2026-09-29 (both completed, run via background subagents on their second attempt)

Built katana v1.7.0 and vigolium from source in-session (vigolium needed a one-line stub for its bundled `jstangle` helper, unrelated to this repo, to
compile; binaries reused afterward, no rebuild needed). Both needed `NO_PROXY=127.0.0.1` and closed stdin to run at all in this sandbox (they otherwise
read targets from stdin or hang on the outbound proxy).

**katana**: crawled `adc-14.1-73.33-vulnerable` in ~6s, found 2 endpoints (`/`, the logon page's one linked script), both 200. Its own tech-detection
reported `["Citrix", "Apache HTTP Server", "Microsoft ASP.NET"]` -- confirms the logon-page markers (`ctxs.core.min.js`, `CTXS.*` globals) work.
Shallow crawl depth: the login form posts to `/cgi/login` but katana's default (non-headless) mode doesn't submit forms, so it never explored further.

**vigolium**: `scan -t https://127.0.0.1:8448 -S --intensity balanced --known-issue-scan-templates-dir <sparse nuclei-templates checkout> -o ... --format
jsonl` ran to completion in ~7m33s (discovery -> spidering -> dynamic-assessment -> known-issue-scan/nuclei), no crashes. Findings: 0 critical/high, 1
low, 1 info. It reached and logged hits against `/vpn/../vpns/cfg/smb.conf`, `/saml/login`, `/wsfed/passive` and `/p/u/doAuthentication.do`, and its
nuclei phase actually **fired our CVE-2025-5777 route** (`[WARNING] Detected CVE-2025-5777 probe` in the honeypot's own log) -- the first end-to-end
confirmation that a real scanner's detection logic triggers one of these routes, not just a hand-crafted curl request. It did *not* reach
`/oauth/idp/.well-known/openid-configuration`, `/nf/auth/startwebview.do`, `/logon/LogonPoint/tmindex.html`, or `/epa/scripts/linux/nsepa.deb` at
`--intensity balanced` -- nothing links to them from the pages it crawled, so a scanner without out-of-band knowledge of those exact paths won't find
them either. Worth revisiting with `--intensity deep` or a seeded path list.

`technion/netscaler_scanner`'s `fingerprint.sh` (see below) also ran to completion and confirmed the patch oracle.

## Implemented so far (Phase 3)

Profile feature `netscaler-surface` + profiles `adc-14.1-73.33-vulnerable` / `adc-14.1-73.37-patched`: real 404 for unmatched paths, Citrix logon page with
`ctxs.core.min.js` and `CTXS.*` markers, `Cneonction` header, `nsepa.deb` size oracle (with Range), `rdx_en.json.gz` with the build's gzip MTIME (only for builds in
citrixscan's table, i.e. not 73.x).

CVE routes, all detection oracles (canned/random data, never real memory or exploit execution), build-derived vulnerable/patched state:
- CVE-2025-5777 "CitrixBleed 2": fake leak or empty `<InitialValue>` when fixed.
- CVE-2023-3519: `POST /saml/login` -> `SAML Assertion verification failed;`.
- CVE-2023-4966 "CitrixBleed": oversized-`Host` `GET /oauth/idp/.well-known/openid-configuration` -> JSON body plus a `HONEYPOT-FAKE-LEAK` comment
  containing a fake 100-hex-char string with nuclei's expected fixed suffix; `POST .../GetUserName` session-replay logging.
- CVE-2023-6549: oversized-`Host` `GET /nf/auth/startwebview.do` -> canned body with nuclei's two required markers.
- CVE-2026-3055: `GET /wsfed/passive?wctx` -> 302 + `NSC_TASS=<base64>` cookie decoding to a fake `wctx=HONEYPOT-FAKE-LEAK-...` value.
- CVE-2020-8193/8195/8196: unauth `GET /menu/ss`,`/menu/neo`,`/menu/stc`, `POST /pcidss/report`, `POST /rapi/filedownload` -> fake `/etc/passwd`
  matching nuclei's `root:.*:0:0:` matcher, HTTP 406 on the two POST requests, `X-NITRO-USER`/`X-NITRO-PASS`/`rand_key` header telemetry when
  sent -- corroborated independently by Zeop-CyberSec/citrix_adc_netscaler_lfi's Metasploit module, not just nuclei. Fixed versions verified
  against NVD (not from citrixscan's table).

## WAF mimicry (opt-in) -- live-tested, the predicted vigolium back-off did NOT happen

`core/routes/waf_block.py` (profile feature `waf-mimicry`, profile `adc-14.1-73.33-waf`) mocks Citrix AppFirewall's *observable shape*
(403 + `NS Transaction ID` body) for generic SQLi/XSS/command-injection/traversal-looking requests not already claimed by a specific
CVE/IOC route -- prompted by a user discussion: a honeypot with zero filtering on textbook attack strings is itself a tell to anyone
past the script-kiddie stage, and capturing *intent-revealing* traffic is the actual point, which a believable "you got blocked, try
something smarter" response encourages rather than a flat wall. The fingerprint is deliberately exact: it's vigolium's own WAF
detector's signature (`pkg/deparos/waf/detector.go`, `citrixNetscalerRule()`) -- 403/429 + `Cneonction`/`NSC_*` (already sent by these
profiles) + `NS Transaction ID` in the body.

**Predicted trade-off, tested 2026-09-29, did not manifest for a nuclei-driven scan.** katana's passive crawl was unaffected (identical
2 paths, same Citrix tech-detection, WAF layer correctly silent on benign traffic -- as expected). The real question was vigolium's
`known-issue-scan`: re-run against `adc-14.1-73.33-waf`, it made **more** total requests (28,710 vs. the earlier non-WAF baseline's
24,000+) over a **longer** run (8m59s vs. 7m33s), while the WAF layer fired 8,003 times (6,914 traversal / 808 sqli / 160 cmdi / 121
xss -- correct signature classification throughout). Nothing in vigolium's console output mentioned a WAF, edge, filtering, or pacing.

**Why, and this is grounded in vigolium's own source read earlier this session, not speculation**: `pkg/knownissuescan/runner.go`'s own
comments say known-issue-scan is "the one active phase whose traffic does NOT go through `pkg/http.Requester`... That left it outside
everything the shared requester provides -- per-host AIMD back-off ... proactive pacing when a CDN/WAF edge is fingerprinted." nuclei
runs as an in-process library with its own HTTP client during that phase, architecturally unable to consult the `citrixNetscalerRule()`
detector, which is wired into the shared requester used by vigolium's *native* scan phases (discovery, dynamic-assessment) instead. So
the theoretical risk was real for a tool built the way I read it to be built, but for THIS tool's THIS scan mode it's a non-issue: the
feature adds realism and a rich block-event signal (8,003 of them, correctly classified) at effectively no cost to scanner engagement.
Not yet tested against vigolium's native dynamic-assessment phase specifically (where the detector actually is wired in), or against
any other scanner that does implement WAF-aware back-off -- the trade-off may still be real elsewhere, just not observed here.

## GitHub survey, 2026-09-29 (two background research passes, ~59 repos catalogued across 2010-2026)

Historical (pre-2022) and modern (2022-2026) passes via `firecrawl_search`/`firecrawl_scrape` (no GitHub API, per this session's repo-scope
rule). Full per-repo notes were written to scratch files, not checked into the repo; verified, actionable findings are folded into CLAUDE.md
and the routes above. Highlights not already covered elsewhere:
- **fox-it/citrix-netscaler-triage** and **securekomodo/citrixInspector**: independent, actively-maintained gzip-MTIME/build tables (the
  same Fox-IT technique citrixscan's `RDX_EN_STAMP_TO_VERSION` uses), both more current than citrixscan's table (which stops at
  14.1-66.59). Not yet fetched/merged -- would let modern profiles finally set `rdx_en_mtime` for 14.1-73.x builds.
- **watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771** and **-PreAuth-RCE-CVE-2026-8452**: verified directly (see CVE-2026-88771
  and CVE-2026-8452 entries in CLAUDE.md) -- the richest concrete finds of the whole survey, both from research published in the last ~6
  weeks.
- **Zeop-CyberSec/citrix_adc_netscaler_lfi**: a real Metasploit module giving the precise 3-request/406-status/`rand_key` chain now folded
  into `core/routes/cve_2020_8193.py`.
- **mandiant/ioc-scanner-CVE-2019-19781**, **citrix/ioc-scanner-CVE-2019-19781** (vendor's own), **mandiant/citrix-ioc-scanner-cve-2023-3519**:
  official/vendor IOC scanners; all are disk/forensic artifact hunting (file paths, shell history), not wire-level request patterns a
  network-listening honeypot could reproduce -- useful mainly as a cross-check for "these filenames must never appear to exist here".
- **rapid7/metasploit-framework**'s `citrix_bleed_cve_2023_4966.rb`: the official Metasploit CitrixBleed scanner, corroborating our
  CVE-2023-4966 route's request/response shape from a second independent source.
- **No other Citrix/NetScaler honeypot project exists on GitHub** besides this fork's own bontchev/MalwareTech lineage, confirmed by both
  passes independently. `cybrdude/citrixscan` is a fork/rename of the already-known jtatman/citrixscan, not a new resource.
- Several CVEs remain genuinely untooled on public GitHub even under this broader IOC-inclusive search (not just formal-PoC search): the
  2020-8191/8194 pair, most pre-2018 CVEs (2014-7140, the 2015 trio, 2016-9111, 2010-4566, 2017-6316), and the newest 2025 CVEs
  (7776/8424/12101). CLAUDE.md's "researched, skipped" note now reflects that this was checked, not just assumed.

**Attempt/IOC fingerprinting** (not exploit-confirmation oracles; the honeypot's real job -- see CLAUDE.md's Phase 3 note on this):
- CVE-2026-88771 (`core/routes/cve_2026_88771.py`): a `${IFS}` login command-injection attempt on `/cgi/login` or `/nf/auth/doAuthentication.do`, and a
  webshell check-in probe for a published path, both from GreyNoise's 2026-09-28 IOC blog (see CLAUDE.md).
- Generic, CVE-agnostic (`core/routes/ioc_probes.py`, from citrixscan's `IOC_PATHS`/`MISCONFIG_PATHS`): known webshell/backdoor filenames from
  CVE-2023-3519 campaigns + CISA AA23-201A, and NSIP/CLIP/SNIP management-interface paths (`/nitro/v1/config/*`, `/gui/`, `/nsconfig/ns.conf`) that
  should never look reachable on a clean profile -- see CLAUDE.md's NSIP-vs-Console clarification.

Bug found and fixed while adding these: `dispatch()`'s generic "no route-specific `patched=` handler" fallback used `dataclasses.replace()` on the
vulnerable `Hit`, which only overrides `page`/`status`/`event` - a route's `data`/`cookies`/`headers` (used by all three new oversized-Host/redirect
routes) silently survived into the "patched" response. Fixed by building a fresh `Hit` instead; regression tests in `tests/test_memleak_cves.py`
assert the patched responses carry no leaked cookie/body.

## Findings for this honeypot (fixed)

1. FIXED (profiles with `not_found:`; the legacy profile intentionally keeps the old 200/empty behaviour for parity).
2. FIXED: the modern profiles' login page has the Citrix JS markers and the `Cneonction` header.
3. **Handlers missing** for everything in the table except 2019-19781. Most are plain reflect/echo responses and are cheap to emulate; the memory-leak
   family (4966, 6549, 5777, 3055) needs a canned *fake* leak (random bytes/tokens that contain no real data) and correct content types.
4. The detection oracles need HTTP details the current server does not control: oversized `Host` header handling (Twisted limits), header injection via
   CRLF in redirect targets (must be *simulated in the logged event and response body*, never by reflecting raw attacker bytes into headers), `POST` bodies
   without values.
5. Unverified leads from web search snippets (Rapid7, watchTowr, Citrix CTX697096 mention newer 2026 CVEs, e.g. `CVE-2026-19490`, `CVE-2026-88771/88772`).
   Not in citrixscan's table or nuclei-templates; verify against the vendor bulletin before adding anything.
