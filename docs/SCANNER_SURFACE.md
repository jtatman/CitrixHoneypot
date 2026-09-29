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

## Live tool run, 2026-09-29 (partial)

Built katana v1.7.0 and vigolium from source in-session (vigolium needed a one-line stub for its bundled `jstangle` helper, unrelated to this repo, to
compile). Both needed `NO_PROXY=127.0.0.1` and closed stdin to run at all in this sandbox (they otherwise read targets from stdin or hang on the
outbound proxy). katana's own tech-detection reported "Citrix" against the `adc-14.1-73.33-vulnerable` profile, confirming the logon-page markers work.
A `vigolium scan` was started against the same profile (discovery -> spidering -> dynamic-assessment) and was mid-run, with an early passive
`clickjacking-detect` finding, when the run was interrupted; its known-issue-scan (nuclei-in-process) results against our CVE routes were not seen.
Not re-attempted this session. `technion/netscaler_scanner`'s `fingerprint.sh` (see below) *did* run to completion and confirmed the patch oracle.

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
