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

## Findings for this honeypot

1. **Unknown paths return HTTP 200 with an empty body** (`core/routes` falls through to `Hit()`). Crawlers and scanners calibrate against soft-404s
   and the nuclei `status: 200` matchers become easier to satisfy; every `/menu/*`, `/nitro/*`, `/gui/` probe currently "exists". Add a profile-level
   not-found response (status + page) and make it the default for unmatched requests.
2. **The login page is a 2019 stub** with no `/vpn/js/...` assets, no `ctxs.core.min.js`, no `CTXS.*` globals: katana/wappalyzer will not identify it as
   Citrix. Real NetScaler also mangles `Connection` (`Cneonction`/`nnCoection`); we send `Connection: Close`.
3. **Handlers missing** for everything in the table except 2019-19781. Most are plain reflect/echo responses and are cheap to emulate; the memory-leak
   family (4966, 6549, 5777, 3055) needs a canned *fake* leak (random bytes/tokens that contain no real data) and correct content types.
4. The detection oracles need HTTP details the current server does not control: oversized `Host` header handling (Twisted limits), header injection via
   CRLF in redirect targets (must be *simulated in the logged event and response body*, never by reflecting raw attacker bytes into headers), `POST` bodies
   without values.
5. Unverified leads from web search snippets (Rapid7, watchTowr, Citrix CTX697096 mention newer 2026 CVEs, e.g. `CVE-2026-19490`, `CVE-2026-88771/88772`).
   Not in citrixscan's table or nuclei-templates; verify against the vendor bulletin before adding anything.
