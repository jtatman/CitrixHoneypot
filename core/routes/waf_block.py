"""AppFirewall-style generic block, gated behind the profile feature ``waf-mimicry``.

Real NetScaler ADC/Gateway ships an integrated WAF module (Citrix AppFirewall, aka "NetScaler Web App
Firewall" -- a licensed feature of the appliance itself, not a separate product; see CVE-2015-2841 "NS10.5
WAF Bypass via HTTP Header Pollution" for a real bug in it). A raw web surface that never blocks obviously
malicious-looking traffic (textbook SQLi/XSS/command-injection strings) is itself a tell to anyone past the
"run a script, hope for the best" stage. This route mocks that layer's *observable shape* only: a 403 with
an "NS Transaction ID" in the body -- which is deliberately the exact fingerprint vigolium's own WAF
detector (pkg/deparos/waf/detector.go, citrixNetscalerRule(), read directly from that repo this session)
checks for: status in {403, 429}, Cneonction/NSC_* already sent by the profile, and that body substring.

Trade-off (see docs/SCANNER_SURFACE.md and CLAUDE.md): vigolium's known-issue-scan treats that exact
signature as "this host is already filtering -- drop it, don't scan further". Enabling this feature makes
the honeypot look more convincing to a human attacker at the cost of possibly disengaging some automated
scanners. It is therefore opt-in per profile, not the default.

Registered LAST (see core/routes/__init__.py's import order): it only ever sees requests no more specific
CVE/IOC/surface route already claimed, so a genuine detection oracle is never shadowed by a generic block.
The signature list below is a small, illustrative subset (in the spirit of OWASP CRS's classic rules), not
an exhaustive WAF ruleset -- broadening it is left for later if useful.
"""
import re
import secrets

from core.routes import Hit, route

FEATURE = 'waf-mimicry'

# (name, compiled pattern) -- checked against the decoded path+query and the POST body, case-insensitive.
SIGNATURES = [
    ('sqli', re.compile(r"(\bunion\b.{0,40}\bselect\b|\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bsleep\(\d|"
                        r"\bbenchmark\(|xp_cmdshell|;\s*drop\s+table)", re.I)),
    ('xss', re.compile(r"<script[\s>]|javascript:|on(error|load|mouseover)\s*=", re.I)),
    ('cmdi', re.compile(r"\$\(.{0,60}\)|`[^`]{1,60}`|;\s*(cat|wget|curl|nc|bash|sh)\s", re.I)),
    # ctx.path/ctx.body are already percent-decoded by the time this runs, so match the decoded forms.
    # Excludes anything shaped like core/routes/cve_2019_19781.py's own /vpn/../vpns/... traversal (see
    # _is_legacy_traversal below) -- that family is registered later and is the intentionally more specific,
    # dedicated handler for exactly that pattern; this signature is only for '../' elsewhere.
    ('traversal', re.compile(r"\.\.[/\\]|\x00")),
]


def _is_legacy_traversal(ctx):
    return ctx.traversal and ctx.segments and ctx.segments[0] == 'vpns'


def _hits(ctx):
    haystack = ctx.path + '\n' + ctx.body
    for name, pattern in SIGNATURES:
        if name == 'traversal' and _is_legacy_traversal(ctx):
            continue
        if pattern.search(haystack):
            yield name


def _match(ctx):
    if not (ctx.profile and ctx.profile.has(FEATURE)):
        return False
    return next(_hits(ctx), None) is not None


def _signature_name(ctx):
    return next(_hits(ctx), 'unknown')


@route('waf-block', _match)
def block(ctx):
    name = _signature_name(ctx)
    txn_id = secrets.token_hex(8)
    body = ('<html><head><title>Application Blocked</title></head><body>'
            '<h1>Application Firewall Alert</h1><p>NS Transaction ID: {}</p>'
            '<p>This request has been blocked by the security policy.</p></body></html>').format(txn_id)
    return Hit('WARNING', 'AppFirewall-style block (heuristic: {})'.format(name), status=403,
               data=body.encode(),
               event={'message': 'Generic attack-signature block', 'waf_signature': name, 'ns_txn_id': txn_id})
