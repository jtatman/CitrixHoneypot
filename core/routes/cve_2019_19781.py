"""CVE-2019-19781 (Citrix ADC/Gateway directory traversal -> RCE) emulation.

Scanner references:
  type 1  https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
  type 2  https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
  type 3  https://github.com/mekoko/CVE-2019-19781/blob/master/CVE-2019-19781.py (repo gone/404, checked 2026-10-02)
"""
from urllib.parse import parse_qs

from core.routes import Hit, route

CVE = 'CVE-2019-19781'
RCE_PATHS = ('/vpns/portal/scripts/newbm.pl', '/vpns/portal/scripts/rmbm.pl')
STRUGGLE_PATHS = ('/vpns/portal/scripts/newbm.pl', '/vpns/cfg/smb.conf', '/vpns/')


def _struggle(ctx):
    # No /../ in the path: the attacker's client probably sanitised it away.
    return bool(ctx.cfg.get('struggle')) and ctx.path in STRUGGLE_PATHS


def _vpns(ctx):
    return ctx.traversal and len(ctx.segments) >= 1 and ctx.segments[0] == 'vpns'


def _read(ctx):
    return ctx.method != 'POST'


def _get_like(ctx):
    return _read(ctx) and ctx.method != 'HEAD'


def _gold_star():
    return 'gold_star.html'


@route('struggle', lambda c: _get_like(c) and _struggle(c))
def struggle(ctx):
    return Hit('DEBUG', 'Detected a failed directory traversal attempt.', page=_gold_star())


@route('login', lambda c: _get_like(c) and (
    len(c.raw_segments) == 0
    or (len(c.raw_segments) == 1 and c.raw_segments[0] == 'vpn')
    or (len(c.raw_segments) == 2 and c.raw_segments[0] == 'vpn' and c.raw_segments[1].lower().startswith('index.htm'))))
def login(ctx):
    return Hit(page=ctx.profile.login_page)


# --- POST -------------------------------------------------------------------

@route('payload', lambda c: c.method == 'POST' and bool(c.body), cve=CVE)
def payload(ctx):
    # RCE path is /vpns/portal/scripts/newbm.pl and the payload is the "title" POST field
    payload = parse_qs(ctx.body).get('title', [''])[0]
    level, msg = 'INFO', 'POST body: {}'.format(ctx.body)
    if ctx.collapsed in RCE_PATHS:
        level, msg = 'CRITICAL', 'Detected CVE-2019-19781 payload: {}'.format(payload)
    return Hit(level, msg, page=_gold_star() if _struggle(ctx) else '',
               eventid='citrix.payload',
               event={'request': 'POST', 'message': 'Exploit', 'body': ctx.body, 'payload': payload})


@route('post-struggle', lambda c: c.method == 'POST' and _struggle(c))
def post_struggle(ctx):
    return Hit('DEBUG', 'Detected a failed directory traversal attempt.', page=_gold_star())


# --- scans / completion (GET, HEAD and custom methods) -----------------------

def _scan(ctx, message, level, log_msg, page='', status=200, **subst):
    # No method-based page/status stripping here: Twisted's own Request.render() already sets
    # Content-Length from this (full, GET-equivalent) body and then discards the actual bytes for HEAD
    # (see twisted.web.server.Request.render -- verified directly in its source), so a route returning
    # the same page for HEAD as for GET gives the correct non-zero Content-Length on HEAD for free.
    # Special-casing HEAD to an empty page here, as this used to do, instead produced the bug: a HEAD
    # response reporting Content-Length: 0 even though GET on the same path has a body.
    return Hit(level, log_msg, page=page, status=status, subst=subst, event={'message': message})


@route('scan-type1', lambda c: _read(c) and _vpns(c) and len(c.segments) == 1, cve=CVE)
def scan_type1(ctx):
    # The real appliance's Apache sends an actual 403 here (its own directory-listing-forbidden page,
    # unrelated to NetScaler's own access control -- this happens on patched builds too, since the
    # traversal reaching Apache at all isn't gated on the CVE's patch status for a bare directory with no
    # filename): confirmed via multiple independent write-ups, e.g. bleepingcomputer.com's and mpgn's
    # CVE-2019-19781 PoC (github.com/mpgn/CVE-2019-19781) both showing `curl -I .../vpn/../vpns/` as
    # literal "HTTP/1.1 403 Forbidden". CISA's own checker (cisagov/check-cve-2019-19781) matches only the
    # body text and ignores status, so this was previously left at the Hit default (200) unverified.
    return _scan(ctx, 'Scan type 1', 'WARNING', 'Detected type 1 CVE-2019-19781 scan attempt!', '403.html',
                 status=403, url=ctx.collapsed)


@route('scan-type2', lambda c: _read(c) and _vpns(c) and c.collapsed == '/vpns/cfg/smb.conf', cve=CVE)
def scan_type2(ctx):
    return _scan(ctx, 'Scan type 2', 'WARNING', 'Detected type 2 CVE-2019-19781 scan attempt!', 'smb.conf')


@route('scan-type3', lambda c: _read(c) and _vpns(c) and c.collapsed == '/vpns/services.html', cve=CVE)
def scan_type3(ctx):
    # NOTE: serves smb.conf, as the original honeypot did; unverified against a real vulnerable host.
    # The scanner this route was meant to match (mekoko/CVE-2019-19781) is gone (404s, checked 2026-10-02)
    # -- nothing left to re-verify this against, so left as-is rather than guessing a change.
    return _scan(ctx, 'Scan type 3', 'WARNING', 'Detected type 3 CVE-2019-19781 scan attempt!', 'smb.conf')


@route('exploit-completion', lambda c: _get_like(c) and _vpns(c) and len(c.segments) >= 2 and c.segments[1] == 'portal',
       cve=CVE)
def completion(ctx):
    return _scan(ctx, 'Exploit completion', 'CRITICAL', 'Detected CVE-2019-19781 completion!')


@route('scan-unknown', lambda c: _read(c) and _vpns(c), cve=CVE)
def scan_unknown(ctx):
    return _scan(ctx, 'Unknown scan', 'DEBUG',
                 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(ctx.path))
