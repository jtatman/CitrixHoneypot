"""CVE-2026-3055 (NetScaler SAML IDP memory overread) detection oracle.

Citrix bulletin CTX696300 (precondition: SAML IDP configured); this repo does not model config
preconditions (see CLAUDE.md), so the route fires whenever the profile is vulnerable to this CVE.

nuclei http/cves/2026/CVE-2026-3055.yaml: POST /saml/login with a SAMLRequest (shares the request shape
with CVE-2023-3519's /saml/login probe -- that route already answers it, see cve_2023_3519.py), then
GET /wsfed/passive?wctx. Positive: 302, a Set-Cookie ``NSC_TASS=<base64>`` whose decoded value contains
``wctx=``, and the body does NOT contain 'Parsing of presented Assertion failed'. The base64 payload here is
random filler, not real memory.
"""
import base64
import secrets

from core.routes import Hit, route

CVE = 'CVE-2026-3055'
PATH = '/wsfed/passive'


def _match(ctx):
    return ctx.method == 'GET' and ctx.bare == PATH and 'wctx' in (ctx.collapsed.split('?', 1) + [''])[1]


@route('cve-2026-3055', _match, cve=CVE)
def wsfed_passive(ctx):
    leaked = 'wctx=HONEYPOT-FAKE-LEAK-' + secrets.token_urlsafe(32)
    cookie = 'NSC_TASS=' + base64.b64encode(leaked.encode()).decode() + ';Path=/;Secure'
    return Hit('WARNING', 'Detected CVE-2026-3055 probe (GET {}?wctx)'.format(PATH), status=302, data=b'',
               cookies=[cookie], headers={'Location': '/logon/LogonPoint/'},
               event={'message': 'SAML IDP memory-overread probe', 'leaked_fake': leaked})
