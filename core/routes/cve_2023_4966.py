"""CVE-2023-4966 "CitrixBleed" detection oracle.

Real bug: an oversized ``Host`` header sent to the OIDC discovery endpoint triggers an out-of-bounds memory
read; the appliance echoes adjacent heap memory (session tokens) appended to the normal JSON body. An
attacker then replays a stolen ``NSC_AAAC`` value against the authentication endpoint to hijack the session.

nuclei http/cves/2023/CVE-2023-4966.yaml (two-request flow):
  1. GET /oauth/idp/.well-known/openid-configuration, oversized Host -> body starts '{"issuer":',
     extractor regex ``([a-f0-9]{100}45525d5f4f58455e445a4a42)`` pulls the leaked bytes.
  2. POST /logon/LogonPoint/Authentication/GetUserName with Cookie: NSC_AAAC=<leaked> -> word match
     'NSC_AAAC=' / 'HTTP/1.1'.

This oracle never reads real memory: the "leak" is `secrets.token_hex`, clearly marked, and long enough to
satisfy the extractor's length/suffix shape so a tool using that exact regex still gets a match to report.
The exact byte-for-byte nuclei behaviour (matcher-to-request wiring) was reconstructed from a truncated tool
dump, not verified live against nuclei -- see docs/SCANNER_SURFACE.md.
"""
import secrets

from core.routes import Hit, route

CVE = 'CVE-2023-4966'
OIDC_PATH = '/oauth/idp/.well-known/openid-configuration'
AUTH_PATH = '/logon/LogonPoint/Authentication/GetUserName'
# threshold to call a Host header "oversized"; the real overflow needs a much larger value, but this stays a
# detection oracle (no code path here can actually overflow anything)
OVERSIZED_HOST = 256
LEAK_SUFFIX = '45525d5f4f58455e445a4a42'   # fixed tail nuclei's extractor regex requires


def _oversized(ctx):
    return len(ctx.host) >= OVERSIZED_HOST


@route('cve-2023-4966-oidc', lambda c: c.method == 'GET' and c.bare == OIDC_PATH and _oversized(c), cve=CVE,
       patched=lambda ctx: Hit(data=_oidc_body(ctx).encode(), content_type='application/json',
                                event={'message': 'CitrixBleed probe (patched, no leak)'}))
def oidc_leak(ctx):
    # 100 hex chars + the fixed suffix, matching nuclei's extractor regex exactly; wrapped in a marker comment
    # so the raw body is unambiguously synthetic to anyone reading it, without breaking the hex run itself.
    fake_hex = secrets.token_hex(50) + LEAK_SUFFIX
    body = _oidc_body(ctx) + '<!-- HONEYPOT-FAKE-LEAK: {} -->'.format(fake_hex)
    return Hit('WARNING', 'Detected CVE-2023-4966 probe (oversized Host on {})'.format(OIDC_PATH),
               data=body.encode(), content_type='application/json',
               event={'message': 'CitrixBleed probe', 'leaked_fake': fake_hex})


def _oidc_body(ctx):
    return '{{"issuer":"https://{}"}}'.format(ctx.host or 'localhost')


@route('cve-2023-4966-replay', lambda c: c.method == 'POST' and c.bare == AUTH_PATH and 'NSC_AAAC=' in c.body,
       cve=CVE)
def session_replay(ctx):
    return Hit('CRITICAL', 'Detected CVE-2023-4966 session replay (POST {})'.format(AUTH_PATH),
               data=b'NSC_AAAC=xyz;Path=/;Secure\r\n\r\nOK', content_type='text/plain',
               event={'message': 'CitrixBleed replay attempt', 'body': ctx.body[:4096]})
