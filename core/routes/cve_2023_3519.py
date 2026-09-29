"""CVE-2023-3519 (Gateway/AAA SAML RCE) detection oracle.

nuclei http/cves/2023/CVE-2023-3519.yaml: POST /saml/login with SAMLRequest=..., positive when the response is
200 and contains 'SAML Assertion verification failed;'. No payload is ever parsed or executed here.
"""
from core.routes import Hit, route

CVE = 'CVE-2023-3519'
BODY = '<html><body>SAML Assertion verification failed; Please contact your administrator.</body></html>'


@route('cve-2023-3519', lambda c: c.method == 'POST' and c.bare == '/saml/login' and 'SAMLRequest=' in c.body, cve=CVE)
def saml_login(ctx):
    return Hit('WARNING', 'Detected CVE-2023-3519 probe (POST /saml/login)', data=BODY.encode(),
               event={'message': 'SAML probe', 'body': ctx.body[:4096]})
