"""CVE-2023-6549 (NetScaler ADC/Gateway out-of-bounds memory read via oversized Host) detection oracle.

nuclei http/cves/2023/CVE-2023-6549.yaml: GET /nf/auth/startwebview.do with an extremely long ``Host``
header; positive when the response is 200 and the body contains both '/nf/auth/webview/done' and
'AuthenticationRequirements'. This route only reproduces that observable shape -- no memory is read, real or
otherwise; the body is the same static markers on every hit.
"""
from core.routes import Hit, route

CVE = 'CVE-2023-6549'
PATH = '/nf/auth/startwebview.do'
OVERSIZED_HOST = 256
BODY = ('<AuthenticationRequirements><PostBack>/nf/auth/webview/done</PostBack>'
        '</AuthenticationRequirements>')


@route('cve-2023-6549', lambda c: c.method == 'GET' and c.bare == PATH and len(c.host) >= OVERSIZED_HOST, cve=CVE)
def startwebview(ctx):
    return Hit('WARNING', 'Detected CVE-2023-6549 probe (oversized Host on {})'.format(PATH),
               data=BODY.encode(), content_type='text/xml', event={'message': 'OOB memory-read probe'})
