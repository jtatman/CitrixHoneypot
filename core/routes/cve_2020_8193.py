"""CVE-2020-8193 / CVE-2020-8195 / CVE-2020-8196 (Citrix ADC/Gateway unauthenticated access to restricted
endpoints, chained with an information-disclosure LFI) detection oracle.

All three share one bulletin (CTX276688) and one fixed-build set, verified against NVD:
  https://nvd.nist.gov/vuln/detail/cve-2020-8193 / -8195 / -8196
  fixed: 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14, 10.5-70.18

Request/matcher shape (the LFI chain nuclei attributes to CVE-2020-8193) is nuclei's
http/cves/2020/CVE-2020-8193.yaml:
  POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1
       (XML body <appfwprofile><login></login></appfwprofile>, X-NITRO-USER/X-NITRO-PASS headers)
  GET  /menu/ss?sid=nsroot&username=nsroot&force_setup=1
  GET  /menu/neo
  GET  /menu/stc
  POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd (XML body <clipermission></clipermission>)
  positive: response body matches regex 'root:.*:0:0:'
We only have one concrete public request/matcher chain (attributed to -8193); -8195/-8196 share the same
bulletin/fixed builds but no distinct public request shape was found, so they ride on this route's state too
(see CLAUDE.md "verify, don't guess"). The "leaked" /etc/passwd content is entirely canned, not a real file.
"""
from core.routes import Hit, route

CVE = 'CVE-2020-8193'
UNAUTH_PATHS = ('/menu/ss', '/menu/neo', '/menu/stc')
RAPI_PATH = '/rapi/filedownload'
PCIDSS_PATH = '/pcidss/report'
# canned /etc/passwd-shaped body -- matches nuclei's `root:.*:0:0:` regex, never a real file
FAKE_PASSWD = (
    'root:x:0:0:root:/root:/bin/bash\n'
    'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
    'nsroot:x:0:0:nsroot:/root:/bin/sh\n'
)


@route('cve-2020-8193-unauth', lambda c: c.method == 'GET' and c.bare in UNAUTH_PATHS, cve=CVE)
def unauth_menu(ctx):
    return Hit('WARNING', 'Detected CVE-2020-8193 probe (unauthenticated {})'.format(ctx.bare),
               data=b'', event={'message': 'Unauthenticated endpoint access probe'})


@route('cve-2020-8193-pcidss', lambda c: c.method == 'POST' and c.bare == PCIDSS_PATH, cve=CVE)
def pcidss_report(ctx):
    return Hit('WARNING', 'Detected CVE-2020-8193 probe (POST {})'.format(PCIDSS_PATH),
               data=b'<appfwprofile><login>nsroot</login></appfwprofile>', content_type='application/xml',
               event={'message': 'Unauthenticated pcidss/report probe', 'body': ctx.body[:4096]})


@route('cve-2020-8193-lfi', lambda c: c.method == 'POST' and c.bare == RAPI_PATH and 'etc' in c.path.lower()
       and 'passwd' in c.path.lower(), cve=CVE)
def rapi_lfi(ctx):
    return Hit('CRITICAL', 'Detected CVE-2020-8193 LFI (POST {} -> /etc/passwd)'.format(RAPI_PATH),
               data=FAKE_PASSWD.encode(), content_type='text/plain',
               event={'message': 'LFI via rapi/filedownload', 'body': ctx.body[:4096]})
