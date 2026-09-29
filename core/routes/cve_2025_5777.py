"""CVE-2025-5777 "CitrixBleed 2" detection oracle.

nuclei http/cves/2025/CVE-2025-5777.yaml + exploit-db 52401: POST /p/u/doAuthentication.do with the body ``login``
(no value). A vulnerable appliance returns Content-Type application/vnd.citrix.authenticateresponse* whose
<InitialValue> holds leaked memory; a patched one returns it empty.

The "leak" here is random, clearly-marked filler; no memory or session data is ever read. The XML layout is a
best-effort reconstruction of the public write-ups, matched to what the nuclei matcher checks.
"""
import re
import secrets

from core.routes import Hit, route

CVE = 'CVE-2025-5777'
PATH = '/p/u/doAuthentication.do'
CONTENT_TYPE = 'application/vnd.citrix.authenticateresponse-1.xml'
XML = ('<?xml version="1.0" encoding="UTF-8"?>\n'
       '<AuthenticateResponse xmlns="http://citrix.com/authentication/response/1"><Status>success</Status>'
       '<Result>more-info</Result><StateContext></StateContext><AuthenticationRequirements>'
       '<PostBack>' + PATH + '</PostBack><CancelPostBack>' + PATH + '</CancelPostBack>'
       '<CancelButtonText>Cancel</CancelButtonText><Requirements><Requirement><Credential><ID>login</ID>'
       '<SaveID>ExplicitForms-Username</SaveID><Type>username</Type></Credential>'
       '<Label><Text>User name</Text><Type>plain</Type></Label><Input><Text><Secret>false</Secret>'
       '<ReadOnly>false</ReadOnly><InitialValue>{iv}</InitialValue><Constraint>.+</Constraint></Text></Input>'
       '</Requirement></Requirements></AuthenticationRequirements></AuthenticateResponse>')


def _match(ctx):
    return ctx.method == 'POST' and ctx.bare == PATH


def _bleed_shaped(ctx):
    # `login` present without `=value`
    return re.match(r'^login(&|$)', ctx.body) is not None


def _respond(ctx, iv, message):
    return Hit('WARNING', 'Detected CVE-2025-5777 probe', data=XML.format(iv=iv).encode(), content_type=CONTENT_TYPE,
               event={'message': message, 'body': ctx.body[:4096]})


@route('cve-2025-5777', _match, cve=CVE, patched=lambda ctx: _respond(ctx, '', 'CitrixBleed 2 probe (patched)'))
def doauth(ctx):
    if _bleed_shaped(ctx):
        return _respond(ctx, 'HONEYPOT-FAKE-LEAK_' + secrets.token_hex(24), 'CitrixBleed 2 probe')
    return _respond(ctx, '', 'Authentication request')
