"""CVE-2026-88771 (CTX697096 unauthenticated RCE) attempt/IOC fingerprinting.

Citrix/GreyNoise have not published the exploitation chain itself, but GreyNoise's IOC blog (2026-09-28,
https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation) names concrete observables from a
real attack it caught pre-disclosure:
  - GreyNoise's own tag for the attempt is "Citrix NetScaler CVE-2026-88771 Login Command Injection RCE
    Attempt", alongside a generic "Generic ${IFS} Use in RCE Attempt" tag -- i.e. the injection rides in a
    login POST and uses ${IFS} (a classic space-avoiding shell trick) as its signature.
  - Post-exploitation, the actor tried to plant a password-protected webshell at
    /var/netscaler/logon/LogonPoint/custom/.ctxs.receiver, then alias it behind
    receiver.min.css and an AliasMatch pattern receiver\\.min\\.[0-9a-f]+\\.css so it isn't obviously a
    dotfile in web logs. Its SHA-256 is 6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7.

watchTowr Labs' own detection-artifact tool (https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771,
verified 2026-09-29) confirms the exploitation primitive itself is *log poisoning*: it builds the exact
payload `pitboss PPE unexpectedly died NSPPE;<command>;# X` (spoofing an internal "pitboss" process-death log
line from NetScaler's Packet Processing Engine), writes it somewhere that reaches the appliance's own log
stream, then triggers a "force pickup" that re-parses and executes the poisoned line. The tool doesn't name
which endpoint carries the payload into the logs, so we can't tie this to one specific path -- but the
payload string itself is a highly specific, attacker-only signature: no legitimate client would ever send
it. We match on that literal substring appearing anywhere (any path or POST body), regardless of endpoint.

This route only recognises those three published observables (an injection *attempt* signature, a
log-poisoning payload signature, and a webshell-checking-in-on-a-patched-box IOC scan) -- it never executes
anything from the request, and the "webshell" path genuinely doesn't exist on disk here, so it truthfully
404s either way. The webshell check-in and log-poison signature are logged unconditionally (evidence worth
capturing regardless of whether this profile currently looks vulnerable or patched).
"""
import re

from core.routes import Hit, route

CVE = 'CVE-2026-88771'
LOGIN_PATHS = ('/cgi/login', '/nf/auth/doAuthentication.do')
# NOTE: /p/u/doAuthentication.do is deliberately excluded -- it's CVE-2025-5777's endpoint (cve_2025_5777.py
# already matches every POST there) and is registered earlier, so it would shadow this route anyway.
WEBSHELL_DOTFILE = '/logon/LogonPoint/custom/.ctxs.receiver'
WEBSHELL_ALIAS_RE = re.compile(r'^/logon/LogonPoint/custom/receiver\.min\.([0-9a-f]+\.)?css$')


def _login_injection(ctx):
    return ctx.method == 'POST' and ctx.bare in LOGIN_PATHS and '${IFS}' in ctx.body


def _login_response(ctx, message):
    return Hit('CRITICAL', 'Detected {} probe ({})'.format(CVE, message), page=ctx.profile.login_page,
               event={'message': message, 'body': ctx.body[:4096]})


@route('cve-2026-88771-login-injection', _login_injection, cve=CVE,
       patched=lambda ctx: _login_response(ctx, 'Login command-injection attempt (${IFS}, patched build)'))
def login_injection(ctx):
    return _login_response(ctx, 'Login command-injection attempt (${IFS})')


def _webshell_checkin(ctx):
    return ctx.method == 'GET' and (ctx.bare == WEBSHELL_DOTFILE or WEBSHELL_ALIAS_RE.match(ctx.bare))


@route('cve-2026-88771-webshell-checkin', _webshell_checkin)   # not CVE-gated: an IOC scan, not exploitation
def webshell_checkin(ctx):
    return Hit('CRITICAL', 'Webshell check-in probe for {} (GreyNoise IOC path {})'.format(CVE, ctx.bare),
               page='404.html', subst={'url': ctx.path}, status=404,
               event={'message': 'Post-exploitation webshell check-in probe',
                      'ioc_source': 'https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation'})


LOG_POISON_SIGNATURE = 'pitboss PPE unexpectedly died NSPPE'


def _log_poison_attempt(ctx):
    return LOG_POISON_SIGNATURE in ctx.path or LOG_POISON_SIGNATURE in ctx.body


def _log_poison_response(ctx, message):
    return Hit('CRITICAL', 'Detected {} probe ({})'.format(CVE, message), page=ctx.profile.login_page,
               event={'message': message, 'body': ctx.body[:4096],
                      'ioc_source': 'https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771'})


@route('cve-2026-88771-log-poison', _log_poison_attempt, cve=CVE,
       patched=lambda ctx: _log_poison_response(ctx, 'Log-poisoning attempt (pitboss PPE spoof, patched build)'))
def log_poison(ctx):
    return _log_poison_response(ctx, 'Log-poisoning attempt (pitboss PPE spoof)')
