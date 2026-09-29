"""Generic attempt/IOC fingerprinting for paths that are not tied to a single CVE but are still
recognisable evidence of a specific tool or campaign probing this host.

Per the honeypot's actual purpose: capturing *what was attempted* (which known webshell/backdoor a scanner
checked for, which management path it tried) has value on its own, even without an exploit-confirmation
oracle for the underlying bug -- see CLAUDE.md's CVE-2026-88771 entry for the same reasoning applied to a
single CVE. Not CVE-gated: a scanner checking for a known backdoor, or probing a management endpoint, is
worth logging regardless of which CVE (if any) this profile currently looks vulnerable to. Every response
here is truthful (404/empty) -- none of these files or endpoints exist here.
"""
from core.routes import Hit, route

CITRIXSCAN_SOURCE = 'https://github.com/jtatman/citrixscan citrixscan.py IOC_PATHS (MIT)'

# path -> where the IOC comes from. Excludes /vpns/portal/scripts/{newbm,rmbm}.pl: those are
# core/routes/cve_2019_19781.py's struggle-check paths already, with their own (older) dedicated handling;
# duplicating them here would shadow that.
IOC_PATHS = {
    '/vpn/media/logo.png.php': CITRIXSCAN_SOURCE,
    '/vpn/media/ns_gui/vpn/media/MediaServlet': CITRIXSCAN_SOURCE,
    '/vpn/media/test.html': CITRIXSCAN_SOURCE,
    '/vpns/portal/scripts/test.pl': CITRIXSCAN_SOURCE,
    '/vpns/portal/scripts/ns_gui.pl': CITRIXSCAN_SOURCE,
    '/logon/LogonPoint/custom/login.php': CITRIXSCAN_SOURCE,
    '/logon/LogonPoint/custom/config.php': CITRIXSCAN_SOURCE,
    '/logon/LogonPoint/Resources/skin/skin.php': CITRIXSCAN_SOURCE,
    '/vpn/js/info.php': CITRIXSCAN_SOURCE,
    '/vpn/js/cmd.php': CITRIXSCAN_SOURCE,
    '/vpn/themes/default/info.php': CITRIXSCAN_SOURCE,
    # CVE-2026-8452 (SAML SP/IdP pre-auth heap overflow -> RCE, fixed 14.1-72.61/13.1-63.18): the tool's own
    # README shows the resulting webshell served at this path with a `?0=<cmd>` query parameter.
    '/vpn/theme/x.php': 'https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452',
}

# Excludes /menu/ss, /menu/neo, /menu/stc: core/routes/cve_2020_8193.py already owns those (more specific:
# tied to a real CVE with verified fixed versions).
MISCONFIG_PATHS = frozenset((
    '/nitro/v1/config/nsconfig',
    '/nitro/v1/config/nshardware',
    '/nitro/v1/config/nsip',
    '/nitro/v1/config/sslcertkey',
    '/nitro/v1/stat/system',
    '/gui/',
    '/nsconfig/ns.conf',
    '/var/log/ns.log',
    '/var/nstrace/',
))


def _truthful_404(ctx, message, ioc_source):
    return Hit('WARNING', message, page='404.html', subst={'url': ctx.path}, status=404,
               event={'message': message, 'ioc_source': ioc_source})


@route('ioc-webshell-probe', lambda c: c.method == 'GET' and c.bare in IOC_PATHS)
def webshell_probe(ctx):
    return _truthful_404(ctx, 'Known webshell/backdoor IOC path probe: {}'.format(ctx.bare), IOC_PATHS[ctx.bare])


@route('ioc-misconfig-probe', lambda c: c.method == 'GET' and c.bare in MISCONFIG_PATHS)
def misconfig_probe(ctx):
    return _truthful_404(ctx, 'Management/diagnostic endpoint probe: {}'.format(ctx.bare), CITRIXSCAN_SOURCE)
