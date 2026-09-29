"""Generic attempt/IOC fingerprinting for paths that are not tied to a single CVE but are still
recognisable evidence of a specific tool or campaign probing this host.

Per the honeypot's actual purpose: capturing *what was attempted* (which known webshell/backdoor a scanner
checked for, which management path it tried) has value on its own, even without an exploit-confirmation
oracle for the underlying bug -- see CLAUDE.md's CVE-2026-88771 entry for the same reasoning applied to a
single CVE. These two path lists are vendored from jtatman/citrixscan (MIT), IOC_PATHS/MISCONFIG_PATHS in
citrixscan.py, cited there as: known webshell locations from CVE-2023-3519 campaigns + CISA AA23-201A
indicators (IOC_PATHS), and NITRO/management/diagnostic paths that "should not be externally accessible
without auth" (MISCONFIG_PATHS). Not CVE-gated: a scanner checking for a known backdoor, or probing a
management endpoint, is worth logging regardless of which CVE (if any) this profile currently looks
vulnerable to. Every response here is truthful (404/empty) -- none of these files or endpoints exist here.
"""
from core.routes import Hit, route

SOURCE = 'https://github.com/jtatman/citrixscan citrixscan.py IOC_PATHS/MISCONFIG_PATHS (MIT)'

# Excludes /vpns/portal/scripts/{newbm,rmbm}.pl: those are core/routes/cve_2019_19781.py's struggle-check
# paths already, with their own dedicated (and older) handling; duplicating them here would shadow that.
IOC_PATHS = frozenset((
    '/vpn/media/logo.png.php',
    '/vpn/media/ns_gui/vpn/media/MediaServlet',
    '/vpn/media/test.html',
    '/vpns/portal/scripts/test.pl',
    '/vpns/portal/scripts/ns_gui.pl',
    '/logon/LogonPoint/custom/login.php',
    '/logon/LogonPoint/custom/config.php',
    '/logon/LogonPoint/Resources/skin/skin.php',
    '/vpn/js/info.php',
    '/vpn/js/cmd.php',
    '/vpn/themes/default/info.php',
))

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


def _truthful_404(ctx, message):
    return Hit('WARNING', message, page='404.html', subst={'url': ctx.path}, status=404,
               event={'message': message, 'ioc_source': SOURCE})


@route('ioc-webshell-probe', lambda c: c.method == 'GET' and c.bare in IOC_PATHS)
def webshell_probe(ctx):
    return _truthful_404(ctx, 'Known webshell/backdoor IOC path probe: {}'.format(ctx.bare))


@route('ioc-misconfig-probe', lambda c: c.method == 'GET' and c.bare in MISCONFIG_PATHS)
def misconfig_probe(ctx):
    return _truthful_404(ctx, 'Management/diagnostic endpoint probe: {}'.format(ctx.bare))
