"""Recognisable NetScaler Gateway surface, enabled by the profile feature ``netscaler-surface``.

Everything here is what version/patch fingerprinters request, taken from:
  https://github.com/technion/netscaler_scanner   (fingerprint.sh: tmindex.html + nsepa.deb size, CTX697096)
  https://github.com/jtatman/citrixscan           (rdx_en.json.gz gzip MTIME -> build, Fox-IT technique)
Bodies are stand-ins: only sizes/timestamps/markers that scanners key on are meaningful.
"""
import gzip
import re

from core.routes import Hit, route

FEATURE = 'netscaler-surface'
LOGON_PAGES = ('/logon/LogonPoint/tmindex.html', '/logon/LogonPoint/index.html', '/vpn/tmindex.html')
CTXS_JS = '/logon/LogonPoint/receiver/js/ctxs.core.min.js'
EPA_DEB = '/epa/scripts/linux/nsepa.deb'
RDX_EN = '/vpn/js/rdx/core/lang/rdx_en.json.gz'
CTXS_JS_BODY = b'var CTXS = CTXS || {}; CTXS.AccessGateway = {}; CTXS.WebApiClient = {};\n'


def _on(ctx):
    return ctx.profile is not None and ctx.profile.has(FEATURE) and ctx.method in ('GET', 'HEAD')


@route('ns-logon-page', lambda c: _on(c) and c.bare in LOGON_PAGES)
def logon_page(ctx):
    return Hit(page='logonpoint.html', event={'message': 'Fingerprint probe (logon page)'})


@route('ns-ctxs-js', lambda c: _on(c) and c.bare == CTXS_JS)
def ctxs_js(ctx):
    return Hit(data=CTXS_JS_BODY, content_type='application/javascript')


def _range(header, size):
    """(start, end) inclusive for a single 'bytes=' range, or None (serve the whole file)."""
    m = re.fullmatch(r'bytes=(\d*)-(\d*)', (header or '').strip())
    if not m or not (m.group(1) or m.group(2)):
        return None
    if m.group(1):
        start = int(m.group(1))
        end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
    else:   # suffix range: last N bytes
        start, end = max(size - int(m.group(2)), 0), size - 1
    return (start, end) if 0 <= start <= end < size else None


@route('ns-epa-deb', lambda c: _on(c) and c.bare == EPA_DEB and c.profile.epa_deb_size > 0)
def epa_deb(ctx):
    # Patch oracle: the size of this served file differs between builds (technion/netscaler_scanner).
    size = ctx.profile.epa_deb_size
    event = {'message': 'Patch-status probe (nsepa.deb)'}
    if ctx.method == 'HEAD':   # the real appliance answers HEAD without a Content-Length
        return Hit(data=b'', content_type='application/octet-stream', event=event)
    rng = _range(ctx.range, size)
    if rng:
        start, end = rng
        return Hit(status=206, data=bytes(end - start + 1), content_type='application/octet-stream',
                   headers={'Content-Range': 'bytes {}-{}/{}'.format(start, end, size)}, event=event)
    return Hit(data=b'!<arch>\n' + bytes(size - 8), content_type='application/octet-stream', event=event)


@route('ns-rdx-en-gz', lambda c: _on(c) and c.bare == RDX_EN and bool(c.profile.gzip_mtime()))
def rdx_en(ctx):
    # The gzip header MTIME is what version fingerprinters read (bytes 4-8).
    return Hit(data=gzip.compress(b'{}\n', mtime=ctx.profile.gzip_mtime()), content_type='application/x-gzip',
               event={'message': 'Fingerprint probe (rdx_en.json.gz)'})
