from pathlib import Path
from time import time

from twisted.web.resource import Resource

from core import tools
from core.routes import Ctx, dispatch

RESPONSES_DIR = Path(__file__).resolve().parent.parent / 'responses'
MAX_BODY = 1 << 20   # bytes of a request body we are willing to read/log

# NetScaler-style cookies, sent expired; the duplicates are deliberate (as on the real appliance)
COOKIES = [
    'NSC_AAAC=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_EPAC=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_USER=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_BASEURL=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'CsrfToken=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'CtxsAuthId=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'ASP.NET_SessionId=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_TMAA=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT',
    'NSC_TMAS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT',
    'NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT',
]


class Index(Resource):
    """Single entry point: normalise the request, dispatch to the route table, log, respond."""
    isLeaf = True

    def __init__(self, options):
        super().__init__()
        self.cfg = options
        self._pages = {}

    def render(self, request):
        # Overrides Resource.render so that custom HTTP methods are handled too.
        method = request.method.decode('ascii', 'replace')
        raw = request.content.read(MAX_BODY) if method == 'POST' else b''
        ctx = Ctx.build(method, request.uri, raw, self.cfg)

        tools.logger(request, 'INFO', '{}: {}'.format(method, ctx.path))
        route, hit = dispatch(ctx)

        if hit.log_msg:
            tools.logger(request, hit.log_level, hit.log_msg)
        if hit.event is not None:
            self.emit(request, ctx, route, hit)

        page = self.get_page(hit.page) if hit.page else ''
        for key, value in hit.subst.items():
            page = page.replace('{' + key + '}', value)
        return self.send_response(request, page)

    def emit(self, request, ctx, route, hit):
        unix_time = time()
        event = {
            'eventid': hit.eventid,
            'timestamp': tools.getutctime(unix_time),
            'unixtime': unix_time,
            'src_ip': tools.get_real_ip(request),
            'src_port': tools.get_real_port(request),
            'dst_ip': tools.getlocalip(),
            'dst_port': self.cfg['port'],
            'sensor': self.cfg['sensor'],
            'request': ctx.method,
            'url': ctx.path,
            'cve': route.cve,
            'route_id': route.id,
        }
        event.update(hit.event)
        tools.write_event(event, self.cfg)

    # a simple wrapper to cache files from the "responses" folder
    def get_page(self, name):
        if name not in self._pages:
            self._pages[name] = (RESPONSES_DIR / name).read_text()
        return self._pages[name]

    def send_response(self, request, page=''):
        body = page.encode('utf-8')
        request.setHeader('Server', 'Apache')
        for cookie in COOKIES:
            request.responseHeaders.addRawHeader(b'Set-Cookie', cookie.encode())
        request.setHeader('Connection', 'Close')
        request.setHeader('Content-Length', str(len(body)))
        request.setHeader('Cache-control', 'no-cache, no-store')
        request.setHeader('Pragma', 'no-cache')
        request.setHeader('Content-type', 'text/html')
        return body
