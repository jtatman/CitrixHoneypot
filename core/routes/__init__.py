"""Declarative route table.

A Route pairs a ``match`` predicate with a ``handle`` function returning a Hit.
Routes are tried in registration order and the first match wins.
Route modules register themselves with @route at import time.
"""
from dataclasses import dataclass, field
from importlib import import_module
from typing import Callable, Dict, List, Optional
from urllib.parse import unquote

from core import tools


@dataclass
class Ctx:
    """A request, normalised once, as seen by route matchers/handlers."""
    method: str
    path: str                 # percent-decoded request target (incl. query string)
    collapsed: str            # ``path`` with any ../ segments resolved
    raw_segments: List[str]   # non-empty segments of ``path``
    segments: List[str]       # non-empty segments of ``collapsed``
    traversal: bool           # ``/../`` present in ``path``
    body: str
    cfg: dict
    profile: object = None    # core.profile.Profile the honeypot is currently impersonating
    range: str = ''           # Range request header, if any
    host: str = ''            # Host request header, if any (oversized-header probes key on its length)
    nitro_user: str = ''      # X-NITRO-USER header, if any (CVE-2020-8193 family's auth-bypass signature)
    nitro_pass: str = ''      # X-NITRO-PASS header, if any
    rand_key: str = ''        # rand_key header, if any (CVE-2020-8193 family's scraped-token signature)

    @property
    def bare(self) -> str:
        """Collapsed path without the query string."""
        return self.collapsed.split('?')[0]

    @classmethod
    def build(cls, method: str, uri: bytes, body: bytes, cfg: dict, profile=None, range_header: str = '',
              host_header: str = '', nitro_user: str = '', nitro_pass: str = '', rand_key: str = '') -> 'Ctx':
        path = unquote(uri.decode('utf-8', 'replace'))
        bare_path = path.split('?', 1)[0]   # segments must never include the query string (see bug note below)
        traversal = bare_path.find('/../') != -1
        collapsed = tools.resolve_url(path) if traversal else path
        return cls(
            method=method,
            path=path,
            collapsed=collapsed,
            # BUG (found 2026-09-30 via nmap testing, present since before this fork): splitting the raw
            # ``path``/``collapsed`` strings on '/' without first stripping the query string turns e.g.
            # '/?x=1' into a single fake segment ['?x=1'] instead of the empty root segment list routes like
            # cve_2019_19781's login page expect -- so any GET to '/' (or '/vpn/') with a query string, which
            # is completely ordinary traffic (SSO/deep-link redirects), used to 404 instead of getting the
            # login page. Fixed by splitting on the query-stripped path instead.
            raw_segments=[s for s in bare_path.split('/') if s],
            segments=[s for s in collapsed.split('?', 1)[0].split('/') if s],
            traversal=traversal,
            body=body.decode('utf-8', 'replace'),
            cfg=cfg,
            profile=profile,
            range=range_header or '',
            host=host_header or '',
            nitro_user=nitro_user or '',
            nitro_pass=nitro_pass or '',
            rand_key=rand_key or '',
        )


@dataclass
class Hit:
    """What a route decided: log line, optional event, response body."""
    log_level: str = 'INFO'
    log_msg: str = ''
    page: str = ''                 # file in responses/ to serve
    subst: Dict[str, str] = field(default_factory=dict)   # {name} -> value replacements in the page
    event: Optional[Dict] = None   # extra fields merged into the base event; None = no event
    eventid: str = 'citrix.connection'
    status: int = 200
    data: Optional[bytes] = None   # raw body; takes precedence over page
    content_type: str = 'text/html'
    headers: Dict[str, str] = field(default_factory=dict)   # extra response headers
    cookies: List[str] = field(default_factory=list)        # extra Set-Cookie values, appended after the profile's


@dataclass
class Route:
    id: str
    cve: Optional[str]
    match: Callable[[Ctx], bool]
    handle: Callable[[Ctx], Hit]
    patched: Optional[Callable[[Ctx], Hit]] = None   # what a patched build does instead of the generic not-found


ROUTES: List[Route] = []


def route(id, match, cve=None, patched=None):
    """Decorator registering ``handle`` as the handler of route ``id``."""
    def deco(handle):
        ROUTES.append(Route(id, cve, match, handle, patched))
        return handle
    return deco


def dispatch(ctx: Ctx):
    """Return (route, hit) for the first matching route, or (None, Hit()).

    Profile CVE states: 'off' skips the route; 'patched' keeps the logging/event but swaps the response
    for the profile's patched response, so attempts are still recorded.
    """
    prof = ctx.profile
    for r in ROUTES:
        state = prof.state(r.cve) if (prof and r.cve) else 'vulnerable'
        if state == 'off' or not r.match(ctx):
            continue
        if state == 'patched' and r.patched:
            hit = r.patched(ctx)
            hit.event = dict(hit.event, patched=True) if hit.event is not None else None
            return r, hit
        hit = r.handle(ctx)
        if state == 'patched':
            # Build a plain not-found response from scratch rather than `replace()`-ing the vulnerable Hit:
            # its `data`/`cookies`/`headers` would otherwise leak through unchanged (only page/status get
            # overridden), since `data` takes priority over `page` in protocol.py regardless of state.
            event = dict(hit.event, patched=True) if hit.event is not None else None
            hit = Hit(page=prof.patched_page, subst={'url': ctx.collapsed}, status=prof.patched_status,
                     event=event)
        return r, hit
    nf = prof.not_found if prof else None
    if nf:   # modern profiles: unmatched paths are a real 404, not a 200/empty soft-404
        return None, Hit(page=nf['page'], subst={'url': ctx.path}, status=nf['status'])
    return None, Hit()


# Registration order is match order: specific routes first, the legacy catch-alls (any POST body, /vpns/*) last.
for _name in ('cve_2020_8193', 'cve_2023_3519', 'cve_2023_4966', 'cve_2023_6549', 'cve_2025_5777',
              'cve_2026_3055', 'cve_2026_88771', 'ioc_probes', 'waf_block', 'netscaler_surface',
              'cve_2019_19781'):
    import_module('core.routes.' + _name)
