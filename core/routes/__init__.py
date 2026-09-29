"""Declarative route table.

A Route pairs a ``match`` predicate with a ``handle`` function returning a Hit.
Routes are tried in registration order and the first match wins.
Route modules register themselves with @route at import time.
"""
from dataclasses import dataclass, field
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

    @classmethod
    def build(cls, method: str, uri: bytes, body: bytes, cfg: dict) -> 'Ctx':
        path = unquote(uri.decode('utf-8', 'replace'))
        traversal = path.find('/../') != -1
        collapsed = tools.resolve_url(path) if traversal else path
        return cls(
            method=method,
            path=path,
            collapsed=collapsed,
            raw_segments=[s for s in path.split('/') if s],
            segments=[s for s in collapsed.split('/') if s],
            traversal=traversal,
            body=body.decode('utf-8', 'replace'),
            cfg=cfg,
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


@dataclass
class Route:
    id: str
    cve: Optional[str]
    match: Callable[[Ctx], bool]
    handle: Callable[[Ctx], Hit]


ROUTES: List[Route] = []


def route(id, match, cve=None):
    """Decorator registering ``handle`` as the handler of route ``id``."""
    def deco(handle):
        ROUTES.append(Route(id, cve, match, handle))
        return handle
    return deco


def dispatch(ctx: Ctx):
    """Return (route, hit) for the first matching route, or (None, Hit())."""
    for r in ROUTES:
        if r.match(ctx):
            return r, r.handle(ctx)
    return None, Hit()


from core.routes import cve_2019_19781  # noqa: E402,F401  (registers routes)
