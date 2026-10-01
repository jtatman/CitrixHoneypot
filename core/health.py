"""Localhost-only liveness endpoint for local-lab orchestration (docker-compose healthcheck, etc.).

Deliberately not part of core/routes/: it's an operator-facing ops endpoint, not part of the emulated
Citrix surface, so hits here are never logged as honeypot events and it never counts towards any CVE
state.
"""
from json import dumps
from time import time

from twisted.web.resource import Resource


class HealthCheck(Resource):
    isLeaf = True

    def __init__(self, profile, version):
        super().__init__()
        self.profile = profile
        self.version = version
        self.started = time()

    def render_GET(self, request):
        request.setResponseCode(200)
        request.setHeader(b'Content-Type', b'application/json')
        body = dumps({
            'status': 'ok',
            'version': self.version,
            'profile': self.profile.name,
            'uptime': round(time() - self.started, 1),
        }).encode()
        return body
