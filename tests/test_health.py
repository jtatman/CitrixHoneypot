"""core/health.py: the localhost-only liveness endpoint added in Phase 4."""
from io import BytesIO
from json import loads

from twisted.internet.address import IPv4Address
from twisted.web.test.requesthelper import DummyRequest

from core.health import HealthCheck
from core.profile import load_profile


def test_render_get_returns_ok_json():
    profile = load_profile('adc-12.1-vulnerable')
    check = HealthCheck(profile, '2.0.2')

    req = DummyRequest([b''])
    req.client = IPv4Address('TCP', '127.0.0.1', 5555)
    req.method = b'GET'
    req.uri = b'/health'
    req.content = BytesIO(b'')

    body = check.render_GET(req)
    data = loads(body)
    assert data['status'] == 'ok'
    assert data['version'] == '2.0.2'
    assert data['profile'] == 'adc-12.1-vulnerable'
    assert data['uptime'] >= 0
    assert req.responseCode == 200
