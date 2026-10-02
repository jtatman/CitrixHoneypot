"""core/tools.py's get_real_ip/get_real_port: X-Real-IP/X-Real-Port are only honoured when
[honeypot] trust_proxy_headers is explicitly enabled (off by default -- see CLAUDE.md bug 8)."""
from core.tools import get_real_ip, get_real_port


class FakeAddress:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class FakeRequest:
    def __init__(self, headers, client_ip='127.0.0.1', client_port=5555):
        self.headers = headers
        self._client = FakeAddress(client_ip, client_port)

    def getHeader(self, name):
        return self.headers.get(name)

    def getClientAddress(self):
        return self._client


def test_proxy_headers_ignored_by_default():
    req = FakeRequest({'X-Real-IP': '1.2.3.4', 'X-Real-Port': '9999'})
    assert get_real_ip(req) == '127.0.0.1'
    assert get_real_port(req) == 5555
    assert get_real_ip(req, {}) == '127.0.0.1'
    assert get_real_ip(req, {'trust_proxy_headers': False}) == '127.0.0.1'


def test_proxy_headers_honoured_when_enabled():
    req = FakeRequest({'X-Real-IP': '1.2.3.4', 'X-Real-Port': '9999'})
    cfg = {'trust_proxy_headers': True}
    assert get_real_ip(req, cfg) == '1.2.3.4'
    assert get_real_port(req, cfg) == '9999'


def test_enabled_but_header_absent_falls_back_to_socket():
    req = FakeRequest({})
    cfg = {'trust_proxy_headers': True}
    assert get_real_ip(req, cfg) == '127.0.0.1'
    assert get_real_port(req, cfg) == 5555


def test_event_src_ip_respects_trust_proxy_headers(make_index, send, capture):
    idx = make_index(trust_proxy_headers=True)
    send(idx, 'GET', '/vpn/../vpns/', headers={'X-Real-IP': '9.9.9.9', 'X-Real-Port': '1234'})
    assert capture.events[0]['src_ip'] == '9.9.9.9'
    assert capture.events[0]['src_port'] == '1234'


def test_event_src_ip_ignores_headers_by_default(make_index, send, capture):
    idx = make_index()
    send(idx, 'GET', '/vpn/../vpns/', headers={'X-Real-IP': '9.9.9.9', 'X-Real-Port': '1234'})
    assert capture.events[0]['src_ip'] == '127.0.0.1'
    assert capture.events[0]['src_port'] == 5555
