"""output_plugins/syslog.py: CEF/JSON framing, UDP vs TCP send path, and error handling -- all without
a real syslog server, via a fake socket."""
from json import loads

import pytest


def event(**overrides):
    base = {
        'eventid': 'citrix.connection', 'timestamp': '2026-09-30T00:00:00.000000Z', 'unixtime': 1.0,
        'src_ip': '127.0.0.1', 'src_port': 5555, 'dst_ip': '127.0.0.1', 'dst_port': 8443,
        'sensor': 'test', 'request': 'GET', 'url': '/vpn/../vpns/', 'message': 'Scan type 1',
        'cve': 'CVE-2019-19781', 'route_id': 'scan-type1',
    }
    base.update(overrides)
    return base


class FakeSocket:
    instances = []

    def __init__(self, *a, **kw):
        self.sent = []
        self.connected_to = None
        self.closed = False
        FakeSocket.instances.append(self)

    def settimeout(self, t):
        pass

    def connect(self, addr):
        self.connected_to = addr

    def sendall(self, data):
        self.sent.append(data)

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


@pytest.fixture
def cfg(monkeypatch):
    from core.config import CONFIG
    overrides = {}

    def get(section, option, fallback=None, **kw):
        return overrides.get((section, option), fallback)

    def getint(section, option, fallback=None, **kw):
        return overrides.get((section, option), fallback)

    def getboolean(section, option, fallback=None, **kw):
        return overrides.get((section, option), fallback)

    monkeypatch.setattr(CONFIG, 'get', get)
    monkeypatch.setattr(CONFIG, 'getint', getint)
    monkeypatch.setattr(CONFIG, 'getboolean', getboolean)
    return overrides


@pytest.fixture
def fake_socket(monkeypatch):
    import output_plugins.syslog as syslog_module

    FakeSocket.instances = []
    monkeypatch.setattr(syslog_module.socket, 'socket', FakeSocket)
    return FakeSocket


def test_udp_cef_by_default(cfg, fake_socket):
    from output_plugins.syslog import Output

    cfg[('output_syslog', 'host')] = 'siem.local'
    cfg[('output_syslog', 'port')] = 514
    out = Output({'sensor': 'test'})
    out.write(event())
    (sock,) = fake_socket.instances
    (data, addr) = sock.sent[0]
    assert addr == ('siem.local', 514)
    assert data.startswith(b'<')
    assert b'CEF:0|CitrixHoneypot|CitrixHoneypot|2.0|scan-type1|Scan type 1|5|' in data
    assert b'src=127.0.0.1' in data and b'cs1=CVE-2019-19781' in data


def test_payload_event_uses_warning_severity(cfg, fake_socket):
    from output_plugins.syslog import Output

    out = Output({'sensor': 'test'})
    out.write(event(eventid='citrix.payload', message='Exploit'))
    (sock,) = fake_socket.instances
    (data, _addr) = sock.sent[0]
    assert b'|4|' in data   # CEF severity field


def test_json_format(cfg, fake_socket):
    from output_plugins.syslog import Output

    cfg[('output_syslog', 'format')] = 'json'
    out = Output({'sensor': 'test'})
    out.write(event())
    (sock,) = fake_socket.instances
    (data, _addr) = sock.sent[0]
    body = data.decode().split(': ', 1)[1]
    assert loads(body)['message'] == 'Scan type 1'


def test_tcp_connects_and_sends(cfg, fake_socket):
    from output_plugins.syslog import Output

    cfg[('output_syslog', 'protocol')] = 'tcp'
    cfg[('output_syslog', 'host')] = 'siem.local'
    cfg[('output_syslog', 'port')] = 601
    out = Output({'sensor': 'test'})
    out.write(event())
    (sock,) = fake_socket.instances
    assert sock.connected_to == ('siem.local', 601)
    assert sock.sent[0].endswith(b'\n')


def test_tcp_reconnects_after_send_failure(cfg, fake_socket):
    from output_plugins.syslog import Output

    cfg[('output_syslog', 'protocol')] = 'tcp'
    out = Output({'sensor': 'test'})
    out.write(event())
    (first_sock,) = fake_socket.instances
    first_sock.sendall = lambda data: (_ for _ in ()).throw(OSError('broken pipe'))
    out.write(event())
    assert first_sock.closed
    assert out.sock is None
