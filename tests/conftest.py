from io import BytesIO
from pathlib import Path

import pytest
from twisted.internet.address import IPv4Address
from twisted.web.test.requesthelper import DummyRequest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _repo_root(monkeypatch):
    # responses/ and etc/ are opened via relative paths
    monkeypatch.chdir(ROOT)


class Capture:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


@pytest.fixture
def capture():
    return Capture()


@pytest.fixture
def make_index(capture):
    from core.protocol import Index

    def factory(**overrides):
        cfg = {'port': 443, 'sensor': 'test', 'struggle': False, 'output_plugins': [capture]}
        cfg.update(overrides)
        return Index(cfg)

    return factory


@pytest.fixture
def index(make_index):
    return make_index()


@pytest.fixture
def send():
    """Drive Index.render() (the entry point Twisted calls) and return (body, request)."""

    def _send(index, method, uri, body=b'', headers=None):
        req = DummyRequest([b''])
        req.client = IPv4Address('TCP', '127.0.0.1', 5555)
        req.method = method.encode()
        req.uri = uri.encode() if isinstance(uri, str) else uri
        req.content = BytesIO(body)
        req.requestHeaders.setRawHeaders(b'content-length', [str(len(body)).encode()]) if body else None
        for k, v in (headers or {}).items():
            req.requestHeaders.setRawHeaders(k.encode(), [v.encode()])
        return index.render(req), req

    return _send
