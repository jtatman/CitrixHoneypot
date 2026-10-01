"""output_plugins/elasticsearch.py: URL construction, auth header, JSON body, and error handling --
all without a real Elasticsearch instance, by monkeypatching urlopen."""
from json import loads

import pytest


def event(**overrides):
    base = {
        'eventid': 'citrix.connection', 'timestamp': '2026-09-30T00:00:00.000000Z', 'unixtime': 1.0,
        'src_ip': '127.0.0.1', 'src_port': 5555, 'dst_ip': '127.0.0.1', 'dst_port': 8443,
        'sensor': 'test', 'request': 'GET', 'url': '/', 'message': 'Scan type 1',
    }
    base.update(overrides)
    return base


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
def requests_made(monkeypatch):
    import output_plugins.elasticsearch as es_module

    calls = []

    def fake_urlopen(req, timeout=None, context=None):
        calls.append(req)

    monkeypatch.setattr(es_module, 'urlopen', fake_urlopen)
    return calls


def test_url_and_body(cfg, requests_made):
    from output_plugins.elasticsearch import Output

    cfg[('output_elasticsearch', 'host')] = 'es.local'
    cfg[('output_elasticsearch', 'port')] = 9200
    cfg[('output_elasticsearch', 'index')] = 'honeypot'
    out = Output({'sensor': 'test'})
    out.write(event())
    (req,) = requests_made
    assert req.full_url == 'http://es.local:9200/honeypot/_doc'
    assert req.get_method() == 'POST'
    assert loads(req.data)['message'] == 'Scan type 1'


def test_basic_auth_header_set_when_configured(cfg, requests_made):
    from output_plugins.elasticsearch import Output

    cfg[('output_elasticsearch', 'username')] = 'elastic'
    cfg[('output_elasticsearch', 'password')] = 'secret'
    out = Output({'sensor': 'test'})
    out.write(event())
    (req,) = requests_made
    assert req.get_header('Authorization').startswith('Basic ')


def test_no_auth_header_by_default(cfg, requests_made):
    from output_plugins.elasticsearch import Output

    out = Output({'sensor': 'test'})
    out.write(event())
    (req,) = requests_made
    assert req.get_header('Authorization') is None


def test_write_does_not_raise_when_urlopen_fails(cfg, monkeypatch):
    import output_plugins.elasticsearch as es_module
    from output_plugins.elasticsearch import Output

    def raising_urlopen(req, timeout=None, context=None):
        raise OSError('connection refused')

    monkeypatch.setattr(es_module, 'urlopen', raising_urlopen)
    out = Output({'sensor': 'test'})
    out.write(event())   # must not raise
