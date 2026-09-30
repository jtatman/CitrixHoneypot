"""output_plugins/jsonlog.py: file mode (existing behaviour) and the stdout mode added in Phase 4."""
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

    monkeypatch.setattr(CONFIG, 'get', get)
    monkeypatch.setattr(CONFIG, 'getboolean', lambda section, option, fallback=None, **kw: fallback)
    return overrides


def test_file_mode_writes_jsonl(cfg, tmp_path):
    from output_plugins.jsonlog import Output

    logfile = tmp_path / 'log' / 'honeypot.json'
    cfg[('output_jsonlog', 'logfile')] = str(logfile)
    out = Output({'sensor': 'test'})
    out.write(event())
    out.stop()
    lines = logfile.read_text().strip().splitlines()
    assert len(lines) == 1
    assert loads(lines[0])['message'] == 'Scan type 1'
    assert 'unixtime' not in loads(lines[0])


@pytest.mark.parametrize('marker', ['-', 'stdout'])
def test_stdout_mode_writes_jsonl_to_stdout(cfg, marker, capsys):
    from output_plugins.jsonlog import Output

    cfg[('output_jsonlog', 'logfile')] = marker
    out = Output({'sensor': 'test'})
    out.write(event())
    out.stop()
    captured = capsys.readouterr()
    lines = captured.out.strip().splitlines()
    assert len(lines) == 1
    assert loads(lines[0])['message'] == 'Scan type 1'
