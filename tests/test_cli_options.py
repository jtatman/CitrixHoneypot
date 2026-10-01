"""CitrixHoneypot.py's get_options(): CLI/config wiring for the plain-HTTP listener added in Phase 4."""
import sys

import pytest

from CitrixHoneypot import get_options


def base_cfg(**overrides):
    cfg = {
        'addr': '0.0.0.0', 'port': 443, 'logfile': None, 'ssldir': 'ssl',
        'sensor': 'test', 'profile_name': 'adc-12.1-vulnerable', 'http_port': 0,
    }
    cfg.update(overrides)
    return cfg


@pytest.fixture(autouse=True)
def _argv(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['CitrixHoneypot.py'])


def test_http_port_defaults_to_config_value():
    args = get_options(base_cfg(http_port=3010))
    assert args.http_port == 3010


def test_http_port_disabled_by_default():
    args = get_options(base_cfg())
    assert args.http_port == 0


def test_http_port_overridable_on_cli(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['CitrixHoneypot.py', '--http-port', '8080'])
    args = get_options(base_cfg())
    assert args.http_port == 8080
