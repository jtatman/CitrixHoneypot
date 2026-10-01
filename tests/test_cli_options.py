"""CitrixHoneypot.py's get_options(): CLI/config wiring for the plain-HTTP listener, multiple TLS ports,
and --tls-profile added in Phase 4."""
import sys

import pytest

from CitrixHoneypot import get_options, parse_ports


def base_cfg(**overrides):
    cfg = {
        'addr': '0.0.0.0', 'port': 443, 'logfile': None, 'ssldir': 'ssl',
        'sensor': 'test', 'profile_name': 'adc-12.1-vulnerable', 'tls_profile_name': '',
        'http_port': 0, 'extra_ports': '',
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


def test_tls_profile_defaults_empty():
    args = get_options(base_cfg())
    assert args.tls_profile == ''


def test_tls_profile_from_config_and_cli(monkeypatch):
    args = get_options(base_cfg(tls_profile_name='adc-14.1-73.33-vulnerable'))
    assert args.tls_profile == 'adc-14.1-73.33-vulnerable'

    monkeypatch.setattr(sys, 'argv', ['CitrixHoneypot.py', '--tls-profile', 'adc-12.1-vulnerable'])
    args = get_options(base_cfg(tls_profile_name='adc-14.1-73.33-vulnerable'))
    assert args.tls_profile == 'adc-12.1-vulnerable'


def test_extra_ports_default_empty():
    args = get_options(base_cfg())
    assert args.ports == ''


def test_extra_ports_from_config_and_cli(monkeypatch):
    args = get_options(base_cfg(extra_ports='8443,3010'))
    assert args.ports == '8443,3010'

    monkeypatch.setattr(sys, 'argv', ['CitrixHoneypot.py', '--ports', '9443'])
    args = get_options(base_cfg(extra_ports='8443,3010'))
    assert args.ports == '9443'


@pytest.mark.parametrize('spec,expected', [
    ('', []),
    ('8443', [8443]),
    ('8443,3010', [8443, 3010]),
    (' 8443 , 3010 ', [8443, 3010]),
])
def test_parse_ports(spec, expected):
    assert parse_ports(spec) == expected
