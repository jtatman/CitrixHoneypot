"""CVE-2023-4966 (CitrixBleed), CVE-2023-6549 and CVE-2026-3055 (memory-overread family).

These are all detection oracles: the honeypot never reads real memory. "Leaked" bytes are random and
clearly marked (HONEYPOT-FAKE-LEAK / a base64 blob decoding to the same), which these tests assert on.
"""
import base64
import re

import pytest

from core.profile import load_profile

# 14.1-8.10 predates every fixed_versions entry for all three CVEs below -> vulnerable to all of them
VULN_BUILD = '14.1-8.10'
OVERSIZED_HOST = 'A' * 300


@pytest.fixture
def vuln(make_index):
    p = load_profile('adc-14.1-73.33-vulnerable')
    p.build = VULN_BUILD
    return make_index(profile=p)


@pytest.fixture
def patched(make_index):
    return make_index(profile=load_profile('adc-14.1-73.37-patched'))   # 73.37 is fixed for all three


# --- CVE-2023-4966 "CitrixBleed" ------------------------------------------------------------------------
def test_citrixbleed_oidc_leak_shape(vuln, send, capture):
    body, req = send(vuln, 'GET', '/oauth/idp/.well-known/openid-configuration', headers={'Host': OVERSIZED_HOST})
    assert req.responseCode == 200 and body.startswith(b'{"issuer":')
    m = re.search(rb'HONEYPOT-FAKE-LEAK: ([a-f0-9]{100}45525d5f4f58455e445a4a42)', body)
    assert m, body
    assert capture.events[0]['cve'] == 'CVE-2023-4966' and capture.events[0]['leaked_fake'] == m.group(1).decode()


def test_citrixbleed_requires_oversized_host(vuln, send, capture):
    body, req = send(vuln, 'GET', '/oauth/idp/.well-known/openid-configuration', headers={'Host': 'localhost'})
    assert b'HONEYPOT-FAKE-LEAK' not in body   # falls through: not our route, so no CVE event at all
    assert not any(e.get('cve') == 'CVE-2023-4966' for e in capture.events)


def test_citrixbleed_patched_no_leak(patched, send, capture):
    body, req = send(patched, 'GET', '/oauth/idp/.well-known/openid-configuration', headers={'Host': OVERSIZED_HOST})
    assert req.responseCode == 200 and body == b'{"issuer":"https://' + OVERSIZED_HOST.encode() + b'"}'
    assert capture.events[0]['patched'] is True


def test_citrixbleed_session_replay_logged(vuln, send, capture):
    body, req = send(vuln, 'POST', '/logon/LogonPoint/Authentication/GetUserName', b'Cookie-ish: NSC_AAAC=deadbeef')
    assert req.responseCode == 200 and b'NSC_AAAC=' in body
    assert capture.events[0]['route_id'] == 'cve-2023-4966-replay'


# --- CVE-2023-6549 ---------------------------------------------------------------------------------------
def test_cve_2023_6549_oversized_host(vuln, send, capture):
    body, req = send(vuln, 'GET', '/nf/auth/startwebview.do', headers={'Host': OVERSIZED_HOST})
    assert req.responseCode == 200
    assert b'/nf/auth/webview/done' in body and b'AuthenticationRequirements' in body
    assert capture.events[0]['cve'] == 'CVE-2023-6549'


def test_cve_2023_6549_normal_host_not_matched(vuln, send, capture):
    send(vuln, 'GET', '/nf/auth/startwebview.do', headers={'Host': 'localhost'})
    assert not any(e.get('cve') == 'CVE-2023-6549' for e in capture.events)


def test_cve_2023_6549_patched_by_build(patched, send, capture):
    body, req = send(patched, 'GET', '/nf/auth/startwebview.do', headers={'Host': OVERSIZED_HOST})
    assert req.responseCode == 404   # fixed build: falls through to the profile's not_found


# --- CVE-2026-3055 ----------------------------------------------------------------------------------------
def test_cve_2026_3055_wsfed_passive(vuln, send, capture):
    body, req = send(vuln, 'GET', '/wsfed/passive?wctx')
    assert req.responseCode == 302 and body == b''
    cookies = req.responseHeaders.getRawHeaders(b'set-cookie')
    tass = next(c for c in cookies if c.startswith(b'NSC_TASS='))
    encoded = tass.split(b'=', 1)[1].split(b';', 1)[0]
    decoded = base64.b64decode(encoded)
    assert decoded.startswith(b'wctx=HONEYPOT-FAKE-LEAK-')
    assert b'Parsing of presented Assertion failed' not in body
    assert capture.events[0]['cve'] == 'CVE-2026-3055'


def test_cve_2026_3055_requires_wctx_param(vuln, send, capture):
    send(vuln, 'GET', '/wsfed/passive')
    assert not any(e.get('cve') == 'CVE-2026-3055' for e in capture.events)


def test_cve_2026_3055_patched_by_build(patched, send, capture):
    body, req = send(patched, 'GET', '/wsfed/passive?wctx')
    assert req.responseCode == 404
    cookies = req.responseHeaders.getRawHeaders(b'set-cookie') or []
    assert all(not c.startswith(b'NSC_TASS=') for c in cookies)   # no leaked cookie on a patched build
    assert req.responseHeaders.getRawHeaders(b'location') is None
