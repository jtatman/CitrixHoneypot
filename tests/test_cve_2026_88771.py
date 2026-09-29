"""CVE-2026-88771 (CTX697096) attempt/IOC fingerprinting, from GreyNoise's 2026-09-28 IOC blog and
watchTowr Labs' detection-artifact tool. We only recognise the three published observables (a ${IFS} login
command-injection attempt, a webshell check-in path scan, and the "pitboss PPE" log-poisoning payload
signature) -- nothing here executes attacker input, and the webshell path genuinely 404s (it never exists
on disk).
"""
import pytest

from core.profile import load_profile

VULN_BUILD = '14.1-8.10'    # predates the CTX697096 fix (14.1-73.37)


@pytest.fixture
def vuln(make_index):
    p = load_profile('adc-14.1-73.33-vulnerable')
    p.build = VULN_BUILD
    return make_index(profile=p)


@pytest.fixture
def patched(make_index):
    return make_index(profile=load_profile('adc-14.1-73.37-patched'))


@pytest.mark.parametrize('path', ['/cgi/login', '/nf/auth/doAuthentication.do'])
def test_login_injection_attempt_logged(vuln, send, capture, path):
    body, req = send(vuln, 'POST', path, b'login=root&passwd=x${IFS}id')
    assert req.responseCode == 200 and b'ctxs.core.min.js' in body   # served the normal (modern) login page
    ev = capture.events[0]
    assert ev['cve'] == 'CVE-2026-88771' and ev['route_id'] == 'cve-2026-88771-login-injection'
    assert '${IFS}' in ev['body']


def test_login_injection_patched_still_logged(patched, send, capture):
    body, req = send(patched, 'POST', '/cgi/login', b'login=root&passwd=x${IFS}id')
    assert req.responseCode == 200   # login page still exists on a patched build
    assert capture.events[0]['patched'] is True
    assert 'patched build' in capture.events[0]['message']


def test_normal_login_not_flagged(vuln, send, capture):
    send(vuln, 'POST', '/cgi/login', b'login=root&passwd=hunter2')
    assert not any(e.get('cve') == 'CVE-2026-88771' for e in capture.events)


def test_legacy_profile_serves_own_login_page(index, send, capture):
    body, req = send(index, 'POST', '/cgi/login', b'login=root&passwd=x${IFS}id')
    assert req.responseCode == 200 and b'ns_login_body' in body and b'ctxs.core.min.js' not in body


@pytest.mark.parametrize('path', [
    '/logon/LogonPoint/custom/.ctxs.receiver',
    '/logon/LogonPoint/custom/receiver.min.css',
    '/logon/LogonPoint/custom/receiver.min.a1b2c3.css',
])
def test_webshell_checkin_ioc(vuln, send, capture, path):
    body, req = send(vuln, 'GET', path)
    assert req.responseCode == 404 and path.encode() in body
    ev = capture.events[0]
    assert ev['cve'] is None and ev['route_id'] == 'cve-2026-88771-webshell-checkin'
    assert ev['message'] == 'Post-exploitation webshell check-in probe'
    assert 'greynoise.io' in ev['ioc_source']


def test_webshell_checkin_logged_even_when_patched(patched, send, capture):
    send(patched, 'GET', '/logon/LogonPoint/custom/.ctxs.receiver')
    assert capture.events[0]['route_id'] == 'cve-2026-88771-webshell-checkin'
    assert 'patched' not in capture.events[0]   # not CVE-gated, so no patched flag is added


def test_webshell_alias_regex_does_not_overmatch(vuln, send, capture):
    send(vuln, 'GET', '/logon/LogonPoint/custom/receiver.min.cssx')
    send(vuln, 'GET', '/logon/LogonPoint/custom/receiver.css')
    assert not any(e.get('route_id') == 'cve-2026-88771-webshell-checkin' for e in capture.events)


# --- log-poisoning payload signature (watchTowr Labs) -----------------------------------------------------
LOG_POISON = 'pitboss PPE unexpectedly died NSPPE;id;# X'


def test_log_poison_in_body(vuln, send, capture):
    body, req = send(vuln, 'POST', '/some/diagnostic/endpoint', LOG_POISON.encode())
    assert req.responseCode == 200
    ev = capture.events[0]
    assert ev['cve'] == 'CVE-2026-88771' and ev['route_id'] == 'cve-2026-88771-log-poison'
    assert 'watchtowrlabs' in ev['ioc_source'] and LOG_POISON in ev['body']


def test_log_poison_in_path(vuln, send, capture):
    from urllib.parse import quote
    send(vuln, 'GET', '/anything?x=' + quote(LOG_POISON))
    assert capture.events[0]['route_id'] == 'cve-2026-88771-log-poison'


def test_log_poison_patched_still_logged(patched, send, capture):
    send(patched, 'POST', '/x', LOG_POISON.encode())
    assert capture.events[0]['patched'] is True
    assert 'patched build' in capture.events[0]['message']


def test_log_poison_normal_traffic_not_flagged(vuln, send, capture):
    send(vuln, 'POST', '/some/diagnostic/endpoint', b'ordinary body text')
    # a non-empty POST body always matches cve_2019_19781's generic legacy catch-all; what matters here is
    # that the log-poison signature specifically did not fire
    assert not any(e.get('route_id') == 'cve-2026-88771-log-poison' for e in capture.events)
