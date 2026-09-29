import pytest

from core.profile import ProfileError, load_profile
from core.tls import ensure_cert


@pytest.fixture
def patched_index(make_index):
    return make_index(profile=load_profile('adc-13.1-patched'))


def test_default_profile_loads():
    p = load_profile()
    assert p.state('CVE-2019-19781') == 'vulnerable' and len(p.cookies) == 13


def test_patched_profile_logs_but_hides(patched_index, send, capture):
    body, req = send(patched_index, 'GET', '/vpn/../vpns/cfg/smb.conf')
    assert req.responseCode == 404
    assert b'[global]' not in body
    ev = capture.events[0]
    assert ev['message'] == 'Scan type 2' and ev['patched'] is True and ev['profile'] == 'adc-13.1-patched'


def test_patched_profile_still_logs_payload(patched_index, send, capture):
    body, req = send(patched_index, 'POST', '/vpn/../vpns/portal/scripts/newbm.pl', b'title=x')
    assert req.responseCode == 404
    assert capture.events[0]['payload'] == 'x'


def test_patched_profile_still_serves_login(patched_index, send):
    body, req = send(patched_index, 'GET', '/vpn/index.html')
    assert req.responseCode == 200 and b'ns_login_body' in body


def test_vulnerable_profile_unchanged(index, send, capture):
    _, req = send(index, 'GET', '/vpn/../vpns/cfg/smb.conf')
    assert req.responseCode == 200 and capture.events[0].get('patched') is None
    assert capture.events[0]['profile'] == 'adc-12.1-vulnerable'


def test_state_off_disables_route(make_index, send, capture):
    p = load_profile()
    p.cves['CVE-2019-19781'] = 'off'
    body, _ = send(make_index(profile=p), 'GET', '/vpn/../vpns/cfg/smb.conf')
    assert body == b'' and capture.events == []


@pytest.mark.parametrize('name', ['../etc/passwd', 'nope', '', 'A/b'])
def test_bad_profile_names(name):
    with pytest.raises(ProfileError):
        load_profile(name)


def test_bad_state_rejected(tmp_path):
    (tmp_path / 'x.yaml').write_text('name: x\ncves:\n  CVE-2019-19781: maybe\n')
    with pytest.raises(ProfileError, match='states'):
        load_profile('x', tmp_path)


def test_unknown_key_rejected(tmp_path):
    (tmp_path / 'x.yaml').write_text('name: x\nbogus: 1\n')
    with pytest.raises(ProfileError, match='unknown keys'):
        load_profile('x', tmp_path)


def test_profile_extra_headers_and_server(make_index, send):
    p = load_profile()
    p.server_header, p.headers = 'X', {'X-Foo': 'bar'}
    _, req = send(make_index(profile=p), 'GET', '/')
    assert req.responseHeaders.getRawHeaders(b'server') == [b'X']
    assert req.responseHeaders.getRawHeaders(b'x-foo') == [b'bar']


def test_ensure_cert(tmp_path):
    assert ensure_cert(tmp_path, 'lab.local') is True
    assert ensure_cert(tmp_path, 'lab.local') is False
    from cryptography import x509
    cert = x509.load_pem_x509_certificate((tmp_path / 'cert.pem').read_bytes())
    assert cert.subject.rfc4514_string() == 'CN=lab.local'


@pytest.mark.parametrize('build,expected', [
    ('12.1-50.28', 'vulnerable'),   # < 12.1-55.18
    ('12.1-55.18', 'patched'),
    ('13.0-47.23', 'vulnerable'),
    ('13.0-47.24', 'patched'),
    ('10.5-70.11', 'vulnerable'),
    ('13.1-49.13', 'patched'),      # branch released after the fix
    ('11.1-60.1', 'vulnerable'),
    ('garbage', None),
])
def test_state_derived_from_build(build, expected):
    from core.cvedb import state_for_build
    assert state_for_build('CVE-2019-19781', build) == expected


def test_derived_state_and_override(tmp_path):
    (tmp_path / 'a.yaml').write_text('name: a\nbuild: "12.1-50.28"\n')
    (tmp_path / 'b.yaml').write_text('name: b\nbuild: "12.1-50.28"\ncves:\n  CVE-2019-19781: patched\n')
    assert load_profile('a', tmp_path).state('CVE-2019-19781') == 'vulnerable'
    assert load_profile('b', tmp_path).state('CVE-2019-19781') == 'patched'
    assert load_profile('a', tmp_path).state('CVE-9999-0000') == 'vulnerable'   # unknown CVE: default


def test_eol_branch_unlisted_is_vulnerable():
    from core.cvedb import state_for_build
    assert state_for_build('CVE-2023-3519', '11.1-63.15') == 'vulnerable'   # EOL, no fix ever listed
    assert state_for_build('CVE-2023-3519', '13.1-49.12') == 'vulnerable'   # listed, one below the fix
    assert state_for_build('CVE-2023-3519', '13.1-49.13') == 'patched'
