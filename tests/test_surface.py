import gzip
import re
import struct

import pytest

from core.profile import load_profile

VULN, PATCHED = 'adc-14.1-73.33-vulnerable', 'adc-14.1-73.37-patched'


@pytest.fixture
def vuln(make_index):
    return make_index(profile=load_profile(VULN))


@pytest.fixture
def patched(make_index):
    return make_index(profile=load_profile(PATCHED))


def test_unknown_path_is_real_404(vuln, send):
    body, req = send(vuln, 'GET', '/menu/neo')
    assert req.responseCode == 404 and b'Not Found' in body and b'/menu/neo' in body


def test_legacy_profile_still_soft_404(index, send):
    _, req = send(index, 'GET', '/menu/neo')
    assert req.responseCode == 200


def test_logon_page_has_citrix_markers(vuln, send, capture):
    body, req = send(vuln, 'GET', '/logon/LogonPoint/tmindex.html')
    assert req.responseCode == 200 and b'ctxs.core.min.js' in body
    assert capture.events[0]['message'] == 'Fingerprint probe (logon page)'
    js, _ = send(vuln, 'GET', '/logon/LogonPoint/receiver/js/ctxs.core.min.js')
    assert b'CTXS.AccessGateway' in js


def test_surface_absent_on_legacy_profile(index, send):
    _, req = send(index, 'GET', '/logon/LogonPoint/tmindex.html')
    assert req.responseCode == 200 and req.responseHeaders.getRawHeaders(b'content-length') == [b'0']


def test_connection_header_mangled(vuln, send):
    _, req = send(vuln, 'GET', '/')
    assert req.responseHeaders.getRawHeaders(b'cneonction') == [b'Close']
    assert req.responseHeaders.getRawHeaders(b'connection') is None


@pytest.mark.parametrize('name,size', [(VULN, 11230664), (PATCHED, 10688726)])
def test_nsepa_deb_size_is_the_patch_oracle(make_index, send, name, size):
    idx = make_index(profile=load_profile(name))
    body, req = send(idx, 'GET', '/epa/scripts/linux/nsepa.deb', headers={'Range': 'bytes=0-0'})
    assert req.responseCode == 206 and len(body) == 1
    assert req.responseHeaders.getRawHeaders(b'content-range') == ['bytes 0-0/{}'.format(size).encode()]
    full, req = send(idx, 'GET', '/epa/scripts/linux/nsepa.deb')
    assert req.responseCode == 200 and len(full) == size and full.startswith(b'!<arch>')


def test_nsepa_deb_head_has_no_body(vuln, send):
    body, req = send(vuln, 'HEAD', '/epa/scripts/linux/nsepa.deb')
    assert body == b'' and req.responseCode == 200


def test_rdx_en_gzip_mtime_matches_build(make_index, send, tmp_path):
    p = load_profile(VULN)
    _, req = send(make_index(profile=p), 'GET', '/vpn/js/rdx/core/lang/rdx_en.json.gz')
    assert req.responseCode == 404   # 73.x timestamp unknown
    p.rdx_en_mtime = 1689014191   # 13.1-49.13 in citrixscan's table
    body, _ = send(make_index(profile=p), 'GET', '/vpn/js/rdx/core/lang/rdx_en.json.gz')
    assert struct.unpack('<I', body[4:8])[0] == 1689014191 and gzip.decompress(body) == b'{}\n'


def test_rdx_en_mtime_derived_from_known_build(make_index, send):
    p = load_profile(VULN)
    p.build = '13.1-49.13'
    body, _ = send(make_index(profile=p), 'GET', '/vpn/js/rdx/core/lang/rdx_en.json.gz')
    assert struct.unpack('<I', body[4:8])[0] == 1689014191


# --- CVE-2025-5777 ---------------------------------------------------------------------------
def test_citrixbleed2_vulnerable_shape(make_index, send, capture):
    p = load_profile(VULN)
    p.cves['CVE-2025-5777'] = 'vulnerable'     # 73.33 is fixed for this one; force the old behaviour
    body, req = send(make_index(profile=p), 'POST', '/p/u/doAuthentication.do', b'login')
    ctype = req.responseHeaders.getRawHeaders(b'content-type')[0]
    assert ctype.startswith(b'application/vnd.citrix.authenticateresponse')
    iv = re.search(rb'<InitialValue>([^<]*)</InitialValue>', body).group(1)
    assert iv.startswith(b'HONEYPOT-FAKE-LEAK_') and len(iv) >= 10
    assert not re.fullmatch(rb'[A-Za-z0-9+/=\s]+', iv)   # what the nuclei matcher requires
    assert capture.events[0]['cve'] == 'CVE-2025-5777' and capture.events[0]['message'] == 'CitrixBleed 2 probe'


def test_citrixbleed2_patched_by_build(vuln, send, capture):
    body, _ = send(vuln, 'POST', '/p/u/doAuthentication.do', b'login')   # 14.1-73.33 >= fix
    assert b'<InitialValue></InitialValue>' in body
    assert capture.events[0]['patched'] is True


def test_citrixbleed2_normal_request_no_leak(make_index, send):
    p = load_profile(VULN)
    p.cves['CVE-2025-5777'] = 'vulnerable'
    body, _ = send(make_index(profile=p), 'POST', '/p/u/doAuthentication.do', b'login=bob&passwd=x')
    assert b'<InitialValue></InitialValue>' in body


# --- CVE-2023-3519 ---------------------------------------------------------------------------
def test_saml_probe(make_index, send, capture):
    p = load_profile(VULN)
    p.cves['CVE-2023-3519'] = 'vulnerable'
    body, req = send(make_index(profile=p), 'POST', '/saml/login', b'SAMLRequest=abc')
    assert req.responseCode == 200 and b'SAML Assertion verification failed;' in body
    assert capture.events[0]['route_id'] == 'cve-2023-3519'


def test_saml_probe_patched_by_build(vuln, send):
    _, req = send(vuln, 'POST', '/saml/login', b'SAMLRequest=abc')
    assert req.responseCode == 404


# --- CTX697096 data ----------------------------------------------------------------------------
@pytest.mark.parametrize('build,state', [('14.1-73.33', 'vulnerable'), ('14.1-73.37', 'patched'),
                                         ('13.1-64.22', 'vulnerable'), ('13.1-64.23', 'patched'),
                                         ('12.1-55.18', 'vulnerable')])   # EOL branch: never fixed
def test_ctx697096_states(build, state):
    from core.cvedb import state_for_build
    assert all(state_for_build('CVE-2026-8877{}'.format(i), build) == state for i in range(1, 9))
