"""CVE-2020-8193/8195/8196: unauthenticated endpoint access chained with an LFI, per nuclei's
http/cves/2020/CVE-2020-8193.yaml. Fixed versions verified against NVD (see core/routes/cve_2020_8193.py).
"""
import re

import pytest

from core.profile import load_profile

# 12.1-50.28 predates every fixed build (12.1-57.18) -> vulnerable
VULN_BUILD = '12.1-50.28'
PATCHED_BUILD = '12.1-57.18'   # exactly the fixed build


@pytest.fixture
def vuln(make_index):
    p = load_profile('adc-14.1-73.33-vulnerable')
    p.build = VULN_BUILD
    return make_index(profile=p)


@pytest.fixture
def patched(make_index):
    p = load_profile('adc-14.1-73.33-vulnerable')
    p.build = PATCHED_BUILD
    return make_index(profile=p)


@pytest.mark.parametrize('path', ['/menu/ss', '/menu/neo', '/menu/stc'])
def test_unauth_menu_paths(vuln, send, capture, path):
    body, req = send(vuln, 'GET', path)
    assert req.responseCode == 200 and body == b''
    assert capture.events[0]['cve'] == 'CVE-2020-8193' and capture.events[0]['route_id'] == 'cve-2020-8193-unauth'


def test_unauth_menu_patched(patched, send, capture):
    body, req = send(patched, 'GET', '/menu/neo')
    assert req.responseCode == 404
    assert capture.events[0]['patched'] is True


def test_pcidss_report(vuln, send, capture):
    body, req = send(vuln, 'POST', '/pcidss/report?type=allprofiles&sid=x&username=nsroot&set=1',
                      b'<appfwprofile><login></login></appfwprofile>')
    assert req.responseCode == 200 and b'<appfwprofile>' in body
    assert capture.events[0]['route_id'] == 'cve-2020-8193-pcidss'
    assert capture.events[0]['body'].startswith('<appfwprofile>')


def test_rapi_lfi_shape(vuln, send, capture):
    body, req = send(vuln, 'POST', '/rapi/filedownload?filter=path:%2Fetc%2Fpasswd',
                      b'<clipermission></clipermission>')
    assert req.responseCode == 200
    assert re.search(rb'root:.*:0:0:', body)   # nuclei's exact matcher regex
    assert capture.events[0]['message'] == 'LFI via rapi/filedownload'


def test_rapi_other_path_not_matched(vuln, send, capture):
    send(vuln, 'POST', '/rapi/filedownload?filter=path:%2Fetc%2Fshadow', b'<clipermission></clipermission>')
    assert not any(e.get('route_id') == 'cve-2020-8193-lfi' for e in capture.events)


def test_rapi_lfi_patched(patched, send, capture):
    body, req = send(patched, 'POST', '/rapi/filedownload?filter=path:%2Fetc%2Fpasswd',
                      b'<clipermission></clipermission>')
    assert req.responseCode == 404
    assert b'root:' not in body
