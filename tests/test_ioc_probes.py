"""Generic IOC/misconfig probe logging, vendored from citrixscan's IOC_PATHS/MISCONFIG_PATHS. Not tied to
any CVE: the point is capturing which known webshell/backdoor or management path a scanner checked for.
"""
import pytest

from core.routes.ioc_probes import IOC_PATHS, MISCONFIG_PATHS


@pytest.mark.parametrize('path', sorted(IOC_PATHS))
def test_ioc_path_logged_and_404(index, send, capture, path):
    body, req = send(index, 'GET', path)
    assert req.responseCode == 404 and path.encode() in body
    ev = capture.events[0]
    assert ev['route_id'] == 'ioc-webshell-probe' and ev['cve'] is None
    assert path in ev['message'] and 'citrixscan' in ev['ioc_source']


@pytest.mark.parametrize('path', sorted(MISCONFIG_PATHS))
def test_misconfig_path_logged_and_404(index, send, capture, path):
    body, req = send(index, 'GET', path)
    assert req.responseCode == 404
    assert capture.events[0]['route_id'] == 'ioc-misconfig-probe'


def test_menu_paths_owned_by_cve_2020_8193_not_ioc(index, send, capture):
    # /menu/ss, /menu/neo, /menu/stc are more specific (tied to a real CVE); ioc_probes must not shadow them
    send(index, 'GET', '/menu/neo')
    assert capture.events[0]['route_id'] == 'cve-2020-8193-unauth'


def test_struggle_paths_owned_by_cve_2019_19781_not_ioc(make_index, send, capture):
    # /vpns/portal/scripts/newbm.pl is the struggle-check's path; it must not be shadowed by ioc_probes.
    # The struggle route emits no structured event (gold-star page + log line only), so check the body.
    idx = make_index(struggle=True)
    body, req = send(idx, 'GET', '/vpns/portal/scripts/newbm.pl')
    assert req.responseCode == 200 and b'at least you tried' in body.lower()
    assert capture.events == []


def test_unrelated_path_not_flagged(index, send, capture):
    send(index, 'GET', '/some/random/path')
    assert capture.events == []


def test_ioc_probe_works_on_legacy_profile_too(index, send, capture):
    # not CVE-gated / not netscaler-surface-gated: fires on every profile
    body, req = send(index, 'GET', '/vpn/js/cmd.php')
    assert req.responseCode == 404
    assert capture.events[0]['route_id'] == 'ioc-webshell-probe'
