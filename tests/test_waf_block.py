"""AppFirewall-style generic block, gated behind the 'waf-mimicry' profile feature. The exact fingerprint
(403/429 + 'NS Transaction ID' in body) matches vigolium's own citrixNetscalerRule() WAF detector
(pkg/deparos/waf/detector.go, read from that repo this session) -- so enabling it is a deliberate trade-off:
see core/routes/waf_block.py's module docstring.
"""
import pytest

from core.profile import load_profile


@pytest.fixture
def waf(make_index):
    return make_index(profile=load_profile('adc-14.1-73.33-waf'))


@pytest.mark.parametrize('query,name', [
    ("?id=1' OR '1'='1", 'sqli'),
    ('?q=<script>alert(1)</script>', 'xss'),
    ('?x=$(id)', 'cmdi'),
    ('?f=..%2f..%2fetc%2fpasswd', 'traversal'),
])
def test_generic_attack_signature_blocked(waf, send, capture, query, name):
    body, req = send(waf, 'GET', '/some/random/path' + query)
    assert req.responseCode == 403 and b'NS Transaction ID' in body
    ev = capture.events[0]
    assert ev['route_id'] == 'waf-block' and ev['waf_signature'] == name and ev['cve'] is None


def test_sqli_in_post_body_blocked(waf, send, capture):
    body, req = send(waf, 'POST', '/x', b"username=admin' UNION SELECT password FROM users--")
    assert req.responseCode == 403
    assert capture.events[0]['waf_signature'] == 'sqli'


def test_benign_traffic_not_blocked(waf, send, capture):
    body, req = send(waf, 'GET', '/vpn/index.html')
    assert req.responseCode == 200
    assert not any(e.get('route_id') == 'waf-block' for e in capture.events)


def test_off_by_default_on_other_profiles(index, send, capture):
    body, req = send(index, 'GET', "/x?id=1' OR '1'='1")
    assert not any(e.get('route_id') == 'waf-block' for e in capture.events)


def test_modern_vulnerable_profile_unaffected(make_index, send, capture):
    idx = make_index(profile=load_profile('adc-14.1-73.33-vulnerable'))   # no waf-mimicry feature
    send(idx, 'GET', "/x?id=1' OR '1'='1")
    assert not any(e.get('route_id') == 'waf-block' for e in capture.events)


def test_specific_cve_route_takes_priority_over_waf_block(waf, send, capture):
    # /wsfed/passive?wctx is CVE-2026-3055's route; nothing here looks like an attack signature anyway, but
    # confirm the specific route still wins the moment there's any overlap risk in registration order.
    body, req = send(waf, 'GET', '/wsfed/passive?wctx')
    assert capture.events[0]['route_id'] == 'cve-2026-3055'


def test_log_poison_signature_still_wins_over_waf_block(waf, send, capture):
    # The literal pitboss string contains no SQLi/XSS/cmdi/traversal signature, but confirm registration
    # order still lets the more specific CVE-2026-88771 route fire first when it does apply.
    send(waf, 'POST', '/x', b'pitboss PPE unexpectedly died NSPPE;id;# X')
    assert capture.events[0]['route_id'] == 'cve-2026-88771-log-poison'


def test_legacy_vpns_traversal_not_shadowed_by_waf_block(waf, send, capture):
    # waf_block is registered before cve_2019_19781's catch-alls (so root/POST SQLi gets blocked); its
    # 'traversal' signature must explicitly exclude the /vpn/../vpns/... shape or it would shadow the
    # older, more specific CVE-2019-19781 handling entirely. (This build is already "patched" for the 2019
    # CVE itself -- 14.1 isn't in its fixed_versions table -- so the response is the patched 404; what
    # matters here is which route matched, not the vulnerable/patched response shape.)
    send(waf, 'GET', '/vpn/../vpns/cfg/smb.conf')
    assert capture.events[0]['route_id'] == 'scan-type2'


def test_non_legacy_traversal_still_blocked(waf, send, capture):
    body, req = send(waf, 'GET', '/some/other/path/../../etc/passwd')
    assert req.responseCode == 403
    assert capture.events[0]['waf_signature'] == 'traversal'
