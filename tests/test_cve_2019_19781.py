"""Golden tests for the CVE-2019-19781 emulation. Scanner URLs are from the projects cited in core/protocol.py."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def page(name):
    return (ROOT / 'responses' / name).read_text()


def test_login_page(index, send, capture):
    for uri in ('/', '/vpn/', '/vpn', '/vpn/index.html'):
        body, _ = send(index, 'GET', uri)
        assert body == page('login.html').encode()
    assert capture.events == []


def test_login_page_with_query_string(index, send, capture):
    # Regression: root_segments/segments used to be computed by splitting the raw path on '/' without first
    # stripping the query string, so '/?x=1' produced a fake segment ['?x=1'] instead of the empty root
    # segment list this route matches on -- any GET with a query string (SSO/deep-link redirects, completely
    # ordinary traffic) 404'd instead of getting the login page. Found 2026-09-30 via nmap testing.
    for uri in ('/?redirect=%2Fportal', '/vpn/?sid=abc', '/vpn/index.html?lang=en'):
        body, _ = send(index, 'GET', uri)
        assert body == page('login.html').encode()
    assert capture.events == []


def test_unknown_path_is_empty(index, send, capture):
    body, _ = send(index, 'GET', '/nothing/here')
    assert body == b''
    assert capture.events == []


def test_scan_type1_403(index, send, capture):
    body, _ = send(index, 'GET', '/vpn/../vpns/')
    assert body == page('403.html').replace('{url}', '/vpns/').encode()
    (ev,) = capture.events
    assert ev['eventid'] == 'citrix.connection'
    assert ev['message'] == 'Scan type 1'
    assert ev['request'] == 'GET' and ev['url'] == '/vpn/../vpns/'
    assert ev['src_ip'] == '127.0.0.1'


def test_scan_type2_smb_conf(index, send, capture):
    body, _ = send(index, 'GET', '/vpn/../vpns/cfg/smb.conf')
    assert body == page('smb.conf').encode()
    assert capture.events[0]['message'] == 'Scan type 2'


def test_scan_type3_services(index, send, capture):
    body, _ = send(index, 'GET', '/vpn/../vpns/services.html')
    assert body == page('smb.conf').encode()   # current (unverified) behaviour, see CLAUDE.md
    assert capture.events[0]['message'] == 'Scan type 3'


def test_exploit_completion(index, send, capture):
    body, _ = send(index, 'GET', '/vpn/../vpns/portal/bookmark.pl')
    assert body == b''
    assert capture.events[0]['message'] == 'Exploit completion'


def test_unknown_vpns_scan(index, send, capture):
    body, _ = send(index, 'GET', '/vpn/../vpns/other.html')
    assert body == b''
    assert capture.events[0]['message'] == 'Unknown scan'


def test_traversal_outside_vpns_not_logged(index, send, capture):
    send(index, 'GET', '/vpn/../etc/passwd')
    assert capture.events == []


def test_head_scan_logged_without_body(index, send, capture):
    body, _ = send(index, 'HEAD', '/vpn/../vpns/cfg/smb.conf')
    assert body == b''
    assert capture.events[0]['message'] == 'Scan type 2'
    assert capture.events[0]['request'] == 'HEAD'


def test_head_no_completion_event(index, send, capture):
    send(index, 'HEAD', '/vpn/../vpns/portal/x')
    assert capture.events[0]['message'] == 'Unknown scan'


def test_custom_method_handled_like_get(index, send, capture):
    body, _ = send(index, 'PROPFIND', '/vpn/../vpns/')
    assert body == page('403.html').replace('{url}', '/vpns/').encode()
    assert capture.events[0]['request'] == 'PROPFIND'


def test_struggle_check(make_index, send, capture):
    idx = make_index(struggle=True)
    body, _ = send(idx, 'GET', '/vpns/cfg/smb.conf')
    assert body == page('gold_star.html').encode()


def test_struggle_off_by_default(index, send):
    body, _ = send(index, 'GET', '/vpns/cfg/smb.conf')
    assert body == b''


def test_post_payload_event(index, send, capture):
    data = b"url=http://x&title=%5B%25template.new%28%7B%27BLOCK%27%3D%27print+%60id%60%27%7D%29%25%5D&desc=t"
    body, _ = send(index, 'POST', '/vpn/../vpns/portal/scripts/newbm.pl', data)
    assert body == b''
    (ev,) = capture.events
    assert ev['eventid'] == 'citrix.payload'
    assert ev['message'] == 'Exploit'
    assert ev['request'] == 'POST'
    assert ev['payload'] == "[%template.new({'BLOCK'='print `id`'})%]"
    assert ev['body'] == data.decode()


def test_post_without_title_does_not_crash(index, send, capture):
    body, _ = send(index, 'POST', '/vpn/../vpns/portal/scripts/newbm.pl', b'foo=bar')
    assert body == b''
    assert capture.events[0]['payload'] == ''


def test_post_non_utf8_body_does_not_crash(index, send, capture):
    send(index, 'POST', '/x', b'title=\xff\xfe')
    assert len(capture.events) == 1


def test_post_struggle_gold_star(make_index, send, capture):
    idx = make_index(struggle=True)
    body, _ = send(idx, 'POST', '/vpns/portal/scripts/newbm.pl', b'title=x')
    assert body == page('gold_star.html').encode()
    assert len(capture.events) == 1


def test_all_cookies_sent(index, send):
    _, req = send(index, 'GET', '/')
    cookies = req.responseHeaders.getRawHeaders(b'set-cookie')
    assert len(cookies) == 13
    assert any(c.startswith(b'NSC_AAAC=') for c in cookies)


def test_content_length_is_bytes(index, send):
    body, req = send(index, 'GET', '/')
    assert req.responseHeaders.getRawHeaders(b'content-length') == [str(len(body)).encode()]


def test_event_has_cve_and_route_id(index, send, capture):
    send(index, 'GET', '/vpn/../vpns/')
    assert capture.events[0]['cve'] == 'CVE-2019-19781'
    assert capture.events[0]['route_id'] == 'scan-type1'


def test_log_injection_is_escaped(index, send, monkeypatch):
    lines = []
    monkeypatch.setattr('core.tools.log.msg', lines.append)
    send(index, 'GET', '/a%0d%0a[CRITICAL]%20fake')
    assert all('\n' not in line and "\r" not in line for line in lines)
    assert '\\x0d\\x0a' in lines[0]
