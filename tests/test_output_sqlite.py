"""output_plugins/sqlite.py: schema auto-creation, event round-tripping, and JSON overflow of
route-specific fields into `extra`."""
import sqlite3
from json import loads

import pytest


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    from core.config import CONFIG
    from output_plugins.sqlite import Output

    db_file = str(tmp_path / 'honeypot.db')
    monkeypatch.setattr(CONFIG, 'get', lambda section, option, fallback=None, **kw: db_file
                         if (section, option) == ('output_sqlite', 'db_file') else fallback)
    monkeypatch.setattr(CONFIG, 'getboolean', lambda section, option, fallback=None, **kw: fallback)
    out = Output({'sensor': 'test'})
    yield out, db_file
    out.stop()


def event(**overrides):
    base = {
        'eventid': 'citrix.connection', 'timestamp': '2026-09-30T00:00:00.000000Z', 'unixtime': 1.0,
        'src_ip': '127.0.0.1', 'src_port': 5555, 'dst_ip': '127.0.0.1', 'dst_port': 8443,
        'sensor': 'test', 'request': 'GET', 'url': '/', 'message': 'Scan type 1',
        'cve': 'CVE-2019-19781', 'route_id': 'scan-type1', 'profile': 'adc-12.1-vulnerable',
    }
    base.update(overrides)
    return base


def rows(db_file):
    con = sqlite3.connect(db_file)
    con.row_factory = sqlite3.Row
    cur = con.execute('SELECT * FROM events')
    result = [dict(r) for r in cur.fetchall()]
    con.close()
    return result


def test_schema_created_on_first_write(plugin):
    out, db_file = plugin
    out.write(event())
    (row,) = rows(db_file)
    assert row['cve'] == 'CVE-2019-19781' and row['route_id'] == 'scan-type1'
    assert row['message'] == 'Scan type 1' and row['src_ip'] == '127.0.0.1'


def test_route_specific_fields_land_in_extra(plugin):
    out, db_file = plugin
    out.write(event(message='Generic attack-signature block', route_id='waf-block', cve=None,
                     waf_signature='sqli', ns_txn_id='deadbeef'))
    (row,) = rows(db_file)
    assert row['cve'] is None
    extra = loads(row['extra'])
    assert extra == {'waf_signature': 'sqli', 'ns_txn_id': 'deadbeef'}


def test_payload_event_round_trips(plugin):
    out, db_file = plugin
    out.write(event(eventid='citrix.payload', request='POST', message='Exploit',
                     body='title=x', payload='x'))
    (row,) = rows(db_file)
    assert row['eventid'] == 'citrix.payload' and row['body'] == 'title=x' and row['payload'] == 'x'


def test_multiple_events_accumulate(plugin):
    out, db_file = plugin
    out.write(event())
    out.write(event(url='/vpn/../vpns/cfg/smb.conf', message='Scan type 2', route_id='scan-type2'))
    assert len(rows(db_file)) == 2
