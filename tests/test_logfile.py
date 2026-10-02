"""core/logfile.py: UTCLogObserver formats events with a UTC timestamp and writes to the given file,
without monkeypatching twisted.python.log.FileLogObserver (see CLAUDE.md bug 10)."""
from io import StringIO

from twisted.python import log

from core.logfile import UTCLogObserver, _utc_timestamp


def test_utc_timestamp_format():
    assert _utc_timestamp(1767322245.0) == '[2026-01-02 02:50:45.000000Z]'


def test_observer_writes_formatted_line():
    out = StringIO()
    observer = UTCLogObserver(out)
    observer({'time': 1767322245.0, 'message': ('hello world',), 'isError': 0, 'system': '-'})
    line = out.getvalue()
    assert line.startswith('[2026-01-02 02:50:45.000000Z] ')
    assert 'hello world' in line
    assert line.endswith('\n')


def test_observer_skips_events_with_no_text():
    out = StringIO()
    observer = UTCLogObserver(out)
    observer({'time': 1767322245.0, 'message': (), 'isError': 0, 'system': '-'})
    assert out.getvalue() == ''


def test_does_not_monkeypatch_file_log_observer():
    # The whole point of the rewrite: no class-level overrides on Twisted's own FileLogObserver.
    assert log.FileLogObserver.emit is not None
    assert 'core.logfile' not in repr(log.FileLogObserver.emit)
    assert 'core.logfile' not in repr(log.FileLogObserver.formatTime)
