
from datetime import datetime, timezone
from sys import stdout

from twisted.python import log, util
from twisted.python.logfile import DailyLogFile


class HoneypotDailyLogFile(DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate):
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        try:
            return "{:02d}-{:02d}-{:02d}".format(tupledate[0], tupledate[1], tupledate[2])
        except Exception:
            # try taking a float unixtime
            return '_'.join(map(str, self.toDate(tupledate)))


def _utc_timestamp(when):
    """Format a POSIX (UTC) timestamp as '[YYYY-MM-DD HH:MM:SS.ffffffZ]'."""
    return datetime.fromtimestamp(when, timezone.utc).strftime('[%Y-%m-%d %H:%M:%S.%fZ]')


class UTCLogObserver:
    """Writes log events to `outfile` with a UTC timestamp.

    Deliberately not a twisted.python.log.FileLogObserver subclass with overridden emit()/formatTime():
    those methods are undocumented/internal, so monkeypatching or overriding them is fragile across
    Twisted versions. log.startLoggingWithObserver() (used by set_logger() below) is the documented,
    supported way to install a custom observer callable instead.
    """

    def __init__(self, outfile):
        self.outfile = outfile

    def __call__(self, eventDict):
        text = log.textFromEventDict(eventDict)
        if text is None:
            return
        line = '{} {}\n'.format(_utc_timestamp(eventDict['time']), text.replace('\n', '\n\t'))
        util.untilConcludes(self.outfile.write, line)
        util.untilConcludes(self.outfile.flush)


def set_logger(cfg_options):
    if cfg_options['logfile'] is None:
        outfile, set_stdout = stdout, True
    else:
        outfile, set_stdout = HoneypotDailyLogFile.fromFullPath(cfg_options['logfile']), False
    log.startLoggingWithObserver(UTCLogObserver(outfile), setStdout=set_stdout)
