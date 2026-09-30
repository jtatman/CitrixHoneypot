
import os
import sys
from copy import deepcopy
from errno import EEXIST
from json import dump

from core import output
from core.config import CONFIG
from core.logfile import HoneypotDailyLogFile

# logfile = - (or 'stdout') writes JSONL to stdout instead of a rotated file -- handy for
# `docker logs`/local-lab use where a bind-mounted log directory is unwanted ceremony.
STDOUT_MARKERS = ('-', 'stdout')


class Output(output.Output):

    def start(self):
        self.epoch_timestamp = CONFIG.getboolean('output_jsonlog', 'epoch_timestamp', fallback=False)
        fn = CONFIG.get('output_jsonlog', 'logfile')
        if fn in STDOUT_MARKERS:
            self.outfile = sys.stdout
            return
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)
        if not os.path.exists(dirs) and os.sep in fn:
            try:
                os.makedirs(dirs)
            except OSError as exc:
                if exc.errno != EEXIST:
                    raise
        self.outfile = HoneypotDailyLogFile(base, dirs, defaultMode=0o664)

    def stop(self):
        if self.outfile is not sys.stdout:
            self.outfile.flush()

    def write(self, event):
        if not self.epoch_timestamp:
            # We need 'unixtime' value in some other plugins
            event_dump = deepcopy(event)
            event_dump.pop('unixtime', None)
        else:
            event_dump = event
        dump(event_dump, self.outfile, separators=(',', ':'))
        self.outfile.write('\n')
        self.outfile.flush()
