import os
import sqlite3
from json import dumps

from twisted.python import log

from core import output
from core.config import CONFIG

# Columns broken out for querying; everything else in the event dict (waf_signature, ns_txn_id,
# leaked_fake, ioc_source, nitro_user, nitro_pass, rand_key, matched, headers, body_sha256, body_b64,
# ...) varies per route/CVE, so it's kept losslessly in `extra` as JSON instead of growing the schema
# per route. See docs/sql/sqlite3.sql for the table definition.
CORE_FIELDS = ('timestamp', 'unixtime', 'eventid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'sensor',
               'request', 'url', 'message', 'cve', 'route_id', 'patched', 'profile', 'body', 'payload')


class Output(output.Output):

    def start(self):
        self.debug = CONFIG.getboolean('output_sqlite', 'debug', fallback=False)
        db_file = CONFIG.get('output_sqlite', 'db_file', fallback='honeypot.db')
        schema = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'docs', 'sql', 'sqlite3.sql')
        self.dbh = sqlite3.connect(db_file, check_same_thread=False)
        with open(schema) as f:
            self.dbh.executescript(f.read())
        self.dbh.commit()

    def stop(self):
        self.dbh.close()

    def local_log(self, msg):
        if self.debug:
            log.msg(msg)

    def write(self, event):
        try:
            row = {k: event.get(k) for k in CORE_FIELDS}
            extra = {k: v for k, v in event.items() if k not in CORE_FIELDS}
            row['extra'] = dumps(extra, default=str) if extra else None
            columns = list(row)
            placeholders = ', '.join('?' for _ in columns)
            self.dbh.execute(
                'INSERT INTO events ({}) VALUES ({})'.format(', '.join(columns), placeholders),
                [row[c] for c in columns],
            )
            self.dbh.commit()
        except Exception as e:
            self.local_log('output_sqlite: {}'.format(e))
