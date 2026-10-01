import ssl
from base64 import b64encode
from json import dumps
from urllib.error import URLError
from urllib.request import Request, urlopen

from twisted.python import log

from core import output
from core.config import CONFIG


class Output(output.Output):
    """POSTs each event as a document to an Elasticsearch/OpenSearch index over its HTTP API
    (`PUT {index}/_doc`, no mapping type -- ES7+/OpenSearch style).

    Synchronous and blocking, like output_plugins/sqlite.py: honeypot event volume is low enough that a
    slow/unreachable ES instance stalling the reactor for up to `timeout` seconds per event is an
    acceptable, simple trade-off for a local-lab output plugin, not a production SIEM forwarder.
    """

    def start(self):
        self.debug = CONFIG.getboolean('output_elasticsearch', 'debug', fallback=False)
        self.scheme = CONFIG.get('output_elasticsearch', 'scheme', fallback='http')
        self.host = CONFIG.get('output_elasticsearch', 'host', fallback='localhost')
        self.port = CONFIG.getint('output_elasticsearch', 'port', fallback=9200)
        self.index = CONFIG.get('output_elasticsearch', 'index', fallback='honeypot')
        self.username = CONFIG.get('output_elasticsearch', 'username', fallback='')
        self.password = CONFIG.get('output_elasticsearch', 'password', fallback='', raw=True)
        self.timeout = CONFIG.getint('output_elasticsearch', 'timeout', fallback=5)
        self.verify_tls = CONFIG.getboolean('output_elasticsearch', 'verify_tls', fallback=True)
        self.url = '{}://{}:{}/{}/_doc'.format(self.scheme, self.host, self.port, self.index)
        self.ssl_context = None if self.verify_tls else ssl._create_unverified_context()

    def local_log(self, msg):
        if self.debug:
            log.msg(msg)

    def write(self, event):
        req = Request(self.url, data=dumps(event, default=str).encode('utf-8'), method='POST',
                       headers={'Content-Type': 'application/json'})
        if self.username:
            token = b64encode('{}:{}'.format(self.username, self.password).encode()).decode()
            req.add_header('Authorization', 'Basic {}'.format(token))
        try:
            urlopen(req, timeout=self.timeout, context=self.ssl_context)
        except (URLError, OSError) as e:
            self.local_log('output_elasticsearch: {}'.format(e))
