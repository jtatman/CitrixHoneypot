import socket
from json import dumps
from time import gmtime, strftime

from twisted.python import log

from core import output
from core.config import CONFIG

# RFC 3164 facility codes (the subset relevant to a host app like this one).
FACILITIES = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3, 'auth': 4, 'syslog': 5,
    'lpr': 6, 'news': 7, 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}
SEVERITY_NOTICE = 5   # citrix.connection
SEVERITY_WARNING = 4  # citrix.payload


class Output(output.Output):
    """Sends each event to a remote syslog server, RFC 3164-framed (`<PRI>timestamp host tag: body`),
    body as CEF (default, SIEM-friendly) or raw JSON.

    UDP (the default) is fire-and-forget, so there's no blocking concern; TCP connects lazily on first
    write and reconnects on failure, blocking briefly on connect/send -- an acceptable trade-off for a
    local-lab output at honeypot traffic volumes, consistent with output_plugins/sqlite.py/elasticsearch.py.
    """

    def start(self):
        self.debug = CONFIG.getboolean('output_syslog', 'debug', fallback=False)
        self.host = CONFIG.get('output_syslog', 'host', fallback='localhost')
        self.port = CONFIG.getint('output_syslog', 'port', fallback=514)
        self.protocol = CONFIG.get('output_syslog', 'protocol', fallback='udp').lower()
        self.format = CONFIG.get('output_syslog', 'format', fallback='cef').lower()
        self.tag = CONFIG.get('output_syslog', 'tag', fallback='CitrixHoneypot')
        self.timeout = CONFIG.getint('output_syslog', 'timeout', fallback=5)
        facility_name = CONFIG.get('output_syslog', 'facility', fallback='local0')
        self.facility = FACILITIES.get(facility_name, FACILITIES['local0'])
        self.sock = None

    def stop(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def local_log(self, msg):
        if self.debug:
            log.msg(msg)

    def format_cef(self, event):
        severity = SEVERITY_WARNING if event['eventid'] == 'citrix.payload' else SEVERITY_NOTICE
        name = event.get('message') or event['eventid']
        fields = (
            ('src', event.get('src_ip')), ('spt', event.get('src_port')),
            ('dst', event.get('dst_ip')), ('dpt', event.get('dst_port')),
            ('request', event.get('request')), ('requestUrl', event.get('url')),
            ('cs1Label', 'cve'), ('cs1', event.get('cve')),
            ('cs2Label', 'routeId'), ('cs2', event.get('route_id')),
        )
        extension = ' '.join(
            '{}={}'.format(k, str(v).replace('\\', '\\\\').replace('=', '\\='))
            for k, v in fields if v is not None
        )
        return 'CEF:0|CitrixHoneypot|CitrixHoneypot|2.0|{}|{}|{}|{}'.format(
            event.get('route_id') or event['eventid'], name, severity, extension)

    def format_json(self, event):
        return dumps(event, default=str)

    def _connect_tcp(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

    def write(self, event):
        body = self.format_cef(event) if self.format == 'cef' else self.format_json(event)
        pri = self.facility * 8 + (SEVERITY_WARNING if event['eventid'] == 'citrix.payload'
                                    else SEVERITY_NOTICE)
        timestamp = strftime('%b %d %H:%M:%S', gmtime(event.get('unixtime')))
        message = '<{}>{} {} {}: {}'.format(pri, timestamp, socket.gethostname(), self.tag, body)
        data = message.encode('utf-8', 'replace')[:2048]
        try:
            if self.protocol == 'tcp':
                self._connect_tcp()
                self.sock.sendall(data + b'\n')
            else:
                if self.sock is None:
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.sendto(data, (self.host, self.port))
        except OSError as e:
            self.local_log('output_syslog: {}'.format(e))
            if self.protocol == 'tcp' and self.sock is not None:
                self.sock.close()
                self.sock = None
