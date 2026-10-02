
from datetime import datetime, timezone
from errno import EEXIST
from os import makedirs, path
from re import compile as re_compile
from socket import AF_INET, SOCK_DGRAM, socket
from urllib.parse import urlsplit, urlunsplit

from twisted.python import log

from core.config import CONFIG

_CONTROL = re_compile(r'[\x00-\x1f\x7f]')


def get_real_ip(request, cfg=None):
    # X-Real-IP is only honoured when trust_proxy_headers is explicitly enabled: it's attacker-supplied
    # and trivially spoofable otherwise, and only meaningful if the honeypot sits behind a trusted proxy
    # that sets it itself (overwriting whatever the client sent).
    if cfg and cfg.get('trust_proxy_headers'):
        ip = request.getHeader('X-Real-IP')
        if ip is not None:
            return ip
    return request.getClientAddress().host


def get_real_port(request, cfg=None):
    if cfg and cfg.get('trust_proxy_headers'):
        port = request.getHeader('X-Real-Port')
        if port is not None:
            return port
    return request.getClientAddress().port


def getutctime(unixtime):
    return datetime.fromtimestamp(unixtime, timezone.utc).replace(tzinfo=None).isoformat() + 'Z'


def getlocalip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def resolve_url(url):
    parts = list(urlsplit(url))
    segments = parts[2].split('/')
    segments = [segment + '/' for segment in segments[:-1]] + [segments[-1]]
    resolved = []
    for segment in segments:
        if segment in ('../', '..'):
            if resolved[1:]:
                resolved.pop()
        elif segment not in ('./', '.'):
            resolved.append(segment)
    parts[2] = ''.join(resolved)
    return urlunsplit(parts)


def logger(request, log_level, msg, cfg=None):
    ip = get_real_ip(request, cfg)
    port = get_real_port(request, cfg)
    # attacker-controlled text: escape control characters to prevent log injection
    msg = _CONTROL.sub(lambda m: '\\x{:02x}'.format(ord(m.group())), msg)
    log.msg('[{}] ({}:{}): {}'.format(log_level, ip, port, msg))


def write_event(event, cfg):
    output_plugins = cfg['output_plugins']
    for plugin in output_plugins:
        try:
            plugin.write(event)
        except Exception as e:
            log.err(e)
            continue


def mkdir(dir_path):
    if not dir_path:
        return
    try:
        makedirs(dir_path)
    except OSError as exc:
        if exc.errno == EEXIST and path.isdir(dir_path):
            pass
        else:
            raise


def import_plugins(cfg):
    # Load output modules (inspired by the Cowrie honeypot)
    log.msg('Loading the plugins...')
    output_plugins = []
    general_options = cfg
    for x in CONFIG.sections():
        if not x.startswith('output_'):
            continue
        if CONFIG.getboolean(x, 'enabled') is False:
            continue
        engine = x.split('_')[1]
        try:
            output = __import__('output_plugins.{}'.format(engine),
                                globals(), locals(), ['output'], 0).Output(general_options)
            output_plugins.append(output)
            log.msg('Loaded output engine: {}'.format(engine))
        except ImportError as e:
            log.err('Failed to load output engine: {} due to ImportError: {}'.format(engine, e))
        except Exception as e:
            log.err('Failed to load output engine: {} {}'.format(engine, e))
    return output_plugins


def stop_plugins(cfg):
    log.msg('Stoping the plugins...')
    for plugin in cfg['output_plugins']:
        try:
            plugin.stop()
        except Exception as e:
            log.err(e)
            continue

