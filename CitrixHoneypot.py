#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Licencing Agreement: MalwareTech Public Licence
This software is free to use providing the user yells
"Oh no, the cyberhackers are coming!" prior to each installation.
"""

from argparse import ArgumentParser
from os.path import join
from socket import gethostname

from twisted.internet import endpoints, reactor
from twisted.python import log
from twisted.web import server

from core.config import CONFIG
from core.health import HealthCheck
from core.logfile import set_logger
from core.profile import DEFAULT_PROFILE, ProfileError, load_profile
from core.protocol import Index
from core.tls import ensure_cert
from core.tools import import_plugins, mkdir, stop_plugins

__VERSION__ = '2.0.2'
__description__ = 'Citrix CVE-2019-19781 Honeypot by MalwareTech'


def parse_ports(spec):
    """Parse a comma-separated port list ('8443,3010') into a list of ints. '' -> []."""
    return [int(p.strip()) for p in spec.split(',') if p.strip()]


def get_options(cfg_options):
    parser = ArgumentParser(description=__description__)

    parser.add_argument('-v', '--version', action='version', version='%(prog)s version ' + __VERSION__)
    parser.add_argument('-a', '--addr', type=str, default=cfg_options['addr'],
                        help='Address to bind to (default: {})'.format(cfg_options['addr']))
    parser.add_argument('-p', '--port', type=int, default=cfg_options['port'],
                        help='Port to listen on (default: {})'.format(cfg_options['port']))
    parser.add_argument('-l', '--logfile', type=str, default=cfg_options['logfile'],
                        help='Log file (default: stdout)')
    parser.add_argument('-d', '--ssldir', type=str, default=cfg_options['ssldir'],
                        help='Directory of the SSL certificate (default: {})'.format(cfg_options['ssldir']))
    parser.add_argument('-s', '--sensor', type=str, default=cfg_options['sensor'],
                        help='Sensor name (default: {})'.format(cfg_options['sensor']))

    parser.add_argument('-P', '--profile', type=str, default=cfg_options['profile_name'],
                        help='Appliance profile from profiles/ (default: {})'.format(cfg_options['profile_name']))

    parser.add_argument('--tls-profile', type=str, default=cfg_options['tls_profile_name'],
                        help='Appliance profile from profiles/ to take the TLS certificate subject CN '
                             'from, decoupled from --profile (e.g. to test cert-based fingerprinting '
                             'separately from the HTTP surface). Default: same as --profile.')

    parser.add_argument('--http-port', type=int, default=cfg_options['http_port'],
                        help='Also listen on this plain-HTTP port, same routes/site, no TLS (0 = disabled, '
                             'local-lab convenience only -- a real appliance does not serve this over HTTP; '
                             'default: {})'.format(cfg_options['http_port']))

    parser.add_argument('--ports', type=str, default=cfg_options['extra_ports'],
                        help='Comma-separated extra TLS ports to also listen on, same site/cert/profile as '
                             '-p/--port (e.g. "8443,3010" for a secondary gateway port plus a management-'
                             'looking port) -- these are the same surface bound to another port, not a '
                             'distinct management-interface emulation; dst_port in logged events is what '
                             'tells them apart. Default: {!r}'.format(cfg_options['extra_ports']))

    parser.add_argument('--health-port', type=int, default=cfg_options['health_port'],
                        help='Serve a JSON liveness check on this port, bound to 127.0.0.1 only regardless '
                             'of -a/--addr, for local-lab orchestration (e.g. a docker-compose healthcheck). '
                             'Not part of the emulated surface: never logged as an event (0 = disabled, '
                             'default: {})'.format(cfg_options['health_port']))

    args = parser.parse_args()
    return args


def mySiteLog(request):
    """
    Empty log formatter to suppress the normal logging of
    the web requests, since we'll be doing our own logging.
    """
    return


def main():
    cfg_options = {}
    cfg_options['addr'] = CONFIG.get('honeypot', 'out_addr', fallback='0.0.0.0')
    cfg_options['port'] = CONFIG.getint('honeypot', 'listen_port', fallback=443)
    log_name = CONFIG.get('honeypot', 'log_filename', fallback='')
    if log_name:
        logdir = CONFIG.get('honeypot', 'log_path', fallback='')
        mkdir(logdir)
        cfg_options['logfile'] = join(logdir, log_name)
    else:
        cfg_options['logfile'] = None
    cfg_options['ssldir'] = CONFIG.get('honeypot', 'ssl_dir', fallback='ssl')
    cfg_options['sensor'] = CONFIG.get('honeypot', 'sensor_name', fallback=gethostname())
    cfg_options['debug'] = CONFIG.get('honeypot', 'verbosity', fallback='info')
    cfg_options['struggle'] = CONFIG.getboolean('honeypot', 'struggle_check', fallback=False)
    cfg_options['trust_proxy_headers'] = CONFIG.getboolean('honeypot', 'trust_proxy_headers', fallback=False)
    cfg_options['profile_name'] = CONFIG.get('honeypot', 'profile', fallback=DEFAULT_PROFILE)
    cfg_options['tls_profile_name'] = CONFIG.get('honeypot', 'tls_profile', fallback='')
    cfg_options['http_port'] = CONFIG.getint('honeypot', 'http_port', fallback=0)
    cfg_options['extra_ports'] = CONFIG.get('honeypot', 'extra_listen_ports', fallback='')
    cfg_options['health_port'] = CONFIG.getint('honeypot', 'health_port', fallback=0)

    args = get_options(cfg_options)

    cfg_options['addr'] = args.addr
    cfg_options['port'] = args.port
    cfg_options['logfile'] = args.logfile
    cfg_options['ssldir'] = args.ssldir
    cfg_options['http_port'] = args.http_port
    cfg_options['extra_ports'] = args.ports
    cfg_options['health_port'] = args.health_port
    try:
        cfg_options['profile'] = load_profile(args.profile)
    except ProfileError as e:
        raise SystemExit('Error: {}'.format(e))
    tls_cn = cfg_options['profile'].tls_cn
    if args.tls_profile:
        try:
            tls_cn = load_profile(args.tls_profile).tls_cn
        except ProfileError as e:
            raise SystemExit('Error: {}'.format(e))
    cfg_options['sensor'] = args.sensor

    set_logger(cfg_options)

    log.msg(__description__)
    profile = cfg_options['profile']
    log.msg('Profile: {} ({} {})'.format(profile.name, profile.product, profile.build))
    if ensure_cert(cfg_options['ssldir'], tls_cn):
        log.msg('Generated a self-signed certificate (CN={}) in {}'.format(tls_cn, cfg_options['ssldir']))

    cfg_options['output_plugins'] = import_plugins(cfg_options)

    site = server.Site(Index(cfg_options))
    site.log = mySiteLog

    tls_ports = [cfg_options['port']] + [p for p in parse_ports(cfg_options['extra_ports'])
                                          if p != cfg_options['port']]
    for port in tls_ports:
        endpoint_spec = 'ssl:interface={}:port={}:privateKey={}/key.pem:certKey={}/cert.pem'.format(
            cfg_options['addr'],
            port,
            cfg_options['ssldir'],
            cfg_options['ssldir']
        )
        log.msg('Listening on {}:{}.'.format(cfg_options['addr'], port))
        endpoints.serverFromString(reactor, endpoint_spec).listen(site)

    if cfg_options['http_port']:
        # Local-lab convenience only (e.g. for tools that don't handle a self-signed cert well); a real
        # NetScaler ADC/Gateway does not serve this surface over plain HTTP. Same Site/routes, no TLS.
        http_endpoint_spec = 'tcp:interface={}:port={}'.format(cfg_options['addr'], cfg_options['http_port'])
        log.msg('Also listening on plain HTTP {}:{}.'.format(cfg_options['addr'], cfg_options['http_port']))
        endpoints.serverFromString(reactor, http_endpoint_spec).listen(site)

    if cfg_options['health_port']:
        # Always 127.0.0.1, regardless of -a/--addr: an ops endpoint, never meant to be reachable from
        # wherever the honeypot surface itself is exposed.
        health_site = server.Site(HealthCheck(profile, __VERSION__))
        health_site.log = mySiteLog
        health_endpoint_spec = 'tcp:interface=127.0.0.1:port={}'.format(cfg_options['health_port'])
        log.msg('Serving health checks on 127.0.0.1:{}.'.format(cfg_options['health_port']))
        endpoints.serverFromString(reactor, health_endpoint_spec).listen(health_site)

    reactor.run()   # pylint: disable=no-member
    log.msg('Shutdown requested, exiting...')
    stop_plugins(cfg_options)


if __name__ == '__main__':
    main()
