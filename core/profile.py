"""Appliance profiles: what product/build the honeypot pretends to be and which CVEs it looks vulnerable to."""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import yaml

from core import cvedb

PROFILES_DIR = Path(__file__).resolve().parent.parent / 'profiles'
DEFAULT_PROFILE = 'adc-12.1-vulnerable'
STATES = ('vulnerable', 'patched', 'off')
_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]*$')

DEFAULT_COOKIES = [
    'NSC_AAAC=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_EPAC=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_USER=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_BASEURL=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'CsrfToken=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'CtxsAuthId=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'ASP.NET_SessionId=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_TMAA=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT',
    'NSC_TMAS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure',
    'NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT',
    'NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT',
]


class ProfileError(ValueError):
    pass


@dataclass
class Profile:
    name: str
    product: str = 'NetScaler ADC'
    build: str = ''
    server_header: str = 'Apache'
    login_page: str = 'login.html'
    headers: Dict[str, str] = field(default_factory=dict)      # extra response headers
    cookies: List[str] = field(default_factory=lambda: list(DEFAULT_COOKIES))
    tls_cn: str = 'localhost'
    cves: Dict[str, str] = field(default_factory=dict)
    patched_status: int = 404
    patched_page: str = '404.html'

    def state(self, cve):
        """'vulnerable', 'patched' or 'off' for a CVE.

        Precedence: explicit `cves:` entry in the profile > derived from `build` via the CVE fix-version
        table > 'vulnerable'.
        """
        return self.cves.get(cve) or cvedb.state_for_build(cve, self.build) or 'vulnerable'


def load_profile(name=DEFAULT_PROFILE, directory=PROFILES_DIR):
    if not _NAME.match(name or ''):
        raise ProfileError('invalid profile name: {!r}'.format(name))
    path = Path(directory) / '{}.yaml'.format(name)
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except FileNotFoundError:
        raise ProfileError('unknown profile {!r} (looked for {})'.format(name, path)) from None
    if not isinstance(data, dict):
        raise ProfileError('{}: top level must be a mapping'.format(path))

    known = {'name', 'product', 'build', 'server_header', 'login_page', 'headers', 'cookies', 'tls', 'cves',
             'patched_response'}
    if set(data) - known:
        raise ProfileError('{}: unknown keys {}'.format(path, sorted(set(data) - known)))
    if data.get('name', name) != name:
        raise ProfileError('{}: name {!r} does not match file name'.format(path, data.get('name')))

    cves = data.get('cves') or {}
    bad = {k: v for k, v in cves.items() if v not in STATES}
    if bad:
        raise ProfileError('{}: cve states must be one of {}: {}'.format(path, STATES, bad))

    p = Profile(name=name, cves=dict(cves))
    for key in ('product', 'build', 'server_header', 'login_page'):
        if key in data:
            setattr(p, key, str(data[key]))
    if 'headers' in data:
        p.headers = {str(k): str(v) for k, v in (data['headers'] or {}).items()}
    if 'cookies' in data:
        p.cookies = [str(c) for c in (data['cookies'] or [])]
    p.tls_cn = str((data.get('tls') or {}).get('subject_cn', p.tls_cn))
    pr = data.get('patched_response') or {}
    p.patched_status = int(pr.get('status', p.patched_status))
    p.patched_page = str(pr.get('page', p.patched_page))
    for page in (p.login_page, p.patched_page):
        if not _NAME.match(page):
            raise ProfileError('{}: invalid page name {!r}'.format(path, page))
    return p
