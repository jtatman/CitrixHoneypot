"""CVE fix-version data used to derive a profile's CVE states.

Vendored from citrixscan (tools/extract_cves.py) plus hand-added bulletins in cves_extra.json.
"""
import json
import re
from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).resolve().parent / 'data'


@lru_cache(maxsize=1)
def _db():
    db = json.loads((_DIR / 'cves.json').read_text())
    db['cves'].update(json.loads((_DIR / 'cves_extra.json').read_text())['cves'])   # hand-added bulletins
    return db


@lru_cache(maxsize=1)
def _stamps():
    return json.loads((_DIR / 'rdx_en_stamps.json').read_text())['versions']


def rdx_en_mtime(build):
    """gzip MTIME of rdx_en.json.gz for a build, from the citrixscan table; None if the build is not in it."""
    stamps = _stamps().get(build)
    return stamps[0] if stamps else None


def parse_build(build):
    """'12.1-55.18' -> (12, 1, 55, 18); None if unparsable."""
    m = re.match(r'^(\d+)\.(\d+)[-.](\d+)\.(\d+)$', (build or '').strip())
    return tuple(int(x) for x in m.groups()) if m else None


def info(cve):
    return _db()['cves'].get(cve)


def state_for_build(cve, build):
    """'vulnerable' / 'patched' for a build, or None when the CVE or build is unknown.

    Same rules as citrixscan: a listed branch is vulnerable below its fixed build; an unlisted branch is
    vulnerable only if it is end-of-life (never patched), otherwise not affected.
    """
    entry, ver = info(cve), parse_build(build)
    if entry is None or ver is None:
        return None
    branch = '{}.{}'.format(*ver[:2])
    fixed = entry['fixed_versions'].get(branch)
    if fixed:
        return 'vulnerable' if ver < parse_build(fixed) else 'patched'
    return 'vulnerable' if branch in _db()['eol_branches'] else 'patched'
