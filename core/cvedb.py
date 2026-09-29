"""CVE fix-version data (vendored from citrixscan, see tools/extract_cves.py) used to derive a profile's CVE states."""
import json
import re
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).resolve().parent / 'data' / 'cves.json'


@lru_cache(maxsize=1)
def _db():
    return json.loads(_DATA.read_text())


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
