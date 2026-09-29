"""Regenerate core/data/cves.json from a checkout of jtatman/citrixscan (MIT licensed, stdlib only).

Usage: python tools/extract_cves.py /path/to/citrixscan/citrixscan.py
"""
import importlib.util
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('citrixscan', src)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

out = {
    '_source': 'https://github.com/jtatman/citrixscan (MIT), CVE_DATABASE',
    'cves': {
        c.cve_id: {
            'title': c.title, 'cvss': c.cvss, 'severity': c.severity, 'advisory': c.advisory,
            'affected_config': c.affected_config,
            'fixed_versions': {b: mod.format_version(v) for b, v in c.fixed_versions.items()},
            'exploited_in_wild': c.exploited_in_wild, 'public_poc': c.public_poc, 'cwe': c.cwe,
        }
        for c in mod.CVE_DATABASE
    },
    'eol_branches': sorted(mod.EOL_BRANCHES),
}
dest = Path(__file__).resolve().parent.parent / 'core' / 'data' / 'cves.json'
dest.write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
print('wrote', dest, len(out['cves']), 'CVEs')

# gzip MTIME of /vpn/js/rdx/core/lang/rdx_en.json.gz -> firmware build (Fox-IT technique), version -> [mtimes]
stamps = {}
for mtime, ver in mod.RDX_EN_STAMP_TO_VERSION.items():
    stamps.setdefault(ver, []).append(mtime)
dest2 = dest.with_name('rdx_en_stamps.json')
dest2.write_text(json.dumps({'_source': out['_source'] + ' RDX_EN_STAMP_TO_VERSION',
                             'versions': {v: sorted(t) for v, t in stamps.items()}}, indent=1, sort_keys=True) + '\n')
print('wrote', dest2, len(stamps), 'versions')
