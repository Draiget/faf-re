#!/usr/bin/env python3
"""Compare only this run's selected boundary states; ignore stale files."""
import hashlib
import json
import re
import sys
from pathlib import Path


def current_files(directory):
    names = (directory / 'run-files.txt').read_text().splitlines()
    if not names or len(set(names)) != len(names):
        raise ValueError('Expected a nonempty manifest of unique filenames')
    cases = {scenario: set() for scenario in range(5)}
    for name in names:
        match = re.fullmatch(r'scenario-([0-4])-fail-(0|[1-9][0-9]*)\.bin', name)
        if match is None or Path(name).name != name:
            raise ValueError(f'Invalid relative state filename: {name!r}')
        if not (directory / name).is_file():
            raise ValueError(f'Missing current-run state file: {name}')
        cases[int(match[1])].add(int(match[2]))
    for scenario, points in cases.items():
        if not points or points != set(range(max(points) + 1)):
            raise ValueError(f'Incomplete state sequence for scenario {scenario}')
    return {name: directory / name for name in names}


root = Path(sys.argv[1])
off = current_files(root / 'states-0')
on = current_files(root / 'states-1')
if off.keys() != on.keys():
    raise SystemExit('Different current-run allocation scenario sets')
rows = []
for name in sorted(off):
    a, b = off[name].read_bytes(), on[name].read_bytes()
    rows.append({'case': name, 'equal': a == b, 'bytes': len(a),
                 'off_sha256': hashlib.sha256(a).hexdigest(),
                 'on_sha256': hashlib.sha256(b).hexdigest()})
(root / 'allocation-comparison.json').write_text(json.dumps(rows, indent=2) + '\n')
if not all(row['equal'] for row in rows):
    raise SystemExit('Allocation boundary-state mismatch; see allocation-comparison.json')
print(f'{len(rows)} selected boundary states match between switch off and on')
