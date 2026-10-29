#!/usr/bin/env python3
"""Run faf-argorder-scan on every faf_sim translation unit of a Linux build (plan WPL.24).

Usage: scan.py <build dir> <scanner> <output file> [jobs]
Reads <build dir>/compile_commands.json, scans each faf_sim TU with its own compiler arguments
and writes the sorted, de-duplicated report (one line per call; see ArgOrderScan.cpp).
"""
import json
import os
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

build, scanner, output = sys.argv[1], sys.argv[2], sys.argv[3]
jobs = int(sys.argv[4]) if len(sys.argv) > 4 else 4
entries = [e for e in json.load(open(os.path.join(build, "compile_commands.json")))
           if "faf_sim.dir" in e.get("output", e.get("command", "")) and e["file"].endswith(".cpp")]


def arguments(entry):
    args = shlex.split(entry["command"]) if "command" in entry else list(entry["arguments"])
    out, skip = [], False
    for index, arg in enumerate(args[1:]):
        if skip:
            skip = False
            continue
        if arg in ("-o", "-MF", "-MT", "-MQ"):
            skip = True
            continue
        if arg in ("-c", entry["file"]) or arg.startswith("-M"):
            continue
        out.append(arg)
    return out


def scan(entry):
    result = subprocess.run([scanner, entry["file"], "--"] + arguments(entry), cwd=entry["directory"],
                            capture_output=True, text=True)
    return entry["file"], result.returncode, result.stdout, result.stderr


lines, failures = set(), []
with ThreadPoolExecutor(max_workers=jobs) as pool:
    for path, code, out, err in pool.map(scan, entries):
        if code != 0:
            failures.append(path + ": " + err.strip()[:200])
        lines.update(line for line in out.splitlines() if line)

with open(output, "w") as handle:
    for line in sorted(lines):
        handle.write(line + "\n")
print(f"{len(entries)} TUs scanned, {len(failures)} failed, {len(lines)} calls reported -> {output}")
for failure in failures[:20]:
    print("FAILED", failure)
