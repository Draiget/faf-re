#!/usr/bin/env python3
"""I2 (plan WP16.1): a dedicated server's game, re-simulated from its replay by other builds, beat by beat.

The server writes per-beat digests beside its replay (`server --checksum-period 1 --digests <file> --state-digests
<file>`). This script plays that replay with each headless build given, at the same checksum period, and compares
both digest files with the server's on every beat they share:

- checksum digests: the sim's own MD5 checksum of each checksummed beat (equal only at equal periods);
- state digests: a hash of everything the sim published that beat (src/headless/StateDigest.h), any period.

Usage, where the builds are (copy the server's out folder there first):

    python tools/server-i2/i2.py --server-dir <server --out folder> --init <init_replay.lua> \
        --headless x64=<path to headless_x64.exe> --headless x86=<path to headless.exe> [--period 1]

or, for runs made elsewhere, compare files alone:

    python tools/server-i2/i2.py --compare <server digests> <other digests> [--compare ...]

The exit code is 0 when every comparison found at least one common beat and no difference, 1 otherwise.
"""

import argparse
import os
import subprocess
import sys


def read_digests(path):
    """`beat value` lines into {beat: value}; later lines win (a beat written twice keeps its last value)."""
    digests = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 2 and parts[0].lstrip("-").isdigit():
                digests[int(parts[0])] = parts[1]
    return digests


def compare(label, ours_path, theirs_path):
    """Prints one line and returns True when the files share beats and agree on all of them."""
    if not os.path.isfile(ours_path) or not os.path.isfile(theirs_path):
        missing = ours_path if not os.path.isfile(ours_path) else theirs_path
        print(f"{label}: FAIL, no file {missing}")
        return False
    ours = read_digests(ours_path)
    theirs = read_digests(theirs_path)
    common = sorted(set(ours) & set(theirs))
    differ = [beat for beat in common if ours[beat] != theirs[beat]]
    only_ours = len(set(ours) - set(theirs))
    only_theirs = len(set(theirs) - set(ours))
    span = f"beats {common[0]}-{common[-1]}" if common else "no beats"
    verdict = "PASS" if common and not differ else "FAIL"
    first = f", first difference at beat {differ[0]}" if differ else ""
    print(f"{label}: {verdict}, {len(common)} common beats ({span}), {len(differ)} differ{first}; "
          f"only in the first file {only_ours}, only in the second {only_theirs}")
    return verdict == "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server-dir", help="the server's --out folder with game.scfareplay")
    parser.add_argument("--replay", help="the replay (default: <server-dir>/game.scfareplay)")
    parser.add_argument("--digests", help="the server's --digests file (default: <server-dir>/digests.txt)")
    parser.add_argument("--state-digests", help="the server's --state-digests file (default: <server-dir>/state-digests.txt)")
    parser.add_argument("--init", help="init file for headless (/init)")
    parser.add_argument("--headless", action="append", default=[], metavar="LABEL=PATH",
                        help="a headless build to play the replay with; repeat for each")
    parser.add_argument("--period", type=int, default=1, help="checksum period, the server's --checksum-period (default 1)")
    parser.add_argument("--work", help="folder for the builds' digests and logs (default: <server-dir>/i2)")
    parser.add_argument("--timeout", type=int, default=60, help="headless --timeout in whole minutes (default 60)")
    parser.add_argument("--args", default="", help="more headless arguments, one string")
    parser.add_argument("--compare", nargs=2, action="append", default=[], metavar=("FIRST", "SECOND"),
                        help="only compare two digest files of the same kind")
    options = parser.parse_args()

    results = []
    for first, second in options.compare:
        results.append(compare(f"{os.path.basename(first)} vs {os.path.basename(second)}", first, second))

    if options.headless:
        if not options.server_dir or not options.init:
            parser.error("--headless needs --server-dir and --init")
        replay = options.replay or os.path.join(options.server_dir, "game.scfareplay")
        server_digests = options.digests or os.path.join(options.server_dir, "digests.txt")
        server_states = options.state_digests or os.path.join(options.server_dir, "state-digests.txt")
        work = options.work or os.path.join(options.server_dir, "i2")
        os.makedirs(work, exist_ok=True)
        for entry in options.headless:
            label, _, exe = entry.partition("=")
            if not exe:
                parser.error(f"--headless takes LABEL=PATH, not {entry}")
            digests = os.path.join(work, f"{label}-digests.txt")
            states = os.path.join(work, f"{label}-state-digests.txt")
            log = os.path.join(work, f"{label}.log")
            command = [exe, "--label", label, "--replay", replay, "/init", options.init, "/nobugreport", "/nosound",
                       "/log", log, "--timeout", str(options.timeout), "--checksum-period", str(options.period),
                       "--digests", digests, "--state-digests", states] + options.args.split()
            with open(os.path.join(work, f"{label}.out"), "w", encoding="utf-8") as out:
                code = subprocess.call(command, stdout=out, stderr=subprocess.STDOUT)
            verdict = ""
            with open(os.path.join(work, f"{label}.out"), encoding="utf-8", errors="replace") as out:
                for line in out:
                    if "VERDICT" in line:
                        verdict = line.strip()[line.find("VERDICT"):][:120]
            print(f"{label}: headless exit {code} {verdict}")
            results.append(compare(f"{label} checksum digests", server_digests, digests))
            results.append(compare(f"{label} state digests", server_states, states))

    if not results:
        parser.error("nothing to do: give --headless or --compare")
    print("I2 PASS" if all(results) else "I2 FAIL")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
