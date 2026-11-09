"""Prints each executable ctest runs in a build folder, once per line (tools/coverage/report.sh).

Usage: test_executables.py <build folder>
"""
import json
import os
import subprocess
import sys


def main():
    build = sys.argv[1]
    listing = subprocess.run(
        ["ctest", "--test-dir", build, "--show-only=json-v1"], capture_output=True, text=True, check=True
    ).stdout
    seen = []
    for test in json.loads(listing).get("tests", []):
        command = test.get("command") or []
        if not command:
            continue
        exe = os.path.normpath(command[0])
        if os.path.isfile(exe) and exe not in seen:
            seen.append(exe)
    for exe in seen:
        print(exe)


if __name__ == "__main__":
    main()
