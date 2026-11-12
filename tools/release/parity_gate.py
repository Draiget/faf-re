"""Decides whether a nightly parity report allows publishing a release.

usage: parity_gate.py REPORT_JSON [--max-desync-percent 5]

Publishing is cancelled when the new desyncs are more than the given share of the replays that
reached a checksum verdict (pass, desync, expected-desync). Only new desyncs count: a crash,
timeout, error or a desync listed in the expected file does not. A report with no such replay
cancels too, as it proves nothing. Prints one line for the job summary and exits 0 to publish, 3
to cancel; any other code (a missing or unreadable report) is an error, not a verdict.
"""
import argparse
import json
import sys

PLAYED = ("pass", "desync", "expected-desync")
CANCEL = 3


def decide(report, max_percent):
    """Returns (publish, line)."""
    replays = report.get("replays", [])
    played = sum(1 for r in replays if r.get("verdict") in PLAYED)
    new = sorted(r["id"] for r in replays if r.get("verdict") == "desync")
    if played == 0:
        return False, "No replay reached a checksum verdict: nothing to publish."
    percent = 100.0 * len(new) / played
    shown = ", ".join(str(i) for i in new[:20]) + (", ..." if len(new) > 20 else "")
    line = "%d new desyncs in %d replays played (%.2f %%, limit %g %%)%s" % (
        len(new), played, percent, max_percent, ": " + shown if new else "")
    if percent > max_percent:
        return False, line + ": nothing to publish."
    return True, line + ": publishing."


def main():
    p = argparse.ArgumentParser()
    p.add_argument("report")
    p.add_argument("--max-desync-percent", type=float, default=5.0)
    args = p.parse_args()
    with open(args.report, encoding="utf-8") as f:
        report = json.load(f)
    publish, line = decide(report, args.max_desync_percent)
    print(line)
    return 0 if publish else CANCEL


if __name__ == "__main__":
    sys.exit(main())
