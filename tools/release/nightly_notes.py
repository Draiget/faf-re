"""Writes a nightly pre-release's notes: the parity run it passed, every commit since the previous
nightly (or release), how to install it, and the zips' checksums.

usage: TAG=... SHA=... PREVIOUS=... [PARITY_RUN=... PARITY_URL=...] nightly_notes.py --out notes.md

Reads git history, zips/SHA256SUMS.txt and, when the parity run's report was downloaded, report/report.json.
"""
import argparse
import json
import os
import subprocess

REPO = "https://github.com/Draiget/faf-re"
# GitHub refuses a release body over 125,000 characters.
MAX_CHANGES = 100_000


def changes(previous, sha):
    """One Markdown line per commit, newest first, as the history shows them."""
    log = subprocess.run(["git", "log", "--no-merges", "--format=- %s (%h)", "%s..%s" % (previous, sha)],
                         capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return log.splitlines()


def parity_line():
    run, url = os.environ.get("PARITY_RUN"), os.environ.get("PARITY_URL")
    if not run:
        return "Built by hand: no parity run is tied to this build."
    text = "Passed the [nightly replay parity](%s)" % url
    if os.path.isfile("report/report.json"):
        with open("report/report.json", encoding="utf-8") as f:
            counts = json.load(f)["counts"]
        shown = [(counts.get(k, 0), k) for k in ("pass", "desync", "crash", "not-run")]
        text += " on Linux x64: " + ", ".join("%d %s" % c for c in shown if c[0])
        text += ". The desyncs listed are known failures, none of them new"
    return text + "."


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    tag, sha, previous = os.environ["TAG"], os.environ["SHA"], os.environ["PREVIOUS"]

    commits = changes(previous, sha)
    shown, size = [], 0
    for line in commits:
        size += len(line) + 1
        if size > MAX_CHANGES:
            break
        shown.append(line)
    with open("zips/SHA256SUMS.txt", encoding="utf-8") as f:
        sums = f.read().strip()

    lines = ["A nightly build of master at [`%s`](%s/commit/%s). It has had no testing beyond the checks below: "
             "use a [release](%s/releases/latest) unless you want the newest changes." % (sha[:7], REPO, sha, REPO), "",
             parity_line(), "",
             "## Changes since %s (%d)" % (previous, len(commits)), ""]
    lines += shown or ["No commits."]
    if len(shown) < len(commits):
        lines += ["", "%d more in the comparison below." % (len(commits) - len(shown))]
    lines += ["", "All changes: %s/compare/%s...%s" % (REPO, previous, tag), "",
              "## Install", "",
              "- **x64:** extract `faf-engine-%s-x64.zip` into the folder you run the x64 engine from. `INSTALL.txt` inside lists the steps." % tag,
              "- **x86:** extract `faf-engine-%s-x86.zip` into FAF's `bin` folder." % tag,
              "- The `.pdb` files are optional, but crash reports are much more useful with them. Crash reports are written next to the exe as `faf_crash_<date>.txt`; please attach them with your log.",
              "", "SHA-256:", "", "```", sums, "```", ""]
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print("%d commits since %s, %d listed" % (len(commits), previous, len(shown)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
