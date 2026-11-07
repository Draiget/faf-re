"""Writes a nightly release's notes: the parity run it passed, every commit since the previous
nightly (or release), how to install it, and the zips' checksums.

usage: TAG=... SHA=... PREVIOUS=... [PARITY_RUN=... PARITY_URL=... NOTE=...] nightly_notes.py --out notes.md
           [--player-notes player-notes.md]

--player-notes also writes the short notes for players that FAF Develop's changelog shows (issue #323):
each `Player-Note:` trailer of the commits since the previous nightly or release, one line per note.

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


def player_notes(previous, sha):
    """The `Player-Note:` trailers of the commits in previous..sha, oldest first, as Markdown list lines."""
    log = subprocess.run(["git", "log", "--no-merges", "--reverse", "--format=%(trailers:key=Player-Note,valueonly,separator=%x00)",
                          "%s..%s" % (previous, sha)],
                         capture_output=True, text=True, encoding="utf-8", check=True).stdout
    notes = [note.strip() for line in log.splitlines() for note in line.split("\0") if note.strip()]
    return ["- " + note for note in notes]


def write_player_notes(path, tag, previous, sha):
    notes = player_notes(previous, sha)
    lines = ["## faf-re %s" % tag, ""] + (notes or ["No player-facing changes since %s." % previous]) + [""]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print("%d player notes since %s" % (len(notes), previous))


def parity_line():
    run, url = os.environ.get("PARITY_RUN"), os.environ.get("PARITY_URL")
    if not run:
        return "Built by hand: no parity run is tied to this build."
    new = []
    counts = {}
    if os.path.isfile("report/report.json"):
        with open("report/report.json", encoding="utf-8") as f:
            report = json.load(f)
        counts, new = report["counts"], report.get("regressions", [])
    text = ("**Built despite new failures in** the [nightly replay parity](%s)" if new else "Passed the [nightly replay parity](%s)") % url
    if counts:
        shown = [(counts.get(k, 0), k) for k in ("pass", "desync", "crash", "expected-desync", "expected-crash", "not-run")]
        text += " on Linux x64: " + ", ".join("%d %s" % (n, k.replace("expected-", "expected ")) for n, k in shown if n)
        if new:
            text += ". New failures: " + ", ".join(str(i) for i in new)
        text += ". What is expected is [listed with why](%s/blob/%s/tools/parity-data/expected/3835.json)" % (REPO, os.environ["SHA"])
    return text + "."


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    parser.add_argument("--player-notes", help="also write the notes for players to this file")
    args = parser.parse_args()
    tag, sha, previous = os.environ["TAG"], os.environ["SHA"], os.environ["PREVIOUS"]
    if args.player_notes:
        write_player_notes(args.player_notes, tag, previous, sha)

    commits = changes(previous, sha)
    shown, size = [], 0
    for line in commits:
        size += len(line) + 1
        if size > MAX_CHANGES:
            break
        shown.append(line)
    with open("zips/SHA256SUMS.txt", encoding="utf-8") as f:
        sums = f.read().strip()

    lines = ["A nightly build of master at [`%s`](%s/commit/%s). It has had no testing beyond the checks below."
             % (sha[:7], REPO, sha), "",
             parity_line(), ""] + ([os.environ["NOTE"], ""] if os.environ.get("NOTE") else []) + [
             "## Changes since %s (%d)" % (previous, len(commits)), ""]
    lines += shown or ["No commits."]
    if len(shown) < len(commits):
        lines += ["", "%d more in the comparison below." % (len(commits) - len(shown))]
    lines += ["", "All changes: %s/compare/%s...%s" % (REPO, previous, tag), "",
              "## Install", "",
              "- **x64:** extract `faf-engine-%s-x64.zip` into the folder you run the x64 engine from. `INSTALL.txt` inside lists the steps." % tag,
              "- **x86:** extract `faf-engine-%s-x86.zip` into FAF's `bin` folder." % tag,
              "- `main_x64.exe` and `main.exe` are the same exes on their own, for updating an install that already has the rest of the zip.",
              "- The `.pdb` files are optional, but crash reports are much more useful with them. Crash reports are written next to the exe as `faf_crash_<date>.txt`; please attach them with your log.",
              "", "SHA-256:", "", "```", sums, "```", ""]
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print("%d commits since %s, %d listed" % (len(commits), previous, len(shown)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
