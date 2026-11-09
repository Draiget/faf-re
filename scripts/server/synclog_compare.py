"""Compare two /synclog folders of one replay, written on two platforms (plan WPL.21).

usage: synclog_compare.py <dir> <dir> --last-beat <n>

The sim writes one file per beat, beatNNNNN.log, and keeps beat00000.log plus the latest
sim_ChecksumPeriod + 20 (Sim::FlushLog). It opens a beat's file when the previous beat ends and
writes it while the beat runs, so the files after the last beat whose packet headless took
(`last-beat=` in its output) hold whatever the process exit caught: those are left out. The
retained window's first beat moves with them (a run that got one beat further has deleted one
more old file), so the files compared start at the later of the two folders' first beats after
beat 0. Every file in that range must exist in both folders and be identical apart from line
endings (Windows text mode writes CRLF, Linux LF).

Exit code 0 when every compared file is identical, 1 otherwise, 2 on bad arguments.
"""
import argparse
import os
import re
import sys

BEAT_FILE = re.compile(r"^beat(\d{5})\.log$")


def beat_files(folder):
    """{beat: path} of a /synclog folder, or of its one dated subfolder."""
    entries = os.listdir(folder)
    if not any(BEAT_FILE.match(e) for e in entries):
        dated = [e for e in entries if os.path.isdir(os.path.join(folder, e))]
        if len(dated) == 1:
            folder = os.path.join(folder, dated[0])
            entries = os.listdir(folder)
    files = {}
    for e in entries:
        m = BEAT_FILE.match(e)
        if m:
            files[int(m.group(1))] = os.path.join(folder, e)
    return files


def text(path):
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--last-beat", type=int, required=True)
    args = p.parse_args()
    a = {k: v for k, v in beat_files(args.a).items() if k <= args.last_beat}
    b = {k: v for k, v in beat_files(args.b).items() if k <= args.last_beat}
    if not a or not b:
        print("SYNCLOG no beat files up to beat %d" % args.last_beat)
        return 2
    first = max(min((k for k in a if k > 0), default=0), min((k for k in b if k > 0), default=0))
    a = {k: v for k, v in a.items() if k == 0 or k >= first}
    b = {k: v for k, v in b.items() if k == 0 or k >= first}
    problems = 0
    for beat in sorted(set(a) | set(b)):
        if beat not in a or beat not in b:
            print("SYNCLOG beat%05d.log only in %s" % (beat, args.a if beat in a else args.b))
            problems += 1
        elif text(a[beat]) != text(b[beat]):
            print("SYNCLOG beat%05d.log DIFFERS" % beat)
            problems += 1
    print("SYNCLOG files=%d differ=%d last-beat=%d" % (len(set(a) | set(b)), problems, args.last_beat))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
