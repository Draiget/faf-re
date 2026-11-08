"""Line coverage per src/ folder from `llvm-cov export -summary-only` (tools/coverage/report.sh).

Usage: folders.py <coverage.json> <source root> [depth, default 3]
Prints one row per folder of <source root>/src (src/moho/sim at depth 3), most covered lines first,
then the total.
Only files that some test executable linked appear: a folder no test links is missing here, not 0 %.
"""
import json
import sys
from collections import defaultdict


def normal(path):
    return path.replace("\\", "/").rstrip("/").lower()


def folder_of(path, root, depth):
    """src/a/b for a file under <root>/src; None for anything else (dependencies, tests)."""
    if not normal(path).startswith(root + "/src/"):
        return None
    rest = path.replace("\\", "/")[len(root) + 1:].split("/")
    return "/".join(rest[:min(depth, len(rest) - 1)])


def main():
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    root = normal(sys.argv[2])
    depth = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    totals = defaultdict(lambda: [0, 0, 0])  # covered lines, lines, files
    for export in data.get("data", []):
        for entry in export.get("files", []):
            folder = folder_of(entry["filename"], root, depth)
            if folder is None:
                continue
            lines = entry["summary"]["lines"]
            row = totals[folder]
            row[0] += lines["covered"]
            row[1] += lines["count"]
            row[2] += 1
    covered = sum(row[0] for row in totals.values())
    count = sum(row[1] for row in totals.values())
    print("%-40s %10s %10s %7s %6s" % ("folder", "covered", "lines", "cover", "files"))
    for folder, (hit, lines, files) in sorted(totals.items(), key=lambda item: (-item[1][0], item[0])):
        print("%-40s %10d %10d %6.1f%% %6d" % (folder, hit, lines, 100.0 * hit / lines if lines else 0.0, files))
    print("%-40s %10d %10d %6.1f%%" % ("total (linked files only)", covered, count, 100.0 * covered / count if count else 0.0))


if __name__ == "__main__":
    main()
