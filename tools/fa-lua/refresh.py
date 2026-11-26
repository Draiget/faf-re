#!/usr/bin/env python3
"""Regenerate data/fa-lua: our changes to FAF's UI Lua that FAF hasn't taken yet.

The engine ships them as faf-re-lua.nx2 next to the executable (src/moho/misc/FafLuaOverrides.cpp).
Each file in it replaces one FAF file, and only when the FAF file a player has mounted is byte for
byte the one the replacement was made from: manifest.txt pairs every replacement with the SHA-256
of that FAF file. A FAF release that changes the file, or takes our change, makes the replacement
step aside on its own, and running this script again makes a new one.

For every pull request listed in data/fa-lua/sources.txt and every FAF branch players run
(deploy/faf, deploy/fafbeta, deploy/fafdevelop, develop), the script merges the pull request's
change into the branch's file (git merge-file, three-way from the pull request's merge base) and
writes the result under data/fa-lua/files/<first 12 hex of the FAF file's hash>/<path>. A branch
whose file already has the change, or where the merge conflicts, gets no replacement (a conflict is
printed).

Only UI Lua (lua/ui/, lua/keymap/) may be replaced: nothing the simulation loads, so a game with
players on retail Lua cannot desync. The engine refuses other paths too.

Usage:
  python tools/fa-lua/refresh.py --fa G:/repos/fa            # fetch, then regenerate
  python tools/fa-lua/refresh.py --fa G:/repos/fa --no-fetch # use what the clone has
"""

import argparse
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "data" / "fa-lua"
BRANCHES = ["deploy/faf", "deploy/fafbeta", "deploy/fafdevelop", "develop"]
ALLOWED_PREFIXES = ("lua/ui/", "lua/keymap/")
# Files a pull request carries that are not game files.
IGNORED_PREFIXES = ("changelog/",)


def git(fa, *args, check=True):
    result = subprocess.run(["git", "-C", str(fa), *args], capture_output=True, check=False)
    if check and result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{result.stderr.decode(errors='replace')}")
    return result


def blob(fa, ref, path):
    """The file's bytes at `ref`, or None when the file isn't there."""
    result = git(fa, "show", f"{ref}:{path}", check=False)
    return result.stdout if result.returncode == 0 else None


def merge3(current, base, theirs):
    """git merge-file: `theirs`' change from `base` applied to `current`. None on a conflict."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "current").write_bytes(current)
        (tmp / "base").write_bytes(base)
        (tmp / "theirs").write_bytes(theirs)
        result = subprocess.run(
            ["git", "merge-file", "-q", str(tmp / "current"), str(tmp / "base"), str(tmp / "theirs")],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        return (tmp / "current").read_bytes()


def read_sources():
    """Pull request numbers from sources.txt: one per line, '#' starts a comment."""
    numbers = []
    for line in (OUT / "sources.txt").read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            numbers.append(int(text))
    return numbers


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fa", required=True, type=pathlib.Path, help="a clone of FAForever/fa")
    parser.add_argument("--remote", default="origin", help="the clone's remote for FAForever/fa (default origin)")
    parser.add_argument("--no-fetch", action="store_true", help="don't fetch the branches and pull requests")
    args = parser.parse_args()
    fa, remote = args.fa, args.remote

    prs = read_sources()
    if not args.no_fetch:
        refspecs = [f"+refs/heads/{b}:refs/remotes/{remote}/{b}" for b in BRANCHES]
        refspecs += [f"+refs/pull/{n}/head:refs/fa-lua/pr/{n}" for n in prs]
        git(fa, "fetch", "--quiet", remote, *refspecs)

    develop = f"{remote}/develop"
    # path -> list of (pr, merge base, pr head)
    changes = {}
    for n in prs:
        head = f"refs/fa-lua/pr/{n}"
        base = git(fa, "merge-base", head, develop).stdout.decode().strip()
        names = git(fa, "diff", "--name-only", "--no-renames", base, head).stdout.decode().split()
        for path in names:
            if path.startswith(IGNORED_PREFIXES):
                continue
            if not path.startswith(ALLOWED_PREFIXES):
                raise SystemExit(f"FAForever/fa#{n} changes {path}: only UI Lua ({', '.join(ALLOWED_PREFIXES)}) can ship")
            if " " in path:
                raise SystemExit(f"FAForever/fa#{n}: {path} has a space, which manifest.txt can't hold")
            changes.setdefault(path, []).append((n, base, head))

    # (path, FAF file hash) -> (replacement bytes, pull requests, branches)
    variants = {}
    problems = 0
    for path in sorted(changes):
        for branch in BRANCHES:
            original = blob(fa, f"{remote}/{branch}", path)
            if original is None:
                print(f"  {branch}: no {path}, nothing to replace")
                continue
            merged, applied = original, []
            for n, base, head in changes[path]:
                base_bytes, head_bytes = blob(fa, base, path), blob(fa, head, path)
                if head_bytes is None:
                    raise SystemExit(f"FAForever/fa#{n} deletes {path}; a deletion can't ship as a replacement")
                if base_bytes is None:
                    base_bytes = b""
                result = merge3(merged, base_bytes, head_bytes)
                if result is None:
                    print(f"  CONFLICT {branch}: FAForever/fa#{n} on {path}; no replacement for this branch")
                    problems += 1
                    merged = None
                    break
                if result != merged:
                    applied.append(n)
                merged = result
            if merged is None or not applied:
                continue
            key = (path, hashlib.sha256(original).hexdigest())
            if key in variants:
                variants[key][2].append(branch)
            else:
                variants[key] = (merged, applied, [branch])

    files = OUT / "files"
    if files.exists():
        shutil.rmtree(files)
    lines = [
        "# Written by tools/fa-lua/refresh.py; don't edit by hand.",
        "# <SHA-256 of FAF's file> <game path> <replacement in this archive> <pull requests> <FAF branches>",
    ]
    for (path, digest), (content, applied, branches) in sorted(variants.items()):
        entry = f"files/{digest[:12]}/{path}"
        target = OUT / entry
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        prs_text = ",".join(f"FAForever/fa#{n}" for n in applied)
        lines.append(f"{digest} /{path} {entry} {prs_text} {','.join(branches)}")
    (OUT / "manifest.txt").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    print(f"{len(variants)} replacements for {len(changes)} files from {len(prs)} pull requests")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
