#!/usr/bin/env python3
"""Compare the machine code of two builds, function by function.

A pure refactor should leave the machine code alone, and when it does no replay is needed to prove it.
This disassembles every object of both builds with llvm-objdump, keeps one hash per function, and reports the
functions that differ, exist on one side only, or moved between objects (a moved function that hashes the same is
reported as a move, not a difference, so a file split can be checked too).

Addresses and everything that depends on where a file lives are normalised away: the mangled name of an anonymous
namespace holds a hash of its file, and that changes when code moves. Debug information isn't compared.

Usage:
  compare_objs.py <before build dir> <after build dir> [--objdump PATH] [--jobs N] [--filter SUBSTRING]

Exit code 0 when every function has the same code, wherever it moved; 1 otherwise.
"""
import argparse
import collections
import concurrent.futures as cf
import hashlib
import os
import re
import shutil
import subprocess
import sys

# ?A0x1234abcd@ in a mangled name: the anonymous namespace's per-file hash.
ANON = re.compile(r"\?A0x[0-9a-fA-F]+")
# Offsets of a label inside its own section, e.g. "jmp 0x4f <foo+0x1f>": the target is kept relative to its function.
LOCAL_ADDR = re.compile(r"\b0x[0-9a-f]+ <([^>]+)>")
FUNC = re.compile(r"^(?:[0-9a-f]+ )?<?([^<>\s][^<>]*?)>?:\s*$")
SECTION = re.compile(r"^Disassembly of section (.*):\s*$")
RELOC = re.compile(r"^\s*(?:[0-9a-f]+:\s*)?(IMAGE_REL_\S+|R_X86_64_\S+|R_386_\S+)\s+(.*)$")


def find_objdump(explicit):
    if explicit:
        return explicit
    for candidate in ("llvm-objdump", r"C:\Program Files\LLVM\bin\llvm-objdump.exe"):
        found = shutil.which(candidate) or (candidate if os.path.exists(candidate) else None)
        if found:
            return found
    sys.exit("llvm-objdump not found; pass --objdump")


def objects_under(root, needle):
    found = []
    for folder, _, files in os.walk(root):
        for name in files:
            if name.endswith((".obj", ".o")):
                path = os.path.join(folder, name)
                if needle in path.replace(os.sep, "/"):
                    found.append(path)
    return found


def normalise(line):
    line = ANON.sub("?A", line)
    line = LOCAL_ADDR.sub(lambda m: "<" + ANON.sub("?A", m.group(1)) + ">", line)
    return re.sub(r"\s+", " ", line).strip()


def hash_object(job):
    """Returns (object path, {function name: hash}) for one object."""
    objdump, path = job
    proc = subprocess.run(
        [objdump, "--disassemble", "--reloc", "--no-show-raw-insn", "--no-leading-addr", "--demangle=false", path],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0 and "unknown argument" in proc.stderr:
        proc = subprocess.run(
            [objdump, "--disassemble", "--reloc", "--no-show-raw-insn", "--no-leading-addr", path],
            capture_output=True,
            text=True,
            errors="replace",
        )
    funcs = {}
    current = None
    digest = None

    def close():
        if current is not None:
            funcs[current] = digest.hexdigest()

    for raw in proc.stdout.splitlines():
        if SECTION.match(raw) or not raw.strip():
            continue
        match = FUNC.match(raw) if not raw.startswith((" ", "\t")) else None
        if match:
            close()
            current = ANON.sub("?A", match.group(1))
            digest = hashlib.sha1()
            continue
        if current is not None:
            digest.update(normalise(raw).encode())
            digest.update(b"\n")
    close()
    return path, funcs, proc.returncode, proc.stderr[:200]


def scan(root, objdump, jobs, needle):
    objects = objects_under(root, needle)
    table = collections.defaultdict(dict)  # name -> {relative object: hash}
    errors = []
    with cf.ThreadPoolExecutor(jobs) as pool:
        for path, funcs, code, err in pool.map(hash_object, [(objdump, p) for p in objects]):
            if code != 0:
                errors.append((path, err))
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            for name, value in funcs.items():
                table[name][rel] = value
    return table, len(objects), errors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--objdump")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--filter", default="", help="only objects whose path holds this text")
    parser.add_argument("--show", type=int, default=60, help="names to print per group")
    args = parser.parse_args()
    objdump = find_objdump(args.objdump)

    before, count_a, errors_a = scan(args.before, objdump, args.jobs, args.filter)
    after, count_b, errors_b = scan(args.after, objdump, args.jobs, args.filter)
    for path, err in errors_a + errors_b:
        print(f"could not read {path}: {err}")

    # A name can appear in many objects (an inline function, or a static in each file). Compare the set of bodies.
    same = moved = 0
    changed, only_before, only_after = [], [], []
    for name in sorted(set(before) | set(after)):
        a, b = before.get(name), after.get(name)
        if a is None:
            only_after.append(name)
        elif b is None:
            only_before.append(name)
        elif set(a.values()) != set(b.values()):
            changed.append(name)
        elif set(a) != set(b):
            moved += 1
        else:
            same += 1

    # A function that exists on one side only may have been renamed: the same body on the other side settles it.
    bodies_after = {h for v in after.values() for h in v.values()}
    bodies_before = {h for v in before.values() for h in v.values()}
    gone = [n for n in only_before if not set(before[n].values()) <= bodies_after]
    new = [n for n in only_after if not set(after[n].values()) <= bodies_before]

    print(f"objects: {count_a} before, {count_b} after; functions: {len(before)} before, {len(after)} after")
    print(f"same place and code: {same}; moved with the same code: {moved}; renamed with the same code: {len(only_before) - len(gone)}")
    for title, names in (("code differs", changed), ("gone", gone), ("new", new)):
        print(f"{title}: {len(names)}")
        for name in names[: args.show]:
            print("  ", name[:150])
    verdict = "SAME" if not changed and not gone and not new else "DIFFERENT"
    print(f"RESULT {verdict}")
    return 0 if verdict == "SAME" else 1


if __name__ == "__main__":
    sys.exit(main())
