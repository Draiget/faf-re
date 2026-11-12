#!/usr/bin/env python3
"""Platform guards in C and C++ code ask src/platform/PlatformDefines.h, nothing else.

A preprocessor test (#if, #elif, #ifdef, #ifndef, #elifdef, #elifndef) is refused when it names:

  1. a compiler's platform macro: _WIN32, _WIN64, __linux__, __linux, __APPLE__, __MACH__, __unix__,
     __unix. Use FAFRE_PLATFORM_WINDOWS, FAFRE_PLATFORM_POSIX, FAFRE_PLATFORM_LINUX or
     FAFRE_PLATFORM_MACOS: `#ifdef _WIN32` is `#if FAFRE_PLATFORM_WINDOWS`, `#ifndef _WIN32` is
     `#if !FAFRE_PLATFORM_WINDOWS`.
  2. FAFRE_PLATFORM_LINUX or FAFRE_PLATFORM_MACOS with no comment on the same line. Code every POSIX
     system shares (the SDL window layer, the Win32 stand-ins, sockets, pthreads) tests
     FAFRE_PLATFORM_POSIX. Code for something only one system has says what on the line:
     `#if FAFRE_PLATFORM_LINUX // MSG_NOSIGNAL; macOS sets SO_NOSIGPIPE`.

src/platform/PlatformDefines.h reads the compiler macros, and tests/particles/upload_host is a CMake
project of its own without that header; both are skipped.

Usage:
  platform_macros.py --diff BASE HEAD   the lines BASE..HEAD adds (pull requests; GitHub annotations)
  platform_macros.py --all              every line under src, tests and tools (audit)
  platform_macros.py --file PATH        one file's lines (PATH relative to the repository root)

Exit status 1 when something is refused. Imported by the agent harness too, so both apply one list.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOTS = ("src/", "tests/", "tools/")
EXTENSIONS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl")
SKIPPED = (
    re.compile(r"^src/platform/PlatformDefines\.h$"),
    re.compile(r"^tests/particles/upload_host/"),
)

_DIRECTIVE = re.compile(r"^\s*#\s*(if|elif|ifdef|ifndef|elifdef|elifndef)\b(?P<rest>.*)$")
_COMPILER = re.compile(r"\b(_WIN32|_WIN64|__linux__|__linux|__APPLE__|__MACH__|__unix__|__unix)\b")
_ONE_POSIX = re.compile(r"\bFAFRE_PLATFORM_(LINUX|MACOS)\b")
_COMMENT = re.compile(r"(//|/\*)\s*\S")


def applies_to(path):
    """True when `path` (relative, forward slashes) is C or C++ code this check covers."""
    path = path.replace("\\", "/")
    if not path.startswith(ROOTS) or not path.endswith(EXTENSIONS):
        return False
    return not any(pattern.search(path) for pattern in SKIPPED)


def check_line(line):
    """The reason `line` is refused, or None."""
    match = _DIRECTIVE.match(line)
    if match is None:
        return None
    rest = match.group("rest")
    comment = _COMMENT.search(rest)
    condition = rest[: comment.start()] if comment else rest
    found = _COMPILER.search(condition)
    if found:
        return ("tests the compiler macro %s; use FAFRE_PLATFORM_WINDOWS / _POSIX / _LINUX / _MACOS "
                "(src/platform/PlatformDefines.h)" % found.group(1))
    found = _ONE_POSIX.search(condition)
    if found and comment is None:
        return ("tests FAFRE_PLATFORM_%s alone: code every POSIX system shares tests FAFRE_PLATFORM_POSIX; "
                "for an API only %s has, name it in a comment on this line"
                % (found.group(1), {"LINUX": "Linux", "MACOS": "macOS"}[found.group(1)]))
    return None


def check_text(text):
    """[(line number, reason)] for every refused line of `text`."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        reason = check_line(line)
        if reason:
            problems.append((number, reason))
    return problems


def _git(*args):
    return subprocess.run(("git",) + args, check=True, capture_output=True, text=True, encoding="utf-8",
                          errors="replace").stdout


def added_lines(base, head):
    """{path: [(line number, text)]} for the lines base..head adds."""
    diff = _git("diff", "--unified=0", "--no-color", "--no-ext-diff", base, head, "--", *[r.rstrip("/") for r in ROOTS])
    result = {}
    path = None
    number = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            name = line[4:]
            path = name[2:] if name.startswith("b/") else None
            continue
        if line.startswith("@@"):
            hunk = re.search(r"\+(\d+)", line)
            number = int(hunk.group(1)) if hunk else 0
            continue
        if path is None or not applies_to(path):
            continue
        if line.startswith("+"):
            result.setdefault(path, []).append((number, line[1:]))
            number += 1
    return result


def _report(problems, annotate):
    for path, number, reason in problems:
        if annotate:
            print("::error file=%s,line=%d::%s" % (path, number, reason))
        else:
            print("%s:%d: %s" % (path, number, reason))


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--diff", nargs=2, metavar=("BASE", "HEAD"))
    group.add_argument("--all", action="store_true")
    group.add_argument("--file")
    args = parser.parse_args(argv)

    problems = []
    if args.diff:
        base = _git("merge-base", args.diff[0], args.diff[1]).strip()
        for path, lines in sorted(added_lines(base, args.diff[1]).items()):
            for number, text in lines:
                reason = check_line(text)
                if reason:
                    problems.append((path, number, reason))
    else:
        paths = [args.file] if args.file else [p for p in _git("ls-files", *ROOTS).splitlines() if applies_to(p)]
        for path in paths:
            if not applies_to(path):
                continue
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            problems.extend((path, number, reason) for number, reason in check_text(text))

    _report(problems, annotate=bool(args.diff))
    if problems:
        print("%d platform guard(s) to fix; src/platform/PlatformDefines.h lists the macros." % len(problems),
              file=sys.stderr)
        return 1
    print("Platform guards: nothing to fix.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
