#!/usr/bin/env python3
"""Keep src/sources.cmake in step with the ClCompile list of src/main.vcxproj.

src/main.vcxproj (MSVC) is the reference build. Its ClCompile order is the
engine's static-initialisation order (see the comment above the list in the
vcxproj), so the CMake build must list the same translation units in the same
order. This script reads the vcxproj and either checks src/sources.cmake
against it (default) or rewrites it (--write).

    python scripts/cmake_sync_sources.py           # exit 1 on drift
    python scripts/cmake_sync_sources.py --write   # regenerate

Items that are ExcludedFromBuild are left out. Per-file settings (extra
include directories, defines, options) are not generated: they live by hand in
src/CMakeLists.txt, next to their reasons.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VCXPROJ = REPO / "src" / "main.vcxproj"
SOURCES = REPO / "src" / "sources.cmake"
NS = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}

HEADER = """\
# Generated from the ClCompile list of src/main.vcxproj by
# scripts/cmake_sync_sources.py --write. Edit main.vcxproj, then regenerate;
# `python scripts/cmake_sync_sources.py` fails when the two differ.
#
# The ORDER IS LOAD-BEARING. Each translation unit's dynamic initialisers go
# into .CRT$XCU in object order, so this list is the engine's static-init
# order; it matches the shipped binary's __xc_a array (reflection types must
# register before any dependent type's Init() runs). Objects are passed to the
# linker in this order.
#
# Paths are relative to src/. ${FAF_DEPENDENCIES_DIR} is the dependencies/
# tree (FX11 and the boost.thread sources compile into the engine directly).
"""


def excluded(item: ET.Element) -> bool:
    for child in item:
        tag = child.tag.split("}")[1]
        if tag == "ExcludedFromBuild" and (child.text or "").strip().lower() == "true":
            cond = child.get("Condition")
            if cond is None or cond.strip() == "true":
                return True
    return False


def cmake_path(include: str) -> str:
    path = include.replace("\\", "/")
    for prefix in ("$(FafRepoRoot)dependencies/", "../dependencies/"):
        if path.startswith(prefix):
            return "${FAF_DEPENDENCIES_DIR}/" + path[len(prefix):]
    if path.startswith("$("):
        raise SystemExit(f"unhandled MSBuild macro in ClCompile path: {include}")
    return path


def vcxproj_sources() -> list[str]:
    root = ET.parse(VCXPROJ).getroot()
    return [
        cmake_path(item.get("Include"))
        for item in root.iterfind(".//m:ClCompile[@Include]", NS)
        if not excluded(item)
    ]


def render(sources: list[str]) -> str:
    body = "\n".join(f"  {s}" for s in sources)
    return f"{HEADER}\nset(FAF_ENGINE_SOURCES\n{body}\n)\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="regenerate src/sources.cmake")
    args = parser.parse_args()

    wanted = render(vcxproj_sources())
    if args.write:
        SOURCES.write_text(wanted, encoding="utf-8", newline="\n")
        print(f"wrote {SOURCES.relative_to(REPO)}")
        return 0

    current = SOURCES.read_text(encoding="utf-8") if SOURCES.exists() else ""
    if current != wanted:
        print("src/sources.cmake is out of date with src/main.vcxproj; "
              "run: python scripts/cmake_sync_sources.py --write", file=sys.stderr)
        return 1
    print("src/sources.cmake matches src/main.vcxproj")
    return 0


if __name__ == "__main__":
    sys.exit(main())
