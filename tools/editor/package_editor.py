#!/usr/bin/env python3
"""Packages the map editor for people who don't build it: a folder and a zip with the exe, its symbols, the editor's
doc and a short read-me, and a manifest with each file's size and SHA-256 (as FAF Studio's package_editor.py did).

The editor carries its own DXC copy (EmbeddedFiles.rc) and finds FAF's game data by itself when started without
arguments (init_faf.lua next to it or in the FAF client's folders), so the exe is all it needs.

    python tools/editor/package_editor.py --build build/clang-x64-release --out out/editor [--version 2026.11.14]
    python tools/editor/package_editor.py ... --test   # also unpacks the zip into a path with spaces and checks it
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile
import zipfile

README = """FAF map editor
==============

Run FafEditor_x64.exe. It finds Forged Alliance Forever's game data by itself (FAF's init_faf.lua next to it, or in
the FAF client's bin_x64 / bin folders, or under %ProgramData%\\FAForever). To point it somewhere else, start it with
    FafEditor_x64.exe /init <path to init_faf.lua>

It draws with Direct3D 12 or Vulkan. Your settings, layout and keys are kept in %LOCALAPPDATA%\\FAForever\\Editor.
MAP_EDITOR.md describes every tool. manifest.json lists the package's files with their SHA-256.
"""


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def collect(build: pathlib.Path, repo: pathlib.Path) -> list[tuple[pathlib.Path, str]]:
    editor = build / "src" / "editor"
    files = [(editor / "FafEditor_x64.exe", "FafEditor_x64.exe")]
    if (editor / "FafEditor_x64.pdb").exists():
        files.append((editor / "FafEditor_x64.pdb", "FafEditor_x64.pdb"))
    files.append((repo / "docs" / "MAP_EDITOR.md", "MAP_EDITOR.md"))
    missing = [str(source) for source, _ in files if not source.exists()]
    if missing:
        raise SystemExit("missing: " + ", ".join(missing))
    return files


def make(build: pathlib.Path, out: pathlib.Path, version: str, repo: pathlib.Path) -> pathlib.Path:
    folder = out / f"FafEditor-{version}"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    manifest = {"name": "FAF map editor", "version": version, "files": []}
    for source, name in collect(build, repo):
        shutil.copy2(source, folder / name)
    (folder / "README.txt").write_text(README, encoding="utf-8")
    for item in sorted(folder.iterdir()):
        manifest["files"].append({"path": item.name, "bytes": item.stat().st_size, "sha256": sha256(item)})
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    archive = out / f"FafEditor-{version}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        for item in sorted(folder.iterdir()):
            zipped.write(item, f"FafEditor-{version}/{item.name}")
    print(f"package: {folder} ({len(manifest['files'])} files), {archive} ({archive.stat().st_size} bytes)")
    return archive


def test(archive: pathlib.Path) -> bool:
    """Unpacks into a folder whose path has spaces and checks every file against the manifest."""
    with tempfile.TemporaryDirectory(prefix="faf editor package test ") as where:
        root = pathlib.Path(where)
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(root)
        folders = [item for item in root.iterdir() if item.is_dir()]
        if len(folders) != 1:
            print("test: the zip should hold one folder")
            return False
        manifest = json.loads((folders[0] / "manifest.json").read_text(encoding="utf-8"))
        bad = 0
        for entry in manifest["files"]:
            item = folders[0] / entry["path"]
            if not item.exists() or item.stat().st_size != entry["bytes"] or sha256(item) != entry["sha256"]:
                print(f"test: {entry['path']} differs from the manifest")
                bad += 1
        if not (folders[0] / "FafEditor_x64.exe").exists():
            print("test: no FafEditor_x64.exe")
            bad += 1
        print(f"test: {len(manifest['files'])} files checked in '{folders[0]}', {bad} wrong")
        return bad == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", required=True, type=pathlib.Path, help="the CMake build folder")
    parser.add_argument("--out", required=True, type=pathlib.Path, help="where the folder and the zip go")
    parser.add_argument("--version", default=datetime.date.today().isoformat())
    parser.add_argument("--test", action="store_true", help="unpack the zip into a path with spaces and check it")
    args = parser.parse_args()
    repo = pathlib.Path(__file__).resolve().parents[2]
    archive = make(args.build.resolve(), args.out.resolve(), args.version, repo)
    if args.test and not test(archive):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
