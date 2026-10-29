"""Game data pack for headless replay parity runs (CI): the game's data cut down to what
headless reads, with every other file kept as an empty file of the same name.

usage: make_pack.py <command> [options]    (see README.md next to this file)

  types <trace>...           what a set of `headless --disk-trace` files touched: per access kind
                             and file type, and the directory listings; the content types
  build --fa DIR --faf DIR --init FILE --out DIR [--vault DIR] [--m28 DIR] [--content EXTS]
                             a whole pack from local data, to play from locally (layout in README.md)
  retail --fa DIR --out DIR  the retail archives alone (fa/gamedata/*.scd), the one part of the
                             CI data that does not come from FAF (prewarm.py game fetches the rest)
  verify --pack DIR --root ORIG=PACK... <trace>...
                             every file the traces read, mapped or opened is in the pack with
                             its content (not an empty stand-in)

Why empty files instead of none: headless never reads a texture, but the session checksum
hashes every blueprint's reflected value, and a mesh blueprint's LOD texture names are filled
only when `<mesh>_albedo.dds` (and the normals, specular and lookup maps) exist
(RMeshBlueprintLOD::Init, 0x00518870). A missing texture changes the checksum at beat 0, so
existence, names and timestamps stay; only the bytes of types headless never reads go.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile

# The types whose bytes headless reads (`types` on the core set's traces). Everything else
# becomes an empty file.
CONTENT_TYPES = {".bp", ".lua", ".scm", ".sca", ".scmap"}

# Retail archives FAF's init file never mounts (allowedAssetsScd false: their content is in
# FAF's own packages, or unused).
UNMOUNTED_SCD = {"schook.scd", "moholua.scd", "mohodata.scd", "lua.scd", "editor.scd", "ambience.scd"}

ARCHIVE_RE = re.compile(r"/([^/]+\.(?:scd|nx2|zip))/(.+)$", re.I)
CONTENT_KINDS = ("read", "map", "open")


def norm(path):
    return path.replace("\\", "/")


def ext_of(name):
    return os.path.splitext(name)[1].lower() or "(none)"


def read_traces(paths):
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                kind, _, rest = line.rstrip("\n").partition(" ")
                yield kind, rest


def cmd_types(args):
    by_kind = {}
    lists = {}
    for kind, path in read_traces(args.traces):
        if kind == "list" or kind == "children":
            lists[f"{kind} {path}"] = lists.get(f"{kind} {path}", 0) + 1
            continue
        if kind in ("listed", "child"):
            continue
        counts = by_kind.setdefault(kind, {})
        e = ext_of(norm(path))
        counts[e] = counts.get(e, 0) + 1
    for kind in sorted(by_kind):
        row = ", ".join(f"{e} {n}" for e, n in sorted(by_kind[kind].items(), key=lambda x: -x[1]))
        print(f"{kind:6} {row}")
    print("listings:")
    for query, n in sorted(lists.items()):
        print(f"  {n:4} {query}")
    content = sorted({e for k in CONTENT_KINDS for e in by_kind.get(k, {})})
    print("content types:", " ".join(content))
    extra = [e for e in content if e not in CONTENT_TYPES and e not in (".scfareplay", ".prefs")]
    if extra:
        print("NOT IN CONTENT_TYPES:", " ".join(extra))
        return 1
    return 0


class Stats:
    def __init__(self):
        self.kept = 0
        self.kept_bytes = 0
        self.emptied = 0
        self.emptied_bytes = 0

    def line(self):
        return (f"{self.kept} files kept ({self.kept_bytes / 1048576:.1f} MB), "
                f"{self.emptied} emptied ({self.emptied_bytes / 1048576:.1f} MB dropped)")


def pack_archive(src, dst, content, stats):
    """Same entries, order, names and times; bytes only for the content types."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for info in zin.infolist():
            out = zipfile.ZipInfo(info.filename, info.date_time)
            out.external_attr = info.external_attr
            out.create_system = info.create_system
            if info.is_dir():
                zout.writestr(out, b"")
            elif ext_of(info.filename) in content:
                out.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(out, zin.read(info), compresslevel=9)
                stats.kept += 1
                stats.kept_bytes += info.file_size
            else:
                out.compress_type = zipfile.ZIP_STORED
                zout.writestr(out, b"")
                stats.emptied += 1
                stats.emptied_bytes += info.file_size


def pack_tree(src, dst, content, stats):
    """A folder of loose files: content types copied, the rest empty, every mtime kept."""
    for root, _dirs, files in os.walk(src):
        out_root = os.path.join(dst, os.path.relpath(root, src))
        os.makedirs(out_root, exist_ok=True)
        for name in files:
            s = os.path.join(root, name)
            d = os.path.join(out_root, name)
            size = os.path.getsize(s)
            if ext_of(name) in content:
                shutil.copy2(s, d)
                stats.kept += 1
                stats.kept_bytes += size
            else:
                open(d, "wb").close()
                shutil.copystat(s, d)
                stats.emptied += 1
                stats.emptied_bytes += size


def game_version(nx2_dir):
    with zipfile.ZipFile(os.path.join(nx2_dir, "lua.nx2")) as z:
        text = z.read("lua/version.lua").decode("utf-8", "replace")
    m = re.search(r'local Version = "(\d+)"', text)
    return m.group(1) if m else None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


VAULT_LINE = "custom_vault_path = InitFileDir .. '/../vault'"
VAULT_ANCHOR = "if custom_vault_path then"


def ci_init(text):
    """FAF's init file (init_faf_<version>.lua, or a copy that sets its own vault) with the vault
    in the pack. The vault has to be set right before `if custom_vault_path then`: the engine
    resets one set earlier."""
    text = text.replace("\r\n", "\n")
    text, n = re.subn(r"^custom_vault_path = .*$", VAULT_LINE, text, flags=re.M)
    if n == 0:
        if text.count("\n" + VAULT_ANCHOR) != 1:
            raise ValueError("init file: expected one '%s' line" % VAULT_ANCHOR)
        text = text.replace("\n" + VAULT_ANCHOR, "\n" + VAULT_LINE + "\n" + VAULT_ANCHOR)
    # A folder of UI hooks for the gui parity runner; headless has no user Lua state.
    return re.sub(r"^MountDirectory\('[^']*parity_ui', '/'\)\n", "", text, flags=re.M)


def write_init(init_text, version, out):
    """bin/init_ci.lua and fa_path.lua (which the FAF client writes next to bin/; the init only
    logs its versions), every path relative to the pack."""
    os.makedirs(os.path.join(out, "bin"), exist_ok=True)
    with open(os.path.join(out, "bin", "init_ci.lua"), "w", encoding="utf-8", newline="\n") as f:
        f.write(ci_init(init_text))
    with open(os.path.join(out, "fa_path.lua"), "w", encoding="utf-8", newline="\n") as f:
        f.write("fa_path = InitFileDir .. '/../fa'\nGameType = \"faf\"\nGameVersion = \"%s\"\n"
                "ClientVersion = \"parity-ci\"\n" % version)


def cmd_retail(args):
    """The retail archives alone, stripped: the one part CI cannot fetch from FAF."""
    content = set(CONTENT_TYPES)
    scd_dir = os.path.join(args.fa, "gamedata")
    total = 0
    for name in sorted(os.listdir(scd_dir)):
        if name.lower().endswith(".scd") and name.lower() not in UNMOUNTED_SCD:
            stats = Stats()
            dst = os.path.join(args.out, "fa", "gamedata", name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            pack_archive(os.path.join(scd_dir, name), dst, content, stats)
            total += os.path.getsize(dst)
            print(f"fa/gamedata/{name:24} {os.path.getsize(dst) / 1048576:8.1f} MB  {stats.line()}")
    print(f"retail archives: {total / 1048576:.1f} MB")
    return 0


def cmd_build(args):
    content = set(CONTENT_TYPES)
    if args.content:
        content = {e if e.startswith(".") else "." + e for e in args.content.lower().split(",")}
    out = args.out
    if os.path.exists(out) and os.listdir(out):
        sys.exit(f"{out} is not empty")
    nx2_dir = os.path.join(args.faf, "gamedata")
    manifest = {"game_version": game_version(nx2_dir), "content_types": sorted(content), "sources": {}}
    print(f"game version {manifest['game_version']}")

    parts = []
    for name in sorted(os.listdir(nx2_dir)):
        if name.lower().endswith(".nx2"):
            parts.append((os.path.join(nx2_dir, name), os.path.join(out, "gamedata", name), "archive"))
    scd_dir = os.path.join(args.fa, "gamedata")
    for name in sorted(os.listdir(scd_dir)):
        if name.lower().endswith(".scd") and name.lower() not in UNMOUNTED_SCD:
            parts.append((os.path.join(scd_dir, name), os.path.join(out, "fa", "gamedata", name), "archive"))
    if os.path.isdir(os.path.join(args.fa, "maps")):
        parts.append((os.path.join(args.fa, "maps"), os.path.join(out, "fa", "maps"), "tree"))
    # Without --vault: the base pack CI unpacks; the maps and M28AI come from its caches.
    os.makedirs(os.path.join(out, "vault", "maps"), exist_ok=True)
    os.makedirs(os.path.join(out, "vault", "mods"), exist_ok=True)
    if args.vault:
        parts.append((os.path.join(args.vault, "maps"), os.path.join(out, "vault", "maps"), "tree"))
    if args.m28:
        parts.append((args.m28, os.path.join(out, "m28"), "tree"))

    for src, dst, kind in parts:
        stats = Stats()
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if kind == "archive":
            pack_archive(src, dst, content, stats)
            manifest["sources"][os.path.relpath(dst, out)] = sha256(src)
            size = os.path.getsize(dst)
        else:
            pack_tree(src, dst, content, stats)
            size = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(dst) for f in fs)
        print(f"{os.path.relpath(dst, out):32} {size / 1048576:8.1f} MB  {stats.line()}")

    with open(args.init, encoding="utf-8") as f:
        write_init(f.read(), manifest["game_version"], out)
    print("bin/init_ci.lua, fa_path.lua written")
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return 0


def find_ignoring_case(base, relative):
    """The engine looks files up without regard to case (X1MP_005 answers x1mp_005); so does this."""
    path = base
    for part in relative.split("/"):
        if not part:
            continue
        try:
            names = {n.lower(): n for n in os.listdir(path)}
        except OSError:
            return None
        if part.lower() not in names:
            return None
        path = os.path.join(path, names[part.lower()])
    return path


def cmd_verify(args):
    content = set(CONTENT_TYPES)
    roots = []
    for spec in args.root:
        orig, _, packed = spec.partition("=")
        roots.append((norm(orig).lower().rstrip("/") + "/", packed))
    archives = {}
    bad = 0
    checked = 0
    for kind, path in read_traces(args.traces):
        if kind not in CONTENT_KINDS:
            continue
        p = norm(path)
        e = ext_of(p)
        if e in (".scfareplay", ".prefs"):
            continue
        checked += 1
        if e not in content:
            print(f"READ OF AN EMPTIED TYPE {kind} {p}")
            bad += 1
            continue
        m = ARCHIVE_RE.search(p)
        if m:
            name, entry = m.group(1).lower(), m.group(2).lower()
            if name not in archives:
                found = [os.path.join(r, f) for r, _, fs in os.walk(args.pack) for f in fs if f.lower() == name]
                archives[name] = ({i.filename.lower(): i for i in zipfile.ZipFile(found[0]).infolist()}
                                  if found else None)
            entries = archives[name]
            if entries is None or entry not in entries:
                print(f"MISSING {kind} {name}/{entry}")
                bad += 1
            continue
        for orig, packed in roots:
            if p.lower().startswith(orig):
                target = find_ignoring_case(os.path.join(args.pack, packed), p[len(orig):])
                if target is None or not os.path.isfile(target):
                    print(f"MISSING {kind} {p}")
                    bad += 1
                break
    print(f"verify: {checked} reads checked, {bad} problems")
    return 1 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("types")
    p.add_argument("traces", nargs="+")
    p = sub.add_parser("build")
    p.add_argument("--fa", required=True, help="the game's install folder (gamedata/*.scd, maps)")
    p.add_argument("--faf", required=True, help="FAF's data folder (gamedata/*.nx2) for the game version")
    p.add_argument("--vault", help="vault folder with the replays' maps (maps/); left out for CI's base pack")
    p.add_argument("--init", required=True, help="FAF's init file (bin/init_faf.lua) for the game version")
    p.add_argument("--m28", help="folder of M28AI versions (m28ai.vNNNN/m28ai)")
    p.add_argument("--content", help="comma-separated types to keep the bytes of (default: CONTENT_TYPES)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("retail")
    p.add_argument("--fa", required=True, help="the game's install folder (gamedata/*.scd)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("verify")
    p.add_argument("--pack", required=True)
    p.add_argument("--root", action="append", default=[], help="ORIG=PACK: a loose-file folder and its pack folder")
    p.add_argument("traces", nargs="+")
    args = parser.parse_args()
    return {"types": cmd_types, "build": cmd_build, "retail": cmd_retail, "verify": cmd_verify}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
