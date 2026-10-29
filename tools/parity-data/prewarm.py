"""Fills the CI parity caches from FAF, a little at a time and only with what is missing.

usage: prewarm.py <command> [options]    (see README.md next to this file)

  replays --corpus FILE --bucket B --cache DIR [--minutes M]
                             the corpus replays of id bucket B (ids B*10000 .. B*10000+9999):
                             downloads each one the cache lacks, checks it as the parity runner
                             does (featured mod, engine version, sim mods, map) and records the
                             result in DIR/index.jsonl; keeps the .fafreplay of ready ones
  assets --corpus FILE --index DIR --maps DIR --m28 DIR [--index-out FILE] [--minutes M]
                             the cached maps (the corpus' top and retail maps, from FAF's map
                             vault; stripped as make_pack.py does), every M28AI version a ready
                             replay needs, and all buckets' index entries in one file
  game --game-version V --out DIR
                             FAF's game files for version V (its packages and init file, from
                             FAF's updater), stripped: DIR/gamedata/*.nx2, DIR/bin/init_ci.lua,
                             DIR/fa_path.lua; the retail archives are the one part not from FAF

One request at a time, --delay seconds apart (default 1). Each command stops after --minutes and
prints `count=N`, the number of entries it holds, for the cache key; a later run carries on.
"""
import argparse
import glob
import json
import os
import shutil
import sys
import tempfile
import time

import urllib.error

import make_pack
from common import (GAME_URL, MAP_URL, MOD_URL, REPLAY_URL, bucket_of, check_replay, extract_map, fetch,
                    find_mod_info, read_corpus)

# FAF's packages the init file mounts (allowedAssetsNxy in init_faf.lua). Not every version
# publishes every one: 3835 has no mods package.
FAF_PACKAGES = ("effects", "env", "etc", "loc", "lua", "meshes", "mods", "projectiles", "textures", "units")
REQUIRED_PACKAGES = {"lua", "units"}


def read_index(path):
    entries = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    e = json.loads(line)
                    entries[e["id"]] = e
    return entries


def write_output(**values):
    for key, value in values.items():
        print("%s=%s" % (key, value))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            for key, value in values.items():
                f.write("%s=%s\n" % (key, value))


def cmd_replays(args):
    corpus = read_corpus(args.corpus)
    ids = sorted(i for i in corpus if bucket_of(i) == args.bucket)
    os.makedirs(args.cache, exist_ok=True)
    index_path = os.path.join(args.cache, "index.jsonl")
    index = read_index(index_path)
    todo = [i for i in ids if i not in index]
    # Replays already on disk first: they cost no request, and a slow network cannot keep them out.
    todo.sort(key=lambda i: not os.path.isfile(os.path.join(args.cache, "%d.fafreplay" % i)))
    deadline = time.time() + args.minutes * 60
    done = 0
    with open(index_path, "a", encoding="utf-8") as out:
        for replay_id in todo:
            if time.time() > deadline:
                break
            path = os.path.join(args.cache, "%d.fafreplay" % replay_id)
            entry = {"id": replay_id, "state": "unsupported", "reason": None, "map": None, "m28": None,
                     "beats": None, "players": corpus[replay_id]["players"]}
            try:
                if not os.path.isfile(path):
                    fetch(REPLAY_URL % replay_id, path, args.delay)
                with open(path, "rb") as f:
                    info, reason, _ = check_replay(f.read(), args.game_version)
                entry.update({k: info.get(k) for k in ("map", "m28", "beats")})
                entry["state"], entry["reason"] = ("ready", None) if reason is None else ("unsupported", reason)
            except Exception as exc:
                entry["reason"] = "download: %s" % str(exc)[:80]
                if "HTTP Error 404" not in entry["reason"]:
                    continue  # a passing network problem: not recorded, tried again next run
            if entry["state"] != "ready" and os.path.exists(path):
                os.remove(path)
            out.write(json.dumps(entry) + "\n")
            out.flush()
            done += 1
    index = read_index(index_path)
    ready = sum(1 for e in index.values() if e["state"] == "ready")
    print("bucket %d: %d of %d corpus replays indexed (%d ready), %d new this run, %d left"
          % (args.bucket, len(index), len(ids), ready, done, len(ids) - len(index)))
    write_output(count=len(index), left=len(ids) - len(index))
    return 0


def cmd_assets(args):
    corpus = read_corpus(args.corpus)
    index = {}
    for path in glob.glob(os.path.join(args.index, "**", "index.jsonl"), recursive=True):
        index.update(read_index(path))
    deadline = time.time() + args.minutes * 60
    os.makedirs(args.maps, exist_ok=True)
    os.makedirs(args.m28, exist_ok=True)
    work = tempfile.mkdtemp(prefix="prewarm-")
    content = set(make_pack.CONTENT_TYPES)
    try:
        versions = sorted({e["m28"] for e in index.values() if e["state"] == "ready" and e.get("m28")})
        for version in versions:
            tag = "m28ai.v%04d" % version
            if find_mod_info(os.path.join(args.m28, tag)) or time.time() > deadline:
                continue
            zpath = os.path.join(work, tag + ".zip")
            fetch(MOD_URL % tag, zpath, args.delay)
            shutil.unpack_archive(zpath, os.path.join(args.m28, tag), "zip")
            print("M28AI v%d" % version, flush=True)

        # The retail maps come from FAF's map vault too: their .scmap and Lua are the game's
        # (x1mp_005, scmp_009 compared file for file); FAF adds previews.
        cached = {row["map"] for row in corpus.values() if row["map_kind"] in ("cached", "retail")}
        have = {n.lower() for n in os.listdir(args.maps)}
        wanted = sorted(cached - have)
        failed = 0
        for folder in wanted:
            if time.time() > deadline:
                break
            zpath = os.path.join(work, "map.zip")
            raw = os.path.join(work, "raw")
            shutil.rmtree(raw, ignore_errors=True)
            try:
                fetch(MAP_URL % folder, zpath, args.delay)
                src = extract_map(zpath, raw, folder)
            except Exception as exc:
                print("map %s: %s" % (folder, str(exc)[:80]), flush=True)
                failed += 1
                continue
            stats = make_pack.Stats()
            make_pack.pack_tree(src, os.path.join(args.maps, folder), content, stats)
        maps_now = len(os.listdir(args.maps))
        print("maps cached: %d of %d top and retail maps (%d failed this run); M28AI versions: %d"
              % (maps_now, len(cached), failed, len(os.listdir(args.m28))))
        if args.index_out:
            os.makedirs(os.path.dirname(os.path.abspath(args.index_out)), exist_ok=True)
            with open(args.index_out, "w", encoding="utf-8") as f:
                for replay_id in sorted(index):
                    f.write(json.dumps(index[replay_id]) + "\n")
        write_output(maps=maps_now, m28=len(os.listdir(args.m28)), indexed=len(index))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


def cmd_game(args):
    version = args.game_version
    manifest_path = os.path.join(args.out, "manifest.json")
    if os.path.isfile(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            if json.load(f).get("game_version") == str(version):
                print("game files %d already here" % version)
                return 0
    work = tempfile.mkdtemp(prefix="game-")
    content = set(make_pack.CONTENT_TYPES)
    manifest = {"game_version": str(version), "content_types": sorted(content), "sources": {}}
    try:
        for name in FAF_PACKAGES:
            remote = "%s.%d.nx2" % (name, version)
            src = os.path.join(work, remote)
            try:
                fetch(GAME_URL % remote, src, args.delay)
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and name not in REQUIRED_PACKAGES:
                    print("%-28s not published for %d" % (remote, version))
                    continue
                raise
            dst = os.path.join(args.out, "gamedata", name + ".nx2")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            stats = make_pack.Stats()
            make_pack.pack_archive(src, dst, content, stats)
            manifest["sources"][remote] = make_pack.sha256(src)
            print("%-28s %7.1f MB -> %6.1f MB  %s" % (remote, os.path.getsize(src) / 1048576,
                                                       os.path.getsize(dst) / 1048576, stats.line()), flush=True)
            os.remove(src)
        found = make_pack.game_version(os.path.join(args.out, "gamedata"))
        if found != str(version):
            sys.exit("lua.%d.nx2 says game version %s" % (version, found))
        init_name = "init_faf_%d.lua" % version
        fetch(GAME_URL % init_name, os.path.join(work, init_name), args.delay)
        with open(os.path.join(work, init_name), encoding="utf-8") as f:
            make_pack.write_init(f.read(), version, args.out)
        manifest["sources"][init_name] = make_pack.sha256(os.path.join(work, init_name))
        for sub in ("vault/maps", "vault/mods", "fa/gamedata"):
            os.makedirs(os.path.join(args.out, sub), exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print("game files %d ready in %s" % (version, args.out))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("game")
    p.add_argument("--game-version", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--delay", type=float, default=1.0, help="seconds between requests to FAF")
    for name in ("replays", "assets"):
        p = sub.add_parser(name)
        p.add_argument("--corpus", required=True)
        p.add_argument("--minutes", type=float, default=30)
        p.add_argument("--delay", type=float, default=1.0, help="seconds between requests to FAF")
        if name == "replays":
            p.add_argument("--bucket", type=int, required=True)
            p.add_argument("--cache", required=True)
            p.add_argument("--game-version", type=int, default=3835)
        else:
            p.add_argument("--index", required=True, help="folder holding the buckets' index.jsonl files")
            p.add_argument("--maps", required=True)
            p.add_argument("--m28", required=True)
            p.add_argument("--index-out", help="write every bucket's index entries to this one file")
    args = parser.parse_args()
    return {"replays": cmd_replays, "assets": cmd_assets, "game": cmd_game}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
