"""Background replay parity runner: plays FAF vault replays on a rebuilt engine and records
whether every checksum the live players recorded matches.

usage: parity.py [<command> [options]]    (see README.md next to this file)

  console [-n INSTANCES]     live view with key controls (the default command): runs the games
                             itself, or attaches to a background runner
  init                       create tmp/parity, the config and the control file
  import [DIR...]            add .fafreplay files (default: the replay_20261013 downloads)
  fetch [-n COUNT]           read vault headers at random ids, download COUNT new replays
  start [-n INSTANCES]       start the runner in the background
  instances N                change how many games run at once (takes effect within seconds)
  pause / resume             suspend every running game and stop launching / continue
  stop [--now]               finish the running games and exit / kill them and exit now
  status [-v]                pool, per-build results, running games, desyncs
  mode [gui|headless]        show or switch what plays the replays (takes effect for new games)
  run                        the runner itself, in the foreground

Data lives in tmp/parity (FAF_PARITY_DATA overrides): parity.sqlite (pool and results),
results.txt (one line per finished game), desyncs/<build>/, crashes/<build>/, logs/<build>/.
The runner reads control.json every second, so `instances`, `pause` and `stop` only edit it.

Two modes; each tests its own exe, so their results are separate builds.

Mode "headless" (the default): headless_x64.exe --replay <id>.scfareplay /init init_parity*.lua
... (docs/SWITCHES.md, "headless"): the simulation alone, flat out, with no window or console;
its progress and verdict are read from its output.

Mode "gui": <exe> /init init_parity*.lua /replay <id>.scfareplay ... The init file is generated
next to the exe from its init_faf.lua; it mounts the parity vault (downloaded maps), the
M28AI version the replay was recorded with, and tools/replay-parity/hook, which runs the sim
with wld_RunWithTheWind 1 at WLD_GameSpeed 50, parks the camera zoomed in at the map centre and logs a heartbeat.
The game starts minimized (STARTUPINFO show state) and, in window_mode "hidden", loses its
taskbar button: a minimized window keeps the sim running but skips rendering (CScApp::OnFrame).

Verdicts: pass (no mismatch, played to the end), desync (first mismatched beat recorded,
replay and log saved, game killed), incomplete (no mismatch, but the replay stopped well
before its recorded length), crash, timeout, aborted (stopped by the user; queued again).
"""
import argparse
import ctypes
import csv
import ctypes.wintypes as wt
import datetime
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile

try:
    from compression import zstd as _zstd  # Python 3.14+

    def zstd_decompress(blob):
        return _zstd.decompress(blob)
except ImportError:  # pragma: no cover - older Pythons with the zstandard package
    import zstandard as _zstandard

    def zstd_decompress(blob):
        return _zstandard.ZstdDecompressor().decompressobj().decompress(blob)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DATA = os.environ.get("FAF_PARITY_DATA") or os.path.join(REPO, "tmp", "parity")
DB_PATH = os.path.join(DATA, "parity.sqlite")
CONFIG_PATH = os.path.join(DATA, "config.json")
CONTROL_PATH = os.path.join(DATA, "control.json")
STATE_PATH = os.path.join(DATA, "state.json")
PID_PATH = os.path.join(DATA, "runner.pid")
HOOK_DIR = os.path.join(HERE, "hook")
FAF_DIR = "C:/ProgramData/FAForever"
LEGACY_RUN = os.path.join(REPO, "tools", "runs", "replay_20261013")
LEGACY_VAULT = os.path.join(REPO, "tmp", "Supreme Commander Forged Alliance")
UA = {"User-Agent": "faf-re-replay-parity/1.0"}

# docs/PR_REPLAY_CHECK.md: core set first, extended set next, everything else after.
CORE_SET = [26902315, 26930624, 26943656, 26883423, 26881085, 26928211, 26989770, 26897073]
EXTENDED_SET = [26975290, 26953273, 27034831, 26917867, 26876279, 26935800, 26898759,
                27004084, 26915859, 26905122]

DEFAULT_CONFIG = {
    # What plays the replays: "headless", the console replay player (headless_x64.exe: the
    # simulation alone, no window, rendering or audio, flat out), or "gui", the game
    # (main_x64.exe, hidden as window_mode says), which tests the client as players run it.
    # `parity.py mode` and the console's `m` key switch it.
    "mode": "headless",
    # Built exe to test in each mode. The runner snapshots it (copy next to it, named by content
    # hash) and follows rebuilds: once the file changes and has been stable for a minute, new
    # games use the new build and the whole pool is queued again for it.
    "exe": FAF_DIR + "/bin_x64/main_x64.exe",
    "headless_exe": FAF_DIR + "/bin_x64/headless_x64.exe",
    "follow_exe": True,
    "args": ["/simworkers", "8"],
    "headless_args": ["/simworkers", "8"],
    "window": [1024, 576],
    # hidden: minimized from the first frame and its taskbar button removed, so nothing shows;
    # minimized: the same with the taskbar button; normal: visible, for watching a game.
    # Minimized windows run the sim without rendering (CScApp frame loop). A desktop of its
    # own (CreateDesktop) would hide more, but the sandboxed account's children cannot
    # initialise on one (0xC0000142).
    "window_mode": "hidden",
    # Seconds without a new beat (counting only time the game was not suspended) after which
    # the replay is taken as finished.
    "stall_seconds": 45,
    "startup_seconds": 240,
    "max_wall_minutes": 120,
    # Pool filter: featured mod "faf" on this game version (the local gamedata's), at least
    # this long. Replays needing a sim mod other than M28AI are marked unsupported.
    "game_version": None,
    "min_minutes": 5,
    # fetch takes only games with at least this many players (the header's num_players counts
    # the people, not AI armies); 1-player games already in the pool play last.
    "min_players": 2,
    # Game version 3835 era of the vault: 3835 seen up to 27,051,951, 3836 from 27,070,013.
    "scan_range": [26860000, 27065000],
    "request_delay": 0.25,
    # When every ready replay has a result for the current build, fetch this many new ones
    # (0: wait for a new build instead). The console's `a` key turns it off and on.
    "auto_fetch": 10,
    "extra_map_dirs": [LEGACY_VAULT + "/maps"],
    "launch_gap_seconds": 8,
}
# auto_fetch: when every ready replay has a result for the current build, fetch config
# "auto_fetch" (10) more for the game version the exe plays, and keep going.
DEFAULT_CONTROL = {"instances": 4, "paused": False, "stop": False, "stop_now": False, "auto_fetch": True}

FINAL_VERDICTS = ("pass", "desync", "incomplete", "crash", "timeout")

# ---------------------------------------------------------------------------------- files


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_json(path, default):
    # The runner and a console (possibly under another account) share these files. Windows
    # refuses a read while another process replaces the file, so retry before falling back:
    # a control.json read as the defaults would silently undo a pause or a stop.
    for attempt in range(20):
        try:
            with open(path, encoding="utf-8-sig") as f:  # PowerShell 5.1 writes a BOM
                return {**default, **json.load(f)}
        except FileNotFoundError:
            return dict(default)
        except (OSError, ValueError):
            time.sleep(0.05)
    return dict(default)


def write_json(path, value):
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2)
    for attempt in range(40):
        try:
            os.replace(tmp, path)  # refused while another process has the file open
            return
        except PermissionError:
            time.sleep(0.05)
    os.replace(tmp, path)


def fa_path_values():
    try:
        text = open(FAF_DIR + "/fa_path.lua", encoding="latin1").read()
    except OSError:
        return {}
    return dict(re.findall(r'^(\w+)\s*=\s*"([^"]*)"', text, re.M))


def load_config():
    cfg = read_json(CONFIG_PATH, DEFAULT_CONFIG)
    if not cfg.get("game_version"):
        cfg["game_version"] = int(fa_path_values().get("GameVersion", "3835"))
    if cfg.get("mode") not in MODES:
        cfg["mode"] = DEFAULT_CONFIG["mode"]
    return cfg


MODES = ("gui", "headless")


def mode_exe(cfg):
    """The exe the configured mode tests."""
    return cfg["headless_exe"] if cfg["mode"] == "headless" else cfg["exe"]


def set_mode(mode):
    """Write the mode into config.json, keeping the rest of the file as the user left it."""
    raw = read_json(CONFIG_PATH, {})
    raw["mode"] = mode
    write_json(CONFIG_PATH, raw)
    return mode


def mode_of_exe(path):
    return "headless" if "headless" in os.path.basename(path or "").lower() else "gui"


def update_control(**changes):
    ctl = read_json(CONTROL_PATH, DEFAULT_CONTROL)
    ctl.update(changes)
    write_json(CONTROL_PATH, ctl)
    return ctl


def db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS replays (
            id INTEGER PRIMARY KEY, version INTEGER, mod TEXT, players INTEGER, minutes REAL,
            map TEXT, m28 INTEGER, state TEXT, reason TEXT, priority INTEGER, added TEXT);
        CREATE TABLE IF NOT EXISTS runs (
            replay INTEGER, build TEXT, started TEXT, finished TEXT, verdict TEXT,
            first_beat INTEGER, mismatches INTEGER, last_tick INTEGER, last_time REAL,
            expect REAL, wall REAL, log TEXT, note TEXT);
        CREATE TABLE IF NOT EXISTS builds (
            build TEXT PRIMARY KEY, exe TEXT, source TEXT, git TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS scanned (id INTEGER PRIMARY KEY, result TEXT);
        CREATE INDEX IF NOT EXISTS runs_build ON runs(build, replay);
    """)
    if "beats" not in {r[1] for r in conn.execute("PRAGMA table_info(replays)")}:
        conn.execute("ALTER TABLE replays ADD COLUMN beats INTEGER")
        conn.commit()
    return conn


def fill_beats(conn):
    """Game length for ready replays prepared before it was recorded."""
    for (replay_id,) in conn.execute("SELECT id FROM replays WHERE state='ready' AND beats IS NULL").fetchall():
        try:
            beats = replay_beats(open(pool_path(replay_id, "scfareplay"), "rb").read())
        except (OSError, ValueError, IndexError):
            continue
        conn.execute("UPDATE replays SET beats=? WHERE id=?", (beats, replay_id))
    conn.commit()


def pool_path(replay_id, ext):
    return os.path.join(DATA, "pool", "%d.%s" % (replay_id, ext))

# ------------------------------------------------------------------------- replay content


def decode_fafreplay(raw):
    """.fafreplay = one JSON header line, then base64(BE length + zlib) or a raw zstd frame."""
    import base64
    import zlib
    newline = raw.index(b"\n")
    header = json.loads(raw[:newline])
    body = raw[newline + 1:]
    if header.get("compression") == "zstd" or body[:4] == b"\x28\xb5\x2f\xfd":
        return header, zstd_decompress(body)
    blob = base64.b64decode(body)
    data = zlib.decompress(blob[4:])
    if len(data) != struct.unpack(">I", blob[:4])[0]:
        raise ValueError("zlib body length mismatch")
    return header, data


def header_summary(header):
    versions = [v for v in (header.get("featured_mod_versions") or {}).values() if isinstance(v, int)]
    minutes = None
    if header.get("game_end") and header.get("launched_at"):
        minutes = round((header["game_end"] - header["launched_at"]) / 60.0, 1)
    return {
        "version": max(versions) if versions else None,
        "mod": header.get("featured_mod"),
        "players": header.get("num_players"),
        "minutes": minutes,
        "complete": header.get("complete"),
    }


def lua_value(buf, pos):
    """One value of the engine's Lua serialization (replay header tables)."""
    kind = buf[pos]
    pos += 1
    if kind == 0:
        return struct.unpack_from("<f", buf, pos)[0], pos + 4
    if kind == 1:
        end = buf.index(0, pos)
        return buf[pos:end].decode("latin1"), end + 1
    if kind == 2:
        return None, pos
    if kind == 3:
        return buf[pos] != 0, pos + 1
    if kind == 4:
        table = {}
        while buf[pos] != 5:
            key, pos = lua_value(buf, pos)
            value, pos = lua_value(buf, pos)
            table[key] = value
        return table, pos + 1
    raise ValueError("unknown Lua value tag %d at %d" % (kind, pos - 1))


def replay_stream(data):
    """Reads the header as VCR_SetupReplaySession does: returns the command source (client)
    names and the offset where the command stream starts."""
    def cstring(pos):
        return data.index(0, pos) + 1

    pos = cstring(cstring(0)) + 13              # engine version, "\r\n", "Replay v1.9\r\n"
    pos = cstring(cstring(pos))                  # map path, "\r\n\x1a"
    for _ in range(2):                           # sim mods, scenario info
        pos += 4 + struct.unpack_from("<i", data, pos)[0]
    sources = data[pos]
    pos += 1
    names = []
    for _ in range(sources):
        end = cstring(pos)
        names.append(data[pos:end - 1].decode("latin1"))
        pos = end + 4                            # name, timeouts
    armies = data[pos + 1]                       # after the cheats flag
    pos += 2
    for _ in range(armies):
        pos += 4 + struct.unpack_from("<i", data, pos)[0]
        pos = data.index(0xFF, pos) + 1          # unit sources, 0xFF-terminated
    return names, pos + 4                        # random seed


def stream_messages(data, pos):
    """Command stream messages: [type u8][total size u16 LE][payload], as (type, payload)."""
    while pos + 3 <= len(data):
        size = data[pos + 1] | data[pos + 2] << 8
        if size < 3:
            raise ValueError("bad message size at %d" % pos)
        yield data[pos], data[pos + 3:pos + size]
        pos += size
    if pos != len(data):
        raise ValueError("command stream ends mid-message")


def replay_beats(data):
    """Game length in beats (10 per game second): the sum of the CMDST_Advance beat counts."""
    _, pos = replay_stream(data)
    return sum(struct.unpack_from("<i", body)[0] for kind, body in stream_messages(data, pos) if kind == 0)


def replay_checksums(data):
    """Every checksum the live clients recorded: {beat: {md5 hex: [client names]}}.
    CMDST_SetCommandSource (1) names the sender, CMDST_VerifyChecksum (3) carries MD5 + beat."""
    names, pos = replay_stream(data)
    source = None
    beats = {}
    for kind, body in stream_messages(data, pos):
        if kind == 1:
            source = body[0]
        elif kind == 3:
            beat = struct.unpack_from("<i", body, 16)[0]
            name = names[source] if source is not None and source < len(names) else str(source)
            beats.setdefault(beat, {}).setdefault(body[:16].hex(), []).append(name)
    return beats


def replay_body_info(data):
    """Engine version string, map folder and sim mods of a decoded .scfareplay body."""
    version = data[:data.index(b"\0")].decode("latin1")
    m = re.search(rb"Replay v[\d.]+\r\n([^\0]*)\0", data[:8192])
    if not m:
        raise ValueError("no replay map line")
    scmap = m.group(1).decode("latin1")
    folder = re.match(r"/maps/([^/]+)/", scmap, re.I)
    pos = m.end()
    if data[pos:pos + 4] != b"\r\n\x1a\0":
        raise ValueError("unexpected bytes after the map line")
    size = struct.unpack_from("<i", data, pos + 4)[0]
    mods, _ = lua_value(data, pos + 8)
    if not isinstance(mods, dict):
        raise ValueError("sim mod table missing (%d bytes)" % size)
    mod_list = [{"name": str(v.get("name")), "uid": str(v.get("uid")), "version": v.get("version")}
                for v in mods.values() if isinstance(v, dict)]
    return {"version": version, "scmap": scmap, "map": folder.group(1).lower() if folder else None,
            "mods": mod_list}

# --------------------------------------------------------------------------------- network


def http_get(url, headers=None, timeout=60):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


FETCH_PATH = os.path.join(DATA, "fetch.json")


class FetchProgress:
    """What the running fetch is doing, kept in fetch.json so a console in another process
    can draw it. Written at most every 0.3 s unless forced."""

    def __init__(self, target):
        self.state = {"active": True, "target": target, "ready": 0, "headers": 0, "candidates": 0,
                      "requests": 0, "skips": {}, "phase": "starting", "file": "", "bytes": 0,
                      "total": 0, "recent": [], "started_ts": time.time(), "updated_ts": 0.0}
        self.written = 0.0

    def set(self, force=False, **changes):
        self.state.update(changes)
        self.state["updated_ts"] = time.time()
        if force or time.time() - self.written > 0.3:
            self.written = time.time()
            try:
                write_json(FETCH_PATH, self.state)
            except OSError:
                pass

    def skip(self, why):
        self.state["skips"][why] = self.state["skips"].get(why, 0) + 1

    def outcome(self, text):
        self.state["recent"] = (self.state["recent"] + [text])[-4:]
        self.set(force=True)


# The fetch in progress in this process, if any: download() reports its bytes there.
fetch_progress = None


def fetch_running():
    """True while some process is fetching (its fetch.json is active and fresh)."""
    state = read_json(FETCH_PATH, {})
    return bool(state.get("active")) and time.time() - state.get("updated_ts", 0) < 60


def download(url, dest, label=None):
    req = urllib.request.Request(url, headers=UA)
    tmp = dest + ".part"
    got = 0
    with urllib.request.urlopen(req, timeout=300) as resp, open(tmp, "wb") as f:
        total = int(resp.headers.get("Content-Length") or 0)
        if fetch_progress:
            fetch_progress.set(force=True, phase="downloading", file=label or os.path.basename(dest),
                               bytes=0, total=total)
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)
            if fetch_progress:
                fetch_progress.set(bytes=got)
    os.replace(tmp, dest)
    if fetch_progress:
        fetch_progress.set(requests=fetch_progress.state["requests"] + 1, bytes=got, total=got)
    return got


def map_dirs(cfg):
    dirs = [os.path.join(DATA, "vault", "maps")]
    dirs += [d for d in cfg.get("extra_map_dirs") or [] if os.path.isdir(d)]
    fa = fa_path_values().get("fa_path")
    if fa:
        dirs.append(os.path.join(fa, "maps"))
    return dirs


def known_maps(cfg):
    names = set()
    for d in map_dirs(cfg):
        try:
            names.update(n.lower() for n in os.listdir(d))
        except OSError:
            pass
    return names


def ensure_map(folder, cfg, maps):
    """True when the map folder is available; downloads it into the parity vault if not."""
    if folder in maps:
        return True, None
    vault_maps = os.path.join(DATA, "vault", "maps")
    zpath = os.path.join(DATA, "cache", "%s.zip" % folder)
    try:
        if not os.path.isfile(zpath):
            download("https://content.faforever.com/maps/%s.zip" % urllib.parse.quote(folder), zpath,
                     "map %s" % folder)
            time.sleep(cfg["request_delay"])
    except urllib.error.HTTPError as exc:
        return False, "map %s: HTTP %d" % (folder, exc.code)
    except Exception as exc:
        return False, "map %s: %s" % (folder, exc)
    with zipfile.ZipFile(zpath) as z:
        tops = {n.split("/")[0] for n in z.namelist() if n.strip("/")}
        z.extractall(vault_maps)
    if folder not in {t.lower() for t in tops} and len(tops) == 1:
        os.rename(os.path.join(vault_maps, tops.pop()), os.path.join(vault_maps, folder))
    maps.add(folder)
    return True, None


def m28_dir(version, cfg, fetch=True):
    """Folder holding mod_info.lua of M28AI <version>, downloaded on first use."""
    tag = "m28ai.v%04d" % version
    for root in (os.path.join(DATA, "mods", tag), os.path.join(LEGACY_RUN, "modcache", tag)):
        for dirpath, _, files in os.walk(root):
            if "mod_info.lua" in files:
                return dirpath.replace("\\", "/")
    if not fetch:
        return None
    zpath = os.path.join(DATA, "cache", tag + ".zip")
    if not os.path.isfile(zpath):
        download("https://content.faforever.com/mods/%s.zip" % tag, zpath, "M28AI v%d" % version)
        time.sleep(cfg["request_delay"])
    with zipfile.ZipFile(zpath) as z:
        z.extractall(os.path.join(DATA, "mods", tag))
    return m28_dir(version, cfg, fetch=False)

# -------------------------------------------------------------------------------- the pool


def priority_of(replay_id):
    if replay_id in CORE_SET:
        return 0
    if replay_id in EXTENDED_SET:
        return 1
    return 2


def prepare(conn, replay_id, cfg, maps):
    """Convert one pooled .fafreplay, check its version, mods and map; mark it ready or not."""
    raw = open(pool_path(replay_id, "fafreplay"), "rb").read()
    reason = None
    info = {"map": None, "m28": None}
    try:
        header, data = decode_fafreplay(raw)
        summary = header_summary(header)
        body = replay_body_info(data)
        info["map"] = body["map"]
        if summary["mod"] != "faf":
            reason = "featured mod %s" % summary["mod"]
        elif body["version"] != "Supreme Commander v1.50.%d" % cfg["game_version"]:
            reason = "engine version %s" % body["version"]
        elif summary["minutes"] is not None and summary["minutes"] < cfg["min_minutes"]:
            reason = "short (%.1f min)" % summary["minutes"]
        else:
            for mod in body["mods"]:
                if mod["name"].lower() == "m28ai" and isinstance(mod["version"], float):
                    info["m28"] = int(mod["version"])
                    try:
                        if not m28_dir(info["m28"], cfg):
                            reason = "M28AI v%d not found" % info["m28"]
                    except Exception as exc:
                        reason = "M28AI v%d: %s" % (info["m28"], exc)
                else:
                    reason = "sim mod %s" % mod["name"]
            if reason is None and not body["map"]:
                reason = "map path %s" % body["scmap"]
            if reason is None:
                ok, why = ensure_map(body["map"], cfg, maps)
                if not ok:
                    reason = why
        if reason is None:
            with open(pool_path(replay_id, "scfareplay"), "wb") as f:
                f.write(data)
            try:
                info["beats"] = replay_beats(data)
            except (ValueError, IndexError):
                pass  # the engine is the judge of a damaged stream; only the length is unknown
    except Exception as exc:
        summary = {"version": None, "mod": None, "players": None, "minutes": None}
        reason = "unreadable: %s" % exc
    conn.execute(
        "INSERT OR REPLACE INTO replays (id, version, mod, players, minutes, map, m28, state, reason, "
        "priority, added, beats) VALUES (?,?,?,?,?,?,?,?,?,?,COALESCE((SELECT added FROM replays WHERE id=?),?),?)",
        (replay_id, summary["version"], summary["mod"], summary["players"], summary["minutes"],
         info["map"], info["m28"], "unsupported" if reason else "ready", reason,
         priority_of(replay_id), replay_id, now(), info.get("beats")))
    conn.commit()
    return reason


def cmd_init(args):
    for sub in ("pool", "vault/maps", "vault/mods", "mods", "cache", "logs", "desyncs", "crashes"):
        os.makedirs(os.path.join(DATA, sub), exist_ok=True)
    if not os.path.isfile(CONFIG_PATH):
        write_json(CONFIG_PATH, DEFAULT_CONFIG)
    if not os.path.isfile(CONTROL_PATH):
        write_json(CONTROL_PATH, DEFAULT_CONTROL)
    db().close()
    print("data:", DATA)
    print("config:", CONFIG_PATH, "(edit freely; read at each launch)")


def cmd_import(args):
    cmd_init(args)
    cfg = load_config()
    conn = db()
    have = {r[0] for r in conn.execute("SELECT id FROM replays")}
    sources = args.dirs or [os.path.join(LEGACY_RUN, "dl"), LEGACY_RUN]
    maps = known_maps(cfg)
    added = ready = 0
    for d in sources:
        for name in sorted(os.listdir(d)):
            m = re.fullmatch(r"(\d+)\.fafreplay", name)
            if not m or int(m.group(1)) in have:
                continue
            replay_id = int(m.group(1))
            shutil.copyfile(os.path.join(d, name), pool_path(replay_id, "fafreplay"))
            have.add(replay_id)
            added += 1
            reason = prepare(conn, replay_id, cfg, maps)
            ready += reason is None
            print("%d %s" % (replay_id, reason or "ready"), flush=True)
    print("imported %d, ready %d" % (added, ready))


def cmd_retry(args):
    """Prepare again the replays that failed on a map or M28AI download."""
    cfg = load_config()
    conn = db()
    maps = known_maps(cfg)
    rows = conn.execute("SELECT id FROM replays WHERE state='unsupported' AND (reason LIKE 'map %' "
                        "OR reason LIKE 'M28AI%' OR reason LIKE 'unreadable%')").fetchall()
    for (replay_id,) in rows:
        print("%d %s" % (replay_id, prepare(conn, replay_id, cfg, maps) or "ready"), flush=True)


def vault_header(replay_id):
    blob = http_get("https://replay.faforever.com/%d" % replay_id, {"Range": "bytes=0-4095"}, timeout=30)
    return json.loads(blob[:blob.index(b"\n")])


def fetch_new(conn, cfg, count, log=print, stop=lambda: False):
    """Read vault headers at random unscanned ids until `count` new replays are ready."""
    global fetch_progress
    lo, hi = cfg["scan_range"]
    scanned = {r[0] for r in conn.execute("SELECT id FROM scanned")}
    scanned |= {r[0] for r in conn.execute("SELECT id FROM replays")}
    maps = known_maps(cfg)
    rng = random.Random()
    got = 0
    progress = fetch_progress = FetchProgress(count)
    progress.set(force=True, phase="searching")
    # About one header in five qualifies; a run far past that means the range is used up.
    budget = max(200, count * 40)
    try:
        while got < count and not stop():
            if progress.state["headers"] >= budget or len(scanned) > hi - lo:
                log("fetch: gave up after %d headers; widen scan_range or check game_version"
                    % progress.state["headers"])
                progress.outcome("gave up after %d headers" % progress.state["headers"])
                break
            replay_id = rng.randint(lo, hi)
            if replay_id in scanned:
                continue
            scanned.add(replay_id)
            progress.set(phase="searching", file="", headers=progress.state["headers"] + 1,
                         requests=progress.state["requests"] + 1)
            try:
                summary = header_summary(vault_header(replay_id))
                if summary["mod"] != "faf":
                    why = summary["mod"] or "no mod"
                elif summary["version"] != cfg["game_version"]:
                    why = "v%s" % summary["version"]
                elif summary["complete"] is False:
                    why = "incomplete"
                elif (summary["minutes"] or 0) < cfg["min_minutes"]:
                    why = "short"
                elif (summary["players"] or 0) < cfg["min_players"]:
                    why = "%s player" % summary["players"]
                else:
                    why = None
                result = why or "candidate"
            except urllib.error.HTTPError as exc:
                why = result = "HTTP %d" % exc.code
            except Exception as exc:
                why, result = "error", "error %s" % str(exc)[:60]
            conn.execute("INSERT OR REPLACE INTO scanned VALUES (?,?)", (replay_id, result))
            conn.commit()
            time.sleep(cfg["request_delay"])
            if why:
                progress.skip(why)
                continue
            progress.set(candidates=progress.state["candidates"] + 1)
            try:
                download("https://replay.faforever.com/%d" % replay_id, pool_path(replay_id, "fafreplay"),
                         "replay %d" % replay_id)
            except Exception as exc:
                log("%d download failed: %s" % (replay_id, exc))
                progress.outcome("%d download failed" % replay_id)
                continue
            progress.set(force=True, phase="preparing", file="replay %d" % replay_id, bytes=0, total=0)
            reason = prepare(conn, replay_id, cfg, maps)
            got += reason is None
            log("%d %s (%s min)" % (replay_id, reason or "ready", summary["minutes"]))
            progress.set(ready=got)
            progress.outcome("%d %s" % (replay_id, "ready, %s min" % summary["minutes"] if reason is None else reason))
        log("fetch: %d new ready replays, %d requests" % (got, progress.state["requests"]))
    finally:
        progress.set(force=True, active=False, phase="done", file="", ready=got)
        fetch_progress = None
    return got


def cmd_fetch(args):
    cmd_init(args)
    fetch_new(db(), load_config(), args.n, log=lambda s: print(s, flush=True))

# ---------------------------------------------------------------------------- win32 glue

u32 = ctypes.WinDLL("user32", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def _declare(fn, restype, *argtypes):
    """Every call's types, so ctypes never guesses an int's width: on x64 a handle, WPARAM,
    LPARAM or LRESULT is 64 bits (a runner died in _ctypes.pyd, 0xC0000005, on 2026-10-28)."""
    fn.restype = restype
    fn.argtypes = argtypes


LRESULT = ctypes.c_ssize_t
_declare(k32.OpenProcess, wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
_declare(k32.CloseHandle, wt.BOOL, wt.HANDLE)
_declare(k32.GetStdHandle, wt.HANDLE, wt.DWORD)
_declare(k32.GetConsoleMode, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.DWORD))
_declare(k32.SetConsoleMode, wt.BOOL, wt.HANDLE, wt.DWORD)
_declare(k32.GetNumberOfConsoleInputEvents, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.DWORD))
_declare(ntdll.NtSuspendProcess, ctypes.c_long, wt.HANDLE)
_declare(ntdll.NtResumeProcess, ctypes.c_long, wt.HANDLE)
_declare(u32.EnumWindows, wt.BOOL, EnumProc, wt.LPARAM)
_declare(u32.EnumChildWindows, wt.BOOL, wt.HWND, EnumProc, wt.LPARAM)
_declare(u32.GetWindowThreadProcessId, wt.DWORD, wt.HWND, ctypes.POINTER(wt.DWORD))
_declare(u32.GetClassNameW, ctypes.c_int, wt.HWND, wt.LPWSTR, ctypes.c_int)
_declare(u32.IsWindowVisible, wt.BOOL, wt.HWND)
_declare(u32.ShowWindowAsync, wt.BOOL, wt.HWND, ctypes.c_int)
_declare(u32.PostMessageW, wt.BOOL, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
_declare(u32.SendMessageTimeoutW, LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM, wt.UINT, wt.UINT,
         ctypes.POINTER(ctypes.c_size_t))
PROCESS_SUSPEND_RESUME = 0x0800
SW_SHOWNOACTIVATE, SW_SHOWMINNOACTIVE = 4, 7
WM_GETTEXT, WM_GETTEXTLENGTH, BM_CLICK = 0x000D, 0x000E, 0x00F5


class TaskbarList:
    """ITaskbarList::DeleteTab through raw COM vtable calls: takes a window's taskbar button away
    without touching the window, so a minimized game is invisible on screen and taskbar."""

    def __init__(self):
        ole = ctypes.WinDLL("ole32")
        ole.CoInitialize(None)
        clsid = (ctypes.c_byte * 16)(*bytes.fromhex("44f3fd566dfdd011958a006097c9a090"))
        iid = (ctypes.c_byte * 16)(*bytes.fromhex("42f3fd566dfdd011958a006097c9a090"))
        self.ptr = ctypes.c_void_p()
        if ole.CoCreateInstance(clsid, None, 1, iid, ctypes.byref(self.ptr)) != 0:  # CLSCTX_INPROC_SERVER
            self.ptr = None
            return
        self._call(3)  # HrInit

    def _call(self, slot, *args):
        vtbl = ctypes.cast(ctypes.cast(self.ptr, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
        proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *[wt.HWND] * len(args))
        return proto(vtbl[slot])(self.ptr, *args)

    def delete_tab(self, hwnd):
        return self.ptr is not None and self._call(5, hwnd) == 0  # DeleteTab


taskbar = None


def windows_of(pid):
    found = []

    def top(hwnd, _):
        p = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            found.append(hwnd)
        return True
    u32.EnumWindows(EnumProc(top), 0)
    return found


SMTO_ABORTIFHUNG = 0x0002


def window_text(hwnd):
    # With a timeout: a game window that stopped pumping messages must not hang the runner.
    result = ctypes.c_size_t()
    if not u32.SendMessageTimeoutW(hwnd, WM_GETTEXTLENGTH, 0, 0, SMTO_ABORTIFHUNG, 1000, ctypes.byref(result)):
        return ""
    n = result.value
    if not 0 < n < 8192:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    if not u32.SendMessageTimeoutW(hwnd, WM_GETTEXT, n + 1, ctypes.addressof(buf), SMTO_ABORTIFHUNG, 1000,
                                   ctypes.byref(result)):
        return ""
    return buf.value


def child_texts(hwnd):
    out = []

    def child(ch, _):
        cls = ctypes.create_unicode_buffer(256)
        u32.GetClassNameW(ch, cls, 256)
        text = window_text(ch)
        if text:
            out.append((cls.value, text))
        return True
    u32.EnumChildWindows(hwnd, EnumProc(child), 0)
    return out


def dismiss_ack_dialogs(pid):
    """Click OK on the process's 'Ack!' boxes; return their texts."""
    texts = []
    for hwnd in windows_of(pid):
        if window_text(hwnd) != "Ack!":
            continue
        kids = child_texts(hwnd)
        texts.append(" | ".join(t for cls, t in kids if cls == "Static"))
        for cls, t in kids:
            if cls == "Button" and t == "OK":
                u32.PostMessageW(hwnd, BM_CLICK, 0, 0)
    return texts


def minimize(pid):
    done = False
    for hwnd in windows_of(pid):
        if u32.IsWindowVisible(hwnd) and window_text(hwnd) != "Ack!":
            u32.ShowWindowAsync(hwnd, SW_SHOWMINNOACTIVE)
            done = True
    return done


def set_suspended(pid, suspend):
    handle = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not handle:
        return False
    try:
        fn = ntdll.NtSuspendProcess if suspend else ntdll.NtResumeProcess
        return fn(wt.HANDLE(handle)) == 0
    finally:
        k32.CloseHandle(wt.HANDLE(handle))


def kill_pid(pid):
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)


PARITY_EXE_RE = re.compile(r"^.+_parity_[0-9a-f]{10}\.exe$", re.I)


def kill_leftover_games():
    """Games a runner that died left behind (only one runner runs at a time, so any snapshot
    exe still running belongs to none). Another account's games are out of reach and stay.
    By pid: `taskkill /IM` takes a wildcard only at the end of the name, so the old
    "*_parity_*.exe" matched nothing and leftovers kept running."""
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                             timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return
    for row in csv.reader(out.splitlines()):
        if len(row) >= 2 and PARITY_EXE_RE.match(row[0]) and row[1].isdigit():
            kill_pid(int(row[1]))

# ----------------------------------------------------------------------------- the build


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head():
    try:
        out = subprocess.run(["git", "-C", REPO, "log", "-1", "--format=%h %cs %s"],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        dirty = subprocess.run(["git", "-C", REPO, "status", "--porcelain", "--untracked-files=no", "--", "src"],
                               capture_output=True, text=True, timeout=60).stdout.strip()
        return out + (" (+src changes)" if dirty else "")
    except Exception:
        return ""


def snapshot_build(conn, source):
    """Copy the exe next to itself under its content hash; returns (build label, snapshot path)."""
    sha = file_sha(source)[:10]
    folder, name = os.path.split(source)
    stem = os.path.splitext(name)[0]
    snap = os.path.join(folder, "%s_parity_%s.exe" % (stem, sha))
    if not os.path.isfile(snap):
        shutil.copyfile(source, snap)
    if not conn.execute("SELECT 1 FROM builds WHERE build=?", (sha,)).fetchone():
        conn.execute("INSERT INTO builds VALUES (?,?,?,?,?)",
                     (sha, snap, source, git_head(), now()))
        conn.commit()
    return sha, snap

# ------------------------------------------------------------------------- one game


BASE_INIT = "init_faf.lua"
VAULT_ANCHOR = "if custom_vault_path then"
LOAD_ANCHOR = "\tLoadVaultContent(custom_vault_path)\n"


def init_file_for(exe_dir, m28_version, cfg):
    """Generate init_parity[_m28_vNNNN].lua next to the exe from its init_faf.lua."""
    name = "init_parity.lua" if m28_version is None else "init_parity_m28_v%04d.lua" % m28_version
    base = open(os.path.join(exe_dir, BASE_INIT), encoding="latin1").read().replace("\r\n", "\n")
    if VAULT_ANCHOR not in base or LOAD_ANCHOR not in base:
        raise RuntimeError("%s changed: anchors for the vault override not found" % BASE_INIT)
    fwd = lambda p: p.replace("\\", "/")
    extra = "".join("\tMountMapContent('%s')\n" % fwd(d) for d in cfg.get("extra_map_dirs") or []
                    if os.path.isdir(d))
    if m28_version is not None:
        extra += "\tMountDirectory('%s', '/mods/m28ai')\n" % m28_dir(m28_version, cfg)
    text = base.replace(VAULT_ANCHOR, "-- replay parity runner: own vault\ncustom_vault_path = '%s'\n%s"
                        % (fwd(os.path.join(DATA, "vault")), VAULT_ANCHOR), 1)
    text = text.replace(LOAD_ANCHOR, LOAD_ANCHOR + extra, 1)
    text = ("-- Generated by tools/replay-parity/parity.py from %s; regenerated at every launch.\n" % BASE_INIT
            + text + "\n-- replay parity hook: game speed, camera, heartbeat\n"
            "table.insert(hook, '/parityhook')\n"
            "table.insert(path, { dir = '%s', mountpoint = '/parityhook' })\n" % fwd(HOOK_DIR))
    path = os.path.join(exe_dir, name)
    try:
        if open(path, encoding="latin1").read() == text:
            return name
    except OSError:
        pass
    with open(path, "w", encoding="latin1", newline="\n") as f:
        f.write(text)
    return name


MISMATCH_RE = re.compile(r"Checksum for beat (\d+) mismatched: ([0-9a-f]{32}) \(sim\) != ([0-9a-f]{32}) \((.*)\)\.")
HEARTBEAT_RE = re.compile(r"PARITY heartbeat tick=(-?\d+) time=([\d.]+) over=(\w+)")
# FATAL as the whole upper-case word only: player names land in the log too (26892082's
# "vvfatalis" matched a case-blind "fatal" and was taken for a crash).
TROUBLE_RE = re.compile(r"(?-i:\bFATAL\b)|access violation|Assertion failed|Unable to load game replay|"
                        r"Failed to setup initial search path|Unhandled exception", re.I)


def new_game(row, build, exe, cfg):
    """A game of the kind the build's exe plays."""
    return (HeadlessGame if mode_of_exe(exe) == "headless" else Game)(row, build, exe, cfg)


class Game:
    """One replay played by the game (main_x64.exe), minimized or hidden."""

    def __init__(self, row, build, exe, cfg):
        self.id = row["id"]
        self.expect = row["minutes"]  # header: the live game's wall time, lobby and pauses included
        self.beats = row["beats"]     # exact game length from the command stream
        self.build = build
        self.cfg = cfg
        self.started = now()
        self.t0 = time.time()
        logdir = os.path.join(DATA, "logs", build)
        os.makedirs(logdir, exist_ok=True)
        self.log = os.path.join(logdir, "%d.log" % self.id)
        if os.path.exists(self.log):
            os.remove(self.log)
        exe_dir = os.path.dirname(exe)
        init = init_file_for(exe_dir, row["m28"], cfg)
        self.proc = self.launch(exe, exe_dir, init, cfg)
        self.untabbed = set()
        self.pos = 0
        self.tick = -1
        self.time = 0.0
        self.over = False
        self.ended = False
        self.first_beat = None
        self.mismatches = 0
        self.recorded = None      # the replay's recorded checksums, read at the first mismatch
        self.client_desyncs = []  # beats where one live client disagreed and the sim sided with the rest
        self.desynced_clients = set()  # clients outvoted once: their later checksums are not evidence
        self.notes = []
        self.minimized = False
        self.suspended = False
        self.suspended_at = None
        self.paused_total = 0.0
        self.paused_total_at_progress = 0.0
        self.last_progress = time.time()
        self.verdict = None

    def launch(self, exe, exe_dir, init, cfg):
        w, h = cfg["window"]
        cmd = [exe, "/init", init, "/nobugreport", "/replay", pool_path(self.id, "scfareplay"),
               "/replayid", str(self.id), "/nosound", "/nomovie", "/windowed", str(w), str(h),
               "/log", self.log, "/title", "parity-%d" % self.id, *cfg["args"]]
        env = dict(os.environ, __COMPAT_LAYER="HighDpiAware")
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # the game's first ShowWindow takes this
        si.wShowWindow = SW_SHOWNOACTIVATE if cfg["window_mode"] == "normal" else SW_SHOWMINNOACTIVE
        return subprocess.Popen(cmd, cwd=exe_dir, env=env, startupinfo=si)

    def progress(self, tick):
        if tick > self.tick:
            self.tick = tick
            self.last_progress = time.time()
            self.paused_total_at_progress = self.paused_total

    def note_mismatch(self, m):
        """A "Checksum for beat N mismatched" line: ours, or the live game's (see below)."""
        beat, sim, theirs, client = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        if client in self.desynced_clients:
            return  # desynced in the live game earlier; stays wrong for the rest of it
        if self.live_client_desync(beat, sim, theirs):
            self.desynced_clients.add(client)
            self.client_desyncs.append("%s disagreed at beat %d" % (client, beat))
            return
        self.mismatches += 1
        if self.first_beat is None:
            self.first_beat = beat

    def active_seconds_since(self, t):
        paused = self.paused_total + (time.time() - self.suspended_at if self.suspended else 0.0)
        return time.time() - t - paused

    def suspend(self, on):
        if on == self.suspended:
            return
        if set_suspended(self.proc.pid, on):
            if on:
                self.suspended_at = time.time()
            else:
                self.paused_total += time.time() - self.suspended_at
                self.suspended_at = None
            self.suspended = on

    def read_log(self):
        try:
            with open(self.log, encoding="latin1", errors="replace") as f:
                f.seek(self.pos)
                chunk = f.read()
                self.pos = f.tell()
        except OSError:
            return
        for line in chunk.splitlines():
            m = HEARTBEAT_RE.search(line)
            if m:
                self.progress(int(m.group(1)))
                self.time = float(m.group(2))
                self.over = self.over or m.group(3) == "true"
                continue
            m = MISMATCH_RE.search(line)
            if m:
                self.note_mismatch(m)
                continue
            if "GameEnded" in line:
                self.ended = True
            elif TROUBLE_RE.search(line):
                self.notes.append(line.strip()[:200])

    def live_client_desync(self, beat, sim, theirs):
        """True when the mismatch is the live game's, not ours: at that beat more of the
        recorded clients agree with the sim than with the one that differs (26946725: nine
        clients and the sim on one checksum at beat 6700, Paulosan alone on another)."""
        if self.recorded is None:
            try:
                self.recorded = replay_checksums(open(pool_path(self.id, "scfareplay"), "rb").read())
            except (OSError, ValueError, IndexError, struct.error):
                self.recorded = {}
        votes = self.recorded.get(beat, {})
        return len(votes.get(sim, [])) > len(votes.get(theirs, []))

    def poll(self):
        """Advance the watch; returns a verdict once the game is over."""
        if self.suspended:
            return None
        self.read_log()
        for text in dismiss_ack_dialogs(self.proc.pid):
            self.notes.append("Ack: " + text[:300])
        if self.first_beat is not None:
            return "desync"
        if self.proc.poll() is not None:
            self.notes.append("exit code %s" % self.proc.returncode)
            return "crash"
        if self.notes:
            return "crash"
        if self.cfg["window_mode"] == "hidden":
            self.hide_taskbar_buttons()
        if self.tick >= 0 and not self.minimized and self.cfg["window_mode"] != "normal":
            # Minimized from the start already; this catches a frame that ignored the startup
            # show state.
            self.minimized = minimize(self.proc.pid)
        wall = self.active_seconds_since(self.t0)
        if wall > self.cfg["max_wall_minutes"] * 60:
            return "timeout"
        if self.tick < 0:
            if wall > self.cfg["startup_seconds"]:
                self.notes.append("no heartbeat after %ds" % wall)
                return "crash"
            return None
        # The sim stops at game over: a victory ends it a few beats before the stream does (the
        # beats where players leave are never simulated), a replay without one ends one tick
        # past its last beat. Both show over=true at their final tick, so a game over that
        # holds for a few seconds is the end; the stall timeout covers a replay that never
        # reports one.
        stalled = self.stalled_seconds()
        if self.over and stalled >= 5:
            return "pass"
        if stalled < self.cfg["stall_seconds"]:
            return None
        if self.ended or (self.beats and self.tick >= self.beats - 2):
            return "pass"
        if not self.beats and self.expect and self.time / 60.0 >= 0.6 * self.expect:
            return "pass"  # no stream length: the header's wall-time length, loosely
        self.notes.append("stopped at beat %d of %s" % (self.tick, self.beats or "?"))
        return "incomplete"

    def hide_taskbar_buttons(self):
        global taskbar
        for hwnd in windows_of(self.proc.pid):
            if hwnd in self.untabbed or not u32.IsWindowVisible(hwnd) or window_text(hwnd) == "Ack!":
                continue
            if taskbar is None:
                taskbar = TaskbarList()
            if taskbar.delete_tab(hwnd):
                self.untabbed.add(hwnd)

    def stalled_seconds(self):
        paused_since = self.paused_total - self.paused_total_at_progress
        return time.time() - self.last_progress - paused_since

    def stop(self):
        if self.suspended:
            set_suspended(self.proc.pid, False)
        if self.proc.poll() is None:
            kill_pid(self.proc.pid)
            try:
                self.proc.wait(30)
            except subprocess.TimeoutExpired:
                pass
        self.read_log()

    def describe(self):
        state = "parked" if self.suspended else ("minimized" if self.minimized else "starting" if self.tick < 0 else "running")
        return {"id": self.id, "pid": self.proc.pid, "state": state, "tick": self.tick,
                "game_time": round(self.time), "expect_min": self.expect, "beats": self.beats,
                "wall_s": round(self.active_seconds_since(self.t0)), "stalled_s": round(self.stalled_seconds())}


# headless_x64.exe's output (src/headless/ReplayRunner.cpp, HeadlessMain.cpp), every line
# prefixed with "[<label>] ".
HL_LOADED_RE = re.compile(r"\] loaded in [\d.]+s")
HL_PROGRESS_RE = re.compile(r"\] beat (-?\d+) game time \d+:\d+:\d+ after")
HL_ENDED_RE = re.compile(r"\] GAME-ENDED beat (-?\d+)")
HL_SUMMARY_RE = re.compile(r"\] beats=\d+ last-beat=(-?\d+) game-over=(\w+)")
HL_VERDICT_RE = re.compile(r"\] VERDICT ended=(\w+) .*crash=(\w+)")
HL_TROUBLE_RE = re.compile(r"\] (?:FATAL|CRASH|ERROR) ")


class HeadlessGame(Game):
    """One replay played by headless_x64.exe: no window and no console. It plays the replay
    flat out and exits; what it prints goes to logs/<build>/<id>.out, the engine log to
    <id>.log. Mismatch lines are the engine's own ("DESYNC-LINE Checksum for beat N
    mismatched: ..."), so the live-client vote below works as for the game."""

    def launch(self, exe, exe_dir, init, cfg):
        self.out = os.path.splitext(self.log)[0] + ".out"
        self.out_pos = 0
        self.final = None  # (ended, crash) from the VERDICT line
        cmd = [exe, "--replay", pool_path(self.id, "scfareplay"), "/init", os.path.join(exe_dir, init),
               "/nosound", "/log", self.log, "--label", "parity-%d" % self.id,
               "--timeout", str(int(cfg["max_wall_minutes"]) + 5), *cfg["headless_args"]]
        with open(self.out, "wb") as out:
            return subprocess.Popen(cmd, cwd=exe_dir, stdout=out, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)

    def read_log(self):
        try:
            with open(self.out, encoding="latin1", errors="replace") as f:
                f.seek(self.out_pos)
                chunk = f.read()
        except OSError:
            return
        # Only whole lines: the process may be writing the last one.
        cut = chunk.rfind("\n") + 1
        if self.proc.poll() is None:
            chunk = chunk[:cut]
        self.out_pos += len(chunk.encode("latin1", errors="replace"))
        for line in chunk.splitlines():
            m = MISMATCH_RE.search(line)
            if m:
                self.note_mismatch(m)
                continue
            m = HL_PROGRESS_RE.search(line) or HL_ENDED_RE.search(line)
            if m:
                self.progress(int(m.group(1)))
                self.ended = self.ended or "GAME-ENDED" in line
            elif HL_LOADED_RE.search(line):
                self.progress(0)
            elif (m := HL_SUMMARY_RE.search(line)):
                self.progress(int(m.group(1)))
                self.over = m.group(2) == "True"
            elif (m := HL_VERDICT_RE.search(line)):
                self.final = (m.group(1) == "True", m.group(2) == "True")
            elif HL_TROUBLE_RE.search(line):
                self.notes.append(line.strip()[:200])
            self.time = max(self.tick, 0) / 10.0

    def poll(self):
        if self.suspended:
            return None
        self.read_log()
        if self.first_beat is not None:
            return "desync"
        if self.proc.poll() is not None:
            self.read_log()
            if self.first_beat is not None:
                return "desync"
            if self.final is None or self.final[1]:
                self.notes.append("exit code %s%s" % (self.proc.returncode, "" if self.final else ", no verdict"))
                return "crash"
            if self.ended or self.over or (self.beats and self.tick >= self.beats - 2):
                return "pass"
            self.notes.append("stopped at beat %d of %s" % (self.tick, self.beats or "?"))
            return "incomplete"
        wall = self.active_seconds_since(self.t0)
        if wall > self.cfg["max_wall_minutes"] * 60:
            return "timeout"
        if self.tick < 0 and wall > self.cfg["startup_seconds"]:
            self.notes.append("not loaded after %ds" % wall)
            return "crash"
        return None

# ---------------------------------------------------------------------------- the runner


LOG_PATH = os.path.join(DATA, "runner.log")
log_lock = threading.Lock()


def log_line(text, echo=False):
    """One line of runner.log (the console's LOG pane reads it back)."""
    with log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(text.rstrip() + "\n")
    if echo:
        print(text, flush=True)


class Runner:
    def __init__(self, echo=True):
        self.echo = echo
        self.conn = db()
        self.games = []
        self.build = None
        self.exe = None
        self.source = None
        self.source_seen = None
        self.source_missing = None
        self.last_build_check = 0.0
        self.last_launch = 0.0
        self.fetching = None
        self.idle_reported = False
        self.launch_failures = 0
        self.launch_skipped = set()

    def say(self, text):
        log_line("%s %s" % (now(), text), self.echo)

    def refresh_build(self, cfg, force=False):
        source = mode_exe(cfg)
        # A mode switch takes the other exe at once; running games finish on their own build.
        switched = source != self.source
        if not force and not switched and time.time() - self.last_build_check < 60:
            return
        self.last_build_check = time.time()
        try:
            stat = os.stat(source)
        except OSError:
            if force:
                raise
            if switched and self.source_missing != source:
                self.source_missing = source
                self.say("mode %s: %s not found; staying on build %s" % (cfg["mode"], source, self.build))
            return
        key = (source, stat.st_size, stat.st_mtime)
        if not force and not switched and (not cfg["follow_exe"] or key == self.source_seen):
            return
        if not force and not switched and time.time() - stat.st_mtime < 60:
            return  # still being written by a build
        build, exe = snapshot_build(self.conn, source)
        self.source_seen = key
        self.source = source
        self.source_missing = None
        if build != self.build:
            self.build, self.exe = build, exe
            self.say("build %s (%s, %s) %s" % (build, cfg["mode"], exe, git_head()))

    def next_replay(self):
        running = {g.id for g in self.games} | self.launch_skipped
        rows = self.conn.execute(
            "SELECT * FROM replays r WHERE state='ready' AND NOT EXISTS (SELECT 1 FROM runs u "
            "WHERE u.replay=r.id AND u.build=? AND u.verdict IN (%s)) "
            "ORDER BY priority, COALESCE(players, 0) < 2, id"
            % ",".join("?" * len(FINAL_VERDICTS)), (self.build, *FINAL_VERDICTS)).fetchall()
        for row in rows:
            if row["id"] not in running:
                return row
        return None

    def finish(self, game, verdict):
        game.stop()
        wall = game.active_seconds_since(game.t0)
        note = "; ".join(game.notes + game.client_desyncs)[:1000]
        if verdict in ("desync", "crash", "timeout", "incomplete", "launchfail"):
            kind = "desyncs" if verdict == "desync" else "crashes"
            label = "%d_beat%d" % (game.id, game.first_beat) if verdict == "desync" else "%d_%s" % (game.id, verdict)
            keep = os.path.join(DATA, kind, game.build, label)
            os.makedirs(keep, exist_ok=True)
            for src in (pool_path(game.id, "fafreplay"), pool_path(game.id, "scfareplay"), game.log):
                if os.path.isfile(src):
                    shutil.copy2(src, keep)
            write_json(os.path.join(keep, "info.json"), {
                "replay": game.id, "build": game.build, "verdict": verdict, "first_beat": game.first_beat,
                "mismatches": game.mismatches, "last_tick": game.tick, "game_time_s": game.time,
                "expect_min": game.expect, "args": game.cfg["args"], "notes": game.notes,
                "client_desyncs": game.client_desyncs,
                "replay_url": "https://replay.faforever.com/%d" % game.id})
        self.conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (game.id, game.build, game.started, now(), verdict, game.first_beat,
                           game.mismatches, game.tick, game.time, game.expect, wall, game.log, note))
        self.conn.commit()
        line = "%s build=%s replay=%d verdict=%s first_beat=%s tick=%d game=%s expect=%s wall=%s %s" % (
            now(), game.build, game.id, verdict, game.first_beat, game.tick,
            time.strftime("%H:%M:%S", time.gmtime(game.time)), game.expect,
            time.strftime("%M:%S", time.gmtime(wall)) if wall < 3600 else "%dm" % (wall // 60), note)
        with open(os.path.join(DATA, "results.txt"), "a", encoding="utf-8") as f:
            f.write(line.rstrip() + "\n")
        log_line(line, self.echo)

    def abort_all(self):
        for game in self.games:
            game.stop()
            self.conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (game.id, game.build, game.started, now(), "aborted", game.first_beat,
                               game.mismatches, game.tick, game.time, game.expect,
                               game.active_seconds_since(game.t0), game.log, "stopped by the user"))
        self.conn.commit()
        self.games = []

    def write_state(self, ctl):
        write_json(STATE_PATH, {"updated": now(), "updated_ts": time.time(), "pid": os.getpid(),
                                "running": True, "build": self.build, "exe": self.exe,
                                "mode": mode_of_exe(self.exe),
                                "control": ctl, "fetching": bool(self.fetching and self.fetching.is_alive()),
                                "games": [g.describe() for g in self.games]})

    def start_fetch(self, cfg, count):
        def work():
            conn = db()
            try:
                fetch_new(conn, cfg, count, log=lambda s: self.say("fetch: " + s))
            except Exception as exc:
                self.say("fetch failed: %s" % exc)
            finally:
                conn.close()
        self.fetching = threading.Thread(target=work, daemon=True)
        self.fetching.start()

    def run(self):
        cfg = load_config()
        self.refresh_build(cfg, force=True)
        fill_beats(self.conn)
        kill_leftover_games()
        self.say("runner started, data %s" % DATA)
        errors = 0
        try:
            while True:
                try:
                    if self.step():
                        break
                    errors = 0
                except Exception:
                    # One bad iteration (a file another process holds, a database lock) must
                    # not orphan the running games; give up only when it keeps happening.
                    errors += 1
                    self.say("runner error (%d in a row): %s" % (errors, traceback.format_exc().strip()))
                    if errors >= 30:
                        raise
                time.sleep(1)
        except BaseException:
            self.abort_all()
            raise
        finally:
            update_control(stop=False, stop_now=False)
            self.write_state(read_json(CONTROL_PATH, DEFAULT_CONTROL))
            state = read_json(STATE_PATH, {})
            state["running"] = False
            write_json(STATE_PATH, state)
            self.say("runner stopped")

    def step(self):
        """One pass of the runner loop; True when the runner should exit."""
        ctl = read_json(CONTROL_PATH, DEFAULT_CONTROL)
        cfg = load_config()
        if ctl["stop_now"]:
            self.abort_all()
            return True
        self.refresh_build(cfg)
        for game in list(self.games):
            try:
                verdict = game.poll()
            except Exception as exc:
                game.notes.append("runner error %s" % exc)
                verdict = "crash"
            if verdict:
                self.games.remove(game)
                # A game that dies before its first heartbeat within seconds is a launch
                # problem (bad exe, init file, desktop), not a replay result: it is queued
                # again, and three in a row pause the runner instead of eating the pool.
                if verdict == "crash" and game.tick < 0 and game.active_seconds_since(game.t0) < 30:
                    verdict = "launchfail"
                    self.launch_failures += 1
                else:
                    self.launch_failures = 0
                self.finish(game, verdict)
                if self.launch_failures >= 3:
                    update_control(paused=True)
                    self.say("PAUSED: %d launches in a row died at startup (%s); fix it, then "
                             "`parity.py resume`" % (self.launch_failures, "; ".join(game.notes)))
                    self.launch_failures = 0
        target = 0 if ctl["paused"] else max(0, int(ctl["instances"]))
        active = [g for g in self.games if not g.suspended]
        parked = [g for g in self.games if g.suspended]
        if len(active) > target:
            for game in sorted(active, key=lambda g: g.t0)[target:]:
                game.suspend(True)
        elif len(active) < target and parked:
            for game in sorted(parked, key=lambda g: g.t0)[:target - len(active)]:
                game.suspend(False)
        elif (len(active) < target and not ctl["stop"]
              and time.time() - self.last_launch >= cfg["launch_gap_seconds"]):
            row = self.next_replay()
            if row is not None:
                self.idle_reported = False
                try:
                    self.games.append(new_game(row, self.build, self.exe, cfg))
                    self.say("start replay %d (%s, %s players, %s min%s)" % (
                        row["id"], row["map"], row["players"], row["minutes"],
                        ", M28AI v%d" % row["m28"] if row["m28"] else ""))
                except Exception as exc:
                    # e.g. its log still held by a game a dead runner left behind: try the
                    # others and come back to this one in the next session.
                    self.launch_skipped.add(row["id"])
                    self.say("launch of %d failed, skipped this session: %s" % (row["id"], exc))
                self.last_launch = time.time()
            elif not (self.fetching and self.fetching.is_alive()) and not fetch_running():
                # The queue is dry with a slot free (not paused, not stopping): fetch more for
                # the game version this exe plays while the last games still run.
                if ctl["auto_fetch"] and cfg["auto_fetch"] > 0:
                    self.say("every ready replay has a result for build %s; fetching %d more (game version %s)"
                             % (self.build, cfg["auto_fetch"], cfg["game_version"]))
                    self.start_fetch(cfg, cfg["auto_fetch"])
                elif not self.games and not self.idle_reported:
                    self.say("every ready replay has a result for build %s; waiting for a new "
                             "build (or `parity.py fetch`)" % self.build)
                    self.idle_reported = True
        if ctl["stop"] and not self.games:
            return True
        self.write_state(ctl)
        return False


def runner_pid():
    """Pid of the live runner, from the state file it rewrites every second. A process
    handle check would fail from another Windows account (OpenProcess is denied there)."""
    state = read_json(STATE_PATH, {})
    if state.get("running") and time.time() - state.get("updated_ts", 0) < 15:
        return state.get("pid")
    return None


def cmd_run(args):
    cmd_init(args)
    if runner_pid() not in (None, os.getpid()):
        sys.exit("a runner is already running (pid %d)" % runner_pid())
    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))
    try:
        Runner(echo=not args.quiet).run()
    finally:
        try:
            os.remove(PID_PATH)
        except OSError:
            pass


def cmd_start(args):
    cmd_init(args)
    if args.mode:
        set_mode(args.mode)
    if args.n is not None:
        update_control(instances=args.n)
    update_control(stop=False, stop_now=False)
    pid = runner_pid()
    if pid:
        print("runner already running (pid %d); control updated" % pid)
        return
    out = open(LOG_PATH, "a", encoding="utf-8")  # tracebacks; the runner writes its lines itself
    flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008 | subprocess.CREATE_NO_WINDOW  # DETACHED_PROCESS
    proc = subprocess.Popen([sys.executable, "-X", "utf8", os.path.abspath(__file__), "run", "--quiet"],
                            stdout=subprocess.DEVNULL, stderr=out, stdin=subprocess.DEVNULL,
                            creationflags=flags, close_fds=True, cwd=REPO)
    print("runner started (pid %d), %d instances; log %s" % (
        proc.pid, read_json(CONTROL_PATH, DEFAULT_CONTROL)["instances"], os.path.join(DATA, "runner.log")))


def cmd_instances(args):
    print("instances ->", update_control(instances=args.n)["instances"])


def cmd_pause(args):
    update_control(paused=True)
    print("paused: running games are suspended, nothing new starts")


def cmd_resume(args):
    update_control(paused=False)
    print("resumed")


def cmd_stop(args):
    if args.now:
        update_control(stop_now=True)
        print("stopping now: running games are killed and queued again")
    else:
        update_control(stop=True)
        print("stopping after the running games finish (`stop --now` to kill them)")


def cmd_mode(args):
    cmd_init_quiet()
    if args.mode:
        set_mode(args.mode)
    cfg = load_config()
    exe = mode_exe(cfg)
    print("mode %s: %s%s" % (cfg["mode"], exe, "" if os.path.isfile(exe) else " (not found)"))
    if args.mode and runner_pid():
        print("the runner takes it for its next games; running games finish as they are")


def cmd_init_quiet():
    if not os.path.isfile(CONFIG_PATH):
        os.makedirs(DATA, exist_ok=True)
        write_json(CONFIG_PATH, DEFAULT_CONFIG)


def cmd_status(args):
    conn = db()
    fill_beats(conn)
    ctl = read_json(CONTROL_PATH, DEFAULT_CONTROL)
    state = read_json(STATE_PATH, {})
    pid = runner_pid()
    print("runner: %s | mode %s | instances %s%s%s" % (
        "pid %d" % pid if pid else "not running", load_config()["mode"], ctl["instances"],
        " | PAUSED" if ctl["paused"] else "", " | stopping" if ctl["stop"] else ""))
    pool = dict(conn.execute("SELECT state, COUNT(*) FROM replays GROUP BY state").fetchall())
    print("pool: %d ready, %d unsupported" % (pool.get("ready", 0), pool.get("unsupported", 0)))
    build = state.get("build")
    for b in conn.execute("SELECT * FROM builds ORDER BY created DESC LIMIT %d" % (5 if args.v else 2)):
        counts = dict(conn.execute(
            "SELECT verdict, COUNT(DISTINCT replay) FROM runs WHERE build=? GROUP BY verdict", (b["build"],)).fetchall())
        done = conn.execute("SELECT COUNT(DISTINCT replay) FROM runs WHERE build=? AND verdict IN (%s)"
                            % ",".join("?" * len(FINAL_VERDICTS)), (b["build"], *FINAL_VERDICTS)).fetchone()[0]
        print("build %s%s  %s  %s  [%s]" % (b["build"], " (current)" if b["build"] == build else "",
                                             mode_of_exe(b["source"]), b["git"], b["created"]))
        print("   %d/%d done: %s" % (done, pool.get("ready", 0),
                                     ", ".join("%s %d" % kv for kv in sorted(counts.items())) or "nothing yet"))
        for r in conn.execute("SELECT * FROM runs WHERE build=? AND verdict NOT IN ('pass','aborted') "
                              "ORDER BY finished", (b["build"],)):
            print("   %-10s %d beat=%s game=%s %s" % (r["verdict"], r["replay"], r["first_beat"],
                                                    time.strftime("%H:%M:%S", time.gmtime(r["last_time"] or 0)),
                                                    (r["note"] or "")[:120]))
    for g in state.get("games", []) if pid else []:
        print("   game %d pid %d %s beat %d of %s, game %s of %s, wall %s" % (
            g["id"], g["pid"], g["state"], g["tick"], g.get("beats") or "?", clock(g["game_time"]),
            clock((g.get("beats") or 0) / 10) if g.get("beats") else "?", clock(g["wall_s"])))
    if args.v:
        for r in conn.execute("SELECT reason, COUNT(*) n FROM replays WHERE state='unsupported' "
                              "GROUP BY reason ORDER BY n DESC LIMIT 15"):
            print("   unsupported: %4d %s" % (r["n"], r["reason"]))


# ------------------------------------------------------------------------------ console

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = ("\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[36m",
                                              "\x1b[2m", "\x1b[1m", "\x1b[0m")
VERDICT_COLOUR = {"pass": GREEN, "desync": RED, "crash": RED, "timeout": YELLOW,
                  "incomplete": YELLOW, "launchfail": YELLOW, "aborted": DIM}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def enable_vt():
    """Colour codes on, and QuickEdit off: with QuickEdit a mouse click in the window starts a
    selection that blocks every write to the console until Esc, freezing the screen."""
    k32.GetStdHandle.restype = wt.HANDLE
    out = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    mode = wt.DWORD()
    if k32.GetConsoleMode(out, ctypes.byref(mode)):
        k32.SetConsoleMode(out, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    inp = k32.GetStdHandle(-10)  # STD_INPUT_HANDLE
    if k32.GetConsoleMode(inp, ctypes.byref(mode)):
        k32.SetConsoleMode(inp, (mode.value & ~0x0040) | 0x0080)  # ~QUICK_EDIT, EXTENDED_FLAGS
        return mode.value
    return None


class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("bKeyDown", wt.BOOL), ("wRepeatCount", wt.WORD), ("wVirtualKeyCode", wt.WORD),
                ("wVirtualScanCode", wt.WORD), ("uChar", wt.WCHAR), ("dwControlKeyState", wt.DWORD)]


class INPUT_RECORD(ctypes.Structure):
    class _Event(ctypes.Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD), ("raw", ctypes.c_byte * 16)]
    _fields_ = [("EventType", wt.WORD), ("Event", _Event)]


def read_key():
    """The next typed character, or None; never blocks. msvcrt.kbhit() counts input events
    that are not characters (key releases, focus and mouse events in ConPTY terminals such
    as VS Code's and Windows Terminal), and the getwch() after it then blocks until a real
    key: the console stopped redrawing until something was pressed."""
    handle = k32.GetStdHandle(-10)  # STD_INPUT_HANDLE
    pending = wt.DWORD()
    record = INPUT_RECORD()
    got = wt.DWORD()
    while k32.GetNumberOfConsoleInputEvents(handle, ctypes.byref(pending)) and pending.value:
        if not k32.ReadConsoleInputW(handle, ctypes.byref(record), 1, ctypes.byref(got)) or not got.value:
            return None
        key = record.Event.KeyEvent
        if record.EventType == 1 and key.bKeyDown and key.uChar not in ("\x00", ""):  # KEY_EVENT
            return key.uChar
    return None


def restore_input_mode(mode):
    if mode is not None:
        k32.SetConsoleMode(k32.GetStdHandle(-10), mode)


def bar(fraction, width):
    filled = int(round(max(0.0, min(1.0, fraction)) * width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def clock(seconds):
    seconds = int(seconds or 0)
    if seconds >= 3600:
        return "%d:%02d:%02d" % (seconds // 3600, seconds % 3600 // 60, seconds % 60)
    return "%d:%02d" % (seconds // 60, seconds % 60)


def fit(text, width):
    """Cut a line with colour codes to `width` visible characters."""
    out, seen, i = [], 0, 0
    while i < len(text) and seen < width:
        m = ANSI_RE.match(text, i)
        if m:
            out.append(m.group())
            i = m.end()
            continue
        out.append(text[i])
        seen += 1
        i += 1
    return "".join(out) + RESET


def tail_lines(path, count):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 16384))
            return f.read().decode("utf-8", "replace").splitlines()[-count:]
    except OSError:
        return []


def size_text(n):
    return "%.1f MB" % (n / 1048576.0) if n >= 1048576 else "%d KB" % (n // 1024)


def fetch_panel(width):
    """FETCH lines while a fetch runs, and for two minutes after it ends."""
    st = read_json(FETCH_PATH, {})
    if not st:
        return []
    fresh = time.time() - st.get("updated_ts", 0)
    if st.get("active") and fresh > 60:
        return []  # a fetch that died without saying so
    if not st.get("active") and fresh > 120:
        return []
    elapsed = clock(st.get("updated_ts", 0) - st.get("started_ts", 0))
    skips = sorted(st.get("skips", {}).items(), key=lambda kv: -kv[1])
    skipped = ", ".join("%s %d" % kv for kv in skips[:5])
    head = "%sFETCH%s %s %d/%d ready   headers read %d, candidates %d   %d requests   %s" % (
        BOLD, RESET, bar(st["ready"] / st["target"] if st.get("target") else 0, 20), st["ready"],
        st["target"], st["headers"], st["candidates"], st["requests"], elapsed)
    lines = ["", head]
    if not st.get("active"):
        lines[1] = head.replace("FETCH" + RESET, "FETCH" + RESET + GREEN + " done" + RESET, 1)
    elif st.get("phase") == "downloading" and st.get("file"):
        total = st.get("total") or 0
        lines.append("  downloading %s %s %s%s" % (
            st["file"], bar(st["bytes"] / total if total else 0, 20), size_text(st["bytes"]),
            " / " + size_text(total) if total else ""))
    elif st.get("phase") == "preparing":
        lines.append("  preparing %s (converting, map and mod check)" % st.get("file", ""))
    else:
        lines.append("  searching the vault for game version %s replays" % load_config()["game_version"])
    if skipped:
        lines.append(DIM + "  skipped: " + skipped + RESET)
    for text in st.get("recent", []):
        colour = GREEN if "ready" in text else YELLOW
        lines.append("  " + colour + text + RESET)
    return lines


def console_screen(conn, mode, message):
    width, height = shutil.get_terminal_size((120, 40))
    ctl = read_json(CONTROL_PATH, DEFAULT_CONTROL)
    state = read_json(STATE_PATH, {})
    pid = runner_pid()
    build = state.get("build")
    games = state.get("games", []) if pid else []
    lines = []
    if pid:
        if ctl["stop_now"]:
            status = YELLOW + "STOPPING: killing the running games"
        elif ctl["stop"]:
            status = YELLOW + "STOPPING: nothing new starts; exits after the %d running game%s finish (r resumes, k kills)" % (
                len(games), "" if len(games) == 1 else "s")
        elif ctl["paused"]:
            status = YELLOW + "PAUSED (r resumes)"
        else:
            status = GREEN + "RUNNING"
        status += RESET + (YELLOW + " + PAUSED, so they never finish: r resumes" + RESET
                           if ctl["paused"] and ctl["stop"] else "")
    else:
        status = RED + "NOT RUNNING" + RESET
    lines.append("%sFAF replay parity%s   %s   runner %s (%s)   %s" % (
        BOLD, RESET, status, pid or "-", mode, time.strftime("%H:%M:%S")))
    b = conn.execute("SELECT * FROM builds WHERE build=?", (build,)).fetchone() if build else None
    wanted = load_config()["mode"]
    playing = state.get("mode") or (mode_of_exe(b["source"]) if b else wanted)
    mode_text = "%s%s%s" % (BOLD, playing, RESET) + (
        YELLOW + " -> %s for the next games" % wanted + RESET if pid and wanted != playing else "")
    lines.append("build %s%s%s  %s   mode %s" % (CYAN, build or "-", RESET, b["git"] if b else "", mode_text))
    ready = conn.execute("SELECT COUNT(*) FROM replays WHERE state='ready'").fetchone()[0]
    counts = dict(conn.execute("SELECT verdict, COUNT(DISTINCT replay) FROM runs WHERE build=? GROUP BY verdict",
                               (build,)).fetchall()) if build else {}
    done = sum(counts.get(v, 0) for v in FINAL_VERDICTS)
    parked = sum(1 for g in games if g["state"] == "parked")
    lines.append("instances %s%d%s   running %d   parked %d   pool %d ready" % (
        BOLD, ctl["instances"], RESET, len(games) - parked, parked, ready))
    lines.append("")
    tally = "  ".join("%s%s %d%s" % (VERDICT_COLOUR.get(v, ""), v, counts.get(v, 0), RESET)
                      for v in ("pass", "desync", "crash", "incomplete", "timeout", "launchfail")
                      if counts.get(v) or v in ("pass", "desync"))
    lines.append("done %s %d/%d   %s" % (bar(done / ready if ready else 0, 30), done, ready, tally))
    speed = conn.execute("SELECT SUM(last_time), SUM(wall), COUNT(*) FROM runs WHERE build=? AND verdict='pass'",
                         (build,)).fetchone() if build else (None, None, 0)
    if speed[2] and speed[1]:
        rate = speed[0] / speed[1]  # game seconds per wall second, per game
        left = conn.execute(
            "SELECT SUM(beats) FROM replays r WHERE state='ready' AND NOT EXISTS (SELECT 1 FROM runs u "
            "WHERE u.replay=r.id AND u.build=? AND u.verdict IN (%s))" % ",".join("?" * len(FINAL_VERDICTS)),
            (build, *FINAL_VERDICTS)).fetchone()[0] or 0
        left = left / 10.0 - sum(g["game_time"] for g in games)
        eta = left / rate / max(1, ctl["instances"])
        lines.append("speed %.1fx game time per game   %s of game time left   ETA %s at %d instances" % (
            rate, clock(left), clock(eta), ctl["instances"]))
    lines.extend(fetch_panel(width))
    lines.append("")
    lines.append(BOLD + "RUNNING" + RESET)
    if not games:
        lines.append(DIM + "  (none)" + RESET)
    for g in games:
        row = conn.execute("SELECT map, players, m28 FROM replays WHERE id=?", (g["id"],)).fetchone()
        length = (g.get("beats") or 0) / 10.0  # exact, from the replay's command stream
        lines.append("  %d  %-34s %2s pl %s %8s / %-7s %6s wall  %s%s" % (
            g["id"], (row["map"] if row else "?")[:34], row["players"] if row else "?",
            bar(g["game_time"] / length if length else 0, 20), clock(g["game_time"]),
            clock(length) if length else "?",
            clock(g["wall_s"]), g["state"] if g["state"] != "minimized" else "running",
            ", M28AI v%d" % row["m28"] if row and row["m28"] else ""))
    lines.append("")
    lines.append(BOLD + "RESULTS" + RESET)
    recent = conn.execute("SELECT * FROM runs WHERE build=? ORDER BY finished DESC LIMIT 8", (build,)).fetchall() \
        if build else []
    if not recent:
        lines.append(DIM + "  (none yet)" + RESET)
    for r in recent:
        extra = " first mismatch beat %d" % r["first_beat"] if r["first_beat"] is not None else ""
        if r["verdict"] not in ("pass", "desync") and r["note"]:
            extra += "  " + r["note"]
        lines.append("  %s  %s%-10s%s %d  game %s  wall %s%s" % (
            r["finished"][11:], VERDICT_COLOUR.get(r["verdict"], ""), r["verdict"], RESET, r["replay"],
            clock(r["last_time"]), clock(r["wall"]), extra))
    lines.append("")
    lines.append(BOLD + "LOG" + RESET)
    log_room = max(3, height - len(lines) - 3)
    log = [line for line in tail_lines(LOG_PATH, 200) if " verdict=" not in line]  # those are in RESULTS
    for line in log[-log_room:]:
        lines.append(DIM + "  " + line + RESET)
    lines.append("")
    keys = [("+/-", "instances"), ("p", "pause"), ("r", "resume"), ("f", "fetch 10 from vault"),
            ("a", "auto-fetch " + ("on" if ctl["auto_fetch"] else "off")),
            ("m", "switch to " + ("gui" if wanted == "headless" else "headless")),
            ("s", "stop after running"), ("k", "kill now"), ("q", "quit")]
    lines.append("  ".join("%s[%s]%s %s" % (BOLD, k, RESET, what) for k, what in keys)
                 + (("   " + YELLOW + message + RESET) if message else ""))
    lines = lines[:height - 1]
    title = "\x1b]0;FAF parity %d/%d%s\x07" % (done, ready, " PAUSED" if ctl["paused"] else "")
    return title + "\x1b[H" + "".join(fit(l, width - 1) + "\x1b[K\n" for l in lines) + "\x1b[J"


def cmd_console(args):
    os.makedirs(DATA, exist_ok=True)
    if not os.path.isfile(CONFIG_PATH):
        cmd_init(args)
    if args.mode:
        set_mode(args.mode)
    if args.n is not None:
        update_control(instances=args.n)
    def runner_main():
        try:
            Runner(echo=False).run()  # kills its games itself if it fails
        except Exception:
            log_line("%s runner crashed: %s" % (now(), traceback.format_exc().strip()))

    def start_embedded():
        # No runner: this console is the runner. Quitting it stops the games.
        update_control(stop=False, stop_now=False)
        with open(PID_PATH, "w") as f:
            f.write(str(os.getpid()))
        thread = threading.Thread(target=runner_main, daemon=True)
        thread.start()
        return thread

    embedded = None
    if runner_pid():
        mode = "attached: q leaves it running"
    else:
        embedded = start_embedded()
        mode = "in this console: q stops the games"
    input_mode = enable_vt()
    sys.stdout.write("\x1b[?25l\x1b[2J")
    conn = db()
    message, message_until = "", 0.0
    fetcher = None

    def note(text):
        nonlocal message, message_until
        message, message_until = text, time.time() + 6
    try:
        while True:
            if time.time() > message_until:
                message = ""
            if embedded is not None and not embedded.is_alive():
                # The console stays: the screen shows why (LOG) and r starts the runner again.
                embedded = None
                mode = "stopped: r starts it, q quits"
            elif embedded is None and not runner_pid() and not mode.startswith("stopped"):
                mode = "stopped: r starts it, q quits"  # an attached background runner ended
            sys.stdout.write(console_screen(conn, mode, message))
            sys.stdout.flush()
            deadline = time.time() + 1.0
            key = None
            while time.time() < deadline and key is None:
                key = read_key()
                if key is None:
                    time.sleep(0.05)
            if key is None:
                continue
            ctl = read_json(CONTROL_PATH, DEFAULT_CONTROL)
            if key in "+=":
                note("instances -> %d" % update_control(instances=ctl["instances"] + 1)["instances"])
            elif key in "-_":
                note("instances -> %d" % update_control(instances=max(0, ctl["instances"] - 1))["instances"])
            elif key in "pP":
                note("paused" if update_control(paused=not ctl["paused"])["paused"] else "resumed")
            elif key in "rR":
                update_control(paused=False, stop=False)
                if not runner_pid() and embedded is None:
                    embedded = start_embedded()
                    mode = "in this console: q stops the games"
                    note("runner started")
                else:
                    note("resumed: running, stop cancelled" if ctl["stop"] else "resumed")
            elif key in "aA":
                on = update_control(auto_fetch=not ctl["auto_fetch"])["auto_fetch"]
                note("auto-fetch %s" % ("on: 10 more replays whenever the queue runs dry" if on else "off"))
            elif key in "mM":
                cfg = load_config()
                mode = set_mode("gui" if cfg["mode"] == "headless" else "headless")
                note("mode %s: new games use %s; running ones finish as they are"
                     % (mode, mode_exe(load_config())))
            elif key in "sS":
                update_control(stop=not ctl["stop"])
                note("stopping after the running games" if not ctl["stop"] else "stop cancelled")
            elif key in "kK":
                update_control(stop_now=True)
                note("killing the running games")
            elif key in "fF":
                if (fetcher and fetcher.is_alive()) or fetch_running():
                    note("a fetch is already running (see FETCH)")
                else:
                    def fetch_work():
                        try:
                            fetch_new(db(), load_config(), 10, log=lambda s: log_line("%s fetch: %s" % (now(), s)))
                        except Exception as exc:
                            log_line("%s fetch failed: %s" % (now(), exc))
                    fetcher = threading.Thread(target=fetch_work, daemon=True)
                    fetcher.start()
                    note("fetching 10 replays from the vault")
            elif key in "qQ\x1b":
                break
    except KeyboardInterrupt:
        pass
    finally:
        if embedded is not None and embedded.is_alive():
            # The runner kills its games and records them as aborted (queued again). A second
            # q or Ctrl+C skips the wait: the games are killed directly and the console exits.
            update_control(stop_now=True)
            sys.stdout.write("\x1b[H\x1b[2Jstopping the games... (q or Ctrl+C again: quit at once)\n")
            sys.stdout.flush()
            deadline = time.time() + 120
            try:
                while embedded.is_alive() and time.time() < deadline:
                    if read_key() in ("q", "Q", "\x03", "\x1b"):
                        break
                    embedded.join(0.2)
            except KeyboardInterrupt:
                pass
            if embedded.is_alive():
                kill_leftover_games()
                update_control(stop_now=False, stop=False)
                st = read_json(STATE_PATH, {})
                st["running"] = False
                write_json(STATE_PATH, st)
        if embedded is not None:
            try:
                os.remove(PID_PATH)
            except OSError:
                pass
        sys.stdout.write("\x1b[?25h\n")
        sys.stdout.flush()
        restore_input_mode(input_mode)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    p = sub.add_parser("import")
    p.add_argument("dirs", nargs="*")
    p.set_defaults(fn=cmd_import)
    sub.add_parser("retry").set_defaults(fn=cmd_retry)
    p = sub.add_parser("fetch")
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_fetch)
    p = sub.add_parser("start")
    p.add_argument("-n", type=int)
    p.add_argument("--mode", choices=MODES)
    p.set_defaults(fn=cmd_start)
    p = sub.add_parser("run")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("console")
    p.add_argument("-n", type=int)
    p.add_argument("--mode", choices=MODES)
    p.set_defaults(fn=cmd_console)
    p = sub.add_parser("instances")
    p.add_argument("n", type=int)
    p.set_defaults(fn=cmd_instances)
    sub.add_parser("pause").set_defaults(fn=cmd_pause)
    sub.add_parser("resume").set_defaults(fn=cmd_resume)
    p = sub.add_parser("stop")
    p.add_argument("--now", action="store_true")
    p.set_defaults(fn=cmd_stop)
    p = sub.add_parser("status")
    p.add_argument("-v", action="store_true")
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("mode")
    p.add_argument("mode", nargs="?", choices=MODES)
    p.set_defaults(fn=cmd_mode)
    args = ap.parse_args(sys.argv[1:] or ["console"])
    args.fn(args)


if __name__ == "__main__":
    main()
