"""What the CI parity tools share: the corpus file, the replay checks of the parity runner,
downloads from FAF, the run-time estimate and the core and extended sets."""
import gzip
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "replay-parity"))
from replayfile import decode_fafreplay, header_summary, replay_beats, replay_body_info  # noqa: E402

# Cloudflare in front of FAF refuses Python's default user agent (error 1010).
USER_AGENT = "faf-re-parity-data/1.0 (+https://github.com/Draiget/faf-re)"
REPLAY_URL = "https://replay.faforever.com/%d"
MOD_URL = "https://content.faforever.com/mods/%s.zip"
MAP_URL = "https://content.faforever.com/maps/%s.zip"


def clock(seconds):
    """1:02:03 or 2:03, for game and wall times."""
    s = int(round(seconds))
    return "%d:%02d:%02d" % (s // 3600, s // 60 % 60, s % 60) if s >= 3600 else "%d:%02d" % (s // 60, s % 60)


def speed(entry):
    """A result's game time, wall time and speedup (game seconds per wall second) as text, or None
    when it did not play a beat. Wall time runs from launch to exit, loading included."""
    if not entry.get("game_s") or not entry.get("wall_s"):
        return None
    return "game %s, wall %s, x%.1f" % (clock(entry["game_s"]), clock(entry["wall_s"]), entry["game_s"] / entry["wall_s"])


def map_url(folder):
    """Many vault map folders have spaces ("flat 512"): quoted, as FAF serves them."""
    return MAP_URL % urllib.parse.quote(folder)

# FAF's game files by version, as the FAF client's updater fetches them: <package>.<version>.nx2
# and init_faf_<version>.lua. Public: no sign-in.
GAME_URL = "https://content.faforever.com/faf/updaterNew/updates_faf_files/%s"

# docs/PR_REPLAY_CHECK.md (also tools/replay-parity/parity.py).
CORE_SET = [26902315, 26930624, 26943656, 26883423, 26881085, 26928211, 26989770, 26897073]
EXTENDED_SET = [26975290, 26953273, 27034831, 26917867, 26876279, 26935800, 26898759,
                27004084, 26915859, 26905122]

# Corpus columns (corpus/<version>.tsv.gz, one replay per line, made by corpus.py build).
# map_kind: retail (a map the game ships) or cached (a top vault map), both in the maps cache,
# or download (fetched by the job that plays the replay).
CORPUS_COLUMNS = ("id", "ticks", "players", "map", "map_kind")


def read_corpus(path):
    rows = {}
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            values = line.rstrip("\n").split("\t")
            row = dict(zip(CORPUS_COLUMNS, values))
            row["id"] = int(row["id"])
            row["ticks"] = int(row["ticks"])
            row["players"] = int(row["players"])
            rows[row["id"]] = row
    return rows


def bucket_of(replay_id):
    """Replays are cached in buckets of 10,000 ids: a new replay changes one bucket's cache."""
    return replay_id // 10000


def estimate_seconds(ticks, players, m28=False):
    """Wall time of one replay on one core, from its length and player count. Fitted to the
    WSL box's runs (26897073, 12 players: ~650 s; 26902315, 3 players: ~50 s); report.py prints
    the fit of a real run's times, to replace these numbers."""
    seconds = 5 + ticks * (0.0015 + 0.004 * max(players, 1))
    return seconds * (3.0 if m28 else 1.0)


def fetch(url, dest, delay=1.0, attempts=3):
    """Downloads url to dest (via dest.part), then waits `delay` seconds: one request at a time,
    spaced out, so the FAF servers see a slow trickle. Returns the size, or raises."""
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    tmp = dest + ".part"
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=300) as resp, open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
            os.replace(tmp, dest)
            time.sleep(delay)
            return os.path.getsize(dest)
        except urllib.error.HTTPError as exc:
            time.sleep(delay)
            if exc.code in (403, 404, 410):
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(delay * (attempt + 2) * 5)
            if attempt == attempts - 1:
                raise
    raise RuntimeError("download failed: %s" % url)


def check_replay(raw, game_version):
    """The parity runner's checks (parity.py prepare): returns (info, reason, scfareplay bytes);
    reason is None when the replay is ready to play."""
    try:
        header, data = decode_fafreplay(raw)
        summary = header_summary(header)
        body = replay_body_info(data)
    except Exception as exc:
        return {}, "unreadable: %s" % str(exc)[:80], None
    info = {"map": body["map"], "m28": None, "players": summary["players"]}
    if summary["mod"] != "faf":
        return info, "featured mod %s" % summary["mod"], None
    if body["version"] != "Supreme Commander v1.50.%d" % game_version:
        return info, "engine version %s" % body["version"], None
    for mod in body["mods"]:
        if mod["name"].lower() == "m28ai" and isinstance(mod["version"], float):
            info["m28"] = int(mod["version"])
        else:
            return info, "sim mod %s" % mod["name"], None
    if not body["map"]:
        return info, "map path %s" % body["scmap"], None
    try:
        info["beats"] = replay_beats(data)
    except (ValueError, IndexError):
        info["beats"] = None  # the engine is the judge of a damaged stream; only the length is unknown
    return info, None, data


def has_scenario(path):
    """Whether path is a map folder: the engine skips one without a <name>_scenario.lua in it."""
    try:
        return any(n.lower().endswith("_scenario.lua") for n in os.listdir(path))
    except OSError:
        return False


def extract_map(zip_path, maps_dir, folder):
    """A map zip into maps_dir/<folder>: the zip's folder holding the scenario file, renamed to the
    replay's name for it. The names may differ in case alone (FAF's retail maps are SCMP_015/, the
    replay says scmp_015), and the folder need not be at the top (FAF's scmp_001 zip has
    SC/Supreme Commander - Forged Alliance/maps/SCMP_001/)."""
    raw = os.path.join(maps_dir, ".unzip-" + folder)
    shutil.rmtree(raw, ignore_errors=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(raw)
    found = [d for d, _, _ in os.walk(raw) if has_scenario(d)]
    named = [d for d in found if os.path.basename(d).lower() == folder.lower()]
    if len(named) != 1 and len(found) != 1:
        shutil.rmtree(raw, ignore_errors=True)
        raise ValueError("no one map folder %s in the map zip (%d with a scenario file)" % (folder, len(found)))
    path = os.path.join(maps_dir, folder)
    shutil.rmtree(path, ignore_errors=True)
    os.replace((named or found)[0], path)
    shutil.rmtree(raw, ignore_errors=True)
    return path


def find_mod_info(root):
    """The folder under root that holds mod_info.lua (an M28AI version's mod folder)."""
    for dirpath, _, files in os.walk(root):
        if "mod_info.lua" in files:
            return dirpath
    return None
