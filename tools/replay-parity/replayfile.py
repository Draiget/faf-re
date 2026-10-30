"""Replay files and headless output, shared by the parity runner (parity.py, Windows) and the
CI parity tools (tools/parity-data, Linux): .fafreplay decoding, the replay header and command
stream, the checksums the live clients recorded, and the lines headless prints.
"""
import json
import re
import struct

def zstd_decompress(blob):
    """Imported on first use, so the tools that never meet a zstd replay run on any Python."""
    try:
        from compression import zstd  # Python 3.14+
        return zstd.decompress(blob)
    except ImportError:  # older Pythons with the zstandard package
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(blob)


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


def live_client_desync(recorded, beat, sim, theirs):
    """True when a mismatch is the live game's, not ours: at that beat more of the recorded
    clients agree with the sim than with the one that differs (26946725: nine clients and the
    sim on one checksum at beat 6700, Paulosan alone on another). `recorded` is
    replay_checksums() of the replay."""
    votes = recorded.get(beat, {})
    return len(votes.get(sim, [])) > len(votes.get(theirs, []))


MISMATCH_RE = re.compile(r"Checksum for beat (\d+) mismatched: ([0-9a-f]{32}) \(sim\) != ([0-9a-f]{32}) \((.*)\)\.")

# headless_x64.exe's output (src/headless/ReplayRunner.cpp, HeadlessMain.cpp), every line
# prefixed with "[<label>] ".
HL_LOADED_RE = re.compile(r"\] loaded in [\d.]+s")
HL_PROGRESS_RE = re.compile(r"\] beat (-?\d+) game time \d+:\d+:\d+ after")
HL_ENDED_RE = re.compile(r"\] GAME-ENDED beat (-?\d+)")
HL_SUMMARY_RE = re.compile(r"\] beats=\d+ last-beat=(-?\d+) game-over=(\w+)")
HL_VERDICT_RE = re.compile(r"\] VERDICT ended=(\w+) .*crash=(\w+)")
HL_TROUBLE_RE = re.compile(r"\] (?:FATAL|CRASH|ERROR) ")
