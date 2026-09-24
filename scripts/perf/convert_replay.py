"""Convert a .fafreplay (FAF vault download) into the .scfareplay the engine's /replay reads.

usage: convert_replay.py <in.fafreplay> <out.scfareplay> [--as-version NNNN] [--map-from OLD --map-to NEW]

.fafreplay = one JSON header line, then either base64(4-byte BE length + zlib) (older files) or a raw
zstd frame ("compression": "zstd", newer files; needs `pip install zstandard`).

The engine only loads a replay whose first string equals "Supreme Commander v1.50.<GameVersion>" of
the running game (SessionStartup.cpp VCR_SetupReplaySession). --as-version rewrites that string so
a replay from a nearby FAF version loads. It will then desync (the engine logs "Checksum for beat N
mismatched") unless the local gamedata really is that version - fine for load profiling, useless for
determinism checks.
"""
import argparse
import base64
import json
import struct
import zlib


def decode(path):
    raw = open(path, "rb").read()
    newline = raw.index(b"\n")
    header = json.loads(raw[:newline])
    body = raw[newline + 1:]
    if header.get("compression") == "zstd" or body[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard
        return header, zstandard.ZstdDecompressor().decompressobj().decompress(body)
    blob = base64.b64decode(body)
    expected = struct.unpack(">I", blob[:4])[0]
    data = zlib.decompress(blob[4:])
    assert len(data) == expected, (len(data), expected)
    return header, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--as-version")
    ap.add_argument("--map-from")
    ap.add_argument("--map-to")
    args = ap.parse_args()
    header, data = decode(args.src)
    version = data[:data.index(b"\0")]
    print("replay:", header.get("title"), "| map", header.get("mapname"), "| players", header.get("num_players"),
          "|", version.decode("latin1"))
    if args.as_version:
        prefix = b"Supreme Commander v1.50."
        assert version.startswith(prefix) and len(args.as_version) == len(version) - len(prefix)
        data = prefix + args.as_version.encode() + data[len(version):]
    if args.map_from:
        old, new = args.map_from.encode(), args.map_to.encode()
        assert len(old) == len(new), "map path must keep its length (strings are length-prefixed)"
        data = data.replace(old, new)
    open(args.dst, "wb").write(data)
    print("wrote", args.dst, len(data), "bytes")


if __name__ == "__main__":
    main()
