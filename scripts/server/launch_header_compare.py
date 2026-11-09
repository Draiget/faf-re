"""Compare the launch part of replay headers that the clients of one game wrote (plan WP2.10).

usage: launch_header_compare.py <replay> <replay> [...]

Each client of a lockstep game builds its launch info itself (`CLobby::LaunchGame`) and writes
it into its replay header (`VCR_CreateReplay`). The host builds it from the lobby's own Lua
tables; every other client from tables it rebuilt from the host's config bytes. This prints, for
each replay after the first, which header fields are byte-identical to the first's, and for the
Lua values (scenario info, army options) that are not, whether their content is the same in
another key order. A Lua table serialises in its iteration order, which depends on how the table
was built (insertions, growth), so a host and a joiner of one game differ in key order even when
every client is the original game.

Exit code 0 when every field of every replay is byte-identical to the first's.
"""
import struct
import sys

FIELDS = ("map", "mods", "scenario", "sources", "cheats", "armies", "seed")


def read_cstr(b, i):
    j = b.index(b"\0", i)
    return b[i:j], j + 1


def parse(path):
    """The header in VCR_CreateReplay's layout (src/moho/misc/SessionStartup.cpp)."""
    b = open(path, "rb").read()
    h = {}
    i = 0
    h["version"], i = read_cstr(b, i)
    _, i = read_cstr(b, i)
    i += 13  # "Replay v1.9\r\n"
    h["map"], i = read_cstr(b, i)
    _, i = read_cstr(b, i)
    n = struct.unpack_from("<i", b, i)[0]
    i += 4
    h["mods"] = b[i:i + n]
    i += n
    n = struct.unpack_from("<i", b, i)[0]
    i += 4
    h["scenario"] = b[i:i + n]
    i += n
    sources = []
    count = b[i]
    i += 1
    for _ in range(count):
        name, i = read_cstr(b, i)
        sources.append((name, struct.unpack_from("<i", b, i)[0]))
        i += 4
    h["sources"] = sources
    h["cheats"] = b[i]
    i += 1
    armies = []
    count = b[i]
    i += 1
    for _ in range(count):
        n = struct.unpack_from("<i", b, i)[0]
        i += 4
        options = b[i:i + n]
        i += n
        srcs = []
        while b[i] != 0xFF:
            srcs.append(b[i])
            i += 1
        i += 1
        armies.append((options, srcs))
    h["armies"] = armies
    h["seed"] = struct.unpack_from("<i", b, i)[0]
    return h


def decode(b, i=0):
    """One value of the SCR byte stream (LuaObject::ToByteStream)."""
    tag = b[i]
    i += 1
    if tag == 0:
        return struct.unpack_from("<f", b, i)[0], i + 4
    if tag == 1:
        j = b.index(b"\0", i)
        return b[i:j], j + 1
    if tag == 2:
        return None, i
    if tag == 3:
        return bool(b[i]), i + 1
    if tag == 4:
        entries = []
        while b[i] != 5:
            key, i = decode(b, i)
            value, i = decode(b, i)
            entries.append((key, value))
        return ("table", entries), i + 1
    raise ValueError("unknown tag %d" % tag)


def canonical(value):
    if isinstance(value, tuple) and value and value[0] == "table":
        return "{" + ",".join(sorted(canonical(k) + "=" + canonical(v) for k, v in value[1])) + "}"
    return repr(value)


def lua_same_content(a, b):
    return canonical(decode(a)[0]) == canonical(decode(b)[0])


def main():
    files = sys.argv[1:]
    if len(files) < 2:
        print(__doc__)
        return 2
    heads = [parse(f) for f in files]
    ref = heads[0]
    print("%s: %s, %d command sources, %d armies" % (files[0], ref["version"].decode(), len(ref["sources"]),
                                                     len(ref["armies"])))
    differing = 0
    for path, h in zip(files[1:], heads[1:]):
        notes = []
        for field in FIELDS:
            if h[field] == ref[field]:
                continue
            if field == "scenario" or field == "mods":
                notes.append("%s: %s" % (field, "same content, other key order" if lua_same_content(h[field], ref[field])
                                         else "CONTENT DIFFERS"))
            elif field == "armies" and len(h["armies"]) == len(ref["armies"]):
                for index, ((a, sa), (b, sb)) in enumerate(zip(h["armies"], ref["armies"])):
                    if sa != sb:
                        notes.append("army %d unit sources DIFFER" % index)
                    if a != b:
                        notes.append("army %d options: %s" % (index, "same content, other key order"
                                                              if lua_same_content(a, b) else "CONTENT DIFFERS"))
            else:
                notes.append("%s DIFFERS" % field)
        differing += 1 if notes else 0
        print("%s: %s" % (path, "every field byte-identical" if not notes else "; ".join(notes)))
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main())
