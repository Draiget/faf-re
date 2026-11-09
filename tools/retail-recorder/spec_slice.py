"""Slice and bisect an RRS1 spec file (tools/retail-recorder/spec.py output).

The all-functions spec mode of the recorder DLL crashes the game for some
subset of the 3,916 hooked functions. The DLL reads one file
(RETAIL_RECORDER_SPEC), so the way to search for the bad hook is to write
smaller spec files and re-run the game until a minimal crashing set remains.

usage:
  spec_slice.py subset  <in.bin> <out.bin> <start> <end>     # entries [start,end)
  spec_slice.py every2  <in.bin> <outA.bin> <outB.bin>       # alternating halves
  spec_slice.py list    <in.bin>                             # one "index va" per line
  spec_slice.py keep    <in.bin> <out.bin> i,j,k,...         # only these indices
  spec_slice.py drop    <in.bin> <out.bin> i,j,k,...         # all but these indices
  spec_slice.py find    <in.bin> <index>                     # index -> va
"""
import struct
import sys

HEADER = 4 + 4
ENTRY_FIXED = 9
ARG = 4


def read_entries(path):
    data = open(path, "rb").read()
    if data[:4] not in (b"RRS1", b"RRS2"):
        raise SystemExit(f"{path}: not an RRS1/RRS2 file")
    (count,) = struct.unpack_from("<I", data, 4)
    rrs2 = data[:4] == b"RRS2"
    off = HEADER
    entries = []
    for _ in range(count):
        va, pop, prologue, ret, nargs = struct.unpack_from("<IHBBB", data, off)
        off += ENTRY_FIXED
        writes = data[off] if rrs2 else None
        if rrs2:
            off += 1
        args = data[off : off + nargs * ARG]
        off += nargs * ARG
        entries.append((va, pop, prologue, ret, nargs, writes, args))
    return entries


def write_entries(path, entries):
    rrs2 = entries and entries[0][5] is not None
    with open(path, "wb") as f:
        magic = b"RRS2" if rrs2 else b"RRS1"
        f.write(magic + struct.pack("<I", len(entries)))
        for va, pop, prologue, ret, nargs, writes, args in entries:
            f.write(struct.pack("<IHBBB", va, pop, prologue, ret, nargs))
            if rrs2:
                f.write(struct.pack("<B", writes))
            f.write(args)


def parse_indices(text):
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]
    if cmd == "list":
        for i, e in enumerate(read_entries(sys.argv[2])):
            print(f"{i} 0x{e[0]:08X} pop={e[1]} pro={e[2]} ret={e[3]} nargs={e[4]}")
    elif cmd == "find":
        entries = read_entries(sys.argv[2])
        i = int(sys.argv[3])
        print(f"{i} 0x{entries[i][0]:08X} pop={entries[i][1]} pro={entries[i][2]} ret={entries[i][3]} nargs={entries[i][4]}")
    elif cmd == "subset":
        entries = read_entries(sys.argv[2])
        start, end = int(sys.argv[4]), int(sys.argv[5])
        write_entries(sys.argv[3], entries[start:end])
        print(f"{sys.argv[3]}: entries [{start},{end}) = {min(end - start, len(entries) - start)}")
    elif cmd == "every2":
        entries = read_entries(sys.argv[2])
        write_entries(sys.argv[3], entries[0::2])
        write_entries(sys.argv[4], entries[1::2])
        print(f"{sys.argv[3]}: {len(entries[0::2])} even, {sys.argv[4]}: {len(entries[1::2])} odd")
    elif cmd in ("keep", "drop"):
        entries = read_entries(sys.argv[2])
        want = set(parse_indices(sys.argv[4]))
        kept = [e for i, e in enumerate(entries) if (i in want) == (cmd == "keep")]
        write_entries(sys.argv[3], kept)
        print(f"{sys.argv[3]}: {len(kept)} entries ({cmd} {sys.argv[4]})")
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
