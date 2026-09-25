"""Census of the pixel formats of every DDS texture the game can load.

A Direct3D 10/11 texture loader has no equivalent for several legacy D3D9
formats (24-bit RGB, luminance, 16-bit packed), so it has to know which of
them the data actually uses. This reads only the 128-byte header of each DDS:
archive members are opened as streams and never fully decompressed, and the
.scmap files are searched for embedded DDS blobs.

Usage:
    python scripts/effects/dds_format_census.py [--game DIR] [--faf DIR]

Defaults are the Steam install and the FAF client's gamedata directory.
"""
import argparse
import collections
import glob
import os
import struct
import zipfile

DEFAULT_GAME = r"G:\games\steamapps\common\supreme commander forged alliance"
DEFAULT_FAF = r"C:\ProgramData\FAForever\gamedata"

DDPF_ALPHA = 0x2
DDPF_FOURCC = 0x4
DDPF_RGB = 0x40
DDPF_LUMINANCE = 0x20000
DDPF_BUMPDUDV = 0x80000
DDSCAPS2_CUBEMAP = 0x200
DDSCAPS2_VOLUME = 0x200000

D3DFMT_NUMERIC = {
    36: "A16B16G16R16", 110: "Q16W16V16U16", 111: "R16F", 112: "G16R16F",
    113: "A16B16G16R16F", 114: "R32F", 115: "G32R32F", 116: "A32B32G32R32F",
}

# What a Direct3D 10/11 loader has to do with each format.
DXGI_VERDICT = {
    "DXT1": "BC1", "DXT3": "BC2", "DXT5": "BC3",
    "DXT2": "BC2, premultiplied (no DXGI flag)", "DXT4": "BC3, premultiplied (no DXGI flag)",
    "ATI1": "BC4", "ATI2": "BC5", "BC4U": "BC4", "BC5U": "BC5",
    "A8R8G8B8": "B8G8R8A8", "X8R8G8B8": "B8G8R8X8",
    "A8B8G8R8": "R8G8B8A8", "X8B8G8R8": "R8G8B8A8, force alpha",
    "R8G8B8": "NO DXGI FORMAT - expand to 32bpp",
    "L8": "NO DXGI FORMAT - expand, or R8 plus a swizzle",
    "A8L8": "NO DXGI FORMAT - expand, or R8G8 plus a swizzle",
    "A8": "A8",
    "R5G6B5": "B5G6R5 needs DXGI 1.2 (Windows 8), else expand",
    "A1R5G5B5": "B5G5R5A1 needs DXGI 1.2 (Windows 8), else expand",
    "X1R5G5B5": "B5G5R5A1 needs DXGI 1.2 (Windows 8), else expand",
    "A4R4G4B4": "B4G4R4A4 needs DXGI 1.2 (Windows 8), else expand",
    "P8": "NO DXGI FORMAT - expand", "V8U8": "R8G8_SNORM", "Q8W8V8U8": "R8G8B8A8_SNORM",
    "DX10": "DX10 extended header",
    "MALFORMED": "header dwSize/ddspf.dwSize wrong - strict loaders reject it",
}


def classify(header: bytes) -> str:
    """Returns "<format>|<2d|cube|volume>" for one DDS header."""
    if len(header) < 128 or header[:4] != b"DDS ":
        return "NOT_DDS|-"
    header_size = struct.unpack_from("<I", header, 4)[0]
    pf_size, pf_flags, fourcc, bits, rmask, gmask, bmask, amask = struct.unpack_from("<II4sIIIII", header, 76)
    caps2 = struct.unpack_from("<I", header, 112)[0]
    shape = "cube" if caps2 & DDSCAPS2_CUBEMAP else ("volume" if caps2 & DDSCAPS2_VOLUME else "2d")
    if header_size != 124 or pf_size != 32:
        return f"MALFORMED|{shape}"
    if pf_flags & DDPF_FOURCC:
        code = struct.unpack_from("<I", header, 84)[0]
        name = D3DFMT_NUMERIC.get(code) or fourcc.decode("latin1", "replace")
    elif pf_flags & DDPF_BUMPDUDV:
        name = {16: "V8U8", 32: "Q8W8V8U8"}.get(bits, f"DUDV{bits}")
    elif pf_flags & DDPF_LUMINANCE:
        name = "A8L8" if (bits == 16 and amask) else ("L8" if bits == 8 else f"L{bits}")
    elif pf_flags & DDPF_RGB:
        if bits == 32:
            if rmask == 0x00FF0000:
                name = "A8R8G8B8" if amask else "X8R8G8B8"
            elif rmask == 0x000000FF:
                name = "A8B8G8R8" if amask else "X8B8G8R8"
            else:
                name = f"RGB32({rmask:x},{gmask:x},{bmask:x},{amask:x})"
        elif bits == 24:
            name = "R8G8B8"
        elif bits == 16:
            name = {0xF800: "R5G6B5", 0x0F00: "A4R4G4B4"}.get(rmask)
            if rmask == 0x7C00:
                name = "A1R5G5B5" if amask else "X1R5G5B5"
            name = name or f"RGB16({rmask:x})"
        elif bits == 8:
            name = "P8"
        else:
            name = f"RGB{bits}"
    elif pf_flags & DDPF_ALPHA:
        name = "A8"
    else:
        name = f"flags{pf_flags:x}"
    return f"{name}|{shape}"


def scan_archive(path, counts, examples):
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return 0
    scanned = 0
    with archive:
        for info in archive.infolist():
            if not info.filename.lower().endswith(".dds"):
                continue
            with archive.open(info) as member:
                key = classify(member.read(128))
            counts[key] += 1
            examples.setdefault(key, f"{os.path.basename(path)}:{info.filename}")
            scanned += 1
    return scanned


def scan_map(path, counts, examples):
    with open(path, "rb") as handle:
        data = handle.read()
    scanned = 0
    position = data.find(b"DDS |\x00\x00\x00")
    while position != -1:
        key = classify(data[position:position + 128])
        counts[key] += 1
        examples.setdefault(key, os.path.basename(path))
        scanned += 1
        position = data.find(b"DDS |\x00\x00\x00", position + 4)
    return scanned


def report(label, total, counts, examples):
    print(f"== {label}: {total} DDS")
    for key, count in counts.most_common():
        name = key.split("|")[0]
        print(f"  {count:6d}  {key:22s} {DXGI_VERDICT.get(name, '?'):50s} e.g. {examples[key]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--game", default=DEFAULT_GAME, help="Forged Alliance install directory")
    parser.add_argument("--faf", default=DEFAULT_FAF, help="FAF client gamedata directory")
    args = parser.parse_args()

    groups = (
        ("retail gamedata/*.scd", sorted(glob.glob(os.path.join(args.game, "gamedata", "*.scd")))),
        ("FAF *.nx2 / *.nxt", sorted(glob.glob(os.path.join(args.faf, "*.nx2")) + glob.glob(os.path.join(args.faf, "*.nxt")))),
    )
    for label, archives in groups:
        counts, examples = collections.Counter(), {}
        total = sum(scan_archive(path, counts, examples) for path in archives)
        report(label, total, counts, examples)

    maps = sorted(glob.glob(os.path.join(args.game, "maps", "*", "*.scmap")))
    counts, examples = collections.Counter(), {}
    total = sum(scan_map(path, counts, examples) for path in maps)
    report(f"retail maps ({len(maps)} .scmap)", total, counts, examples)


if __name__ == "__main__":
    main()
