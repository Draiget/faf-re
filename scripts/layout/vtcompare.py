"""Compare vtable slot counts class-by-class between the shipped binary and ours.

The engine dispatches by slot index, so a class whose vtable is a different
shape in our build than in the original sends every call below the divergence to
the wrong function. Per-function audits never see it -- each body is faithful --
and the source-side detector that tried to count `virtual` declarations was
unusable (210 "mismatches" of 680, every large family a parser artifact:
implicit overrides, unresolved bases).

This compares image against image instead. No C++ is parsed, so there is nothing
to get wrong: read each vftable head out of the symbols, then walk forward while
each dword points into .text. The walk terminates on its own because MSVC places
the `??_R4` complete-object-locator pointer immediately *before* every vftable,
and that pointer is an .rdata address -- so the next table's header stops the
scan. Independently validated against TerrainCommon 15, UserEntity 17,
CTesselator 12, CDecalManager 30, CWldTerrainRes 77, CameraImpl 44.

Shipped heads come from the IDA callgraph index; ours come from main.pdb's
public symbol stream, which is scanned raw (S_PUB32 records) rather than through
DIA.
"""
from __future__ import annotations

import os
import re
import sqlite3
import struct
import sys
from collections import defaultdict

SHIPPED = r'G:/projects/faf-main/bin/2025.7.1/ForgedAlliance.exe'
OURS_EXE = r'C:/ProgramData/FAForever/bin/main.exe'
OURS_PDB = r'C:/ProgramData/FAForever/bin/main.pdb'
INDEX = r'G:/projects/faf-main/decomp/recovery/disasm/fa_full_2026_03_26/_callgraph_index.sqlite'


class Image:
    def __init__(self, path: str) -> None:
        with open(path, 'rb') as handle:
            self.data = handle.read()
        pe = struct.unpack_from('<I', self.data, 0x3C)[0]
        nsec = struct.unpack_from('<H', self.data, pe + 6)[0]
        optsize = struct.unpack_from('<H', self.data, pe + 20)[0]
        self.base = struct.unpack_from('<I', self.data, pe + 24 + 28)[0]
        self.sections = []
        offset = pe + 24 + optsize
        for _ in range(nsec):
            name = self.data[offset:offset + 8].rstrip(b'\0').decode('latin1')
            vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', self.data, offset + 8)
            self.sections.append((name, va, vsize, rawptr, rawsize))
            offset += 40
        self.text = next((s for s in self.sections if s[0] == '.text'), None)

    def file_offset(self, va: int):
        rva = va - self.base
        for _, sec_va, vsize, rawptr, rawsize in self.sections:
            if sec_va <= rva < sec_va + vsize:
                delta = rva - sec_va
                return rawptr + delta if delta < rawsize else None
        return None

    def in_text(self, va: int) -> bool:
        _, sec_va, vsize, _, _ = self.text
        return sec_va <= va - self.base < sec_va + vsize

    def slot_count(self, head_va: int, limit: int = 512) -> int:
        offset = self.file_offset(head_va)
        if offset is None:
            return -1
        count = 0
        while count < limit and offset + 4 <= len(self.data):
            entry = struct.unpack_from('<I', self.data, offset)[0]
            if not self.in_text(entry):
                break
            count += 1
            offset += 4
        return count


def pdb_public_symbols(path: str):
    """(section, offset, name) for every S_PUB32 record found by raw scan."""
    with open(path, 'rb') as handle:
        data = handle.read()
    marker = struct.pack('<H', 0x110E)
    printable = re.compile(rb'^[\x20-\x7e]+$')
    results = []
    cursor = 0
    size = len(data)
    while True:
        hit = data.find(marker, cursor)
        if hit < 0:
            break
        cursor = hit + 2
        if hit < 2:
            continue
        length = struct.unpack_from('<H', data, hit - 2)[0]
        if not 14 <= length <= 4096:
            continue
        end = hit - 2 + 2 + length
        if end > size:
            continue
        _flags, offset, section = struct.unpack_from('<IIH', data, hit + 2)
        if not 0 < section <= 16:
            continue
        name = data[hit + 12:end]
        terminator = name.find(b'\0')
        if terminator < 0:
            continue
        name = name[:terminator]
        if name and printable.match(name):
            results.append((section, offset, name.decode('latin1')))
    return results


def normalise(vtable_symbol: str):
    """'??_7CFoo@Moho@@6B@' -> ('CFoo', '') ; keep the MI base discriminator."""
    match = re.match(r'^\?\?_7(.+?)@6B(.*)@$', vtable_symbol)
    if not match:
        return None
    qualified, discriminator = match.group(1), match.group(2)
    parts = qualified.split('@')
    while parts and parts[-1] == '':
        parts.pop()
    if not parts:
        return None
    scopes = [p for p in parts[1:] if p.lower() not in ('moho', 'gpg')]
    name = parts[0] if not scopes else parts[0] + '::' + '::'.join(reversed(scopes))
    return name, discriminator


def shipped_vtables():
    connection = sqlite3.connect(INDEX)
    rows = connection.execute(
        "select from_name, min(from_ea) from incoming_xrefs "
        "where from_name like '??_7%' group by from_name"
    ).fetchall()
    connection.close()
    heads = {}
    for raw_name, address in rows:
        symbol = raw_name.split(' ')[0]
        key = normalise(symbol)
        if key and address:
            heads.setdefault(key, address)
    return heads


def our_vtables():
    image_sections = Image(OURS_EXE).sections
    section_va = {index + 1: sec[1] for index, sec in enumerate(image_sections)}
    heads = {}
    for section, offset, name in pdb_public_symbols(OURS_PDB):
        if not name.startswith('??_7') or section not in section_va:
            continue
        key = normalise(name)
        if key:
            heads.setdefault(key, 0x400000 + section_va[section] + offset)
    return heads


def main() -> int:
    shipped_image, our_image = Image(SHIPPED), Image(OURS_EXE)
    shipped, ours = shipped_vtables(), our_vtables()
    print(f'{len(shipped)} vtables in the shipped binary, {len(ours)} in ours')

    common = sorted(set(shipped) & set(ours))
    print(f'{len(common)} classes present in both\n')

    divergent = []
    for key in common:
        theirs = shipped_image.slot_count(shipped[key])
        mine = our_image.slot_count(ours[key])
        if theirs <= 0 or mine <= 0:
            continue
        if theirs != mine:
            divergent.append((mine - theirs, key, theirs, mine))

    divergent.sort(key=lambda row: (-abs(row[0]), row[1]))
    print(f'=== {len(divergent)} classes whose vtable is a different shape ===')
    for delta, (name, discriminator) in ((d, k) for d, k, _, _ in divergent):
        pass
    for delta, key, theirs, mine in divergent:
        name, discriminator = key
        tag = f' [base {discriminator}]' if discriminator else ''
        print(f'  {delta:+4d}   {name}{tag}: shipped {theirs}, ours {mine}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
