"""Dump a vtable out of OUR built main.exe, with names resolved from main.pdb."""
import bisect
import struct
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vtcompare import Image, OURS_EXE, OURS_PDB, pdb_public_symbols, our_vtables, normalise  # noqa: E402

_image = Image(OURS_EXE)
_section_va = {i + 1: s[1] for i, s in enumerate(_image.sections)}

_syms = []
for section, offset, name in pdb_public_symbols(OURS_PDB):
    if section in _section_va:
        _syms.append((0x400000 + _section_va[section] + offset, name))
_syms.sort()
_addrs = [a for a, _ in _syms]


def symbol_for(va):
    index = bisect.bisect_right(_addrs, va) - 1
    if index < 0:
        return '?'
    base, name = _syms[index]
    return name if base == va else f'{name}+0x{va - base:X}'


def dump(class_name, discriminator=''):
    heads = our_vtables()
    key = (class_name, discriminator)
    if key not in heads:
        print(f'{class_name}: no vtable in our image')
        return
    head = heads[key]
    count = _image.slot_count(head)
    print(f'\n=== ours {class_name}: 0x{head:08X}, {count} slots')
    offset = _image.file_offset(head)
    for slot in range(count):
        value = struct.unpack_from('<I', _image.data, offset + 4 * slot)[0]
        print(f'   slot {slot}: 0x{value:08X}  {symbol_for(value)}')


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        dump(arg)
