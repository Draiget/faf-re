"""Compare vtables slot by slot, by method name, between the shipped image and ours.

Counting slots is not enough: CScApp has seven in both binaries and still holds a
different method in slot 1, and CMauiControl's twenty-five were a whole
permutation. What matters is which method sits in which slot, so this aligns the
two tables entry by entry and reports the first index where the names disagree.

Names are reduced to a bare identifier on both sides -- IDA's
`Moho::Class::Method` and MSVC's `?Method@Class@moho@@...` -- and destructors on
either side collapse to `~`, since IDA calls them `dtr` and MSVC emits `??_E`
or `??_G` thunks.

Two sources of noise are filtered rather than reported:
  * slots IDA never named. A class is skipped if the shipped side has unnamed
    entries, because an empty string cannot be compared against anything.
  * tables the forward walk over-ran. It normally stops at the next vftable's
    `??_R4` pointer, but where two sibling tables are adjacent with no locator
    between them (PausedChildThread/PausedMainThread) it keeps going, and the
    tail it invents is exactly the unnamed-slot case above.
"""
import bisect
import re
import sqlite3
import struct
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vtcompare import (Image, shipped_vtables, our_vtables, pdb_public_symbols,  # noqa: E402
                       SHIPPED, OURS_EXE, OURS_PDB, INDEX)


def shipped_names():
    connection = sqlite3.connect(INDEX)
    table = {ea: (dn or fn or '')
             for ea, fn, dn in connection.execute(
                 'select start_ea, function_name, demangled_name from functions')}
    connection.close()
    return table


def our_symbol_lookup(image):
    section_va = {i + 1: s[1] for i, s in enumerate(image.sections)}
    pairs = sorted((0x400000 + section_va[s] + o, n)
                   for s, o, n in pdb_public_symbols(OURS_PDB) if s in section_va)
    addresses = [a for a, _ in pairs]

    def lookup(va):
        index = bisect.bisect_right(addresses, va) - 1
        return pairs[index][1] if index >= 0 and pairs[index][0] == va else ''
    return lookup


def shipped_method(name):
    if not name:
        return ''
    if re.match(r'^(sub|loc|j_sub)_[0-9A-Fa-f]+$', name):
        return ''          # IDA never named it; nothing to compare against
    if name.startswith('_purecall') or name == '_purecall':
        return '_purecall'
    tail = name.split('::')[-1].replace(' ', '_')
    if tail in ('dtr',) or tail.startswith('~'):
        return '~'
    return tail


def our_method(symbol):
    if not symbol:
        return ''
    if 'purecall' in symbol:
        return '_purecall'
    if symbol.startswith('??_E') or symbol.startswith('??_G') or symbol.startswith('??1'):
        return '~'
    match = re.match(r'^\?([A-Za-z_]\w*)@', symbol)
    return match.group(1) if match else symbol


def main():
    shipped_image, our_image = Image(SHIPPED), Image(OURS_EXE)
    names = shipped_names()
    osym = our_symbol_lookup(our_image)
    shipped, ours = shipped_vtables(), our_vtables()

    findings = []
    skipped_unnamed = 0
    for key in sorted(set(shipped) & set(ours)):
        cls, discriminator = key
        if cls.startswith('wx') or cls.startswith('?') or 'Wm3' in cls:
            continue
        theirs = shipped_image.slot_count(shipped[key])
        mine = our_image.slot_count(ours[key])
        if theirs <= 0 or mine <= 0:
            continue

        s_off = shipped_image.file_offset(shipped[key])
        o_off = our_image.file_offset(ours[key])
        s_names, o_names = [], []
        for i in range(theirs):
            s_names.append(shipped_method(names.get(
                struct.unpack_from('<I', shipped_image.data, s_off + 4 * i)[0], '')))
        for i in range(mine):
            o_names.append(our_method(
                osym(struct.unpack_from('<I', our_image.data, o_off + 4 * i)[0])))

        if s_names.count('') > max(2, theirs // 3):
            skipped_unnamed += 1
            continue

        first = None
        for i in range(min(theirs, mine)):
            if s_names[i] and o_names[i] and s_names[i] != o_names[i]:
                first = i
                break
        if first is None and theirs == mine:
            continue
        findings.append((first if first is not None else min(theirs, mine),
                         cls, discriminator, theirs, mine, s_names, o_names))

    findings.sort(key=lambda f: (f[0], f[1]))
    print(f'{len(findings)} engine classes disagree; {skipped_unnamed} skipped '
          f'(shipped side has slots IDA never named)\n')
    for first, cls, disc, theirs, mine, s_names, o_names in findings:
        tag = f' [base {disc}]' if disc else ''
        print(f'{cls}{tag}: shipped {theirs} slots, ours {mine}; first divergence at slot {first}')
        for i in range(max(0, first), min(max(theirs, mine), first + 4)):
            left = s_names[i] if i < theirs else '--'
            right = o_names[i] if i < mine else '--'
            mark = ' ' if left == right else '*'
            print(f'   {mark} {i:3d}  {left:32s} | {right}')
        print()


if __name__ == '__main__':
    main()
