"""Compare each class's RTTI base-class list between the shipped image and ours.

A wrong vtable slot sends a call to the wrong function; a wrong *base class*
moves every field in the object. That is the failure mode that corrupts memory
rather than merely misbehaving, so it is worth checking the same way the vtables
were: image against image, with no C++ parsed.

MSVC's RTTI carries exactly what is needed. For each class:

    ??_R3<name>@@8   ClassHierarchyDescriptor { sig, attrs, numBases, pBaseArray }
    ??_R2<name>@@8   BaseClassArray          -> numBases pointers to ??_R1
    ??_R1...@8       BaseClassDescriptor     { pTypeDescriptor, numContained,
                                               PMD{ mdisp, pdisp, vdisp }, attrs }
    ??_R0?AV<name>@@@8  TypeDescriptor       { pVFTable, spare, ".?AV<name>@@" }

`mdisp` is the base's byte offset inside the derived object, so the ordered list
of (base name, mdisp) is a direct statement of the layout. These are absolute
VAs on x86, not RVAs.

Shipped descriptor addresses come from the IDA index, ours from main.pdb's
public symbols; the class name in the type descriptor is what the two sides are
matched on, after folding the Moho/moho namespace spelling.
"""
import re
import sqlite3
import struct
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vtcompare import Image, pdb_public_symbols, SHIPPED, OURS_EXE, OURS_PDB, INDEX  # noqa: E402


def read_u32(image, va):
    offset = image.file_offset(va)
    if offset is None or offset + 4 > len(image.data):
        return None
    return struct.unpack_from('<I', image.data, offset)[0]


def type_descriptor_name(image, va):
    """TypeDescriptor: pVFTable, spare, then the decorated name."""
    offset = image.file_offset(va)
    if offset is None:
        return None
    end = image.data.find(b'\0', offset + 8)
    if end < 0 or end - (offset + 8) > 512:
        return None
    try:
        return image.data[offset + 8:end].decode('latin1')
    except Exception:                                              # noqa: BLE001
        return None


def base_list(image, hierarchy_va):
    """(name, mdisp) for every base in the class hierarchy descriptor."""
    count = read_u32(image, hierarchy_va + 8)
    array = read_u32(image, hierarchy_va + 12)
    if not count or not array or count > 64:
        return None
    out = []
    for index in range(count):
        descriptor = read_u32(image, array + 4 * index)
        if not descriptor:
            return None
        type_va = read_u32(image, descriptor)
        mdisp = read_u32(image, descriptor + 8)
        name = type_descriptor_name(image, type_va) if type_va else None
        if name is None:
            return None
        out.append((name, mdisp))
    return out


def normalise(decorated):
    """'.?AVCameraImpl@Moho@@' -> 'CameraImpl@moho'."""
    body = decorated[4:] if decorated.startswith('.?A') else decorated
    body = body.rstrip('@')
    parts = [p for p in body.split('@') if p]
    if not parts:
        return decorated
    parts = [parts[0]] + [p.lower() if p.lower() in ('moho', 'gpg', 'std', 'boost') else p
                          for p in parts[1:]]
    return '@'.join(parts)


def hierarchy_from_vftable(image, head_va):
    """MSVC puts the ??_R4 locator pointer immediately before every vftable.

    IDA never named the RTTI structures in this export, so they are reached
    structurally instead: locator -> { sig, offset, cdOffset, pTypeDescriptor,
    pClassDescriptor }. Only the offset-0 locator describes the complete object;
    a secondary base's sub-object vftable points at the same class descriptor
    but with a non-zero `offset`, and is skipped.
    """
    locator = read_u32(image, head_va - 4)
    if not locator:
        return None
    if read_u32(image, locator + 4):            # sub-object table, not the whole class
        return None
    type_va = read_u32(image, locator + 12)
    hierarchy = read_u32(image, locator + 16)
    if not type_va or not hierarchy:
        return None
    name = type_descriptor_name(image, type_va)
    return (name, hierarchy) if name else None


def main():
    shipped_image, our_image = Image(SHIPPED), Image(OURS_EXE)
    from vtcompare import shipped_vtables, our_vtables
    def collect(image, heads):
        out = {}
        for head in heads:
            found = hierarchy_from_vftable(image, head)
            if not found:
                continue
            name, hierarchy = found
            bases = base_list(image, hierarchy)
            if bases:
                out.setdefault(normalise(name), [(normalise(n), d) for n, d in bases])
        return out
    s_by_key = collect(shipped_image, set(shipped_vtables().values()))
    o_by_key = collect(our_image, set(our_vtables().values()))
    print(f'{len(s_by_key)} class hierarchies decoded in the shipped image, {len(o_by_key)} in ours')
    print(f'{len(s_by_key)} / {len(o_by_key)} decoded; '
          f'{len(set(s_by_key) & set(o_by_key))} classes in both\n')

    findings = []
    for key in sorted(set(s_by_key) & set(o_by_key)):
        if key.startswith('wx') or 'Wm3' in key or key.startswith('?'):
            continue
        theirs, mine = s_by_key[key], o_by_key[key]
        if theirs != mine:
            findings.append((key, theirs, mine))

    print(f'=== {len(findings)} classes whose base-class layout differs ===')
    for key, theirs, mine in findings:
        print(f'\n{key}')
        print(f'   shipped: {theirs}')
        print(f'   ours   : {mine}')


if __name__ == '__main__':
    main()
