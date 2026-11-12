#!/usr/bin/env python3
"""glibc version requirements of ELF files, and making the newest weak (issue #394; from Julian
Cooper's faf-re fork, tools/linux-build/elf_weak_versions.py).

    elf_glibc_versions.py --max 2.34 --report FILE...     list each GLIBC_ requirement; fail when one
                                                          newer than --max is not weak
    elf_glibc_versions.py --max 2.34 --weaken FILE...     mark the GLIBC_ requirements newer than --max
                                                          weak (VER_FLG_WEAK), in place

A weak version requirement that the C library lacks is not an error when the dynamic linker loads the
file (glibc's dl-version.c); the symbols bound to that version then resolve to another object's
unversioned definition. tools/release/linux/package.sh weakens Microsoft's DXC libraries' GLIBC_2.36
and GLIBC_2.38 requirements, and adds libfaf-glibc-compat.so (glibc_compat.c) with those symbols, so
the Linux download runs on glibc 2.34. On a newer glibc nothing changes: the requirements are met and
glibc's own functions are used.

Reads the dynamic segment (DT_VERNEED, DT_VERNEEDNUM, DT_STRTAB), so it needs no section headers.
ELF64 little-endian (x86-64) only.
"""
import argparse
import struct
import sys

PT_LOAD = 1
PT_DYNAMIC = 2
DT_NULL = 0
DT_STRTAB = 5
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
VER_FLG_WEAK = 0x2


def parse_version(text):
    return tuple(int(part) for part in text.split("."))


class Elf:
    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not an ELF64 little-endian file")
        self.data = data
        (self.phoff,) = struct.unpack_from("<Q", data, 0x20)
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 0x36)
        self.segments = []
        for index in range(self.phnum):
            p_type, _flags, offset, vaddr, _paddr, filesz, _memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", data, self.phoff + index * self.phentsize)
            self.segments.append((p_type, offset, vaddr, filesz))

    def offset_of(self, vaddr):
        for p_type, offset, seg_vaddr, filesz in self.segments:
            if p_type == PT_LOAD and seg_vaddr <= vaddr < seg_vaddr + filesz:
                return offset + (vaddr - seg_vaddr)
        raise ValueError(f"address {vaddr:#x} is in no PT_LOAD segment")

    def dynamic(self):
        entries = {}
        for p_type, offset, _vaddr, filesz in self.segments:
            if p_type != PT_DYNAMIC:
                continue
            for pos in range(offset, offset + filesz, 16):
                tag, value = struct.unpack_from("<qQ", self.data, pos)
                if tag == DT_NULL:
                    break
                entries.setdefault(tag, value)
        return entries

    def string(self, strtab, index):
        start = strtab + index
        end = self.data.index(b"\0", start)
        return self.data[start:end].decode()

    def requirements(self):
        """(file, version name, flags, offset of vna_flags) for every version requirement."""
        dyn = self.dynamic()
        if DT_VERNEED not in dyn:
            return []
        strtab = self.offset_of(dyn[DT_STRTAB])
        pos = self.offset_of(dyn[DT_VERNEED])
        out = []
        for _ in range(dyn.get(DT_VERNEEDNUM, 0)):
            _version, count, file_index, aux, next_need = struct.unpack_from("<HHIII", self.data, pos)
            library = self.string(strtab, file_index)
            aux_pos = pos + aux
            for _ in range(count):
                _hash, flags, _other, name_index, next_aux = struct.unpack_from("<IHHII", self.data, aux_pos)
                out.append((library, self.string(strtab, name_index), flags, aux_pos + 4))
                aux_pos += next_aux
            if next_need == 0:
                break
            pos += next_need
        return out


def glibc_version(name):
    if not name.startswith("GLIBC_") or not name[6:7].isdigit():
        return None
    return parse_version(name[6:])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max", required=True, help="newest glibc version the files may require (e.g. 2.34)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--report", action="store_true")
    mode.add_argument("--weaken", action="store_true")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    limit = parse_version(args.max)

    failed = False
    for path in args.files:
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        elf = Elf(data)
        newest = None
        changed = []
        for library, name, flags, flags_pos in elf.requirements():
            version = glibc_version(name)
            if version is None:
                continue
            if version > limit:
                if args.weaken and not flags & VER_FLG_WEAK:
                    flags |= VER_FLG_WEAK
                    struct.pack_into("<H", data, flags_pos, flags)
                    changed.append(f"{library} {name}")
                if not flags & VER_FLG_WEAK:
                    print(f"{path}: needs {name} ({library}), newer than {args.max}", file=sys.stderr)
                    failed = True
                continue
            if newest is None or version > newest[0]:
                newest = (version, name)
        if changed:
            with open(path, "wb") as handle:
                handle.write(data)
            print(f"{path}: weakened {', '.join(changed)}")
        print(f"{path}: newest required (non-weak) glibc version: {newest[1] if newest else 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
