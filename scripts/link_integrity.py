"""Check what /FORCE is hiding in main.exe's link, without running a link.

main.vcxproj sets ForceFileOutput (/FORCE) and passes /IGNORE:4006, because the
recovery tree has historically had unresolved externals.  The cost is that two
whole classes of link error become invisible:

  * /FORCE:UNRESOLVED  -- a call to a symbol nothing defines still links.  It
    lands on an arbitrary address, and the crash surfaces inside a completely
    unrelated function, which is indistinguishable from memory corruption.  This
    cost three crash reports before it was found: a probe declared
    `SndDiagIsRegisteredParams(const void*)` while its definition wrote
    `const void* const`, MSVC encoded the top-level const in the decorated name
    (PBX vs QBX), and the call jumped into a wxWidgets hash-table method.

  * /FORCE:MULTIPLE   -- a symbol defined by two translation units is neither an
    error (LNK2005) nor, with /IGNORE:4006, a warning.  The linker keeps the
    first definition and drops the second silently.  Both copies still emit a
    dynamic initializer and an atexit destructor against the one surviving
    storage, so a duplicated container global gets constructed twice and freed
    twice.

Both are read straight out of the COFF symbol tables of the object files, so
this needs no link step and no PDB -- only a prior compile.  Run it after any
change that adds a definition, a declaration, or a project file entry:

    python scripts/link_integrity.py

Exit status is 1 if anything is reported.

Two things make a naive scan of the intermediate directory wrong, and both have
produced false alarms here:

  * MSBuild never deletes objects for sources that were renamed or marked
    ExcludedFromBuild, so the directory accumulates stale ones the linker never
    sees (CrtRuntimeHelpers.obj, SPhysBodyReflection.obj).  The object list is
    therefore derived from the live ClCompile items.
  * A symbol missing from every object is usually supplied by an import
    library, so the .lib archives on the link line are read too.
"""
from __future__ import annotations

import argparse
import glob
import os
import struct
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

MSBUILD_NS = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SYM_CLASS_EXTERNAL = 2

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CoffObject:
    """Just enough COFF to answer 'what does this object define and need'."""

    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, 'rb') as handle:
            self._data = handle.read()
        self._valid = False
        if len(self._data) < 20:
            return

        machine, sections = struct.unpack_from('<HH', self._data, 0)
        if machine == 0 and sections == 0xFFFF:      # ANON_OBJECT_HEADER_BIGOBJ
            if struct.unpack_from('<H', self._data, 4)[0] < 2:
                return
            self._sections = struct.unpack_from('<I', self._data, 32)[0]
            self._sym_ptr, self._nsyms = struct.unpack_from('<II', self._data, 44)
            self._sec_start, self._sym_size, self._sect_fmt = 56, 20, '<i'
        else:
            self._sections = sections
            self._sym_ptr, self._nsyms = struct.unpack_from('<II', self._data, 8)
            optional = struct.unpack_from('<H', self._data, 16)[0]
            self._sec_start, self._sym_size, self._sect_fmt = 20 + optional, 18, '<h'
        self._valid = self._sym_ptr != 0 and self._nsyms != 0

    def _section_flags(self) -> list[int]:
        flags = []
        for index in range(self._sections):
            offset = self._sec_start + 40 * index
            if offset + 40 > len(self._data):
                break
            flags.append(struct.unpack_from('<I', self._data, offset + 36)[0])
        return flags

    def symbols(self):
        """Yield (name, section_number, value, is_comdat) for each external."""
        if not self._valid:
            return
        flags = self._section_flags()
        table_end = self._sym_ptr + self._nsyms * self._sym_size
        if table_end + 4 > len(self._data):
            return
        size = struct.unpack_from('<I', self._data, table_end)[0]
        strings = self._data[table_end:table_end + max(4, size)]

        index = 0
        while index < self._nsyms:
            record = self._sym_ptr + index * self._sym_size
            if record + self._sym_size > len(self._data):
                return
            raw = self._data[record:record + 8]
            if raw[:4] == b'\0\0\0\0':
                start = struct.unpack_from('<I', raw, 4)[0]
                end = strings.find(b'\0', start)
                name = strings[start:end].decode('latin1') if end > 0 else ''
            else:
                name = raw.rstrip(b'\0').decode('latin1')
            value = struct.unpack_from('<I', self._data, record + 8)[0]
            section = struct.unpack_from(self._sect_fmt, self._data, record + 12)[0]
            storage = self._data[record + self._sym_size - 2]
            aux = self._data[record + self._sym_size - 1]
            if name and storage == IMAGE_SYM_CLASS_EXTERNAL:
                comdat = bool(flags[section - 1] & IMAGE_SCN_LNK_COMDAT) if 0 < section <= len(flags) else False
                yield name, section, value, comdat
            index += 1 + aux


def archive_symbols(path: str) -> set[str]:
    """Names in a .lib's first linker member -- everything the archive can supply."""
    with open(path, 'rb') as handle:
        data = handle.read()
    if data[:8] != b'!<arch>\n':
        return set()
    header = data[8:68]
    try:
        size = int(header[48:58].decode('latin1').strip())
    except ValueError:
        return set()
    body = data[68:68 + size]
    if len(body) < 4:
        return set()
    count = struct.unpack_from('>I', body, 0)[0]
    names = body[4 + 4 * count:].split(b'\0')
    return {name.decode('latin1') for name in names if name}


def linked_objects(vcxproj: str, intdir: str, configuration: str):
    """The object list MSBuild hands the linker, not whatever is on disk."""
    root = ET.parse(vcxproj).getroot()
    wanted, excluded = [], []
    for item in root.iterfind('.//m:ItemGroup/m:ClCompile', MSBUILD_NS):
        source = item.get('Include')
        if not source:
            continue
        skip = False
        for node in item.iterfind('m:ExcludedFromBuild', MSBUILD_NS):
            condition = node.get('Condition') or ''
            if condition and configuration not in condition:
                continue
            skip = (node.text or '').strip().lower() == 'true'
        if skip:
            excluded.append(source)
            continue
        override = item.find('m:ObjectFileName', MSBUILD_NS)
        if override is not None and override.text:
            relative = override.text.replace('$(IntDir)', '').replace('\\', '/')
        else:
            relative = os.path.splitext(os.path.basename(source))[0] + '.obj'
        wanted.append((source, os.path.join(intdir, relative)))
    return wanted, excluded


def library_symbols(extra_dirs) -> set[str]:
    patterns = [
        os.path.join(REPO_ROOT, 'output', '*', 'Win32', 'Debug', '*.lib'),
        os.path.join(REPO_ROOT, 'dependencies', '**', '*.lib'),
        r'C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/*/lib/x86/*.lib',
        r'C:/Program Files (x86)/Windows Kits/10/Lib/*/ucrt/x86/*.lib',
        r'C:/Program Files (x86)/Windows Kits/10/Lib/*/um/x86/*.lib',
        r'C:/Program Files (x86)/Microsoft DirectX SDK*/Lib/x86/*.lib',
    ]
    patterns += [os.path.join(d, '*.lib') for d in extra_dirs]
    symbols: set[str] = set()
    seen: set[str] = set()
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                continue
            seen.add(key)
            try:
                symbols |= archive_symbols(path)
            except Exception:                                      # noqa: BLE001
                continue
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--project', default=os.path.join(REPO_ROOT, 'src', 'sdk', 'main.vcxproj'))
    parser.add_argument('--intdir', default=os.path.join(REPO_ROOT, 'buildstage', 'main', 'Win32', 'Debug'))
    parser.add_argument('--configuration', default='Debug')
    parser.add_argument('--lib-dir', action='append', default=[])
    args = parser.parse_args()

    wanted, excluded = linked_objects(args.project, args.intdir, args.configuration)
    present = [(src, obj) for src, obj in wanted if os.path.isfile(obj)]
    absent = [src for src, obj in wanted if not os.path.isfile(obj)]
    print(f'{len(wanted)} live ClCompile items; {len(present)} objects present, '
          f'{len(absent)} not compiled yet, {len(excluded)} ExcludedFromBuild')
    if not present:
        print('No objects found -- compile first:')
        print('  MSBuild src\\sdk\\main.vcxproj -t:ClCompile -p:Configuration=Debug -p:Platform=Win32')
        return 1

    defined: set[str] = set()
    referenced: dict[str, set[str]] = defaultdict(set)
    concrete: dict[str, set[str]] = defaultdict(set)
    for _, obj in present:
        name = os.path.basename(obj)
        for symbol, section, value, comdat in CoffObject(obj).symbols():
            if section > 0:
                defined.add(symbol)
                if not comdat:
                    concrete[symbol].add(name)
            elif value:                       # a COMMON block is a definition
                defined.add(symbol)
            else:
                referenced[symbol].add(name)

    from_libs = library_symbols(args.lib_dir)
    unresolved = {
        symbol: owners for symbol, owners in referenced.items()
        if symbol not in defined
        and symbol not in from_libs
        and symbol.lstrip('_') not in from_libs
        and ('_' + symbol) not in from_libs
    }
    duplicated = {symbol: owners for symbol, owners in concrete.items() if len(owners) > 1}

    print(f'\nunresolved externals (/FORCE invents an address): {len(unresolved)}')
    for symbol, owners in sorted(unresolved.items()):
        print(f'  {symbol}')
        for owner in sorted(owners)[:8]:
            print(f'      referenced by {owner}')

    print(f'\nduplicate non-COMDAT definitions (/FORCE keeps the first): {len(duplicated)}')
    for symbol, owners in sorted(duplicated.items()):
        print(f'  {symbol}')
        for owner in sorted(owners):
            print(f'      defined by {owner}')

    if not unresolved and not duplicated:
        print('\nLink is clean: every reference resolves and every symbol is defined once.')
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
