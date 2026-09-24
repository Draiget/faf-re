# FAF zlib 1.2.3 patch

Baseline: **vendored** `zlib-1.2.3.7z`, SHA256
`68a08d43b156ddc07ab02c9cb37b75e937a68607285fbb32d3e5f83a5f3713f3`.
Cut against upstream `zlib-1.2.3.tar.gz`, SHA256 `1795c7d0…` (zlib.net
fossils). Pinned in [`docker/deps.lock.json`](../../docker/deps.lock.json).

Role: **baked-in** — the modifications are already present in the vendored
archive. The patch is the record of what differs from upstream, verified by
reverse-check on every build.

## This is not a full zlib tree

`dependencies/zlib-1.2.3` is thirteen hand-picked files, not an extracted
release:

```
ChangeLog  FAQ  README  crc32.c  deflate.c  deflate.h  zutil.h  zlib.def
include/zconf.h  include/zlib.h
zlib.lib  zdll.lib  zlib1.dll        <- prebuilt, in no upstream tarball
```

Two consequences:

- `include/` does not exist upstream — `zconf.h` and `zlib.h` live at the root
  there. The patch is written against the **vendored** layout, so its paths
  are `include/zconf.h`, not `zconf.h`.
- Extracting the upstream tarball does not reproduce this tree, which is why
  the baseline is the vendored archive rather than the tarball.

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `include/zconf.h` | `HAVE_UNISTD_H` flipped from `0` to `1`, with a `_WIN32` branch including `<io.h>` instead of `<unistd.h>` | **Yes** |
| `crc32.c` | FAF binary provenance for `0x0095D6D0` (`get_crc_table`) and `0x0095DE30` (`crc32`) | No |
| `deflate.c` | FAF binary provenance for `0x0095AB90` (`deflateSetHeader`) | No |
| `README` | records the vendoring | No |

Only `include/zconf.h` affects a build: `main.vcxproj` puts
`dependencies\zlib-1.2.3\include` on the Win32 header search path, so every
translation unit that reaches zlib headers sees this file.

The `crc32.c` and `deflate.c` annotations are recovery evidence, not code —
neither file is compiled here. They record that `get_crc_table` at `0x0095D6D0`
is a two-instruction stub returning `crc_table`, which proves
`DYNAMIC_CRC_TABLE` was **not** defined in the shipped build, and that
`deflateSetHeader`'s field offsets (`+0x18` wrap, `+0x1C` gzhead) match this
project's `zlib::DeflateState`.

## How zlib is actually linked

- **Win32**: `zlib.lib` comes from the **wxWindows** tree
  (`dependencies\wxWindows-2.4.2\lib`), built by the wx `nmake` step. This
  tree contributes only headers.
- **x64**: `AdditionalLibraryDirectories` points at `dependencies\zlib-1.2.3`
  and links the prebuilt `zlib.lib` from here.

## Added 2026-09-23

There was previously no zlib patch, and the first audit pass wrongly concluded
none was possible — "the tree is a selection, not a modification". Diffing the
four vendored source files against upstream showed all four are modified, one
of them load-bearing.

## Checking it

```powershell
.\docker\scripts\Apply-Patches.ps1 -CheckOnly -Only zlib-1.2.3
```
