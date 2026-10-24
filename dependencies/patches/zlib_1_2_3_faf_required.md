# FAF zlib 1.2.3 patch

Baseline: the `madler/zlib` submodule at tag `v1.2.3` (`dependencies/zlib-1.2.3`), the upstream tree in its own layout (`zconf.h` and `zlib.h` at the root). `cmake/FafDependencies.cmake` applies the patch at configure time; see `wildmagic3p8_faf_required.md` for the `git -c core.autocrlf=false apply` rule.

Re-cut 2026-10-24 for that layout. Against upstream, the result is byte-identical to the hand-picked files the old vendored folder held. That folder's prebuilt `/MD` `zlib.lib`, `zdll.lib` and `zlib1.dll` are gone.

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `zconf.h` | `HAVE_UNISTD_H` flipped from `0` to `1`, with a `_WIN32` branch including `<io.h>` instead of `<unistd.h>` | **Yes**: every engine file that includes zlib sees it |
| `crc32.c` | FAF binary provenance for `0x0095D6D0` (`get_crc_table`) and `0x0095DE30` (`crc32`) | No |
| `deflate.c` | FAF binary provenance for `0x0095AB90` (`deflateSetHeader`) | No |
| `README` | records the vendoring | No |

The `crc32.c` and `deflate.c` notes are evidence, not code. `get_crc_table` at `0x0095D6D0` is a two-instruction stub returning `crc_table`, which proves `DYNAMIC_CRC_TABLE` was not defined in the shipped build, and `deflateSetHeader`'s field offsets (`+0x18` wrap, `+0x1C` gzhead) match the engine's `zlib::DeflateState`.

## How zlib is linked

- **x86**: the engine links the zlib that wxWindows builds (`wx_zlib` in `cmake/deps/wxwindows`), as the shipped exe does. This tree contributes only headers.
- **x64**: `cmake/deps/zlib` builds `zlib123` from this tree, `/MT`.
