# FAF zlib 1.2.3 patch

Baseline: the `madler/zlib` submodule at tag `v1.2.3` (`dependencies/zlib-1.2.3`), the upstream tree in its own layout (`zconf.h` and `zlib.h` at the root). `cmake/FafDependencies.cmake` applies the patch at configure time; see `wildmagic3p8_faf_required.md` for the `git -c core.autocrlf=false apply` rule.

Re-cut 2026-10-24 for that layout. The old vendored folder's prebuilt `/MD` `zlib.lib`, `zdll.lib` and `zlib1.dll` are gone.

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `zconf.h` | `HAVE_UNISTD_H` flipped from `0` to `1`, with a `_WIN32` branch including `<io.h>` instead of `<unistd.h>` | **Yes**: every engine file that includes zlib sees it |

Binary-address notes that earlier versions of this patch carried as comments are kept in the recovery archive (`faf-re-archive/dependency-patches-with-provenance/`), not here.

## How zlib is linked

- **x86**: the engine links the zlib that wxWindows builds (`wx_zlib` in `cmake/deps/wxwindows`), as the shipped exe does. This tree contributes only headers.
- **x64**: `cmake/deps/zlib` builds `zlib123` from this tree, `/MT`.
