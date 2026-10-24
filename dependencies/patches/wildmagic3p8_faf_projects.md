# FAF Wild Magic 3.8 project files

Baseline: the original Wild Magic 3.8 release (`Draiget/wild-magic-3-8`), after `wildmagic3p8_faf_required.patch`. Regenerated 2026-10-24 against that original; it now also adds `Tools/build_wm3.bat`, `Tools/dumpbin_symbols.bat` and `Tools/gen_vcxproj.py` (the generator the `.vcxproj` files came from). See `wildmagic3p8_faf_required.md` for how to apply.

## Scope — ten added files

Upstream Wild Magic 3.8 (2006) ships VS2005 `_VC80.vcproj` project files and nothing newer; all 119 of them are still present in the tree alongside these. The five modern projects and their filter files were added by FAF:

| File | Consumed by |
|---|---|
| `Foundation/Foundation.vcxproj` (+ `.filters`) | `ProjectReference` of `main.vcxproj` |
| `Renderers/Dx9Renderer/Dx9Renderer.vcxproj` (+ `.filters`) | `ProjectReference` of `main.vcxproj` |
| `Applications/Dx9Application.vcxproj` (+ `.filters`) | `ProjectReference` of `main.vcxproj` |
| `Renderers/OpenGLRenderer/WglRenderer.vcxproj` (+ `.filters`) | not referenced by the engine build |
| `Applications/WglApplication.vcxproj` (+ `.filters`) | not referenced by the engine build |

Because the first three are `ProjectReference`s, `msbuild src/main.vcxproj` builds Wild Magic as part of the engine. There is no separate Wild Magic build step.

## `_ITERATOR_DEBUG_LEVEL=0` on Foundation

`Foundation.vcxproj`'s `Debug|Win32` configuration defines `_ITERATOR_DEBUG_LEVEL=0`, matching `main.vcxproj`. This is the one setting in these files that will stop a build if it is lost.

`Foundation.lib` is the only static library linked into the engine that carries std containers, and `_ITERATOR_DEBUG_LEVEL` changes their size — so a mismatch changes object layout. It is not silent: MSVC records the level per object and the linker rejects the mismatch with **LNK2038**, naming `Wm3System.obj`, `Wm3Math.obj` and `Wm3Vector3.obj`.

`main.vcxproj` pins the level to 0 in Debug deliberately — checked iterators cost more than they are worth in a configuration whose job is to run the engine, and leaving it at the `_DEBUG` default of 2 would make binary-layout structs differ between Debug and Release.

## Added 2026-09-23

These ten files were in the vendored archive but in no patch, so a tree rebuilt from a genuine Wild Magic 3.8 release would have had no modern project files and no `_ITERATOR_DEBUG_LEVEL` setting.

Verified by applying the patch to an empty tree and comparing all ten files byte-for-byte against the working tree.
