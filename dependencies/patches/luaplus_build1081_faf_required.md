# FAF LuaPlus Build 1081 patch

Baseline: **vendored** `LuaPlus_Build1081.7z`, SHA256
`1f1bc467e7c430a52610ed8331f2d966728c9658ad909e971c4eaf9f61e08890`.
Pinned in [`docker/deps.lock.json`](../../docker/deps.lock.json) and pushed to
your OCI registry as `faf/deps:LuaPlus_Build1081`.

LuaPlus Build 1081 has no stable upstream download any more, so the archive
itself is the baseline rather than a vendor release.

`luaplus_build1081_faf_required.patch` carries eighteen files, fifty-seven
hunks.

## Already in the baseline

The archive is a post-patch snapshot, so the modern-CRT `swprintf` fixes are
present in it and do **not** appear in the patch. Recorded here so the change
is not lost:

- `Src/LuaPlus/LuaPlusAddons.c` — `lua_number2wstr` uses `_snwprintf` with an
  explicit buffer length (32).
- `Src/LuaPlus/lwstrlib.c` — `swprintf` → `_snwprintf` with explicit lengths in
  the quoted-escape and `%`-format helper paths.

LuaPlus Build 1081 predates the C99 `swprintf(buffer, count, format, …)`
signature; without these the build fails with `C2440` in both files.

## Patch scope — the Lua VM layout

The eighteen patched files align the Lua VM with the fork the game shipped.
The bulk is in the object and state layouts:

| File | Changed lines |
|---|---|
| `Src/LuaPlus/src/lstate.h` | 231 |
| `Src/LuaPlus/src/lobject.h` | 96 |
| `Src/LuaPlus/src/lstate.c` | 61 |
| `Src/LuaPlus/src/lvm.c` | 47 |
| `Src/LuaPlus/src/ldo.c` | 35 |
| `Src/LuaPlus/src/ldebug.c` | 29 |
| `Src/LuaPlus/src/lstring.c` | 13 |
| `Src/LuaPlus/include/lua.h` | 12 |
| `Src/LuaPlus/LuaObject.cpp` | 12 |
| `Src/LuaPlus/src/{lstring.h, lmem.h}` | 8 each |
| `Src/LuaPlus/src/lgc.c` | 7 |
| `Src/LuaPlus/src/{lmem.c, llex.c}` | 6, 5 |
| `Src/LuaPlus/{LuaPlusAddons.h, LuaObject.h}` | 5 each |
| `Src/LuaPlus/src/ldebug.h` | 3 |
| `LuaPlusLib_1081.vcxproj` | project file (v143, MBCS, `LUAPLUS_HAS_WCHAR_T`) |

These are layout changes: getting them wrong does not fail the build, it
produces an engine that reads Lua objects at the wrong offsets.

## Regenerated 2026-09-23 — this patch previously did not exist in usable form

Two defects, both fixed:

1. The old patch was **malformed**. Its first hunk declared `@@ -20,7 +20,7 @@`
   but carried six lines of body, so `git apply` rejected the entire file with
   `corrupt patch at line 12`, in both directions. It had never been applicable.
2. It covered **two** files. Eighteen were modified. The other sixteen —
   everything in the table above — existed only in one working tree and were
   recorded nowhere, since `dependencies/` is gitignored.

Anyone setting up a fresh checkout would have got stock LuaPlus VM layouts with
no error and no warning. See
[`docker/DEPENDENCY-AUDIT.md`](../../docker/DEPENDENCY-AUDIT.md) findings 1 and 2.

The regenerated patch was verified by applying it to a fresh extraction of the
archive and hashing the result: byte-identical to the working tree, zero
differences.

## Build and linkage

`LuaPlusLib_1081.vcxproj` builds a static library to
`output/LuaPlus_Build1081/Win32/$(Configuration)`. Consumers define
`LUAPLUS_LIB` so the headers do not auto-link `LuaPlus_1081.lib`.

**`main.exe` does not link that output.** It links `LuaPlusLibD_1081.lib` from
`dependencies/LuaPlus_Build1081/Prebuilt/Lib/win32`, and those files are the
2004 vendor binaries — verified byte-identical to the copies in the `.7z`.
`main.vcxproj` holds no `ProjectReference` to the LuaPlus project; only
`faf.sln` references it.

So the eighteen files above currently compile into a library nothing links.
Audit finding 7 covers the options; resolving it is an engine decision, and the
build container deliberately reproduces the existing wiring rather than
changing it.

## Applying it

Normally automatic — `docker/scripts/Resolve-Deps.ps1` then
`docker/scripts/Apply-Patches.ps1`. To check the current state:

```powershell
.\docker\scripts\Apply-Patches.ps1 -CheckOnly -Only LuaPlus_Build1081
```
