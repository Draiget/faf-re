---
name: project-force-link-garbage-globals
description: Undefined extern globals resolve to the image base under /FORCE, where the MZ header makes every bool read true — plus the recipe for auditing the dead FAF_RUNTIME_LAYOUT_ASSERTs.
metadata:
  type: project
---

Two traps that each cost a long debugging detour on 2026-08-04, both of which
silently produce *wrong runtime behaviour with a green build*.

**1. Undefined extern globals are not link errors here.** `main.exe` links with
`/FORCE`, so a global that is declared `extern` and defined nowhere resolves to
the image base instead of failing. The first byte there is `'M'` (0x4D) from the
`MZ` header, so **every undefined `bool` reads back as `true`**. This is not
theoretical: `ren_ShowFrameTimes` reading true made `REN_DebugStuff` draw the
frame-time HUD during startup and take an access violation in
`CD3DPrimBatcher::SetTexture`. `ren_Ui`, `ren_Bloom`, `ren_Oblivion`,
`ren_Decals` and `ren_ShowNormals` were equally arbitrary.

Find them with a forced relink (delete `output/main/Win32/Debug/main.exe`
first, otherwise msbuild skips the link and prints nothing):

    bld.bat 2>&1 | Select-String "LNK2001|LNK2019"

Fixed in `adab78b` by defining 15 of them in
`src/sdk/moho/misc/RuntimeTuningGlobals.cpp` with values read out of the PE.
**Baseline moved from 37 unresolved symbols to 18** — that is the number to
compare against now.

Read a global's shipped default straight from `bin/2025.7.1/ForgedAlliance.exe`:
map VA→file offset via the section table (imagebase 0x400000). An address past a
section's `SizeOfRawData` but inside its `VirtualSize` is in the zero-fill tail,
so its default is 0 — that is how `ren_ShowFrameTimes` @0x010A6430 was
established as false while `ren_Ui` @0x00F57DE7 reads 0x01.

**2. `FAF_RUNTIME_LAYOUT_ASSERT` is compiled out.**
`FAF_ENFORCE_STRICT_LAYOUT_ASSERTS` defaults to `0` (see
`moho/audio/SofdecRuntime.h`), so **every one of those asserts in the tree is
dead** and layouts drift unnoticed. Audit a subsystem by compiling one TU that
includes its headers with the flag on — scratchpad `uilayout.bat` is
`tucheck.bat` plus `/DFAF_ENFORCE_STRICT_LAYOUT_ASSERTS=1`. Doing that to the UI
headers surfaced 18 real failures in two classes (`fc4706e`). **The other
subsystems have never been audited this way.**

Related: [[project-thin-class-alloc-and-view-drift]],
[[project-render-frame-blockers-2026-08]]
