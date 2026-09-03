---
name: project-debug-build-was-1fps
description: Why the Debug engine rendered ~1 fps during movies while audio stayed correct, and the four build settings that fixed it (f0b56ca). Includes the Foundation.lib _ITERATOR_DEBUG_LEVEL coupling.
metadata:
  type: project
---

# Debug build rendered ~1 fps during movies — fixed (f0b56ca)

Symptom: in Debug the splash movies played with correct **audio** and roughly
**one video frame per second**. Not a 30% slowdown — the Sofdec clock is driven
in real time by ADXM/audio, so the movie keeps its schedule and simply drops
every frame the renderer misses. Release was always fine.

Neither configuration set `<Optimization>` or `_ITERATOR_DEBUG_LEVEL`, so both
inherited the MSBuild defaults from `UseDebugLibraries`. Four costs stacked up:

1. **`/Od` on the two numeric kernels** — the dominant one. The Sofdec CFT
   colour converter (`CFT_Ycc420plnToArgb8888*` → `cft_sse_*`) converts
   720x512 = 368,640 pixels per frame and its fast path is **SSE intrinsics**,
   which `/Od` spills to a stack slot after every instruction. The MPEG decoder
   is the same story with lambdas/templates/8-byte `std::memcpy`s.
2. **`/JMC`** — default-on for a Debug configuration under v143; prepends a
   `__CheckForDebuggerJustMyCode` call to *every* function.
3. **`/RTC1`** — stack-frame poisoning + uninitialised-use checks per function.
4. **`_ITERATOR_DEBUG_LEVEL=2`** — checked iterators on every std container.

Fix in `src/sdk/main.vcxproj` Debug|Win32: keep `/Od` project-wide (stepping is
the point) but add `/Ob1`, turn off `/JMC` and `/RTC1`, pin
`_ITERATOR_DEBUG_LEVEL=0`, and give **`moho\movie\MPVDecoder.cpp`** and
**`moho\audio\SofdecRuntime.cpp`** per-file `MaxSpeed`/`AnySuitable`/
`IntrinsicFunctions`. Drop the two per-file blocks if you ever need to
single-step those.

## Measuring which flags actually fire

Compile one TU with the config's flags and look for the helpers rather than
guessing — `dumpbin /symbols x.obj | findstr __CheckForDebuggerJustMyCode` and
`_RTC_CheckStackVars`. Stock Debug on `MPVDecoder.cpp` = 359,319-byte obj with
both present; `/Od /Ob1` without JMC/RTC = 265,748 bytes with neither.

## ⚠ `_ITERATOR_DEBUG_LEVEL` couples to Foundation.lib

`dependencies/` is **not tracked by git**, so the matching change to
`WildMagic3p8/Foundation/Foundation.vcxproj` (add `_ITERATOR_DEBUG_LEVEL=0` to
Debug|Win32, rebuild) exists only locally. On a fresh checkout Debug will fail
to link with `LNK2038 ... '_ITERATOR_DEBUG_LEVEL': value '2' doesn't match
value '0'` naming `Wm3System.obj` / `Wm3Math.obj` / `Wm3Vector3.obj`. That is
the fix instruction, not a mystery. It cannot fail silently.

Beyond speed this closed a real hazard: with IDL differing between the two
configurations, **every std container had a different size in Debug than in
Release**, so any binary-layout struct holding one had two different layouts.

## Unrelated find: a dead duplicate colour converter

`src/sdk/cri/sofdec/SofdecColorConvertRuntime.cpp` is untracked **and not
`#include`d by anything**. Its own header comment claims it is a fragment of
`moho/audio/SofdecRuntime.cpp`, but that aggregator includes 13 fragments and
this is not one of them. The live `mwPlyFxCnvFrmARGB8888` (0x00ACC6E0) is the
one in `SofdecSfxRuntime.cpp`. Including the orphan would be a duplicate-symbol
clash. Decide whether to delete it or fold it in — do not assume it is live.
