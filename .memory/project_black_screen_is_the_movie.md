---
name: project-black-screen-is-the-movie
description: The black screen is the intro movie failing to open, not a renderer bug. The UI tree is correct and rendering runs. Records the full Sofdec SFD identification chain, what is now recovered, and the one stub left.
metadata:
  type: project
---

Established 2026-08-04. Supersedes the "two leads" framing in
[[project-black-screen-next-steps]] - LEAD 1 and LEAD 2 are both closed.

## The renderer is fine; the front end never advances

Probing `CMauiFrame::RenderChildControls` (which IS `CMauiFrame::DoRender`,
0x007870F0) with RTTI on each child gives, every frame, at mask 8:

```
SELF=CMauiFrame children=3
  [0] CMauiFrame  hidden=0 pass=8   <- the frame itself
  [1] CMauiGroup  hidden=0 pass=8
  [2] CMauiMovie  hidden=0 pass=8
```

Entry [0] pointing back at the frame is expected and already documented in
`UiRuntimeTypes.h` - `CMauiControl::Render` seeds the rendered-children lane
with the subtree root, which is exactly why `RenderChildControls` must NOT be
declared as a `DoRender` override (it would recurse into itself). Masks 1 and
4 match nothing; only mask 8 draws.

So the whole subtree is **a group and a movie player**. That is the intro-movie
screen. The engine is not failing to draw the main menu - it never gets to the
main menu, because the intro movie never opens and never completes.

**The black screen is the movie failure.** Stop looking at the renderer.

## Why the movie fails, in full

`CMovie::OpenMovie` rejects with "is not a valid SFD file" when the parsed
stream type is not 1 or 3. The identification path, bottom to top:

```
CMovieManager::CMovieManager (0x00874AF0)
  -> mwPlyInitSfdFx (0x00AC9130)          <- STILL A STUB. the blocker.
     -> mwPlySfdInit (0x00AC9490)          recovered, never called
        -> SFD_Init (0x00AD8B90)
           -> sflib_InitSub (0x00AD8ED0)
              -> SFHDS_Init (0x00AE7150)   recovered c12a734
                 -> SFH_Init (0x00ADC700)  recovered c12a734
                    -> seeds sfh_workinfo with 32 slots
```

With the pool empty, `SFH_Create` returns null on every call, so
`SFHDS_IsSfdHeader` always says no, so `sfcre_AnalySfh` never sets
`videoDescriptor`, so `SFD_AnalyCreInf` leaves both header-valid bytes clear,
so `mwPlyGetHdrInf` bails before even reaching the stream-type classifier.

Recovered in c12a734 (all verified against .asm displacements):
`mwsfcre_DecideFtypeByHdrInf`, `mwsfdcre_IsPlayableByHdrInf`,
`SFHDS_IsSfdHeader`, `SFH_IsSfdHeader`, `SFH_AnlyHdrToolVer`,
`SFH_AnlyHdrToolInf`, `isEffectiveObj`, `SFH_Destroy`, `SFH_Init`,
`SFH_GetSbverStr`, `SFHDS_Init`.

**Next step is `mwPlyInitSfdFx`.** It is not a one-liner - it also calls
`ADXT_Init`, `MWSFSVM_Init`, `SJRBF_Init`, `SJMEM_Init`, `SJUNI_Init`, all
currently stubs. Its own pass.

## Ground truth for thqlogo.sfd (use this to check any parser work)

`g:\games\...\movies\thqlogo.sfd`, first 5000 bytes:
- 2048-byte packs; `00 00 01 BA` at 0 / 2048 / 4096, system header `BB` at 12.
- **No** `B3` sequence header, **no** `E0`/`C0` PES in that window - so
  `sfcre_AnalyMpv` and `sfcre_AnalyAudio` correctly find nothing. Identification
  rests entirely on the SFH path.
- Sofdec header is **pack 1**: `"SofdecStream            "` at +0x20, raw
  version bytes `02 1A` at +0x38, tool banner
  `"Sofdec CRAFT/Console Ver.2.94"` at +0x60. The recovered version compare
  (`minor + 100*major`) picks 2.94 over 2.26, matching the binary.

## Two corrections to earlier readings

- The 18 `<None Include>` Sofdec files are **not** excluded from the build.
  They are fragments `#include`d by `moho/audio/SofdecRuntime.cpp`, which is
  compiled. Confirmed by resolving a runtime function address through the PDB
  with `scratchpad/symat.exe`. Do not "fix" the vcxproj.
- Linkage traps: these fragments are at **global scope**, and declarations mix
  `extern "C"` and plain C++ linkage per symbol. `SFHDS_Init` is declared
  WITHOUT `extern "C"`; defining it with `extern "C"` silently creates a
  different symbol that `/FORCE` binds to the image base, and the build still
  reports the same 18 errors. **Always match the existing declaration's
  linkage, and verify the new body actually runs.**

Related: [[project-reference-binary-log-diff]],
[[project-resize-crash-fixed-ondeviceexit]], [[project-sofdec-movie-crash]]
