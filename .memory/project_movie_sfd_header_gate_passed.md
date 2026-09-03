---
name: project-movie-sfd-header-gate-passed
description: BREAKTHROUGH - the "not a valid SFD file" rejection is GONE. The SFD transfer strategy table is modelled and mwPlyInitSfdFx is un-stubbed, so SFD_Init runs and the SFH pool initialises. Next wall is mwPlyCalcWorkCprmSfd / mwPlyCreateSofdec inside CMovie::OpenMovie.
metadata:
  type: project
---

Established 2026-08-06. Work is UNCOMMITTED in the tree at time of writing.
Supersedes the "31 unrecovered functions" scope estimate in
[[project-movie-sfh-pool-never-init]], which was badly wrong - see below.

## The blocker was ONE function, not 31

The old note said modelling `mwsfd_initsfdpara` needed "8 descriptor blocks -
116 entries, of which 31 are still unrecovered". That over-counted enormously:

- The 8 blocks are `SofdecTransferStrategy` descriptors, **0x38 apart = 14
  slots**, not 2. Slot roles confirmed identical across all 8 families from the
  IDA symbol at every one of the 112 addresses:
  `Init, Finish, ExecServer, Create, Destroy, RequestStop, Start, Stop, Pause,
   GetWrite, AddWrite, GetRead, AddRead, Seek`.
- Families and block addresses:
  SFUO 0x00D7F49C, SFM2TS 0x00D7F4D4, SFAOAP 0x00D7F50C, SFVOM 0x00D7F544,
  SFADXT 0x00D7F57C, SFMPV 0x00D7F5D4, SFMPS 0x00D7F670, SFMEM 0x00D7F6B8.
- List head 0x00D7F3D0 is 0x3C bytes (15 pointers, 8 used); `mwsfd_initsfdpara`
  begins at 0x00D7F40C - i.e. **immediately after it** - and its `callbacks`
  field points back at the list.
- **`SFTRN_Init` only ever calls slot 0.** `sftrn_CallTrEntry(table, sel)`
  indexes 0 (init) or 1 (finish). 97 of the 112 slot functions were already in
  src, and 7 of the 8 `Init` slots too. Only SFADXT was missing entirely.

So the gate on `SFD_Init` was effectively **SFADXT_Init alone** (9 instructions).

## What landed (uncommitted)

- `SofdecFoundationRuntime.cpp`: replaced the 2-callback
  `SftrnEntryDispatchView` (asserted 0x8) with `SofdecTransferStrategy` - 14
  named slots, `static_assert(sizeof == 0x38)`. Init/Finish are typed
  `Sint32(*)()` (uniform across all 8 families); the other 12 stay a generic
  pointer because arity genuinely differs per family (`SFMEM_GetWrite` takes an
  out cursor, `SFVOM_GetWrite` does not; `SFUO_Create` takes a handle,
  `SFMEM_Create` does not). That per-family mismatch is why the original C used
  one generic table type.
- `SofdecSvmTransferRuntime.cpp`: `sftrn_CallTrEntry` now dispatches
  `strategy->init()` / `->finish()` by name instead of indexing a 2-array.
- `SofdecSfdRuntime.cpp` (end of file): the 7 recovered strategy descriptors +
  `gSofdecTransferStrategyList`.
- `SofdecAdxDeclarationsRuntime.cpp`: `gMwsfdInitSfdParams` now initialised with
  the list address instead of `{}` (that null was the actual runtime blocker).
- `SofdecAdxPlatformRuntime.cpp`: real `mwPlyInitSfdFx` (0x00AC9130) +
  `MWSFSVM_Init` (0x00ACCAB0) + `mwsfd_init_cnt` / `cri_verstr_ptr_mwsfd`.
- `SofdecExternalStubs.cpp`: the `mwPlyInitSfdFx` nullptr stub is DELETED.
- `SofdecRuntime.h`: cross-TU declarations for the 13 non-Init SFMPV slots.

## Proof it worked

Before: `warning: /movies/thqlogo.sfd is not a valid SFD file.`
After:  that warning is **gone**; log shows `debug: OpenMovie /movies/thqlogo.sfd: 0`.

Stack proof that `mwPlyInitSfdFx` really runs now:
`CMovieManager::CMovieManager -> mwPlyInitSfdFx -> MWSFSFX_Init -> SFX_Init`.

## Stage 2 DONE: mwPlyCalcWorkCprmSfd resolved (uncommitted)

`CMovie::OpenMovie` calls two `/FORCE`-unresolved symbols. The first is now
recovered and verified resolved (gone from the link's unresolved list, and the
run no longer faults there):

  - **`mwPlyCalcWorkCprmSfd` (0x00AC7D00) - DONE**, with its whole chain:
    `mwPlyCalcWorkSfd` (0x00AC78E0), `mwPlyCalcWorkCompo` (0x00AC7CD0),
    `mwsfcre_CalcWorkStmBuf` (0x00AC7990), `mwsfcre_CalcWorkFrmBuf`
    (0x00AC7AD0), `mwsfcre_CalcWorkCtrl` (0x00AC7C40), `mwsfcre_CalcWorkM2ts`
    (0x00AC7C60), `mwsfcre_CalcFrmRes` (0x00AC7BB0),
    `mwsfcre_CalcWorkRecordMalloc` (0x00AC7CC0),
    `mwsfcre_ConvBufFmtFromMwsfd` (0x00AC7C00).
  - **`mwPlyCreateSofdec` (0x00AC80C0) - STILL UNRESOLVED**, and it is now the
    only thing between us and a created movie handle. The run faults there.

### The allocator was entirely stubbed (found on the way)

`MWSFD_Malloc` called THREE nullptr stubs - `mwsfcre_OrgMalloc`,
`mwsfcre_UsrMalloc`, `mwsfcre_IncMallocCnt` - so every Sofdec allocation
returned null regardless. Recovered all of those plus `mwsfcre_DecMallocCnt`,
`mwsfcre_GetMallocCnt`, `mwsfcre_OrgFree`, `mwsfcre_UsrFree`, `MWSFD_Free`
(0x00AC9030) and `mwsfcre_AllFree` (0x00AC90A0); the 5 stubs are deleted.

Layout work that came with it (all asm-proven):
  - ply +0x1EC is the arena BASE POINTER, not a size - it was named
    `mwsfcreWorkSizeBytes`. Correct map: `mwsfcreWorkBase` +0x1EC,
    `mwsfcreWorkCapacity` +0x1F0, `mwsfcreWorkCursor` +0x1F4,
    `mwsfcreWorkUsedBytes` +0x1F8, `mwsfcreAllocationCount` +0x1FC,
    `mwsfcreAllocations[32]` +0x200. (The old `mUnknown1F0[0x0C]` hole.)
  - `MwsfdLibWork` +0x28 `userMallocFn`, +0x2C `userFreeFn`, +0x30
    `userAllocObject` (was the `mUnknown28[0x0C]` hole). `sfx_libwork` base
    0x011F9B20: `last` +0x04, `errFn` +0x08, `errParam` +0x0C, `cirFx` +0x14.
    `sfxz_work` base 0x011F9180: `zbufType` +0x04, `last` +0x08, size 0x98C.
  - `SofdecCreateParams` was a CMovie.cpp-private duplicate; promoted to
    `moho::MwsfcreCreateParams` in SofdecRuntime.h and CMovie.cpp aliases it.
  - CMovie.cpp declared both mwPly* entry points taking `void*`, which gave
    them a different C++ mangling from any recovered definition - that alone
    would have kept them unresolved. Now declared with real types in the
    header's `extern "C"` block.

### SofdecSfxRuntime.cpp is now compiled

Added to the `moho/audio/SofdecRuntime.cpp` aggregator. Recovered its four
startup leaves: `SFX_SetErrFn` (0x00ACC840), `SFX_SetCcirFx` (0x00ACCA50),
`SFXZ_SetZbufType` (0x00ACDDF0), `sfxzmv_InitLibWork` (0x00ACD5B0). Removed its
duplicate `SFXA_Init`/`SFXSUD_Init` bodies (already in
SofdecSvmTransferRuntime.cpp) and fixed its `MWSFSVM_Error` declaration.
`MWSFSFX_Init()` is re-enabled inside `mwPlyInitSfdFx`.
`SFX_Finish` (0x00ACC810, 9 instr) and `SFX_Create` (0x00ACC860, 71 instr, pulls
sfx_SearchFreeHn/sfx_InitHn/SFXZ_Create/SFXA_Create/SFXLIB_Error/SFX_Destroy)
are deliberately still unresolved - neither is on the startup path, so the
link count is 19 not 18 and that is expected and safe.

## Stage 3 DONE: the create path landed, THE CRASH IS GONE (f9ef3cf)

`mwPlyCreateSofdec` + `mwsfcre_CreateSfd` + ~17 helpers are recovered and
committed. A run now reports `fault=0` - no access violation anywhere - and
fails cleanly through the real CRI error channel:

```
SofDec error: E20010703C mwPlyCreateSofdec: create error
SofDec error: E2012 mwPlyCreate:can't create SFD
```

## Stage 4 (NEXT): `sfply_InitHn` is a nullptr stub

`sfply_Create` returns null because `sfply_InitHn` is
`void* sfply_InitHn() { return nullptr; }` in SofdecExternalStubs.cpp:185.
**Fifth** instance of the C-linkage stub trap in this subsystem (after
mwPlyGetHdrInf, SFHDS_ProcessHdr, mwPlyInitSfdFx, ADXT_Init).

`sfply_InitHn` is FUN_00AD7AE0, 111 instructions. Its only stubbed callee is
`SFHDS_InitFhd`; everything else is already recovered. It also needs a new
global `sfply_last_hnctrl_wksiz`.

It is gated on extending `SofdecSfdWorkctrlSubobj`, which is still modelled as
`{ mUnknown00[0x48]; handleState; }` but is really ~0x3600 bytes. **Every
offset is already extracted from FUN_00AD7AE0.asm - do not re-derive:**

  scalars: `v24` +0x44, `flibHn` +0x48 (the existing `handleState`),
  `v26` +0x4C, `v27` +0x50, `v28` +0x54, `v29` +0x58, `v30` +0x5C.
  sub-objects: `fhd` +0x78, `mvInfo` +0x90C, `plyInfo` +0x950,
  `errInfo` +0x9F8, `setConds` +0xA0C (MEM_Copy 400 bytes from SFLIB_libwork),
  `v750` +0xB9C (MEM_Copy 0x190), `timeHn` +0xD30, `bufHn` +0x1310,
  `trnHn` +0x1F30, `seeHn` +0x3550, `tmrInfo` +0x3560.

Note the body does `qmemcpy(v3, a1, 0x44)` - which independently confirms the
create template is exactly 0x44 bytes - and passes `&a1->v0` (the strategy
sub-table) to `SFTRN_InitHn`. The guards that can make it return null early:
`workCtrl1` null, `workCtrlSize1 <= 0 || > 0x6CC0`, or a second create with a
different `workCtrlSize1` than the first (`sfply_last_hnctrl_wksiz`). Our
create passes 0x4000, so none of those should fire.

## Earlier notes: what `mwPlyCreateSofdec` needed (now done)

`mwsfcre_CreateSfd` (0x00AC8380, 378) is the hard one; the rest are small:
`mwsfcre_IsOkCprm` (0x00AC8C10), `mwsfcre_IsOkUsrMalloc` (0x00AC8B90),
`mwsfcre_InitMemMng` (0x00AC8BC0), `mwsfcre_CreateSj` (0x00AC8B60),
`mwsfcre_IsPlayAudio` (0x00AC8B10), `mwsfcre_MallocRfb` (0x00AC8920),
`mwsfcre_MallocTab` (0x00AC8A00), `mwsfcre_MallocCompoWork` (0x00AC8C50),
`MWSFCRE_SetCondSfd` (0x00AC7F70), `MWSFTAG_CreateAinfSj` (0x00AC6F40),
`MWSFFRM_InitSfhInfTable` (0x00ACAA90), `MWSFFRM_SetShfCbFn` (0x00ACAAD0),
`MWSKG_Create` (0x00AC8B30), `MWSTM_Create` (0x00AD90C0),
`MWSTM_SetFlowLimit` (0x00AD9060), `MWSFPLY_SetFlowLimit` (0x00ACB330 - also a
nullptr stub today), `MWSFD_SetFlowLimit` (0x00ACB990).

Static data it needs (all dumped from the PE already):
  - `mwsfd_packsize` 0x00F40164 = 2048; `mwsfd_sisjadr` 0x00FB8C5C.
  - `mwsfd_mpvpara` 0x00F40124 (10 dwords), `mwsfd_adxtpara` 0x00F40150.
  - Four 0x44-byte crepara blocks, identical except their first dword:
    `mwsfd_sfdmps_crepara` 0x00F40008, `mwsfd_sfdmpv_crepara` 0x00F40050,
    `mwsfd_vonlysfd_crepara` 0x00F40098, `mwsfd_mpeg2ts_crepara` 0x00F400E0.
    Common values: +0x08=0x10000, +0x0C=0x50800, +0x10=0x12000, +0x28=0x800,
    +0x2C=3, +0x38=3. Field offsets seen written: obj2 +0x08, sib +0x0C,
    vib +0x10, aib +0x14, packsize +0x28, nfrm_pool_wk +0x30, max_width +0x34,
    max_height +0x38, bufFmt +0x3C, workCtrl1 +0x40.
  - **Their first dword points at a per-ftype strategy sub-table** (0x00D7F2FC
    mps / 0x00D7F320 mpv / 0x00D7F344 vonly / 0x00D7F368 m2ts), and every entry
    in those sub-tables is one of the SAME eight strategy descriptors modelled
    above. ftype 3 (video-only, what the check in OpenMovie accepts alongside
    1) selects SFMEM/SFMPS/SFMPV/SFVOM/SFUO and **does not use SFADXT at all** -
    so the unrecovered SFADXT family does not block a video-only movie.

## Two more dead-code finds

1. **`cri/sofdec/SofdecSfxRuntime.cpp` is a fully recovered 428-line fragment
   that is in NO translation unit** - `<None>` in the vcxproj and not included
   by any aggregator. Adding the include links, but `SFX_Init` reaches five
   unrecovered leaves; two are on the startup path so it faults:
   `sfxzmv_InitLibWork` (0x00ACD5B0, 11 instr), `SFX_SetErrFn` (0x00ACC840, 5),
   `SFX_Finish` (0x00ACC810, 9), `SFX_SetCcirFx` (0x00ACCA50, 3),
   `SFX_Create` (0x00ACC860, 71 - pulls sfx_SearchFreeHn/sfx_InitHn/SFXZ_Create/
   SFXA_Create/SFXLIB_Error/SFX_Destroy). Offsets already extracted:
   `sfxz_work` base 0x011F9180, `.unk2` +0x04, `.last` +0x08, size 0x98C;
   `sfx_libwork.errFn` 0x011F9B28, `.errParam` 0x011F9B2C.
   `SFXA_Init`/`SFXSUD_Init` in that fragment are duplicates of bodies already
   in SofdecSvmTransferRuntime.cpp - removed.
   The `MWSFSFX_Init()` call inside `mwPlyInitSfdFx` is currently commented out
   with that explanation. Everything the movie path needs runs before it.
2. **`ADXT_Init` is a C-linkage nullptr stub** (SofdecExternalStubs.cpp:47) - so
   the whole ADX transport layer never initialises. Fourth instance of the
   C-linkage stub trap in this subsystem after mwPlyGetHdrInf,
   SFHDS_ProcessHdr, mwPlyInitSfdFx.

## SFADXT inventory (for when the table is completed)

The SFADXT TU is 0x00AD0220..0x00AD1790, **59 functions / 1690 instructions**,
all small (max 187). Needs `SofdecSfdWorkctrlSubobj` (currently modelled only to
0x48) extended - SFADXT indexes +0x48, +0x50, +0x1020, +0x2004 (adxtInf ptr,
also reachable as `a1[2049]`), +0x2008/+0x200C (src/dst buffer ids), +0x0F24/
+0x0F28, +0x3448 (the adxtInf block itself), +0x3550.
Also still missing for a complete table: `SFMPV_Create` (0x00AD4BA0, 85),
`SFM2TS_ExecServer` (0x00ACF140, 21), `SFM2TS_Create` (0x00ACF800, 88).

ply offsets already pinned from asm for that work (do not re-derive):
  - **`params` (MwsfcreCreateParams) lives at ply +0x08.** The existing
    `fileType` +0x08 and `framePoolSize` +0x18 fields ARE `params.ftype` and
    `params.framePoolWork`; fold them into a nested `params` member rather
    than leaving three names for the same bytes.
  - SJ create triple: `sisjadr` +0x1C4, `sjb - packsize` +0x1C8,
    `packsize` +0x1CC (`mwsfcre_CreateSj` feeds these to `SJRBF_Create`).
  - Compo work: `hnWork` +0xAC, `hnWorkSiz` +0xB0, AINF `obj` +0x180,
    `objSize` +0x184 (0x20000 when the AINF SJ lane is used).
  - MWSKG: writes a 3-dword block at +0x160/+0x164/+0x168 and stores its own
    address into +0x178.

Related: [[project-movie-sfh-pool-never-init]], [[project-sofdec-movie-crash]]
