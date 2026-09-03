---
name: project-sfd-transfer-descriptor-table
description: mwPlyInitSfdFx is fully recovered but cannot be enabled - it needs the SFD transfer descriptor table (mwsfd_initsfdpara.callbacks), an unmodelled static. Records the exact table layout from the PE and the 31 remaining functions.
metadata:
  type: project
---

Established 2026-08-04. Continues [[project-black-screen-is-the-movie]].

## Where the movie chain actually stops

`mwPlyInitSfdFx` (0x00AC9130) is **recovered and verified** - the body ran
correctly end to end when wired in, reaching
`CMovieManager::CMovieManager` -> `mwPlyInitSfdFx` -> `mwPlySfdInit` ->
`SFD_Init` -> `sflib_InitLibWork`. It is NOT committed as live code, because
that last hop faults.

**Root cause: `gMwsfdInitSfdParams` is an unmodelled static.** In the binary
`mwsfd_initsfdpara` lives at 0x00D7F40C and is statically initialised to

```
callbacks = 0x00D7F3D0     version = 0x0000EA24   (60004 = 60.004 Hz in mHz)
```

Ours is `moho::MwsfdInitSfdParams gMwsfdInitSfdParams{}` -
defined once, assigned nowhere, so `callbacks` is null.
`sflib_InitLibWork` ends in `SFTRN_Init(&trnInit, callbacks)`, which does an
unconditional 60-byte copy (`rep movsb`, ecx=0x3C) from that pointer. Our
`SFTRN_Init` matches the binary exactly - there is no null guard in either, so
this is not a bug to fix in `SFTRN_Init`.

Observed fault: `ACCESS_VIOLATION read from address 00000000`,
`esi=0 ecx=3C edi=<dst>`, inside memcpy called from
`sflib_InitLibWork+0xC3`.

## The table (read out of bin/2025.7.1/ForgedAlliance.exe)

`0x00D7F3D0` is 60 bytes: 8 descriptor-block pointers then 7 zero dwords.
Each block is an array of function pointers - the per-stream-type transfer
handler vtables.

| block | address | entries |
|---|---|---|
| 0 | 0x00D7F49C | 14 |
| 1 | 0x00D7F4D4 | 14 |
| 2 | 0x00D7F50C | 14 (SFAOAP) |
| 3 | 0x00D7F544 | 14 |
| 4 | 0x00D7F57C | 22 (SFADXT) |
| 5 | 0x00D7F5D4 | 39 (SFMPV) |
| 6 | 0x00D7F670 | 18 |
| 7 | 0x00D7F6B8 | 14 |

Each block is a **uniform 14-entry interface** (confirmed across all eight):

```
[0] Init  [1] Finish  [2] ExecServer  [3] Create   [4] Destroy
[5] RequestStop  [6] Start  [7] Stop   [8] Pause
[9] GetWrite [10] AddWrite [11] GetRead [12] AddRead [13] Seek
```

Blocks 4 and 5 append family-specific config words after the fourteen;
block 6 appends four more function pointers (`sfmps_Copy*`, all recovered).

`SftrnEntryListView` (SofdecFoundationRuntime.cpp) already models the table
correctly as `std::array<SftrnEntryDispatchView*, 15>` = 0x3C. But
`SftrnEntryDispatchView` is modelled with only **2** callbacks when the real
block has 14 - fix that when building the table. `sftrn_CallTrEntry` only ever
indexes [0] and [1], and **breaks at the first null entry**, so at
`SFTRN_Init` time only the eight `Init` functions actually run; the rest need
to be valid pointers, nothing more.

Status per block:

| block | family | state |
|---|---|---|
| 0 | SFUO | complete |
| 1 | SFM2TS | needs ExecServer (0x00ACF140), Create (0x00ACF800) |
| 2 | SFAOAP | **recovered d926c05** |
| 3 | SFVOM | complete |
| 4 | SFADXT | all 14 missing |
| 5 | SFMPV | needs Create (0x00AD4BA0) |
| 6 | SFMPS | complete |
| 7 | SFMEM | complete |

**SFADXT is the hard one** and should be its own pass: it is entangled with
the ADXT audio transport, which is entirely stubbed. Beyond its fourteen it
needs `sfadxt_ExecServerSub` (43), `sfadxt_InitInf` (116), `sfadxt_CreateEx`
(27), `sfadxt_WaitStart` (20), `sfadxt_SetTimeFn` (13), `sfadxt_GetHd`,
`sfadxt_SaveAdxtHn`, `sfadxt_DestroySub`, `sfadxt_ExcludeSilence`,
`SFADXT_SetOutPan/GetOutPan/SetOutVol/GetOutVol/SetSpeed`, plus `ADXT_Finish`,
`ADXT_InsertHdrSfa`, `ADXT_SetTimeOfst`, `SFPLY_GetResetFlg`, `UTY_FinishTmr`
and the init-count pair at 0x00B0F4A0/0x00B0F4B0 (`++/--` on 0x010597B0).
`UTY_MemsetDword` is still a stub. Note `ADXT_Init` itself is a 55-instruction
stub pulling in ~15 subsystem inits - that is the "audio never initializes"
item.

Original count when this was scoped: 116 unique code addresses, 85 recovered,
31 missing - 626 instructions across:

- **SFAOAP** (audio output adapter, 0x00ACFBD0-0x00ACFE50): Init/Finish/
  ExecServer/Create/Destroy/RequestStop/Start/Stop/Pause/GetWrite/AddWrite/
  GetRead/AddRead/Seek. Nearly all 2-20 instructions; most are
  `SFSET_GetCond(x,6)` guards forwarding to `SFTRN_CallTrtTrif` or
  `SFLIB_SetErr(x, -16774655)`.
- **SFADXT** (ADX transport, 0x00AD02C0-0x00AD1150): Init/Finish/ExecServer/
  Create(80)/Destroy(44)/Start/Stop/RequestStop/Pause(80)/Seek(33)/
  Get|AddWrite/Get|AddRead.
- Plus `SFM2TS_Create` (88), `SFM2TS_ExecServer` (21), `SFMPV_Create` (85).

The three Create bodies are the real work: they index big work-area structs
(`a1[3346]`, `a1 + 13564`, `a1[2049]`), so they need typed layouts with named
fields first - not raw offset arithmetic.

## Recipe for reading a static out of the PE

Section-mapped RVA reader (imageBase 0x00400000, 7 sections) - the pattern is
in the session scratchpad; parse `e_lfanew`, walk the section table, map
`rva -> rawPtr + (rva - virtualAddress)`. This is how the table above was
read; do the same rather than guessing at initialisers.

## What DID land

- `MWSFSVM_Error` (0x00ACCCC0) - 42edf71. 76 call sites had **no definition**
  at all (two conflicting overload declarations, plus a C-linkage stub whose
  name matched neither), so every Sofdec diagnostic would have jumped to the
  image base under /FORCE.
- Not committed but verified correct, ready to re-apply once the table exists:
  `MWSFSVM_Init` (0x00ACCAB0), `mwPlyInitSfdFx` (0x00AC9130), the four SFX
  leaves (`SFX_SetErrFn` 0x00ACC840, `SFX_SetCcirFx` 0x00ACCA50,
  `SFXZ_SetZbufType` 0x00ACDDF0, `sfxzmv_InitLibWork` 0x00ACD5B0), and a
  **size fix for `sfx_libwork`**: it was modelled as 8 bytes when
  `sfx_InitLibWork` clears 0x4AA dwords (0x12A8), with `errFn`/`errParam` at
  +0x08/+0x0C and `cirFx` at +0x14. `sfxz_work` is 0x98C
  (`zbufType` +0x04, `last` +0x08).

`SofdecSfxRuntime.cpp` and `SofdecCftColorTableRuntime.cpp` are the only two
Sofdec fragments **no TU includes** - their bodies are absent from the build.
Wiring SfxRuntime in needs its duplicate `SFXA_Init`/`SFXSUD_Init` dropped
(canonical copies are in `SofdecSvmTransferRuntime.cpp`) and its
`MWSFSVM_Error` declaration corrected; doing so adds `_SFX_Create` and
`_SFX_Finish` as unresolved (both unreachable - their only callers,
`MWSFSFX_Create`/`MWSFSFX_Finish`, have no callers).

Related: [[project-gal-device-vtable-slot-mismatch]],
[[project-reference-binary-log-diff]]
