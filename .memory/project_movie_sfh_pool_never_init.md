---
name: project-movie-sfh-pool-never-init
description: CONFIRMED root cause of "not a valid SFD file" - the SFH analyzer pool is never initialised (sfh_workinfo.size==0), so SFH_Create always returns null and no movie pack can ever be identified. Traced to SFD_Init never completing. Plus the SFHDS_ProcessHdr stub found on the way.
metadata:
  type: project
---

Established 2026-08-05. Work is UNCOMMITTED in the tree at time of writing.

## The confirmed failure, proven at runtime

Probe output from a live run:

```
warning: SofDec error: SFDPROBE IsSfdHeader: SFH_Create null - POOL NEVER INITIALISED (size==0)   (x3)
warning: /movies/thqlogo.sfd is not a valid SFD file.
```

`sfh_workinfo.size == 0`, so `SFH_Create` (0x00ADC760) returns null on its
first test (`cur >= size`), so `SFHDS_IsSfdHeader` answers 0 for every pack,
so `sfcre_AnalySfh` bails before assigning a video descriptor, so
`SFD_AnalyCreInf` leaves headerWord0/1 clear, so `mwPlyGetHdrInf` returns 0.

**The movie file is fine.** Verified byte-for-byte against `thqlogo.sfd`:
pack start codes every 2048 bytes exactly, signature at pack+0x20 is
`'SofdecStream            '` which is byte-identical to `kSofdecStreamSignature`,
tool banner at +0x60 is `'Sofdec CRAFT/Console Ver.2.94'`, version bytes at
+0x38/0x39 are 2/26 -> banner 294 beats embedded 226 -> version 294 (>=110, so
`isEffectiveVer` would pass). Detection would succeed if it ever got a slot.

## The init chain that never runs

```
mwPlySfdInit (0x00AC9490)          <- SofdecAdxPlatformRuntime.cpp:1830
  initParams.callbacks = gMwsfdInitSfdParams.callbacks
  SFD_Init (0x00AD8B90)            <- SofdecSfdRuntime.cpp:8867
    sflib_InitBaseLib()
    if (sflib_InitLibWork(initParams) != 0) return;   <-- EARLY RETURN
    sflib_InitSub()                <- the only caller of SFHDS_Init
      SFHDS_Init() -> SFH_Init(32, sfh_work) -> publishes sfh_workinfo
```

**RESOLVED by probe: `SFD_Init` is never entered at all** - its entry probe
never prints. `mwPlySfdInit` has zero callers in our source. In the binary its
only caller is `mwPlyInitSfdFx` (0x00AC9130), and that is a **deliberate
nullptr stub** at SofdecExternalStubs.cpp:162, with this reason recorded there:

> mwPlyInitSfdFx is fully recovered and verified, but cannot be enabled yet: it
> reaches SFD_Init -> sflib_InitLibWork -> SFTRN_Init, which copies the 60-byte
> SFD transfer descriptor table out of mwsfd_initsfdpara.callbacks. That static
> (0x00D7F40C -> table at 0x00D7F3D0) is not modelled, so the pointer is null
> and the copy faults. Modelling it needs the 8 descriptor blocks it points at -
> 116 entries, of which 31 are still unrecovered (SFAOAP and SFADXT). Until
> those land, this stays a no-op stub so startup does not crash.

`StartupHelpers.cpp:6351` DOES call `::mwPlyInitSfdFx(&initParams)` - it binds
to the no-argument stub because C linkage ignores parameters. That is the same
trap for the third time in this subsystem (mwPlyGetHdrInf, SFHDS_ProcessHdr,
mwPlyInitSfdFx).

**So the movie blocker is fully mapped and is the descriptor-table work:**
1. finish the unrecovered SFADXT entries (SFAOAP block 2 landed in d926c05),
   plus SFM2TS ExecServer 0x00ACF140 / Create 0x00ACF800 and SFMPV Create
   0x00AD4BA0,
2. model `mwsfd_initsfdpara` (0x00D7F40C) + the 8-block table at 0x00D7F3D0,
3. un-stub `mwPlyInitSfdFx`.

Then the pool initialises, `SFH_Create` hands out slots, detection succeeds,
and the SFHDS analysis chain recovered below actually runs. The SFHDS work is a
genuine prerequisite - it would have been the very next failure.

## Also found and fixed on the way (uncommitted)

- **`SFHDS_ProcessHdr` was a nullptr stub** (SofdecExternalStubs.cpp). C
  linkage ignores parameters when mangling, so a no-argument stub silently
  satisfied the properly-declared call in `sfcre_ProcessHdr` and the linker
  never complained. Recovered (0x00AE7400) with its worker `sfhds_DoProcessHdr`
  and the analyzers. It is a REAL blocker, just the second one, not the first.
- **29 missing `SFH_Anly*`/`SFH_Is*` accessors** recovered (0x00ADC930-0x00ADD6D0).
- **`SofdecFeatureHeaderRuntimeView::version` was at +0x08; it is at +0x0C.**
  asm proof: `isEffectiveVer` does `mov eax,[esi+0Ch]`, `SFH_AnlyByteRate` does
  `cmp dword ptr [edi+0Ch], 6Eh`. +0x08 is the remaining byte count, so the
  version check was comparing a length against 107/110.
- **`SfcreHeaderRuntimeView` was 0x70; it is 0x894.** `sfhds_DoProcessHdr`
  writes to index 35 (0x8C), and `sfcre_ProcessHdr` copies 0x800 bytes to +0x94
  with the length at +0x90. Backing storage is `std::uint8_t sfcre_fhd[4096]`,
  which is why the undersized model never crashed.

## Build-system traps that cost several cycles

- `cri/sofdec/*.cpp` are **fragments `#include`d** into aggregator TUs
  (`SofdecSfdRuntime.cpp` -> `moho/audio/SofdecRuntime.cpp`;
  `SofdecAdxPlatformRuntime.cpp` -> `SofdecAdxRuntime.cpp`) and are listed as
  `<None>` in the vcxproj. Editing a fragment does NOT reliably invalidate the
  aggregator - I got repeated 10-second "successful" builds that compiled
  nothing. Delete `buildstage/main/Win32/Debug/SofdecRuntime.obj` to force it,
  and always verify by searching the staged exe for a probe string.
- Concurrent agent builds cause `error C1041: cannot open program database`.
  Fix without touching the shared vcxproj: `set CL=/FS` before msbuild -
  scratchpad `bldfs.bat` does this.
- `tucheck` on `cri/sofdec/SofdecAdxRuntime.cpp` fails with bogus
  `std::int32_t is not a member of std` - its isolated harness lacks the
  prelude. That TU builds fine in the real build; don't chase it.

Related: [[project-sofdec-movie-crash]], [[project-taskbar-owner-and-dpi-icon]]
