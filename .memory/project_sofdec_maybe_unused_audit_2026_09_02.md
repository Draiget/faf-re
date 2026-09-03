---
name: project-sofdec-maybe-unused-audit-2026-09-02
description: Full maybe_unused audit of SofdecAdxPlatformRuntime.cpp/SofdecAdxXeficRuntime.cpp/SofdecMwPlaybackRuntime.cpp (146 function-level markers). 85 fixed via real wiring, 2 new functions recovered (ADXT_Finish, mwSndGetData), 5 confirmed legitimate bucket-A, 9 real-evidence-but-blocked-on-bigger-work, 50 triple-confirmed genuinely dead in this build.
metadata:
  type: project
---

## Scope and method

Audited every `[[maybe_unused]]`-marked function (146 function-level markers,
distinct from ~13 parameter-level `[[maybe_unused]]` uses that are unrelated
and correct as-is) across the three sofdec files with the highest
concentration: `SofdecAdxPlatformRuntime.cpp` (94), `SofdecAdxXeficRuntime.cpp`
(32), `SofdecMwPlaybackRuntime.cpp` (20).

Three independent evidence sources, escalating in cost:
1. Text grep for the function name as a call expression anywhere in
   `src/sdk` (catches already-wired-but-never-cleaned-up markers).
2. The namespace's `_callgraph_index.sqlite` via `find_callers.py`
   (binary-level code/data xrefs, cross-checked against
   `recovered_progress.json` status).
3. Direct read of the function's own `decomp/recovery/disasm/<ns>/FUN_*.xrefs.txt`
   (IDA's own ground-truth xref database — the most authoritative source,
   used to confirm every bucket-C conclusion below, not just spot-checked).

All three files aggregate transitively into one true translation unit,
`src/sdk/moho/audio/SofdecRuntime.cpp` (`SofdecRuntime.cpp` includes
`SofdecFoundationRuntime.cpp`, then `SofdecAdxRuntime.cpp` — itself
`SofdecAdxDeclarationsRuntime.cpp` → `SofdecM2aBitstreamRuntime.cpp` →
`SofdecAdxXeficRuntime.cpp` → `SofdecCvfsRuntime.cpp` →
`SofdecAdxPlatformRuntime.cpp` — then `SofdecSvmTransferRuntime.cpp`,
`SofdecSfdRuntime.cpp`, `SofdecSfxRuntime.cpp`, `SofdecMwPlaybackRuntime.cpp`,
and 5 more). **That is the correct tucheck target for any sofdec file** —
none of the three individual files compile standalone (no leading
`#include`s; they assume the aggregate context). Every commit below was
gated on `tucheck moho/audio/SofdecRuntime.cpp` → `EXITCODE=0`.

## Tallies

| Bucket | Count | Detail |
|---|---|---|
| (A) legitimate address-taken, left alone | 5 | 4 pre-existing (`SofDecVirt2_Func20`-`23`) + 1 newly recovered (`mwSndGetData`/`Func19`), all confirmed via the `sofdec_vtable2` data xref |
| (B) fixed via real wiring | 86 | see below; +1 for `adxt_PauseAll`/`ADXRNA_SetPauseAllStateAdapter`, landed in a same-session follow-up pass, commit `06121761` |
| (B) real caller found, wiring blocked on separate larger recovery | 8 | was 9; item #2 (`adxt_PauseAll`) resolved, see "Left open" |
| (C) genuinely dead in this build | 50 | triple-confirmed: text search + SQL callgraph + IDA's own xrefs.txt all independently show zero references |

Commits: `20992e6f`, `cf76b10f`, `7104ba08`, `4c3eada9`, `4f29f596`, `06121761`
(all on `master`).

## (B) fixed — 85 markers

- **63** were simple stale-marker removals: the function already had a real,
  by-name caller elsewhere in the tree (confirmed by both grep and the
  callgraph DB showing a `recovered` code caller) but the attribute was
  never cleaned up after that caller got wired in a later pass. No code
  change beyond removing `[[maybe_unused]]`. Covers the LSC background-
  server chain (`lsc_StatWait/Read/End` → `lsc_ExecHndl` →
  `lsc_ExecServer` → `LSC_ExecServer` → `adxt_ExecLscSvr`, itself
  registered into the SVM server-callback table by `ADXT_Init`), the
  ADXSJD decode-server chain (called cross-file from
  `SofdecAdxXeficRuntime.cpp`), the ADXT seamless-loop entry family, the
  `adxf_enter`/`adxf_leave` critical-section pair (~24 call sites), and 3
  cross-file `SofdecSet/GetMonoRoutingMode`/`SofdecSetBufferPlacementMode`
  calls from Xefic into MwPlayback. Plus 1 more caught in a follow-up sweep
  (`ADXRNA_SetTransposeWords` — missed in the first pass, has a real caller
  at `ADXRNA_SetSfreq`'s sibling).
- **4** in the first batch (`lsc_Alloc`, `LSC_Create`, `LSC_LockCrs`,
  `LSC_UnlockCrs`) — landed alongside a real fidelity bug: `LSC_Create` and
  `LSC_Init` called `SJCRS_Lock()`/`SJCRS_Unlock()` directly, but their own
  disassembly (`0x00B08AB0`, `0x00B098BB`, etc.) calls `_LSC_LockCrs`/
  `_LSC_UnlockCrs` — a real (already-recovered, itself a thin `SJCRS_Lock`
  wrapper) extra layer of indirection the source had skipped. Fixed the
  call chain to match.
- **7** ADXRNA public-thunk splits (`GetStateByte`, `SetControlWord44`,
  `SetBitPerSmpl`, `SetSfreq`, `SetOutVol`, `SetOutBalance`, `SetOutPan`) —
  see "Real bugs found" #2 and #3 below.
- **2** un-orphaned by recovering `ADXT_Finish` (`LSC_Finish`,
  `ADXCRS_Finish`) — see "Real bugs found" #5.
- **8** un-orphaned by recovering `mwSndGetData` (`SofdecCopyPcmBytes`,
  `SofdecWriteStereoCenterMix`, `SofdecWriteMonoIntoInterleavedLane`,
  `SofdecWriteStereoPrimaryPanMix`, `SofdecBuildStereoPanScratch`,
  `SofdecAccumulateStereoPanScratch`, `SofdecSwapPrimaryAndSecondaryBuffers`,
  `SofdecDrainAuxBufferToSilence`) — see "Real bugs found" #4 and #6.

## Real bugs found (beyond the orphan markers themselves)

1. **`LSC_Create`/`LSC_Init` locking bug** — called `SJCRS_Lock`/`Unlock`
   directly where the binary routes through `LSC_LockCrs`/`LSC_UnlockCrs`
   first (asm-confirmed both call sites). Same underlying critical section
   either way, so not a behavior bug, but a real source-fidelity gap. Fixed.
2. **7 ADXRNA functions had a never-recovered public thunk.** Each of
   `ADXRNA_GetStateByte`/`SetControlWord44`/`SetBitPerSmpl`/`SetSfreq`/
   `SetOutVol`/`SetOutBalance`/`SetOutPan` is really TWO binary functions:
   an internal core (properly addressed, already recovered) and a separate
   5-byte `jmp` thunk at the real *exported* symbol address
   (`0x00B17CA0`-`0x00B17D20`). A prior pass recorded the thunk's address
   as `Also emitted at: 0xXXXXXXXX` on the core function instead of
   recovering it as its own function, silently dropping it. Verified all 7
   thunk bodies directly (`FUN_00B17CA0.asm` etc.) before splitting each
   into `adxrna_*Core` + a new public wrapper. One caller
   (`ADXRNA_SetStreamHeaderLane4`) calls the *core* address directly per
   its own disassembly — repointed it at the `*Core` name rather than the
   new public wrapper, to keep the binary call graph 1:1.
3. **Duplicate recovery: `ADXRNA_SetOutPan` vs `SetAdxrnaOutputPan`.** The
   properly-addressed `ADXRNA_SetOutPan` (`FUN_00B15A80`, in
   `SofdecAdxPlatformRuntime.cpp`) had an independent, *unaddressed*
   near-duplicate named `SetAdxrnaOutputPan` in
   `SofdecAdxDeclarationsRuntime.cpp` — same logic, slightly different
   guard-clause shape, no `Address:` citation at all. The real caller
   (`adxt_SetOutPan`, `SofdecAdxCodecRuntime.cpp`) was wired to the
   *duplicate*, which is why the addressed function stayed orphaned
   despite genuinely having a caller. Folded away: deleted the duplicate,
   redirected `adxt_SetOutPan` to the addressed function (renamed to
   `adxrna_SetOutPanCore` to match the other 6 thunk-splits), added the
   missing `0x00B17D00` public thunk.
4. **`SofdecBuildStereoPanScratch` had the wrong arity.** Its real caller
   (`mwSndGetData`) pushes the same 4-argument block for it and its sibling
   `SofdecAccumulateStereoPanScratch` — one shared branch + one shared
   stack-cleanup for both — but `SofdecBuildStereoPanScratch`'s own
   disassembly (`FUN_00B17150.asm`) only ever reads `arg_0`/`arg_8`/`arg_C`;
   `arg_4` is dead on entry. The already-recovered 3-parameter signature had
   silently dropped that always-unused 2nd argument. Restored it as an
   explicit `[[maybe_unused]]` parameter to match the real call-site ABI —
   this doesn't change behavior (the parameter genuinely goes unused) but
   it does matter for anyone trying to verify the callsite matches the ABI
   byte-for-byte.
5. **`ADXT_Finish` (`0x00B0A4A0`) was completely unrecovered** — not
   present anywhere in `src/sdk` before this session, despite being the
   direct reference-counted teardown mirror of the already-recovered
   `ADXT_Init` (same subsystem list, same three `SVM_DelCbSvr` calls
   undoing `ADXT_Init`'s three `SVM_SetCbSvrWithString` registrations).
   Recovered for real (every callee it needs was already recovered
   somewhere in the tree); un-orphans `LSC_Finish` and `ADXCRS_Finish`.
   Kept `[[maybe_unused]]` itself — see "Left open" #1.
6. **`mwSndGetData` (`SofDecVirt2_Func19`, `0x00B174A0`) was completely
   unrecovered** — the one missing slot in an otherwise fully-recovered
   23-entry `sofdec_vtable2` dispatch table (`Func1`-`18` already existed as
   real public API, `Func20`-`23` are legitimate address-taken orphans).
   `find_callers` showed all 8 PCM-mixing helper functions sharing this
   exact one caller. Recovered name taken from the `kSofdecErrLockFailed`/
   `kSofdecErrUnlockFailed` string constants already in the tree (both say
   `"in mwSndGetData"` — not a guess). Un-orphans all 8 helpers at once.
7. **Systemic DB mis-tagging pattern.** At least 9 real CRI Sofdec/ADX
   engine functions this audit touched or found as callers — `adxt_stat_decinfo`,
   `adxt_stat_prep`, `ADXT_Finish` (now fixed), `mwSndGetData` (now fixed),
   `SFD_AttachMpa`, `SFD_AttachMPEG2AAC`, `SFADXT_Create`,
   `ADXRNA_SetStmHdInfo` — are/were marked `external_dependency` in
   `recovered_progress.json` with generic, apparently-automated
   reclassification notes (one literally cites *"Lua stdlib"* as the reason
   for an ADX statistics function). None have an `__imp_*`/CRT/D3D/wx
   boundary; all are genuine engine code per CLAUDE.md's own test. This
   looks like a real instance of the "external_runtime … usually
   mis-tagged engine code" category CLAUDE.md's own blocker table already
   names (48 tokens tree-wide as of the last snapshot) — worth a dedicated
   sweep, not something this pass tried to fix wholesale.

## (C) genuinely dead in this build — 50, triple-confirmed

Every one of these showed **zero** references from all three evidence
sources, including a direct read of IDA's own ground-truth
`FUN_*.xrefs.txt` (not just the derived SQLite index) — the same rigor
used to rule out the first cluster found (`mwPlySetCondition36`/`37`/
`93And94`/`78And77`/`86And85`/`88And87`/`90And89`/`92And91`/`95Pair`, a
9-function family of tiny `SFD_SetCond`-wrapper wrappers for specific
condition IDs FA/FAF's actual codec usage never sets). Grouped:

- **9** `mwPlySetCondition*` family (above).
- **5** `ADXRNA_Get*Thunk` family (`GetTimeScaleBaseThunk`,
  `GetStreamInfoWord60Thunk`, `GetStreamInfoWord64Thunk`,
  `GetStreamInfoWord6CThunk`, `GetLegacyQueueMetricWord08Thunk`) — each
  successfully un-orphans its own `Get*` counterpart (that WAS fixed, see
  bucket B), but the wrapper itself has no caller of its own.
- **4** other "Thunk"/"Hook"-named functions despite table-suggestive
  names (`ADXRNA_NoopHook0`, `ADXRNA_NoopHook1`,
  `ADXRNA_StopAndEnableTransferThunk`,
  `sofdec_DebugDumpAllQueuedEntriesThunk`).
- **3** `ADXM_*Thunk` multimedia-timer family (`ArmMultimediaTimerSwitchThunk`,
  `StartMultimediaTimerThunk`, `PulseSyncEventThunk`).
- **2** `lsc_EntrySvrInt`/`lsc_DeleteSvrInt` — both have empty `{}` bodies
  matching their own doc comments ("no runtime behavior... this build").
- **2** `ADXT_GetEosSct`/`ADXT_SetEosSct`, plus `ADXT_ResetEntry` and
  `adxstm_GetFilesystemServiceActive` (2 more).
- **10** more ADXRNA getters/setters (`SetLane6WordPair`, `mwRnaSetFx`,
  `SetStreamInfoWord88`, `mwRnaGetFx`, `GetStreamInfoWord88`,
  `GetTransportResetState`, `ClearTransportResetState`,
  `SetStreamHeaderLane3`, `GetStreamHeaderLane3`, `SetWavFname`).
- **3** more (`IsTransportFlagBit2Set`, `GetTransferHeadroomUnits`,
  `sj_QueryLegacyIoStatus`).
- **8** Xefic "safe accessor" family (`xefic_GetQueuedEntryCountOrMinusOne`,
  `xefic_GetUsedWorkBytesOrMinusOne`, `xefic_GetObjectPathPrefixOrNull`,
  `xefic_GetQueuedRelativePathByIndexOrNull`, `wxFicHasCachedHandleOrFalse`,
  `wxFicDisableFileIfValid`, `wxFicEnableFileIfValid`,
  `xefic_DebugDumpQueueForObjectLockedIfValid`) — each wraps a *real,
  called* base function with a null-check, but none of the wrappers
  themselves are ever called.
- **2** more MwPlayback (`SofdecSetPortBufferBytesPerChannel`,
  `SofdecGetPortBufferBytesPerChannel`).

These read as genuine platform/format-variant dead weight in a
multi-platform CRI middleware SDK (console-specific codecs, condition IDs,
legacy compatibility hooks) that this specific PC title's actual Sofdec/ADX
usage never exercises — not a process failure. Given the triple-confirmed
zero-evidence result, treat as **closed, no further action needed** rather
than a to-do list, unless fresh IDA re-analysis surfaces something the
current export missed.

## Left open — 9 items, each with a concrete next step

1. **`mwPlyFinishSfdFx`** (`0x00AC93D0`) is a **wrong-signature stub**
   (`void* mwPlyFinishSfdFx() { return nullptr; }`, in
   `SofdecExternalStubs.cpp`) instead of its real ~155-byte, 14-callee
   teardown body (mirrors the already-recovered `mwPlyInitSfdFx`). Full
   disassembly already captured. Callees: `MWSFLIB_GetLibWorkPtr`,
   `mwPlyDestroy` (×32 slots), `MWSFD_SetReqSvrBdrHn`,
   `MWSFSVM_GotoIdleBorder`/`DeleteVfunc`/`DeleteMainFunc`/`DeleteIdleFunc`,
   `MWSFSFX_Finish`, `LSC_Finish` (recovered), `mwPlySfdFinish`,
   `ADXT_Finish` (recovered this session), `MWSTM_FinishStatic`,
   `SJUNI_Finish`/`SJMEM_Finish`/`SJRBF_Finish` (all recovered),
   `MWSFSVM_Finish` — most are unchecked for recovery status. Un-orphans
   `ADXT_Finish` once done. Not attempted here: outside the 3 target
   files, and this specific stub/signature-mismatch is pre-existing debt,
   not something this session introduced.
2. **`adxt_PauseAll`** (`0x00B0E6F0`) — **RESOLVED 2026-09-02, faf-main-f7,
   later same-session pass, commit `06121761`.** Correction to the note
   above: it did already have a definition (`SofdecAdxPlatformRuntime.cpp`
   ~line 9791) — the "no definition anywhere" claim was wrong, missed
   because the grep that produced this list matched on the declaration
   only. The real bug: that definition called `adxrna_SetPauseAllState`
   (`0x00B15530`) DIRECTLY instead of tail-calling
   `ADXRNA_SetPauseAllStateAdapter` (`0x00B17DB0`) the way the real
   binary's 5-byte `jmp sub_B17DB0` does — behaviorally identical (the
   adapter itself just forwards to the same function, confirmed by
   reading its body) but bypassed the real call chain and kept the
   adapter orphaned. Fixed by rewiring `adxt_PauseAll` to call the
   adapter by name and removing the adapter's now-inaccurate
   `[[maybe_unused]]`. `tucheck` clean on `moho/audio/SofdecRuntime.cpp`
   (the aggregate TU).
3. **`adxt_stat_decinfo`** (`0x00B1A6A0`, ~319 bytes / 25+ callees) and
   **`adxt_stat_prep`** (`0x00B1A9D0`, ~300 bytes / 10+ callees, including
   one unresolved vtable dispatch through `[eax+18h]`/`[eax+20h]`) are both
   genuinely substantial, separate recovery targets — full disassembly
   already captured for both. Together they un-orphan `adxt_start_stm`,
   `ADXRNA_SetStreamHeaderLane4`, `ADXRNA_GetNumRoom`, `ADXRNA_SetNumChan`,
   `ADXRNA_SetTotalNumSmpl`. Both currently DB-mis-tagged
   `external_dependency`.
4. **`SFD_AttachMpa`/`SFD_AttachMPEG2AAC`/`SFADXT_Create`** — un-orphan
   `ADXT_StartSj` once any is recovered; sizes not yet checked.
5. The **DB mis-tagging pattern** (real engine code marked
   `external_dependency` with generic auto-reclassification notes) is
   worth a dedicated tree-wide sweep — see "Real bugs found" #7.

## Guardrails followed

Never touched `Global.cpp`/`LuaObject.cpp`/`LuaParser.cpp`/
`WxRuntimeTypes.cpp`/`CWldSession.cpp`/`CWldMap.cpp`/`*FidelityTerrain.cpp`
(verified via `git status --short` before starting and periodically — they
showed other sessions' concurrent, uncommitted changes throughout; those
were never staged or touched). Every commit used an explicit pathspec
(`git add <exact files>`), never `-A`/`.`, specifically because `.memory/`
and several scratch files from concurrent sessions were sitting untracked
in the working tree the whole time.
