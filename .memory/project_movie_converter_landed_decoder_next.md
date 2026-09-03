---
name: project-movie-converter-landed-decoder-next
description: The whole ARGB8888 movie converter chain is LANDED and links; the black screen is now proven to be upstream - mwPlyGetCurFrm never gets a frame because SFD_GetFrm returns null
metadata:
  type: project
---

Supersedes the "wire the CFT chain" plan in
[[project-movie-black-screen-cft-chain]] - that work is **done**. Session
2026-08-07, commits `73a9e32`, `4d43605`, `03df78c`, `f3d701a`.

## What landed (the conversion tail is complete)

The chain from `CMovie::UploadCurrentFrameToTexture` down to the pixel kernel
is now unbroken source:

  - `cft_sse_Ycc420plnToArgb8888UserTable` (0x00AF2B20) + the MMX twin
    (0x00AF3040). Both were `void* f() { return nullptr; }` C-linkage stubs.
  - `_cftbgra256x3` (0x00F420E0) was a **zero-filled placeholder**
    (`std::array<std::uint64_t, 0x300>{}`), which alone guarantees a black
    picture. Now carried as the real literal, verified word-for-word against
    the PE at file offset 0x00B420E0.
  - `sfxcnv_ExecCnvFrmByCbFunc` (0x00ACEB10) + `sfxcnv_MakeCftSrcBuf`,
    `SFX_GetCnvBottomUp`, `SFX_SetBottomUpDstBuf`.
  - `mwPlyFxCnvFrmARGB8888` / `Clip` + `SFX_Make1PlaneCftDstBuf`,
    `SFX_SetClipping`, `SFX_ShiftYccPtrByPix/ByLine`,
    `sfxset_ShiftBufInfByPix/ByLine`, `sfxcnv_MakeDstBufInf`,
    `sfxcnv_IsCnvUpHalf`, `SFX_SetMaxRowToYccPln`, `SFX_CnvFrmARGB8888ByCbFunc`,
    the six callback setters, `SFX_IsMergeField` + helpers,
    `SFX_GetOutBufSize`, `SFX_SetOutBufSize`,
    `SFX_CnvFrmAndMargFieldByCbFunc`.

**The MMX kernel is a pure table lookup - do not port SIMD.** Per 2x2 luma
quad: `paddw` the Cb and Cr entries once (wraps at 16 bits; the alpha lane of
16320 depends on it), add the luma entry, `psraw 6`, `packuswb`. Table planes
at +0, +0x800, +0x1000. Confirmed against the disassembly, not just the
decompiler.

## Layout bug fixed along the way (was corrupting Cb/Cr)

`MwsfdSfxFrameInfo` had its plane records 12 bytes apart. They are **16**:
`mwsfsfx_SetYcc420plnInfToSfx` (0x00AC68B0) fills them at `a2+1`, `a2+5`,
`a2+9` = +0x04 / **+0x14** / **+0x24**, while `mwsfsfx_SetSfxBufInf`
(0x00AC6960) writes only three dwords, leaving a reserved tail. So `cbPlane`
and `crPlane` sat 4 and 8 bytes low and the recovered setter wrote both chroma
descriptors to the wrong offsets. Confirmed four independent ways: that
setter, `sfxcnv_MakeCftSrcBuf`'s symmetry, `SFX_ShiftYccPtrByPix` (+4/+20/+36),
and the lane picks in `CFT_Ycc420plnToArgb8888Prg/Int`. The former
`planeWidth`/`planeHeight` at +0x28/+0x2C were crPlane's own pitch and height.

## THE ACTUAL BLOCKER NOW - no frame is ever decoded

Instrumented `CMovie::UploadCurrentFrameToTexture` and ran. Every frame:

    debug: MovieUpload: ply=017CAE54 buf=00000000 sheet=0AF0A460

The upload IS called, the texture sheet exists, but `mwPlyGetCurFrm`
(0x00ACA090) returns `bufferAddress == 0`, so it returns before ever reaching
the converter. `MovieFrame:` (the post-conversion probe) never printed.

`mwPlyGetCurFrm` zeroes `bufferAddress` when `SFD_GetFrm(sfdHandle, &frame)`
leaves `frame == nullptr`. `SFD_GetFrm` (0x00AD85D0) is recovered.

`sfply_ExecOne` (0x00AD6F00) WAS a stub and is now recovered (`f9745f4`) -
all five state handlers `sfply_StatStop/Prep/Stby/Play/Fin` already had real
bodies and nothing called them. That fixed a genuine defect but did **not**
produce a frame: `buf=00000000` still, every tick.

**The real blocker is one level up: nothing ever ticks the decode server.**
`SFD_ExecServer` (0x00AD6EC0) walks the SFLIB handle table calling
`sfply_ExecOne`, and it has **no callers in the callgraph index** - it is
reached only through a function-pointer table owned by the Sofdec worker
threads. Every one of those is still a stub in `SofdecExternalStubs.cpp`:

    ADXM_SetupThrd            (creates the middleware threads)
    MWSFSVR_MainThrdProc
    MWSFSVR_VsyncThrdProc
    MWSFSVR_IdleThrdProc
    MWSFSVM_GotoIdleBorder

So the pipeline is: no threads -> no server tick -> no state advance -> no
decode -> `SFD_GetFrm` null -> `bufferAddress == 0` -> black. `SFD_ExecOne` is
called from `SofdecAdxPlatformRuntime.cpp:4189`; trace what drives *that* to
find the tick entry point the threads are supposed to call.

The three MWSFSVR thread procedures are now recovered too (`ee2af20`):
`MWSFSVR_MainThrdProc` (0x00AD9230), `IdleThrdProc` (0x00AD9250),
`VsyncThrdProc` (0x00AD9220), plus `MWSFSVR_GetDecSvrFromIprm` (0x00AD9270)
and `MWSFSVR_TimeServer` (0x00AD9280). Main and idle are exact complements
gated on `MwsfdLibWork::decodeServerSelection` (+0x10). Still
`buf=00000000`.

**NEXT STEP, precisely: `adxm_setup_thrd` (0x00B06C10, 428 bytes, 114
instrs) and its one-line caller `ADXM_SetupThrd` (0x00B07C80) are still
stubs, so the three threads whose bodies now exist are never created.**
The setup function does, in order: init the critical section, capture
QueryPerformanceFrequency/Counter, create `adxt_crs`, `timeBeginPeriod(1)` +
`timeSetEvent(1, 0, fptc, ...)`, `SVM_Init`, install the SVM lock /
unlock / test-and-set callbacks, copy or default the thread parameter block
(priority 15, `dword_1059010 = 2`, sprm `{1, 1, ?, -2}`), then
`adxm_create_thrd` + `adxm_set_thrd_prio`, `ResumeThread` on the vsync, fs
and mwidle handles, and finally `SVM_SetCbBdr(6, adxm_goto_mwidle_border,
0)`. Dependency inventory is DONE - every SVM_* and callback it needs already
has a body (`SVM_Init`, `SVM_SetCbLock/Unlock/TestAndSet/Bdr`, `SVM_Finish`,
`adxm_test_and_set`, `adxm_goto_mwidle_border`, all in
SofdecAdxPlatformRuntime.cpp). Exactly three functions are missing, and they
are the thread-creation trio:

    adxm_create_thrd    0x00B06FE0  320B / 103i
    adxm_set_thrd_prio  0x00B072D0  276B /  90i
    adxm_destroy_thrd   0x00B07120  430B / 127i

`adxm_create_thrd` (0x00B06FE0) and `adxm_set_thrd_prio` (0x00B072D0) are
LANDED (`7f4c45d`), and the priority-block layout bug they exposed is fixed
(`39eb212`).

**`AdxmThreadStartupParams` was mislabelled and is now corrected.** The order
is pinned by absolute addresses: `adxm_setup_thrd` writes `nPriority` at
0x0105900C and `adxm_thread_sprm+0xC` at 0x01059020, putting
`adxm_thread_sprm` at 0x01059014, so the array overlays the block from +0x08.
`adxm_set_thrd_prio` applies sprm[0]/[1]/[3] to vsync/fs/mwidle =
+0x08/+0x0C/+0x14. The old struct had fs and vsync transposed and mwidle at
+0x0C, so `adxm_goto_mwidle_border` (0x00B069F0) was restoring the fs priority
to the mwidle thread. Confirmed at 0x00B06A4A.

**Reuse the existing lanes.** `SofdecAdxDeclarationsRuntime.cpp:~3835` owns
`gAdxmLock`, `gAdxmVsyncCount`, `gAdxmMwIdleCount`, the vsync/fs/mwidle
loop+exit lanes, `gAdxmMwIdleThreadHandle`, `gAdxtVsyncEventHandle`
(= `adxt_crs`) and `gAdxmThreadStartupParams`, and the recovered thread
bodies already read them. The first attempt declared a parallel set and had
to be reverted - do not repeat that.

`adxm_destroy_thrd` (0x00B07120) is LANDED too (`daa9626`) - the binary
spells the same stop-and-close sequence three times and it is lifted into one
helper parameterised on handle + loop/exit flags + timeout message.

The ENTIRE thread layer is now landed: `adxm_destroy_thrd` (`daa9626`),
`adxm_setup_thrd` + `ADXM_SetupThrd` (`d4fc897`). All globals were reused
rather than redeclared - `gAdxmLock`, `gAdxtVsyncEventHandle`,
`gAdxmPerformanceFrequency`, `gAdxmTimerSwitchState`,
`gAdxmMultimediaTimerId`, `gAdxmMultimediaTimerCallback`,
`gAdxmThreadStartupParams`, the worker loop/exit/count lanes. Only
`adxm_init_level` and the perf-counter base are new.

## ROOT CAUSE FOUND: SetThreadAffinityMask fails with error 87

Instrumented down the chain. `CMovieManager::CMovieManager`
(`moho/misc/StartupHelpers.cpp:6336`) already calls `::ADXM_SetupThrd(nullptr)`
in the right order, and it IS reached. Runtime output:

    AdxmSetup: enter level=0 factory=5BE19E00
    AdxmCreate: v=000007F8 f=000007FC m=0000078C cur=FFFFFFFE
    AdxmCreate: affinity pin FAILED err=87
    AdxmSetup: create=-1 prio=0

So **all three worker threads are created successfully**. What fails is the
`SetThreadAffinityMask(..., 1)` pin - ERROR_INVALID_PARAMETER - and because
`adxm_create_thrd` treats that as fatal, `adxm_setup_thrd` tears the threads
straight back down and returns. Hence no server tick, no decode, black frame.

`cur=FFFFFFFE` is just the GetCurrentThread pseudo-handle, which is legal
here. The binary does exactly the same thing (all four calls, short-circuited
with `&&`), so the recovery is faithful - the question is why it fails on
this host.

Host data point, so nobody re-measures it: **36 logical processors, process
affinity mask all 36 bits set.** That is a single processor group and mask 1
is a valid subset, so the obvious "multi-group machine" theory does NOT
explain it. Something else is wrong.

## The affinity failure is ENVIRONMENTAL, and fixing it is still not enough

`adxm_create_thrd` hardcodes thread affinity 1 (CPU 0), as the binary does.
On this host the *process* mask is `0xFFFFFC` - bits 0 and 1 clear - so
asking for CPU 0 returns ERROR_INVALID_PARAMETER and all four pins fail,
including the GetCurrentThread pseudo-handle:

    AdxmPin: ok=1 proc=fffffc sys=ffffffff want=1
    AdxmPin: v=0/87 f=0/87 m=0/87 cur=0/87
    AdxmSetup: create=-1 prio=0

Proved it is only that, by relaunching with a full mask
(`scratchpad/runaff.ps1` starts main.exe then sets ProcessorAffinity):

    AdxmPin: ok=1 proc=fffffff sys=ffffffff want=1
    AdxmPin: v=268435455/0 f=268435455/0 m=268435455/0 cur=268435455/0
    AdxmSetup: create=0 prio=0
    AdxmSetup: threads vsync=000007EC fs=000007F0 mwidle=000007F4

So the recovered code is correct and the whole thread layer works. Nothing in
the engine narrows the mask - `/singleproc` is not passed,
`lua_SetProcessAffinity` needs a Lua call, and `moho/core/Thread.cpp:175`
sets thread affinity only. `explorer` has the full 36-bit mask, so
`0xFFFFFC` is a per-executable setting remembered for main.exe (the shape of
a hand-set Task Manager affinity). Clear it, or keep using `runaff.ps1`.

**BUT THE FRAME IS STILL EMPTY.** With all three threads running:

    MovieUpload: ply=01CACE54 buf=00000000 sheet=0B21EF50

So the thread layer was necessary-looking but is NOT the last blocker
either. That is now five consecutive "this must be it" fixes - converter,
pump, thread procs, thread setup, affinity - each a real defect, none of
them producing a frame.

**Traced one more level and the answer is: `sfply_ExecOne` is NEVER CALLED,
even with all three threads running.** A probe at its top reporting
`handleState` and the pending flag produced no output at all under
`runaff.ps1`.

So the threads are alive but nothing routes from them to the SFD server.
The gap is between the thread bodies and `SFD_ExecServer` / `SFD_ExecOne`:

    adxm_vsync_proc -> SVM_Lock, SVM_ExecSvrVsync, SVM_Unlock
    adxm_fs_proc    -> SVM_ExecSvrFs

**`SVM_ExecSvrVsync` and `SVM_ExecSvrFs` are the next targets.** They
dispatch through the SVM server-registration table, and `SFD_ExecServer` has
no direct callers in the callgraph precisely because it is reached through
that table. So the likely defect is that nothing ever *registers* the SFD
server with SVM - look for the SVM_SetSvr / server-entry registration call
that `mwPlyInitSfdFx` or `MWSFD_Init` should be making, and check whether
those registration functions are still stubs.

Checked: both are real bodies, and both are thin -
`SVM_ExecSvrVsync()` is `return SVM_ExecSvrFunc(2)` and `SVM_ExecSvrFs()` is
`return SVM_ExecSvrFunc(4)` (`SofdecAdxPlatformRuntime.cpp:16413/16429`).
`SVM_ExecSvrFunc(lane)` walks the SVM server-registration table for that
lane.

**So the defect is almost certainly that nothing ever registers the SFD
server into the SVM table.** Start at `SVM_ExecSvrFunc` - read what table it
walks and which setter populates it (`SVM_SetCbSvr` / `SVM_EntrySvr` /
similar), then check whether that setter is a stub and, more importantly,
whether anything calls it. `mwPlyInitSfdFx` (called from
`CMovieManager::CMovieManager` right after ADXM_SetupThrd) is the most likely
place the registration should happen - and it IS reached, since the ctor runs.

**CONFIRMED - the SVM server table is never populated.**
`SVM_ExecSvrFunc(svtype)` walks `gSvmServerCallbackTable`
(`SofdecAdxDeclarationsRuntime.cpp:3900`, 48 slots) and calls whatever
`callbackFn` it finds. The registrar `SVM_SetCbSvr`
(`SofdecAdxPlatformRuntime.cpp:~16150`) is recovered - **but nothing in
`src/sdk/**` calls it.** A grep for SVM_SetCbSvr / SVM_EntrySvr outside its
own definition returns only the error-string constants.

So: threads run -> SVM_ExecSvrVsync/Fs -> SVM_ExecSvrFunc(2)/(4) -> walks an
empty table -> the SFD server is never ticked -> no decode. That is the
whole remaining bug.

**Callers of the registrars, from the callgraph index** (`SVM_SetCbSvr`
0x00B0C4E0 forwards to `SVM_SetCbSvrWithString` 0x00B0C500 -> `svm_SetCbSvr`
0x00B0C530; `SVM_SetCbSvrId` 0x00B0C630 similarly):

    MWSFSVM_EntryVint      body in SofdecSvmTransferRuntime.cpp, 1 callsite
    MWSFSVM_EntryVfunc     body in SofdecSvmTransferRuntime.cpp, 1 callsite
    MWSFSVM_EntryIdleFunc  body in SofdecSvmTransferRuntime.cpp, 3 callsites
    MWSFSVM_EntryMainFunc  body in SofdecSvmTransferRuntime.cpp, 3 callsites
    MWSFSVM_EntryIdVfunc   body in SofdecSvmTransferRuntime.cpp, 3 callsites
    ADXT_Init              *** STILL A STUB *** , 3 callsites

All five MWSFSVM_Entry* have real bodies and real callsites, so registration
*should* be happening - which means the next thing to determine is whether
those callsites actually execute, and into which lane they register.
`SVM_ExecSvrVsync` reads lane 2 and `SVM_ExecSvrFs` lane 4; if the SFD server
registers into a different lane (main = 5, mwidle = 6) then the mwidle thread
is the one that matters and its proc has an early-out worth checking.

`ADXT_Init` being a stub is a separate, real gap - it registers the ADX audio
servers.

**Next run: put an AdxmDiagf in `svm_SetCbSvr` reporting svtype and the
callback, and one in `SVM_ExecSvrFunc` reporting the lane and slot count.**
Two lines, one run, and it will show exactly which lanes get populated and
which lanes the threads actually poll. Use `runaff.ps1` or the threads never
start.

This is a registration-wiring problem of the same shape as
[[project-lua-registration-sweep]]: the machinery is recovered, the question
is only who calls the registrar and when.

## Instrumentation currently in the tree (REMOVE before committing)

`src/sdk/moho/movie/CMovie.cpp` has two throttled `gpg::Debugf` probes in
`UploadCurrentFrameToTexture` (`MovieUpload:` at entry, `MovieFrame:` after
conversion with a non-zero pixel count), plus an `AdxmDiagf` bridge at the
end of the file. `SofdecAdxPlatformRuntime.cpp` has an `AdxmDiagf` call in
`adxm_setup_thrd` and an `extern "C"` declaration for it near
`adxm_set_thrd_prio`. All of it is diagnostics, not recovery - strip it once
frames arrive. The bridge exists because `gpg::Debugf` is not visible from
the Sofdec fragments; it is genuinely useful, so consider keeping it while
this investigation continues.

## Still unresolved at link (both only address-taken, off the taken branch)

`CFT_Ycc420plnToArgb8888Prg` (0x00AEEB40) and `Int` (0x00AEE960), 252 bytes
each, plus their `cft_c_`/`cft_sse_` leaf tier. `SFX_CnvFrmARGB8888ByCbFunc`
picks them only when the frame's chroma-position lane is not 1. Baseline
unresolved count was 17; it is 19 with these two.

## Tools

`scratchpad/capwin2.ps1` captures the game window with `PrintWindow` +
`PW_RENDERFULLCONTENT` and prints a non-black pixel percentage, which is the
fast "did anything render" check. The older `capwin.ps1` uses
`CopyFromScreen` and silently captures whatever window is on top instead -
prefer capwin2.
