---
name: project_playback_speed_frame_slaved
description: Movie playback runs slow because the Sofdec clock advances exactly one vblank per app frame (no-ADXM-worker fallback) and our Debug build renders ~24fps instead of 60. Full measured frame budget + proof every link in the chain is faithful to the binary.
metadata:
  type: project
---

# Why movie playback is slow: the clock is slaved to the frame rate

Measured, not inferred. Do not re-derive this — the whole chain is confirmed
faithful to the shipped binary.

## The mechanism

`sftim_GetTimeVsync` returns `(vsyncTimeMajor, ticksPerSecond)`; time in seconds
is `major/minor`. `minor` = 59940 (set from `initParams.vhz * 1000` via
`SFTIM_Init`). Each vblank adds exactly **1000** to `major`, so correct playback
needs **59.94 vblanks/sec**.

The vblank pump is `SFTIM_VbIn` <- `SFD_VbIn` <- `mwSfdVsync` <-
`MWSFSVR_TimeServer` <- SVM vfunc id 2 <- `SVM_ExecSvrVsync`. That is normally
run by the ADXM **vsync worker thread** at the multimedia-timer rate. With no
worker threads, `adxmng_DecideFramework` picks lane 1, so
`ADXM_ExecMain` -> `ADXM_ExecSvrAll` runs *every* lane on the caller's thread -
and `ADXM_ExecMain()` is called **once per app frame** from `CScApp::Main`
(CScApp.cpp, faithful).

=> **one Sofdec vblank per rendered frame.** Frame rate *is* playback speed.

Measured: 23.6 vblanks/s vs 59.94 needed = **39% speed** (2.5x too slow), and
the app frame rate over the same window was 24.4/s. They track 1:1.

## Why there are no ADXM worker threads (faithful, not a bug)

FAF's stock `C:\ProgramData\FAForever\bin\init.lua` (lines 32-57) does:
```lua
if systemAffinityMask >= 16777215 then
    processAffinityMask = 16777212 -- 2^24-3-1  == 0x00FFFFFC
```
i.e. on any machine reporting >=24 CPUs it **excludes CPUs 0 and 1**. This
machine has 36. Probe confirmed `LUAAFFINITY mask=00FFFFFC` at tick 86400015,
`CMovieManager` ctor 15.8 s later with `proc=00FFFFFC` already in force.

`adxm_create_thrd` pins all four Sofdec threads to **CPU 0** and gives up if any
pin fails. All four `SetThreadAffinityMask(h, 1)` fail with **error 87**
(ERROR_INVALID_PARAMETER) because CPU 0 is not in the process mask, so
`adxm_setup_thrd` runs `adxm_destroy_thrd()` + `SVM_Finish()` and returns.

**All of this is byte-faithful** - verified against `FUN_00B06FE0.c`
(adxm_create_thrd: same `SetThreadAffinityMask(...,1u)` chain, same
`return -1`) and `FUN_00B06C10.c` (adxm_setup_thrd: same
`if (adxm_create_thrd() < 0 || adxm_set_thrd_prio() < 0) { destroy; SVM_Finish;
return; }` early return). The shipped `ForgedAlliance.exe` loses its ADXM
workers on this machine in exactly the same way. It plays correctly only
because it sustains 60 fps.

## Measured frame budget (Debug, 1024x768, splash)

Per frame, early (thqlogo) -> later (gpglogo):

| item | cost |
|---|---|
| `CUIManager::UpdateFrameRate` -> `mFrames[0]->Frame()` (incl. movie `ADXM_WaitVsync` ~10ms + upload 1.8ms) | 11 ms -> 24 ms |
| `PublishEngineStatsToLua` (+ 5 s GC block) | 17 us -> **13.5 ms** |
| `ADXM_ExecMain` -> `SVM_ExecSvrMain` = MPEG decode | 10.2 ms -> 6 ms |
| `WxAppRuntime::Dispatch` (incl. `CD3DDevice::Paint`: Present 1.4ms + render 0.6ms) | 2.5 ms |
| `SND_Frame`+`WLD_Frame`+`sUserStage->UserFrame` | ~35 us total |
| `MsgWaitEx`, `ProcessIdle`, both `UserFrame` stages, `Refresh` | ~0 |
| **total** | **25 ms -> 42 ms** |

`ADXM_WaitVsync` is the *pacing* wait (waits on the manual-reset event the 1 ms
multimedia timer pulses; measured **61 Hz**, healthy, `nextMs=16` fallback since
nothing calls `ADXM_SetInterval1`). It absorbs slack only if the rest of the
frame is under one 16.4 ms period. Our real work is ~14-25 ms, so we straddle
the period and miss roughly every other pulse -> 25-42 ms frames.

`PublishEngineStatsToLua` running every frame is faithful: `FUN_0084D160` calls
`STAT_GetLuaTable(mState, EngineStats->mItem, &value)` +
`SetObject(globals,"__EngineStats")` unconditionally every frame.

## Conclusion

Every hot item is faithful. The deficit is **throughput in an unoptimized
Debug build**, and because the movie clock is frame-slaved in the (correct)
no-worker fallback, slow frames become slow playback. Getting under
16.4 ms/frame locks the loop to the 61 Hz pulse and playback becomes correct.

## Probing recipe (all reverted; re-add if needed)

Timestamps via `std::chrono::steady_clock` deltas are safe despite the QPC hook
(it rebases the origin, deltas stay valid). In `cri/sofdec/*.cpp` fragments
there are no includes of their own - use `fopen_s`/`fprintf` to
`G:\tmp\pace.log`, not `Debugf`. In `moho/**` TUs `gpg::Debugf` works and lands
in `engine.log`. Aggregate over 30-60 frames; never log per frame.

## Release configuration (the decisive test of the throughput conclusion)

`Release|Win32` exists in `main.vcxproj` but had never been built. It failed on
a small set of **configuration-portability** defects, all now fixed:

| commit | defect |
|---|---|
| `0067f36` | `SOffsetInfo::mUnitOffsets` was `std::map`, 0x0C bytes only under `_ITERATOR_DEBUG_LEVEL=2` -> `msvc8::map`. Six failing asserts. |
| `28d541f` | `BeamTextureBucketMapRuntime` was `std::map` -> `msvc8::map`; broke `sizeof(CWorldParticles)==0xDC`. `emplace_hint` -> hint overload of `insert`. |
| `32a0256` | `acos`/`ceil` are intrinsics under optimization (C2169) -> `#pragma function`. `_invalid_parameter` (5-arg) is debug-CRT-only -> `_invalid_parameter_noinfo()`. |

| `5793501` | Release lacked `ForceFileOutput` (Debug has it) -> LNK1120. `/FORCE` is also ignored under WPO, so `WholeProgramOptimization` is off for Release. |
| `1834ba4` | Both configs excluded `msvcrt.lib`; correct for Debug, but that IS the release CRT -> ~297 unresolved EH helpers. Release now excludes `msvcrtd.lib`. |
| `fd3e27c` | **Real bug, movie path.** `MPS_GetLastSysHd` copies a 0x20-byte `MpsSystemHeader`; `sfmps_SetMpsRaw` passed a 0x10-byte probe view -> 16-byte stack overrun on every system-header probe. Only an optimizing build diagnoses it (C4789). The two lanes are `videoBound` (+0x0C, primary slot) and `audioBound` (+0x08, secondary). |

**Release now builds, links with ZERO unresolved externals (cleaner than
Debug's ~19), and runs.** Note it must be launched by FULL path -
`NoDefaultCurrentDirectoryInExePath` is set on this machine, so a bare
`main.exe` fails with 9009 even after `cd`.

### Measured effect on playback speed

| build | thqlogo playback duration |
|---|---|
| Debug | ~13.2 s |
| Release | **6.81 s** (starts 12.34 s, gpglogo starts 19.15 s) |

**1.94x faster.** Debug was ~39% of real time; Release is roughly 70-75%
(thqlogo's true length is ~5 s). So optimization roughly doubles it but does
NOT fully close the gap - the loop is still over the 16.4 ms pulse period and
still quantizes to ~1.5 periods per frame. Remaining work is throughput, not
logic.

**The general lesson: neither configuration sets `_ITERATOR_DEBUG_LEVEL`, so
Debug gets IDL=2 and everything else IDL=0, and any `std::` container in a
binary-facing struct silently changes size between configurations.** Debug
passing a layout assert proves nothing about the layout. Any remaining
`std::map`/`std::vector`/`std::set` in a struct with an offset/size assert is
the same latent bug - the repo's Legacy STL ABI contract already forbids them;
this is why.

## RESOLVED for Release: 60 fps == correct speed

Measured with an FPS probe in `CScApp::Main`:

| build | frame rate | playback |
|---|---|---|
| Debug | 34-50 fps (20-29 ms) | ~67% - too slow |
| **Release** | **60.0-61.0 fps (16.4-16.7 ms)** | **correct** |

Release locks exactly to the 61 Hz multimedia-timer pulse, giving 60 vblanks/s
against the 59.94 the clock needs. Debug cannot reach it and never will - the
unoptimized decode alone is ~10 ms/frame. **The user runs Debug via F5, which is
why they still see slow playback.** thqlogo is ~7 s long (Release plays it in
7.06 s); the movies are **30 fps** (`GetFrameRate` = 30.000002).

`CMovie::GetFrameCount()` returns **0** - `mwsffrm_AnalyTotalFrm` is still a
no-argument stub, so movie duration cannot be computed in-engine. Worth
recovering.

### `1625f81` - the GC storm (big Debug win)

`Udata::len` carries a `gpg::RType*` in this fork, not a byte count (our own
header says so; `luaC_separateudata` reads `u.rtype->mSize`, confirmed against
the binary). `freeobj` charged `sizeof(Udata) + ud->len` on every userdata
free - refunding a ~29 MB pointer value against an allocation of
`sizeof(Udata) + type->size_`. The first free underflowed `nblocks` to ~4.26e9,
permanently above `GCthreshold`, so `luaC_checkGC` ran a **full collection on
every allocation** - ~120 collections/sec, ~13.5 ms per frame. Debug thqlogo
13.2 s -> 9.07 s. Release was already fast enough that it barely moved.

Diagnostic recipe that found it: probe `luaM_realloc` for `nblocks < oldsize`
and symbolize `_ReturnAddress()` with `SymFromAddr` - DbgHelp is already
initialised by `PLAT_Init`, so this Just Works and names the caller
(`freeobj+0x10f`).

## STATUS 2026-08-10: picture corruption is FIXED; a freeze remains

User screenshot of the **Release** build shows a **clean, uncorrupted frame** -
the blocky/displaced-macroblock corruption is gone. Most likely `fd3e27c` (the
16-byte stack overrun in `sfmps_SetMpsRaw`, which smashed the system-stream
parser's frame). Do not chase "corrupted picture" any more; chase the freeze.

Remaining symptom: playback **freezes on one frame**, with **492x
`SFD ERROR(FF000207)`** during **thqlogo** (movie 1 now, not just movie 2).
`sfply_CheckGetFrmApi` returns the mismatch error -> `SFD_GetFrm` fails ->
`mwPlyGetCurFrm` keeps returning the same frame -> frozen image.

`sfply_CheckGetFrmApi` is **verified faithful**: binary `FUN_00AD86E0` reads
`*(a1 + 88)` (== +0x58), latches when zero, and calls `SFLIB_SetErr(a1, ...)`
with the same handle. Its four binary callers are `SFD_GetIdFrm`/`SFD_RelIdFrm`
(type 2) and `SFD_GetFrm`/`SFD_RelFrm` (type 1). Observed
`latched=10101010 requested=1`, so this is **corruption, not API mixing**.

### PROBE DESIGN TRAP - do not repeat

Latching `gProbeFrameApiLane = &frameView->frameApiType` once and re-reading it
later is a **false positive generator**: movie 1's workctrl is freed on
teardown and the memory reused, so the stale pointer reads garbage
(`value=45C7006A`, a pointer, not `0x10101010`). Any lane probe must re-derive
the address from the *current* workctrl each time, or compare only while the
same handle is alive.

Also: `SetThreadContext` with `CONTEXT_DEBUG_REGISTERS` on the **current**
thread does NOT arm a hardware watchpoint - it silently never fires. Use a
suspended second thread to set another thread's DRs, or `PAGE_GUARD`, if a
watchpoint is really needed.

### BISECTED 2026-08-10 to a single function: `sfmpv_DecodeFrm`

Working probe design (reuse this): a helper that re-reads the lane from the
**current** workctrl each call -
`*(int*)((uint8_t*)AddressToPointer<uint8_t>(workctrlAddress) + 0x58)`, ignoring
values 0/1/2 and capping reports. Built into **Release** so the user keeps a
fast staged build. Chain of runs:

| checkpoint | lane |
|---|---|
| `ExecServerSub-entry`, `after-SetCondY16`, `after-ProcessAuxShc` | clean |
| `after-GetActiveSize` | clean |
| **`after-DecodeFrm`** | **10101010** |
| `after-DecodeOneUnit` / `after-DecodeSomePic` / `after-ChkPrepFlg` / `after-ChkTermFlg` | 10101010 (propagated) |

So the writer is inside **`sfmpv_DecodeFrm`** (`SofdecMpvRuntime.cpp:4933`,
FUN_00AD4020-ish). Prime suspects, in order:

1. **`sfmpv_SetFrmPara(workctrlAddress, &mpvInfo->pictureDecodeLane,
   &decodeFrameParam, &frameObjectAddress)`** - this fills the destination
   frame-buffer pointers that `MPV_DecodeFrmSj` then decodes into. A wrong
   destination writes decoded pixels (black luma == `0x10101010`) over the
   workctrl. This also explains the *visible* block corruption.
2. **`SfmpvDecodeFrameParamRuntimeView decodeFrameParam{}` is a stack local**
   passed to `MPV_DecodeFrmSj`. If it is smaller than what the callee writes,
   that is the exact same defect class as `fd3e27c` (`sfmps_SetMpsRaw`), which
   only an optimizing build diagnoses (C4789). **Check its size against the
   binary first - it is the cheapest test.**

**FULLY BISECTED**: clean at `DecodeFrm-afterSetFrmPara`, dirty at
`DecodeFrm-afterMPV_DecodeFrmSj`. So **`MPV_DecodeFrmSj(decoderHandle,
streamBufferAddress, &decodeFrameParam)` writes decoded pixel data through the
destination pointers/strides in `decodeFrameParam` and runs off the end of the
frame buffer into the workctrl.**

### The decisive visual clue

A user screenshot at the end of movie 2 shows the frame as **horizontal
stripes - every other line drawn, the rest black**. That is a stride/field
error in the decode destination, and it explains everything at once: a wrong
line stride makes the decoder write alternate lines AND walk past the end of
the frame buffer, which is how it reaches workctrl+0x58 -> FF000207 -> freeze
and movie-2 failure. **One root cause for the stripes, the freeze and the
error spam.**

### Where the destinations come from

`sfmpv_SetFrmPara` (`SofdecMpvRuntime.cpp:4993`) has two branches:
- `workctrl->mpvCond6Value == 3`: computes tiled strides itself
  (`lumaStride = 32*ceil(align16(w)/32)`, packed `(luma<<16)|chroma`).
- **else (linear, the one these movies use)**: copies luma/chroma/base/**stride**
  straight out of a 4-dword-per-set table at `&mpvInfo->primaryLumaPlaneBaseAddress`,
  indexed by `primaryFrameToggleIndex`/`secondaryFrameToggleIndex`.

**The plane/stride seeding is VERIFIED FAITHFUL - do not re-audit it.**
`sfmpv_ChkBufSiz` (0x00AD3AE0, `SofdecMpvRuntime.cpp:~5337`) matches the binary
line for line:

| binary | ours |
|---|---|
| `v6 = (v5/2+31)/32` | `requestedChromaBlocks32` |
| `v7 = (v5+31)/32` | `requestedLumaBlocks32` |
| `v8 = ((h+31)/32)*v7` | `requestedLumaTiles` |
| `v9 = v6*(32*((h+31)/32)/2)` | `requestedChromaTiles` |
| `v14 = 32*v7` -> +334/+350 | `*LumaStride` at **+0x14E/+0x15E** |
| `v15 = 32*v6` -> +332/+348 | `*ChromaStride` at **+0x14C/+0x15C** |
| `v17 = v8<<10` | `lumaPlaneOffset` |
| `v19 = 32*v9` | `chromaPlaneOffset` |

Field offsets are asserted and correct (chroma 0x14C low word, luma 0x14E high
word - which is what makes `sfmpv_SetFrmPara`'s dword read come out as the
packed `(luma<<16)|chroma` the decoder expects).

**Also verified faithful inside `MPV_DecodeFrmSj` (do not re-audit):**
`MPVUMC_InitOutRfb` (0x00AF6100) - the output-RFB/stride setup. Binary reads
width `+464`(0x1D0), height `+468`(0x1D4), half-res gate `+440`(0x1B8), RFB base
`+644`(0x284), writes `+668`(0x29C); half-res is `(x+7)/8`, aligned luma width
`16*((w+15)/16)`, luma stride units `(v4+31)/32`. **Every offset and every
expression matches ours, and the offsets are static_asserted.**

Note (not a bug, but confusing): `MPVUMC_InitOutRfb` is *declared*
`void(int handleAddress)` in `MPVDecoder.cpp:303` and *defined*
`std::int32_t(MpvcmcRuntimeView*)` in `SofdecMpvRuntime.cpp:2771`. Both are
`extern "C"`, so the linker binds them silently - it only works because the view
is based at the handle. Same C-linkage trap family that has bitten this
subsystem 6 times; worth unifying, but it is not the striping cause.

**=> The destinations handed to the decoder are RIGHT. The bug is INSIDE
`MPV_DecodeFrmSj`, below the setup - i.e. in `MPVSL_DecPicture` and the
macroblock/motion-compensation row-store path.** Path is `MPVSL_DecPicture` (0x00AE98F0, `MPVDecoder.cpp:3853`) -> loop over
`MPVSL_DecSliceOne` (0x00AE9AF0, `MPVDecoder.cpp:3505`) -> macroblock store.

**Checked and RULED OUT (both faithful - do not re-audit):**
- `mpvumct_CalcOfs` (0x00B00C40, `MPVDecoder.cpp:5457`) - this is the
  **thumbnail** path (`mpvumct*`), so its 1-line-per-MB-row scaling is correct
  for that path.
- `MPVUMC_GetMacroblockPlaneOffsets` (0x00C0CC70, `MPVDecoder.cpp:5986`).
  It *looks* wrong (8x for luma, 16x for chroma, which is backwards for 4:2:0)
  but the binary does exactly the same:
  `*a3 = v4 + 8*(a1+828)*(int16*)(a2+12)` and
  `a3[1] = 16*(a1+828)*(int16*)(a2+14) + 2*v4`. The stride at +0x0C must
  therefore already be pre-doubled. Our `MPVMacroblockOffsets` has
  `lumaStride` at **+0x0C** and `chromaStride` at **+0x0E**, matching `a2+12`
  and `a2+14`. Faithful.

### These movies are MPEG-1, not MPEG-2 (settles which decoder to audit)

`MPV_DecodeFrmSj` routes `pictureCodecClassification == 2` to
`MPVM2V_DecodeFrm` -> `M2V_DecodeFrm` (0x00B055D0) -> the **function pointer
`m2vapi_DecodeFrm`, which is `nullptr` and never registered**
(`SofdecAdxDeclarationsRuntime.cpp`, all `m2vapi_*` are null). So an MPEG-2
stream would decode *nothing at all*. We do get a picture, therefore the splash
movies are **MPEG-1** and take the `MPVSL_DecPicture` path - which is the
correct thing to audit.

**Corollary: the unparsed picture-coding-extension fields are a RED HERRING for
these streams.** `framePredFrameDct` (+0x57), `pictureStructure` (+0x55),
`topFieldFirst`, `alternateScan` are reset to -1/0 at `MPVDecoder.cpp:2003-2009`
and never filled from the bitstream, but MPEG-1 has no picture_coding_extension
and no field DCT, so that gap cannot cause the striping here. (It IS a real gap
if MPEG-2 support is ever needed - note `qScaleType`/`intraVlcFormat` get
assigned from `sequenceAspectRatioCode`/`constrainedParametersFlag` at
`MPVDecoder.cpp:2895-2896`, which looks semantically odd; verify against the
binary before touching.)

So: the striping is in the **MPEG-1 slice/macroblock block-store path** below
`MPVSL_DecSliceOne`. Next: checkpoint the lane inside `MPVSL_DecSliceOne` and
its block-store callees, exactly as was done to find `sfmpv_DecodeFrm`. Given the every-other-line striping, the prime suspect is
**field vs frame picture-structure handling** in the recovered MPEG decoder:
writing a frame picture as a single field (or advancing rows by 2x stride)
produces exactly these stripes AND walks off the end of the buffer into the
workctrl. Start at `MPV_DecodeFrmSj` and the row-advance / `picture_structure`
handling in `MPVDecoder.cpp`.

## EARLIER BLOCKER NOTES (both of the user's complaints were ONE bug)

`SFD ERROR(FF000207)` spam, the **blocky/pixelated picture**, and **"second
video not working"** are all the same defect: the MPV decode server writes
`0x10101010` (a black-macroblock luma fill) through a mis-computed destination
pointer. It lands on the SFPLY frame-API lane at workctrl+0x58 - which is what
raises FF000207 and stops movie 2 - and scatters displaced blocks through the
decoded image.

Entry point: `SFD_tr_vd_mpv.execServer` = `SFMPV_ExecServer` ->
`sfmpv_ExecServerSub` (FUN_00AD1C10), `cri/sofdec/SofdecMpvRuntime.cpp:2913`.

**Already ruled out - do NOT re-audit these:**
- `concealOnExec` - byte-faithful, and a probe proved it never runs.
- `sfmpv_ExecServerSub` - byte-faithful vs FUN_00AD1C10 (cond 5, GetTermDst,
  SetCondY16, `*(a1+72)==2` -> ProcessAuxShc, DecodeSomePic, ChkPrepFlg,
  ChkTermFlg).
- **`mpvhdec_InitNqm` (0x00AE8BF0) - the ONLY `0x10101010` in `src/sdk/**`**
  (`MPVDecoder.cpp:2838`). It is faithful: binary writes `a1 + 3296` (+0xCE0),
  our field `decodeWorkScratchPredicted` is at +0xCE0 with a static_assert, and
  `AsHandleView` is a plain cast with no offset. Sibling `mpvhdec_InitIqm`
  writes +0xCA0 == `a1 + 3232`. Note this value is the MPEG **default non-intra
  quantization matrix** (all 16s), NOT pixel data - do not chase it as a
  framebuffer fill.
- `LoadQuantizationMatrix` - correctly applies the zigzag permutation
  (`gMpvIntraScanPermutationRuntime[i]`), matching the binary's
  `*(v14 + byte_11081A0[i] + 3232/3296)`.

- **`mpvhdec_InitNqm` is NEVER CALLED at runtime** - proved with a probe: zero
  `INITNQM` lines while `APIMISMATCH` fired four times. So the only
  `0x10101010` *constant* in the tree is not the writer, and the value must
  arrive as **copied data** (a black-luma block, or an all-16s non-intra quant
  matrix) moved through a wrong destination pointer. Confirmed lane address:
  `wc=40B928A0`, `lane=40B928F8` == wc+0x58, `latched=10101010 requested=1`.

So the write reaching SFPLY workctrl+0x58 is NOT a wrong field offset in the
quant-matrix lane. Either `mpvhdec_InitNqm` receives a wrong handle (but that
would land at handle+0xCE0, not +0x58, so it does not fit), or the earlier
"+0x58" bisect was reading a different structure base than assumed. **NEXT STEP (do this first, it is O(1) instead of many bisect rounds):** install
a **hardware write watchpoint** on the 4 bytes at `&frameView->frameApiType`
(wc+0x58) the moment it is first latched in `sfply_CheckGetFrmApi`
(`SofdecSfdRuntime.cpp:19168`, the `frameApiType == 0` branch). Set DR0 =
address, DR7 = write-type/4-byte via `SetThreadContext` on the current thread -
the decode runs on the main thread because the ADXM workers are dead, so a
per-thread breakpoint is sufficient. Register a vectored exception handler,
log `ExceptionInfo->ContextRecord->Eip`, and symbolize it with `SymFromAddr`
(DbgHelp is already initialised by `PLAT_Init`; this technique already worked
to find `freeobj+0x10f`). That names the writing instruction directly.

Do NOT bisect `sfmpv_DecodeSomePic` call-by-call - it has ~20 sub-calls
(declarations at `SofdecMpvRuntime.cpp:477-513`), so that is many build/run
cycles for the same answer.

## Open / unverified
- `D3D9Interfaces.cpp:6154/6158` look inverted:
  `Windowed = head.mWindowed ? 0 : 1` and
  `FullScreen_RefreshRateInHz = head.mWindowed ? fps : 0`. Either `mWindowed`
  actually means *fullscreen* (misnamed) or both lines are wrong. Not
  pacing-related (Present is 1.4 ms, no vsync block) but worth checking.
- The old `0x10101010` write into SFPLY workctrl+0x58
  ([[project_splash_sequence_advances]]) did **not** reproduce in these runs -
  no `SFD ERROR` spam in a 620-line log.
