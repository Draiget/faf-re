---
name: project-movie-playback-chain-2026-08-07
description: Movie playback trace — the movie now PLAYS and a real decoded frame with content reaches the movie texture; remaining defect is SFD ERROR(FF000F0F) after the first frame
metadata:
  type: project
---

Standing goal "frames and video on screen". Eighteen commits across three
sessions. Every one `BUILD_EXITCODE=0` at the 19-unresolved baseline.

## Where it is NOW (2026-08-07)

**The movie leaves PREP, reaches PLAY, and one real decoded frame lands on the
movie texture with actual picture content:**

```
debug: MovieFrame: buf=2DB11800 pitch=2944 outH=512 texH=512 nonzero=11520/11776 first=FF000000
warning: SofDec error: SFD ERROR(FF000F0F)
debug: Playing movie .../thqlogo.sfd: 2
debug: MovieUpload: ply=018DA134 buf=00000000 sheet=07768E70   <- and buf is null again
```

`nonzero=11520/11776` is 97.8% of sampled pixels — that is a decoded picture,
not a cleared buffer. So the whole chain works once and then stops.

**Next blocker: `FF000F0F` = `kSfmpvErrFrameObjectMismatch`,** raised in
`sfmpvf_AddReadSub` (0x00AD52E0, SofdecMpvRuntime.cpp:6705) when
`mpvInfo->activeFrameObjectAddress != frameObjectAddress` on the release path.
`activeFrameObjectAddress` (+0x70 of mpvInfo) is written only by
`sfmpvf_SearchFrmInf` (0x00AD50C0). Already checked and NOT the cause:
`sizeof(SfmpvfVfrmDataRuntime) == 8`, matching the binary's `v4 + 2`.

### ⚠ Recovering the four remaining `mwPlyGetCurFrm` stubs REGRESSED it

Tried and **reverted** (do not simply redo it): recovering all four of
`mwsffrm_SetFrmApi` (0x00ACA1A0), `mwsffrm_SetAdditionalInfoToFrame`
(0x00ACA1D0, IDA "CheckAinf"), `mwsffrm_SaveFrmDetail` (0x00ACA4E0) and
`mwPlyIsNextFrmReady` (0x00ACA7D0) together — plus naming the ply's +0x88
detail block and `MwsfdLibWork` +0x38 as `usePictureUserData` — built clean but
put the movie back to never leaving PREP: `MovieFrame=0`, no `Playing movie`.
Reverting all three files restored `MovieFrame=1` immediately, so it is
definitely that change set and not drift.

Ruled out while bisecting: the nested `SavedFrameDetail` struct (flattening it
to `std::array<std::int32_t,8>` changed nothing). So the cause is behavioural,
in one of the four bodies — the strongest suspect is **`mwPlyIsNextFrmReady`**,
which the stub answered `0` to. Recovered, it answers `SFD_IsNextFrmReady`, so
`mwPlyGetCurFrm`'s drop loop starts releasing frames — against a **2-frame
pool**, which can plausibly starve the very lane that was feeding the texture.
`MWSFD_GetUsePicUsr` going from stub-`0` to a real `1` is the second suspect:
it switches on the picture-user and subtitle branches inside
`mwl_convFrmInfFromSFD`.

Redo these **one at a time**, running after each. Start with
`mwsffrm_SaveFrmDetail` (pure data copy, no control flow) and leave
`mwPlyIsNextFrmReady` for last.

## Landed this session (2026-08-07)

| Commit | What |
|---|---|
| `a6ce3d0` | `sfmpv_ExecServerSub` (the MPV decode-server tick) + `SFTIM_prate` / `sftim_tc2time` tables |
| `e8dc0b0` | `sfmpv_fps_round` / `sfmpv_conv_29_97` / `sfmpv_conv_59_94`; MPV **header bit-reader start**; `mwPlyGetHdrInf` width/height offsets |
| `c11dc33` | Wired `MPVDEC_InitScanState*`; coefficient block anchored at ctx **+0x44**; +0x60/+0x64 unswapped |
| `bd38a8f` | **Multimedia-timer heartbeat** (`fptc` 0x00B07510) + `ADXM_WaitVsync` |
| `5a1a7c3` | **`conceal_fn_tbl`** + `concealOff` / `concealOn` |
| `2be44e7` | **`mwl_convFrmInfFromSFD`** + 4 `mwsffrm_*` helpers + 3 SUD/lib leaves |

## The defects, in the order they were peeled

1. `sfmpv_ExecServerSub` was a `{return 0;}` stub — the entire video decode.
2. `SFTIM_prate` (0x00D7FA28, 10 entries) and `sftim_tc2time` (0x00D7FA50, 18
   entries) were zeroed 4 KB "buffers". They are tables. Null converter →
   `FF000221` every tick.
3. `sfmpv_fps_round` (0x00D7F60C) / `sfmpv_conv_29_97` (0x00D7F630) /
   `sfmpv_conv_59_94` (0x00D7F650) likewise — zeroed *scalars*. `frameCursor %
   0` killed the decode thread.
4. **MPV header bit reader opened 32 bits early.** The three header decoders do
   `and ~3` then `add 4` (0x00AE8E2A/2E) — first bit lands just past the
   `00 00 01 xx` start code. The slice loader (0x00C0CD50) has no `add 4`.
   Symptom was `tref=0 ptype=0 vbv=32` instead of `tref=0 ptype=1 vbv=65535`;
   ptype 0 is not I/P/B so `sfmpv_IsPtypeSkip` skipped *every* frame.
5. `mwPlyGetHdrInf` wrote width/height to +0x18/+0x1C where
   `MWSFFRM_AnalyzeSofdecHeader` immediately overwrote them. Binary puts width
   at **+0x08**, height at **+0x0C** (0x00AC8E80/8D) — where CMovie reads
   maxWidth/maxHeight. Create configured a 0x0 pool → `FF000F17`.
6. `mpvhdec_DecPscSj` installed the `sub_C0E1B0`/`sub_C0E2E0` **stubs** as the
   picture's read drivers while the real bodies sat orphaned as
   `MPVDEC_InitScanState*`. Those bodies also had ctx +0x60/+0x64 swapped and
   passed the kernel ctx+0x68 instead of **ctx+0x44**.
7. **Nothing kept time.** `gAdxmMultimediaTimerCallback` was an invented
   indirection, never assigned, so `timeSetEvent` got a null callback and the
   vsync event was never pulsed; `ADXM_WaitVsync` was a stub returning
   immediately. The prepare loop busy-spun and starved the Sofdec threads —
   `ADXM_ExecMain` ran ~5 times in 90 s. After the fix: 226 times in 240 s.
8. `conceal_fn_tbl` (0x00D7FFFC) was a zeroed 256-entry buffer. It is a
   **4-entry** table; `MPVCONCEAL_StartFrame` installs a slot as the handle's
   macroblock-discontinuity handler. Null slot → the first B picture (which
   jumps 384 macroblocks on its 2nd macroblock) called through null and killed
   the decode thread.
9. `mwl_convFrmInfFromSFD` was a stub, so the frame buffer address was always
   null even once pictures decoded.

## Method notes that paid off

- **Bisect with `AdxmDiagf` probes, then read the `.asm`.** Every one of these
  was found by narrowing a hang to a call site and then diffing our body
  against the disassembly.
- **`dbgrun.exe` only samples the MAIN thread.** For decode-thread hangs use
  probes, not the debugger.
- `AdxmDiagf` **must be declared `extern "C"` at file scope** in normal C++
  TUs. A block-scope `void AdxmDiagf(const char*, ...);` inside `namespace moho`
  gets C++ linkage, links to garbage under `/FORCE`, and produces bizarre
  failures (it manifested once as a bogus "resource deadlock would occur").
- The Sofdec fragment files are `#include`d into `moho/audio/SofdecRuntime.cpp`
  — `rm buildstage/main/Win32/Debug/SofdecRuntime.obj` before rebuilding, and
  note **`MPVDecoder.cpp` uses LF** while most Sofdec fragments use CRLF, which
  breaks naive python patching. Prefer the Edit tool.
- A zeroed `std::uint8_t X[4096]` in `SofdecExternalStubs.cpp` is the project's
  standing disguise for a real data table. Four separate blockers this session
  were exactly that. **When a lookup misbehaves, check the stub file first.**

## Tooling

- Build `scratchpad/bldz7.bat`; run `scratchpad/runaffchk.ps1` (45 s) or
  `scratchpad/runlong.ps1 -Seconds N` (enumerates windows each 10 s).
- `scratchpad/shot3.ps1 -Proc main -Settle N -Out x.png` screenshots the window.
- `AdxmDiagf` writes `C:\ProgramData\FAForever\bin\adxmdiag.txt`; its definition
  is at the bottom of `moho/movie/CMovie.cpp`, **uncommitted on purpose**, along
  with the MovieUpload/MovieFrame probes that produced the evidence above.

See [[project_sofdec_movie_crash]], [[project_lua_registration_sweep]].
