---
name: project-video-on-screen-2026-08-08
description: Video IS on screen and playing (THQ logo visible, full-screen); the black window was a WRenViewport layout bug. Remaining defect is MPV macroblock corruption - records everything already ruled out.
metadata:
  type: project
---

Standing goal "video playback fully working e2e". **The movie now renders to the
screen and plays continuously.** Six commits this session, all
`BUILD_EXITCODE=0` at the 19-unresolved baseline.

## THE BIG ONE: nothing in the engine had EVER rendered

`WRenViewportRenderView` declared `mScreenPos/mScreenSize/mFullScreen/mHead`
*after* `mCam`, so they landed at 0x2308/0x2310/0x2318/0x2320 instead of
0x308/0x310/0x318/0x320. `UpdateRenderViewportCoordinates` wrote the head extent
into dead space; `RenderUI` read a permanently-zero `mFullScreen` and handed it
to `SetViewport` -> **every draw call in the engine was clipped to a 0x0
viewport.** Fixed in `0b1ba83`.

The assert that would have caught it was behind
`#if defined(MOHO_ABI_MSVC8_COMPAT)`, which is **not defined in this build**.
*Grep for that macro - any other assert hiding behind it is unverified.*

Binary proof (FUN_007F87F0): `mov ecx,[esi+320h]` / `mov [esi+318h],edi` /
`mov [esi+308h],eax` / `mov eax,[esi+219Ch]`.
Also from FUN_007F8290: prim batcher is `[esi+215Ch]`, debug canvas is
`esi+2C8h` - this view had those two names swapped.

## Commits

| Commit | What |
|---|---|
| `e02a585` | `SfmpvfInfoRuntimeView::frameObjects` missing its 4-byte gap -> +0x17C not +0x180; every `SFMPVF_SearchFrmObj` result was 4 low, so the first frame release failed `FF000F0F` and no frame ever returned to the pool |
| `0b1ba83` | the 0x0-viewport keystone above |
| `91cf6d2` | `CMauiMovie::Draw` put `[this+0xF4]` in `mU` and left `mColor` 0 (= black); it is `CMauiControl::mVertexAlpha`, and the UVs are the plain 0/1 corners |
| `ab1c015` | `mwsffrm_SaveFrmDetail` recovered; `mwsfsfx_SetFrmDetail` takes the **ply**, not the frame (FUN_00AC6710 passes `a1`) - killed 4 SofDec errors per frame |
| `35f1fe6` | `mpvdec_MotionSub` output/predictor args were swapped vs the binary (a3=+0x18, a4=+0x10) |
| `9815f53` | B-picture skip-run and discontinuity branches must be `else if` (the binary jumps past the test) |
| `49af891` | **`mpvvlt_motion_1[1]` was 0x05FD05F3, binary has 0x05FD0503** - motion VLC delta +3 mis-transcribed as -13. Biggest quality win of the session |

## How to see the picture

`PrintWindow` CANNOT capture a D3D9 swap chain - it returns pure black. Do not
use it and do not conclude "nothing rendered" from it. `CopyFromScreen` is worse:
`SetForegroundWindow` fails from a background process, so it captures whatever is
in front (it grabbed the operator's VS Code once - delete such files immediately).

**Use the engine's own frame dumper.** It is fully recovered:
`REN_MaybeDumpFrame` writes `<dump_frameDumpName>\SCFrame_<dump_Timestamp>_%05d.bmp`
whenever `moho::dump_frameRate != 0`. Arm it from the `MovieFrame` probe in
`CMovie.cpp` (uncommitted):

```cpp
moho::dump_frameDumpName.assign_owned(std::string_view{"C:\\ProgramData\\FAForever\\bin"});
moho::dump_Timestamp.assign_owned(std::string_view{"movie"});
moho::dump_frameRate = 24;
```
The globals have no header declaration - `extern` them in an ad-hoc
`namespace moho { }` block.

**Delete the old BMPs before every run.** They are not overwritten if the arming
condition never fires, and stale files silently invalidate A/B experiments (this
cost two wrong conclusions here: "half-pel is fine" and "MC has no effect" were
both measured against a stale baseline).

## Remaining defect: B pictures far worse than P (measured 2026-08-08)

**Controlled comparison** - arm the frame dumper on a fixed *frame ordinal*
(`diagFrames == N`), not on a picture type or a brightness threshold, so two runs
capture ADJACENT movie frames instead of two unrelated moments. The display order
is I,B,B,P,B,B,P..., so ordinal 21 is a B and 22 is the P right next to it.
Result: **21 (B) is shredded, 22 (P) is nearly clean at the same instant.** An
earlier P-vs-B pair captured by brightness threshold was NOT a valid comparison
(different moments, different motion) - the ordinal method is the one to use.

Superseded by measurement - see the error curve and the coded-vs-skipped map
below. Routing B's backward/bidirectional modes through `MPVUMC_Forward` did
NOT clean B up, but that only means forward-only is also wrong for those
macroblocks, not that the shared path is at fault: ordinal 4 and 7 measure the
shared path at 0% and 1%.

### Audited since, ALL faithful - do not re-check any of this

Tables, byte-verified or builder-diffed against the binary:
`mpvvlt_mbai_i_0/i_1`, `mpvvlt_mbai_p_0/p_1`, `mpvvlt_mbai_b_0/b_1`,
`mpvvlt_p_mbtype`, `mpvvlt_b_mbtype`, `mpvvlt_y_dcsiz`, `mpvvlt_c_dcsiz`, and
**all six static `mpvvlt_run_level_*` tables read straight out of
`bin/2025.7.1/ForgedAlliance.exe` `.rdata`** plus the runtime-built
`mpvvlt_run_level_8` (FUN_00AF7480).

Logic, diffed against the binary: `form_prediction` + its MV clamp (FUN_00C0C390),
the 8-entry interpolation dispatch (FUN_00AF6040), the four kernels,
`MPVUMC_GetMacroblockPlaneOffsets` (FUN_00C0CC70), `MPVUMC_Forward` /
`Backward` / `BiDirect` (they pass `blockSources.forwardSamples` at ctx+0x118 and
`backwardSamples` at +0x11C exactly as the binary does), `addBlocksFrame420` and
`_also`, `MPVUMC_BpicSkipped`, `SFMPVF_AllocFrm` (FUN_00ADC1E0),
`sfmpv_SetFrmPara`'s reference rotation and plane arithmetic (FUN_00AD4590),
the I/P-vs-B standby marking, the eight f-code fields in `mpvhdec_DecPscSj`
(+0x2F0.. / +0x314..), `MPVDEC_InitScanStatePredicted` (FUN_00C0E2E0), and the
non-intra dequant `((2*level+1) * qscale * W[i]) >> 4` with `(v-1)|1`.

**`CFT_Ycc420plnToArgb8888Prg` / `Int` are NOT the problem.** They are two of the
19 unresolved externals and `SFX_CnvFrmARGB8888ByCbFunc` does route to them - but
only when `chromaPosLo != 1`, and a probe shows this stream reports
`chromaPosLo=1 chromaPosHi=1 detail68=-1 pictStruct=3 chromaFmt=1`, so the safe
`CFT_Ycc420plnToArgb8888` path is always taken. (Those values also confirm the
`ab1c015` SaveFrmDetail recovery is feeding correct data.)

`DCT_FsriTransCbp` / `DCT_FsriTrans6Blk` / `DCT_FsriTransCore` (0x00AF7F30 /
0x00AF7F20 / 0x00AF8350) also match, including the work-view offsets
(`codedBlockPatternMask` +0x28, `blockCoefficientBase` +0x2C,
`blockOutputWordPointers` +0x30, `scaleTableBaseAddress` +0x48) and the DC-only
replication packing.

**What is still unaudited - start here next time:**

1. `mpvhdec_ReadKernelPredictedDefault` (0x00AFD7C0) - the non-intra coefficient
   decoder and the dominant path for this movie (only one I picture, all black).
   ~2500 decompiled lines, heavily unrolled, so diff it by *behaviour* (probe the
   decoded run/level stream against a reference MPEG-1 decoder on the same
   `thqlogo.sfd` elementary stream) rather than by reading.
2. `mpvhdec_ReadKernelIntraDefault` (0x00AFAE50).
3. `DCT_FsriTrans` - the actual 8x8 inverse transform.

## GROUND TRUTH IS AVAILABLE - stop eyeballing frames

**`ffmpeg` (A:\tools\ffmpeg.exe) reads the .sfd directly.** No demuxing needed:

```
ffmpeg -i "g:\games\...\movies\thqlogo.sfd"
  Input #0, mpeg  Stream #0:0[0x1e0]: Video: mpeg1video, yuv420p, 720x512, 30 fps, 6.70s
```

720x512 @ 30fps matches what our decoder reports (45 x 32 macroblocks), so
ffmpeg's decode of display frame `N-1` is the exact reference for our uploaded
frame ordinal `N`.

`scratchpad/moviediff.ps1 -Ordinal N` does the whole loop: pull the reference
frame, run the engine, convert its dump, and print a score. **Use it to A/B every
decoder change instead of judging by eye** - two conclusions this session were
wrong from eyeballing (see the stale-BMP warning above, and "P frames are clean",
which they are not).

### Error curve vs ffmpeg (scratchpad/moviediff.ps1)

| ordinal | type | at `9815f53` | after `49af891` |
|---|---|---|---|
| 4  | P (first P; reference is the black I frame) | 0%  | 0% |
| 5  | B (first real B)                            | 4%  | **1%** |
| 7  | P (first P with real motion compensation)   | 1%  | - |
| 21 | B                                           | 25% | **7%** |
| 22 | P                                           | 12% | **9%** |

The motion-table fix took the shredded B frames down to near-clean; the THQ
logo now renders with a smooth swoosh and solid lettering.

Two independent readings fall out of this:

1. **The residual / coefficient / IDCT path is CORRECT.** Frame 4 predicts from
   an all-black I picture, so its output is essentially pure residual, and it
   scores 0%. Frame 7 is the first P that actually motion-compensates against
   real content and scores 1%, so `form_prediction` and the kernels are fine
   too. Stop auditing those - the earlier plan to attack
   `mpvhdec_ReadKernelPredictedDefault` and `DCT_FsriTrans` is now
   *deprioritised*.
2. **The error ACCUMULATES**, and B carries a consistent extra penalty: B is
   ~4x its neighbouring P at both ends of the clip (4% vs 0-1% early, 25% vs
   12% late). So there is a genuine B-specific defect present from the very
   first B frame, on top of a slower drift in the P reference chain.

Attack order: find why B is worse than its neighbours *at ordinal 5* (only ~3
frames of history, so the state is tiny and easy to reason about), then the P
drift.

### The error is in CODED B macroblocks; the skip path is clean

Measured, not guessed. `MPVDEC_DecBpicMb` was instrumented (probe since removed):
every B picture is **one slice**, runs to `idx=1439 limit=1439 row=31 col=44`,
with **0 discontinuities and 0 mid-slice chunk refills**, exiting on the
start-code test. So there is no desync and no unwritten region - the whole
picture is covered. `coded` macroblocks per B picture are only 141-642 of 1440,
i.e. 60-90% are skipped.

Then: temporarily making `MPVUMC_BpicSkipped` leave skipped macroblocks
untouched moved ordinal 21 from 25% -> 63% bad, and overlaying "changed by that
experiment" (= the skipped regions) against "differs from ffmpeg" gives

```
S=skip-driven only   E=error only   B=both   .=neither
SSSSSSSSSSSSSSSSSSSSSSSS
SSSSSSSSSSSSSSSSSSSSSSSS
SSSSSSSSSSSSSSE....SSSSS
SSSSSSSSSSB.EEE....SSSSS
SSSSSSSS.EEEEEEEE.SSSSSS
S.E.EEEEEEEEEEEEEEEEEEEE
EEEEEBBBBBEEEE........EE
....E.....E..E.EEEEEEEE.
EEEEE.EE...EEEEEBBBBBBBB
EEEEEEEE...E............
EEEEEEEEE.EB..S..BBBBBBS
EEEEE..EE.EB...SSSSSSSSS
EEEEEEEEEBSSSSSSSSSSSSSS
EEEEEEEBBBSSSSSSSSSSSSSS
BBBBBBBBSSSSSSSSSSSSSSSS
SSSBBBSSSSSSSSSSSSSSSSSS
```

Large `S` regions with no error, and the error concentrated in `E` regions that
the skip experiment did *not* touch. **So the skipped-macroblock path is
correct, and the defect is in macroblocks that B pictures actually code.**

Also verified since, all faithful: the mode-slot binding in `mpvhdec_DecPscSj`
(`[esi+2D8h]`<-backward, `[esi+2DCh]`<-forward, `[esi+2E0h]`<-bidirect,
`[esi+2D4h]`<-forward, at 0x00AE9293..0x00AE92C9), `mpvumc_IncreMbadr` /
`mpvumc_SubMbadr` (FUN_00C0CD10 / FUN_00C0CCB0), and `mpvvlc_InitCbpSub1`
(FUN_00AF6E50) dword-for-dword.

### STRONGEST OPEN LEAD: every FORWARD vector in a B picture decodes to (0,0)

Probing the B loop right after the backward MV decode (30 samples):

```
Bmv: flags=04     fwd=(0,0) bwd=(-14,-14)  fCfg=(0,0,27,1) bCfg=(0,3,24,8)
Bmv: flags=3FFFEE fwd=(0,0) bwd=(-97,-17)  fCfg=(0,0,27,1) bCfg=(0,3,24,8)
Bmv: flags=3FFFEE fwd=(0,0) bwd=(-107,-6)  fCfg=(0,0,27,1) bCfg=(0,3,24,8)
Bmv: flags=3FFFE4 fwd=(0,0) bwd=(-11,-117) fCfg=(0,0,27,1) bCfg=(0,3,24,8)
Bmv: flags=3FFFE6 fwd=(0,0) bwd=(16,124)   fCfg=(0,0,27,1) bCfg=(0,3,24,8)
```

`fCfg`/`bCfg` are `(fullPelFlag, fCodeMinus1, wrapShift, fScale)`. Backward is
f_code 4 (range +/-128, and the decoded vectors really do reach +/-126, so the
backward path is working). **Forward is f_code 1 and every single forward vector
comes out exactly (0,0)** - including on `flags=0x..EE` macroblocks, where
`flags & 8` says a forward vector WAS coded and decoded.

**CONFIRMED A BUG, not a property of the stream.** ffmpeg renders the reference
motion field for the same frame:

```
ffmpeg -flags2 +export_mvs -i thqlogo.sfd \
  -vf "codecview=mv=pf+bf+bb,select='between(n\,19\,21)',scale=512:384" -vsync 0 -frames:v 3 mv_%02d.png
```

and frame 21 comes back covered edge to edge in long MV arrows. Better still,
`codecview` can isolate the two B lanes - `mv=bf` is B-frame **forward** vectors,
`mv=bb` is B-frame backward:

```
ffmpeg -flags2 +export_mvs -i thqlogo.sfd \
  -vf "codecview=mv=bf,select='eq(n\,20)',scale=512:384" -vsync 0 -frames:v 1 fwd_only.png
```

`fwd_only.png` is full of arrows. **The stream really does code non-zero forward
motion vectors in this B picture, so our (0,0) for every one of them is a bug.**

Note the config is byte-identical to the P case that works: the P loop probe
reports `fullPel=0 fCode=0 wrap=27 fScale=1` and so does B's forward lane, and
the *same* `mpvdec_MotionSub` decodes healthy vectors in P pictures. Same helper,
same config, same call shape - so suspect the **bitstream position** at the
moment the forward MV is read in the B loop, not the helper or the f_code.

The macroblocks that show this have `flags = 0x..EE`, i.e. bit 0x20 is set, which
means the mbtype VLC was **skipped** and the flags came straight from the MBAI
entry. So on those macroblocks the only thing consumed between the MBAI code and
the forward MV is the optional 5-bit quantiser scale (bit 0x10, clear here) -
a very short window to audit.

Note the f_codes themselves are plausible and probably correct: in a
I B B P B B P GOP the first B sits 1 frame from its forward reference and 2 from
its backward one, so backward f_code 4 > forward f_code 1 is expected. **Do not
"fix" the f_code read** - the defect is in the forward MV decode itself.

That is the asymmetry to chase. All-zero is what `mpvdec_MotionSub` produces when
the VLC keeps returning delta 0 (`*a3 = *a4`, predictor never updated, and the
predictor starts at 0 from the slice-header reset). Either the stream genuinely
codes zero forward vectors here, or the forward MV field is being read at the
wrong bit position / with the wrong f_code. Next step: get ground truth on the
motion vectors - `ffmpeg -debug mv` / `-vismv`, or ffmpeg's `mpeg1video` decoder
with `-trace` - and compare against these for the same macroblock.

Note P pictures use the same f_code 1 and their MVs are healthy (~70% non-zero,
frame 7 scores 1%), so f_code 1 itself is decoded correctly elsewhere.

What a *coded* B macroblock does that a coded P macroblock does not: decode a
**backward** motion vector (flags & 4) and dispatch mode 1 or 3. `mpvvlc_InitCbpSub2` (0x00AF6F90) has since been diffed too and matches, so
**every VLC table in the MPV decoder is now verified against the binary** - stop
looking at tables entirely.

**The ordinal-5 error is ONE COMPACT HORIZONTAL BAND, not scatter.** Binning
|diff|>90 into a 24x32 grid (rows top-to-bottom, every 3rd row shown):

```
                 ..
              .. .+..
 .#########++ +   .+
   .#######+  .++  .+
```

A solid run of bad macroblock columns confined to a few macroblock *rows* on the
left, with everything above and below clean, is the signature of **one slice
decoding wrong and the decoder resyncing at the next slice start code** - not of
a systematically wrong prediction or a wrong table (either of those would spray
errors across the whole picture). So look at the B loop's slice boundaries: the
`PeekWindowBits(state, 9) == 0` exit, the `macroblockLinearIndex >
macroblockLinearLimit` break, and the mid-slice chunk refill
(`ComputeBitstreamSplitOffset` + `LoadBitstreamFromChunk` with
`bitCount & 7`) - a desync there would corrupt from that point to the end of the
slice and then recover.

The P-frame error is not a horizontal scale/padding artifact: binned into 8
vertical bands the diff at ordinal 22 is 16/27/14/6/10/11/11/3 left-to-right,
i.e. it tracks picture content, not x position.

**Trap that already burned one measurement:** the python one-liner that rewrites
`kDiagDumpFrameOrdinal` must match the *current* value. Use a regex
(`kDiagDumpFrameOrdinal = \d+;`) and `grep` the constant back afterwards - a
missed replace silently compares our frame N against reference frame M and
produced a completely bogus "29%" reading. `moviediff.ps1` prints the
`armed dump at ordinal` log line; check it matches `-Ordinal`.

Everything B-specific HAS been audited against the binary and is faithful:

Already audited in the B path and found FAITHFUL - do not redo:

- `mpvvlt_b_mbtype`, word-for-word vs FUN_00AF6C00 (64 entries, indexed by the
  top 6 bits; IDA renders dword[3] as `&mpvm2v_lib_work[219485]`, which is just
  the constant 0x01050105).
- The prediction-mode dispatch: `decodePredictedModes[(flags >> 2) & 3]` off
  base +0x2D4, with slot 0 rewritten to the chosen mode so a later skip repeats
  it. Matches FUN_00C0DA80.
- `MPVUMC_BpicSkipped` (FUN_00C0CC20): `a1[181]` really is +0x2D4
  (`decodePredictedModes[0]` == `decodeSkippedBpicMacroblock` - same offset),
  `a1[206]` is `macroblockLinearIndex`, `a1[211]` is `predictionSignState`.
- `9815f53` fixed a real one - the skip-run and discontinuity branches must be
  `else if` (the binary jumps past the test) - but it changed nothing visible,
  because this stream installs `conceal_fn_tbl[0]` = `concealOff`, a no-op.
  **That also means the discontinuity handler cannot be causing the smearing.**

- `addBlocksFrame420` (FUN_00C0C760), the two-source averaging combine that only
  B uses: matches, including `(back + fwd + 1) >> 1` and the sign-state branch.
- `MPVUMC_InitOutRfb` (FUN_00AF6100): `[a1+674]`/`[a1+672]` really are
  `outputLumaStrideBytes`@+0x2A2 / `outputChromaStrideBytes`@+0x2A0.

So a skipped B macroblock is handled *only* by `decodeSkipRun`. What is left:

1. **Nothing in `src/sdk/**` ever WRITES `forwardOffsets` (+0x264) or
   `backwardOffsets` (+0x274)** - grep finds reads only. Find the producer (the
   per-picture reference-buffer binder) and check it exists and is called;
   if the backward pair is stale or aliases the forward pair, B pictures
   predict from the wrong frame and P pictures stay clean, which is exactly the
   symptom.
2. `MPVUMC_Backward` / `MPVUMC_BiDirect` bodies vs FUN_00C0C250 / FUN_00C0C2E0
   (structure was read and looks right; the argument-level diff was not done).

**Naming warning for this whole file:** in `MPVMacroblockOffsets`, `lumaStride`
(+0x0C) is really the CHROMA stride and `chromaStride` (+0x0E) is the LUMA one,
and in `form_prediction` the "luma" lane drives the two chroma blocks while the
"chroma" lane drives the four luma blocks. It is self-consistent and faithful -
confirmed three separate ways - so do NOT "fix" it, but do not trust the names
when reasoning.

## Earlier notes on the corruption

The THQ logo is clearly legible and full-screen, but blocks are displaced and
smeared, with red/cyan fringing on block edges. **Already ruled out - do not
re-check these:**

- MBAI decode: an I picture decodes exactly 1440 MBs (45 x 32) with **zero**
  discontinuities, so the address increment and the conceal handler are fine.
- `mpvvlt_mbai_i_0/i_1`, `mpvvlt_mbai_p_0/p_1`, `mpvvlt_p_mbtype`: all compared
  word-for-word against FUN_00AF63F0 / FUN_00AF6630 / FUN_00AF6B90. Correct.
  (`WriteTableWord`'s second argument is a **byte offset**, not a word index -
  0x00/0x02/0x04/0x06 really is words 0..3.)
- `form_prediction` (FUN_00C0C390): faithful, including the truncate-toward-zero
  `/2` vs arithmetic `>>1` split and both kernel indices.
- The 8-entry interpolation dispatch: matches FUN_00AF6040's C lane exactly
  (`[6]` and `[7]` really are the same function). Table lives in the BSS tail of
  `.data`, so it cannot be read out of the PE file - only from the initialiser.
- `MPVDEC_ResetMv` zeroes +0x10..+0x1C (predictors), not the config. Correct.
- Half-pel: forcing `motionX &= ~1` changes the picture, but not the artifacts.

Motion vectors are healthy: ~70% non-zero, ~16% odd (half-pel) parity,
`maxAbs=128`, occasional clamps. The all-zero MVs seen in the first 40 samples
are just the static black lead-in - **do not read the first samples and conclude
motion is dead.**

The movie has exactly **one I picture** (the all-black first frame); everything
after is P and B, so any error propagates for the whole clip. Next places to
look: the residual/IDCT path (`decodeResidualMacroblock`, run/level tables,
dequant), `MPVUMC_GetMacroblockPlaneOffsets` / `ConfigureCopyTargetPlanes`, and
whether the forward/backward reference frames are the right pool entries -
`e02a585` proves that struct family had at least one layout bug already.

Useful: `ptype` is logged per uploaded frame (1=I, 2=P, 3=B) from
`MwsfdFrameInfo+0x1C`.

See [[project_movie_playback_chain_2026_08_07]],
[[project_frame_driver_refresh_stub]], [[project_resize_crash_depth_stencil_binding]].
