---
name: project-mpv-copyspan-transposed
description: Movie pixelation + SFD ERROR(FF000207) freeze were ONE bug — MPVUMC_CopyPredictionSpan copied 16 chroma rows and 8 luma rows instead of 8 and 16. Fixed a3e013c. Includes the MPV plane-lane ordering (chroma-first) and the probe recipe that found it.
metadata:
  type: project
---

# Movie pixelation + FF000207 freeze — SOLVED (a3e013c)

Both symptoms the operator reported for the splash movies ("pixelating a bit",
"freezes on one frame", "second video not working") were the **same defect** in
`MPVUMC_CopyPredictionSpan` (FUN_00C0CA20), the skipped-macroblock copy.

The binary copies, per skipped macroblock:
  - **two 8x8 chroma blocks**, stride from `MPVMacroblockOffsets +0x0C`
  - **one 16x16 luma block**, stride from `MPVMacroblockOffsets +0x0E`

The recovered body had the extents transposed — 16 rows of the chroma pair and
8 rows of luma. Consequences:
  - 8 chroma rows written past the bottom of every skipped macroblock →
    for the last macroblock row, past the end of the frame surface;
  - only half of each skipped luma macroblock refreshed → the blockiness.

## ⚠ MPV plane lanes are ordered CHROMA-FIRST

This is the trap that hid the bug and will hide the next one. Both in the
handle and in `MPVMacroblockOffsets`, the planes are U, V, Y — **not** Y first:

| lane | handle (`MPVUMC_InitOutRfb` writes it) | `MPVMacroblockOffsets` |
|---|---|---|
| chroma U | +0x294 | +0x00 |
| chroma V | +0x298 | +0x04 |
| **luma** | +0x29C | +0x08 |
| chroma stride | +0x2A0 (int16) | +0x0C (int16) |
| **luma stride** | +0x2A2 (int16) | +0x0E (int16) |

`MPVSpatialDelta` follows the same order: first word = chroma delta (8 bytes per
MB column), second = luma (16 bytes per column).

**The C++ member names in `MPVMacroblockOffsets`, `MPVSpatialDelta` and
`MPVThumbnailPlaneLayout` are still inverted** (`lumaOffset` is really chroma-U,
`lumaStride` is really the chroma stride, `MPVSpatialDelta::luma` is really the
chroma delta, …). The offsets they resolve to are right, so everything using
them is correct — but read the offset, never the name. Renaming them is
outstanding work and is a *cyclic* rename, so a botched pass still compiles;
do it with placeholder names and review every changed line.

Verified-correct users of the inverted names (do not "fix" these):
`ConfigureCopyTargetPlanes` (blocks 0,1 = chroma U/V; 2..5 = the four luma
quadrants), `mpvumct_PpicSkipMb` (thumbnail: 1 sample per chroma plane, 2x2
luma), `MPVUMC_GetMacroblockPlaneOffsets`, `mpvumct_CalcOfs`.

## Why the freeze looked random

`mwsfcre_CreateSfd` bump-allocates the whole SFD arena in order:
inputBuffers, streamRing, refFrame[0], refFrame[1], framePool[0..N-1],
seekRecord, **ctrlPrimary (the SFD workctrl)**, … Frame surfaces get
`MwsfcreFrameBufferBytes()` and `SFD_SetMpvParaTbl` aligns each base up to
0x800, which leaves **exactly** the decoder's frame size usable — zero slack.

So a chroma overrun from the *last* pool slot lands in the workctrl; the byte
it hit was the frame-API lane at **workctrl+0x58** (`SfplyGetFrameRuntimeView::
frameApiType`). Once that lane holds anything but 0/1/2, every later
`SFD_GetFrm` returns `SFD ERROR(FF000207)` and playback freezes on the frame it
had. An overrun from any *earlier* slot just corrupted the next frame — visible
as artifacts, no error. That is the whole explanation for the run-to-run
randomness; there is no thread race here (the ADXM workers never start — see
[[project-playback-speed-frame-slaved]]).

The corrupting value was `0x10101010` = luma black (16) copied out of a black
reference frame, which is why it looked like a memset.

## Probe recipe that found it (rebuild it this way, it worked)

1. `SofdecSfdRuntime.cpp` — in `sfply_CheckGetFrmApi`, publish
   `gFafSofdecFrameApiLaneWatch = &frameView->frameApiType` on **every** call.
   Never cache it: the workctrl is freed between movies and a stale pointer
   reads a pointer value out of freed memory and reports a false hit.
2. `MPVDecoder.cpp` — a `FafProbeLane(handle, checkpoint, index)` that appends
   to a file only when the lane is outside {0,1,2}, capped at ~40 reports, and
   dumps the decoder geometry (rfb/plane bases/strides/mb cursor) with it.
   Sprinkle checkpoints down `MPV_DecodeFrmSj` → `MPVSL_DecPicture` →
   `MPVSL_DecSliceOne` → the per-macroblock dispatches. The first checkpoint
   that fires names the culprit — here `ppic-skiprun`.
3. `MWSFD_Malloc` — log every arena carve-up (`#n size -> base..end`). This is
   what proved the frame pool sits immediately before the workctrl and that the
   corrupt address was `frameBase + frameSize + 0x8D8`.
4. Build probes into **Release**, never Debug: `run-engine.bat` rebuilds Debug
   and overwrites the staged Release exe, and Debug plays movies at 34-50 fps.
   Use `.vscode/run-engine-release.bat` (added this session; takes
   `nobuild` and a kill-after-N-seconds argument).
5. The corruption is intermittent — loop the run 4-5 times before concluding
   a change fixed it.

## Also landed this session

- `20237db` `SFX_GetCompoMode` (0x00ACCD40) was a no-argument `void* f()` stub —
  the **seventh** C-linkage stub trap in the Sofdec tree. See
  [[project-c-linkage-stub-trap]].
- `a969678` crash diagnostics: `WIN_ShowCrashDialog` now also writes the summary
  and callstack via `gpg::Logf` (the dialog resource does not load in this
  build, so the text was being lost), and the post-build step stages
  `main.pdb` next to `main.exe` — without it DbgHelp resolved every frame
  against a stale pdb and printed unrelated ntdll exports.
