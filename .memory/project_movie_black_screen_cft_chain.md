---
name: project-movie-black-screen-cft-chain
description: Movie plays and renders but the window is BLACK - mwPlyFxCnvFrmARGB8888 is an empty stub; the whole SFX/CFT colour-convert chain is mapped here (~25 mostly-tiny functions)
metadata:
  type: project
---

Continues [[project-movie-decode-kernels-landed]]. Session 2026-08-06/07,
commits `92a6bf1`, `bb01001`, `7274861`, `68b0471`, `f5c47b3`.

## Where playback actually got to

Runtime evidence, `runwinlog.bat`, `cpp=0 fault=0`, process alive at the
60s timeout:

  - a real window exists, title "Forged Alliance", 1040x807
  - `debug: Playing movie ...thqlogo.sfd: 1` — new line, first time ever
  - the render path completes: `WRenViewport::Render` →
    `REN_RenderViewportUI` → `CUIManager::DrawHead` →
    `CMauiFrame::RenderChildControls` → `CMauiMovie::DoRender`

**But the client area is solid black.** Screenshot recipe is in
`scratchpad/capwin.ps1` (launch `runwinlog.bat` with
`run_in_background`, then run capwin.ps1 with a ~22s delay; it finds the
`main` process, foregrounds it, and saves a PNG you can Read).

## Why it is black — found, not fixed

`CMovie::UploadCurrentFrameToTexture` locks the texture sheet and calls

    ::mwPlyFxCnvFrmARGB8888(mPly, &frameInfo, outputBits);

and in `SofdecExternalStubs.cpp` that is

    void mwPlyFxCnvFrmARGB8888(...) {}

an **empty body**. The texture is locked, nothing is written, unlocked.
Every frame is transparent black. Two neighbours are stubbed too and are
comparatively benign: `ADXM_WaitVsync()` (no vsync wait) and
`mwPlyIsPause()` (always reports "not paused").

This is the C-linkage stub trap again — now the fourteenth instance in
this subsystem. Grep `SofdecExternalStubs.cpp` first on any new symptom.

## IN PROGRESS (uncommitted, in the working tree)

`src/sdk/cri/sofdec/SofdecColorConvertRuntime.cpp` is written and complete
but **not yet included anywhere**, so it compiles into nothing and cannot
break the build. It holds:

  - `kCftBgra256x3` — the real `_cftbgra256x3` table (0x00F420E0, file
    offset 0x00B420E0, 6144 bytes, 4051 of them non-zero), extracted from
    the in-repo PE. Three 256-entry planes of four `int16` — luma, Cb, Cr
    — in **BGRA** order, 6-bit fixed point.
  - `CFT_Ycc420plnToArgb8888` (0x00AF2A00) and a faithful scalar
    reimplementation of `cft_sse_Ycc420plnToArgb8888UserTable`
    (0x00AF2B20).

**The MMX kernel is a pure table lookup — do not port the SIMD.** Per
pixel: wrapping 16-bit sum of `luma[y] + cb[cbv] + cr[crv]` per BGRA lane,
arithmetic `>> 6`, saturate to byte. That is exactly
`paddw`/`psraw`/`packuswb`. The wrap matters — the alpha lane is 16320 and
relies on it. One chroma sample feeds a 2x2 luma quad.

Descriptor layouts, all confirmed:
  - source sextet passed to the kernel = `{yPtr, cbPtr, crPtr, yStride,
    cbStride, crStride}`, built by `CFT_Ycc420plnToArgb8888` from plane
    records at `[1..4]`, `[5..8]`, `[9..12]`.
  - target = `{planeCount, pixels, width, height, stride}`; stride goes
    negative after `SFX_SetBottomUpDstBuf`.
  - `tableParams[0]` is the table pointer, or 0 to mean "use
    `kCftBgra256x3`".

It stays uncommitted because nothing invokes it yet — committing it now
would be exactly the orphan-helper pattern CLAUDE.md forbids. Wire it by
recovering the chain below, then commit the whole thing as one unit.

The `SfxHandle` fields it needs are now LANDED (`8c9766d`): `tableBase`
+0x50, `splitField` +0x58, `progOut` +0x5C, `cnvBottomUp` +0x64,
`cnvFrmCallback` +0x68, `copyAlphaCallback` +0x6C,
`colorAdjustTableCallback` +0x70, plus the three callback typedefs.

`scratchpad/chain2.cpp` is a full draft of the rest of the chain
(`sfxcnv_IsCnvUpHalf`, `sfxcnv_MakeDstBufInf`, `sfxset_ShiftBufInfByPix`,
`SFX_ShiftYccPtrByPix`, `SFX_SetClipping`, `SFX_Make1PlaneCftDstBuf`,
`SFX_GetCnvBottomUp`, `SFX_SetBottomUpDstBuf`, `sfxcnv_MakeCftSrcBuf`,
`sfxcnv_ExecCnvFrmByCbFunc`, the setters, the field-split queries,
`SFX_IsMergeField`, `SFX_CnvFrmARGB8888ByCbFunc`,
`mwPlyFxCnvFrmClipARGB8888`, `mwPlyFxCnvFrmARGB8888`).

**It was wired once and the three real compile errors are known** — fix
these before re-wiring, and remember to delete `SofdecRuntime.obj`:

  1. `C2733` on `CFT_Ycc420plnToArgb8888`: something already declares it
     with `extern "C"` and a different signature. Find that declaration
     and match it rather than adding a second one.
  2. `kSfxErrCnvUnknownCompoMode` / `kSfxErrCnvUnknownFormat` do not
     exist. The real strings are in the `.rdata` near the other
     `kSfxErr*` constants in `SofdecAdxDeclarationsRuntime.cpp`
     (`aE201312SfxcnvI`, `aE4111901Sfxcnv`).
  3. `MwsfdSfxFrameInfo` is not visible at that point — it is declared
     inside a namespace in `SofdecAdxPlatformRuntime.cpp`. Either qualify
     it or place the fragment inside the same namespace.

Include it from `moho/audio/SofdecRuntime.cpp` AFTER
`SofdecSfxRuntime.cpp` (SfxHandle) and after `SofdecAdxRuntime.cpp`
(which pulls in `SofdecAdxPlatformRuntime.cpp`).

Still needed as definitions before it links, all currently absent:
`CFT_Ycc420plnToArgb8888Prg` / `Int`, `CFT_Ycc420plnToA256V`,
`CFT_MakeArgb8888AlpLumiTbl` / `Alp3211Tbl` / `Alp3110Tbl` /
`ColAdjTbl`, `SFX_CnvFrmAndMargFieldByCbFunc`,
`SFX_SetMakeLumiTableCbFunc` / `Alp3TableCbFunc` / `Alp3110TableCbFunc`
(these three write through `sfxa` at +0x30, not the handle itself).
Only the ARGB kernel is on the path a progressive movie takes; the rest
are address-taken and just have to exist.

## The chain to recover (addresses resolved, sizes measured)

`scratchpad/calls.py <addr>...` prints a function's resolved direct-call
targets and byte size straight out of the `.asm`. Reuse it.

```
mwPlyFxCnvFrmARGB8888        0x00ACC6E0   36B  STUBBED — 1-line forwarder
  mwPlyFxCnvFrmClipARGB8888  0x00ACC710  116B  missing — 4 lines
    MWSFSFX_CnvFrmInfToSfx   0x00AC6710        RECOVERED
    SFX_Make1PlaneCftDstBuf  0x00ACED60   70B  missing — 4 lines
      SFX_SetClipping        0x00ACE480   38B  missing — 3 lines
        SFX_ShiftYccPtrByPix 0x00ACD070        missing
      sfxcnv_MakeDstBufInf   0x00ACEDB0  118B  missing
        sfxcnv_IsCnvUpHalf   0x00ACE510        missing — switch on [a1+4]
    SFX_CnvFrmARGB8888ByCbFunc 0x00ADE110 172B missing — 27 lines
      SFX_SetCnvFrmCbFunc          0x00ACE940  12B  [a1+104] = cb
      SFX_SetCopyAlphaCbFunc       0x00ACE950  12B  [a1+108] = cb
      SFX_SetMakeLumiTableCbFunc   0x00ACE960  15B  [[a1+48]+24] = cb
      SFX_SetMakeAlp3110TableCbFunc 0x00ACE980 15B  [[a1+48]+28] = cb
      SFX_SetMakeAlp3TableCbFunc   0x00ACE970  15B  [[a1+48]+32] = cb
      SFX_SetMakeColAdjTableCbFunc 0x00ACE990  12B  [a1+112] = cb
      SFX_IsMergeField             0x00ACE3C0 119B + 4 tiny getters
      SFX_CnvFrmAndMargFieldByCbFunc 0x00ACEE30     missing
      SFX_CnvFrmByCbFunc           0x00ACE9A0  290B RECOVERED
        sfxcnv_ExecCnvFrmByCbFunc  0x00ACEB10  127B STUBBED — the executor
          sfxcnv_MakeCftSrcBuf     0x00ACEB90        missing
          SFX_GetCnvBottomUp       0x00ACCFE0        return [a1+100]
          SFX_SetBottomUpDstBuf    0x00ACE4B0        flips the dst stride
          <indirect via esi>       the CFT_* callback
        sfxcnv_ExecFullAlphaByCbFunc 0x00ACEC40      STUBBED
```

Callbacks `SFX_CnvFrmARGB8888ByCbFunc` installs (these do the actual
pixels, still to be located): `CFT_Ycc420plnToArgb8888`,
`…Argb8888Prg`, `…Argb8888Int`, `CFT_Ycc420plnToA256V`,
`CFT_MakeArgb8888AlpLumiTbl`, `CFT_MakeArgb8888Alp3211Tbl`,
`CFT_MakeArgb8888Alp3110Tbl`, `CFT_MakeArgb8888ColAdjTbl`.

Selection logic (0x00ADE110): `[a1+80] = 0`; if `[a2+116] == 1` use the
plain converter, else `[a1+80] = [a1+56] + 8223` and pick `…Prg` when
`[a2+104] == 1`, otherwise `…Int`.

## SfxHandle +0x50 — settled, it is a reused lane

`a1` is the `SfxHandle` (0x94, modelled in `SofdecSfxRuntime.cpp`).
Confirmed by the setters it calls: `+0x68/+0x6C/+0x70` land inside
`mUnknown68[0x2C]`, and `SFX_SetMakeLumiTableCbFunc` dereferences
`+0x30` (`sfxa`) before writing.

Both writes to `+0x50` are real, so no layout is wrong:

  - `sfx_InitHn` (0x00ACC940) does `mov [edx+50h], esi` where esi is the
    raw work address;
  - `SFX_CnvFrmARGB8888ByCbFunc` then replaces it with
    `planeBase(+0x38) + 8223`, a table pointer for the colour-adjust
    callback.

Nothing in `src/sdk/**` ever *reads* `handle->workAddress` — it is
write-only today — so the name is merely too narrow, not incorrect.
Rename it to something neutral (`tableBase`) in the same commit that
lands the converter, and keep both writes.

Also note `SfxCallbackFrameContext` / `SfxStreamState` in
`moho/audio/SofdecRuntime.h` are near-empty placeholders (8 and 0x94
bytes with one named field each), yet `SFX_CnvFrmByCbFunc` is already
typed against them. They almost certainly need to become the real
SfxHandle / frame-info types.
