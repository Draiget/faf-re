---
name: project_movie_create_passes_mps_chain_next
description: Movie create path is fully recovered and fault-free; the one remaining blocker is the 11-function MPS program-stream parser chain, fully mapped with addresses here.
metadata:
  type: project
---

State as of 2026-08-06, commit `07edf6f` ("Recover the SFPLY handle constructor").
Continues [[project_movie_sfd_header_gate_passed]].

## Where the movie path actually is now

`main.exe` builds at the **19-unresolved baseline** (`BUILD_EXITCODE=0`) and runs
with **fault=0** — it reaches the render loop and sits in `DeviceD3D9::Present`
pumping frames. The dbgrun "hang-timeout" line at that point is the watchdog,
not a bug.

`CMovie::OpenMovie` now walks the **entire** Sofdec create path with no access
violation. The log ends:

```
debug: OpenMovie /movies/thqlogo.sfd: 0
warning: SofDec error: SFD ERROR(FF000D08)
warning: SofDec error: E20010703C mwPlyCreateSofdec: create error
warning: SofDec error: E2012 mwPlyCreate:can't create SFD
```

`FF000D08` is `kSflibErrSfmpsCreateFailed`, raised by `SFMPS_Create`
(0x00AD6990, recovered) when `MPS_Create()` returns null.

## UPDATE 2026-08-06 (f87692e): the MPS chain LANDED — movies now CREATE

The 11-function chain below is **recovered and committed**. `SFD ERROR(FF000D08)`,
`mwPlyCreateSofdec: create error` and `E2012 mwPlyCreate:can't create SFD` are
all gone from the log. The Sofdec create path is complete end to end.

`M2P_Create`/`M2P_SetErrFn` had been recovered with no parameters (the backend
slots are one generic pointer type); the binary calls them with 2 and 3
arguments, so they now carry their real signatures and forward.

### The next blocker is the MPEG-1 VIDEO DECODER (MPV) — a whole subsystem

`gSfmpvTransferStrategy` still has `create = nullptr` (grep `TODO-TABLE`), so
`sfply_TrCreate` calls address 0 and the process dies with an
`ACCESS_VIOLATION at 00000000`. Three table holes remain in total:

| Slot | Function | On our path? |
|---|---|---|
| `gSfmpvTransferStrategy.create` | `SFMPV_Create` 0x00AD4BA0 | **YES** — any video stream |
| `gSfm2tsTransferStrategy.execServer` | `SFM2TS_ExecServer` 0x00ACF140 | no — MPEG-2 TS only |
| `gSfm2tsTransferStrategy.create` | `SFM2TS_Create` 0x00ACF800 | no — MPEG-2 TS only |

`SFMPV_Create` itself is small and all its callees exist **except**
`MPV_Create` (0x00AE7C00) and `MPV_SetErrFunc` (0x00AEAE90). `MPV_SetErrFunc`
is trivial and unblocked. `MPV_Create` is what opens the subsystem:

```
MPV_Create 0x00AE7C00
├── mpvlib_SearchFreeHn 0x00AE7C40   18 lines, unblocked
├── MPVM2V_Create       0x00AF5C70    thunk to M2V_Create (recovered)
└── mpvlib_InitHn       0x00AE7C70   32 lines
    ├── mpvlib_InitObj      0x00AE7D60  34 lines  (stores table addresses only)
    ├── UTY_MemcpyDword     0x00AF7CF0  86 lines
    ├── MPVERR_InitErrInf   0x00AEAE70  12 lines
    ├── MPVCMC_InitObj      0x00AF5F30   5 lines -> sub_B05670 (8 lines) + mpvcmc_InitMcOiTa (recovered)
    ├── mpvlib_InitDctPa    0x00AE7F10   8 lines -> sub_AF7E40 (5 lines)
    ├── mpvlib_InitPicAtr   0x00AE7E70  45 lines
    └── takes the address of:
        DCT_FsriTrans6Blk 0x00AF7F20 (4-line thunk)
        DCT_FsriTransCbp  0x00AF7F30 (4-line thunk)
        sub_AFAE50  0x00AFAE50  **2425 lines** — macroblock decoder
        sub_AFD7C0  0x00AFD7C0  **2502 lines** — macroblock decoder
```

**The two ~2500-line macroblock decoders are the real gate.** `mpvlib_InitHn`
only stores their addresses, so they are never *called* during create — but the
symbols must exist to take their address, and a stub body is forbidden. Budget
a dedicated session for those two.

### The VLC tables are NOT static data — do not try to extract them

Verified against the PE: `mpvvlc_run_level_{0a,0b,0c,1,2,4,8}` (0x01108150 /
0x01108158 / 0x01108150 / 0x01108124 / 0x01108120 / 0x01108128 / 0x0110812C),
`mpvvlc_y_dcsiz` (0x01108138), `mpvvlc_c_dcsiz` (0x0110814C),
`mpv_clip_0_255_base` (0x011F8740) and `mpvlib_libwork` (0x01000C08) all land
**past `.data`'s raw size — they are BSS**. The asm confirms the shape:
`mov edx, _mpvvlc_run_level_8` is a *load*, not an address-of, so these are
4-byte **pointer variables**, not arrays. The current stub file models them as
zeroed 4 KB arrays, which is the wrong shape as well as the wrong content.

So there is nothing to extract from the binary. They are wired at runtime by
`MPV_Init` (0x00AE7950), which is the real keystone for the whole decoder:

```
MPV_Init 0x00AE7950   (currently `int MPV_Init() { return 0; }`)
├── mpvlib_ChkFatal / mpvlib_ChkCacheMode
├── MPVLIB_ConvWorkAddr(workAddress)
├── mpvlib_InitWork(framePoolCount, workAddress)   <- builds mpvlib_libwork,
│                                                     sets handleCount (+0x54)
│                                                     and the handle array (+0x58)
├── MPVERR_Init / MPVHDEC_Init / MPVFRM_Init
├── MPVVLC_Init(libwork[20] + 4784)   <- THIS sets the mpvvlc_* pointers
├── MPVBDEC_Init(libwork[20]) / MPVUMC_Init / MPVCDEC_Init
├── mpvlib_InitClip(libwork[20] + 6240)  <- sets mpv_clip_0_255_base
├── mpvlib_InitObjTbl / mpvlib_InitDct(libwork[20])
└── MPVM2V_Init
```

Recover `MPV_Init` before `MPV_Create`: with `mpvlib_libwork` zeroed,
`handleCount` is 0 and `mpvlib_SearchFreeHn` returns null regardless of how
much of the create chain is wired.

Even with all of the above wired, **there is still no picture**, because the
MPV data tables are placeholders: `SofdecExternalStubs.cpp` defines
`mpvlib_libwork`, `mpvvlc_run_level_{0a,0b,0c,1,2,4,8}`, `mpvvlc_y_dcsiz`,
`mpvvlc_c_dcsiz`, `mpvlib_cond_dfl` and `mpv_clip_0_255_base` as **zeroed 4 KB
arrays**, and `MPV_Init` is `int MPV_Init() { return 0; }`. The VLC tables have
to be extracted from the PE (same recipe as the create templates — walk the
section table, convert RVA to file offset). Colour conversion
(`cft_*Ycc420plnToArgb8888*`) is stubbed too.

Useful consequence: with `mpvlib_libwork` zeroed, `handleCount` is 0, so
`mpvlib_SearchFreeHn` returns null and `MPV_Create` returns 0 *before* reaching
`mpvlib_InitHn`. Once the chain links, the runtime path is the binary's own
clean error return (`SFLIB_SetErr(0, -16773366)`), not a crash — so wiring the
chain fixes the access violation even before the decoder works.

## (historical) The blocker that MPS_Create was

`MPS_Create` is `void* MPS_Create() { return nullptr; }` in
`SofdecExternalStubs.cpp`. **Seventh** instance of the C-linkage stub trap in
this subsystem (after `mwPlyGetHdrInf`, `SFHDS_ProcessHdr`, `mwPlyInitSfdFx`,
`ADXT_Init`, `sfply_InitHn`, `SFHDS_InitFhd`). Grep the stub file for
`void* X() { return nullptr; }` before assuming any Sofdec symbol is missing —
it is usually present-but-stubbed.

### The full chain (11 functions) — all addresses verified from the .asm

Recover **bottom-up in this order**; it is atomic (nothing below `MPS_Create`
has a source-level caller until the top lands), so it commits as one unit.

| Address | Symbol | .c lines | Callees |
|---|---|---|---|
| 0x00AEB6F0 | `mpsdec_DecPackHd` | 203 | none |
| 0x00AEBA40 | `mpsdec_DecSysHd` | 530 | `MPS_CheckDelim` (recovered) |
| 0x00AEC050 | `mpsdec_DecPketHd` | 899 | none |
| 0x00AEB650 | `mpsdec_DecOneHd` | 34 | the three above + `MPS_CheckDelim` |
| 0x00AEB5C0 | `MPSDEC_DecHdMpeg1` | 35 | `mpsdec_DecOneHd` |
| 0x00AEB350 | `mpslib_InitPack` | 11 | none (writes 4 × -1) |
| 0x00AEB370 | `mpslib_InitSys` | 15 | none (writes 8 × -1) |
| 0x00AEB390 | `mpslib_InitPket` | 17 | none (writes 10 × -1) |
| 0x00AEB430 | `mpslib_M2sErrFn` | 4 | `MPSLIB_SetErr` (recovered) — thunk |
| 0x00AEB450 | `mpslib_SearchM2pHnWk` | 12 | none |
| 0x00AEB2B0 | `mpslib_InitHn` | 24 | `UTY_MemsetDword`, `MPSLIB_InitErrInf`, the three `mpslib_Init*` |
| 0x00AEB200 | `MPS_Create` | 26 | `mpslib_SearchFreeHn` (recovered), `mpslib_InitHn`, `mpslib_SearchM2pHnWk`, `M2P_Create`, `M2P_SetErrFn` |

**There are no further unrecovered dependencies.** `MPS_CheckDelim`,
`MPSLIB_SetErr`, `MPSLIB_InitErrInf`, `mpslib_SearchFreeHn`,
`mpslib_InitLibWork`, `MPS_Init`, `SFMPS_Init`, `M2P_Create`, `M2P_SetErrFn`
and `UTY_MemsetDword` are all already in `src/sdk/cri/sofdec/`.

### Facts already established — do NOT re-derive

- **`M2P_Create` returning 0 is fine.** `MPS_Create` stores it at handle+0xD0,
  skips `M2P_SetErrFn`, and *still returns the handle*. The M2P backend
  (`m2sapi_m2p_Create`) is a null function pointer in this build. So the only
  thing that can null `MPS_Create` is `mpslib_SearchFreeHn`, which works once
  `SFMPS_Init` has run (it is the SFMPS strategy's slot-0 `init`).
- **`mpslib_m2p_hnwk` (0x011F8300) and `mpslib_m2p` (0x011F8280) are BSS** —
  verified against the PE: both fall past `.data`'s raw size, so they are
  zero-initialised. `mpslib_SearchM2pHnWk(0)` therefore returns index 0.
- **`MPSDEC_dechd` (0x00F42048) is a statically-initialised function pointer
  holding 0x00AEB5C0 = `&MPSDEC_DecHdMpeg1`** (PE bytes `c0 b5 ae 00`). It is
  stored into handle+0xD4 by `mpslib_InitHn`. This is why the DecHd chain has
  to land in the same unit — you cannot take the address of a function you have
  not recovered, and a stub body is forbidden.
- **`MpslibHandleRuntimeView` is 0x100 bytes** and already modelled. The
  `mpslib_InitHn` lane map: +0x00 state=2, +0x04 errInfo (0x0C), +0x10 = 2,
  +0x18 pack, +0x28/+0x48/+0x68/+0x88 four sys blocks (0x20 each), +0xA8 pket,
  +0xD0 m2p handle, +0xD4 `MPSDEC_dechd`, +0xD8..+0xE8 zero. `handleState`
  1 = free, 2 = in use.

## The three parsers are an INLINED bitstream reader — build the helper first

`mpsdec_DecPackHd`/`DecSysHd`/`DecPketHd` decompile into ~1600 lines of
variable soup (`v3`..`v53`) because the compiler inlined a big-endian
`getbits` reader at every field. Do **not** transcribe the decompiler output —
recover the reader once as a named helper and express each parser as a field
list. The fidelity contract requires exactly this.

Reader mechanics, decoded from `FUN_00AEB6F0`'s asm (0x00AEB6F0-0x00AEB735):

- `base = (packet + 4) & ~3` and `shift = 8 * (packet % 4)`; it loads the
  4-byte **big-endian** word at `base` and shifts left by `shift`. Net effect:
  **the bit stream starts at `packet + 4`**, i.e. just past the 32-bit start
  code. The `and al, 0FCh` / `lea esi, 20h[ecx*8]` pair is only the
  aligned-load machinery, not a field.
- The accumulator is MSB-aligned 32-bit with a refill branch at every field:
  `if (pos < K) { pos += K; take from accumulator } else { pos -= K; splice
  in the next big-endian word }`. Each refill re-reads 4 bytes and advances.

`mpsdec_DecPackHd` is the **MPEG-1 pack header** (ISO/IEC 11172-1), confirmed
field-for-field by the store tail at 0x00AEB9E4-0x00AEBA30:

```
pack_start_code 32 | '0010' 4 | SCR[32:30] 3 | marker 1
| SCR[29:15] 15 | marker 1 | SCR[14:0] 15 | marker 1 | marker 1
| mux_rate 22 | marker 1                                   = 96 bits = 12 bytes
```

The two `shld ecx, eax, 0Fh` / `shl eax, 0Fh` pairs are one 64-bit
shift-left-15 each, so the SCR is assembled as
`((scr3 << 15) | scr15a) << 15 | scr15b` — a 33-bit value that genuinely needs
the high dword. Stores: `+0x18` SCR low, `+0x1C` SCR high, `+0x24` mux_rate
(the `shr edi, 0Ah` is the 22-bit field dropping out of an MSB-aligned 32-bit
read), `+0x20` a flag set to `(muxRateHigh == 0)`. `*outBytes = 12`.

Those four offsets are inside the pack lane `mpslib_InitPack` primes
(handle +0x18..+0x24, four dwords of -1), which cross-checks the lane map.

## Layout error fixed this session — worth remembering as a pattern

`SfplyCreateParams::packBytes` was modelled at +0x24; it is at **+0x28**.
`mwsfcre_CreateSfd` stores `mwsfd_packsize` at `[esp+0x98]` against frame base
0x70, and all four shipped create templates (0x00F40008 / 0x50 / 0x98 / 0xE0)
carry 0x800 in that slot. `SFBUF_InitHn` divides lane 0's size by it, so the
one-slot error produced an **integer-divide fault** that only appeared once
`sfply_InitHn` started doing real work. Lesson: when a newly-unstubbed function
faults immediately, suspect the struct it reads before suspecting the function.

Dumping the four create templates straight out of the PE settled it in one
step — `bin/2025.7.1/ForgedAlliance.exe`, imageBase 0x00400000, walk the
section table and convert RVA→file offset. Do that before trusting any
IDA-frame-derived offset.

## Run recipe (unchanged, and non-negotiable)

Build with the scratchpad `bldfs.bat`; **launch only via the scratchpad
`runwinlog.bat`** so `/windowed` goes through cmd.exe. Kill leaked `main.exe`
first. `cri/sofdec/*.cpp` are fragments `#include`d by
`moho/audio/SofdecRuntime.cpp` — editing a fragment does not invalidate the
aggregator's `.obj`, so delete
`buildstage/main/Win32/Debug/SofdecRuntime.obj` to force a rebuild.

## MPV_Init fan-out — measured, all small (2026-08-06)

Every callee is tiny; the tree is broad but shallow. Sizes are decompiled-line
counts, `.c` in the usual namespace dir.

| Function | Token | clines | Callees |
|---|---|---|---|
| `mpvlib_ChkFatal` | FUN_00AE79E0 | 8 | MPVDEC_CheckVersion, MPVERR_SetCode, MPVVLC_IsVlcSizErr |
| `mpvlib_ChkCacheMode` | FUN_00AE7A30 | 4 | none |
| `MPVLIB_ConvWorkAddr` | FUN_00AE7A40 | 4 | none |
| `mpvlib_InitWork` | FUN_00AE7B60 | 13 | UTY_MemcpyDword, UTY_MemsetDword, nullsub_48 |
| `MPVERR_Init` | FUN_00AEAE60 | 4 | MPVERR_InitErrInf |
| `MPVHDEC_Init` | FUN_00AE8120 | 43 | none |
| `MPVFRM_Init` | FUN_00AEAB10 | 4 | none |
| `MPVVLC_Init` | FUN_00AF63A0 | 16 | mpvvlc_Init{Cbp,DcSiz,MbType,Mbai,Motion,RunLevel}, mpvvlc_SetDflPtr, mpvvlc_SetupVlc |
| `MPVBDEC_Init` | FUN_00AF61F0 | 23 | MPVABDEC_Init, mpvbdec_SetupIxa, nullsub_50 |
| `MPVUMC_Init` | FUN_00AF6030 | 5 | none |
| `MPVCDEC_Init` | FUN_00AF5E70 | 5 | none |
| `mpvlib_InitClip` / `mpvlib_InitObjTbl` / `mpvlib_InitDct` / `MPVM2V_Init` | (not yet measured) | | |

`MPVVLC_Init`'s eight `mpvvlc_Init*` helpers are what populate the BSS pointer
variables (`mpvvlc_run_level_*`, `mpvvlc_y_dcsiz`, ...) out of the work area at
`libwork[20] + 4784`. That is the whole answer to "where do the VLC tables come
from" - they are built, not stored.

Recommended order for the next session:
1. `MPV_Init` + this fan-out (~20 small functions, no big leaves).
2. `MPV_SetErrFunc` (0x00AEAE90, 6 lines) and `mpvlib_SearchFreeHn` (18 lines).
3. The two ~2000-line VLC macroblock decoders `sub_AFAE50` / `sub_AFD7C0` -
   the only genuinely large bodies in the whole chain. Leaves, no callees.
4. `mpvlib_InitHn` -> `MPV_Create` -> `SFMPV_Create`, then point
   `gSfmpvTransferStrategy.create` at it and drop the `TODO-TABLE` comment.

Confirmed by the user's own debugger stack: the fault is
`SFTRN_CallTrSetup` (SofdecSfdRuntime.cpp:8221) dispatching that null slot from
`sfply_TrCreate`. Nothing else in the create path faults.
