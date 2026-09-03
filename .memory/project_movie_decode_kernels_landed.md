---
name: project-movie-decode-kernels-landed
description: MPEG kernels + lua_resume LANDED; movie UI script now runs and dies on a FABRICATED CMoviePlaybackInterface vtable (real slot for IsLoaded is 1, not 6)
metadata:
  type: project
---

Session 2026-08-06, four commits: `92a6bf1`, `bb01001`, `7274861` (+ earlier
`03f9dfc`). See also [[project-movie-create-succeeds-stm-gate]] and
[[project-lua-hybrid-abi-blocker]].

## LANDED: both MPEG-1 read kernels

`mpvhdec_ReadKernelIntraDefault` (0x00AFAE50) and
`mpvhdec_ReadKernelPredictedDefault` (0x00AFD7C0) were
`{ return nullptr; }` stubs — every block decoded to nothing. Both are now
real bodies in `src/sdk/moho/movie/MPVDecoder.cpp`, `tucheck EXITCODE=0`
first try.

**Do not transcribe the 2400-line decompiles.** They are hand-unrolled
(two codes retired per dispatch, short codes inlined). Every path resolves
to one `(run, level, sign, lengthBits)` quadruple, so a single-symbol
Table B-14 decoder over the binary's own tables is both faithful and
~150 lines. The unrolling is optimizer shape, not semantics.

### The dispatch, exactly

`mpvvlt_run_level_8` (already recovered, 128 dwords) is a complete
top-byte dispatch table for **every** code with bit 31 clear, indexed by
window bits 30..24. Entry = `length << 16 | level << 8 | run`, level
signed. Entries 0..3 zero = "too long, use the word tables"; entries 4..7
carry run 64 = ESCAPE.

  - `top >= 0xC0` → `11s`, run 0 level 1, 3 bits (sign = bit 29)
  - `0x80..0xBF` → `10` EOB, 2 bits
  - `0x04..0x7F` → `acShortRunLevelTable[top]`
  - `0x00..0x03` → six word tables by leading-zero count:
    11 bits (`(w>>21)&0x3FF`), 13 (`>>19 &0xFFF`), 14 (`>>18 &0x1FFF`),
    15 (`>>17 &0x1F`), 16 (`>>16 &0x1F`), 17 (`>>15 &0x1F`).
    Index the table by `codeBits >> 1`; the dropped low bit is the sign.
  - ESCAPE: 6-bit run at `(w>>20)&0x3F`, 8-bit level at `(int8)(w>>12)`,
    20 bits; if `(level & 0x7F) == 0` then `level = level*2 | ((w>>4)&0xFF)`
    and 28 bits.

Intra dequant is `(quantScale * 2*level * qm[i]) >> 4`; **non-intra is
`2*level + 1`** (confirmed by the folded constants 3/5/9 for levels 1/2/4).
Then `if (v) v = (v-1)|1`, negate on sign,
`coefficients[i] = v * dequantScaleTable[i]`.

Predicted blocks additionally: clear all 64 coefficients on entry, no DC
pass, and the FIRST code cannot be EOB — a leading one is `1s` (two bits)
and it indexes the scan directly (`base + run`, no `+1`). That first
coefficient's scan index becomes `scanIndexLimit`.

### Two layout errors fixed in the same pass

  - `MPVCoefficientDecodeState` had **run and level swapped**. Run is
    +0x00, level +0x04. Swapped, it builds/links/runs and silently
    decodes garbage.
  - The seven pointers at +0x10 are **not uniform**: +0x10 is a
    `uint32*` short table, +0x14..+0x2B are six `uint16*` long tables.
    Split into `acShortRunLevelTable` + `acLongRunLevelTables[6]`.

`mpvlib_InitObj` (0x00AE7D60) is what wires them, with deliberate negative
biases (`run_level_4 - 16`, `run_level_2/1 - 32`) folded into the stored
pointer — so index with the raw code bits, do not re-bias.

## LANDED: lua_resume — the "<non-string lua error>" was this

`lua_resume` was absent, so it resolved to `LuaPlusLibD_1081.lib`, which
walks the coroutine at stock offsets and writes 12-byte TObjects onto our
8-byte stack. **Recovering it made scripts actually run.** No
`luaD_rawrunprotected` in this fork — like `lua_call` it protects with a
C++ try; the handlers at 0x009146BF / 0x00914728 are the elided EH
funclets (return `error.code` / `LUA_ERRRUN` respectively, both after
rewinding to `base_ci`, `luaF_close`, `PushLuaStringAtStackSlot`,
restoring `l_G->allowhook`, `luaD_refreshstacklimit`).

`resume_error` was already recovered but orphaned behind
`[[maybe_unused]]`; it is now wired.

## NEXT BLOCKER (diagnosed, not fixed)

The UI script now reaches `CMauiMovie::IsLoaded` and faults calling
through a garbage vtable slot. Fault address `0x69766F4D` is the ASCII
bytes `"Movi"` — a dead giveaway that the "vtable" is really data.

**The `CMoviePlaybackInterface` slot order is CORRECT — do not "fix" it.**
I nearly rewrote it on the strength of IDA's `cmovie->Func4` /
`cmovie->Func7` naming. Those are *arbitrary IDA field names*, not slot
indices and not byte offsets (`Func7` is not even 4-aligned). The `.asm`
settles it:

  - `FUN_0079FCF0` (IsLoaded): `mov edx,[ecx]` / `mov eax,[edx+18h]`
    → byte 0x18 = **index 6** = the shim's `IsLoaded`. Correct.
  - `FUN_0079FE50` (GetNumFrames): `[edx+2Ch]` → **index 11** =
    the shim's `GetFrameCount`. Correct.
  - `mMovie` is `[esi+11Ch]` → +0x11C. Correct.

**Read the `.asm` displacement, never IDA's synthesized `FuncN` name.**

So the real defect is that the `CMovie` object's **vptr is clobbered**,
not that the slot is wrong. The fault target `0x69766F4D` is the literal
text `"Movi"`, and the only producer of a string starting with those
bytes on this path is

    SetDebugName(gpg::STR_Printf("Movie filename = %s", filename));

in `CMauiMovie::LoadFile` (`UiRuntimeTypes.cpp:15635`), which runs right
after `mMovie` is published. Next step: check where `SetDebugName` stores
its text relative to `CMauiMovie`/`CMovie` — a debug-name lane written at
the wrong offset would land on the freshly constructed `CMovie`'s vptr.
Verify against the binary's own `SetDebugName` displacement before
changing anything.

## Run/verify recipe (unchanged, but note the stale-obj trap)

`cri/sofdec/*.cpp` are fragments `#include`d into
`moho/audio/SofdecRuntime.cpp`. Editing a fragment does **not** invalidate
the aggregator `.obj` — `rm buildstage/main/Win32/Debug/SofdecRuntime.obj`
before rebuilding or the old stub silently survives.

`OpenMovie /movies/thqlogo.sfd: N` — the N is `snd_index`, a counter, NOT
a status. Do not read `: 0` as failure.

Baseline link is **17 unresolved**, `BUILD_EXITCODE=0`. Healthy.
