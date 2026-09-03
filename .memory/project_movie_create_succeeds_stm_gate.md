---
name: project-movie-create-succeeds-stm-gate
description: Movie create/param gates all pass; blocker is now a silent nullptr from MWSTM_Create->ADXSTM. Records the goal_guard hook, the MPV chain landing, and the SFMPV layout resolution.
metadata:
  type: project
---

# Movies now create; blocker is the ADXSTM stream handle

Commits this session: `aaf3de1`, `fced7ce`, `9aa1e1c` (after `f57c26c`).

## Runtime state (verified, not inferred)

`ACCESS_VIOLATION at 00000000` in `SFTRN_CallTrSetup` is **gone**. `cpp=0
fault=0`; the process reaches `CScApp::Main` and runs frames. Every CRI
error string is gone from the log — zero occurrences of "SofDec" in
38 238 lines. The log now ends:

```
debug: OpenMovie /movies/thqlogo.sfd: 0
warning: mwPlyCreateSofdec failed for movie /movies/thqlogo.sfd
warning: Error opening movie /movies/thqlogo.sfd
```

**The silence is the diagnosis.** Every `return nullptr` in
`mwPlyCreateSofdec` calls `MWSFSVM_Error` first — except three. Of those,
`mwsfcre_MallocCompoWork` reports on both its own failure paths, so the
only remaining silent exit is:

```
SofdecAdxPlatformRuntime.cpp:2887   MWSTM_Create(ply->sjRingBufferHandle)
  -> ADXSTM_Create(sj, 0)           :14307
  -> adxstm_Create(sj, 0)           :14377
  -> ADXSTMF_CreateCvfsRt(nullptr, 0, 0, sj)   <- returns null here
```

Suspect the same shape as the old SFH-pool bug: a free-handle search over
a pool whose size lane was never initialised. Check that first.

`mwPlyGetStat` is NOT the problem — `mwPlyCreateSofdec` sets
`ply->compoMode = 0` at :2868, and GetStat returns compoMode unless it is
2. Verified faithful against FUN_00ACBA90.

## RULE ZERO / goal_guard

The Stop hook `cr_run_guard.py` clears after **one** commit, which is why
turns kept ending with the goal unmet. Added
`.claude/skills/continue-recovery/scripts/goal_guard.py` (wired into
`.claude/settings.json` on both UserPromptSubmit and Stop):

- `/goal <text>` sets `.claude/.faf-goal.json`; `/goal clear` clears it.
- UserPromptSubmit re-injects the goal every prompt, so it survives
  `/compact`.
- Stop blocks while a goal is active. Only the user can clear it.

"RULE ZERO" written into project `CLAUDE.md`, global `~/.claude/CLAUDE.md`,
both continue-recovery `SKILL.md`s, `init-recovery/SKILL.md`,
`.claude/commands/continue-recovery.md`, and all five `fa-*` skills.
Slogan that matters: **a goal is not a batch.**

## What landed

**`aaf3de1` MPV_Init** — the ninth no-argument nullptr stub
(`int MPV_Init() { return 0; }` satisfying a two-arg call through C
linkage). Its entire fan-out was already recovered in `MPVDecoder.cpp`.
Two data defects came with it:
- `mpvlib_cond_dfl` (0x00D7FC80) is initialized `.rdata`, not BSS. The
  4 KB zero stub gave every handle null condition defaults. Real contents:
  `{0,1,1,0, 0,0,3,0x7FFFFFFF, &conceal_cb, 0…}` — slot 8 is `nullsub_26`.
- `sfmpv_work` was `int sfmpv_work = 0;` while `mpvlib_InitWork` clears
  `(32+1)<<13` = 264 KB from it. Now sized from that clear, `alignas(32)`.

**`fced7ce` SFMPV_Create + the SfmpvHandleRuntimeView layout.** The
embedded `SfmpvTimingLane` really is 0x2A4 bytes: `SFTIM_UpdateItime`
(0x00ADAC60) reads `[esi+294h]` off the pointer `sfmpv_IsLate` passes,
and that pointer is `lea edi,[ebx+0D30h]` — the lane's own base. The
eleven fields previously declared as siblings after the lane (concat-time
history, total-sample queue, read/max frame times) are *interior* lane
fields at +0x168..+0x288. Moving them inside re-enabled every disabled
assert and they now all hold at once (mpvInfo 0x1FC0, seekFixedReadTotal
0x1FD8, headerWorkspaceBaseAddress 0x3550, sizeof 0x35E0).

**`9aa1e1c`** — `sfmpvf_CheckMpvPara` walked `sfmpv_rfb_adr_tbl` until the
cursor reached `sfmpv_work`. That only works because the symbols are
adjacent in the shipped BSS (0x00FB9CA8 and 0x00FB9CB0 — the table is
exactly 2 entries). Ours are in different TUs, so the walk ran off the
table and rejected every movie with `SFD ERROR(FF000F15)`.
**Watch for this pattern generally: any recovered loop bounded by
`&otherGlobal` depends on link order we do not reproduce.**
Also fixed `mwsfcre_CreateSfd` assigning `inputBuffers` to
`workControlBuffer` (overwritten two lines later); the binary writes
`a1.obj2` = `inputBufferPoolBase` at +0x04.

## Layout facts worth keeping

`SfplyCreateParams` confirmed from IDA's own stack-member names in
`mwsfcre_CreateSfd` (struct base = raw 0x74 at the esp+0F8h frame):
`inputBufferPoolBase` +0x04, `streamInputBytes` +0x08, `packBytes` +0x28,
`framePoolWork` +0x2C, `maxWidth` +0x30, `maxHeight` +0x34,
`bufferFormat` +0x38, `workControlBuffer` +0x3C. The earlier
+0x24→+0x28 `packBytes` move was right.

## STATUS UPDATE — movies now OPEN cleanly

`70514ab` (SFX_Create chain) and `e99b253` (MWSFD_IsEnableHndl) landed
after the section below was written, so **that section is done**.

The movie log is now clean for the first time: `/movies/thqlogo.sfd`
produces `OpenMovie …: 0` and **nothing else** — no `SofDec error`, no
`mwPlyCreateSofdec failed`, no `Error opening movie` — with `cpp=0
fault=0`. The whole create + start path works.

`MWSFD_IsEnableHndl` was the **tenth** no-argument nullptr stub. Every
public `mwPly*` opens with `if (MWSFD_IsEnableHndl(ply) != 1)`, so the
stub made a good handle look invalid everywhere. Real body: null in →
null out, else `ply->used` (first dword, `mov eax,[eax]` at 0x00ACBA19).
**Whenever a subsystem reports a wall of "handle is invalid", check the
validity predicate for this trap before doubting the handle.**

The log now reaches a line that had never appeared before:

```
debug: OpenMovie /movies/thqlogo.sfd: 0
debug: Preparing movie /movies/thqlogo.sfd: 0
warning: Error running lua script: <non-string lua error>
```

So `CMovie::OpenMovie` completes and the prepare loop (`kSofdecStatPreparing`,
CMovie.cpp:444) runs. **The immediate next blocker is that Lua error, not
Sofdec** — chase it first, and remember `lua_call` IS `LuaCallProtected`
with the status discarded, so surface the real message before assuming.

### The Lua error is the hybrid-ABI blocker, not a movie bug

Surfaced with a temporary diagnostic (since reverted — do not leave it in;
it faults, because `lua_typename` indexes `luaT_typenames` with whatever
`lua_type` returns). Result: **`type=159299440 top=1`**. The stack slot is
correct (`negindex(-1)` → `L->top-1`, top is 1) but the TObject's `tt`
holds `0x097EB770`, a pointer.

Cause: **`lua_resume` and `luaD_seterrorobj` are not in our tree at all** —
they resolve to the vendored `LuaPlusLibD_1081.lib`, which writes a stock
**12-byte** TObject onto a stack our 8-byte core then reads. See
[[project_lua_hybrid_abi_blocker]].

Recovering them is well-scoped but not trivial: `lua_resume` FUN_00914610
(30 clines), `resume` FUN_00914580 (31), `resume_error` FUN_00913DC0 (15).
All their callees exist (`luaD_precall`, `luaD_poscall`, `luaV_execute`,
`luaS_newlstr`, `luaD_growstack`) **except** the protected-call wrapper,
which the binary inlines as MSVC SEH around `call resume` at 0x009146A3
(handler does `luaF_close`, an indirect call, `sub_913810`, `sub_914080`).
`luaD_rawrunprotected` has no standalone symbol.

Useful confirmation from `resume_error`: it tests
`stack_last - top <= 8`, i.e. **the fork's TObject stride really is 8** and
our layout is the correct one.

### CONFIRMED final blocker for a picture

`MPVDecoder.cpp:7048` dispatches `context->decodeReadKernelIntra`, so the
kernels really are on the decode path — this is not bypassed by the M2V
backend. `mpvlib_InitHn` (:1988-1989) and :2987-2995 wire them to
`mpvhdec_ReadKernelIntraDefault` / `…PredictedDefault` /
`…IntraIdcPrec3`, and the first two are still `{ return nullptr; }` in
`SofdecExternalStubs.cpp`.

All three are the same C-linkage trap again (instances 11-13):
`SofdecExternalStubs.cpp` :159, :199, :200 define them as no-argument
`void*` stubs, while `MPVDecoder.cpp:262` declares the real shape
`std::uint8_t (MPVDecoderScanContext*, void*)`. So the count of that trap
in this subsystem is now thirteen — it is worth grepping
`SofdecExternalStubs.cpp` for `() { return nullptr; }` as a routine first
move on any new Sofdec symptom.

#### Head start on `sub_AFAE50` (`mpvhdec_ReadKernelIntraDefault`)

Signature `int __cdecl sub_AFAE50(int* a1, int a2)` = `(MPVDecoderScanContext*
ctx, DecodeState* st)`, matching the declaration at `MPVDecoder.cpp:262`
(`std::uint8_t (MPVDecoderScanContext*, void*)`).

Shape: read a DC coefficient through the lookup table at `st+44`, then a
`while(2)` loop whose body is `switch (HIBYTE(bitWindow))` — a 256-way
dispatch on the top byte decoding run/level pairs. That switch is the
whole 2400 lines. Body starts at **line 436** of the `.c`; everything
before it is IDA's local declarations.

`a1[n]` maps onto the existing `MPVDecoderScanContext` (already modelled
in `MPVDecoder.h:221`):

| decompiler | offset | field |
|---|---|---|
| `a1[0]` | +0x00 | `bitstreamState.bitWindowPrimary` |
| `a1[1]` | +0x04 | `bitstreamState.bitWindowSecondary` |
| `a1[2]` | +0x08 | `bitstreamState.bitCount` |
| `a1[3]` | +0x0C | `bitstreamState.byteCursor` |
| `a1[11]` | +0x2C | **unnamed** (inside `reserved_0010`) — block write cursor |
| `a1[12]` | +0x30 | **unnamed** (inside `reserved_0010`) — VLC mask table |
| `a1[122]` | +0x1E8 | **unnamed** (inside `reserved_01E0`) — picture-type gate, compared `!= 4` |

Those three are the only layout work needed before the body can be
written with named fields. `a2` lanes seen so far: `+0x10` and `+0x14`
zeroed, `+0x1C` a `float*` written `= *(int*)(a2+40) * 0.125`, `+0x28`
the DC-accumulator pointer, `+0x2C` the DC lookup table.


#### `sub_AFAE50` structural map (done — the switch is NOT 2400 unique lines)

The `.c` is 2425 lines but only ~1500 are case bodies, and they collapse to
**86 decode paths** over the 256 top-byte labels. Extraction recipe (the
labels are hex, `case 0xAu:` — a `\d+` regex silently matches only 10 of
them and makes the switch look tiny):

```python
body="
".join(open("FUN_00AFAE50.c").read().split("
")[435:])
parts=re.compile(r"
\s*case (0x[0-9A-Fa-f]+|\d+)u?:").split(body)
# consecutive labels whose preceding body is empty are fallthrough groups
```

Shape per path: test successive bits to pick a **code length**, select the
matching per-length VLC table, index it for a packed word whose high byte
is the run and low byte the level, store run/level/sign/length into the
decode state, advance the bit cursor.

- code lengths seen: 11, 13, 14, 15, 16, 17, 20, 28
- per-length VLC tables: `a1[4]`..`a1[10]` = ctx +0x10..+0x28
- `a1[11]` (+0x2C) and `a1[13]` (+0x34) appear in nearly every path —
  coefficient write cursor and scan/dequant lane
- `0x80..0xbf` is one 64-label group with a 6-line body: the shortest,
  most common code. `0xfe` is the largest single path at 74 lines.
- decode-state lanes: `a2+0` level, `a2+4` run, `a2+8` sign, `a2+12` code
  length

So ctx **+0x10..+0x34 is a VLC table pointer array**, not opaque padding —
that is the layout work to land before writing the body, and it names
`a1[7..10]` from the `case 0` path (lengths 14/15/16/17 select
`a1[7]/a1[8]/a1[9]/a1[10]` respectively).


#### Layout groundwork is LANDED (`addb1f4`, `c0875a8`)

Both prerequisites for writing the kernel bodies are committed and
asserted, so the next window can write behavior directly with named
fields and skip all re-derivation:

- `MPVDecoderScanContext` +0x10..+0x37 named: `acRunLevelVlcTables[7]`
  (+0x10, length 20/11/13/14/15/16/17 -> index 0..6),
  `coefficientWriteCursor` (+0x2C), `bitMaskByWidth` (+0x30),
  `dequantScaleTable` (+0x34).
- New `MPVCoefficientDecodeState` models the kernels' second argument
  (was `void*`): level +0x00, run +0x04, signBit +0x08,
  codeLengthBits +0x0C, scanIndexLimit +0x10, scanIndex +0x14,
  coefficients +0x1C, quantMatrix +0x20, quantScale +0x24,
  dcAccumulator +0x28, dcSizeTable +0x2C.

Dequant is `(quantScale * 2 * level * quantMatrix[scanIndex]) >> 4`,
negated by sign, times `dequantScaleTable[scanIndex]`, stored into
`coefficients[scanIndex]`.

Remaining: transcribe the 86 decode paths. Do NOT land a partial kernel —
an unhandled path silently emits garbage coefficients, which is worse
than the current stub because it looks like it works.


#### What each decode path actually computes (decoded — do not re-derive)

The cases are **inlined VLC constants**, not table selectors. Worked
example, `case 0xd0..0xd7`:

```
v333 = v17 + 1;                                   // advance scan cursor by 1
v334 = *v333;                                     // scanIndex = scanOrder[cursor]
v336 = (2 * quantScale * quantMatrix[v334]) >> 4; // level == 1 folded in
if (v336) v430 = (v336 - 1) | 1;                  // MPEG-1 oddification
coefficients[v334] = v430 * dequantScaleTable[v334];
v13 += 5;  v14 *= 32;                             // consume 5 bits
```

So each path is `(runAdvance, level, signBit, codeLengthBits)`. The level
is folded into the multiplier: `2*qs*qm` is level 1, `4*qs*qm` is level 2,
`8*qs*qm` is level 4 — i.e. `multiplier / 2 == level`.

**The trap that blocks naive auto-extraction:** only 14 of the 86 paths
carry their own `v13 += N`. The other 72 compute advance/level/sign and
then `goto LABEL_154` / `LABEL_303` / `LABEL_330` / … — shared tails that
do the bit consumption. Any extractor MUST resolve those tails; a
per-case regex silently yields 14 good rows and 72 wrong ones, and a
wrong VLC table is corrupt video that still looks like it decodes.

Recommended approach for the next window: build the 256-entry
`{runAdvance, level, sign, bits}` table by following each case through its
shared tail, emit it as a static table plus one shared emit helper (that
is the idiomatic 2007 shape and matches the binary's behavior), and
spot-check several entries against the `.asm` before trusting it.


#### The shared tails are resolvable — 41 labels, and they carry the bit counts

`goto` targets and their inbound-site counts are dominated by a few:
`LABEL_249` x79, `LABEL_46` x24, `LABEL_333` x14, `LABEL_481` x9,
`LABEL_480` x8; the remaining ~36 have 1-2 sites each.

Decoded so far:
- `LABEL_154`: `v13 += 4` then window `*= 16` — a 4-bit code tail.
- `LABEL_418`: `v13 += 8` — an 8-bit code tail.
- `LABEL_480` / `LABEL_481`: the bit-window refill pair, reached when
  `v13 >= 32`.
- `LABEL_249`: end-of-block / overflow exit, reached when the coefficient
  cursor passes `coefficientWriteCursor + 64`. It sets `v7[1224] = 1`.

That last one is a free cross-check: `1224 * 4 == 0x1320`, which is
exactly `MPVDecoderScanContext::recoverNeededFlag`. **The scan-context
model is independently confirmed correct.**

So completing the table is a bounded graph walk: for each of the 86
paths, follow its `goto` chain until the `v13 += N` that consumes the
code, and pair that with the `(runAdvance, level, sign)` the path already
computed. Every ingredient is now identified; what remains is doing the
walk carefully and spot-checking entries against the `.asm`.


#### *** The VLC table is stock MPEG-1 Table B-14 — do not reverse it ***

Extraction with goto-chain resolution recovered 61/86 paths, and the
recovered `(top-byte, run, level, code length)` tuples match
**ISO/IEC 11172-2 Table B-14** (DCT coefficients, table 0) exactly:

| top byte | recovered | B-14 code |
|---|---|---|
| 0x0C | run 0, level 4, 8 bits | `0000110s`, s=0 |
| 0x0B | run 9, level 1, sign set | `0000101s`, s=1 |
| 0x0F | run 8, level 1, sign set | `0000111s`, s=1 |
| 0x12-13 | run 7, level 1 | `000100s`, s=1 |
| 0x16-17 | run 6, level 1 | `000101s`, s=1 |
| 0x18-19 | run 1, level 2 | `000110s`, s=0 |
| 0x1E-1F | run 5, level 1 | `000111s`, s=1 |
| 0x34-37 | run 4, level 1 | `00110s`, s=1 |

**So the kernel should be written from the published standard, not
transcribed from the decompiler.** That is both more reliable and
verifiable: build the B-14 table, expand it to a 256-entry top-byte
dispatch, and check the generated entries against the case labels above.
The decompiler output then becomes the *oracle* rather than the source,
which removes the fabrication risk entirely.

Caveats on my extractor (fix before reusing it):
- the `level` regex falls back to 1 too eagerly — 0x28-0x2B came out
  level 1 but B-14 says `00101s` is run 0 level 3;
- `bits` is sometimes one too high because the goto-chase lands on a tail
  that has already consumed a bit (0x12-13 and 0x18-19 read 8, B-14 says
  7).
Both are extractor bugs, not binary surprises — the run/level/position
agreement is what matters and it is exact.

The surrounding pipeline is already decoded (see above): advance scan
cursor by `run + 1`, dequantize `(2*quantScale*level*quantMatrix[i])>>4`,
oddify `(v-1)|1`, negate on sign, scale by `dequantScaleTable[i]`, store
to `coefficients[i]`, consume the code bits, refill the window at
`LABEL_480/481`, and bail to `LABEL_249` (which sets `recoverNeededFlag`)
when the cursor passes 64 coefficients.


#### It is a MULTI-SYMBOL unrolled decoder — write a single-symbol B-14 one instead

Two findings that settle the implementation strategy:

1. `case 0x80..0xbf` (`10xxxxxx`) consumes 2 bits and emits **no
   coefficient**. That is **EOB** (`10` in B-14), which is why that
   64-label group has a 6-line body.
2. `case 0xe0..0xe7` (`111xxxxx`) is run 0 / level 1 at **3** bits — the
   `11s` code with s=1. But `0xd0..0xd7` reports 5 bits and `0xf0..0xf7`
   also 5 for the same run/level. Those longer counts are the decoder
   consuming **a second code in the same dispatch**: it peeks far enough
   ahead to retire two short symbols at once.

That multi-symbol unrolling is the real reason the function is 2400
lines, and it means a flat `top-byte -> (run, level, bits)` table is
*not* a faithful model — several entries legitimately carry two symbols.

**Therefore: implement a straightforward single-symbol MPEG-1 B-14
decoder.** It produces identical coefficients (which is the behavior that
must match) without reproducing the compiler's two-at-a-time unrolling,
and it is verifiable against the standard. Reserve the decompiled cases
as the oracle for spot-checks. Do NOT try to reproduce the unrolled
dispatch — that is optimization shape, not semantics, and CLAUDE.md
explicitly prefers the lifted form when behavior is preserved.

Confirmed single-symbol anchors from the extraction:
`10`=EOB, `11s`=run0/lvl1, `011s`=run1/lvl1, `0101s`=run2/lvl1,
`0100s`=run0/lvl2, `00110s`=run4/lvl1, `00111s`=run3/lvl1,
`00101s`=run0/lvl3, `000110s`=run1/lvl2, `000111s`=run5/lvl1,
`000101s`=run6/lvl1, `000100s`=run7/lvl1, `0000110s`=run0/lvl4,
`0000101s`=run9/lvl1, `0000111s`=run8/lvl1.

Those are `sub_AFAE50` (2425 clines) and `sub_AFD7C0` (2502 clines) —
hand-unrolled VLC macroblock decoders, **leaves with zero callees**. They
are the last thing between here and decoded frames, and they need a
dedicated window each. `mpvlib_InitHn` wires
`mpvhdec_ReadKernelIntraDefault` / `…PredictedDefault` — i.e.
`sub_AFAE50` / `sub_AFD7C0`, the two ~2500-line macroblock decoders —
and both are still `{ return nullptr; }` stubs in
`SofdecExternalStubs.cpp`. Those are the remaining work for a picture.

## DONE (kept for the layout facts): SFX_Create (0x00ACC860)

`mwPlyCreateSofdec` now reaches its **last** step and dies at
`SofdecAdxPlatformRuntime.cpp:2902` (`MWSFSFX_Create`), because
`SFX_Create` is an unresolved external and `/FORCE` aims it at garbage
(reported as `main!wxCYAN_PEN+0x0` — that is just the nearest symbol, not
a wx bug). Stack is fully symbolised: `MWSFSFX_Create` ← `mwPlyCreateSofdec`
← `CMovie::OpenMovie` ← `CMauiMovie::LoadFile` ← `cfunc_CMauiMovieInternalSetL`.

Six functions, all tiny, decompiles read and verified:

| addr | name | clines | in src |
|---|---|---|---|
| 0x00ACC860 | `SFX_Create` | 47 | no |
| 0x00ACC910 | `sfx_SearchFreeHn` | 15 | no |
| 0x00ACC9B0 | `sfx_IsEnoughHnWorkSize` | 4 | no |
| 0x00ACC940 | `sfx_InitHn` | 26 | no |
| 0x00ACD5F0 | `SFXZ_Create` | 16 | no |
| — | `sfxzmv_SearchFreeHn`, `sfxzmv_InitHn` | tiny | no |

`SFXLIB_Error`, `SFX_Destroy`, `SFXA_Create` are already present.

`sfx_IsEnoughHnWorkSize(a1,a2)` is literally
`a1 >= 8 * (a2 + a2/2) + 8285`.

**Fix `SfxLibWorkHead` while you are there.** Its +0x00 is modelled as
`dispatcher_tag`; it is actually `cur`, the live-handle count `SFX_Create`
increments. Asm-pinned (`_sfx_libwork` = 0x011F9B20):
`cur` +0x00, `last` +0x04, `objs` +0x18 **stride 0x94**, 32 slots
(0x18 + 32*0x94 = 0x1298). The head currently declared stops at 0x18 with
no object array, so `sfx_SearchFreeHn` has nothing to scan — the same
empty-pool shape as the ADXSTM bug below. `_sfxz_work` = 0x011F9180 with
`cur` +0x00, `zbufType` +0x04, `last` +0x08.

SFX handle fields from `sfx_InitHn` + `SFX_Create` (0x94 bytes, memset first):
`used`/tag +0x00 = 1, +0x04/+0x08/+0x0C = 0, +0x28 = 1, +0x2C = 0,
**`sfxz` +0x24**, **`sfxa` +0x30**, +0x34 = 0,
+0x38 = `(workAddress + 31) & ~0x1F`, then +0x3C/+0x40/+0x44 each +1024,
+0x50 = workAddress, +0x54 = configTag, +0x58 = -1, +0x64 = 0.


## DATA-STUB SWEEP — 28 initialized tables were being zeroed (2 fixed, 25 left)

`SofdecExternalStubs.cpp` declares ~125 `std::uint8_t NAME[4096] = {}` data
stubs. Sweeping them against the PE section map shows **28 are real
initialized `.rdata`/`.data`** that we are silently replacing with zeros;
the other 26 resolvable ones are genuine BSS where a zero stub is correct.

Recipe (worked twice, reuse it): grep the `.asm` exports for
`offset _NAME`, take the 4-byte immediate from the instruction encoding to
get the VA, then classify with the PE section table — `rva - sectionVA >=
rawSize` means BSS, otherwise it is initialized and the file offset is
`ptr + (rva - sectionVA)`.

**Fixed so far:** `mpvvlt_run_level_0a/0b/0c/1/2/4` (`7ba0ef3`), and the
three transfer-strategy descriptors `SFD_tr_vd_mpv` / `SFD_tr_sd_mps` /
`SFD_tr_sd_m2ts` (`9c4352d`, `e81c24a`) which were double-defined — a
populated recovered object *and* a zero stub at the same address, with the
create path resolving the stub.

**Still zeroed (highest non-zero density first):** `dolby_long`
(0x00D88928), `dolby_short` (0x00D8C928), `dolby_start` (0x00D8A928),
`sin_long` (0x00D8ED28), `sin_start` (0x00D90D28), `sin_short`
(0x00D92D28), `mpadcd_synthesis_window_table` (0x00F56EF8),
`spectra_huffman_codebook_parameters` (0x00D9515C), `book` (0x00F49A98),
`alloc_len_08sb/12sb/27sb/30sb`, `m2adec_num_spectra_per_sfb`(+`8`),
`mpadcd_group_type1_high`, `mpadcd_bits_type1_2bit/3bit/4bit_high/4bit_low`,
`mpadcd_quant_type1_3bit/4bit_high/4bit_low`. Note `dolby_stop` and
`sin_stop` are initialized but genuinely all-zero in the image.

These are the MPEG/Dolby **audio** decode tables — movie sound, not video
frames. Sizes must be read from each table's copy/loop bounds before
extracting, the way `mpvvlc_SetVlcRunLevel` gave the run/level sizes.

Only 54 of the 125 stub names resolved to addresses via the `offset _NAME`
scan; the remaining 71 are referenced some other way and still need
addresses before they can be classified.


#### Kernel entry + exit contract (exact — the switch is all that is left)

**Exit** (`LABEL_481`, the single return path):
```c
ctx->bitstreamState.bitWindowPrimary   = window;
ctx->bitstreamState.bitWindowSecondary = lookahead;
ctx->bitstreamState.bitCount           = bitCount;
ctx->bitstreamState.byteCursor         = cursor;
int result = state->scanIndex;
if (result != state->scanIndexLimit) result = -result;
state->scanIndex = result;
return result;                 // negative == block did not complete
```

**Entry** (DC coefficient, before the AC loop):
```c
window = ctx->bitWindowPrimary >> 16;                  // HIWORD
if (bitCount > 16) window |= bitWindowSecondary >> (48 - bitCount);
sizeCode = state->dcSizeTable[window >> 9];
len = sizeCode & 0xF; extra = sizeCode >> 4;
if (extra) {
  v = (ctx->bitMaskByWidth[len] & window) >> (16 - (extra + len));
  int half = 1 << (extra - 1);
  if (!(half & v)) v = 1 - 2*half + v;                  // sign extend
  extra = 8 * v; len += extra_len;
}
*state->dcAccumulator += extra;
*state->coefficients = *state->dcAccumulator * 0.125f;  // note: float store
state->scanIndexLimit = 0; state->scanIndex = 0;
cursor = ctx->coefficientWriteCursor;
if (ctx->pictureTypeGate != 4) { ...AC loop... }        // a1[122], ctx +0x1E8
```

**AC dispatch** is `switch (window >> 24)` — the top byte — with these
ranges (matches the extracted case groups exactly):
`0x80-0xFF` short codes, `0x04-0x07` = ESCAPE (`000001`, the group whose
lengths were 20/28), `0x00-0x03` the long codes that index
`acRunLevelVlcTables`, and the bands between them the 3-8 bit codes.

Complete B-14 code set at <=8 bits (all that need inlining; longer ones
come from the now-recovered tables):
`10`=EOB, `11s`=0/1, `011s`=1/1, `0100s`=0/2, `0101s`=2/1, `00101s`=0/3,
`00111s`=3/1, `00110s`=4/1, `000110s`=1/2, `000111s`=5/1, `000101s`=6/1,
`000100s`=7/1, `0000110s`=0/4, `0000100s`=2/2, `0000111s`=8/1,
`0000101s`=9/1, `000001`=ESCAPE.

Per emitted coefficient: advance cursor by `run + 1`, `i = *cursor`,
`state->scanIndex = i`,
`v = (2*quantScale*level*quantMatrix[i]) >> 4`, `if (v) v = (v-1)|1`,
negate when the sign bit is set, then
`state->coefficients[i] = v * ctx->dequantScaleTable[i]`, then consume the
code bits (refill when `bitCount >= 32`). Bail to the exit when the cursor
passes `coefficientWriteCursor + 64`, setting `ctx->recoverNeededFlag = 1`.


#### CORRECTION: the decode state is a VIEW onto the scan context at +0x68

`ProbeScanSlot` (MPVDecoder.cpp:1034) calls
`readKernel(context, &context->decodeBitstreamWord)`. So the kernel's
second argument is **not** a separate object — it is `ctx + 0x68`, and
`MPVCoefficientDecodeState` overlays the scan context from there:

| state | ctx | existing scan-context field |
|---|---|---|
| +0x00 level | +0x68 | `decodeBitstreamWord` |
| +0x04 run | +0x6C | `decodeHuffmanPrimary` |
| +0x08 signBit | +0x70 | `decodeHuffmanSecondary` |
| +0x0C codeLengthBits | +0x74 | `decodePhase` |
| +0x10 scanIndexLimit | +0x78 | `decodeFlags[0..3]` |
| +0x14 scanIndex | +0x7C | (in `decodeFlags` tail / reserved) |
| +0x1C coefficients | +0x84 | reserved_007E region |
| +0x20 quantMatrix | +0x88 | " |
| +0x24 quantScale | +0x8C | " |
| +0x28 dcAccumulator | +0x90 | " |
| +0x2C dcSizeTable | +0x94 | " |

Two consequences:
- The kernel writes its result into what the caller then reads as
  `decodeFlags[0]` — `ProbeScanSlot` returns the value and
  `MPVDecoder.cpp:7048` stores it straight into `context->decodeFlags[0]`.
  That is why the return is typed `std::uint8_t` in our header even though
  the binary returns a full int (the scan index, negated when the block
  did not complete): the caller truncates.
- Anyone implementing the kernel from the earlier struct note alone would
  have allocated a standalone state object and written to the wrong
  memory. The two models must be reconciled — either keep
  `MPVCoefficientDecodeState` purely as a cast-over view (never
  instantiated), or fold its fields into the scan context at +0x68 and
  drop the separate struct.

## Still ahead

- `sub_AFAE50` / `sub_AFD7C0`, the two ~2500-line macroblock decoders.
  `mpvlib_InitHn` wires them as `mpvhdec_ReadKernelIntraDefault` /
  `…PredictedDefault`, both `{ return nullptr; }` stubs in
  `SofdecExternalStubs.cpp`. Needed for actual frames, not for create.
- `SFX_Create` is still an unresolved external (`MWSFSFX_Create` calls it).
  Reached only after the MWSTM gate, so it is the blocker after next.
- `LSC_Create` and `MWSFPLY_SetFlowLimit` are stubs on this path too.
