---
name: project-createui-corruptor-ruled-out
description: OPEN — the non-deterministic corruptor that breaks CreateUI. Keeps the ruled-out list so hypotheses are not re-checked; eight eliminated with hard evidence as of 2026-09-01 (added D3D9 GAL size audit + TextReadArchive-reachability). Also closes the "is orders.lua the same file the engine loads" open question (yes, byte-identical).
metadata:
  type: project
---

# The CreateUI corruptor — still OPEN, with a growing ruled-out list

One non-deterministic fault, five faces across runs of the *same* binary:

1. `orders.lua(1106): access to nonexistent global variable "AttackMoveBehavior"`
   — a file-scope `local function` declared at line 517 resolving as a global.
   Local #52 of 74, `nactvar=73`.
2. `GetPrefetchTextures did not return a table of strings`
3. access violation in `traverseproto`, from `luaC_collectgarbage`
4. fault in `ForEachAllArmyUnit` reading `0x188`
5. a bare `gpg::Die` at WinMain.cpp:689

(1) and (2) break `CreateUI` -> `CreateMainWorldView`, so no world view exists.
That is what currently blocks the commander-spawn goal, downstream of the sim
work, which is done and verified (`synced=5371 newUnits=2280`, avatar
`uel0001`, `GetArmyAvatars count=1`).

## Ruled out — do not re-check without new evidence

Earlier sessions:

- Lua parser local resolution (as an algorithm bug)
- TString interning
- thin-class ctor overrun
- `~Entity` dangling entity

Added 2026-09-01, each against the disassembly:

- **Proto layout.** `traverseproto` (0x009154A0) walks `[esi+20h]` source,
  `[esi+28h]`/`[esi+8]` sizek/k at an 8-byte stride, `[esi+24h]`/`[esi+1Ch]`
  sizeupvalues/upvalues, `[esi+34h]`/`[esi+10h]` sizep/p, `[esi+38h]`
  sizelocvars. **Every offset matches ours.** Now asserted in
  `LuaRuntimeTypes.h` (commit `9614b7fb`), so drift here would be caught.
- **FuncState layout / `actvar`.** `singlevaraux` (0x0091AFB0) reads
  `[ebx+34h]` for `nactvar` and `lea edx,[ebx+eax*4+2B8h]` for `actvar` —
  4-byte elements at +0x2B8, exactly what `FuncStateRuntimeView` declares, so
  those asserts describe the binary rather than being self-consistent.
  `f->locvars` at +0x18 with a 12-byte `LocVar` stride confirmed in the same
  function. So symptom (1) is **not** a layout bug.
- **RuntimeView constructor overrun** (the `CD3DPrimBatcher` /
  `CameraImpl` bug class — a class whose fields live in a view, so `sizeof` is
  a vptr while the ctor writes to the view's full extent). Audited all 1950
  views against plain-`new` sites: 6 candidates, **all six safe**. Table and
  method in [[feedback_operator_new_size_audit_technique]].
- **Container `cpy` recovered as lane assignment** (the
  [[project_lua_gc_string_table_corruption]] bug class, which freed one live
  block per unit). Swept for surviving cross-container
  `a.start_ = b.start_` / `_Myfirst` aliasing: **none**; every hit is a
  same-object clear.

- **The entire parser local-variable chain.** Symptom (1) needs
  `singlevaraux`'s pointer compare of interned `TString`s to fail, so every
  step that could produce that was checked against ground truth and **all
  match exactly**:
  `new_localvar` (`actvar[nactvar+n] = luaI_registerlocalvar(...)`, limit
  `MAXVARS`=0xC8), `luaI_registerlocalvar` (0x0091ACF0 — grow at
  `nlocvars+1 > sizelocvars`, 12-byte stride, limit 2147483645 = `INT_MAX-2`,
  and our `MAX_INT` is `0x7FFFFFFD`), `adjustlocalvars` (0x0091AD80),
  `luaS_newlstr` (0x009248E0 — `step=(l>>5)+1`, `h ^= (h>>2)+32*h+str[l1-1]`,
  bucket `h & (size-1)`), and `luaS_resize` (0x009247C0 — rehashes by the
  *stored* hash `p[3]`, which our code does as `node->ts.hash`).
  `TString` is correctly recovered as **non-stock**: `reserved` at +0x08 (not
  +0x06), `hash` at +0x0C, `len` at +0x10, `str` at +0x14. Had `hash` been
  left at stock's +0x08, resize would have rehashed by *length* and scattered
  every bucket — that was the specific theory, and it is wrong.

## What the eliminations imply

Both previously-solved corruptors were *a constructor writing past its
allocation*, and that class now looks clean. The remaining candidate shapes are
therefore the ones not yet swept: wrong element size or count in an array
allocation (`new T[n]`, `operator new(n * sizeof(T))` — the size audit only
covered constant sizes), a wrong stride in a copy/fill loop, or a
use-after-free rather than an overrun.

### Array-allocation element-size sweep (2026-09-01, faf-main-f7) — also clean

Extended the size audit to the array shape specifically: every cast-typed
`(TypeName *)operator new(LITERAL * countExpr)` /
`(TypeName *)operator new(countExpr * LITERAL)` in the whole corpus (regex
sweep of all 67,123 `.c` exports, both multiply orders). 29 distinct typed
candidates. Most are trivially safe by construction (pointer arrays at
elemsize=4, `_WORD`/`double`/`POINT`/`tagACCEL`-class fixed-size Windows/
primitive types, container `_Node` types already covered by the generic
`RbTree.h`/`Vector.h` templates). The engine-specific ones that could
plausibly diverge:

- `LuaPlus::LuaObject` (elemsize=20, `FUN_004C7FD0.c`) — already asserted
  `sizeof(LuaObject) == 0x14` (`LuaObject.h:951`). Directly relevant given
  symptom (3)'s GC/traverseproto connection, but confirmed safe.
- `Moho::InfluenceGrid` (elemsize=140, `FUN_0071D5E0.c`) — already asserted
  `sizeof(InfluenceGrid) == 0x8C` (`CInfluenceMap.h:403`). Safe.
- `Moho::CollisionResult`, `Moho::DebugLine`, `struct_PoseBone`,
  `struct_SoundStruct1` — **not declared as real types anywhere in
  `src/sdk` at all** (checked directly, not just "no assert" — these
  IDA-placeholder-named structs have no recovered home yet). Latent only,
  same status as `WRenViewport`'s constructor: nothing in recovered source
  can currently mismatch a size that doesn't exist as recovered code.

No active array-allocation size mismatch found. This closes the "wrong
element size in a cast-typed array new" half of the unswept space; the
"wrong stride in a copy/fill loop" and "use-after-free" shapes remain
fully open (neither attempted this pass — the array-size sweep was chosen
first because it reused the existing size-audit tooling directly).

The parser sweep sharpens this further. Since every function that builds and
reads `actvar[]` / `locvars[]` is provably faithful, symptom (1) is **not a
recovery error in the parser** — something else is overwriting that memory
while the chunk is being compiled. `FuncState` is ~0x5D8 bytes and normally
lives on the C stack of `open_func`'s caller, and `actvar` occupies its last
0x320 bytes, so a **stack** overrun in a neighbouring frame is as plausible
here as a heap one.

The obvious form of that — a `FuncState` whose stack storage is smaller than
the 0x5D8 view written through it, i.e. the RuntimeView-overrun bug on the
stack rather than the heap — is **checked and clean**. Both storage sites
declare the full view: `luaY_parser` (0x0091DF80) has
`FuncStateRuntimeView funcstate;` and `body` (0x0091BC70) has
`FuncStateRuntimeView new_fs;`, each cast to `FuncState*` only when passed to
`open_func`. A stack overrun from a *neighbouring* frame is still open.

Note symptom (1)'s specificity: local #52 of 74 with `nactvar=73`. If the
parser state were being smashed at random this would not reproduce as the same
named local. Worth checking whether it is always `AttackMoveBehavior` and
always #52 before assuming randomness — that would point at something
deterministic about that chunk rather than at heap damage.

### ANSWERED (2026-09-01, faf-main-f7): it IS always the same, across every historical run — this materially changes the picture

Checked the exact question above against real data instead of a single
observation. `/c/ProgramData/FAForever/bin/*.sclog` holds logs from many past
launches this project (both sessions) has run; grepped all of them for the
literal string `AttackMoveBehavior` (not the generic "nonexistent global"
phrase, which is a routine warning firing for dozens of unrelated globals
across many files — `blueprints.lua`'s `ScriptedIconAssignments`,
`score.lua`'s `SessionIsReplay`, etc. — and is NOT itself evidence of this
bug). Four independent historical logs actually contain it: `mmdiag8`,
`mmdiag11`, `pf5`, `vardiag`. **All four are identical**: same line
(`orders.lua(1106)`), same identifier, same call stack
(`worldview.lua:202` in `CreateMainWorldView` <- `gamemain.lua:273` in
`CreateUI`), at essentially the same log line number in every file.

That is 100% reproducibility across four separate process launches, which is
strong evidence AGAINST "something non-deterministic corrupts memory that
happens to alias `actvar[52]`" and FOR "compiling `orders.lua` deterministically
fails at this exact point, every single time, regardless of heap/stack
layout differences between runs." The "5 faces / non-deterministic" framing
at the top of this note describes *which* symptom a run hits varying
run-to-run (a real observation from earlier sessions) — it does not mean
symptom (1) itself, once it fires, is random. Those are different claims,
and only the second one has hard multi-run evidence now.

**Also checked and clean:** `actvar[]`'s declared bound. `nactvar=73` is
nowhere near a limit that could explain an overflow —
`FuncStateRuntimeView::actvar[0xC8]` (`LuaParser.cpp:177`) correctly matches
`MAXVARS=0xC8=200` (`LuaParser.cpp:315`), so declaring 73 locals is nowhere
near the array's real bound. Ruled out as cleanly as the earlier
`FuncStateRuntimeView` storage-size check.

**Implication for where to look next:** if this is genuinely deterministic,
the stack/heap-corruption search (this whole file's focus so far) is
very likely the wrong tree for symptom (1) specifically — a real corruption
bug depends on allocator/stack state that plausibly differs between
independent launches, and this doesn't. The more promising angle is now:
what is different about `orders.lua`'s *content* up to local #52/line 1106
specifically (73 simultaneously-active top-level locals is a lot for one
chunk — worth checking whether any earlier local in the same chunk shares a
name, number, or hash bucket with `AttackMoveBehavior` in a way that could
make `singlevaraux`'s *comparison* correct-but-still-wrong, e.g. two
distinct `TString`s that should intern to the same pointer but don't, or
vice versa) — not another sweep for a stack-frame neighbour.

**Extended the mechanical chain audit further this same pass, still clean:**
- `newlstr` (`LuaObject.cpp:2848`, the actual string-table *insertion* body
  `luaS_newlstr` falls through to on a miss — not explicitly named in the
  earlier `luaS_newlstr`/`luaS_resize` check, so verified separately):
  allocates, sets `len`/`hash`/`marked`/`tt`/`reserved`, copies bytes +
  null terminator, computes the bucket with the *same* `hash & (size-1)`
  formula as the lookup, prepends to the chain, increments `nuse`, and
  conditionally calls `luaS_resize(state, size*2)` when `nuse > size`.
  Textbook-correct, no divergence found.
- `LS_import` (`LuaObject.cpp:12660`, the *C-level* Lua global named
  `import`) turned out to be an unrelated legacy fallback stub that just
  returns `false` — **not** what `orders.lua`'s callers actually use. The
  real `import()` is Lua-side content, `gamedata/lua/system/import.lua`.
  Read it directly: it **does** cache by module name in `__modules[name]`
  (checked at both the raw and lowercased name, lines 110-120) before ever
  calling `LoadModule`/`doscript`. This rules out a hypothesis this pass
  raised and dropped: that `orders.lua` might get *recompiled from scratch*
  on every one of its ~13 `import()` call sites across the UI, with one
  particular repeat compile failing where earlier ones succeeded. It
  compiles exactly once, by whichever call site runs first at process
  startup — consistent with, but not additional evidence beyond, the
  determinism already established above.

At this point the entire mechanical chain from `lua_load` down through
`singlevaraux`'s comparison has been read against ground truth by two
independent sessions and found faithful throughout: `luaY_parser`,
`open_func` (both storage sites), `chunk`/statement dispatch down to
`localfunc`/`localstat`, `new_localvar`, `luaI_registerlocalvar`,
`adjustlocalvars`, `singlevaraux`'s search loop, `luaS_newlstr`, `newlstr`,
`luaS_resize`, `TString`/`Proto`/`FuncState` layout, `actvar[]`'s bound.
**Nothing wrong has been found by reading code.** Further progress on
symptom (1) most likely needs runtime inspection (actual `actvar[]`/
`locvars[]` contents and the exact `import()` call sequence at the moment
of failure) rather than more static reading of already-audited functions —
gated on the D3D9 window. Not pursued further this pass.

### The locvars growth chain — verified faithful end to end (2026-09-01, faf-main-2c)

Following the determinism finding, the best remaining mechanical theory was
that `f->locvars` loses its contents when it grows, which would corrupt every
already-registered name and would only bite a chunk with enough top-level
locals to cross a growth threshold — orders.lua has 74, and doubling from
`MINSIZEARRAY`=4 puts the last growth at 64. That would explain "only this
file, every time" exactly.

**It is wrong. Every link is faithful to ground truth:**

| link | binary | verdict |
|---|---|---|
| `new_localvar` | inlined | `actvar[nactvar+n] = luaI_registerlocalvar(...)` ✓ |
| `luaI_registerlocalvar` | 0x0091ACF0 | grow test, 12-byte stride, re-reads `f->locvars` after growing ✓ |
| `luaM_growaux` | 0x0091A310 | MINSIZEARRAY=4, doubling, limit clamp, runerror condition ✓ |
| `luaM_realloc` | 0x0091A240 | delegates to `l_G->reallocFunc`, nblocks accounting ✓ |
| `luaHelper_ReallocFunction` | 0x00923F20 | `realloc(ptr, size)` ✓ |
| `realloc_0` | 0x00957B00 | identical logic incl. the `msize`/half-size shrink rule and binding to the engine's own `free` (Global.cpp:1311), not the CRT's ✓ |

**Also resolved: `nactvar=73` is CORRECT, not an off-by-one.** orders.lua
declares exactly 74 top-level locals before line 1106 and
`AttackMoveBehavior` is exactly the 52nd (verified by counting). The 74th is
`defaultOrdersTable` itself, declared at line 1104 — and Lua activates a local
only *after* its initializer is parsed, so while the parser is inside that
table constructor at line 1106 there are 73 active. The counts corroborate
each other rather than indicating a dropped local, and the scan range
(`nactvar-1`=72 down to 0) does cover index 51.

So the parser resolves over a correctly-sized, correctly-populated `actvar`,
using a faithful allocator, and still emits a global reference. **Everything
mechanical in the compile path is now eliminated.**

What that leaves, and where the next pass should start:

- Is the error even from the *parser*? "access to nonexistent global variable"
  is FA's strict-globals metatable firing at **runtime**, not a compile
  diagnostic. It only proves the emitted opcode was GETGLOBAL, at whatever
  point line 1106 executed. Worth confirming the chunk that ran is the chunk
  we think it is.
- Is the `orders.lua` the engine loads the same file as
  `gamedata/lua/ui/game/orders.lua` in this repo? If the engine reads a
  packaged copy from a `.scd`, the line numbers matching is a coincidence
  worth checking rather than an assumption.

  **ANSWERED (2026-09-01, faf-main-f7): yes, byte-identical.** `.nx2` archives
  are plain PK-ZIP (`C:\ProgramData\FAForever\gamedata\lua.nx2`, confirmed via
  `unzip -l`). Extracted `lua/ui/game/orders.lua` from it and diffed/md5sum'd
  against the repo's loose copy: identical (`b9100794b74c9f490bae6dd4a7601089`,
  both 67741 bytes). Also checked `effects.nx2`'s
  `lua/entities/UnitTeleport01/UnitTeleport01_proj.bp` (relevant to the
  separate projectile-lookup bug, see [[project_commander_spawn_script_class_resolution_gap]]):
  also present in both loose and archived form, same size. Whatever engine
  content the running binary actually mounts, it is the same content this
  repo's static reading has been analyzing — the "coincidence" concern above
  is refuted for both files checked. (Note the archive's own internal zip
  entry names are mixed-case, e.g. `Entities/UnitTeleport01/...` — a real fact
  worth knowing, but NOT a bug: `CVFSImpl.cpp`'s `EnumerateZipFiles`/
  `EnumerateZipChildren` explicitly `STR_ToLower`s every entry name before use,
  confirmed by reading `CVFSImpl.cpp:213-250`, so this doesn't survive into any
  registered path.)

  **Also checked, independently corroborating the projectile-lookup bug's
  fix (`89b4f267`/`44bf506b`) is correct**: retail's own reference log
  (`refmap.sclog`, a clean `ForgedAlliance.exe` run on the same map) has
  **zero** `CreateProjectile`/`UnitTeleport` hits at all — i.e. this really is
  a divergence our recovered binary hit and retail didn't, not a shared
  original-engine quirk both binaries have. Re-derived the whole
  registration-vs-lookup slash-mismatch chain independently from three
  ground-truth `.c` files (`FUN_00531D80`/`FUN_00532380` for
  unit/projectile registration, `FUN_0068A110` for the lookup call site,
  `FUN_00458450` for `STR_CanonizeFilename`'s forward-to-backslash
  conversion) before discovering the fix was already landed — every function
  on both sides is independently ground-truth-faithful, so the mismatch is a
  genuine **latent original-engine defect** (per the already-landed commit's
  own analysis), not a recovery bug on either side. No new action needed;
  this only adds a second, independent confirmation of already-verified work.

Runtime verification is gated on the D3D9 window —
see [[project_d3d9_zero_adapters_is_host_not_code]].

### Two more static threads closed, both clean (2026-09-01, faf-main-f7)

**D3D9 GAL operator-new size audit, the last unchecked bucket from the
original size-audit sweep**: extended `sizeprobe*.cpp` (C2440 array-size
compile-error trick) to all 12 `gpg::gal::*D3D9` classes with real headers
under `gpg/gal/backends/d3d9/*.hpp` (the earlier attempt failed on incomplete
types from wrong includes — fixed by including the real per-class headers).
11/12 match the binary's `operator new` immediate exactly (`CubeRenderTargetD3D9`
=44, `DepthStencilTargetD3D9`=28, `EffectD3D9`=116, `EffectTechniqueD3D9`=48,
`EffectVariableD3D9`=44, `IndexBufferD3D9`=32, `PipelineStateD3D9`=12,
`RenderTargetD3D9`=28, `TextureD3D9`=100, `VertexBufferD3D9`=36,
`VertexFormatD3D9`=28). The 12th, `gpg::gal::DeviceD3D9` itself, measured 40
vs. an expected 132 — looked like a live instance of the thin-class bug class
at first, but is a FALSE POSITIVE: the real allocation site
(`D3D9Interfaces.cpp:6249`, `new DeviceD3D9BackendObject()`) constructs a
properly-typed DERIVED class, not the base `DeviceD3D9` my probe measured —
`DeviceD3D9BackendObject` already carries its own
`static_assert(sizeof(DeviceD3D9BackendObject) == 0x84, ...)`
(`D3D9Interfaces.cpp:429`), exactly matching the binary. Clean, 12/12. Closes
the D3D backend half of [[feedback_operator_new_size_audit_technique]]'s
unchecked bucket for good.

**`serialize.fromstring`/`tostring` (`CreateTextReadArchive`/
`CreateTextWriteArchive`, the `84b7a604`/`f1989beb` TextReadArchive-overflow
fix pair) reachability — now definitively closed, not just "weakened"**: grepped
ALL of `src/sdk` for `CreateTextReadArchive`/`CreateTextWriteArchive` call
sites. Zero, outside `LuaSerializeFromString`/`LuaSerializeToString`
themselves (`ArchiveSerialization.cpp`). Combined with the earlier-confirmed
zero `gamedata/lua/**` callers of `serialize.fromstring`/`tostring`, this
whole subsystem is **provably unreachable** in any normal run — no hidden
C++-side caller (SimCallback marshalling, network sync) exists either.
`84b7a604`/`f1989beb` remain correct, real fixes (asm-cited 12-byte overflow;
confirmed-vanished link error) but are now definitively NOT the corruptor —
stop treating them as a live candidate for symptoms (1)-(4).

Also found (not chased further this pass — a new, separate lead for whoever
picks up the fake-vtable sweep): see
[[feedback_thin_fake_composition_bug_class]] for a THIRD confirmed instance
of the "standalone class faking a base via a vtable-tag byte" pattern found
independently this same day (`CAiAttackerImpl`, commit `c68161f4`, by
`faf-main-2c`) — a background sweep found 2 more (`CThrustManipulator`/
`CStorageManipulator`, fixed `c23ad589`) and is checking a further 12
candidates as of this note.

### Reframe worth testing once GetPrefetchTextures also clears (2026-09-01, faf-main-f7, hypothesis only)

The actual root cause of the commander-spawn blocker turned out to be
completely unrelated to everything in this file: `InitializeArmies` was
dying on a genuinely MISSING `moho.IEffect` Lua export (`f36336a0`, see
[[project_moho_class_exports_10_missing]]), not memory corruption. Now that
army init completes, it's worth re-testing whether symptoms (3)
`traverseproto`/GC-fault and (4) `ForEachAllArmyUnit` from the "five
symptoms" list above still reproduce AT ALL, or whether they were
downstream artifacts of the sim running in a half-initialized state
(armies that never finished setup, entity/army bookkeeping left
inconsistent) rather than independent memory-safety bugs.

**Superseded by stronger evidence (2026-09-01, later same day):** this
"downstream of incomplete init" theory was a plausible guess written before
`faf-main-2c`'s allocator instrumentation caught the corruptor in the act.
Their live probe found a genuine corrupt free-lane in the engine's own
allocator (`PopLaneNode` reading an unreadable `node->next`, from
`luaD_growstack`/`luaD_precall`/`luaV_execute` — i.e. firing during ordinary
Lua execution, not a rare edge case), matching the exact signature of the
already-solved [[project_lua_gc_string_table_corruption]] `UnitAttributes`
bug (a lane-assignment where a real deep-copy/`cpy` call was needed,
leaving a container aliasing a buffer it doesn't own, then freeing it out
from under the real owner). Given a REAL, reproducing, evidenced heap
corruptor now exists, prefer "one wild write/free explains 1/2/3/4, not
downstream-of-incomplete-init" as the leading theory — it's better
evidenced, not just more parsimonious. Both theories make the same
prediction for (3)/(4) (they should stop once the root cause is fixed), so
the test is unchanged: run past the current blocker and check recurrence.
Symptom (1) (`AttackMoveBehavior`/`orders.lua`) fits this newer theory
comfortably too — this file's own earlier section already revised toward
"non-deterministic heap corruption from a wild write" for symptom (1)
specifically, before the allocator instrumentation existed to name a
concrete culprit shape. Keep it open until a run confirms zero recurrence,
but there's no longer a reason to treat it as a separate mechanism from
(3)/(4).

### `luaD_growstack`/`correctstack`/`luaD_precall` stack-rebase audit — clean, do not re-check (2026-09-01, faf-main-f7)

Given the live crash trace is `PopLaneNode <- ... <- luaD_growstack <-
luaD_precall <- luaV_execute`, checked whether the Lua VM's OWN stack-growth
machinery could be the corruptor — a classic embedded-Lua bug class is a
raw `StkId`/stack pointer cached across a reentrant call that can move the
stack, then used stale after the move. All of it is faithful, checked
directly against ground truth `.c` (not by "matches stock" assumption —
this fork already has confirmed deliberate deviations from stock Lua 5.0
elsewhere, e.g. `localfunc` using `freereg` not `nactvar`, so "differs from
stock" alone proves nothing):

- `correctstack` (`LuaObject.cpp:5640`) rebases `state->top`, every open
  upvalue's `v`, and every live `CallInfo`'s `base`/`top` — the complete set
  stock Lua 5.0 also rebases, nothing missing.
- `luaD_growstack`/`luaD_reallocstack` (`:5665`/`:14822`) both call
  `correctstack` immediately after the `luaM_realloc`, correct order.
- `luaD_reallocCI` (`:14851`) only touches the CallInfo array's own
  allocation and rebases `state->ci` via index math — correctly separate
  concern from the value-stack rebase above.
- `luaD_precall` (`:16673`, ground truth `FUN_009142A0.c` read directly)
  computes `funcOffset` from `func` ONCE, **before** the
  `func = tryFuncTM(func, state)` reassignment (ground truth line 11 vs. 13
  — same order, confirmed byte-for-byte). This LOOKS like a bug at first
  glance (a stale offset used after `func` is reassigned to a different
  slot) but is not: `tryFuncTM` (`:16599`) writes its `__call` handler back
  into `func`'s ORIGINAL slot (`t(x)` becomes `mt.__call(t, x)` by shifting
  everything ABOVE `func` up one slot and overwriting `func`'s own slot with
  the handler — `t` becomes the shifted-up first argument), so the "function
  slot" offset is invariant across the whole `__call` redirection even
  though `tryFuncTM` can itself call `luaD_growstack` internally
  (`:16616`) and reallocate the stack. Both the original binary and our
  recovery reuse the same pre-computed offset because it stays valid by
  construction, not by accident.
- `LuaStackObject` (`LuaObject.h:953`) stores `(state, stackIndex)` — an
  index, re-resolved at use time — not a raw pointer, so it's inherently
  immune to this bug class. `LuaObject` stores its value by copy
  (GC-anchored via the intrusive used-object list, already verified
  elsewhere this session), also immune.

**Net: the Lua VM's own stack-growth and call-setup path is fully faithful
and provably correct, including the one spot that looks suspicious on a
skim.** This doesn't find the corruptor, but it closes off a whole
plausible bug FAMILY (stale stack pointers across reallocation) as a
source — the remaining search space is engine-side C++ object ownership
(what the wild-free sweep and the live allocator instrumentation are both
independently chasing), not Lua VM internals. Do not re-audit
`correctstack`/`luaD_growstack`/`luaD_reallocstack`/`luaD_reallocCI`/
`luaD_precall`/`tryFuncTM` for this bug class without new evidence
specifically implicating one of them.

### FOUND AND FIXED (2026-09-01, faf-main-f7): `CDecoder::DecodeCells` freed inline SBO storage as heap — commit `00d79258`

The wild-free sweep (background agent, prompted with the `UnitAttributes`
precedent as its search template) found a real, ground-truth-verified bug:
`CDecoder::DecodeCells` (`CDecoder.cpp:799`) did an **unconditional**
`delete[] cells.start_` on a `gpg::core::FastVectorN<SOCellPos, 2>&`
parameter that had been silently narrowed to the base `FastVector<SOCellPos>&`
type (dropping the derived class's `originalVec_`/inline-buffer awareness).
Both real call sites (`DecodeCommandData`'s freshly-constructed
`commandData.mCells`, `DecodeSetCommandCells`'s freshly-constructed local)
**always** enter this function with `cells.start_` still pointing at its own
inline SBO buffer — never heap memory — so this fired on **every decoded
issue-command** (any player order carrying a cell-position list, e.g. an
attack-move waypoint list), freeing a stack/embedded address through
`operator delete[]`, which this codebase routes through the engine's own
small-object allocator (`Global.cpp:1609`) — the same allocator Lua's
allocations use.

Verified against ground truth (`FUN_006E55C0.c` -> `sub_5532F0` ->
`sub_553A80`, plus `FUN_006E4B00.c`'s local-variable layout for the OTHER
caller): the real binary never unconditionally frees here — it resizes via
a container helper that only reallocates past inline capacity, guarded by
`start_ == originalVec_`, matching `FastVector.h`'s own already-correct
`resize()`/`GrowToCapacity()`/`ResetInline_()`. Also found and fixed a
second bug the same investigation surfaced: `DecodeSetCommandCells`'s local
`cells` was mismodeled as the base (always-empty, non-SBO) `FastVector<T>`
instead of the `FastVectorN<T,2>` ground truth actually uses there — fixed
alongside, confirmed via `FUN_006E4B00.c`'s decompiled local-variable shape
(an inline buffer plus an `originalVec_`-equivalent field, with the
caller's own `start_ != originalVec_` guard around its own
`operator delete[]` call, applied AFTER `DecodeCells` returns rather than
inside it).

**Relationship to `faf-main-2c`'s live allocator instrumentation (same day,
concurrent)**: their poison+freer-stamp probe found **zero** double-free/UAF
hits on TRACKED allocator blocks, and concluded "the evidence no longer
supports a wild free" for the specific `PopLaneNode` crash they were
chasing — their OWN next fault (a `VisionDB::TryAdd` null-pointer read, a
completely different and unrelated bug, fixed `0d4a51e1`) came from a live
per-frame render path, not the allocator. **This does not contradict the
`DecodeCells` finding** — a `delete[]` on a stack/embedded address is UB on
a pointer the allocator never tracked as one of its own blocks in the first
place, so a probe that only watches already-tracked blocks (double-free,
UAF-after-free) would not flag it; it would only show up as *whatever
memory happens to sit near that stack address getting corrupted*, which is
a different and harder-to-instrument shape than a tracked-block violation.
Both fixes are real, independently justified by direct ground-truth
evidence, and should both stay landed. Whether `DecodeCells` was
*specifically* the corruptor behind the `PopLaneNode` crash is still
unconfirmed either way — that needs a fresh live run with this fix in
place, which is the natural next step once the host/build situation allows
it.
