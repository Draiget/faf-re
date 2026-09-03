---
name: project_cunitcommand_missing_base_and_undersized
description: FIXED 2026-09-01/02 (commit 36c93a06), real bug, worth keeping on fidelity grounds — CUnitCommand (backs every unit order) was missing its real CScriptObject base AND SCommandUnitSet was 0x1C bytes undersized. LIVE-TESTED AND FALSIFIED as the session's crash cause (peer, 2026-09-02): [LANEBAD]/[CLOBBER] still fire identically after this fix. Not the corruptor — see [[project_session_runs_full_skirmish_display_blocked]] for where the hunt goes next (a narrow 4-byte offset-0 overwrite of a fresh, never-touched block from an unrelated neighbour ~0x300 bytes earlier).
metadata:
  type: project
---

# CUnitCommand was undersized by exactly 0x50 bytes — likely the actual crash cause

Found by an audit agent sweeping all 65 `Moho::CScriptObject`-derived classes
in `dumps/rtti_dump_all.hpp` for the missing-base bug class (6th+ instance,
after CameraImpl/CAimManipulator/CAiAttackerImpl/CThrustManipulator/
CStorageManipulator/CMauiControl+widgets/CMauiCursor). This one is the
highest-impact instance found: `CUnitCommand` backs every unit order issued
in the game (move/attack/build/guard/patrol/reclaim/ferry/capture/...).

## What was wrong (two compounding bugs)

1. **Missing `CScriptObject` base.** `class CUnitCommand : public Broadcaster`
   — only the RTTI dump's SECONDARY base (mdisp=0x34) was kept; the PRIMARY
   base (`CScriptObject`, mdisp=0, 0x34 bytes) was dropped entirely, same
   shape as every other instance of this bug class.
2. **`SCommandUnitSet` (the `mUnitSet` member) was 0x1C bytes undersized.**
   Declared as a bare `gpg::core::FastVector<CScriptObject*> mVec` (0x0C
   bytes). Ground truth constructs a self-linked 2-pointer sentinel prefix
   (`next`/`previous`, both self-pointers — role beyond "sentinel" not
   identified) PLUS a `FastVectorN<CScriptObject*,4>` (4-element inline SBO,
   0x20 bytes) = 0x28 bytes total.

Combined: current (pre-fix) `sizeof(CUnitCommand)` computed to `0x128`
(verified via a `ShowValue<N>` compiler-error probe technique — write
`template<int> struct ShowValue; ShowValue<static_cast<int>(offsetof(...))> x;`
and read the value out of the resulting `error C2079` text; MSVC's
static_assert failures don't print the actual value, this does). Ground
truth is `0x178`. Shortfall: exactly `0x50` = `0x34` (CScriptObject) +
`0x1C` (SCommandUnitSet's shortfall).

## How this was verified (methodology worth reusing)

Every offset re-derived from RAW disassembly, not trusted from any existing
comment or assert:
- `FUN_006E81B0.asm` (the 3-arg constructor) read field-by-field: every
  `[ebp+XX]` write mapped in instruction order to the C decompile's
  corresponding `this->field = ...` statement. `mSim@0x40`,
  `mConstDat@0x44` (0x3C bytes), `mVarDat@0x80` (0x6C bytes), `unk1@0xEC`
  (4 bytes, never written in ctor), `mUnitSet@0xF0` (0x28 bytes: sentinel
  at 0xF0/0xF4, vector fields at 0xF8-0x108, inline buffer 0x108-0x118),
  `mFormationInstance@0x118`, `mTarget@0x11C` (0x20 bytes),
  `mInstanceSerial@0x13C`, 4 bools@0x140-0x143, `mCoordinatingOrders@0x144`
  (0x0C), `mIsDone@0x154`, `mFerryBeacon`(=`mUnit`)`@0x158` (0x08),
  `mArgs@0x160` (0x14), `mUnknownTailInt@0x174`. Total: `0x178`. Every
  single value matches what the ALREADY-PRESENT (but dead, see below)
  static_asserts and the ALREADY-PRESENT (but never connected to the
  header) `DestroyInternal()` teardown comments (`+0x158/+0x15C`,
  `+0x148..+0x154`, `+0x120`, `+0x118`, `+0x0F8`, `+0x0034`) independently
  claimed — strong convergent evidence, not a single fragile reading.
- Cross-checked against `FUN_006E7FF0.c` (the default ctor) — same
  `Moho::CScriptObject::CScriptObject(a1);` as its first line, same field
  layout.
- Cross-checked against the file's own pre-existing
  `BroadcasterSubobjectPtr(command)` helper, which hardcodes
  `command + 0x34` — independently confirms Broadcaster's real offset.
- `FastVectorN<CScriptObject*,4>`'s size (0x20) cross-checked against
  `FastVector.h`'s own `"FastVectorN<uint,4> must be 0x20"` assert for a
  same-size element type.

## Why this went undetected for so long — the asserts existed and were correct, just never compiled

```cpp
#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(sizeof(CUnitCommand) == 0x178, ...);
  static_assert(offsetof(CUnitCommand, mUnit) == 0x158, ...);
#endif
```

`MOHO_ABI_MSVC8_COMPAT` is **never defined anywhere in this tree** — checked
via `grep -r "define MOHO_ABI_MSVC8_COMPAT"` and `main.vcxproj`, zero hits.
Peer (`faf-main-2c`) corrected an oversimplification in an earlier version
of this note: the macro is not a harmless "would work if enabled" dead
check — `Platform.h` uses it to select `MOHO_EMPTY_BASES` between
`__declspec(empty_bases)` (current, always-active path) and a plain no-op,
and `CScriptObject.h`/`CAiSteeringImpl.h` use `!defined(...)` to ADD a
`MOHO_EBO_PADDING_FIELD` compensating for the layout difference — so it's a
genuine ABI switch, not just a assert-gate, and you cannot "just define it"
to test. The values behind the guard happen to be correct for the CURRENT
(macro-undefined) build too, but that was verified independently from raw
asm here, not inferred from the macro's semantics. Peer also confirmed
`SCommandUnitSet`'s own `sizeof==0x28` assert (added as part of this fix)
was NOT behind any dead guard — it's live from the moment it was added.

**Fixed**: made both `CUnitCommand` asserts unconditional (removed the
`#if` guard) now that the layout they describe is real and verified.
Peer independently confirmed the target value from a THIRD angle:
`FUN_006E91C0.c:9` (`MemberConstruct`) does `operator new(0x178u)` — the
shipped binary's own allocation site, not just a static_assert or a
disassembled ctor.

## RESULT: falsified (peer, 2026-09-02, same session)

Peer tested commit 36c93a06 live. Their own falsifiable prediction ("[LANEBAD]/
[CLOBBER] should stop firing entirely") did NOT hold:

    [CLOBBER] alloc block=5C803E00 next=00000178 expected=5C804100 freedBy=00000000 step=0
    [LANEBAD] kind=25 blockSize=768 head=00000178 count=13 cache=080E0D80 tid=56432
    ACCESS_VIOLATION traverseproto+0x120 reading 0005C05F   (same crash as before)

So CUnitCommand's undersizing was NOT the cause of the free-list corruption.
The fix is still correct and worth keeping (`operator new(0x178u)` at
`FUN_006E91C0.c:9` independently confirms the real size), but this file's
"leading theory" framing was wrong. Do not re-chase this angle without new
evidence.

The SAME test run sharpened the actual mechanism considerably, via a
redundant-copy probe (a copy of the lane's `next` value stored at a
DIFFERENT offset, +0x0C, that a naive poison-from-offset-4 probe would
never see): the victim block (`5C803E00`) has `freedBy=00000000`, meaning
it was stamped by the initial-carve REFILL path, never actually allocated
to or freed by anyone. It is a fresh, untouched block that just happens to
sit on the free lane, and its offset-0 word gets overwritten anyway — a
narrow (4-byte, bytes 4-0xF untouched, magic at +4 intact) out-of-bounds
WRITE, not a stale read and not a UAF. `5C803E00 - 0x300 = 5C803B00` is the
immediately-preceding same-size-class (kind=25, 768-byte) block, so the
leading theory going forward is an out-of-bounds write from THAT neighbour
(or from something further back overrunning further). Peer is arming DR0
directly on the (deterministic, hardcodeable) victim address next, which
should name the writer's stack directly. Check
[[project_session_runs_full_skirmish_display_blocked]] for the current
state before assuming this file's framing is still current.

## The corruption-mechanism theory this feeds (SUPERSEDED, kept for the trail)

Peer's live crash hunt (see [[project_session_runs_full_skirmish_display_blocked]])
had converged on a deterministic, always-identical corrupted word. Their
mechanism, pending the live test result: if `sizeof(CUnitCommand)` compiles
smaller than the real `0x178` the binary allocates for, `operator new`
under-allocates, but the recovered member-write code still targets the REAL
binary offsets (since that's how the fields were individually recovered) —
so construction of every `CUnitCommand` writes past its own too-small
allocation into whatever's adjacent, which — if that neighbor is sitting on
a free lane — clobbers exactly the free-list `next` pointer at its offset 0.
This would explain: determinism (same layout → same overflow distance every
run), timing (CUnitCommand churns hardest exactly when a skirmish starts),
and why the allocator itself kept coming back byte-faithful under audit
(it's not a UAF at all — it's an out-of-bounds WRITE from a live,
correctly-functioning-but-too-small object). **Falsifiable prediction**:
peer's `[LANEBAD]`/`[CLOBBER]` detectors should stop firing entirely after
this fix. Update this file once that result is in.

## The fix (commit 36c93a06, tucheck EXITCODE=0)

1. `class CUnitCommand : public CScriptObject, public Broadcaster`.
2. `SCommandUnitSet` gained a `TDatListItem<SCommandUnitSet, void> mListNode`
   prefix and `mVec`'s type changed from `FastVector<CScriptObject*>` to
   `FastVectorN<CScriptObject*, 4>`, plus its own
   `static_assert(sizeof(SCommandUnitSet) == 0x28, ...)`.
3. Both constructors gained `: CScriptObject()` as the first member-init
   (matching ground truth's literal first statement in both real ctors),
   and the now-redundant `mUnitSet.mVec = FastVector<CScriptObject*>{}`
   reset lines were removed (FastVectorN's own default ctor already does
   this correctly).
4. Verified `SCommandUnitSet::InsertUnitSorted`/`RemoveUnitSorted`'s
   existing `mVec.Reserve(...)` calls are SAFE post-fix: `FastVectorN`
   shadows (non-virtually) the base `Reserve()` with an SBO-aware version
   (`FastVector.h`'s own comment: "Reserve is overridden for FastVectorN to
   avoid Base::Reserve deleting inline storage"), and since `mVec`'s static
   type at these call sites is the full `FastVectorN<CScriptObject*,4>`
   (not passed through a type-erasing base-reference parameter), ordinary
   C++ name hiding resolves to the safe override. This is the SAME
   mechanism (static type preserved vs. erased through a parameter) that
   distinguishes this fix from the DecodeCells/WaveSystem bug class — see
   [[project_lua_gc_string_table_corruption]].
5. Orphaned `static CScriptObject* DestroyWithDeleteFlag(CScriptObject*,
   uint8_t)` (zero callers anywhere in `src/sdk`, confirmed via grep)
   replaced with a real `~CUnitCommand() override { DestroyInternal(); }`.
   Ground truth's own `dtr` (`FUN_006E8140.c`) is literally
   `~CUnitCommand(this); if (flag&1) operator delete(this); return this;`
   — exactly what the compiler now synthesizes automatically around a real
   virtual destructor, no manual wrapper needed.
6. Added the missing `GetClass()` override (vtable slot 0) — was declared
   `StaticGetClass()`/`GetPointerType()` (static) and `GetDerivedObjectRef()`
   (instance) but never the instance `GetClass()` CScriptObject's pure
   virtual requires. `GetDerivedObjectRef()` was left calling
   `StaticGetClass()` directly rather than switched to virtual `GetClass()`
   — produces an identical result since `GetClass()` just forwards to
   `StaticGetClass()`, not worth the extra diff for a leaf class.

## Left undone, deliberately

- `unk0`/`unk1`'s actual meaning not identified (both confirmed real,
  4-byte, correctly-positioned gaps via ground truth; neither is written
  in either constructor).
- `mUnitSet.mListNode`'s actual purpose beyond "self-linked sentinel" not
  identified — never observed linked to another `SCommandUnitSet` anywhere
  in recovered code.
- `RefreshBlipState()`'s `reinterpret_cast<ReconBlip*>(this)` (right next
  to the old `DestroyWithDeleteFlag`) not investigated — unrelated to this
  fix, flagged here only because it was seen in passing.
- `BroadcasterSubobjectPtr`'s hardcoded `+0x34u` could now be
  `static_cast<Broadcaster*>(command)` instead (the offset is numerically
  identical either way, this is a fidelity/idiom cleanup, not a
  correctness issue) — not changed this pass.
