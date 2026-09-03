---
name: project-icf-twin-pool
description: 729 unrecovered engine functions are byte-identical twins of bodies already recovered in src/sdk. A large slice of the remaining pool needs an address record, not a recovery.
metadata:
  type: project
---

Swept 2026-08-17. Grouping every indexed function by `function_sha256`
and keeping the groups that contain **both** a recovered token and an
unrecovered one gives **729 unrecovered engine functions** (below
0x00A00000, so CRT excluded) whose exact body is already written in
`src/sdk`.

They are not folded. `/OPT:ICF` would have left one address; IDA exports
each of these at its own address with identical bytes, so the binary
really does carry N copies. But there is only ever **one source function**
behind them, so the correct action is to record the extra address on the
recovered body's Doxygen block and mark the twin `skip` - never to write
the body again.

Worst offenders, by the file holding the canonical body:

    127  (canonical has no address annotation - see below)
     64  moho/resource/ResourceManager.cpp
     48  moho/mesh/MeshBatchKey.cpp
     38  legacy/containers/Vector.cpp
     36  moho/particles/ParticleRenderBuckets.cpp
     36  moho/sim/CPlatoon.cpp
     35  gpg/core/containers/FastVectorInsertLanes.cpp
     32  moho/containers/LegacyContainerFillLanes.cpp

## Why this matters for target selection

These are **invisible traps in every clean-candidate query**. A twin has
a real caller, a closure of 1, and no address in `src/sdk` - which is
exactly the profile every "recoverable now" ranking sorts to the top.
`FUN_005EDCE0` reached the top of a closure-1 sweep that way and was
already implemented as `LowerBoundUnitEntityById` (`c2622da`).

**Add a hash check to the candidate screen**: before writing anything,
look up the candidate's `function_sha256` and check whether any token
sharing it is already in the have-set. One query, and it kills the
biggest false-positive family in the pool.

## Most are template instantiations, and that is fine

Many pairs are different instantiations that compile identically - e.g.
`std::map<EntId, UserEntity>::find` and
`std::map<CmdId, CommandIssueHelper>::find` are both red-black finds on a
32-bit key. Distinct in source, identical in machine code. The recovered
map type covers them; see
[[feedback-no-duplicate-container-helpers]] and
[[feedback-canonical-template-helper-pattern]].

## A twin is only the same SOURCE function if its callers agree

Refined 2026-08-17 after nearly mis-attributing one. `FUN_0042A860`,
`FUN_007344F0` and `FUN_007608E0` share one hash (84 instrs). The first
is already recorded as `SortKerningPairsByPackedKey` in `CD3DFont.cpp`,
which lists nine addresses - so appending the other two looks like the
obvious move.

It would have been wrong. Their callers live in different subsystems
entirely (0x734xxx and 0x760xxx, versus the font code around 0x42xxxx).
These are three *different* sorts that compile to identical code, not one
function reached from three places.

**The test is caller locality.** `c2622da` was safe because both
addresses of the unit-id lower bound are called from the same class's
methods - `ContainsUnit` reaches one, `AddUnit`/`RemoveUnit` the other.
Same owner, so one source function. When the callers belong to unrelated
subsystems, the bodies are sibling instantiations and each needs its own
home.

Corollary: a twin whose callers are all unrecovered cannot be placed at
all yet. Writing it would produce an orphan in a guessed subsystem.
Leave those until a caller lands.

Do **not** mass-mark all 729 from a script. That is the process bug
`CLAUDE.md` names. Resolve them as they surface, citing the hash match
and the canonical token, the way `c2622da` does.

## The 127 with an unknown canonical

For 127 of them the canonical twin has no address annotation in
`src/sdk` either, so the sweep could not name a file. Those are the
[[reference-have-set-detection-gap]] cases and need the behaviour grep,
not an address search.

## Scripts

Both live in `decomp/recovery/` (gitignored, so they survive but are not
committed):

    icf_sweep.py      lists every unrecovered token whose body hash matches
                      a recovered one, grouped by the canonical body's file
    cand_no_icf.py    closure-1 candidate ranking WITH the twin filter applied

`cand_no_icf.py` is the one to run before picking a target. With the
filter on, the closure-1 engine pool at 45-320 instructions drops from
**138 to 51** - so roughly two thirds of what the old ranking offered was
already written.

## FUN_00519800 - LANDED 9a25fbf, and a layout trap worth knowing

Reached the top of the filtered list (73 instrs, 10 recovered callers)
and is NOT a twin. It is `RMeshBlueprintLOD::~RMeshBlueprintLOD()` - the
compiler-generated destructor, tearing the seven string lanes down in
reverse declaration order.

**I first read it as a +4 shift and nearly mis-attributed it.** The
string writes land at `a1 + {4, 32, 60, 88, 116, 144, 172}` while the
header declares the strings at `+0x00, 0x1C, ...`, which looks like
`this` points 4 bytes before a LOD. It does not:

    msvc8::string is 28 bytes with a 4-byte leading member (the
    allocator). Inside one string: _Bx at +4, _Mysize at +20,
    _Myres at +24.

So a string based at 0 writes its `_Buf[0]` at 4, and a string based at
168 writes at 172. Every offset lines up with the header, and the next
field after the last string is `168 + 28 = 196 = 0xC4` = `mLodCutoff`,
exactly where the header puts it.

**The check that settles this in one step: read the constructor.**
`FUN_005183D0` writes the same seven offsets plus `+196 = 1000.0f` and
`+200/201/202 = 0`, which matches `mLodCutoff{1000.0f}` and the three
flags. A ctor pins field offsets far more cleanly than a dtor, because
it writes the scalars too.

Generalisation: when decompiled offsets look uniformly shifted from a
modelled layout, suspect the *member's* internal layout before concluding
the object is shifted.
