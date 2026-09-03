---
name: reference-landable-now-query
description: "Query for blocked tokens that are genuinely landable: every dependency terminal AND present in src/sdk, plus a live caller. Returns ~30; three were recovered from it in batch 35"
metadata:
  node_type: memory
  type: reference
---

Built 2026-08-21 (batch 35) after several batches of picking targets that
turned out to be lease-blocked or caller-blocked. This is the filter that
actually predicts a landing.

## The query

1. Index every `0x`+8hex and every `FUN_`+8hex across `src/sdk/**/*.{cpp,h}`
   (see [[project-citation-audit-2026-08-21]] for the gotchas -- write grep to
   a file, `subprocess` capture truncates).
2. Take `status == blocked` tokens with a non-empty `depends_on`.
3. Keep only those where **every** dependency is terminal
   (`recovered`/`external_dependency`/`skip`) **AND its address is actually
   present in src/sdk**. The second half is the point: a DB row saying
   "recovered" is not proof -- 11% of them are uncited.
4. Then intersect with: at least one `owner=` in the token's `.xrefs.txt` is
   also present in src/sdk (a live caller).

Step 3 alone gives 113. Step 4 narrows it to **30**.

## Known false positive in step 4

"Address present in src/sdk" counts **doc-comment mentions**, so an elided
caller passes. The fix is the doc-block screen added in batch 39 (below):
require the caller to appear in an `Address: 0x...` index, not anywhere in
source.

*Historic example, now RESOLVED:* `FUN_00865880` and `FUN_00870310` both
listed `0x008704B0` (`CUIWorldView::HandleEvent`) as a live caller while
HandleEvent existed only in comments. A worktree agent landed HandleEvent for
real on 2026-08-21 (merge `f916c1ad`, 119-line body in
`moho/ui/UiRuntimeTypes.cpp`) together with both callees, so **stop skipping
those two** -- they are cited and done. Always open the caller and
confirm it is a real body before committing
([[project-elided-caller-false-positives]], and the CreateMeshes case in
[[project-stub-inventory-2026-08-21]]).

## What it found (batch 35, all three landed)

The small end of the list is dominated by container-template emissions whose
canonical home is `msvc8::vector<T>` -- recognisable as a strided loop with a
single callee. A quick shape filter: single distinct `call` target + an
`add reg, <stride>h` + a `cmp`/`jnz` pair.

| token | is | committed |
|---|---|---|
| `FUN_00519BA0` | `destroy_range` for 0xCC `RMeshBlueprintLOD` | 53bf86db |
| `FUN_00680BD0` | `insert`'s gap `std::fill` for 0xD8 `SEntityVariableUpdateEntry` | 53bf86db |
| `FUN_005EC880` | `copy_backward` for 0x20 `SAiReservedTransportBone` | c5ddf9e9 |

**All three were blocked on stale reasons.** `FUN_00680BD0` was `owner_layout`
"element type unmodelled" -- it is modelled (`SEntityVariableUpdateEntry`,
SimDriver.h:152). `FUN_005EC880` was `owner_layout` -- both the element and its
`operator=` were already recovered. `FUN_00519BA0` was one of the 139 I reverted
as falsely-recovered, and is now genuinely recovered. Expect more of the same:
**check the stated blocker against current reality before believing it.**

The remaining 27 are in `<scratchpad>/landable.txt`; regenerate rather than
trusting that file, since the tree moves.

## Telling the two containers apart from the asm (batch 36)

Element size alone is not enough to pick the right canonical home. Use the
offsets of the lane test:

| shape in asm | container | member |
|---|---|---|
| `[obj+0x04]` vs `[obj+0x08]` (last vs capacity) | `gpg::core::FastVector` `{start_, end_, capacity_}` | `push_back` / `PushBack` |
| `[obj+0x08]` vs `[obj+0x0C]` | `msvc8::vector` `{proxy, first, last, end}` | `push_back` |
| `[obj+0x04]` read as begin, `[obj+0x08]` as end | `msvc8::vector` first/last | iteration/size |

`FUN_00515890` is a 12-byte 3-float element, so it looked exactly like the
`msvc8::vector<Wm3::Vector3f>::push_back` already cited on that container --
but its test is `[eax+4]` vs `[eax+8]`, so it is a **fastvector**, and the
caller (`moho::ClipEdgeAgainstPlane`, CTesselator.cpp:377) does take a
`FastVectorN<Wm3::Vector3f, 6>&`. Citing it on msvc8::vector would have been
wrong.

Cross-check the caller's parameter type whenever both containers use the same
element.

## Batch 36 additions

| token | is | committed |
|---|---|---|
| `FUN_00533FD0` | ctor EH-unwind-funclet partial cleanup -> cited on `~EntityCategoryLookupTableRuntimeView` | 53dc75d7 |
| `FUN_00515890` | `fastvector_n<Wm3::Vector3f,6>::push_back` | 7893cc20 |

`FUN_00533FD0` is worth noting as a shape: **one xref, `type=19`, from an
address in the EH region (0x00BAxxxx / 0x00B8xxxx)** means an unwind funclet,
not a called function. RULE ONE says those map to no source line -- cite them
on the destructor MSVC generated them from. Its partial nature (20 instrs vs
the full destructor's 32) is because the throw happens mid-construction, so
only the already-built members get torn down.

## Batch 37 additions

| token | is | committed |
|---|---|---|
| `FUN_00547F20` | `msvc8::vector<ResourceDeposit>::resize(n,_Ty)` + an 11-address lane-family collapse | dcfb51f2 |
| `FUN_00867AC0` | VC8 `_Tree::erase(const key_type&)` for the weak-entity set | a3f8c8cc |
| `FUN_009329A0` | implicit copy ctor of a map value_type; DB row was stale, source was already right | a3f8c8cc |

**Check whether the function is already recovered under another address before
writing anything.** `FUN_00867AC0` looked like fresh work -- equal_range,
count, erase-range -- and `EraseSelectionKeyRangeAndCount` (0x008B2E70) was
already sitting in the same file with exactly that body. Three of this
batch's addresses were second emissions of already-recovered functions. The
cheap test: grep the owning file for the shape (a distinctive callee name, or
the two or three helpers the asm calls) before deriving a new body.

**Decide where a member lives from what the callers actually pass, not from
where its siblings sit.** `EraseRange` was on `SSelectionSetUserEntity`, but
`Erase` is reached with `army->mFactories` / `army->mEngineers`, which are
bare 12-byte `WeakEntitySetUserEntity`s embedded in `UserArmy`. Downcasting
to the derived type to reach the lane would have been UB at five call sites.
Both bodies read only `mHead` and write only `mSize`, so moving them to the
base was behaviour-preserving *and* the only correct option.

**`container_lane_guard.py` had a false positive worth knowing about.** It
fired on moving the `EraseRange` *declaration* between a class and its base,
reporting it as "a per-type container operation". A member of a type that
models a binary object is legitimate recovered source; the shape the guard
exists to stop is the free `VerbNoun` helper at namespace scope. It now
exempts out-of-line member definitions (`Type::Name(`) and declarations inside
a `struct`/`class` body, and `namespace { }` is deliberately *not* a class
body so the original abuse is still caught. Regression-checked against
`4e8030e0`: all eight lanes still blocked.

## The per-type lane family, as a recurring shape

`ResourceDepositVectorReflection.cpp` held nine hand-written lanes carrying
eleven addresses, eight of them `[[maybe_unused]]`. What made them obvious:

  - six were *byte-identical forwarders* that only permuted argument order
    (VC8's `copy` -> `_Copy_opt` -> `_Copy_impl` chain, one out-of-line body
    per level), and had **zero xrefs in the binary**;
  - the "copy loop" carried an `if (destination != nullptr)` test *inside*
    the loop -- a compiler artifact, never something a person writes;
  - the capacity helper open-coded `0x0CCCCCCC`, which is `0xFFFFFFFF / 0x14`
    -- an inlined `max_size()`.

Same collapse as [[project-runtime-view-sweep-in-progress]]: move each address
to an `Address:` line on the canonical `msvc8::vector<T>` member and delete the
lane. `uninit_copy_n` now carries 21 addresses across element types, including
"register-shape adapter" and "source-first adapter" entries -- that is the
expected shape, not duplication.

**One citation was flatly wrong and the sizes caught it.** `0x006E3D30` was
listed as a fourth adapter sharing a body with `0x00549A50`. It calls
`0x006E3EA0`, not `0x00549BC0`, and that callee copies at stride 4 rather than
0x14 -- same template, different element type. Reverted to blocked. This is
the third time the resolve-the-call-targets check has overturned a duplicate
claim ([[feedback-verify-duplicate-claims-bytewise]]).

## Batch 39: two filters and a much better target-selection move

**Screen callers by doc-block, not by address presence.** The known false
positive (prose mentions counting as a live caller) is now cheap to kill: build
a second index of only `Address: 0x...` doc-block citations and require the
caller to appear in *that*. It cut the queue from 22 to 15 and removed four
candidates whose "caller" was a comment -- including a three-function cluster
hanging off `Sim::Sync` (0x00560A00), which is named only in a comment in
Sim.h.

**Audit citations against binary instruction counts.** For every cited address
in a file, compare the binary's instruction count against the recovered body.
A **one-instruction `jmp` carrying a multi-line body** is a mis-citation. This
found two in `CUnitRefuel.cpp`: `CUnitRefuelDeserializeThunkSecondary` claimed
0x0063A290 (jumps to an animation manipulator) and 0x0089BEA0 (jumps to a sort
swap) alongside its one genuine thunk. Both mis-cited thunks also had zero
xrefs. Committed 8d882582. Worth running over other multi-address citations.

**Walk UP from a blocked leaf, not down from a queue entry.** The highest-yield
move this batch: `FUN_0089C070` was blocked with no recovered caller, so I
followed its callers upward instead of dropping it. Four hops reached
`CWldSession::GenerateBuildTemplates` (0x00896AA0), already recovered -- and
the whole closure below it was **twelve uncited functions, 1121 instructions**,
one complete `std::sort` instantiation. Committed d2396e1f.

Recipe: from a blocked token, BFS the `owner=` sets upward until a token's
address appears in `src/sdk`; then BFS *down* from that root over `call`
targets to get the full closure. Cite the whole closure at once.

### Identifying a VC8 std::sort instantiation from the asm

Distinctive constants, all confirmed on this instantiation:

| tell | member |
|---|---|
| calls **itself** twice + one partition + three fallbacks | `sort_impl` (the driver) |
| `cmp eax, 28h` (40 < count, ninther vs median-of-3) | `median3` |
| one median call + N swap calls | `unguarded_partition` |
| `lea eax,[esi-1]; cdq; sub eax,edx; sar edi,1` = `(hole-1)/2` | the `_Push_heap` settle-up inside `adjust_heap` |
| element-size divide magic + a one-element stack temp | `insertion_sort` body |

VC8 emits `_Push_heap`, `_Pop_heap` and `_Pop_heap_hole` out-of-line where
`Sort.h` inlines them; cite those on the member that absorbs them and say so.

Note `msvc8::sort`, never `std::sort`, in recovered call sites -- only the
former carries the 32-element cutoff, the 40-element ninther and the
three-quarters recursion budget this binary uses.

## The closure-ranking query (batch 40-42) -- now the primary target picker

Ranks blocked work by how much a single landing unlocks. For each blocked,
uncited token: BFS `owner=` upward (depth <= 5) until a token whose address
appears in the `Address:` doc index; group tokens by that root; then BFS `call`
targets downward from the group to get the uncited closure. Sort by size.

It is strictly better than the flat landable list because it finds work whose
*root* is recovered even when the individual token looks caller-blocked.
Current top of the ranking:

| root | closure | what it is |
|---|---|---|
| 0x00826140 | 25 fns / 2308 instr | UICommandGraph draw nodes -- another agent's |
| 0x00529700 | 18 fns / 2352 instr | blocked on a type migration, see [[project-rrulegamerules-blueprint-map-migration]] |
| 0x00576690 | 10 fns / 635 instr | FORMATION_RunScript's slot fastvector -- 4 landed in 8275d844 |
| 0x007B22B0 | 9 fns / 805 instr | untried |
| 0x007DF530 | 9 fns / 751 instr | untried |
| 0x0084DA80 | 8 fns / 828 instr | untried |

Watch for `0x0128E638`-style roots: those are data addresses (vtables), not
functions -- skip them.

## Pin container emissions by call structure, not by shape

The four bodies landed in 8275d844 were assigned from the call graph, which is
unambiguous where shape is not:

```
FORMATION_RunScript -> copy ctor -> ResetFrom -> grow
                    -> push_back --------------> grow
```

Then each assignment was cross-checked against an independent constant:
capacity seated at `this+0x10+0x460` = twenty 0x38 slots for the copy ctor;
`92492493h` + `sar 5` = divide by 56 = that same 0x38 stride for the grow.

The six remaining bodies in that closure were **left blocked on purpose** --
three are near-identical 36-38 instruction range loops (copy / uninit-copy /
copy_backward) and shape alone cannot separate them. Assigning those by
guesswork is how wrong citations get in; see the two found in `CUnitRefuel.cpp`
the same day.

## "Alias of FUN_xxxx" is a citation bug that hides finished work

Found 2026-08-21 (batch 43). `DeserializeStringArmyStatItemMap` in
`SConditionTriggerReflection.cpp` was fully recovered and correct, but its doc
block opened `Alias of FUN_00710460 (serializer load helper lane)` instead of
`Address: 0x00710460 (...)`. Every citation audit and every landable query
reads the `Address:` form, so the token sat blocked while the work was already
done.

**Swept it the same day -- the vein is benign, do not spend a batch on it.**
`rg -n 'Alias of FUN_[0-9A-Fa-f]{8}' src/sdk` returns 329 lines / 202 distinct
tokens, but **193 are already `recovered`, 4 `skip`, 1 external, 4 absent, and
zero are blocked.** `FUN_00710460` was hidden only because it was *both*
blocked *and* referenced solely through an alias line.

The real lesson is about the **query, not the source**: the landable query
indexes only `0x`+8hex, so an alias line (which spells `FUN_xxxxxxxx`) is
invisible to it, while the batch-32 citation audit indexed both forms and so
counted these as cited. **Index both spellings**, or the query will keep
surfacing already-finished work as landable.

This is the mirror image of [[project-ani-dumpskeleton-partial-root]]: there a
doc block claimed more than the body delivered, here it claimed less.

**How the identification was confirmed, not assumed:** the binary calls the
named import `gpg::ReadArchive::ReadPointer_CArmyStatItem`, and so does the
recovered body. A named import shared by both is far stronger evidence than
shape, and it is what separates the load lane from its sibling save lane at
0x007105A0 that the same `Init` installs beside it.

## Multi-agent: never conclude another agent's merge

Hit 2026-08-21: `git commit <pathspec>` failed with *"cannot do a partial
commit during a merge"*. `git status` showed "All conflicts fixed but you are
still merging" with another agent's file staged. Concluding that merge would
have committed their staged work under my message.

Correct handling: leave your edits **unstaged** in the working tree (they are
safe -- a merge commit does not touch unstaged files), check the age of
`.git/MERGE_HEAD` to see whether the merge is active or abandoned, and retry
the commit after it clears. Never `git merge --abort` or `git commit` to
"unblock" yourself. Companion to
[[feedback-concurrent-commit-race-orphans-commits]].

## Highest-yield pattern found so far: a MISSING TEMPLATE MEMBER

Batch 44, commit f3e3858c. `FUN_0067C750` was blocked, and both of its
neighbours were already cited on `msvc8::vector`: `0x0067B780` as `push_back`
and `0x0067D320` as `_Insert_n`. The member **between** them --
`insert(iterator, const T&)` -- did not exist in the template at all, so the
emission had nowhere to live.

The cause was a divergence that looked harmless. Our `push_back` was:

```cpp
ensure_grow_for(1); new (last_) T(value); ++last_;
```

VC8's is two halves, both kept out of line by the linker:

```cpp
if (size() < capacity()) _Mylast = _Ufill(_Mylast, 1, _Val);
else                     insert(end(), _Val);
```

Behaviourally identical -- and that is exactly why it survived review. But the
merged form never emits `insert(pos, value)`, so a real binary function had no
possible source-level caller. RULE ONE's "fix the template, not the call site"
is what resolves it, and it fixes every element type at once.

**Look for this shape whenever a blocked token sits numerically between two
already-cited members of the same container.** That adjacency is the tell:
`0x0067B780 push_back / 0x0067C750 ??? / 0x0067D320 _Insert_n`. MSVC lays a
template's members out together, so a gap in the cited addresses of one
instantiation usually means a missing member rather than a mystery function.

Cheap query: for each container home, collect the cited addresses, sort, and
look for blocked tokens falling inside the runs.

### The sandwich query (batch 44)

Mechanised the adjacency tell: index the cited `Address:` set, then find
blocked-and-unreferenced tokens whose nearest cited neighbours on both sides
lie within 0x1000. Filter to engine range (< 0x00900000) and >= 25 instructions
to drop the IAT thunk noise, which otherwise dominates (1593 raw hits ->
**459** real candidates).

Top of that list, and the trap it exposed:

`FUN_00560CC0` (26 instr) sits 0x10 after a cited address and is unmistakably
`gpg::fastvector_n<Moho::SSTIUnitWeaponInfoSnapshot, 1>`'s **copy
constructor** -- it seats start/finish/capacity/originalVec on `this+0x10`
with capacity at `+0x98`, then calls `cpy` at 0x00561D90, which is already
cited as that exact instantiation. `sizeof(SSTIUnitWeaponInfoSnapshot)` is
0x98 and N is 1, so the inline span matches to the byte.

**It is still not citable, and my first explanation for why was wrong.**

I initially blamed `SSTIUnitVariableData(const SSTIUnitVariableData&)`
(Unit.cpp:13047), which is written `: SSTIUnitVariableData()
{ AssignFrom(other); }` -- delegate-then-assign never instantiates a member's
*copy* constructor. That reasoning is sound in general, but it is **not this
function's owner**.

Checked in batch 46: `FUN_00560CC0`'s only caller is `FUN_00560680` (171
instr, currently `skip`), a member-wise copy constructor whose direct field
writes stop at `[ebp+98h]` and which calls `sub_560CC0` exactly once. Since
that helper seats its inline span at `this+0x10 .. +0x98`, the vector member
sits at **offset 0x98 of the enclosing struct** -- so the owner cannot be
`SSTIUnitVariableData`, whose `mWeaponInfo` is at +0xF8 and whose total size
is 0x228. Two of `FUN_00560680`'s other callees (0x00560C60, 0x005608A0) are
uncited, so the owning type is still unidentified.

What *is* settled: `FUN_00560CC0` is
`gpg::fastvector_n<SSTIUnitWeaponInfoSnapshot, 1>`'s copy constructor, because
it calls `cpy` at 0x00561D90 which is already cited as exactly that
instantiation, and the 0x98 inline span matches `sizeof` x N to the byte.

To finish it: identify the struct that holds that vector at +0x98 (start from
0x00560C60 / 0x005608A0), confirm it is copy-constructed from source, then
cite. Do not cite it against `SSTIUnitVariableData`.
