---
name: reference-closure-candidate-query
description: SQLite closure query that ranks recovery candidates by how many UNRECOVERED functions they transitively pull in; replaces the blocked-list + fa-find-callers sweep and exposes both false-caller and false-negative traps.
metadata:
  type: reference
---

The `_callgraph_index.sqlite` `call_edges` table plus a set of "addresses that
appear anywhere in `src/sdk`" gives a far better candidate ranking than the
skill's blocked-list sweep: for each candidate, BFS its callees but **stop
expanding at any function already in src or above 0x00A00000 (CRT)**. The
result is the exact set of functions you would have to write to land it.

    # BOTH spellings, or the set is wrong (see the 2026-08-14 note below):
    have = {'FUN_' + (m[4:] if m.startswith('FUN_') else m[2:]).upper()
            for m in rg('-o','-N','--no-filename',
                        r'(0x|FUN_)00[0-9A-Fa-f]{6}','src/sdk')}

Working script: `scratchpad/closure2.py` (also splits the closure into
behavioural / template / CRT, which the original version did not).

Ranking by closure size turns "which of 1175 blocked tokens is tractable" into
a sorted list in one query. Closure == 1 means every callee is already
recovered.

## Two traps it exposes, in opposite directions

- **False positive (the known one).** `FUN_0085CD40` ranked first at 568
  instructions, closure 1 - but its only caller is `CWldSession::
  RenderStrategicIcons`, a **comment-only stub**. The address annotation on a
  stub body makes it look recovered. Always read the caller's body.
- **False negative (new, 2026-08-14).** `FUN_006D77B0` looked unrecovered in
  both the query and the progress DB. It was already implemented as
  `AddWeaponBlacklistEntry` in CAcquireTargetTask.cpp - just with **no address
  annotation**, so no address-based search could see it. Confirmed by three
  offsets (`SBlackListInfo` 0x0C stride, `mValue` +8, `UnitWeapon::mBlacklist`
  +0x160). Before writing a body, grep for its *behaviour*, not just its
  address.

## Measured state, 2026-08-14

- 1175 tokens have closure <= 12. 150 have closure == 1.
- The **unit subsystem is drained of behavioural work at closure <= 4**: 12
  candidates with closure 1, of which the two real ones landed (a7a8212), and
  the rest are container/template emissions (`std::queue::clear`,
  `std::map::find`, `Box3f` ctor, fastvector grow). Only 3 chains exist at
  closure 2-4 and all three are reflection/container lanes.
- **`CUnitRefuel::Execute` (FUN_00621490) is fully recovered** - a 226-line
  state machine at CUnitRefuel.cpp:416, 18 callees, the only two unrecovered
  being CRT `std::string` ctor/dtor. The standing goal's literal subject is
  done; what remains under it is "related unit sources".

## The have-set must match `FUN_00ABCDEF` too (2026-08-14)

Matching only `0x00ABCDEF` marks every intent-first recovery unrecovered,
because those cite the bodies they absorbed as bare `FUN_` tokens. Concretely:
`FUN_0061C750` ranked as a clean 114-instruction candidate with a recovered
caller — it is already implemented as `FastVector.h`'s `InsertAt` intrusive
weak-ref grow lane, cited at line 818 as `FUN_0061C750` with no `0x`. Fixing
the regex dropped the candidate pool 850 → 824. **This is the same
false-negative trap as `AddWeaponBlacklistEntry`, and the query itself was
causing it.**

Also: CRT must be classified by *name*, not just by `ea >= 0x00A00000`. The
low CRT block (`std::string::*` at 0x0040xxxx) sits below that cutoff, and
letting it expand is what produced the bogus 148-function figure below.

## Absorbed STL clusters are not candidates

`FUN_00629750` (`std::_Insertion_sort`) looked clean: recovered caller, both
callees recovered. Its "caller" is only named in a *comment* — the whole MSVC8
introsort COMDAT cluster is absorbed into one `std::sort(...)` call at
`CUnitLoadUnits.cpp:600`. Writing it would be a duplicate container helper.
Before taking a candidate whose caller lives in the 0x0062xxxx / 0x0085xxxx
template blocks, grep whether the caller address appears in prose rather than
as an `Address:` annotation.

## Correcting an earlier estimate

I previously scoped the `UICommandGraph::CreateMeshes` cluster at "12
functions, ~1280 lines" by grepping callee names out of the `.c` files. That
was wrong - the `.c` hides most calls behind inlining and IDA renaming. But
the **148 / ~8928** correction I then recorded was ALSO wrong, in the other
direction: it let the low CRT block expand unbounded. With CRT classified by
name the closure is **94 fns / 6322 instrs**, of which 49 are STL container
instantiations (identifiable by their `list<T> too long` / `map/set<T> too
long` / `vector<T> too long` `_Xlen` string refs) and the 0x0085xxxx block is
`std::stable_sort` machinery. The **behavioural core is 13 fns / ~1900
instrs** - close to the original 12-function estimate.

Lesson: over-correcting is as bad as the original error. Classify the closure
before quoting a number.

**Never size a cluster from `.c` call greps. Use the closure query.**

Related: [[reference_decomp_read_helper]],
[[project_cuiworldview_render_vtable_cluster]].

## The low address block is CRT/STL too (2026-08-14)

`FUN_0045B860` ranked well (99 instrs, 7 recovered callers, closure 0) and is
`std::wstring::assign(const wstring&, pos, len)`. The demangled name is just
`sub_45B860`, so neither the name-based CRT regex nor the `ea >= 0x00A00000`
cutoff caught it. **Everything below roughly 0x00470000 is the CRT/STL COMDAT
block** - treat an unnamed candidate there as a container/CRT emission until
proven otherwise, and read the first 20 lines of its `.c` before spending a
recovery pass on it. Same for the 0x0085xxxx `std::stable_sort` block and the
0x0082A-0x00832 `std::list/vector<Vector3f>` block.


## Four ways a recovered function hides from a presence check (2026-08-15)

Checking "is FUN_X already in src" keeps failing in new ways. All four have now
cost a wasted pass:

1. **No address annotation** - `AddWeaponBlacklistEntry` was the real body of
   FUN_006D77B0 with no `Address:` line.
2. **Intent-first name** - `RunScript_WeakunitStr` is
   `CScriptObject::RunScriptOnStopBeingBuilt`; grepping one header for the IDA
   spelling said "missing" and I reported a bogus bottom-up chain.
3. **Unannotated overload** - `0x00907D80` is the `PushStack(LuaState*)`
   overload; its sibling carries the annotation.
4. **Inline definition in the class body** (NEW) -
   `LuaPlus::LuaStackObject::GetNumber` (0x005459F0) is
   `[[nodiscard]] double GetNumber() const { return ToNumber(); }` at
   `LuaObject.h:1007`. **`rg 'LuaStackObject::GetNumber'` cannot match it** -
   there is no qualified name to find. I declared it a genuine gap and started
   writing a duplicate; the compiler stopped me with C2084.

**So the presence check must be: grep the BARE member name inside the owning
class's header *and* cpp, not `Class::Method`.** And when the binary function
is a one-line forwarder, expect the source form to be an inline forwarder with
a different target name (`GetNumber` -> `ToNumber` here).
