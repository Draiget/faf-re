---
name: project-rbtree-secure-scl-iterator-gap-2026-08-21
description: RESOLVED 2026-09-02 (commit 65d64393) -- case (a), validation is provably inert on the success path. Citation-only fix landed on rb_iterator's constructor/operator++/operator--/operator!=, 11 DB tokens corrected. Original 2026-08-21 diagnosis kept below for the historical trail; see RESOLUTION section at the end for the final answer and evidence.
metadata:
  type: project
---

## RESOLUTION (2026-09-02, commit 65d64393)

**Case (a): the validation is pure fail-fast-on-misuse, provably inert on the
success path.** No `rb_iterator` modeling was needed -- citation-only fix.

### The decisive evidence

`sub_A84A40`/`FUN_00A84A40` is not project-specific: it's MSVC8's standard
`_SCL_SECURE_VALIDATE` failure trap (`xor eax,eax; push eax x5; call
__invalid_parameter; add esp,14h; retn` -- literally `_invalid_parameter(0,0,
0,0,0)`), COMDAT-shared across 119 callers spanning genuine Microsoft STL/CRT
internals (`std::ctype<char>::_Do_widen_s`), wx, and at least three distinct
container families in this binary (rb-tree/map/set, a checked deque/bitset
random-access iterator, and a checked vector range iterator).

Read the FULL raw asm (not just the paraphrased decompile the 2026-08-21 note
quoted) for every `sub_A84A40` call site in the confirmed rb-tree family
(operator++, operator--, operator!=, the 2-arg checked constructor -- 12
addresses total). Every single call site follows one of exactly two patterns:

1. **Falls through unconditionally.** `cmp dword ptr [x],0; jnz +5; call
   sub_A84A40` is NOT followed by a jump past the rest of the function --
   execution continues into the normal computation regardless of whether the
   check "failed". A null/mismatched container pointer changes nothing about
   the computed result on any of the 12 traced addresses.
2. **Tail-jumps only on provably-UB misuse.** The only `sub_A84A40` call
   sites that actually divert control flow (`jmp sub_A84A40` instead of
   falling through) fire exclusively when the node being stepped from/to is
   already the nil sentinel -- i.e. `++end()`, `--begin()`, or `--end()` on
   an empty tree. All three are undefined behavior for any iterator, checked
   or not, and are explicitly outside this project's fidelity contract
   (observable behavior on well-formed usage, not crash-on-misuse).

This was independently corroborated three separate ways in the same pass:
this file's own pre-existing (and previously un-cross-referenced) `proxy_`
field comment on `rb_tree` already documented the identical policy ("checked-
container machinery is real in the binary but deliberately unmodeled because
it never changes observable behavior") for the sibling `_Container_proxy`/
checked-erase mechanism; `recovered_progress.json`'s note on `FUN_00A65320`
(a different prior pass, `erase_range`) reached the same conclusion
independently; and the DB already had `FUN_00A52CB0`/`FUN_00A52E00` marked
`external_dependency` with a note gesturing at exactly this pattern before
this pass started.

### What actually owns these tokens

All 11 rb-tree-family tokens touched in this pass are **WildMagic**
(`Wm3::ConvexHull3<Real>::m_kHull`, a `std::set<HullTriangle3<Real>*>`, and
its `Update()`-local `std::map<int, TerminatorData>` "kTerminator"), already
`external_dependency` per CLAUDE.md's named terminal category, not engine
code:

| Member | float | double |
|---|---|---|
| `operator++` (m_kHull) | FUN_00A52760 | FUN_00A52930 |
| `operator++` (kTerminator) | FUN_00A52CB0 | FUN_00A52E00 |
| `operator--` (m_kHull) | FUN_00A528A0 | FUN_00A526D0 |
| `operator--` (kTerminator) | FUN_00A52C20 | FUN_00A52D70 |
| 2-arg checked ctor | FUN_00A552D0 | FUN_00A55670 (owner not pinned to a field) |
| `operator!=` | FUN_00A55150 (zero-xref duplicate, owner not pinned) | -- |

`FUN_00A528A0`/`FUN_00A526D0` were found mis-marked `recovered` with a fake
`CrtRuntimeHelpers.cpp` citation (null `source_paths`, matching the known
contamination pattern) -- corrected to `external_dependency` alongside this
pass. `FUN_00A552D0`/`FUN_00A55670`/`FUN_00A55150` had zero incoming xrefs of
their own; recovered per this file's established "compiler emits the same
body more than once, only some copies are ever reached from a live caller"
convention, matching several dozen other precedent citations already in
`RbTree.h`.

### The 2026-09-02 sweep's "7 corroborating tokens" -- 4 were a different container

Reading every one individually (not trusting the sweep note's grouping)
found the cluster was a MIX: `FUN_00A55150`/`FUN_00A552D0`/`FUN_00A55670` are
genuine rb-tree emissions (cited above). `FUN_00A55750`/`FUN_00A557A0`/
`FUN_00A55A50`/`FUN_00A55AB0` are a **completely different container**: a
checked deque/bitset-style random-access iterator, isNil-independent 3-word
`{0, container, rawIndex}` shape (`this[2]>>2`/`this[2]&3` block/sub-index
split, matching Dinkumware's `_DEQUESIZ` block-of-4 formula for a 4-byte
element type), with its OWN constructor validating the index against a
`[start, start+count)` range read from the container at +12/+16 -- nothing
like rb-tree's `left@0/parent@4/right@8/isNil@N` node layout. Not cited in
`RbTree.h`; left for a separate pass (owner engine type not yet identified).

### Real RULE ONE debt surfaced, not fixed here

`src/sdk/moho/math/Wm3DistanceFafExtras.cpp` has
`AreQueryTreeOwnerKeyCursorsNil17NotEqualLaneA`/`...LaneB`
(`FUN_00A52870`/`FUN_00A52A40`, isNil@0x11, same `m_kHull` neighbourhood) --
a `QueryTreeOwnerKeyCursorNil17`-typed reach-in wrapper duplicating
`rb_iterator::operator!=` instead of calling it, exactly RULE ONE's
`*_runtime_view`/reach-in pattern one level removed. Already has real,
working, cited behavior, so left as-is rather than re-cited a second place;
collapsing it is a separate, larger pass through that file's whole
`QueryTree*` family (worth checking how large that family is before
starting -- not scoped in this pass).

### Was the original 2026-08-21 diagnosis right about the shape?

Partially. It correctly identified the gap and the risk (real, cross-
instantiation, worth a dedicated pass). It got the **direction wrong**:
`FUN_00A52760`'s decompile was read as `operator--` ("two-arm structure:
walk left-subtree-rightmost, or walk up while `n==ancestor->right`") but is
actually `operator++` -- confirmed by cross-checking against this file's own
canonical, already-cited `rb_node<V>` layout (`left@+0x00, parent@+0x04,
right@+0x08`), which the increment/decrement algorithms are NOT symmetric
under without that layout in hand (both directions produce the same abstract
shape when you don't know which offset is which child). This file's own
pre-existing citation on `rb_tree::equal_range`'s counting-loop helper
(`sub_A598A0`, already calling `FUN_00A52760` "the `rb_increment`-
equivalent") had it right all along -- worth cross-checking an existing
citation elsewhere in the file before trusting a memory note's paraphrase,
even a careful one.

---

## Original 2026-08-21 diagnosis (superseded by RESOLUTION above; kept for trail)

## What was found

While citing more RB-tree rotate/erase instantiations (`FUN_00A52800`/
`FUN_00A529D0`/`FUN_00A63950`/`FUN_00A633D0`/`FUN_00A63690`/`FUN_00A553A0`/
`FUN_00A553F0`/`FUN_00A554D0`/`FUN_00A55520`, all cited this session), two
more candidates in the same 0xA5xxxx neighbourhood turned up:
`FUN_00A52760`/`FUN_00A52930` (byte-identical to each other). Their raw
decompile:

```c
int __thiscall sub_A52760(_DWORD *this)
{
  if (!*this) sub_A84A40();                  // this[0] == container ptr, null -> debug fail
  v2 = *(this+1);                            // this[1] == the node the iterator holds
  if (*(_BYTE*)(v2+17)) return sub_A84A40(); // node is nil -> debug fail (can't decrement end() from a bad state?)
  v4 = *(_DWORD*)(v2+8);                     // v4 = node->left
  if (*(_BYTE*)(v4+17)) {
    // walk ancestors while this[1] == ancestor->right, matching rb_decrement's ancestor-walk arm
  } else {
    // walk v4's rightmost, matching rb_decrement's rb_max(n->left) arm
  }
  this[1] = result;   // <-- writes the new node back into the iterator, doesn't just return it
  return result;
}
```

The `rb_decrement`/`rb_max` walk logic algorithmically matches the
already-recovered `rb_decrement<V>(rb_node<V>*)` free function exactly (same
two-arm structure: walk left-subtree-rightmost, or walk up while
`n==ancestor->right`). **But** this candidate is not a bare
`rb_decrement(node)` call — it's `iterator::operator--()` on an iterator
*object* (`this[0]` = container/proxy pointer, `this[1]` = node pointer),
and it calls `sub_A84A40()` (a debug/`_Compat`-style validation routine,
independently seen elsewhere this session guarding cross-container iterator
misuse in `FUN_00A65D00`) before doing the decrement — on both a null
container-pointer check and what looks like a nil-node guard.

## Why this wasn't just cited and closed

The currently-recovered `rb_iterator::operator--()` (`RbTree.h` line ~324):

```cpp
rb_iterator& operator--() noexcept
{
    node_ = rb_decrement(node_);
    return *this;
}
```

...is a bare wrapper with **no validation call**. `sub_A84A40` (the debug/
`_Compat` check) is present in the **shipped Release binary** — this is
VS2005/MSVC8's `_SECURE_SCL` checked-iterator behavior, which defaults to
**on** in Release builds unless the project explicitly disables it. That
means this potential gap isn't local to `FUN_00A52760`/`FUN_00A52930` — it
plausibly affects **every** `rb_iterator::operator++`/`operator--`/
`operator*` emission across the whole `msvc8::map`/`msvc8::set` family, not
just this one instantiation. Confirming and fixing that is a real
architectural change to the shared template (model `sub_A84A40`'s real
semantics, decide whether/how to reproduce checked-iterator validation in
the modern `rb_iterator`, wire it into every relevant operator), not a
one-line citation — too large to safely rush.

## What to do next time this comes up

1. Read `sub_A84A40`'s real body (it's called from at least 3 sites found
   this session: here, and the cross-container check in `FUN_00A65D00`) to
   pin down exactly what it validates — likely orphan-iterator detection
   (does the iterator's stored container pointer match the tree being
   operated on) plus possibly a "not already erased" check.
2. Decide whether the modern `rb_iterator` needs an equivalent runtime
   check at all — if `_SECURE_SCL` checked iterators are purely a
   debug/safety feature with no behavioral difference in the success path
   (which is typical), the current bare `rb_decrement`/`rb_increment` calls
   may already be *behaviorally* equivalent for all valid-usage call sites,
   and the gap might only matter for reproducing the exact
   fail-fast-with-`sub_A84A40`-crash behavior on MISUSE — which may not be
   worth reproducing faithfully at all (crash-on-misuse is not
   observable behavior in the success path CLAUDE.md's fidelity contract
   cares about).
3. If it IS decided to model it, `FUN_00A52760`/`FUN_00A52930` are a clean
   starting pair (byte-identical to each other, in the same address
   neighbourhood as the other 9 tokens already cited this session — likely
   the same unidentified `map<int32_t, T>`-family instantiation's
   `operator--`).

Left `FUN_00A52760`/`FUN_00A52930` blocked (unchanged) rather than force a
citation onto `rb_decrement` that would misrepresent the missing validation
wrapper.
