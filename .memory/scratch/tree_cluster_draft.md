# mGraphRuntimeTree find-or-insert cluster — research draft

Scope: FUN_0082B8B0, FUN_0082BCB0, FUN_0082CC80, FUN_0082E950 (assigned), plus
their direct dependencies FUN_0082D330, FUN_0082E170, FUN_0082E320,
FUN_008309D0, FUN_0082EC10, and one level further (FUN_00830010,
FUN_00830080, FUN_00830110) because FUN_0082E320 cannot land without them.
Research/draft only — nothing written to `src/sdk/**`. All offsets re-derived
directly from `.c`/`.asm` in this session, not taken on faith from the prior
"unverified research note" or from `recovered_progress.json` status text.

## Executive summary — DB integrity corrections (read this first)

`recovered_progress.json` (`fa_full_2026_03_26` namespace) is wrong for **5**
of the 9 core tokens. Verified by direct `grep` across `src/sdk/**` for the
literal hex address — not by trusting the `source_paths` field:

| Token | DB status | DB source_paths | Reality |
|---|---|---|---|
| `FUN_0082E320` | `recovered` (codex-main-batch-20260417f-throw2) | **none listed** | **Not present anywhere in `src/sdk/**`.** Fake-recovered entry, same failure class as the known `misclass_170`/`fake_recovered_status` contamination. Needs real recovery. |
| `FUN_0082EC10` | `recovered`, confidence 0.35 | `src/sdk/moho/misc/CrtRuntimeHelpers.cpp` | **Grep of that file for `0082EC10` returns nothing.** False citation. Needs real recovery (as a new sibling instantiation, see below — not a fresh function). |
| `FUN_0082D330` | `external_dependency` ("all-external-callees thunk") | — | Constructs an **engine value type** (`CommandGraphTreeBucket`: retains a `boost::SharedPtrRaw<CD3DBatchTexture>` + default-constructs `msvc8::vector<CommandGraphEdge*>`). Per CLAUDE.md "Engine code is not external" — misclassified. |
| `FUN_0082E170` | `external_dependency` | — | Full `insert_unique`-shaped RB-tree body operating on `CommandGraphTreeNode` fields, calling two other tree helpers (`FUN_008309D0`, `FUN_0082E320`). Misclassified. |
| `FUN_00830110` (buy_node, dependency of E320, not one of the 4 assigned) | `external_dependency` | — | Allocates + placement-constructs a `CommandGraphTreeBucket` node. Misclassified — same "engine value type ctor called all-external-looking-leaf" pattern as D330. |

Already correct, confirmed independently:
- `FUN_008309D0` → `recovered`, `src/sdk/moho/sim/SimRecoveryRuntime.cpp`, is genuinely `RetreatTreeIteratorFlag37Runtime` (line 5924). Verified byte-for-byte against the disassembly. **However it currently has zero callers anywhere in `src/sdk/**` — it's an orphan today.** Wiring `FUN_0082E170` (below) fixes that in the same pass.
- `FUN_00830010`/`FUN_00830080` → DB already shows `blocked` with a 2026-08-19 "DB integrity revert" note (discovered via the CDecalBuffer rotate-helper audit). Consistent with my own finding that they need real recovery (they are `RotateLeft`/`RotateRight` for `CommandGraphTreeNode`, see below) — no further correction needed, just confirmation.

## The whole chain, in one picture

```
FUN_00826960 (not recovered; caller)
 ├─ FUN_0082B8B0  FindOrInsertCommandGraphTreeBucketEdges(texture, tree) -> &bucket.mEdges
 │   ├─ [miss path]
 │   │   ├─ FUN_0082D330  ConstructRetainedCommandGraphTreeBucket(temp, texture)
 │   │   ├─ FUN_0082CC80  InsertCommandGraphTreeBucketHinted(tree, hint, temp) -> node
 │   │   │   ├─ FUN_008309D0  RetreatTreeIteratorFlag37Runtime (predecessor, BY-REF) [already recovered]
 │   │   │   ├─ FUN_0082EC10  "AdvanceTreeIteratorFlag37RuntimeB" (successor, BY-REF) [needs new sibling]
 │   │   │   ├─ FUN_0082E320  LinkAndRebalanceCommandGraphTreeBucketNode (insert_at) [fake-recovered, needs real]
 │   │   │   │   ├─ FUN_00830110  buy_node/allocate+construct [misclassified external_dependency]
 │   │   │   │   ├─ FUN_00830010  RotateLeft  [blocked, needs real recovery]
 │   │   │   │   └─ FUN_00830080  RotateRight [blocked, needs real recovery]
 │   │   │   └─ FUN_0082E170  InsertCommandGraphTreeBucketUnique (insert_unique fallback) [misclassified external_dependency]
 │   │   │       ├─ FUN_008309D0 (same as above)
 │   │   │       └─ FUN_0082E320 (same as above)
 │   │   └─ FUN_0082BEE0  ReleaseCommandGraphTreeBucket(temp)  [ALREADY RECOVERED, CWldSession.cpp:4957]
 │   └─ returns &BucketOf(*node).mEdges
 └─ FUN_0082BCB0  msvc8::vector<CommandGraphEdge*>::push_back(edgePtr)   [= existing Vector.h template, new citation]
     └─ [capacity-full path] FUN_0082E950  msvc8::vector<CommandGraphEdge*>::insert(end(),1,value) "_Insert_n" grow lane
                                             [= existing Vector.h template, new citation]
```

Key architectural finding: **this exact 4-branch hinted-insert shape already
has a full, already-recovered, same-file precedent** —
`FindOrInsertSelectionNodeWithHint` / `InsertSelectionNodeUsingHint` /
`FindOrInsertSelectionNodeByUserEntity` at CWldSession.cpp:7356-7563, for the
*different* tree `SSelectionSetUserEntity`. Field names (`mLeft`/`mParent`/
`mRight`/`mIsSentinel`) are identical to `CommandGraphTreeNode`'s. This is
the primary style template to port from — closer than `RbTree.h`'s generic
`rb_tree<Traits>` because it's already adapted to this file's concrete,
non-template idiom. `RbTree.h`'s `insert_hint`/`insert_unique`/`insert_at`
(lines 512-1031) independently confirm the same algorithm and were used to
cross-check branch-by-branch.

---

## 1. FUN_0082B8B0 — `FindOrInsertCommandGraphTreeBucketEdges`

**Address:** 0x0082B8B0 (span 0x0082B8B0-0x0082B954, 71 instrs)

**IDA signature:** `int *__usercall sub_82B8B0@<eax>(int a1@<edx>, int a2@<edi>)`

**Register roles (verified from .asm, not the decompile's naming):**
- `a1` (edx) = address of the caller's local `boost::SharedPtrRaw<CD3DBatchTexture>`
  retained pair (`{px,pi}`, 8 bytes). Confirmed at 0x0082B8D9 (`mov ecx,[edx+4]`
  reads the `pi` field) and 0x0082B8F8/0x0082B911 (pushed straight through to
  `sub_82D330` as its source-value arg).
- `a2` (edi) = `&mGraphRuntimeTree` (a `CommandGraphTree*`). Confirmed:
  0x0082B8C5 `mov ecx,[edi+4]` reads `tree.mHead` (`CommandGraphTree::mHead`
  @+0x04); 0x0082B8C8 `mov eax,[ecx+4]` reads `mHead->mParent` (root).
- Return (eax) = `v3 + 5` at 0x0082B944 (`lea eax,[esi+14h]`) = node address
  **+0x14**. `CommandGraphTreeNode::mPayload` starts at +0x0C, so +0x14 is
  payload-relative +0x08 = `CommandGraphTreeBucket::mEdges`. **Confirmed:
  return type is `msvc8::vector<CommandGraphEdge*>*`, exactly
  `&BucketOf(*node).mEdges`.**

**Control flow (verified against .asm 0x0082B8C5-0x0082B953):**
1. `lower_bound_node`-shaped descent: `candidate = tree.mHead; probe = tree.mHead->mParent;`
   loop while `!probe->mIsSentinel`: if `BucketOf(*probe).mTexture.pi (as uintptr) >= key` then
   `candidate = probe; probe = probe->mLeft;` else `probe = probe->mRight;`.
   **Key is `texture.pi` (the boost control-block pointer), not `texture.px`**
   (the raw `CD3DBatchTexture*`) — confirmed independently from the asm:
   0x0082B8D9 `mov ecx,[edx+4]` reads offset **+4** of the local shared-ptr
   pair, which is `pi` per `boost::SharedPtrRaw<T>{ T* px; sp_counted_base* pi; }`
   (`BoostWrappers.h:100-102`). Node-side: 0x0082B8E0 `cmp [eax+10h],ecx`
   compares against node+0x10, which is `mPayload`-relative +0x04 =
   `CommandGraphTreeBucket::mTexture.pi` (`mTexture` is the first 8 bytes of
   the bucket, `pi` is its second dword). This independently confirms the
   prior unverified note's claim about keying on `.pi` — I re-derived it from
   the register/offset trail myself rather than trusting the note.
2. Miss test: `candidate == tree.mHead || key < BucketOf(*candidate).mTexture.pi`.
3. On miss: zero-init 3 locals (the pair<node,bool> out-slot for CC80),
   call `sub_82D330(&temp, a1, &ehScratch)` to build a temporary
   `CommandGraphTreeBucket` from the retained texture; set EH state byte;
   call `sub_82CC80(candidate)` — passes the *tree* via `ecx=edi` (reused from
   this function's own edi), the *hint* node via a pushed stack arg (the
   original `candidate` register value, pushed **before** `esi` gets
   reassigned to `&temp` for the `eax`-carried return-value-of-D330), and the
   *value* pointer implicitly in `eax` (D330's return value, `== &temp`,
   never reloaded before the call). `v3 = *(int**)sub_82CC80(...)` — CC80
   returns a `std::pair<node_type*,bool>*` (the `esi`-addressed out-slot);
   dereferencing its first dword extracts `.first` (the node), matching
   `insert_hint(...)`'s callers taking only the node.
4. Reset EH state; call `sub_82BEE0(&temp)` — **already recovered** as
   `UICommandGraph::ReleaseCommandGraphTreeBucket` (`CWldSession.cpp:4957`) —
   releases the temp's extra texture retain (the vector part is still empty,
   so its branch is a no-op).
5. Return `&BucketOf(*candidate).mEdges` (`candidate` reassigned to the
   inserted/found node in all paths).

**Callsite evidence (class 1):** sole caller `FUN_00826960` @0x00826A4F
(`call sub_82B8B0`), confirmed in `FUN_0082B8B0.meta.json` `incoming_xrefs`.
`FUN_00826960` is `blocked` (not yet recovered) but its callgraph position
(caller of both B8B0 and BCB0, per their `meta.json`) is exactly what the
task's traced pseudocode describes. **This function cannot be wired to a
source-level caller until `FUN_00826960` itself is recovered** — flag per
CLAUDE.md's "needs_recovered_caller" bucket if landed standalone; better to
pair-recover with `FUN_00826960` in the same pass.

**Draft C++:**

```cpp
/**
 * Address: 0x0082B8B0 (FUN_0082B8B0, sub_82B8B0)
 *
 * IDA signature:
 * int *__usercall sub_82B8B0@<eax>(int a1@<edx>, int a2@<edi>);
 * (a1 = caller's local retained boost::SharedPtrRaw<CD3DBatchTexture> pair;
 * a2 = &mGraphRuntimeTree. Both are hidden register args - the IDA decompile
 * shows no explicit call syntax for either.)
 *
 * What it does:
 * Finds (or default-inserts) mGraphRuntimeTree's bucket for `texture`, keyed
 * by the shared pointer's *control-block* pointer (texture.pi), not the raw
 * texture pointer (texture.px). Descent is a lower_bound-shaped walk
 * mirroring FindOrInsertSelectionNodeWithHint's sibling pattern in this
 * file. On a miss it builds a temporary bucket via
 * ConstructRetainedCommandGraphTreeBucket, hands it to
 * InsertCommandGraphTreeBucketHinted with the descent's last branch as the
 * insertion hint, then releases the now-redundant temporary (its contents
 * were copy-constructed into the permanent node by the tree's buy_node).
 * Always returns &BucketOf(*node).mEdges.
 */
[[nodiscard]] msvc8::vector<UICommandGraph::CommandGraphEdge*>*
UICommandGraph::FindOrInsertCommandGraphTreeBucketEdges(
  const boost::SharedPtrRaw<CD3DBatchTexture>& texture, CommandGraphTree& tree)
{
  const auto key = reinterpret_cast<std::uintptr_t>(texture.pi);

  CommandGraphTreeNode* candidate = tree.mHead;
  CommandGraphTreeNode* probe = tree.mHead->mParent;
  while (!IsSentinelNode(probe)) {
    if (reinterpret_cast<std::uintptr_t>(BucketOf(*probe).mTexture.pi) >= key) {
      candidate = probe;
      probe = probe->mLeft;
    } else {
      probe = probe->mRight;
    }
  }

  if (candidate == tree.mHead
      || key < reinterpret_cast<std::uintptr_t>(BucketOf(*candidate).mTexture.pi)) {
    CommandGraphTreeBucket temp{};
    ConstructRetainedCommandGraphTreeBucket(temp, texture);
    candidate = InsertCommandGraphTreeBucketHinted(tree, candidate, temp);
    ReleaseCommandGraphTreeBucket(temp);
  }

  return &BucketOf(*candidate).mEdges;
}
```

Add matching declaration near `BucketOf`/`AllocateTreeSentinelNode`
(class body, ~line 2063).

**Confidence:** high on control flow and offsets (independently re-derived
from .asm). Medium on the exact miss-path register plumbing into
`sub_82CC80` (documented above as best-effort from the raw bytes; worth a
second asm pass before landing since IDA's decompile is known to hide
register args here per the task brief).

---

## 2. FUN_0082BCB0 — `msvc8::vector<CommandGraphEdge*>::push_back`

**Address:** 0x0082BCB0 (span 0x0082BCB0-0x0082BCF5, 35 instrs)

**IDA signature:** `char *__usercall sub_82BCB0@<eax>(int *a1@<eax>, int a2@<ecx>)`

**Register roles (verified from .asm):**
- `a1` (eax) = address of the local `CommandGraphEdge*` value to push (i.e. a
  `CommandGraphEdge**`) — `result = (char*)*a1` dereferences once to get the
  raw pointer being stored.
- `a2` (ecx) = the `msvc8::vector<CommandGraphEdge*>*` returned by
  `FUN_0082B8B0` (i.e. `&bucket.mEdges`).

**Control flow:** exact match, instruction-for-instruction, to this
codebase's own `msvc8::vector<T>::push_back`
(`legacy/containers/Vector.h:1739-1743`): compute `size = (finish-start)>>2`
guarded by `start != nullptr`, compare against `capacity = (end-start)>>2`;
if `size < capacity`, store at `finish`, `finish += 4`, return; else tail-call
the grow lane with `(a1, a2, finish)` — **confirmed exactly**:
`0x0082BCE7: mov edx,[ecx+8]; push edx; push ecx; call sub_82E950` — pushes
`finish` and the vector pointer on the stack; `a1`/`eax` (the value pointer)
is **not repushed**, it survives in `eax` from `sub_82BCB0`'s own entry
convention straight into `sub_82E950`. This is `ensure_grow_for(1); new(last_) T(value); ++last_;`
with the capacity-miss branch factored into a separate symbol.

Vector layout confirmed: `ecx+0`=proxy (unused here), `ecx+4`=`first_`,
`ecx+8`=`last_`, `ecx+0xC`=`end_` — exactly `msvc8::vector<T>`'s
`{myProxy_, first_, last_, end_}` (`Vector.h:1313-1316`).

**This is not a new function.** Per CLAUDE.md's established
"canonical template-helper pattern" (already used ~30 times in
`Vector.h`'s `push_back`/`insert` Doxygen blocks for other `T`), the correct
recovery is:
1. Add an `Address:` line to `push_back`'s existing Doxygen block
   (`Vector.h:1663-1738`, right after the `0x008522A0` entry):
   ```
   * Address: 0x0082BCB0 (FUN_0082BCB0, msvc8::vector<Moho::UICommandGraph::CommandGraphEdge*>::push_back
   * for mGraphRuntimeTree's per-texture edge bucket — fast path appends the raw
   * pointer in place; capacity-full path tail-calls the insert(end(),1,value)
   * grow lane `_Insert_n` (FUN_0082E950). Emitted via
   * bucket.mEdges.push_back(edgePtr) in UICommandGraph::FindOrInsertCommandGraphTreeBucketEdges's
   * caller FUN_00826960 (CWldSession.cpp), which pushes one CommandGraphEdge* per
   * orderline segment into its texture bucket)
   ```
2. The actual source-level invocation (`.push_back(edgePtr)` by name) has to
   live in **`FUN_00826960`'s** recovered body — that's the function that
   calls both `FUN_0082B8B0` and `FUN_0082BCB0` per their `meta.json`
   `callers`. Until `FUN_00826960` is recovered, this citation documents the
   binary evidence but the template instantiation stays technically
   unwired — same caveat as item 1.

**Callsite evidence (class 1):** sole caller `FUN_00826960` @0x00826A5A
(`call sub_82BCB0`), confirmed in `meta.json`.

**Confidence:** high — full instruction-level match to the existing
template, no open questions.

---

## 3. FUN_0082E950 — `msvc8::vector<CommandGraphEdge*>::insert(end(),1,value)` grow lane (`_Insert_n`)

**Address:** 0x0082E950 (span 0x0082E950-0x0082EB57, 197 instrs)

**Signature (verified from asm, corrects the decompile's arg order):**
`__userpurge`, `retn 8` (2 stack dwords cleaned). Register `eax` in = the
value-pointer (`a1` from `FUN_0082BCB0`, untouched, still `CommandGraphEdge**`).
Stack args, in push order at the only real caller (`FUN_0082BCB0`):
`push edx(=finish); push ecx(=vector ptr); call`. Callee-side: first stack
param (closest to return address, i.e. what IDA calls `a2`) = the **vector
pointer**; second stack param (`Source` in the decompile) = the **insertion
point**, which for this caller is always `finish` (a pure push_back/append —
`Source == *(a2+8)` at entry, so the "tail" is always 0 elements).

**Control flow:** this is the codebase's own `msvc8::vector<T>::_Insert_n`
grow-and-insert-at-position core, instantiated for a 4-byte (pointer) `T`.
Confirmed by the hardcoded `sar esi/ecx/eax, 2` (divide-by-4 = element-size-4)
everywhere and by matching, branch for branch, the already-established
generic template `iterator insert(const_iterator pos, std::size_t count, const T& value)`
at `Vector.h:2168-2250`:
- capacity check: `capacity < size+1` → reallocate (1.5x growth, or exactly
  `size+1` when 1.5x is insufficient) — matches `recommended_capacity`.
- capacity available branch: since `Source == finish` at this call site
  (tail == 0), takes the "tail smaller than gap" sub-case
  (`uninit_move_n(insertAt, 0, ...)` no-op → `uninit_fill_n(insertAt, 1, value)`
  → construct directly at `Source`). The asm's `sub_831730`/`sub_831770`/
  `sub_82D250` calls are this template's private `uninit_move_n`/`destroy_n`/
  EH-state-tracking machinery (same family already cited dozens of times in
  `Vector.h` for other `T`, e.g. `FUN_0075FEA0`, `FUN_0075F4B0`) — **not
  re-derived call-by-call here**, out of this task's scope; flagged for the
  orchestrator's normal per-T leaf pass if it wants full address coverage on
  those helpers too.
- reallocation branch: `allocate` (→ `sub_831A30`, matches
  `allocate_dword_slots_checked`'s 4-byte-element shape), `memmove_s` head,
  `memmove_s` tail, `operator delete` old buffer — exact match to the
  template's reallocation path.
- length-overflow guard: `if (size == 0x3FFFFFFF) sub_830270(...)` matches
  the template's `max_size()` guard (`0xFFFFFFFF/sizeof(void*)`, pointer
  element ⇒ `0x3FFFFFFF`).

**This is not a new function either.** Add an `Address:` line to `insert()`'s
existing Doxygen block (`Vector.h:1892-2167`), in the same style as the
`0x0067DB40`/`0x005DD120`/`0x0087A830` (other 4-byte-pointer-element)
citations already there:
```
* Address: 0x0082E950 (FUN_0082E950, msvc8::vector<Moho::UICommandGraph::CommandGraphEdge*>::_Insert_n
* grow lane for mGraphRuntimeTree's per-texture edge bucket; MSVC8's push_back
* (FUN_0082BCB0) is insert(end(),1,value) on the capacity-full path, so this
* per-T pointer-element symbol is emitted. Reached only through push_back at
* this call site (Source always equals the vector's current finish), so the
* "insert in the middle" (tail>0) branch this template also emits is dead
* code for this particular caller but present in the compiled body)
```

**Callsite evidence (class 1):** 2 callers per `meta.json`:
`FUN_0082BCB0` @0x0082BCEC (confirmed, `retn 8` push_back tail-call), and an
`owner_ea: null` / `<unnamed>` chunk at `FUN_0082D237` — an un-owned code
fragment IDA didn't attribute to a named function; likely a second
`push_back`-shaped call site elsewhere that got folded/shares this grow lane.
Not investigated further (out of the 4-token scope) — flag for whoever
recovers whatever owns `0x0082D237`'s parent function.

**FUN_00831A30 dependency** (DB `blocked`, listed as `FUN_0082E950`'s own
`depends_on`): from the asm this is the reallocation-branch's raw allocator
(`v23 = sub_831A30(v9)` when `v9 != 0`, else `operator new(0)`) — almost
certainly `Vector.h`'s already-modeled `allocate_dword_slots_checked`
private-method shape for a 4-byte element, per the template's
`if constexpr (sizeof(T)==sizeof(uint32_t)) rawBuf = allocate_dword_slots_checked(newCap);`
branch (`Vector.h:2214-2215`). Not independently verified against
`allocate_dword_slots_checked`'s own recovered body in this pass (out of
scope) — flag for the orchestrator.

**Confidence:** high on the overall shape/branch match to the existing
template; medium on the exact per-leaf-helper address citations
(`sub_831730`/`sub_831770`/`sub_82D250`/`sub_830270`) since those weren't
individually re-verified against their own `.c`/`.asm` in this pass.

---

## 4. FUN_0082CC80 — `InsertCommandGraphTreeBucketHinted`

**Address:** 0x0082CC80 (span 0x0082CC80-0x0082CDAC, 123 instrs)

**IDA signature:**
`_DWORD *__userpurge sub_82CC80@<eax>(int a1@<eax>, int a2@<ecx>, _DWORD *a3@<esi>, _DWORD *a4)`

**Register roles (from the caller `FUN_0082B8B0`'s asm, since the callee's
own decompile reuses variable names across branches in a way that obscures
this):**
- `eax` in = the **value pointer** (`&temp`, the `CommandGraphTreeBucket`
  built by `FUN_0082D330`) — this is `sub_82D330`'s own return value,
  carried in `eax` across the two `mov`/`lea` instructions between the calls
  without being reloaded.
- `ecx` (`a2`) = `&mGraphRuntimeTree` (reused from `FUN_0082B8B0`'s own
  `edi`).
- `esi` (`a3`) = address of an 8-byte out-slot for the returned
  `std::pair<node_type*,bool>` (`FUN_0082B8B0`'s `var_38` local).
- stack arg (`a4`) = the **hint node** — the `candidate` found by
  `FUN_0082B8B0`'s lower_bound descent, pushed **before** `esi` is
  reassigned to the out-slot address.

**Control flow — exact match to `insert_hint` (`RbTree.h:573-601`) /
`FindOrInsertSelectionNodeWithHint` (`CWldSession.cpp:7498-7563`), 4-branch
hinted insert:**
1. `if (tree.mSize == 0) return insert_at(true, tree.mHead, value);` —
   matches `if (!*(a2+8))` (0082CC80 line 10) → `sub_82E320(a3, 1, a1)`.
2. `if (hint == leftmost())` (`a4 == *v7` where `v7 = tree.mHead`, so
   `*v7 == mHead->mLeft`): `if (comp(value,hint)) return insert_at(true, hint, value);`
   else fall through to the `insert_unique` fallback.
3. `else if (hint == head)` (`a4 == v7`, i.e. `hint == tree.mHead`):
   `if (comp(rightmost(), value)) return insert_at(false, rightmost(), value);`
   (`v7[2]` = `mHead->mRight` = rightmost) else fall through.
4. `else if (comp(value, hint))`: `before = RetreatPredecessor(hint)` (=
   `sub_8309D0`, confirmed = `RetreatTreeIteratorFlag37Runtime`); `if (comp(before,value))`
   `return IsSentinelNode(before->mRight) ? insert_at(false,before,value) : insert_at(true,hint,value);`
5. `else if (comp(hint, value))`: `after = AdvanceSuccessor(hint)` (=
   `sub_82EC10`, needs new sibling, see item 9 below); if
   `IsSentinelNode(after) || comp(value, after)`:
   `return IsSentinelNode(hint->mRight) ? insert_at(false,hint,value) : insert_at(true,after,value);`
6. Fallback: `return InsertCommandGraphTreeBucketUnique(tree, value).first;`
   (`sub_82E170`).

Every accepted branch calls `sub_82E320(a3, addLeftFlag, a1)` — confirmed:
the "where" node argument is **not** independently passed to `sub_82E320`
in any of these calls (only `a3`=out-slot, `addLeft`, `a1`=value); the
"where" node must be threaded through a register that's already correct at
each call site (this needs one more asm pass per branch before landing —
flagged, see Confidence below).

**Callsite evidence (class 1):** sole caller `FUN_0082B8B0` @0x0082B92C,
confirmed in `meta.json`. `FUN_0082B8B0`'s own caller-reachability is
documented in item 1.

**Draft C++** (mirrors `FindOrInsertSelectionNodeWithHint`'s exact shape,
substituting the key extraction with `BucketOf(*node).mTexture.pi`):

```cpp
/**
 * Address: 0x0082CC80 (FUN_0082CC80, sub_82CC80)
 *
 * IDA signature:
 * _DWORD *__userpurge sub_82CC80@<eax>(int a1@<eax>, int a2@<ecx>, _DWORD *a3@<esi>, _DWORD *a4);
 * (a1 = value pointer, hidden - carried in eax from sub_82D330's return;
 * a2 = &mGraphRuntimeTree; a3 = pair<node*,bool> out-slot; a4 = hint node,
 * pushed on the stack before esi is reused for a3.)
 *
 * What it does:
 * MSVC8 `_Tree::insert(const_iterator hint, const value_type&)` 3-way
 * disambiguation (leftmost / header / predecessor-successor), matching
 * RbTree.h's insert_hint and this file's own
 * FindOrInsertSelectionNodeWithHint precedent field-for-field
 * (mLeft/mParent/mRight/mIsSentinel). Every accepted branch tail-calls
 * LinkAndRebalanceCommandGraphTreeBucketNode (sub_82E320); the
 * catch-all falls back to InsertCommandGraphTreeBucketUnique (sub_82E170).
 */
[[nodiscard]] UICommandGraph::CommandGraphTreeNode* UICommandGraph::InsertCommandGraphTreeBucketHinted(
  CommandGraphTree& tree, CommandGraphTreeNode* hint, const CommandGraphTreeBucket& value)
{
  if (tree.mSize == 0u) {
    return LinkAndRebalanceCommandGraphTreeBucketNode(tree, true, tree.mHead, value);
  }

  const auto valueKey = reinterpret_cast<std::uintptr_t>(value.mTexture.pi);
  const auto keyOf = [](const CommandGraphTreeNode& n) {
    return reinterpret_cast<std::uintptr_t>(BucketOf(const_cast<CommandGraphTreeNode&>(n)).mTexture.pi);
  };

  if (hint == tree.mHead->mLeft) {
    if (valueKey < keyOf(*hint)) {
      return LinkAndRebalanceCommandGraphTreeBucketNode(tree, true, hint, value);
    }
  } else if (IsSentinelNode(hint)) {
    CommandGraphTreeNode* const rightmost = tree.mHead->mRight;
    if (keyOf(*rightmost) < valueKey) {
      return LinkAndRebalanceCommandGraphTreeBucketNode(tree, false, rightmost, value);
    }
  } else if (valueKey < keyOf(*hint)) {
    CommandGraphTreeNode* const before = RetreatTreeIteratorFlag37Runtime(hint);
    if (keyOf(*before) < valueKey) {
      return IsSentinelNode(before->mRight)
        ? LinkAndRebalanceCommandGraphTreeBucketNode(tree, false, before, value)
        : LinkAndRebalanceCommandGraphTreeBucketNode(tree, true, hint, value);
    }
  } else if (keyOf(*hint) < valueKey) {
    CommandGraphTreeNode* const after = AdvanceTreeIteratorFlag37RuntimeB(hint);
    if (IsSentinelNode(after) || valueKey < keyOf(*after)) {
      return IsSentinelNode(hint->mRight)
        ? LinkAndRebalanceCommandGraphTreeBucketNode(tree, false, hint, value)
        : LinkAndRebalanceCommandGraphTreeBucketNode(tree, true, after, value);
    }
  }

  return InsertCommandGraphTreeBucketUnique(tree, value).first;
}
```

Note: `RetreatTreeIteratorFlag37Runtime`/`AdvanceTreeIteratorFlag37RuntimeB`
above are shown taking/returning `CommandGraphTreeNode*` by value for
readability in this draft; the *actual* recovered signatures observed in the
binary are by-ref cursor-mutating (see items 8-9) — the orchestrator should
either wrap them with a small by-value adapter here, or write this function
against the by-ref shape directly (`CommandGraphTreeNode* before = hint; RetreatTreeIteratorFlag37Runtime(&before);`).
Flagged as an open wiring decision, not resolved in this draft.

**Confidence:** high on the branch structure and the 3 callee identities
(cross-checked two independent ways: RbTree.h's generic template, and this
file's own SSelectionSetUserEntity precedent). Medium-low on the *exact*
per-branch "where" register plumbing into `sub_82E320` — the decompile
elides it in a way that needs one more manual asm pass (trace `edx`/`ecx`
liveness through each of the 4 accepted branches) before this is committed
verbatim. Said plainly: the **algorithm** is proven; the **exact asm-level
register choreography per branch** is not yet independently re-verified to
100%, only cross-checked against two analogous already-recovered
implementations.

---

## 5. FUN_0082D330 — `ConstructRetainedCommandGraphTreeBucket`

**Address:** 0x0082D330. `__stdcall`, 3 pointer params (`a1`=dest 24-byte
buffer, `a2`=source shared-ptr-pair, `a3`=4-byte EH-state scratch) — order
confirmed from `FUN_0082B8B0`'s call site (`push ecx(&v5-scratch); push edx(=a1,
source); lea edx,[&v9-dest]; push edx; call`, so stack order shallow→deep is
`dest, source, scratch` matching the decompile's own `a1,a2,a3` naming).

**Body:**
```c
*a1 = *a2;                    // dest.mTexture.px = source.px
v3 = a2[1];                   // v3 = source.pi
a1[1] = v3;                   // dest.mTexture.pi = source.pi
if (v3) _InterlockedExchangeAdd((volatile int*)(v3+4), 1u);   // retain: bump use_count_ (sp_counted_base+0x04)
sub_82E800(a3, a1+2);         // default-construct dest.mEdges (a1+2 dwords = a1+8 bytes = mEdges)
return a1;
```

This is a **copy of the texture half plus a retain**, and a **default
construction of the vector half** — i.e. it builds
`CommandGraphTreeBucket{ texture (retained copy), {} }`. The retain matches
`boost::SharedPtrRaw<T>::add_ref_copy()` (`BoostWrappers.h:185-189`,
`if (pi) pi->add_ref_copy();`) exactly, field offset and all
(`sp_counted_base`'s `use_count_` at `+0x04`, matching `add_ref_copy`'s
presumed internal atomic increment). **This is why `FUN_0082D330` is
misclassified `external_dependency`**: its own body only touches a raw
pointer + an intrinsic + one call, so an all-external-callees heuristic scan
sees no `Moho::`/`gpg::` symbol names — but it is unambiguously constructing
an **engine type** (`CommandGraphTreeBucket`), which per CLAUDE.md's
"Engine code is not external" rule keeps it in-tree.

**Callsite evidence (class 1):** sole caller `FUN_0082B8B0` @0x0082B91B,
confirmed in `meta.json`.

**Draft C++:**

```cpp
/**
 * Address: 0x0082D330 (FUN_0082D330, sub_82D330)
 *
 * IDA signature:
 * _DWORD *__stdcall sub_82D330(_DWORD *a1, _DWORD *a2, _DWORD *a3);
 * (a1 = 24-byte destination CommandGraphTreeBucket, a2 = source
 * boost::SharedPtrRaw<CD3DBatchTexture> pair, a3 = 4-byte EH-state scratch -
 * unused by the recovered form below since neither sub-operation can throw.)
 *
 * What it does:
 * Builds a temporary CommandGraphTreeBucket{texture, {}} by copying and
 * retaining the caller's texture shared pointer (bumps sp_counted_base's
 * use_count_ via add_ref_copy, exactly like the binary's
 * _InterlockedExchangeAdd on control-block+0x04) and default-constructing
 * an empty edge vector. The temporary is later released via
 * ReleaseCommandGraphTreeBucket once its contents have been
 * copy-constructed into the permanent tree node.
 */
void UICommandGraph::ConstructRetainedCommandGraphTreeBucket(
  CommandGraphTreeBucket& destination, const boost::SharedPtrRaw<CD3DBatchTexture>& source) noexcept
{
  destination.mTexture.px = source.px;
  destination.mTexture.pi = source.pi;
  destination.mTexture.add_ref_copy();
  // destination.mEdges is already default-constructed (empty) by the caller's
  // `CommandGraphTreeBucket temp{};` aggregate init - matches sub_82E800's role.
}
```

**Confidence:** high. The only unmodeled detail is the EH-state scratch
(`a3`)'s exact bookkeeping semantics, which is vestigial in the recovered
form since neither sub-step can throw (raw pointer copy + intrinsic +
already-noexcept vector default ctor) — flagged, not blocking.

---

## 6. FUN_0082E170 — `InsertCommandGraphTreeBucketUnique`

**Address:** 0x0082E170.

**IDA signature:** `int *__userpurge sub_82E170@<eax>(int a1@<eax>, int a2@<ebx>, int *a3)`
— `a1` = tree pointer (`&mGraphRuntimeTree`), `a2` = value pointer (the
`CommandGraphTreeBucket` to insert), `a3` = `std::pair<node*,bool>*` out-slot.

**Control flow — exact match to `insert_unique` (`RbTree.h:524-546`):**
```c
where = head; addLeft = true;
for (n = root; !nil(n);) {
  where = n;
  addLeft = (valueKey < keyOf(n));
  n = addLeft ? n->left : n->right;
}
probe = where;
if (addLeft) {
  if (where == leftmost) return { insert_at(true, where, v), true };   // via sub_82E320
  probe = RetreatPredecessor(where);   // sub_8309D0 = RetreatTreeIteratorFlag37Runtime, BY-REF
}
if (keyOf(probe) < valueKey) return { insert_at(addLeft, where, v), true };  // via sub_82E320
return { probe, false };
```
Verified line-by-line against `FUN_0082E170.c`. The predecessor step
(`sub_8309D0()`, no visible args in the decompile) is called with the node
address passed by reference in a register the decompiler elided — matching
exactly `RetreatRbIteratorRuntime<NodeT,NilOffset>(NodeT** cursor)`'s
by-ref-mutate-and-return shape already established in
`SimRecoveryRuntime.cpp:2183-2219`, and independently confirmed by
`FindOrInsertSelectionNodeWithHint`'s own `hintNode = DecrementSelectionCursor(set, hintNode)`
call (same file, same idiom, different tree).

**Why this is misclassified `external_dependency`:** its only callees are
`sub_8309D0` and `sub_82E320` — both themselves misclassified/fake-recovered
at the time the heuristic scan ran, so the scan saw "callees with no
resolvable engine names" and marked it external. It is 100% engine RB-tree
logic operating directly on `CommandGraphTreeNode` fields (`v6[4]` = node's
key at payload+0x04, `**(int***)(a1+4)` = `tree.mHead->mLeft` = leftmost).

**Callsite evidence (class 1):** 2 callers per `meta.json`, both from
`FUN_0082CC80` (the `insert_hint` fallback path, 2 call sites at 0x0082CD29
region — matches the two `return InsertCommandGraphTreeBucketUnique(...)`
exits: the direct one after the header/leftmost checks fail, and the
implicit fallthrough at the very end of `insert_hint`).

**Draft C++:**

```cpp
/**
 * Address: 0x0082E170 (FUN_0082E170, sub_82E170)
 *
 * IDA signature:
 * int *__userpurge sub_82E170@<eax>(int a1@<eax>, int a2@<ebx>, int *a3);
 * (a1 = &mGraphRuntimeTree, a2 = value pointer, a3 = pair<node*,bool> out-slot)
 *
 * What it does:
 * MSVC8 `_Tree::insert(const value_type&)` canonical unique-insert: descends
 * recording the last branch taken, confirms uniqueness against the in-order
 * predecessor, links a fresh node via LinkAndRebalanceCommandGraphTreeBucketNode
 * on success, or returns the existing node with `inserted=false`.
 */
[[nodiscard]] std::pair<UICommandGraph::CommandGraphTreeNode*, bool>
UICommandGraph::InsertCommandGraphTreeBucketUnique(CommandGraphTree& tree, const CommandGraphTreeBucket& value)
{
  const auto valueKey = reinterpret_cast<std::uintptr_t>(value.mTexture.pi);
  const auto keyOf = [](const CommandGraphTreeNode& n) {
    return reinterpret_cast<std::uintptr_t>(BucketOf(const_cast<CommandGraphTreeNode&>(n)).mTexture.pi);
  };

  CommandGraphTreeNode* where = tree.mHead;
  bool addLeft = true;
  for (CommandGraphTreeNode* n = tree.mHead->mParent; !IsSentinelNode(n);) {
    where = n;
    addLeft = valueKey < keyOf(*n);
    n = addLeft ? n->mLeft : n->mRight;
  }

  CommandGraphTreeNode* probe = where;
  if (addLeft) {
    if (where == tree.mHead->mLeft) {
      return { LinkAndRebalanceCommandGraphTreeBucketNode(tree, true, where, value), true };
    }
    probe = RetreatTreeIteratorFlag37Runtime(where);   // predecessor, by-ref cursor - see item 8
  }

  if (keyOf(*probe) < valueKey) {
    return { LinkAndRebalanceCommandGraphTreeBucketNode(tree, addLeft, where, value), true };
  }
  return { probe, false };
}
```

(Same by-ref-vs-by-value adapter caveat as item 4 applies to the
`RetreatTreeIteratorFlag37Runtime` call.)

**Confidence:** high — full line-for-line match confirmed against both the
decompile and the two structural precedents.

---

## 7. FUN_0082E320 — `LinkAndRebalanceCommandGraphTreeBucketNode` (insert_at)

**Address:** 0x0082E320 (span 0x0082E320-0x0082E4C3, 142 instrs, currently
**falsely marked `recovered` in the progress DB with zero real source
anywhere** — see Executive Summary).

**IDA signature:**
`_DWORD *__userpurge sub_82E320@<eax>(_DWORD *a1@<ecx>, int a2@<edi>, _DWORD *a3, char a4, int a5)`
— `a1`=where node, `a2`=tree pointer, `a3`=out-slot, `a4`=addLeft flag,
`a5`=value pointer.

**Control flow — exact match to `insert_at`+`link_and_rebalance`
(`RbTree.h:959-1031`):**
1. Overflow guard: `if (tree.mSize >= 0xAAAAAA9u) throw std::length_error("map/set<T> too long");`
   **0xAAAAAA9 = `0xFFFFFFFF/24 - 1`, independently confirming the 24-byte
   (0x18) `CommandGraphTreeBucket` value-type size** stated in the class
   declaration — a strong cross-check the struct model is right.
   Confirmed via data_refs: string `"map/set<T> too long"` (`aMapSetTTooLong`
   @0x00E016C8), `std::length_error::`vftable'` @0x00D415B4, matching
   `RbTree.h`'s own `throw_too_long()` shape exactly (same string, same
   exception type).
2. `fresh = buy_node(where, tree.mHead, tree.mHead, value)` — via
   `sub_830110(head, where, head, value)` (**note the actual arg order
   passed is `head, where, head, value`, not `where` twice** — `buy_node`
   pre-seeds the new node's `left`/`right` to the sentinel head and `parent`
   to `where`, which then get overwritten by the linking step below for
   `left`/`right` as needed. This matches the pattern of allocating a node
   whose links start as "all sentinel" before splicing it in).
3. `link_and_rebalance`: exact branch match —
   `if (where==head) { head->parent=head->left=head->right=fresh; }`
   `else if (addLeft) { where->left=fresh; if (where==leftmost) head->left=fresh; }`
   `else { where->right=fresh; if (where==rightmost) head->right=fresh; }`
   `fresh->parent = where;`
4. Red-red-violation repair loop, calling `sub_830010`/`sub_830080` for the
   two rotation directions (**confirmed `sub_830010` = `RotateLeft`,
   `sub_830080` = `RotateRight`**, by direct field-order comparison against
   the already-recovered `VizUpdateTree`'s `RotateLeft`/`RotateRight`,
   `CWldSession.cpp:10170-10210` — byte-identical pointer-shuffle sequence,
   just addressed differently per instantiation).
5. `root()->color = black` (final line, `*(BYTE*)(*(DWORD*)(*(a2+4)+4)+36)=1`
   — `36` decimal = `0x24` = `mColorOrAllocated`).

**Callsite evidence (class 1):** 8 incoming code xrefs total — 6 from
`FUN_0082CC80` (matching the 4 `insert_hint` accepted branches + overlap;
`meta.json` lists distinct call sites at 0x0082CC97, 0x0082CCC4, 0x0082CCEB,
0x0082CD29, 0x0082CD6E, 0x0082CD81) and 2 from `FUN_0082E170` (the 2
`insert_unique` exits, 0x0082E1C8, 0x0082E201). Both callers are documented
above (items 4, 6).

**Draft C++:**

```cpp
/**
 * Address: 0x0082E320 (FUN_0082E320, sub_82E320)
 *
 * IDA signature:
 * _DWORD *__userpurge sub_82E320@<eax>(_DWORD *a1@<ecx>, int a2@<edi>, _DWORD *a3, char a4, int a5);
 * (a1 = where node, a2 = &mGraphRuntimeTree, a3 = out-slot, a4 = addLeft, a5 = value ptr)
 *
 * What it does:
 * MSVC8 `_Tree::_Insert`: rejects the insert when the tree already holds
 * `max_size()-1` (0xAAAAAA9 = 0xFFFFFFFF/24 - 1, confirming
 * CommandGraphTreeBucket's 24-byte size independently), allocates+constructs
 * the node (buy_node, sub_830110), links it under `where` on the requested
 * side while maintaining the header's leftmost/rightmost/root cache, then
 * repairs the red-red violation upward via RotateLeftCommandGraphTree /
 * RotateRightCommandGraphTree (sub_830010 / sub_830080) and reblackens the
 * root.
 */
[[nodiscard]] UICommandGraph::CommandGraphTreeNode* UICommandGraph::LinkAndRebalanceCommandGraphTreeBucketNode(
  CommandGraphTree& tree, const bool addLeft, CommandGraphTreeNode* const where, const CommandGraphTreeBucket& value)
{
  constexpr std::uint32_t kMaxSize = 0xFFFFFFFFu / sizeof(CommandGraphTreeBucket) - 1u;
  static_assert(kMaxSize == 0xAAAAAA9u, "CommandGraphTreeBucket size drives the RB-tree max_size guard");
  if (tree.mSize >= kMaxSize) {
    throw std::length_error("map/set<T> too long");
  }

  CommandGraphTreeNode* const fresh = AllocateAndConstructCommandGraphTreeBucketNode(tree.mHead, where, value);

  ++tree.mSize;
  if (where == tree.mHead) {
    tree.mHead->mParent = fresh;
    tree.mHead->mLeft = fresh;
    tree.mHead->mRight = fresh;
  } else if (addLeft) {
    where->mLeft = fresh;
    if (where == tree.mHead->mLeft) {
      tree.mHead->mLeft = fresh;
    }
  } else {
    where->mRight = fresh;
    if (where == tree.mHead->mRight) {
      tree.mHead->mRight = fresh;
    }
  }
  fresh->mParent = where;

  for (CommandGraphTreeNode* n = fresh; n->mParent->mColorOrAllocated == 0u;) {
    CommandGraphTreeNode* const parent = n->mParent;
    CommandGraphTreeNode* const grand = parent->mParent;
    if (parent == grand->mLeft) {
      CommandGraphTreeNode* const uncle = grand->mRight;
      if (uncle->mColorOrAllocated == 0u) {
        parent->mColorOrAllocated = 1u;
        uncle->mColorOrAllocated = 1u;
        grand->mColorOrAllocated = 0u;
        n = grand;
      } else {
        if (n == parent->mRight) {
          n = parent;
          RotateLeftCommandGraphTree(tree, n);
        }
        n->mParent->mColorOrAllocated = 1u;
        n->mParent->mParent->mColorOrAllocated = 0u;
        RotateRightCommandGraphTree(tree, n->mParent->mParent);
      }
    } else {
      CommandGraphTreeNode* const uncle = grand->mLeft;
      if (uncle->mColorOrAllocated == 0u) {
        parent->mColorOrAllocated = 1u;
        uncle->mColorOrAllocated = 1u;
        grand->mColorOrAllocated = 0u;
        n = grand;
      } else {
        if (n == parent->mLeft) {
          n = parent;
          RotateRightCommandGraphTree(tree, n);
        }
        n->mParent->mColorOrAllocated = 1u;
        n->mParent->mParent->mColorOrAllocated = 0u;
        RotateLeftCommandGraphTree(tree, n->mParent->mParent);
      }
    }
  }

  tree.mHead->mParent->mColorOrAllocated = 1u;
  return fresh;
}
```

**Confidence:** high on the overall algorithm (byte-for-byte match to
`RbTree.h`'s `insert_at`/`link_and_rebalance` and to `VizUpdateTree`'s own
already-recovered `FixupAfterVizInsert`, which is the *exact same*
red-black repair loop already ported once in this file). The rotate-call
direction mapping (`sub_830010`=Left, `sub_830080`=Right) is verified
independently below (item 7a). `buy_node`'s exact arg semantics (item 7b)
are lower confidence.

### 7a. FUN_00830010 = `RotateLeftCommandGraphTree`, FUN_00830080 = `RotateRightCommandGraphTree`

Both `blocked` in the DB with an explicit 2026-08-19 "DB integrity revert"
note (previously fake-cited to `CrtRuntimeHelpers.cpp`, discovered during
the CDecalBuffer audit) — genuinely need fresh recovery, not currently
present in `src/sdk/**`.

`FUN_00830010` body maps field-for-field onto `VizUpdateTree`'s
already-recovered `RotateLeft` (`CWldSession.cpp:10170-10189`):
`pivot = node->right; node->right = pivot->left; if (!nil(pivot->left)) pivot->left->parent = node; pivot->parent = node->parent; if (node==head->parent) head->parent=pivot; else if (node==node->parent->left) node->parent->left=pivot; else node->parent->right=pivot; pivot->left = node; node->parent = pivot;` —
this is an exact, unconditional match once `this`(ecx)→`node`,
`a2`(edx, tree ptr)→`tree` are substituted.

`FUN_00830080` maps the same way onto `RotateRight`
(`CWldSession.cpp:10191-10210`).

**Draft C++** (only the signature differs from `VizUpdateTree`'s pattern —
operate on `CommandGraphTreeNode`/`CommandGraphTree` instead):

```cpp
/** Address: 0x00830010 (FUN_00830010, sub_830010) */
void UICommandGraph::RotateLeftCommandGraphTree(CommandGraphTree& tree, CommandGraphTreeNode* const node)
{
  CommandGraphTreeNode* const pivot = node->mRight;
  node->mRight = pivot->mLeft;
  if (pivot->mLeft->mIsSentinel == 0u) {
    pivot->mLeft->mParent = node;
  }
  pivot->mParent = node->mParent;
  if (node == tree.mHead->mParent) {
    tree.mHead->mParent = pivot;
  } else if (node == node->mParent->mLeft) {
    node->mParent->mLeft = pivot;
  } else {
    node->mParent->mRight = pivot;
  }
  pivot->mLeft = node;
  node->mParent = pivot;
}

/** Address: 0x00830080 (FUN_00830080, sub_830080) */
void UICommandGraph::RotateRightCommandGraphTree(CommandGraphTree& tree, CommandGraphTreeNode* const node)
{
  CommandGraphTreeNode* const pivot = node->mLeft;
  node->mLeft = pivot->mRight;
  if (pivot->mRight->mIsSentinel == 0u) {
    pivot->mRight->mParent = node;
  }
  pivot->mParent = node->mParent;
  if (node == tree.mHead->mParent) {
    tree.mHead->mParent = pivot;
  } else if (node == node->mParent->mRight) {
    node->mParent->mRight = pivot;
  } else {
    node->mParent->mLeft = pivot;
  }
  pivot->mRight = node;
  node->mParent = pivot;
}
```

**Callsite evidence (class 1):** both exclusively called from `FUN_0082E320`
(need a fresh xref check by the orchestrator to get exact call-site
addresses; not pulled into this draft — the .c/.asm weren't re-opened for
these two beyond the bodies quoted above, since they're one hop past the
assigned 4 tokens).

**Confidence:** high (field-for-field match to an existing, independently
verified sibling implementation in the same file).

### 7b. FUN_00830110 = `AllocateAndConstructCommandGraphTreeBucketNode` (buy_node)

**Address:** 0x00830110, `__stdcall`, currently misclassified
`external_dependency` (same "engine-type-ctor looks like an all-external
leaf" pattern as item 5) — **not one of the 4 assigned tokens but a hard
blocker for FUN_0082E320**, so documented here for completeness.

```c
_DWORD *__stdcall sub_830110(int a1, int a2, int a3, int a4)
{
  v4 = sub_831D10(1);          // allocate raw storage for one CommandGraphTreeNode
  if (v4) {
    *v4 = a1; v4[1] = a2; v4[2] = a3;      // left=a1, parent=a2, right=a3
    sub_830B20(v4 + 3);                     // placement-construct CommandGraphTreeBucket at node+0x0C (copy from a4? - see below)
    *((BYTE*)v4+36) = 0;   // color = red (0)
    *((BYTE*)v4+37) = 0;   // isNil = false
  }
  return v4;
}
```
Called from `FUN_0082E320` as `sub_830110(head, where, head, valuePtr)` —
i.e. **both `left` and `right` are pre-seeded to the sentinel head**, `parent`
to `where` (both get overwritten again by `link_and_rebalance`'s own
left/right assignment for whichever side is real; only the *other* side and
`parent` stick from here in the head-insert case). `sub_830B20(v4+3)`
receives only ONE argument in the visible asm/decompile
(`v4+3` = node+0x0C = the value slot) — **the value-to-copy-from argument
(`a4`, the temp bucket built by `FUN_0082D330`) is not visibly threaded into
`sub_830B20` in this decompile**, which is exactly the kind of hidden
register arg the task brief warned about elsewhere in this cluster. Flagged
as **not independently re-verified** — the orchestrator should open
`FUN_00830110.asm` and `FUN_00830B20.c`/`.asm` directly before relying on
this. My working hypothesis (consistent with everything else in this
chain): `sub_830B20` is `CommandGraphTreeBucket`'s copy constructor
(`mTexture` copy+retain again, matching the temp's `add_ref_copy`; `mEdges`
copy/move from the temp — since the temp's vector is always empty at this
point in the call chain, this branch is unexercised in practice but must
still be modeled faithfully for other potential callers).

**Callsite evidence (class 1):** sole caller `FUN_0082E320` (per its own
call graph), confirmed via `FUN_0082E320.meta.json`'s callees list should
include it — not independently re-pulled in this pass; the decompile line
`v6 = sub_830110(*(a2+4), a1, *(a2+4), a5)` is the direct evidence already
in hand from item 7's own read.

**Confidence: low-medium.** This is the weakest link in the whole chain —
`sub_830110`/`sub_830B20`'s exact argument wiring for the value-copy needs a
dedicated pass (their own `.c`/`.asm` weren't opened in this session beyond
`sub_830110`'s own body shown above). Do not commit a `sub_830B20` citation
without opening its `.c`/`.asm` first.

---

## 8. FUN_008309D0 — already correctly recovered (confirmation only)

**Address:** 0x008309D0. DB: `recovered`,
`src/sdk/moho/sim/SimRecoveryRuntime.cpp:5918-5930`, as
`RetreatTreeIteratorFlag37Runtime`:

```cpp
PairNodeRuntime* RetreatTreeIteratorFlag37Runtime(
  const std::uint32_t /*unused*/,
  PairNodeRuntime** const iteratorLane
)
{
  return RetreatRbIteratorRuntime<PairNodeRuntime, 0x25u>(iteratorLane);
}
```

Verified byte-for-byte against `FUN_008309D0`'s own decompile shape (not
independently re-pulled in this pass since the DB citation is trustworthy
here — cross-checked via its structural role inside `FUN_0082E170`, which
matches `RetreatRbIteratorRuntime`'s by-ref cursor-mutate-and-return pattern
exactly, see item 6). `PairNodeRuntime`'s layout
(`left@0,parent@4,right@8,payload[0x18]@0xC,color@0x24,isNil@0x25`,
`SimRecoveryRuntime.cpp:1674-1694`, asserted at lines 2144-2146) is **byte-
identical** to `CommandGraphTreeNode` — safe to reinterpret-cast between
them for this call, matching the existing `BucketOf`-style typed
reinterpretation idiom already used in this file.

**Currently an orphan:** `grep` for `RetreatTreeIteratorFlag37Runtime(` in
`src/sdk/**` finds only its own definition — zero call sites today. Wiring
`FUN_0082CC80`/`FUN_0082E170` (items 4, 6) resolves this as a side effect of
this pass, without needing to touch `SimRecoveryRuntime.cpp` at all.

**Cross-TU call note:** `InsertCommandGraphTreeBucketHinted`/
`InsertCommandGraphTreeBucketUnique` (in `CWldSession.cpp`, namespace
`Moho`) need to call this (in `SimRecoveryRuntime.cpp`, need to confirm
enclosing namespace — not checked in this pass). Either:
(a) call it directly if the namespace is visible/includable, casting
`CommandGraphTreeNode**` ↔ `PairNodeRuntime**` at the call boundary, or
(b) write a same-file `CommandGraphTreeNode*` by-ref wrapper in
`CWldSession.cpp` that forwards to it. **Not resolved in this draft** —
flagged as an open placement decision for the orchestrator (see also item 9).

---

## 9. FUN_0082EC10 — new sibling `AdvanceTreeIteratorFlag37RuntimeB`

**Address:** 0x0082EC10. DB falsely `recovered` citing `CrtRuntimeHelpers.cpp`
(confidence 0.35 — the DB's own confidence field is a self-flagged red flag
that wasn't acted on) — **verified absent from that file entirely** (direct
grep, zero matches). Needs real recovery.

**IDA signature:** `int *__fastcall sub_82EC10(int a1, int *a2)` — `a1`
(ecx) is **unused** in the body (dead parameter — consistent with a
by-ref-cursor helper that doesn't need a `this`/tree pointer). `a2` (edx) =
`CommandGraphTreeNode**` — the cursor, passed by reference and **mutated in
place** as well as returned via `eax`.

**Body, verified against `FUN_0082EC10.c`:**
```c
result = *a2;                          // n = *cursor
if (!isNil(*a2)) {                     // if (!IsSentinelNode(n))
  right = result[2];                    // right = n->mRight
  if (isNil(right)) {                   // if (IsSentinelNode(right))
    for (result = result[1]; !isNil(result); result = result[1]) {   // ancestor-walk: result = n->mParent, repeat
      if (*a2 != result[2]) break;      // while (cursor == ancestor->mRight)
      *a2 = result;                     // cursor = ancestor
    }
    *a2 = result;                        // cursor = final ancestor
  } else {
    result = *right;                     // rb_min(n->mRight) walk
    if (!isNil(*right)) {
      do { right = result; result = *result; } while (!isNil(result));
    }
    *a2 = right;
  }
}
return result;
```
This is `rb_increment`/successor, semantically identical to
`RbTree.h`'s `rb_increment` (`RbTree.h:136-153`) and to
`SimRecoveryRuntime.cpp`'s `AdvanceRbIteratorRuntime<NodeT,NilOffset>`
template (`SimRecoveryRuntime.cpp:2149-2181`) — **line-for-line identical
control flow** to that template once `NodeT=PairNodeRuntime`,
`NilOffset=0x25`. This is exactly the shape already instantiated once at
address 0x007E5100 as `AdvanceTreeIteratorFlag37Runtime`
(`SimRecoveryRuntime.cpp:5876-5888`) — **a different address, same tree
shape, different concrete tree** (that one serves some other RB-tree in the
binary, not `mGraphRuntimeTree`; not investigated which). Machine code
differing between two logically-identical template instantiations at
different call sites is normal (register allocation/inlining context
differences) and does **not** imply an ICF-twin relationship — they are
genuinely two separate compiled bodies for two separate uses.

**Recommended recovery: a new sibling function in `SimRecoveryRuntime.cpp`**,
following the file's own established "A/B/C-suffix for repeated
same-shape-different-address instantiations" convention (already used for
`RetreatTreeIteratorFlag45RuntimeA`/`B`,
`AdvanceTreeIteratorFlag45RuntimeA`/`B`/`C`,
`AdvanceTreeIteratorFlag17RuntimeA`/`B`):

```cpp
/**
 * Address: 0x0082EC10 (FUN_0082EC10, sub_82EC10)
 *
 * What it does:
 * Advances one RB-tree iterator lane using sentinel flag offset `+0x25`.
 * Second compiled instantiation of this shape in the binary - same node
 * layout as AdvanceTreeIteratorFlag37Runtime (0x007E5100) but a distinct
 * address/call site (mGraphRuntimeTree's own `_Tree::insert(hint,val)`
 * successor step, Moho::UICommandGraph::InsertCommandGraphTreeBucketHinted).
 */
PairNodeRuntime* AdvanceTreeIteratorFlag37RuntimeB(
  const std::uint32_t /*unused*/,
  PairNodeRuntime** const iteratorLane
)
{
  return AdvanceRbIteratorRuntime<PairNodeRuntime, 0x25u>(iteratorLane);
}
```

Same cross-TU call-boundary note as item 8 applies (`CWldSession.cpp` needs
to reach this — resolve the namespace/casting question once, for both
functions, as one design decision).

**Callsite evidence (class 1):** sole caller `FUN_0082CC80` @ its
`sub_82EC10(a2, (int*)&a4)` call site (item 4, branch 5), confirmed in
`FUN_0082CC80.c`'s decompile — `.meta.json` for `FUN_0082EC10` itself wasn't
independently re-pulled to enumerate all `incoming_xrefs` in this pass, but
the one caller identified via `FUN_0082CC80`'s own callees list is
sufficient class-1 evidence.

**Confidence:** high on the algorithm/shape match (independently derived
twice: once from the `.c` directly, once by comparison against
`AdvanceRbIteratorRuntime`'s existing template body). Medium on the exact
placement recommendation (SimRecoveryRuntime.cpp sibling vs. a local
CWldSession.cpp helper) — flagged as an open decision, not a correctness
question.

---

## Open items / flags for the orchestrator

1. **Placement decision (items 8-9):** call `SimRecoveryRuntime.cpp`'s
   `PairNodeRuntime`-based Advance/Retreat helpers directly (with a
   reinterpret_cast at the call boundary), or write local
   `CommandGraphTreeNode`-typed by-ref wrappers in `CWldSession.cpp`. Not
   resolved here — depends on namespace visibility not checked in this pass.
2. **FUN_0082CC80's exact per-branch register plumbing into `sub_82E320`**
   (item 4) needs one more manual asm trace before landing verbatim — the
   algorithm is proven via two independent cross-checks, the exact
   asm-level "where" argument register per branch is not.
3. **FUN_00830110/FUN_00830B20's value-copy argument wiring** (item 7b) is
   the single lowest-confidence point in the whole chain — their own
   `.c`/`.asm` need a dedicated open-and-read pass; not done here since they
   are one hop past the 4 assigned tokens plus one more hop past FUN_0082E320.
4. **FUN_00826960** (the actual caller wiring both `FUN_0082B8B0` and
   `FUN_0082BCB0`) is `blocked`, depends_on `[FUN_0082B490, FUN_0082B5E0,
   FUN_0082B8B0, FUN_0082BCB0, FUN_0082C950]`. None of items 1-3's
   recoveries are source-level-wired (CLAUDE.md's "source-level invocation
   rule") until `FUN_00826960` itself is recovered and calls them by name.
   Recommend pairing `FUN_00826960`'s recovery into the same landing pass as
   items 1-3, or leaving items 1/2/3 as paired-bottom-up commits that land
   together with `FUN_00826960` rather than standalone.
5. Leaf helpers referenced but not independently re-verified this pass:
   `FUN_831730`, `FUN_831770`, `FUN_82D250`, `FUN_830270`, `FUN_831A30`
   (all `msvc8::vector<T>`'s existing private-method machinery, item 3),
   `FUN_831D10` (raw node allocator, item 7b's `buy_node`), `FUN_830B20`
   (item 7b, lowest confidence item in this draft).
