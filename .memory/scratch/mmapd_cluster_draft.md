# mMapD (`HashTable<HashListNode10>`) cluster — research + draft

Scope: `UICommandGraph::mMapD` find/insert primitives (FUN_0082C950, FUN_0082B5E0,
FUN_0082CBA0, FUN_0082DD60, FUN_0082FB10) plus every dependency touched while tracing
them (FUN_0082DE90, FUN_0082DE20, FUN_00831C90, FUN_0082F7A0/F210/D820, FUN_0082B870).
Research only — nothing written under `src/sdk/**`. All offsets/branches below are
cross-checked against the raw `.asm`, not just the Hex-Rays `.c`.

## 0. Headline findings (read this first)

1. **Progress-DB contamination confirmed on 3 of the 4 assigned tokens.**
   - `FUN_0082DD60` and `FUN_0082FB10` are marked `status: recovered` with
     `source_paths: src/sdk/moho/misc/CrtRuntimeHelpers.cpp`, but **neither address
     string (`82DD60`, `82FB10`) appears anywhere in `src/sdk`** (repo-wide grep, zero
     hits). The `FUN_0082DD60.md` report even names a function
     `RuntimeIncrementRecord16ListSizeCheckedLaneP` — that identifier also does not
     exist anywhere in `src/sdk`. Both are fabricated-recovery entries (same pattern
     as `project_fake_recovered_status_contamination` in memory). **Treat both as
     fully open; they need real recovery, exactly as originally scoped.**
   - `FUN_0082C950` is marked `status: external_dependency` ("All-external-callees
     thunk... no Moho/gpg engine references"). This is **wrong** — see §1 verdict.
   - `FUN_0082F7A0`, `FUN_0082DE20`, `FUN_00831C90` **are** genuinely already
     recovered and correct (verified below) — reuse them, don't re-derive.
2. **`FUN_0082DE20` (the truncate-path helper) is already recovered but orphaned.**
   `MoveDwordTailLaneA` in `LegacyContainerRuntime.cpp` (line ~1134) is byte-for-byte
   what `EnsureHashBucketVectorLengthForMapD`'s truncate branch needs, and it
   currently has **zero callers anywhere in `src/sdk`**. Wiring it in (or citing why
   it's elided, matching the AB0 sibling's precedent — see §5) fixes an existing
   orphan for free.
3. **Caller-reachability gap.** Both `FUN_0082C950` and `FUN_0082B5E0`'s *only*
   xref'd caller is `FUN_00826960`, which is `status: blocked` (not recovered).
   `FUN_0082C950`'s second "caller" (`FUN_0082B870`) has **zero incoming xrefs of its
   own** (`callers_count: 0`) — it cannot supply reachability. **Recovering the 4
   assigned tokens alone, without also landing `FUN_00826960` (or at least stubbing
   it in the same pass per the paired-bottom-up rule), leaves them orphaned** per the
   source-level-invocation rule. Flagging this per instructions; not blocking the
   draft on it since the task said `FUN_00826960` recovery is out of scope for this
   pass — but the orchestrator should recover/wire `FUN_00826960` in the same commit
   or immediately after, not leave these as a second orphan batch.
4. **`HashListNode10` needs a layout upgrade** from the current bare
   `using HashListNode10 = HashListNode<0x10>;` alias to a dedicated struct with named
   `mKey`/`mWidth` fields (§2) — same size (0x10), same offsets, just named. Every
   function below needs this to avoid raw-offset access, which the fidelity contract
   forbids.

---

## 1. FUN_0082C950 → `FindHashListNode10`

- **Address**: `0x0082C950`–`0x0082C9EA` (57 instrs, 154 bytes).
- **Raw signature** (IDA, register args correctly attributed): `_DWORD *__usercall
  sub_82C950@<eax>(_DWORD *a1@<ebx>, int *a2@<edi>, _DWORD *a3@<esi>)` — `a1`=out
  pointer (also echoed back as the return value), `a2`=pointer to the search key
  (dereferenced once, `*a2`), `a3`=`HashTable<HashListNode10>*`.
- **Control flow** (asm-verified, `0x0082C950`–`0x0082C9E9`):
  1. `eax = *edi ^ 0xDEADBEEF` (search key), `ldiv(eax, 127773)`, then the Park-Miller
     scramble `16807*rem − 2836*quot`, `+0x7FFFFFFF` if negative — **identical** inline
     scramble to `HashKeyToBucketIndex`.
  2. `ecx = [esi+0x20]` (=`table.mBucketMask`), `and eax, edx` (scrambled & mask),
     `cmp [esi+0x24], eax` (`table.mBucketCount`), `ja` skip; else wraparound
     `eax += -1 - (mBucketMask>>1)` — **identical** to `HashKeyToBucketIndex`.
  3. `ecx = [esi+0x14]` (=`table.mBuckets.mStart`), `lea ecx,[ecx+eax*4]` → bucket
     slot pointer (single dword stride per bucket index, N+1 slots — same convention
     documented on `FindHashListNode88`).
  4. `eax = *ecx` (bucket begin), `ecx = *(ecx+4)` (bucket end / next bucket's begin).
     If `begin==end` → empty bucket, return `table.mListHead` (sentinel).
  5. Walk `node = node->mNext` (`[eax]`) while `node->mKey < key` (`[eax+8]`, i.e.
     `HashListNode10::mKey` at header+8), stopping at bucket end → sentinel on
     exhaustion.
  6. Final check: `key >= node->mKey` → return `node`; else → sentinel
     (`[esi+8]`=`table.mListHead`).
- **This is `FindHashListNode88`'s exact algorithm**, single-key, over
  `HashTable<HashListNode10>` instead of `HashTable<HashListNode88>`. Confirmed
  offset-for-offset against the already-recovered `HashTable<TNode>` layout
  (`mListHead@0x08`, `mBuckets.mStart@0x14`, `mBucketMask@0x20`, `mBucketCount@0x24`
  — all match the asm reads above 1:1).
- **Only callee**: `__imp_ldiv` (CRT import), used purely as the hash-scramble's
  division step — same as `HashKeyToBucketIndex` itself, which nobody disputes is
  engine code.

### Verdict on `external_dependency` (explicit correction)

**WRONG. Reclassify as engine code, recover for real.** The DB note says
"All-external-callees thunk... no Moho/gpg engine references... Modern source uses
the underlying libraries directly." That is false on inspection: the function body is
a hash-bucket walk over `UICommandGraph::HashListNode10`/`HashTable<HashListNode10>`
— both engine-owned types declared in `CWldSession.cpp` — comparing engine struct
fields (`node->mKey`) and returning an engine sentinel (`table.mListHead`). The
*only* callee happening to be `__imp_ldiv` is an artifact of the automated
all-external-callees scanner counting leaf calls without looking at what the body
*does* with them — exactly the false-positive shape CLAUDE.md's "Engine code is not
external" clause calls out ("if you cannot point at an `__imp_*` IAT entry ... the
function is engine code" — the test is about the function *itself* being a thunk,
not about it calling one CRT leaf mid-algorithm). `HashKeyToBucketIndex` itself also
calls into the same `ldiv` scramble and nobody has ever proposed marking *that*
external. Batch-scan chain reaction (per the DB note: "chain reaction from batch 5
third-party-body scan") almost certainly mis-flagged `FUN_0082B870` too (see §6),
which cascaded into this one being flagged via its caller-adjacency, not real
analysis.

### Draft

```cpp
/**
 * Address: 0x0082C950 (FUN_0082C950, sub_82C950)
 *
 * IDA signature:
 * _DWORD *__usercall sub_82C950@<eax>(_DWORD *a1@<ebx>, int *a2@<edi>, _DWORD *a3@<esi>);
 *
 * What it does:
 * mMapD's analogue of FindHashListNode88: finds the node whose key exactly
 * matches `key` within its hash bucket, or returns the table's list sentinel
 * (`mListHead`) on a miss. Same Park-Miller scramble, same bucket-vector
 * convention (N+1 boundary slots for N buckets) as HashKeyToBucketIndex /
 * FindHashListNode88 - confirmed instruction-for-instruction against
 * 0x0082C950's own disassembly.
 */
[[nodiscard]] static HashListNode10* FindHashListNode10(
  HashTable<HashListNode10>& table, const std::uint32_t key
) noexcept
{
  const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, key); // see §2 templating note
  auto* const bucketSlots = reinterpret_cast<HashListNode10**>(table.mBuckets.mStart);
  HashListNode10* node = bucketSlots[bucketIndex];
  HashListNode10* const bucketEnd = bucketSlots[bucketIndex + 1u];

  if (node == bucketEnd) {
    return table.mListHead;
  }
  while (node->mKey < key) {
    node = node->mNext;
    if (node == bucketEnd) {
      return table.mListHead;
    }
  }
  return (key >= node->mKey) ? node : table.mListHead;
}
```

### Callsite evidence (Evidence class 1 — code xref)

- Callers (from `.meta.json`): `FUN_00826960` (2 code xrefs, `call sub_82C950` at
  `0x00826AAC`) and `FUN_0082B870` (`call sub_82C950` at `0x0082B873`).
- `FUN_00826960`: **not recovered** (`status: blocked`). Not satisfying reachability
  on its own.
- `FUN_0082B870`: **`callers_count: 0`, `incoming_xrefs_count: 0`** — a 6-instruction
  thunk (`sub_82C950(); return a1;`) that itself has no known caller anywhere in the
  binary per the exported xref data. It cannot supply reachability either, and its
  own `external_dependency` status is separately suspect (§6).
- **Net**: real code-xref evidence exists (class 1 satisfied), but the
  reachable-from-recovered-source requirement is currently unmet — flagged in §0.3.
  `CommandGraphEdge::mTouchCount` (already documented at `CWldSession.cpp:1688`,
  "confirmed by FUN_00826960/FUN_008275B0") independently corroborates that
  `FUN_00826960` really is this cluster's caller and that the search key is the
  edge's touch count — good independent confirmation the target function is real and
  wired at runtime, just not yet reachable from committed source.

---

## 2. Layout prerequisite: `HashListNode10` needs named fields

Currently (`CWldSession.cpp:1497`): `using HashListNode10 = HashListNode<0x10>;` — a
bare alias to the generic `{mNext, mPrev, mPayload[8]}` template. Every function in
this cluster needs typed `mKey`/`mWidth` access. Recommend replacing the alias with a
dedicated struct (same size/offsets, so `AllocateMapDListSentinel`,
`InitMapDBuckets`, `InitMapD`, and the existing `sizeof(...)==0x10` static_assert at
line 2330 are all unaffected):

```cpp
/**
 * mMapD's node: caches one Lua-computed "waypoint line width" per edge touch-count
 * key. Trivially destructible (no owned resources), unlike HashListNode88.
 */
struct HashListNode10
{
  HashListNode10* mNext; // +0x00
  HashListNode10* mPrev; // +0x04
  std::uint32_t mKey;    // +0x08 - CommandGraphEdge::mTouchCount
  float mWidth;          // +0x0C - cached CalculateWaypointLineWidth(mKey) result
};

/**
 * The value portion of one HashListNode10 - mirrors HashListNode88Value's role for
 * ConstructHashListNode10 (§4). Trivially copyable, so no relocate-helper is needed
 * (unlike RelocateDrawNode for the AB0 family's non-trivial payload).
 */
struct HashListNode10Value
{
  std::uint32_t mKey;  // +0x00
  float mWidth;        // +0x04
};
```

`ClearHashListNodes<TNode>`/`DestroyMap<TNode>` are already templated and already
handle "no `DestroyPayload`" via `if constexpr` — no changes needed there for
`HashListNode10`.

**`HashKeyToBucketIndex` should be templated** (currently hardwired to
`HashTable<HashListNode88>`): its body only ever touches `table.mBucketMask`/
`table.mBucketCount`, which live at fixed offsets regardless of `TNode` (proven by
this cluster's asm: `FUN_0082C950` reads `[esi+0x20]`/`[esi+0x24]` for
`HashTable<HashListNode10>`, the exact same offsets `HashKeyToBucketIndex` already
uses for `HashTable<HashListNode88>`). Recommend:

```cpp
template <typename TNode>
[[nodiscard]] static std::uint32_t HashKeyToBucketIndex(const HashTable<TNode>& table, std::uint32_t key) noexcept;
```

This is a mechanical generalization (identical body), backward-compatible with every
existing AB0 call site via template argument deduction — no behavior change, avoids
a would-be duplicate per `feedback_no_duplicate_container_helpers`.

---

## 3. FUN_0082FB10 → `ConstructHashListNode10`

- **Address**: `0x0082FB10`–`0x0082FB45` (19 instrs, 53 bytes).
- **Raw signature**: `_DWORD *__userpurge sub_82FB10@<eax>(_DWORD *a1@<esi>, int a2, int a3)`.
- **Caller-side register recovery** (asm-verified at the one real callsite,
  `FUN_0082B5E0` / `0x0082B7ED`, see §7): `esi` is loaded at `0x0082B77A`
  (`mov esi, [esp+14h+a3]`) from `InsertOrFindHashListNode10`'s own third parameter
  (the `{key,width}` value being inserted) and never reassigned before the call —
  so **`a1@esi` = `&valueSource`** (the `HashListNode10Value` being inserted), not a
  fresh local. `a2`/`a3` are pushed explicitly at the callsite:
  `push eax /*=v29[1]=insertionPoint->mPrev*/; push ebp /*=v29=insertionPoint*/`,
  i.e. **`a2 = next`, `a3 = prev`** — the classic Dinkumware `_Buynode(next, prev,
  val)` shape, identical argument order to the already-recovered
  `ConstructHashListNode88(next, prev, valueSource)`.
- **Body**:
  ```c
  result = sub_831C90(1u);      // allocate one 16-byte record
  if ( result ) *result = a2;               // mNext = next
  if ( result != (_DWORD *)-4 ) result[1] = a3;   // mPrev = prev
  if ( result != (_DWORD *)-8 ) { result[2] = *a1; result[3] = a1[1]; } // mKey, mWidth
  return result;
  ```
- **On the `-4`/`-8` guards** — task's hypothesis (SEH-funclet artifact) is **refuted
  on inspection, but the "not real logic" conclusion still holds for a different
  reason.** `FUN_0082FB10.meta.json` shows `callees_count: 1` (only `sub_831C90`,
  **no** `___CxxFrameHandler3_0`/`_CxxThrowException`, no exception-table data refs)
  — there is no SEH machinery here at all, so these are not funclet artifacts.
  Raw asm confirms they're literal `lea reg,[eax+N]; test reg,reg; jz` sequences —
  genuine (if paranoid) per-field null-guards against `result` being null, decomposed
  per-field because the compiler couldn't prove non-null after the first field write.
  **They are dead in practice**: `sub_831C90` (= `0x00831C90`, already recovered,
  see below) throws `std::bad_alloc` on overflow and otherwise calls global
  `operator new`, which itself never returns null (throws on failure) — so `result`
  is never null on any path that reaches these guards. Safe and correct to recover as
  straight-line code, exactly matching how `ConstructHashListNode88` already drops
  the binary's per-step conditionality in favor of clean field assignment (there via
  try/catch simplification instead of null-guard elision, but the same "known-always-
  true precondition, so simplify" principle).
- **Allocator dependency, already recovered and reusable**: `sub_831C90` = `0x00831C90`
  is one of 14 addresses folded into
  `gpg::core::legacy::AllocateChecked16ByteLane(std::uint32_t elementCount)` in
  `CheckedArrayAllocationLanes.h`/`.cpp` (confirmed: the doc comment at line 138 of
  the header explicitly lists `Address: 0x00831C90 (FUN_00831C90)` among the 16-byte
  lane's addresses — `HashListNode10` is exactly 16 bytes, so this is a correct,
  already-proven match, no new allocator work needed). **`CWldSession.cpp` does not
  yet `#include "gpg/core/containers/CheckedArrayAllocationLanes.h"`** — needs adding
  when this lands.

### Draft

```cpp
/**
 * Address: 0x0082FB10 (FUN_0082FB10, sub_82FB10)
 *
 * IDA signature:
 * _DWORD *__userpurge sub_82FB10@<eax>(_DWORD *a1@<esi>, int a2, int a3);
 *
 * What it does:
 * mMapD's analogue of ConstructHashListNode88: allocates one HashListNode10
 * via the shared 16-byte checked allocation lane (0x00831C90, one of the
 * addresses already folded into gpg::core::legacy::AllocateChecked16ByteLane),
 * links it explicitly via the caller-supplied next/prev (Dinkumware
 * `_Buynode(next, prev, val)` shape), then copies the trivially-copyable
 * {key, width} value. The binary's per-field null guards against the
 * allocation result are unreachable in practice - AllocateChecked16ByteLane's
 * underlying operator new never returns null (throws std::bad_alloc instead),
 * confirmed from 0x00831C90's own body - so they're dropped here exactly as
 * ConstructHashListNode88 already drops its own binary-side conditionality.
 */
[[nodiscard]] static HashListNode10* ConstructHashListNode10(
  HashListNode10* const next, HashListNode10* const prev, const HashListNode10Value& valueSource
)
{
  auto* const node = static_cast<HashListNode10*>(gpg::core::legacy::AllocateChecked16ByteLane(1u));
  node->mNext = next;
  node->mPrev = prev;
  node->mKey = valueSource.mKey;
  node->mWidth = valueSource.mWidth;
  return node;
}
```

### Callsite evidence

- **Class 1, code xref**: sole real caller is `FUN_0082B5E0` (`InsertOrFindHashListNode10`,
  §7) at `0x0082B7ED` (`call sub_82FB10`), confirmed via `.meta.json` incoming_xrefs
  and directly in the raw asm dump. (Other listed callers — `FUN_0082CAE0`,
  `FUN_0082DC90`, `FUN_008320C0` — are the analogous insert primitives for `mMapC`/
  another table; not this cluster's concern, noted for completeness.)
- Reachability: same caveat as §1 — depends on `FUN_0082B5E0` landing and, above it,
  `FUN_00826960`.
- Allocator dependency (`AllocateChecked16ByteLane`) is itself `recovered` and its
  address list already covers `0x00831C90` — verified by direct read of
  `CheckedArrayAllocationLanes.h`.

---

## 4. FUN_0082DD60 → `CheckedIncrementListSizeForMapD`

- **Address**: `0x0082DD60`–`0x0082DDEE` (40 instrs, 160 bytes).
- **Raw signature**: `int __fastcall sub_82DD60(unsigned int a1, int a2)` — `a1`=count
  (ecx), `a2`=pointer to a struct whose `+8` field is the size lane (edx).
- **Body** (verbatim structure, already correctly transcribed by the task prompt —
  independently re-read and confirmed):
  ```c
  v2 = *(_DWORD *)(a2 + 8);
  if ( 0x1FFFFFFF - v2 < a1 ) { /* build & throw std::length_error("list<T> too long") via CxxThrowException */ }
  result = a1 + v2;
  *(_DWORD *)(a2 + 8) = result;
  return result;
  ```
- **Threshold confirmed as genuinely different from the AB0 sibling**: `0x1FFFFFFF`
  here vs. `0x1FFFFFFu` in the already-landed `CheckedIncrementListSize`
  (536,870,911 vs. 33,554,431 — an 8x difference, not a typo/duplicate). Data refs in
  `.meta.json` confirm the string literal `"list<T> too long"` at `0x00E068A0` and the
  `std::length_error` vftable (`0x00D415B4`) — same throw *lane* as the AB0 variant
  (`RuntimeThrowContainerTooLong`, already shared/exported from `CrtRuntimeHelpers.cpp`),
  just a different table-specific overflow cap, exactly mirroring how
  `ThrowHashBucketVectorTooLong`/`CheckedIncrementListSize` already share
  `RuntimeThrowContainerTooLong` while keeping distinct per-table wrapper identities.
- Callers per `.meta.json` (5 distinct owners: `FUN_0082B5E0`, `FUN_0082CAE0`,
  `FUN_0082CB2A`(unowned chunk), `FUN_0082DC90`, `FUN_008320C0`) — this constant is
  shared across multiple hash tables beyond just mMapD; only `FUN_0082B5E0`'s call is
  this cluster's concern.

### Draft

```cpp
/**
 * Address: 0x0082DD60 (FUN_0082DD60, sub_82DD60)
 *
 * What it does:
 * Adds `count` to `sizeField` after an overflow guard against a legacy VC8
 * list max-size of 0x1FFFFFFF - genuinely different from
 * CheckedIncrementListSize's 0x1FFFFFF cap (confirmed: both throw the same
 * "list<T> too long" diagnostic via the same shared lane, but with distinct
 * per-table overflow constants; not a duplicate). Used by mMapD's insert
 * primitive (and by several sibling hash tables' own list-size lanes outside
 * this cluster's scope).
 */
static std::uint32_t CheckedIncrementListSizeForMapD(const std::uint32_t count, std::uint32_t& sizeField)
{
  if ((0x1FFFFFFFu - sizeField) < count) {
    RuntimeThrowContainerTooLong("list<T> too long");
  }
  sizeField += count;
  return sizeField;
}
```

### Callsite evidence

- **Class 1**: `FUN_0082B5E0` calls `sub_82DD60(1)` right after `sub_82FB10(...)`
  (§7) — `0x0082B6FA` per `.meta.json` incoming_xrefs, `call sub_82DD60`. Same
  reachability caveat as above.
- **DB correction needed**: current `status: recovered` citing
  `CrtRuntimeHelpers.cpp`/`RuntimeIncrementRecord16ListSizeCheckedLaneP` is fabricated
  — that symbol does not exist in `src/sdk` (repo-wide grep, zero hits). Must be
  reset before/when this lands for real.

---

## 5. FUN_0082CBA0 → `EnsureHashBucketVectorLengthForMapD`

- **Address**: `0x0082CBA0`–`0x0082CC0E` (53 instrs, 110 bytes).
- **Raw signature**: `int __userpurge sub_82CBA0@<eax>(unsigned int a1@<eax>, int a2@<ecx>, char a3)`
  — `a1`=`requiredLength` (eax), `a2`=`HashBucketVector*` (ecx, confirmed:
  `[ecx+4]`=`mStart`, `[ecx+8]`=`mFinish` match `HashBucketVector`'s layout), `a3`=
  fill value **received by plain value** on the stack (IDA typed it `char` because
  the body only ever takes its *address*, never reads it directly — the full 4-byte
  slot holds a real pointer, confirmed at the one real caller, §7, which pushes
  `edx=table.mListHead` as the sole stack arg).
- **Control flow, asm-verified (`0x0082CBA0`–`0x0082CC0B`):**
  - `eax=[ecx+4]` (mStart); if nonzero, `edx=([ecx+8]-eax)>>2` (currentLength) else 0.
  - `cmp edx, esi(=a1=requiredLength); jnb loc_82CBE5` → **truncate branch** if
    `currentLength >= requiredLength`.
  - **Growth branch** (`0x0082CBBD`–`0x0082CC0B` short path): recompute
    `currentLength`, `eax=[ecx+8]` (mFinish), **`lea edi,[esp+10h+arg_0]`** — takes
    the **address of its own by-value 3rd parameter** (`&a3`) — `esi -= edx`
    (`insertCount = requiredLength - currentLength`), then
    `push edi(&a3); push esi(insertCount); push eax(mFinish); call sub_82DE90`. This
    is the **exact same "receive fillValue by value, forward its address"** idiom
    already proven for `EnsureHashBucketVectorLength`'s own raw body (`0x0082D820`,
    see cross-check below) and for `ResetHashBucketVectorToNineSlots` /
    `PrepareForRebuild`'s `void* const mapCFillValue = ...; ResetHashBucketVectorToNineSlots(buckets, &mapCFillValue);`
    pattern already landed in this file.
  - **Truncate branch** (`0x0082CBE5`–`0x0082CC07`): `test eax,eax; jz` (mStart null →
    just return); else recompute `currentLength`; `cmp esi,edx; jnb` (no-op if
    already exactly/under length); else `eax = mStart + requiredLength*4`
    (new-finish target), `push edi(oldFinish=mFinish); push eax(newFinishTarget); ...
    call sub_82DE20`.
- **Cross-check against the already-landed `EnsureHashBucketVectorLength`
  (`0x0082D820`)**: its raw `.c` body is **structurally identical**
  (`if (v5>=a1) { if (...) return sub_82F1C0(&a3, a2, &result[a1], a2[2]); } else { ...
  return sub_82F210(a2, a2[2], a1-v6, &a3); }`) — i.e. the AB0 sibling's raw binary
  **also** takes its fill value by value and forwards `&a3` to both its growth callee
  (`sub_82F210` = the already-recovered `GrowHashBucketVector`, confirmed same
  address in that function's own doc comment) *and* its truncate callee
  (`sub_82F1C0` = `MoveDwordTailLaneB`, confirmed present in
  `LegacyContainerRuntime.cpp`). The already-landed `EnsureHashBucketVectorLength`
  deliberately elides `sub_82F1C0`'s call on the truncate path down to a bare
  `buckets.mFinish = buckets.mStart + requiredLength;` pointer update (its own doc
  comment: "degenerates to a pure pointer update ... because source and vector's own
  end always coincide on this path"). **This is precedent, not my own invention** —
  I'm mirroring an already-approved simplification, not introducing a new one.
- **`FUN_0082DE20`'s own body independently confirms the same degenerate-to-pointer-
  update conclusion for mMapD's truncate path**: `sub_82DE20(result, a2, a3, a4)`
  re-reads `v5 = *(a2+8)` (buckets.mFinish) **fresh**, which at call time is
  unconditionally equal to `a4` (also `buckets.mFinish`, passed in unchanged) — so
  `if (a4 != v5)` is always false, the copy loop never executes, and the net effect
  really is just `buckets.mFinish = a3; return a3;`. Already independently recovered,
  correctly, as `MoveDwordTailToGapAndCommitEnd`/`MoveDwordTailLaneA` in
  `LegacyContainerRuntime.cpp:1134` — **but that function currently has zero callers
  anywhere in `src/sdk`** (orphan). Recommend citing it in the doc comment (as done
  below) rather than calling it, mirroring the AB0 precedent exactly; if the
  orchestrator prefers strict parity with the *call graph* rather than the *value*
  precedent, calling `MoveDwordTailLaneA(&buckets.mFinish is wrong shape—see its real
  signature) is also viable but changes the established idiom for this table family
  — flagging both options rather than picking silently.

### Draft

```cpp
/**
 * Address: 0x0082CBA0 (FUN_0082CBA0, sub_82CBA0)
 *
 * IDA signature:
 * int __userpurge sub_82CBA0@<eax>(unsigned int a1@<eax>, int a2@<ecx>, char a3);
 *
 * What it does:
 * mMapD's analogue of EnsureHashBucketVectorLength: ensures the hash bucket
 * vector holds at least `requiredLength` elements, growing via
 * GrowHashBucketVectorForMapD when short (0x0082DE90), or truncating the tail
 * in place when already longer.
 *
 * Unlike EnsureHashBucketVectorLength's clean by-value fillValue parameter,
 * this variant's raw binary body receives fillValue by value on its own stack
 * slot and forwards *its address* to the growth callee - confirmed at
 * 0x0082CBD0 (`lea edi, [esp+10h+arg_0]`). EnsureHashBucketVectorLength's own
 * raw body (0x0082D820) does the exact same by-value-in/by-address-out dance
 * to its own growth/truncate callees (0x0082F210/0x0082F7A0's true sibling
 * 0x0082F1C0) and the already-landed recovery already elides that truncate
 * call down to a pointer update with the same justification reproduced here.
 */
static void** EnsureHashBucketVectorLengthForMapD(
  HashBucketVector& buckets, const std::uint32_t requiredLength, void* fillValue
)
{
  const std::uint32_t currentLength =
    buckets.mStart ? static_cast<std::uint32_t>(buckets.mFinish - buckets.mStart) : 0u;

  if (currentLength >= requiredLength) {
    if (buckets.mStart != nullptr && requiredLength < currentLength) {
      // Truncate in place - degenerates from the binary's move-tail-to-gap
      // call (0x0082DE20 / MoveDwordTailLaneA in LegacyContainerRuntime.cpp)
      // to a pure pointer update, because that helper's own copy source and
      // the vector's current mFinish always coincide on this path (confirmed
      // from 0x0082DE20's own disassembly). Mirrors
      // EnsureHashBucketVectorLength's identical truncate-branch elision.
      buckets.mFinish = buckets.mStart + requiredLength;
    }
    return buckets.mStart;
  }

  return GrowHashBucketVectorForMapD(buckets, buckets.mFinish, requiredLength - currentLength, &fillValue);
}
```

### Callsite evidence

- **Class 1**: sole caller `FUN_0082B5E0` at `0x0082B634` (`call sub_82CBA0`),
  confirmed in raw asm with `eax=newMask+2` (requiredLength), `ecx=&table.mBuckets`
  (loaded once at `0x0082B5FC: lea ecx,[edi+10h]` and held live through the call —
  verified no intervening `mov ecx` in between), `edx=table.mListHead` pushed as the
  fill value — i.e. `EnsureHashBucketVectorLengthForMapD(table.mBuckets, newMask + 2u,
  table.mListHead)`, parameter-for-parameter identical call shape to the already-
  landed `EnsureHashBucketVectorLength(table.mBuckets, newMask + 2u, table.mListHead)`
  call inside `InsertOrFindHashListNode88`.
- Same reachability caveat as above (depends on `FUN_0082B5E0` + `FUN_00826960`).

---

## 6. FUN_0082DE90 → `GrowHashBucketVectorForMapD`

- **Address**: `0x0082DE90`–`0x0082E101` (236 instrs, 625 bytes).
- **Raw signature**: `char *__thiscall sub_82DE90(int this, char *a2, unsigned int a3, char **a4)`
  — `this`=`HashBucketVector*` (ecx, not a real C++ `this`), `a2`=insertPosition,
  `a3`=insertCount, `a4`=**pointer to fill value** (`v5 = *a4` dereferenced once at
  entry, never again).
- **Byte-for-byte structural match against `FUN_0082F7A0`** (`GrowHashBucketVectorByFillRef`,
  already recovered): read both `.c` files side by side — every branch, every
  capacity check (`0x3FFFFFFF - count`), every in-place-shift-vs-reallocate split is
  identical; only the *internal* callee addresses differ (`sub_82FC70` vs
  `sub_8307F0`, `sub_831640` vs `sub_831910`, `sub_831690` vs `sub_831960`,
  `sub_8319C0` vs `sub_831C20`, `sub_8326C0` vs `sub_832710`, `sub_832B80` vs
  `sub_832BE0`). Not ICF-folded (different addresses, called from different sites,
  and the internal callee addresses genuinely differ so the machine code isn't
  byte-identical) — this is a separate compiled instantiation of the same generic
  "insert-with-growth" shape, one per hash-table family, exactly as `GrowHashBucketVector`
  (`0x0082F210`) is itself **also** structurally identical to both (confirmed: its own
  `.c` — `int __thiscall sub_82F210(int *this, _DWORD *a2, unsigned int a3, int *a4)`
  — has `v5 = *a4` at entry too, i.e. **the already-landed `GrowHashBucketVector`'s
  real raw binary body also takes fillValue by pointer**; the landed C++ signature
  deliberately flattens that to a plain-value parameter since the pointer is
  dereferenced exactly once and never re-read — same simplification
  `GrowHashBucketVectorByFillRef` already documents doing for its own caller-side
  bridging).
- **Conclusion: reuse, don't reimplement.** `GrowHashBucketVectorForMapD` should be
  the same one-line thin wrapper shape as the already-landed
  `GrowHashBucketVectorByFillRef`, forwarding into the single shared
  `GrowHashBucketVector` implementation. This directly answers the task's explicit
  question: yes, this pair is a genuine thin-fill-by-pointer wrapper exactly like the
  `FUN_0082F7A0` sibling the orchestrator already resolved — confirmed independently
  here, not assumed.

### Draft

```cpp
/**
 * Address: 0x0082DE90 (FUN_0082DE90, sub_82DE90)
 *
 * What it does:
 * mMapD's thin fill-value-by-pointer wrapper around GrowHashBucketVector -
 * instruction-for-instruction identical body shape to GrowHashBucketVectorByFillRef
 * (0x0082F7A0, mMapC's copy) and to GrowHashBucketVector's own raw body
 * (0x0082F210, which also takes its fill value by one level of pointer
 * indirection in the binary). A distinct compiled address, not ICF-folded
 * with either sibling (different internal callee addresses per table family),
 * so kept as its own named function per the one-address-one-function
 * invariant, even though its body is a single forwarding call.
 */
static void** GrowHashBucketVectorForMapD(
  HashBucketVector& buckets, void** const insertPosition, const std::uint32_t insertCount,
  void* const* const fillValueRef
)
{
  return GrowHashBucketVector(buckets, insertPosition, insertCount, *fillValueRef);
}
```

### Callsite evidence

- **Class 1**: sole caller `FUN_0082CBA0` (§5) at `0x0082CBD9` (`call sub_82DE90`),
  confirmed in `.meta.json` and raw asm.

---

## 7. FUN_0082B5E0 → `InsertOrFindHashListNode10`

- **Address**: `0x0082B5E0`–`0x0082B861` (215 instrs, 630 bytes).
- **Raw signature**: `int __userpurge sub_82B5E0@<eax>(_DWORD *a1@<edi>, int a2, int *a3)`
  — `a1`=`HashTable<HashListNode10>*` (edi; confirmed via field offsets:
  `a1[9]`=mBucketCount@0x24, `a1[3]`=mListSize@0x0C, `a1[5]`=mBuckets.mStart@0x14,
  `a1[6]`=mBuckets.mFinish@0x18, `a1[8]`=mBucketMask@0x20, `a1[2]`=mListHead@0x08 —
  all match `HashTable<TNode>` exactly); `a2`=hidden pointer to a
  `{HashListNode10* node; bool inserted;}` 5-byte out-struct (MSVC small-struct-
  return-by-hidden-pointer ABI — modeled as an explicit `bool& outInserted` +
  `HashListNode10*` return, matching `InsertOrFindHashListNode88`'s established
  signature convention rather than reproducing the raw ABI artifact); `a3`=pointer to
  the `{key,width}` value being inserted/searched.
- **Structurally verified line-for-line identical to the already-landed
  `InsertOrFindHashListNode88`** (`0x0082BFB0`), field-index-substituted for
  `HashListNode10`'s narrower payload:
  1. **Load-factor check**: `mBucketCount <= (mListSize >> 2)` → same condition,
     same field indices.
  2. **Incremental rehash** (only entered when load factor exceeded): same
     `bucketVectorLength - 1 > mBucketCount` branch choosing between "just bump the
     mask" vs. "grow the bucket vector then bump the mask", same
     `EnsureHashBucketVectorLengthForMapD(table.mBuckets, newMask + 2u, table.mListHead)`
     call (§5), same split-one-bucket rehash loop: raw masked hash **without**
     wraparound adjustment (`node->mKey ^ 0xDEADBEEF` → same Park-Miller scramble),
     same splice-onto-tail-before-sentinel logic, same cascade-bucket-boundary walk.
     Confirmed identical opcode-for-opcode shape by direct comparison of both `.c`
     bodies (`FUN_0082B5E0.c:61-124` vs. the landed `InsertOrFindHashListNode88`
     source `CWldSession.cpp:4730-4813`).
  3. **Post-rehash find-or-insert** (asm-verified at `0x0082B77A`–`0x0082B861`):
     `esi = a3` loaded at `0x0082B77A` and held live through the `ConstructHashListNode10`
     call — i.e. `a1@esi` in `FUN_0082FB10`'s call (§3) really is `&valueSource`, the
     caller's own third parameter, not a fresh temporary. Walk backward via `mPrev`
     from the bucket-end boundary comparing `node->mKey <= searchKey`; on an exact
     match (`node->mKey >= searchKey` after stopping) → **found**, `outInserted=false`,
     return existing node; otherwise fall through to `LABEL_33`: construct new node
     (`sub_82FB10(next=v29, prev=v29->mPrev, valueSource)`), bump size
     (`sub_82DD60(1)` = `CheckedIncrementListSizeForMapD`, §4), splice
     (`insertionPoint->mPrev = newNode; oldPrev->mNext = newNode;` — same order as
     the AB0 sibling, verified: `newNode`'s own `mPrev` field, set during
     construction from the *pre-splice* value, is read back to locate `oldPrev`
     *after* `insertionPoint->mPrev` has already been overwritten — matches
     `InsertOrFindHashListNode88`'s `oldPrev = newNode->mPrev; insertionPoint->mPrev =
     newNode; oldPrev->mNext = newNode;` sequencing exactly), cascade bucket boundary
     pointers, `outInserted=true`, return new node.

### Draft

```cpp
/**
 * Address: 0x0082B5E0 (FUN_0082B5E0, sub_82B5E0)
 *
 * IDA signature:
 * int __userpurge sub_82B5E0@<eax>(_DWORD *a1@<edi>, int a2, int *a3);
 *
 * What it does:
 * mMapD's hash-bucket insert lane - structurally identical to
 * InsertOrFindHashListNode88 (same load-factor check, same incremental
 * split-one-bucket rehash, same splice/cascade logic), confirmed line-for-
 * line against that already-landed sibling's source. Grows/rehashes when the
 * load factor is exceeded, then finds-or-inserts `key`, returning the
 * existing node when found (`outInserted=false`) or a freshly constructed
 * node linked into its bucket and the table's global list (`outInserted=true`,
 * `mListSize` bumped via CheckedIncrementListSizeForMapD).
 */
static HashListNode10* InsertOrFindHashListNode10(
  HashTable<HashListNode10>& table, HashListNode10Value& valueSource, bool& outInserted
)
{
  if (table.mBucketCount <= (table.mListSize >> 2u)) {
    const std::uint32_t bucketVectorLength =
      table.mBuckets.mStart ? static_cast<std::uint32_t>(table.mBuckets.mFinish - table.mBuckets.mStart) : 0u;

    if ((bucketVectorLength - 1u) > table.mBucketCount) {
      if (table.mBucketMask < table.mBucketCount) {
        table.mBucketMask = 2u * table.mBucketMask + 1u;
      }
    } else {
      const std::uint32_t newMask = 2u * bucketVectorLength - 3u;
      table.mBucketMask = newMask;
      EnsureHashBucketVectorLengthForMapD(table.mBuckets, newMask + 2u, table.mListHead);
    }

    auto* const rehashBucketSlots = reinterpret_cast<HashListNode10**>(table.mBuckets.mStart);
    const std::uint32_t splitBucketIndex = table.mBucketCount - (table.mBucketMask >> 1u) - 1u;
    HashListNode10* node = rehashBucketSlots[splitBucketIndex];
    HashListNode10* const splitBucketEnd = rehashBucketSlots[splitBucketIndex + 1u];

    if (splitBucketEnd != node) {
      for (;;) {
        const std::ldiv_t split = std::ldiv(static_cast<long>(node->mKey ^ 0xDEADBEEFu), 127773L);
        long scrambled = 16807L * split.rem - 2836L * split.quot;
        if (scrambled < 0) {
          scrambled += 0x7FFFFFFFL;
        }
        const std::uint32_t rehashedIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;

        if (rehashedIndex == splitBucketIndex) {
          node = node->mNext;
        } else {
          HashListNode10* const next = node->mNext;
          if (next != table.mListHead) {
            if (rehashBucketSlots[splitBucketIndex] == node) {
              std::uint32_t walkIndex = splitBucketIndex;
              for (;;) {
                rehashBucketSlots[walkIndex] = next;
                if (walkIndex == 0u) {
                  break;
                }
                --walkIndex;
                if (rehashBucketSlots[walkIndex] != node) {
                  break;
                }
              }
            }

            HashListNode10* const sentinel = table.mListHead;
            HashListNode10* const oldTail = sentinel->mPrev;
            node->mPrev->mNext = next;
            next->mPrev = node->mPrev;
            node->mNext = sentinel;
            node->mPrev = oldTail;
            oldTail->mNext = node;
            sentinel->mPrev = node;
          }

          std::uint32_t cascadeIndex = table.mBucketCount;
          while (cascadeIndex > splitBucketIndex && rehashBucketSlots[cascadeIndex] == table.mListHead) {
            rehashBucketSlots[cascadeIndex] = node;
            --cascadeIndex;
          }

          if (next == table.mListHead) {
            break;
          }
          node = next;
        }
      }
    }

    ++table.mBucketCount;
  }

  const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, valueSource.mKey);
  auto* const bucketSlots = reinterpret_cast<HashListNode10**>(table.mBuckets.mStart);
  HashListNode10* insertionPoint = bucketSlots[bucketIndex + 1u];

  if (bucketSlots[bucketIndex] != insertionPoint) {
    bool reachedBegin = false;
    for (;;) {
      insertionPoint = insertionPoint->mPrev;
      if (insertionPoint->mKey <= valueSource.mKey) {
        break;
      }
      if (bucketSlots[bucketIndex] == insertionPoint) {
        reachedBegin = true;
        break;
      }
    }

    if (!reachedBegin) {
      if (insertionPoint->mKey >= valueSource.mKey) {
        outInserted = false;
        return insertionPoint;
      }
      insertionPoint = insertionPoint->mNext;
    }
  }

  HashListNode10* const newNode = ConstructHashListNode10(insertionPoint, insertionPoint->mPrev, valueSource);
  CheckedIncrementListSizeForMapD(1u, table.mListSize);

  HashListNode10* const oldPrev = newNode->mPrev;
  insertionPoint->mPrev = newNode;
  oldPrev->mNext = newNode;

  if (bucketSlots[bucketIndex] == insertionPoint) {
    std::uint32_t cascadeIndex = bucketIndex;
    for (;;) {
      bucketSlots[cascadeIndex] = newNode;
      if (cascadeIndex == 0u) {
        break;
      }
      --cascadeIndex;
      if (bucketSlots[cascadeIndex] != insertionPoint) {
        break;
      }
    }
  }

  outInserted = true;
  return newNode;
}
```

### Callsite evidence

- **Class 1**: sole caller `FUN_00826960` at `0x00826B5E` (`call sub_82B5E0`) —
  `.meta.json` `callers_count: 1`. **Reachability not yet satisfied** (§0.3):
  `FUN_00826960` is `status: blocked`. This is the cluster's single biggest open
  item — recovering `InsertOrFindHashListNode10` without also landing (or
  pairing-in) `FUN_00826960` leaves it a committed-but-unreachable orphan per the
  source-level-invocation rule.

---

## 8. Summary table

| Token | Name | Real status (verified) | DB status (as-is) | Action needed |
|---|---|---|---|---|
| `FUN_0082C950` | `FindHashListNode10` | Open, real engine code | `external_dependency` (wrong) | Recover for real; reclassify |
| `FUN_0082B5E0` | `InsertOrFindHashListNode10` | Open | `blocked` (accurate) | Recover for real |
| `FUN_0082CBA0` | `EnsureHashBucketVectorLengthForMapD` | Open | `blocked` (accurate) | Recover for real |
| `FUN_0082DD60` | `CheckedIncrementListSizeForMapD` | Open (fake-marked) | `recovered` (**fabricated**) | Recover for real; fix DB |
| `FUN_0082FB10` | `ConstructHashListNode10` | Open (fake-marked) | `recovered` (**fabricated**) | Recover for real; fix DB |
| `FUN_0082DE90` | `GrowHashBucketVectorForMapD` | Open, trivial thin wrapper | `blocked` | Recover (1-line body) |
| `FUN_0082DE20` | `MoveDwordTailLaneA` (already exists) | **Already correct**, orphaned | `recovered` (accurate) | No new work; cite, don't duplicate; orphan-fix opportunity |
| `FUN_00831C90` | `AllocateChecked16ByteLane` (already exists) | **Already correct** | `recovered` (accurate) | No new work; add missing `#include` when wiring |
| `FUN_0082F7A0` | `GrowHashBucketVectorByFillRef` (already exists) | **Already correct** | `recovered` (accurate in CWldSession.cpp; the separate CrtRuntimeHelpers.cpp DB citation for the same address is a duplicate/stale name worth a look) | No new work; used as design precedent throughout |
| `FUN_0082B870` | (unnamed 6-instr thunk) | `callers_count: 0` — cannot supply reachability; itself suspicious as `external_dependency` misclassification bait | `external_dependency`, `depends_on: [FUN_0082C950]` (self-contradictory: external deps shouldn't depend_on internal engine tokens) | Out of scope for this pass; flag for a future zero-caller-fragment audit |
| `FUN_00826960` | (edge orientation-hint accumulator, out of scope) | `blocked`; is the **only** real reachability path into this whole cluster | `blocked` | Must land (or pair in) before/with this cluster to avoid a fresh orphan batch |

## 9. Suggested landing order

1. `HashListNode10`/`HashListNode10Value` layout upgrade + `HashKeyToBucketIndex`
   templating (§2) — pure refactor, zero behavior change, unblocks everything else.
2. `GrowHashBucketVectorForMapD` (§6) — trivial, no dependencies beyond the already-
   landed `GrowHashBucketVector`.
3. `EnsureHashBucketVectorLengthForMapD` (§5) — depends on #2.
4. `ConstructHashListNode10` (§3) — depends on #1 and the already-landed
   `AllocateChecked16ByteLane` (needs the missing `#include`).
5. `CheckedIncrementListSizeForMapD` (§4) — independent, can land anytime after #1.
6. `FindHashListNode10` (§1) — independent, can land anytime after #1.
7. `InsertOrFindHashListNode10` (§7) — depends on #1, #3, #4, #5.
8. Before/with #7 landing as non-orphan: recover `FUN_00826960` (or explicitly pair
   it into the same commit) so this cluster has a real, reachable, recovered caller —
   otherwise steps 2-7 land as a second orphan batch on top of the `FUN_0082DE20`
   orphan already sitting in the tree.
9. Fix the two fabricated DB entries (`FUN_0082DD60`, `FUN_0082FB10`) to reflect
   whatever the real landing actually does, and correct `FUN_0082C950`'s
   `external_dependency` misclassification (and flag `FUN_0082B870`'s for a follow-up
   look — it's out of this pass's scope but is DB-inconsistent as noted in §8).
