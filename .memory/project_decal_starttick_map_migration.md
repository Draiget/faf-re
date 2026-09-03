---
name: project-decal-starttick-map-migration
description: "A fifth hand-rolled tree: CDecalBuffer's start-tick map is msvc8::map<uint32, msvc8::list<...>>; two-level because the mapped type is itself a hand-rolled list"
metadata:
  node_type: project
  type: project
---

Found 2026-08-21 (batch 55). Fifth instance of
[[project-handrolled-rbtrees-are-the-wall]].

## The type

`DecalMapNode` (CDecalBuffer.cpp:39) is 0x20:

```
  left / parent / right        0x00 0x04 0x08
  startTick   uint32           0x0C          <- key
  bucketAllocatorCookie        0x10   \
  bucketHead                   0x14    }- a 0x0C list header = the mapped value
  bucketSize  uint32           0x18   /
  color                        0x1C
  isNil                        0x1D
```

So `msvc8::map<std::uint32_t, msvc8::set<CDecalHandle*>>`: value_type is
`pair<const uint32, set>` = 4 + 0x0C = 0x10, node = 0x0C + 0x10 = 0x1C with
colour/nil at 0x1C/0x1D, total 0x20. `CDecalStartTickMapStorage` is the usual
0x0C `{cookie, head, size}` header.

**Correction (batch 57):** the mapped value is a *set*, not a list. I first
recorded it as `msvc8::list<DecalBucket>` from the `{cookie, head, size}`
shape alone, but `DecalBucketNode` (CDecalBuffer.cpp:27) is
`{left, parent, right, handle, colour, isNil}` at 0x14 -- a red-black node,
not a list node. A 0x0C `{proxy, head, size}` header is common to both
containers, so it does not by itself distinguish them; read the node.

**This 0x20 node with nil at +0x1D is the same shape as the unattributed
family in [[project-ani-dumpskeleton-partial-root]]** (`FUN_007B4040` erase
plus rotates `FUN_007B4360`/`FUN_007B43C0`). Worth checking whether those
belong to this map or a sibling instantiation before recovering either.

## Why it is harder than the other four

The mapped type is **itself a hand-rolled tree**, so this is two migrations:

  - inner: `msvc8::set<CDecalHandle*>` -- node 0x14, links 0x0C, handle at
    +0x0C, colour/nil at +0x10/+0x11. **Byte-for-byte the same shape as the
    trail-segment owner pool** landed in 458d4cfe, so the same recipe applies.
    17 functions touch it.
  - outer: `msvc8::map<uint32, set>` -- 14 functions touch it, 2 of them the
    real API (`DestroyBucketTreeNodes`, `FindOrCreateStartTickBucket`).

Do the inner set first: the outer map's value type *is* the inner set, so
migrating it first makes the outer substitution mechanical.

No definition-only orphans at either level -- all interlock -- so this is the
trail-pool ordering (mechanics and API first, type last), not the
RRuleGameRules one.

82 references to `DecalMapNode`, 13 to `CDecalStartTickMapStorage`.

## The immediate prize

`FUN_0077A3C0` (252 instr) is the insert-with-rebalance -- the "CreateHandle
insert-side" left deferred in [[project-cdecalbuffer-tree-chain]] (90e6ffa).
It was the **last remaining entry** in the strict landable queue. All five of
its callees are already cited in the same file
(0x0077B0B0/0x0077B160 rotates, 0x0077B4F0 erase-range, 0x0077CE50 successor).

It cannot be landed as a per-type insert: that would add to the very debt the
migration removes, and the container-lane guard would reject the name. It
lands as a citation on `RbTree.h`'s `insert_at` *after* the type migrates.

## Attempt 1 (batch 57) reverted -- what was learned

Got as far as: header migrated to the two aliases, 43 errors, then 27
mechanics deleted leaving 39. Reverted rather than leave a shared file broken.

**The one-line payoff is confirmed.** `FindOrCreateStartTickBucket` returns a
pointer to `&candidate->bucketAllocatorCookie` -- i.e. a reference to the
mapped set -- and its only real call site is

```cpp
DecalBucketTreeStorage* const bucket = FindOrCreateStartTickBucket(&mStartTickBuckets, tick);
(void)FindOrInsertBucketNode(bucket, handle);
```

which is exactly `mStartTickBuckets[tick].insert(handle);`. That is what the
whole 31-function apparatus collapses to.

**Header shape that compiled:**

```cpp
using CDecalBucketSet          = msvc8::set<CDecalHandle*>;
using CDecalStartTickMapStorage = msvc8::map<std::uint32_t, CDecalBucketSet>;
```
plus a `class CDecalHandle;` forward declaration and includes of Map.h/Set.h.

**Three functions were removed twice** by the name-based cutter --
`AdvanceBucketNodeToSuccessor`, `DescendBucketLeftChainRuntime`,
`RetreatStartTickMapIterator`. A removal count above 1 is the over-deletion
signal from [[feedback-function-cutter-failure-modes]]; here it most likely
means genuine overloads (map-level and bucket-level variants sharing a name),
which the cutter cannot tell apart. **For this file, delete by explicit
line range from the function parser, or by exact literal Edit, not by name.**

Remaining after the mechanics went: 39 errors, all call sites of the deleted
helpers plus `CloneDecalBucketSubtreeRecursive`, which the name list missed.

Budget honestly: this is the largest of the five trees -- two levels, 31
functions, ~95 references -- and it wants a fresh context, not the tail of a
long turn.
