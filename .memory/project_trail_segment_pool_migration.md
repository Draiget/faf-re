---
name: project-trail-segment-pool-migration
description: "A fourth hand-rolled red-black tree: TrailSegmentPoolRuntime is msvc8::set<TrailSegmentBufferRuntime*>; 12 addresses, 18 mechanics, spans two files"
metadata:
  node_type: project
  type: project
---

Found 2026-08-21 (batch 55) by following the ICF-twin canonicals of the
CAniSkel rotates. Same family as
[[project-handrolled-rbtrees-are-the-wall]] -- this is the fourth instance.

## The type is settled

```cpp
using TrailSegmentPoolRuntime = msvc8::set<TrailSegmentBufferRuntime*>;
```

Node is 0x14: links at 0/4/8, the buffer pointer at +0x0C, colour and nil at
+0x10/+0x11 -- exactly `msvc8::set`'s layout for a 4-byte value. Header is the
usual 0x0C `{proxy, head, size}`. Ordering is by raw pointer
(`IsTrailSegmentPointerLess`), so the default `std::less` is correct.

## 12 addresses at stake

```
  0x0049EC00  node-array allocate      0x0049A7B0  node allocate + link
  0x00497E10  destroy subtree          0x00496000  find-or-insert
  0x00497E50  insert                   0x0049AD20  successor walk
  0x00498060  maximum   (+ 0x0087CC20) 0x00498080  minimum (+ 0x0087CC40)
  0x00498010  rotate left              0x004980C0  rotate right
```

The two rotates are the canonical bodies that `FUN_007B3590` / `FUN_007B3610`
are byte-identical ICF twins of -- verified byte-for-byte, 76B and 80B, so
those `skip` statuses are justified.

**Eight of the 18 mechanics carry no address at all** (sentinel test, black
test, min, max, lower-bound, find-equivalent, both fixups) -- invented
scaffolding, the same proportion as CArmyStats.

## Ordering matters, and it is the opposite of RRuleGameRules

There are **no definition-only orphans here** -- all 18 interlock -- so the
delete-the-free-ones-first trick does not apply.

Migrating the header first is wrong: removing `TrailSegmentPoolNodeRuntime`
while 95 references remain produces 115 errors at once. **Delete the 18
mechanics and rewrite the two real API functions first
(`AcquireTrailSegmentBufferFromOwnerPool`,
`ReturnTrailSegmentBufferToOwnerPool`), then migrate the type.**

## It spans two files

`CWorldParticles.cpp` keeps a parallel helper set --
`TrailSegmentPoolHeadNode`, `TrailSegmentPoolNodeRaw`,
`TrailSegmentPoolNodeWithNullLinksBlack`, `TrailSegmentPoolNodesRecursive`,
`TrailSegmentPoolStorage`, plus `ResetTrailSegmentPool`. Both files move in
one commit, exactly as `Sim.cpp` and `CArmyImpl.cpp` had to for
RRuleGameRules.
