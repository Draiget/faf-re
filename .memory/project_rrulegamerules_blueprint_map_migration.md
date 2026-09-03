---
name: project-rrulegamerules-blueprint-map-migration
description: "18 uncited map-teardown emissions under RRuleGameRulesImpl::~RRuleGameRulesImpl are unlandable until RRuleGameRulesBlueprintMap becomes a real msvc8::map; scoped, not started"
metadata:
  node_type: project
  type: project
---

Found 2026-08-21 (batch 42) via the closure ranking in
[[reference-landable-now-query]]: root `0x00529700`
(`RRuleGameRulesImpl::~RRuleGameRulesImpl`) has **18 blocked, uncited
functions** beneath it, ~2350 instructions, in three clean shape groups:

| group | count | instrs | is |
|---|---|---|---|
| A | 7 | 74 each | `_Tree::erase(first, last)` -- compares `first` against `head->_Left` and `last` against `head`, and on the full range calls `_Erase(root)` then resets `_Root`/`_Lmost`/`_Rmost` to head and size to 0 |
| B | 7 | 246 each | the rebalancing single-node erase |
| C | 4 | 28 each | the RB rotate/relink helpers |

Seven of each because there are seven blueprint-map instantiations.

## Why it is not landable yet

The node layout is already fully modelled and matches the asm exactly --
`RRuleGameRulesBlueprintNode` is 0x30 with the `msvc8::string` key at +0x0C,
the value at +0x28, `mColor` at +0x2C and `mIsSentinel` at +0x2D, and it
already derives from `msvc8::Tree`. So these really are
`msvc8::map<msvc8::string, RBlueprint*>` members.

But `RRuleGameRulesBlueprintMap` is a **bare 12-byte struct**
`{mAllocProxy, mHead, mSize}`, not the container. So `msvc8::map`'s destructor
chain is never instantiated from source, and citing the 18 addresses on
RbTree.h/Map.h members would be paperwork -- the linker would emit none of
them. The source-level invocation rule forbids exactly that.

## The fix, when someone takes it

Migrate the member type to `msvc8::map<msvc8::string, RBlueprint*>` and let the
container's own members carry the addresses. Also fold
`DestroyBlueprintObjectsFromMap` (RRuleGameRules.cpp:2247), which walks
`mHead->left` by hand and deletes each `mBlueprint` without erasing -- the
binary leaves the nodes in place too, so that part is faithful and the map's
own destructor is what emits the 18 bodies afterwards.

**Size: 217 references across 4 files** -- `RRuleGameRulesBlueprintMap` (82),
`RRuleGameRulesBlueprintNode` (135), spanning `RRuleGameRules.{h,cpp}`,
`CArmyImpl.cpp` and `Sim.cpp`. Two of those are frequently held by other
agents, so take file leases first. This is a dedicated pass, not a batch
increment.

## LANDED 2026-08-21, commit 18210e05 -- 49 addresses, 962 lines removed

Third attempt succeeded. Two earlier ones were reverted for over-deletion.

**What made the difference was ordering, not a better cutter.** Reference
counts showed **33 of the 48 mechanics were already pure orphans** --
referenced only by their own definition. Deleting those needs no type change
and breaks no callers, and it dropped the error surface from 113 to 49 before
anything risky happened. Only then did the type migration go in.

Generalisable: **before any container migration, count references and delete
the definition-only functions first.** It is free, it is safe, and it shrinks
the dangerous part by more than half.

The other rule that held: every cut is verified brace-balanced and rejected if
the extracted text contains a `struct`/`class` opener. That is what stops the
failure mode where a cut eats a neighbouring type
([[feedback-function-cutter-failure-modes]]).

### Final address map

| member | count | what |
|---|---|---|
| `leftmost` | 11 | `head->left` begin lane |
| `lower_bound_node` | 13 | six walks + seven store-result adapters |
| `header` | 8 | the `end()` lane |
| map constructor | 7 | header initialisers |
| `buy_node` | 6 | per-table head-sentinel allocators |
| `find_node` | 4 | incl. 0x0052C420, already labelled `map_string_RBeamBlueprint::operator[]` |

### Scope was wider than the file

`Sim.cpp` held a **parallel copy** of the same mechanics (allocate,
ensure-head, find, three per-type probes, insert) and `CArmyImpl.cpp`
recursed the tree by hand for category-bit bounds. Both had to move in the
same commit. When migrating a type, grep the whole tree for its node type --
not just the file that declares it.
