---
name: project-uicommandgraph-drawnode
description: Fully-resolved layout of the UICommandGraph AB hash-node payload (0x78 at node+0x10), the fastvector inline-capacity stash idiom, and the leak fix landed in 182c629.
metadata:
  type: project
---

`UICommandGraph`'s two AB hash tables (`mMapAB0` +0x0D30, `mMapAB1` +0x0D58)
hold a **0x88-byte node** whose payload starts at **node+0x10** and is 0x78
bytes. Every helper in the cluster is passed `node+0x10`, not the node.

Landed 2026-08-14 as **182c629** (type + destructor + leak fix). All offsets are
pinned by `static_assert` in `src/sdk/moho/sim/CWldSession.cpp` and were verified
against `.asm`, not just the decompiler.

## Payload layout (P = node + 0x10)

| off | field | evidence |
|---|---|---|
| +0x00 | `CmdId mCommandId` (ctor writes -1) | 0x00824600; `*(v10)=cmdId` in 0x00826140 |
| +0x04 | `mHelperLink.mHead` | intrusive chain |
| +0x08 | `mHelperLink.mNext` | |
| +0x0C | `Wm3::Vector3f mPositionSum` | 0x00826140 accumulates unit pos |
| +0x18 | `float mWeight` (count; 1.0f for AB0) | |
| +0x1C | `mHasResolvedPosition` | CreateMeshes reads `[edi+2Ch]` |
| +0x1D | `mIsChainBoundary` | 0x00826140 `*(v10+29)` |
| +0x1E | `mIsVisible` (ctor writes 1) | |
| +0x20 | `void* mOwnerPx` | weak_ptr px |
| +0x24 | `sp_counted_base* mOwnerControl` | weak_release in dtor |
| +0x34 | `Wm3::Vector3f mPreviousCentroid` | prev node's avg, the edge start |
| +0x48 | `CommandGraphDwordLane mLaneA` (0x18) | |
| +0x60 | `CommandGraphDwordLane mLaneB` (0x18) | |

Still `field_0x28/0x2C/0x30/0x40/0x44` — typed placeholders, resolve when
0x008272A0 / 0x00827360 land.

## The fastvector inline-capacity stash (do not "fix" this)

`CommandGraphDwordLane` is the four-pointer `gpg::fastvector` shape
`{begin, end, capacity, inlineOrigin}` + 2 inline dwords, inline capacity **1**.

The destructor restores capacity with `capacity = *inlineOrigin` — a load
*through* the inline slot. That looks like a garbage read and it is not: the
grow helper at **0x0082E708** does
`if (begin == inlineOrigin) *inlineOrigin = capacity;` — it stashes the inline
capacity-end into the slot it is vacating, precisely so the reset can restore it
with one indirect load. Verified in `FUN_0082E6D0.c`. I nearly recorded this as
an engine bug; check the grow before ever calling an SBO restore broken.

## The leak that was there

`ClearHashListNodes` was templated over all three tables with the comment "the
hash-list nodes hold trivially-destructible payloads". That is true for the 0x10
table (0x0082FAB0 frees without destroying) and **false for the AB tables**:
their list-erase helper **0x0082EF80** calls `sub_826550(node+0x10)` and only
then `operator delete(node)`. Each cleared AB node was leaking two spilled
dword lanes plus one weak reference, on every clear and on `~UICommandGraph`.

Fixed by opting node types in through `HashListNode88::DestroyPayload` +
`if constexpr (requires ...)` in the template.

## What remains of the CreateMeshes cluster

`FUN_00828FB0` is still a comment-only stub. Behavioural core is **13 fns /
~1900 instrs**, all atomic under it (no member has an external recovered
caller), so it commits in one pass:

    826000(97) 826140(283) 826620(86) 824600(28) 826740(168) 826960(179)
    826BA0(27) 826C50(185) 826F10(281) 8272A0(65) 827360(154) 8275B0(268)

`sub_824600` (ctor) and `sub_826620` (copy-assign) are **written and verified**
but were deliberately NOT committed — their only caller is `sub_826140`, so
committing them now would create orphan helpers. Re-derive from the note above;
the natural wiring is `node.mDraw = UICommandGraphDrawNode{};`, which reproduces
the binary's ctor→assign→dtor temp sequence exactly.

Related: [[reference_closure_candidate_query]],
[[project_cuiworldview_render_vtable_cluster]].
