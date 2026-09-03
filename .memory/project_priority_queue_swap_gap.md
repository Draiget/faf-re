---
name: project-priority-queue-swap-gap
description: RESOLVED cc05033. The sim priority queue's sift helpers used std::swap where the binary calls a swap that also rewrites the position map and carries each slot's weak node across. Layout, queue type and swap all landed.
metadata:
  type: project
---

**RESOLVED.** Landed across d39c993 (slot layout), dc26259 (link pair is a
WeakPtr node), 56fa2fd (queue type) and cc05033 (the swap itself, plus both
sift helpers re-signatured). tucheck EXITCODE=0 throughout.

`FUN_00687530` is `gpg::PriorityQueue<SPropPriorityInfo>::Swap(i, j)`. It
does **three** things:

  1. swaps the two 20-byte entries (via `sub_687A70` twice, which is a
     move-assign that relinks a `TDatListItem` as it goes),
  2. rewrites the back-map: `a1->mVec._Myfirst[entry.mPriority] = index`
     for **both** entries,
  3. restores the intrusive list link it saved from entry `i` before the
     moves, walking the chain to find the node that pointed at it.

The recovered sift helpers open-code only the first part:

    src/sdk/moho/sim/SimRecoveryRuntime.cpp:3049
      SiftPriorityQueueEntryDownRuntime  (0x006875F0)
        std::swap(entries[index], entries[best]);

`std::swap` moves the bytes. It does not touch the back-map and does not
fix the list. A heap that sifts with it leaves `mVec._Myfirst` pointing at
stale positions, so any later lookup-by-id finds the wrong entry - and the
intrusive list ends up with nodes whose `mPrev` points into a moved slot.

## Why nothing is broken yet

`SiftPriorityQueueEntryDownRuntime` is `[[maybe_unused]]` - an orphan.
So is its sibling. Nothing in the recovered tree drives this queue yet,
which is why the gap has not shown up as a runtime fault. It will the
moment the queue's real driver lands.

## Layout RESOLVED from the asm - landed d39c993

Read straight off `FUN_00687530.asm`, no guessing left:

    entry +0x00  priority       ordering key
    entry +0x04  boundedTick    tie-break, only when priorities match
    entry +0x08  backLinkSlot   POINTER to the pointer that refers here
    entry +0x0C  nextInChain    POINTER to the next entry in the chain
    entry +0x10  id             index into the queue's position map

    queue +0x04  entry array base   (`mov eax,[eax+4]`)
    queue +0x14  position map base  (`mov edx,[eax+14h]`)

Two things that were typed wrong and are now fixed:

  - **+0x08/+0x0C are pointers, not counters.** The swap does
    `mov edx,[eax]` / `mov [eax],ecx` at 0x0068756B - it dereferences
    `[entry+8]` and stores its own stack temporary there. Only an
    intrusive link that must keep pointing at the entry behaves that way.
  - **+0x10 is the stable id**, not an opaque lane. 0x006875A0-0x006875B4
    rewrites `positionMap[id] = heapIndex` for both entries.

Stride confirmed by `lea ecx,[ecx+ecx*4]` + `lea edi,[eax+ecx*4]` = 20.

## CORRECTION: the link pair is a WeakPtr, and 0x00687A70 was never missing

`d39c993` typed +0x08/+0x0C as two `void*`. Wrong twice over - the
intrusive-link contract forbids `void*` for a prev/next pair, and it hid
what they are. Fixed in `dc26259`.

They are a **`WeakPtr<void>` node**. The "chain walk" in the swap is an
owner-chain relink, which is what an intrusive weak link does when the
object it observes is physically moved. And the move-assign the swap
calls twice, **0x00687A70, is already recovered** - it is
`CopyPrefixedWeakPtrDwordPayloadLane` in `moho/misc/WeakPtr.h:981`, whose
`PrefixedWeakPtrDwordPayloadLane` is this exact 20-byte shape (two
dwords, weak node, trailing dword). I had it on the to-recover list.

Lesson: an intrusive relink loop in a decompile is a **type signature**,
not just control flow. Before recovering one, grep the tree for the
link's owner type - here `WeakPtr` - because the relink helper has very
likely already been recovered under that type's name.

## The other model: EntityDb has a complete one

`EntityDb.cpp` models the same queue at a higher level as
`BoundedPropQueueRuntime`, and **its swap is correct**:

    SwapBoundedPropHeapEntries (EntityDb.cpp:1441)
        std::swap(queue.heap[lhs], queue.heap[rhs]);
        UpdateBoundedPropHandleMapping(queue, lhs);
        UpdateBoundedPropHandleMapping(queue, rhs);

That is the swap plus the position-map update - the two steps the
SimRecoveryRuntime sift helpers skip. So the sim-side block is the
duplicate, and it is the weaker of the two.

**Do not staple 0x00687530 onto `SwapBoundedPropHeapEntries`.** It is the
semantic counterpart, not a 1:1 layout recovery: the binary stores
entries **by value** in a 20-byte array and physically moves them (hence
the weak relink), while EntityDb stores `unique_ptr` and swaps owning
pointers, so nothing moves and no relink is needed. Same behaviour,
different layout.

## Queue type RESOLVED - landed 56fa2fd

    queue +0x00  msvc8::vector<Entry>          heap        (_Myfirst +0x04)
    queue +0x10  msvc8::vector<std::uint32_t>  positionMap (_Myfirst +0x14)
    sizeof = 0x20

`msvc8::vector` is `{proxy, _Myfirst, _Mylast, _Myend}` at 0x10 bytes, so
the first-element pointer sits four bytes into each vector. A vector at
+0x00 and another at +0x10 account for both observed offsets
(`mov eax,[eax+4]`, `mov edx,[eax+14h]`) with nothing left over.

## Where Swap's temporary step belongs - NOT the sim file

`WeakPtr<T>` has **no `operator=`**. The compiler-generated one copies
both members and relinks nothing, which is exactly why
`CopyPrefixedWeakPtrDwordPayloadLane` exists as an explicit helper. So

    temp = a;  a = b;  b = temp;

reproduces the original bug rather than fixing it.

The binary's swap does the two real moves through 0x00687A70 (that
helper), but builds its stack temporary inline: it copies the two
prefixes and the id, then re-points `*(a.ownerLinkSlot)` at the
temporary's weak node, guarded on the slot being non-null. That is
WeakPtr-internal pointer work and belongs **next to
`CopyPrefixedWeakPtrDwordPayloadLane` in `moho/misc/WeakPtr.h`**, not
open-coded in `SimRecoveryRuntime.cpp` - the fidelity contract keeps that
kind of link surgery out of behaviour code.

So the remaining shape is: add a "move lane to a temporary, relinking"
helper in WeakPtr.h, then `Swap` becomes three calls plus two map writes.

## What the fix still needs
  - a WeakPtr.h helper for the relinking move-to-temporary (see above),
  - a decision on which model owns this queue - EntityDb's is complete
    and safe but is not the binary's layout; the sim-side one is the
    binary's layout but incomplete,
  - both sift helpers re-signatured to take the **queue**, not the bare
    entry array. That is why they open-code `std::swap` today: from
    `(index, entries, count)` the position map is simply not reachable.

Then rewrite both sift helpers to call `Swap` by name instead of
`std::swap`, which is what [[project-solid-texture-operator-index]]
did for `map::operator[]` - same shape of defect: a recovered caller
open-coding a container operation the binary actually called, except
here the open-coded version is not even equivalent.

Callers of `Swap`, all three already in source:
`FUN_00686740`, `FUN_006867F0` (EntityDb.cpp:1513),
`FUN_006875F0` (SimRecoveryRuntime.cpp:3017).

## The general lesson

`std::swap` on a container element is a red flag whenever the container
keeps an index or an intrusive link. Grep for it in recovered heap /
priority-queue / sorted-vector code and check what the binary called
instead.


## How it was finally expressed

    staged adopts left's chain position   (LinkIntoOwnerChainHeadUnlinked)
    left  = right                          (forwards to 0x00687A70)
    right = staged                         (forwards to 0x00687A70)
    positionMap[left.id]  = lhs
    positionMap[right.id] = rhs
    staged drops out                       (UnlinkFromOwnerChain)

Two things worth keeping:

  - **Both `WeakPtr` primitives already existed** -
    `LinkIntoOwnerChainHeadUnlinked()` is exactly the binary's temporary
    adoption (`nextInOwner = *head; *head = this;`) and
    `UnlinkFromOwnerChain()` is exactly its closing walk-and-splice. The
    swap did not need any new link surgery, only the right two calls.
  - **The relinking move forwards to the recovered helper** through a
    documented cast, guarded by the size assert tying the queue slot to
    `PrefixedWeakPtrDwordPayloadLane`. Restating the owner-chain logic
    would have been a duplicate of 0x00687A70 - see
    [[feedback-no-duplicate-container-helpers]].

## The root cause was a signature

Both sift helpers took `(index, entries, count)`. The position map lives
on the **queue**, so there was physically nothing to update from inside
them - `std::swap` was the only thing that signature could express. The
fix was to take the queue.

Generalisable: when a recovered helper open-codes something the binary
called out to, check whether its **parameter list** can even reach the
state the real callee touches. A too-narrow signature silently forces the
incomplete version, and it looks perfectly reasonable in isolation.
