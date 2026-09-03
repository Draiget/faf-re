---
name: project-cdecalbuffer-deserialize-gap
description: CDecalBuffer is the last one-sided serializer. Layout and both read bodies are fully decoded here; the only blocker is that mStartTickBuckets is hand-rolled instead of msvc8::map<uint32,msvc8::set<CDecalHandle*>>.
metadata:
  type: project
---

`CDecalBuffer` is the **last** `*Serializer` whose load side is missing (443 of
444 adapters have bodies). `CDecalBufferSerializer.cpp` has the whole save side
and sets `mLoadCallback = nullptr`.

Two earlier notes are **stale** - both said this needed the class modelling
first. It does not: `moho/render/CDecalBuffer.h` already models it, and the
layout is confirmed correct against the ctor asm (0x00779170), field for field:

    +0x0000 Sim* mSim                     mov [esi], eax
    +0x0004 uint32 mReserved04            never written (same idiom as IdPool::mReserved04)
    +0x0008 IdPool mPool                  lea ecx,[esi+8]; call IdPool::IdPool  (0xCB0 -> ends 0xCB8)
    +0x0CB8 CDecalHandleList mHandleListHead   [eax]=eax, [eax+4]=eax (self-linked)
    +0x0CC0 CDecalStartTickMapStorage     head +0xCC4 (fresh node, isNil at node+0x1D), size +0xCC8
    +0x0CCC msvc8::vector<SDecalInfo> mVisibleDecals
    +0x0CDC msvc8::vector<uint32> mPendingHideObjectIds
    +0x0CEC uint32 mPendingHideObjectIdsAux
            sizeof == 0xCF0

The "unresolved ~3.1 KB middle" in the old notes was simply `IdPool`
(`sizeof(IdPool) == 0xCB0`). It sits at +0x08, **not** +0x04 - `lea ecx,[esi+8]`.

## Both missing bodies, fully decoded

`sub_77F0F0` (0x0077F0F0, 38 instrs) is the exact mirror of the recovered
`CDecalBufferSaveCallback` (`sub_77F160`):

    ReadPointer_Sim(&buf->mSim, ar, &ref);
    ar->Read(CachedIdPoolType(), &buf->mPool, RRef{});   // lazy IdPool::sType lookup
    ReadDecalHandles(buf, ar);                           // = sub_779D70

`sub_779D70` (0x00779D70, 67 instrs) reads owned `CDecalHandle*` until null.
Per handle:

  1. **Unlink** its list node from wherever the read left it:
     `next->prev = prev; prev->next = next`.
  2. **Self-link** it (`node->next = node->prev = node`).
  3. **push_front** onto `mHandleListHead`: `node->next = head.mNext;
     node->prev = &head; head.mNext = node; node->next->prev = node`.
     Note this **reverses** the write order - `WriteDecalHandles` walks
     `mNext` forward. Mirror it anyway; it is what the binary does.
  4. If `handle->mInfo.mStartTick != 0`, insert into the start-tick map:
     `sub_77A250(&map, &startTick)` (find-or-insert the node) then
     `sub_77A930(node, &handle, scratch)` (insert into that node's bucket).

## The one blocker: the map is hand-rolled

`DecalMapNode` is exactly an `msvc8::map<std::uint32_t,
msvc8::set<CDecalHandle*>>` node - `left/parent/right`, `startTick` +0x0C, a
nested 12-byte container triplet +0x10..+0x1C, `color` +0x1C, `isNil` +0x1D,
size 0x20. But `mStartTickBuckets` is modelled as a raw
`{allocatorCookie, head, size}` triplet with hand-written tree helpers, so
there is **no container API to call** and step 4 cannot be written without
either duplicating RB-tree insert (forbidden - see
[[feedback-no-duplicate-container-helpers]]) or retyping first.

`msvc8::set` exists (`legacy/containers/Set.h`), so after a retype step 4 is:

    if (handle->mInfo.mStartTick != 0) {
      mStartTickBuckets[handle->mInfo.mStartTick].insert(handle);
    }

**Do the retype as its own pass first.** Blast radius is ~92
`DecalMapNode`/`DecalBucketNode` references in `CDecalBuffer.cpp` across 5
helpers (`AllocateMapHeadNode`, `DestroyMapNodes`, `FindStartTickBucketNode`,
`RetreatStartTickMapIterator` + adapters). Several are already
`[[maybe_unused]]` orphans, i.e. existing debt the retype clears. Do not bundle
it with the deserializer - land the container change, then the three read
bodies plus the adapter and `mLoadCallback`.
