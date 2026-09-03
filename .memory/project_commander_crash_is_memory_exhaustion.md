---
name: project_commander_crash_is_memory_exhaustion
description: TWO findings, one verified and one RETRACTED. VERIFIED - msvc8::string had no destructor and the engine used 2.16x retail's memory; adding it cut in-use from 632.4M to 243.8M, below retail. RETRACTED - that was NOT the crash cause; runs survived 44 minutes at 688M. The crash is heap corruption introduced between 10:54 and 14:26 on 2026-09-02.
metadata:
  type: project
---

## VERIFIED: the memory finding (commit `a5a072ff`)

`msvc8::string` had **no destructor** -- a documented deliberate deferral in
`String.h`. Every heap-backed string buffer leaked. The multiplier came from the
containers, not scattered locals: `msvc8::vector<T>` guards element teardown
with `if constexpr (!std::is_trivially_destructible_v<T>)`, so while `string`
stayed trivially destructible **every `msvc8::vector<msvc8::string>` freed its
own block and leaked every element's**.

Measured on SCMP_009 at Game time 00:00, `gpg` allocator `Heap: total / inUse`:

| | before | after | retail |
|---|---|---|---|
| in use | 632.4M | **243.8M** | 293.3M |

**388.6 MB recovered, and now below retail.** A second run measured 276.1M at
Game time 01:45. This finding is solid.

Safety checks done before adding it (all clean): no unions holding
`msvc8::string`; no `is_trivially_destructible`/`is_trivial` assertions on it;
the four `memmove`/`memcpy` relocation sites in `Vector.h` (3382, 3529, 5675,
6828) are all `is_trivially_copyable_v<T>`-guarded and `string` *already* failed
that trait; nothing outside `String.*` writes `.bx`; every hand-inlined tidy
(`AudioEngine.cpp:1281`, `WxRuntimeTypes.cpp:62266/64007/81581`,
`Vector.cpp:790`) does delete-then-stamp `myRes=15`, so a following destructor
is a no-op. One live hazard was found and fixed in the same commit:
`operator=(const string&)` lifted a temporary copy's fields out by hand, which
was only safe while the temporary had no destructor; it now takes ownership via
the move assignment.

## RETRACTED: memory exhaustion is NOT why it crashes

I committed `a5a072ff` claiming the 2.16x footprint was "what makes the process
crash". **That was wrong**, and a survey of the day's runs refutes it directly:

| log | heap in use | reached |
|---|---|---|
| `fx1` 02:49 | 691.7M | Game 00:27:21, no crash |
| `light1` 02:59 | 697.3M | Game 00:44:24, no crash |
| `nm1` 03:38 | 699.6M | Game 01:07:05, no crash |
| `cmdrverify2` 10:54 | 688.9M | Game 00:14:30, no crash |
| `simcrash1` 14:26 | 688.6M | Game 00:01:52, **crashed** |

688M was survivable for 44 minutes at 02:59 and fatal at 14:26. The footprint
did not change; the code did.

## What IS still true about the allocator

`AllocateFreeRegion` (`Global.cpp`, `0x00958660`) re-commits a recycled region
and **discards `VirtualAlloc`'s return value**, returning the record regardless:

```cpp
::VirtualAlloc(candidate->allocation, commitBytes, gAllocationType | MEM_COMMIT, PAGE_READWRITE);
gHeapCommitted += commitBytes;
return candidate;
```

**The binary does the same** -- both lanes, `0x009586F6` and `0x00958738`, go
straight from `call ds:__imp_VirtualAlloc` to `add Heap_Committed, edi` /
`mov eax, esi` / `retn`, with no test of `eax`. This is faithful, must stay, and
is **not** the defect. `gAllocationType` is `0` in our tree, so commits are plain
`MEM_COMMIT` -- also a red herring. See
[[project_main_exe_not_large_address_aware]] for the related 2GB ceiling, which
*is* a real gap.

## The actual crash: heap corruption, introduced 2026-09-02 between 10:54 and 14:26

Every commit in that window is mine: `e522e1dc` (curPose re-blend), `3dff30e6`
(MeshBatchKey mLod), `34ab0097` (frameCounter unsigned), `fd114bc5` (CAniPose
builds bones), `6a5eafe4` (sound pump), `2d7cb10a` (MeshBatch counters),
`9d496aed` (SetBoneEnabled recursion), then five linkage-only fixes. The two
that matter switched on **previously dormant** code: before `fd114bc5` every
pose had zero bones, and before `2d7cb10a` every MeshBatch counter was zero, so
neither the bone-palette fill nor the batch buffers ever ran.

Four distinct wild-pointer faults observed, all consistent with one corruption:

1. `luaH_getstr` reading `0x592B5600`, a `MEM_RESERVE`/`PAGE_NOACCESS` page.
2. `msvc8::list::_Alloc_proxy` under `Unit::InitializeArmor` (operator's report).
3. `TDatListItem<CTaskThread>::ListUnlink` writing `0x16820007` (odd address),
   from `CTaskStage::UserFrame` -- the task list smashed.
4. `CountedObject::ReleaseReferenceAtomic` null write from
   `ReleaseCountedTexturePointerRangeAndClear` (`CEffectImpl::~CEffectImpl`),
   **on window resize**, per the operator.
5. `assign_owned`'s `memcpy` under `SNetCommandArg`'s copy in
   `cfunc_GpgNetSendL` (operator's, lobby-host path).

### Already checked and CLEARED -- do not re-audit

- **`MeshBatch::Initialize` offsets are faithful.** Read against
  `FUN_007E6F60.asm`: `[edi+18h]`→mVertexCount, `[edi+20h]`→mIndexCount,
  `imul 55555556h`→mTriangleCount, `[edi+0Ch]`→**mSkinBoneCount**,
  `[edi+2Ch]-[edi+0Ch]`→mAttachCount, and
  `mov eax,50h; cdq; idiv ecx; mov [esi+24h],eax` = `80 / mBoneCount`. All match.
- **`FastVectorRuntimeReallocateInsert` handles inline storage correctly** --
  `if (oldBegin == view.metadata) stash sentinel; else delete[] oldBegin;`, and
  `CAniPoseBoneArray`'s 4 header pointers map onto the view's
  `{begin,end,capacityEnd,metadata}` with `mOriginal` at +0x0C. `mInlineStorage`
  at +0x10 is exactly one 0x4C-byte bone.
- **`FastVectorN` shadows both `Reserve` and `PushBack`**, so the base's
  unguarded `delete[] start_` is not reachable on inline storage.

`ResizePoseBoneStorage` still goes through `AsFastVectorRuntimeView`, which
CLAUDE.md RULE ONE hard-prohibits; it is the next thing to replace regardless of
whether it is the corrupter.

Related: [[reference_retail_engine_ab_oracle]],
[[project_canipose_empty_bones_hid_every_unit]],
[[project_meshbatch_initialize_zeroed_every_counter]].
