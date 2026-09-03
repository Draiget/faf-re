---
name: project-last-two-missing-deserializers
description: After Entity and CFormationInstance, exactly two serializer adapters remain whose member body is absent - PathQueue and CDecalBuffer. Both need one unrecovered helper first.
metadata:
  type: project
---

Swept all **444** `*Serializer::Deserialize` / `*Serializer::Serialize` emissions
and checked whether each adapter's callee body exists in `src/sdk`. After the
`Entity` (826ef83, cd077e9) and `CFormationInstance` (de0fe86, 3fd7b4a) work,
**exactly two remain**. Both are small but each is blocked on one helper a level
down - recover the helper first, then the body, then the adapter.

## 1. PathQueue

    PathQueueSerializer::Deserialize  0x00766970  (adapter, trivial)
      -> sub_76AD40                   0x0076AD40  38 instrs   ABSENT
        -> ReadPointerOwned_PathQueue_Impl  0x0076B570  82 instrs  DONE (b481382)

**The reader is landed**, so `sub_76AD40` is now writable. Note it needs the
full three-piece install pattern - there is **no** existing PathQueue serializer
lane in `PathTables.cpp` (only the generic `SerSaveLoadHelperInitRuntimeView`
layout at line 52). So it is: body + `PathQueueSerializer` helper class +
`register_PathQueueSerializer`, exactly like `EntitySerializer` (cd077e9) and
`CFormationInstanceSerializer` (3fd7b4a). Do not land the body alone - it would
be an orphan.

The slot argument is a `PathQueueRuntimeView*` (`PathTables.cpp:671`,
`mImpl` at +0x00, size == sizeof(PathQueue)).

`sub_76AD40` itself is easy once the reader exists - swap the pointer, tear the
old one down, free it:

    PathQueue::Impl* loaded = nullptr;
    archive->ReadPointerOwned_PathQueue_Impl(&loaded, &owner);
    prior = *slot; *slot = loaded;
    if (prior) { DestroyPathQueueImpl(prior->mBase);
                 UnlinkAndResetPathQueueNode(prior->mHeightSentinel);
                 ::operator delete(prior); }

That teardown is **already written** at `PathTables.cpp:725-731` (in the typeinfo
destroy lane) - copy it rather than re-deriving. `PathQueue::Impl` is fully
modelled (`PathTables.cpp:640`): `mOwner` +0x00, `mHeightSentinel` +0x04,
`mBase` +0x0C, size 0x88 - so `sub_765BE0((ImplBase*)(v3+12))` is
`DestroyPathQueueImpl(prior->mBase)` and the +4/+8 unlink is the height
sentinel. Note the two nodes are different: `DestroyPathQueueImpl` already
unlinks `mBase.mTraveler`, and the sentinel unlink is separate.

`ReadPointerOwned_PathQueue_Impl` (82 instrs) should mirror the recovered
`ReadPointerOwned_PathQueue` (0x00707460, also 82 instrs) almost exactly - same
size, same family.

## 2. CDecalBuffer -- the last one, and it needs a class modelled first

    CDecalBufferSerializer::Deserialize  0x00779C30  (adapter)
      -> sub_77F0F0                      0x0077F0F0  38 instrs  ABSENT
        -> sub_779D70                    0x00779D70  67 instrs  ABSENT
          -> sub_77A250                  0x0077A250  99 instrs  std::map internal
          -> sub_77A930                  0x0077A930  77 instrs  std::map internal
          -> ReadPointerOwned_CDecalHandle 0x0077D7A0  present

**`CDecalBuffer` does not exist as a type in `src/sdk`** - only forward
declarations in `ReadArchive.h:77`, `Reflection.h:148` and `Sim.h:33`. So this
is a type-modelling job before it is a transcription job, the same shape as the
`CFormationInstance` split
([[project-cformationinstance-split-blocks-saveload]]).

The two `sub_77A*` helpers are `std::map` internals (lower-bound and node
insert). Per the container/template-emission rule they should **not** be
recovered as standalone bodies - once `CDecalBuffer::map` is modelled with the
tree's map type, express the operations through its API and the two emissions
resolve to the container's own code.

`sub_779D70` itself is a loop: read a `CDecalHandle` owned pointer, unlink it
from its ring, insert it into the buffer's map keyed by
`mInfo.mStartTick`, repeat until the archive yields null.

### Order of work
1. Model `CDecalBuffer` (needs `CDecalHandle` and the map's key/value types).
2. Write `sub_779D70` against the modelled map.
3. Write `sub_77F0F0` (reads `ReadPointer_Sim` into `buffer->sim`, then an
   `IdPool` lane, then calls the above).
4. Add the adapter + registration, file-local like the PathQueue one (b78d914)
   if the types stay internal to their TU.

### CDecalBuffer layout evidence gathered (2026-08-17)

`CDecalBufferTypeInfo::Init` (0x00778F30) sets **mSize = 3312 = 0xCF0**.

The ctor (0x00779170, `CDecalBuffer(Sim*)`) names the fields in order:

    this->sim = sim;                       // +0x00
    IdPool::IdPool(&this->pool);           // +0x04 ...
    this->ptr = &this->decalhandleList;
    this->decalhandleList = &this->decalhandleList;   // self-linked ring head
    this->map._Myhead = <fresh node>;      // std::map, head self-linked
    this->map._Mysize = 0;
    this->vec1._Myfirst/_Mylast/_Myend = 0;
    this->vec2._Myfirst/_Mylast/_Myend = 0;

`this`-relative offsets observed in the ctor asm:

    +0x04 +0x0C +0x10 +0x14 +0x18 +0x1C +0x28      (IdPool interior)
    +0xCB8 +0xCC4 +0xCC8 +0xCD0 +0xCD4 +0xCD8 +0xCE0 +0xCE4 +0xCE8

**Tail resolved** by cross-reading `~CDecalBuffer` (0x00779270) and
`SwapVectors` (0x00779BB0). `SwapVectors` touches exactly +0xCD0/+0xCD4/+0xCD8
and +0xCE0/+0xCE4/+0xCE8, which are the `_Myfirst/_Mylast/_Myend` triples of two
`msvc8::vector`s (0x10 each, proxy word first):

    +0xCB8  decalhandleList   TDatListItem, self-linked by the ctor
                              (prev +0xCB8, next +0xCBC; `ptr` is the ctor's
                              name for the head pointer it writes there)
    +0xCC0  map               msvc8::map  (proxy +0xCC0, _Myhead +0xCC4,
                              _Mysize +0xCC8)
    +0xCCC  vec1              msvc8::vector (first +0xCD0, last +0xCD4, end +0xCD8)
    +0xCDC  vec2              msvc8::vector (first +0xCE0, last +0xCE4, end +0xCE8)
                              -> ends at 0xCEC; 4 bytes to the 0xCF0 size

Head is `sim` +0x00 then `IdPool pool` +0x04, whose interior the ctor and dtor
touch at +0x0C..+0x30.

**Still unresolved: the middle, ~+0x30..+0xCB8 (~3.1 KB).** Neither ctor nor
dtor touches it, but `CDecalBuffer::CreateHandle` (0x007793D0, 231 instrs) does
- it references +0x20, +0x44, +0xF0, +0xF4, +0x8D8, +0x900, +0x90C, +0x910,
+0x914. Those came from a bare offset grep, so **some may be on a different
object**: the function juggles `edi`/`eax`/`ebp`, and only `[edi+0CB8h]` /
`[edi+18h]` are confirmed `this`-relative. Track the registers before assigning
any of them.

Do not pad the middle to make `sizeof` reach 0xCF0. A class that asserts
correctly but is wrong in the middle is worse than no class at all - every
reflected read through it lands at a plausible-looking offset.

Other emissions that will pin the rest: `CDecalBuffer::CreateHandle`
(0x007793D0, 231 instrs), `~CDecalBuffer` (0x00779270, 163),
`SwapVectors` (0x00779BB0, 31 - names vec1/vec2).

### CreateHandle register facts (partial, 2026-08-17)

From the prologue of `CDecalBuffer::CreateHandle` (0x007793D0):

  - `operator new(0xD8)` -> **`CDecalHandle` is 0xD8 bytes**. Its result lives in
    `ebx` for the whole function, so `[ebx+N]` offsets are *handle* fields, not
    buffer fields.
  - `mov edi, [esp+24h+arg_0]` -> **`edi` is the `CDecalBuffer`**, passed as a
    stack argument (IDA types it `__usercall`, not `this` in `ecx`). This is why
    `[edi+0CB8h]` and `[edi+18h]` are buffer-relative.
  - `xor ebp, ebp` at entry, so every `[ebp+N]` is on some object assigned to
    `ebp` later in the body - **none of those are buffer offsets**.

So of the middle-region offsets seen in a bare grep (+0x20, +0x44, +0xF0, +0xF4,
+0x8D8, +0x900, +0x90C, +0x910, +0x914), the `[eax+...]` ones still need tracing
to whichever object `eax` holds at each point; several are likely on `ebx`
(the 0xD8 handle) or on a map node, not on the buffer. Resolve them one at a
time before adding any field.
