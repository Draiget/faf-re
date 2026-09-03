---
name: project-skydome-dtor-stub
description: SkyDome::~SkyDome is an empty stub in EngineMethodStubs2.cpp while the binary's destructor is 601 instructions - a real teardown leak, and a false-recovered-caller for sub_815A00.
metadata:
  type: project
---

`SkyDome::~SkyDome() {}` - an **empty body** - sits in
`src/sdk/moho/EngineMethodStubs2.cpp:87`, while the emission at **0x00814CD0 is
601 instructions**. The header (`moho/render/SkyDome.h:89`) carries the address
annotation, so every sweep and every have-set treats it as recovered.

Consequences:

- **Teardown leak.** Whatever those 601 instructions release is never released.
  `SkyDome::Destroy` (0x008175D0) *is* properly recovered in `SkyDome.cpp:450`
  and clears seven texture handles plus the decal upload list, so the destructor
  presumably calls it and then tears down more - none of which happens.
- **`sub_815A00` is NOT related** - I asserted that first and it is wrong. The
  `call_edges` row says `FUN_00814CD0 -> FUN_00815A00`, but its `src_ea` is the
  *function start* (0x814CD0), and `FUN_00814CD0.asm` contains no call to it.
  `sub_815A00` is a **render** function (DeviceD3D9, matrices, `Clear`) whose
  real callers are FUN_008E76D0 and FUN_00944630.

  This is the second time a `call_edges.src_ea` has misled me this run (the
  first pointed mid-instruction). **Always confirm an edge by grepping the
  caller's `.asm` for the callee symbol** before building on it.

## To land

The destructor's real callees, read from its asm: `SkyDome::Reset()`,
`CResourceWatcher::~CResourceWatcher()`, `sub_81A550`, plus two indirect calls
and `operator delete`. `Reset` is the one to check for existing recovery first.

Recover 0x00814CD0 (and `sub_81A550` if absent), and **delete the stub from
`EngineMethodStubs2.cpp` in the same commit** - leaving it would give the linker
two definitions or silently keep the empty one.

## CLOSED (2026-08-17): SkyDome was the only real defect in that file

`~SkyDome` is recovered (b42e717) and the stub removed;
`ClearSkyDomeDecalUploadList` fixed to clear the count (d372c43).

**All seven other `{}` bodies in `EngineMethodStubs2.cpp` are legitimate.** Each
is an interface base declaration whose annotated address belongs to a *derived*
class, and every one of those derived implementations exists and is annotated:

    EntityCollisionUpdater::SetTransform -> CColPrimitive_Box::SetTransform    EntityCollisionUpdater.cpp
    IWldSessionLoader::Finalize          -> CWldSessionLoaderImpl::Func6       CWldSessionLoaderImpl.cpp
    IWldSessionLoader::SetCreated        -> CWldSessionLoaderImpl::SetCreated  CWldSessionLoaderImpl.cpp:226
    IWldSessionLoader::Update            -> CWldSessionLoaderImpl::Func5       CWldSessionLoaderImpl.cpp
    ICommandSink::AdvanceBeat            -> Sim::AdvanceBeat                   Sim.cpp:13324
    ICommandSink::EndGame                -> Sim::EndGame                       Sim.cpp:13506

**Do not re-sweep this file.** Two traps if you do: matching a method name
across classes gives false hits, and `rg -l <address>` returns only the *first*
file, so a function can look unannotated in its own `.cpp` when it is annotated
there - check the `.cpp` directly before concluding anything is missing.

### Original note (why SkyDome differed)

Checked all seven remaining `{}` bodies. Most are **interface base
declarations** whose header annotation points at the *derived* implementation -
`ICommandSink::AdvanceBeat` is annotated 0x00749F40, which is
`Sim::AdvanceBeat` (551 instrs) and is recovered separately in `Sim.cpp`. An
empty base body there is harmless; the vtable slot resolves to the override.

Do not sweep this file by "empty body vs large emission" alone - matching a
method name across classes produces false hits (`EntityCollisionUpdater::
SetTransform` matches `CColPrimitive_Box::SetTransform`, a different class).
The discriminator is whether the annotated address belongs to *this* class or to
a derived one.

`~SkyDome` is the real defect because it is a **concrete destructor** whose own
emission (0x00814CD0, 601 instrs) is the thing being stubbed - there is no
override to pick up the slack.

## Body shape (read 2026-08-17) - and the one layout question left

`FUN_00814CD0` is 232 decompiled lines, but **~190 of them are compiler-emitted
`boost::shared_ptr` member releases** (the `sp_counted_impl_p` locals v4..v18).
In C++ those happen automatically in reverse declaration order, so the recovered
body is small:

    SkyDome::~SkyDome()
    {
      Reset();                                  // 0x008175D0 region, recovered SkyDome.cpp:338
      ClearSkyDomeDecalUploadList(<head>);       // sub_81A550, recovered SkyDome.cpp:202
      // shared_ptr members and the CResourceWatcher base tear down implicitly
    }

All callees are present: `Reset` (SkyDome.cpp:338), `ClearSkyDomeDecalUploadList`
(SkyDome.cpp:202), `~CResourceWatcher` (CResourceWatcher.cpp:34).

**⛔ RESOLVED, and it exposes a second defect.** The destructor's asm is
unambiguous:

    lea  esi, [edi+0B4h]      ; arg = this + 0xB4
    call sub_81A550           ; ClearSkyDomeDecalUploadList(this + 0xB4)
    mov  eax, [esi+4]         ; head pointer is at +4 of that arg (= this+0xB8)
    push eax
    call operator delete      ; delete the head node
    mov  [esi+4], ebx         ; and null it

So the thing at **+0xB4 is a two-word owner struct** `{ ?, head }`, and
`sub_81A550` takes *that*, not the head node. The identical shape appears at
0x0081A210 (`sub_81A550(esi); delete [esi+4]; [esi+4] = 0`), confirming it is a
reusable owner-struct idiom rather than a one-off.

The constructor corroborates the +0xB8 half: it stores `sub_81A440`'s return
(a fresh self-linked node) into +0xB8 and 0 into +0xBC, with **no store at
+0xB4**.

### Consequence: SkyDome::Destroy is passing the wrong pointer

`SkyDome.cpp:452` calls `ClearSkyDomeDecalUploadList(mDecalUploadHead)` - the
head *node*. The binary passes the owner struct four bytes earlier. If
`sub_81A550` dereferences its argument's `+4` (as the two call sites imply),
the recovered call is off by one indirection.

**Confirm by reading `FUN_0081A550`'s own body** - does it use `[arg]` or
`[arg+4]` as the list head? Then fix both `Destroy` and the header
(`mPadB4` is not padding; it is the first word of the owner struct), and only
then write the destructor. Do not write the destructor first: it would bake in
whichever reading turns out wrong.
