---
name: project_string_dtor_exposed_double_release
description: Adding ~msvc8::string cut memory 632.4M->243.8M but made freed blocks actually recycle, which turned a latent CParticleTexture double-release into a hard crash. Records the exact fault, why "delete this" faults at edx=0, and the two candidate owners.
metadata:
  type: project
---

## The trade this created

[[project_commander_crash_is_memory_exhaustion]] records the win: `~string()`
took allocator in-use from **632.4M to 243.8M** (retail is 293.3M), reproduced
across three runs (243.8 / 276.1 / 244.3).

The cost: **freed blocks now actually return to the freelist and get reused.**
While every string buffer leaked, a released-too-early object's memory stayed
stale-but-intact, so a double release was survivable. Now the block is recycled
and its first word overwritten, so the second release faults immediately.

**This is a latent bug being surfaced, not a bug being created.** Do not treat
the destructor as the defect.

## The fault, in full

```
[EXCEPTION] ACCESS_VIOLATION read from address 00000000
  main!moho::CountedObject::ReleaseReferenceAtomic+0x37   [CountedObject.cpp:55]
  main!`anonymous namespace'::ReleaseCountedTexturePointerRangeAndClear+0x27  [CEffectImpl.cpp:66]
  main!moho::CEffectImpl::~CEffectImpl+0x68                [CEffectImpl.cpp:127]
  main!moho::CEfxEmitter::~CEfxEmitter+0xA7                [CEfxEmitter.cpp:402]
  main!moho::CEfxEmitter::`scalar deleting destructor'
  main!moho::CEffectManagerImpl::PurgeDestroyedEffects+0x4F [CEffectManagerImpl.cpp:458]
  main!`anonymous namespace'::PurgeDestroyedEffects+0x1E    [Sim.cpp:7482]
  main!moho::Sim::AdvanceBeat+0x435                        [Sim.cpp:13574]
  ... CDecoder::DecodeAdvance ... CSimDriver::ThreadCreateSim
    eax=1251E810 ebx=3EB75A80 ecx=1251E810 edx=00000000
```

**Read how to interpret this** -- it is not a null `this`. `ecx` (the object) is
`1251E810`, non-null, and `ReleaseCountedTexturePointerRangeAndClear` null-checks
before calling. CountedObject.cpp:55 is `delete this;`, which is a **virtual**
destructor call: load the vptr, then call through it. `edx=00000000` is the
loaded vptr. So the object's **vtable pointer is zero** -- the block was already
destroyed and recycled. Refcount reached zero twice.

It is on the **sim thread**, in `Sim::AdvanceBeat`'s effect purge, so it kills
the sim -- which is why the commander stops appearing.

## Ruled out already -- do not re-audit

- `AssignParticleTextureRef` / `RetainParticleTextureRef` /
  `ReleaseParticleTextureRef` (`CEffectImpl.cpp:14-41`) are correct: retain new,
  release old, store; release nulls the slot.
- `ReleaseCountedTexturePointerRangeAndClear` null-checks each slot **and**
  writes `*begin = nullptr` after releasing, so running it twice on the same
  array is safe.
- `~CEfxEmitter` does not touch `mParticleTextures` at all -- only `mCurves`.

## FOUND AND FIXED -- commit `7e43fd61`

`CEffectImpl::OnInit` (`CEffectImpl.cpp`) created the texture, handed it to the
slot, **and then released it again**:

```cpp
CParticleTexture* texture = new CParticleTexture(paramName);
AssignParticleTextureRef(mParticleTextures.start_[paramIndex], texture);
ReleaseParticleTextureRef(texture);        // fabricated - not in the binary
```

That is the create-then-drop-my-reference idiom, correct only when the object
starts at refcount **one**. `CountedObject` starts at **zero** (`0x004228D0`
clears `mRefCount`), so the retain inside `AssignParticleTextureRef` was the
slot's only reference and the extra release deleted the texture the instant it
was stored, leaving `mParticleTextures[paramIndex]` dangling until
`~CEffectImpl` released it a second time.

**The binary proves it.** `FUN_00654460`: `0x006544BB` `operator new(0x2C)`,
`0x006544D5` `CParticleTexture::CParticleTexture`, `0x006544EF` `sub_4954F0`
(`AssignCountedParticleTexturePtr`, `0x004954F0`), then straight to the epilogue
at `0x006544F4` / `retn 8`. **No release lane is called.** The only release on
this function is the empty-name branch at `loc_654509`, which is the `else` arm.

Every other `CParticleTexture` creation site already had the right shape
(`CEffectManagerImpl::CreateLightParticle`, `WaveSystem`,
`CParticleTextureConstruct`) -- this was the only one.

**Lesson worth keeping:** a refcounted type whose constructor leaves the count at
**zero** inverts the usual COM/`AddRef` idiom. `new X(...)` followed by
"assign then release my temporary reference" is *wrong* here and reads exactly
like correct code. Check `CountedObject::CountedObject` before trusting any
release that follows a create.

## Earlier candidates (both cleared by the above)

1. **Deserialization does not retain.** `CEffectImplSerializer.cpp:62` does
   `archive->Read(ResolveFastVectorCountedParticleTextureType(),
   &object->mParticleTextures, gpg::RRef{})` -- the reflection layer writes raw
   `CParticleTexture*` into the vector. If that path does not `AddReference`,
   every deserialized effect holds borrowed pointers that `~CEffectImpl` then
   releases. `PurgeDestroyedEffects` destroying deserialized effects is exactly
   the observed stack.
2. **`CEfxTrailEmitter.cpp:441-455`** hand-rolls a retain/swap of
   `mParticleTextures[0]` and `[1]` into `texture0`/`texture1`. Check the retain
   counts on both arms.

## Also diagnosed in the same session: the resize crash

Different bug, same session, operator-reported ("on window resize at least"):

```
  !RaiseException / !CxxThrowException
  main!gpg::gal::ThrowGalErrorFromHresult   [D3D9Interfaces.cpp:3437]
  main!gpg::gal::DeviceD3D9::StretchRect    [D3D9Interfaces.cpp:7706]
  main!moho::CD3DDevice::SetViewRect        [CD3DDevice.cpp:1755]
  main!moho::WRenViewport::RenderCopyForRefraction  [WxRuntimeTypes.cpp:71164]
  ... wxWndProc -> STATUS_FATAL_USER_CALLBACK_EXCEPTION (0xC000041D)
```

`RenderCopyForRefraction` builds `sourceRect` from `mScreenPos`/`mScreenSize`
(the **new** window size) and blits into `mPrimaryTargetLocks[head]`. The
allocation guard at `WxRuntimeTypes.cpp:70132` only creates a target
**when the slot is empty** ("filled only when empty, so a device rebind restores
just the targets that were released"), so if a resize reaches this without
having released them, the surface keeps its **old** size, `StretchRect` gets an
out-of-bounds source rect, returns a failure HRESULT, and the throw escapes the
window procedure. The `StretchRect` throw itself is faithful -- the binary bakes
in the same `DeviceD3D9.cpp` 624/625/637 error line numbers.

This is a *different* bug from the 2026-08-04 one in
[[project_resize_crash_fixed_ondeviceexit]] (which was the missing release
before `Reset`); that fix still stands. `WxRuntimeTypes.cpp` was peer-locked
with uncommitted work, so this was diagnosed but not fixed.

Reproduce it without a human: launch under `dbgrun`, then drive
`user32!MoveWindow` against the game's `MainWindowHandle` from PowerShell.
