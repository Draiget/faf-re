---
name: project-gal-device-vtable-slot-mismatch
description: gpg::gal::Device declares 21 slots as no-arg purecallN() stubs, so DeviceD3D9 never overrides them - DeviceD3D9's vtable is 71 entries where the binary has 50. Fatal for any base-Device* dispatch. Lists the broken slots and the fix pattern.
metadata:
  type: project
---

Established 2026-08-04, fixed for the reachable cases in cb6da91.
Workspace-local replacement for the older
`~/.claude/projects/.../project_gal_device_vtable_mismatch.md`.

## The defect

`gpg/gal/Device.hpp` carries placeholder slots spelled
`virtual void purecallN() {}` - no arguments, empty body. In the binary these
are pure virtuals holding the backend's **real signature**; the reconstruction
kept the slot but lost the signature.

`DeviceD3D9` declares the real method at each of those positions, but a
different name/signature **does not override**. The compiler appends the
backend method past the base's 50 slots and the placeholder stays at the
indexed position.

**Broken slots (21): 5, 8, 10-24, 32, 40, 41, 42.**
`DeviceD3D9`'s vtable is 71 entries where the binary has 50.

Affected methods: GetModesForAdapter(5), GetPipelineState(8), CreateTexture(10),
CreateVolumeTexture(11), CreateCubeRenderTarget(12), CreateDepthStencilTarget(13),
CreateVertexFormat(14), CreateVertexBuffer(15), CreateIndexBuffer(16),
CreateRenderTarget(17), StretchRect(18), UpdateSurface(19), Func3(20), Func4(21),
Func5(22), GetTexture2D(23), Func7(24), InitCursor(32), SetVertexDeclaration(40),
SetVertexBuffer(41), SetBufferIndices(42).

## Why it only sometimes bites

A normal `deviceD3D9->Method()` call binds to the **appended** slot and reaches
the correct body - inert. It is fatal only when something reaches a backend
method **through a base `Device*`**, which fails two ways at once:

1. the empty stub runs instead of the real body, so output parameters are left
   untouched (then dereferenced null by the caller), and
2. a `__thiscall` callee pops its own arguments - a no-arg stub pops 0 where
   the caller pushed N, so the debug CRT's `_RTC_CheckEsp` traps on return.

That is exactly the **window-resize crash**: `EffectD3D9::OnReset` reached
`GetPipelineState` by hand-indexing `vtable[8]`, from
`CD3DDeviceResources::InitResources` <- `CD3DDeviceSingleton::InitContext` <-
`SyncSupComFrameClientSizeAndViewport`. Slot 14 had the same bug via both
`HardwareVertexFormatterD3D9::SelectVertexFormatToken` and the float16 variant,
unhit only because nothing had exercised the hardware vertex formatter yet.

## The fix pattern - do this, not vtable indexing

Reach backend methods with a typed cast, the way `Device::InitCursor`
(Device.cpp) already does. `D3D9Interfaces.cpp` now has `ActiveDeviceD3D9()`:

```cpp
[[nodiscard]] DeviceD3D9& ActiveDeviceD3D9()
{
    return *static_cast<DeviceD3D9*>(Device::GetInstance());
}
```

Slot 9 (`CreateEffect`) took the other route - its real signature was hoisted
onto the base so the override binds. Either is fine; hand-indexing is not.

**Do NOT "fix" this by adding another `Invoke*` helper that indexes the vtable.**
That is what caused the crash.

## Remaining debt

The full repair is to give every `purecallN` its real signature so the backend
genuinely overrides and the vtable is 50 entries again. That needs the D3D9
wrapper types (`TextureD3D9`, `PipelineStateD3D9`, `VertexFormatD3D9`, ...) to
derive from their GAL base interfaces first, since the base cannot name backend
types - **none of them do today** (`class PipelineStateD3D9` etc. have no base,
while `gpg/gal/PipelineState.hpp` exists as an all-purecall skeleton). Not
attempted in cb6da91.

`DeviceD3D10` does **not** derive from `Device` at all, so it is unaffected by
base-class changes - but `D3D10Interfaces.cpp` still has four `InvokeDevice*`
vtable-indexing helpers on a `Device*`, which is unsound by construction there.
Unreachable while the game runs D3D9.

Legitimately-raw vtable dispatch that must stay: the `InvokeEffect*` helpers in
`D3D9Interfaces.cpp` (ID3DXEffect) and everything in `StateManagerD3D9.cpp`
(IDirect3DDevice9). Those are real COM interfaces with no header.

Related: [[project-resize-crash-fixed-ondeviceexit]] (the *previous* resize
crash - a missed release path, different root cause),
[[project-resize-crash-depth-stencil-binding]]
