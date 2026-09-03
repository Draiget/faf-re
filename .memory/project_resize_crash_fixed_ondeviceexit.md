---
name: project-resize-crash-fixed-ondeviceexit
description: The resize crash is FIXED (8c26fa1) - WD3DViewport::D3DWindowOnDeviceExit was an empty stub so nothing released default-pool surfaces before Reset. Records the inverted-inheritance stub pattern to hunt for elsewhere.
metadata:
  type: project
---

Fixed 2026-08-04, commit 8c26fa1. Supersedes the "resize crash" entries in
[[project-resize-crash-depth-stencil-binding]].

## The bug

`IDirect3DDevice9::Reset` inside `DeviceD3D9::Func9` returned a failure
HRESULT and `ThrowGalErrorFromHresult` threw straight out through
`wxWndProc`. `Func9` itself matches the binary 1:1 - the fault was upstream.

`WD3DViewport::D3DWindowOnDeviceExit` was `{}`. D3D9 **refuses** a `Reset`
while any default-pool surface is still referenced, so a missed release is not
a quiet leak - it takes the whole resize path down.

## The pattern worth hunting

`WD3DViewport`'s slots really are bare `retn` in the binary; the work lives in
`WRenViewport` overrides. This tree models the inheritance **inverted**, so
the correct shape is *body on WRenViewport, WD3DViewport slot forwards* -
already done for `D3DWindowOnDeviceInit` and `D3DWindowOnDeviceRender`.
`D3DWindowOnDeviceExit` had been left as a genuine empty stub instead, and its
`bool` parameter had been dropped from the signature entirely.

**Check the other `WD3DViewport` slots the same way** - `RenderPreviewImage`
(0x0042BB20) is still `{}` and the binary has
`WRenViewport::RenderPreviewImage(bool)` at 0x007F7400 (vtable slot 134).

Vtable slots read from `ForgedAlliance.vftable_rtti.md` (`WRenViewport`
VFTABLE `0x00E405BC`): 131 OnDeviceInit 0x007F6B60, 132 OnDeviceRender
0x007F7B30, **133 OnDeviceExit 0x007F70F0**, 134 RenderPreviewImage
0x007F7400.

Callers: `CD3DDevice::InitContext` passes **false** (rebind - keep batchers,
only `MeshRenderer::Reset`); `CD3DDevice::Destroy` pushes **1** at 0x0042E786
(shutdown - drop batchers, `ClearBorder`, full `Shutdown`).

## Two supporting bugs it surfaced

- `CRenFrame::ResetTransientResources` only nulled `mVertexSheet` without
  calling `ID3DVertexSheet::Destroy` (vtable +0x04). Every binary site
  destroys first - see `RangeRenderer::ResetRenderResources` (0x007EE430):
  `if (v1) { (*(vtable+4))(v1); a1[26] = 0; }`. Also fixed Range and Vision,
  which share the helper.
- `Shadow`'s 0x007FE760 body was a file-private free function and
  `MeshThumbnailRenderer::ReleaseTargets` was private, so neither was
  reachable from its real caller. Both promoted to public members.

## Left undone

The `fullShutdown` branch omits the shared terrain/water global teardown at
0x00809E80 (~11 unmodelled file-scope globals: `sTextureBatcher`,
`waterFidelity`, `terrainDynamicTextureSheet`, `dynamicTextureSheet`,
`mTextureGridtest`, `texture_batcher`, ...). Shutdown-only bookkeeping, no
effect on the rebind path. Its own recovery item.

## Harness gotcha - do not misread this as a crash

`dbgrun` has a ~60s `WaitForDebugEvent` hang timeout. When the engine sits
idle in the message loop it prints `WaitForDebugEvent timeout/err 121 -
detaching` with a bogus `NtUserBeginPaint` stack and the process ends. That is
the harness, not the engine - check `exceptions seen: cpp=0 fault=0` on the
line below it. `scratchpad/runwincap.bat` captures that output (redirect
*inside* the batch; redirecting the outer `cmd /c runwinlog.bat` breaks the
launch).

Verified fixed: three successive resizes (900x700, 1180x860, 1024x768) survive
with `cpp=0 fault=0`.
