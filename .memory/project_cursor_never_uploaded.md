---
name: project-cursor-never-uploaded
description: FIXED (0082281) - the cursor texture never loaded because CD3DDeviceResources::GetTexture bypassed the resource manager, so mount-point paths were never resolved through the VFS.
metadata:
  type: project
---

# FIXED (0082281): cursor texture never loaded

**Correction:** an earlier pass concluded `selectable.dds` "does not exist" and
that cursors are only animated frames. That was wrong - the search missed the
`gamedata/` archives. `gamedata/textures.scd` contains
`textures/ui/common/game/cursors/selectable.dds`, and `skins.lua` really does
ask for that exact un-suffixed name for `DEFAULT`. The real cause was the
loader, below.

The user reported "we do not have in-game cursor change". The cursor is never
drawn **at all**, not merely failing to change shape.

## The chain (all measured, 2026-08-11)

    CURSORTEX SetDefaultTexture path=/textures/ui/common/game/cursors/selectable.dds
              loaded=00000000 cur=00000000 def=00000000
    CURSOR ShowCursor show=0 ready=1 srcReady=0
    CURSOR ShowCursor show=1 ready=1 srcReady=0
    (no "CURSOR SetCursor" line at all)

- `CMauiCursor::SetDefaultTexture` asks for
  `/textures/ui/common/game/cursors/selectable.dds` and
  `CD3DDeviceResources::GetTexture` returns **null**.
- so `mTexture` stays null, so `MAUI_UpdateCursor`'s
  `if (mTexture != nullptr) device->SetCursor(...)` never fires,
- so `CD3DDevice::SetCursor` is never called, `mCursorContext.pixelSource_`
  stays null (`srcReady=0`), and `ShowCursor(true)` shows an empty surface.

## Why the load fails

**That file does not exist.** Cursors ship as animated frame sequences. Verified
by listing `gamedata/textures.scd`:

    textures/ui/common/game/cursors/selectable-01.dds
    textures/ui/common/game/cursors/selectable-02.dds  ... etc

There is no `selectable.dds`. Same for every stem: attack, move, patrol,
reclaim, repair, guard, capture, ferry, launch, load, transport, unload,
waypoint-hover, n_s / ne_sw / nw_se / w_e, ...

So this is **not** a VFS bug and not the texture-loading bug fixed in `6c150a5`.
The panel/button bitmaps that render fine go through a different loader
(`CD3DBatchTexture::FromFile`), not `ID3DDeviceResources::GetTexture`.

## Where to look next

The frame-sequence expansion is missing somewhere between the Lua call and
`GetD3DTextureResourceFromPath`. Candidates, in order:
 1. `CD3DDeviceResources::GetTextureSheet` (sits directly below `GetTexture` in
    `CD3DDeviceResources.cpp` ~line 502) - a sheet/animation lane that the
    cursor path may be supposed to use instead of `GetTexture`.
 2. `cfunc_CMauiCursorSetDefaultTextureL` dropping a frame-count argument.
    Measured earlier: `argc=4`, types (string, number, number) - i.e.
    `SetDefaultTexture(self, path, hotspotX, hotspotY)`. If the binary's
    signature carries a frame count, our recovery lost it.
 3. `GetD3DTextureResourceFromPath` itself needing the `-%02d` convention.

Check the binary's `CMauiCursor::SetDefaultTexture` (0x0078CD80) and
`SetTexture` (0x0078CCA0) against ours before changing anything - ours look
like faithful recoveries, so the gap is more likely one level down.

## Probe recipe (cheap, one build)

Log in `CMauiCursor::SetDefaultTexture` the `texturePath` and
`loadedTexture.get()`; log in `CD3DDevice::SetCursor` / `ShowCursor` the
`IsCursorPixelSourceReady()` state. That reproduces the whole chain above in
one run.

Related: [[project-splash-click-crash-solved]],
[[project-gal-device-vtable-mismatch]] (NOT the cause here - `CD3DDevice::SetCursor`
uses the `static_cast<DeviceD3D9*>` workaround and does reach the real backend).
