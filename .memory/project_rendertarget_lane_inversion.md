---
name: project-rendertarget-lane-inversion
description: RenderTargetD3D9 stored its surface and texture handles the wrong way round, so the shader binder handed D3DX an IDirect3DSurface9 as a texture and the bloom pass faulted inside d3d9's draw. Fixed 3426a18.
metadata:
  type: project
---

Fixed 2026-08-04 in `3426a18`. This was the bloom `DrawPrimitive` access
violation, and it is the reason that crash was so hard to localise: nothing
fails at bind time, only four frames deep inside `d3d9.dll` when the draw walks
the sampler.

**The layout, from three independent reads of the binary:**

| offset | holds |
|---|---|
| +0x14 | `IDirect3DSurface9*` |
| +0x18 | `IDirect3DBaseTexture9*` |

- `SetRenderTexture` (0x008F5500) calls `GetSurfaceLevel` (texture vtable slot
  18) on the object at **+0x18** and writes the result into **+0x14**.
- The surface-wrap ctor (0x008F5470) stores its `IDirect3DSurface9*` argument
  at +0x14 and immediately calls `GetDesc` (surface slot 12) on it.
- `FUN_008F5300` calls `GetDC` (surface slot **15**) on +0x14 - it is not a
  `GetSurfaceLevel` on a texture, which is how it had been recovered.

**The xrefs split the two accessors cleanly by role**, which is the fastest way
to settle this kind of question: `GetSurface` (0x008F52D0, +0x14) has five
callers and every one consumes a surface - `StretchRect` on both operands,
`CreateRenderTarget`, `Func4` feeding `D3DXSaveSurfaceToFile`, and
`ClearTarget` feeding `SetRenderTarget`. The +0x18 accessor (0x008F52E0) has
**exactly one** caller, `EffectVariableD3D9::Func3`, which passes the value
straight to `ID3DXEffect::SetTexture`.

**Why it hid for so long:** the storage was inverted *and* all five surface
call sites had been recovered as the +0x18 accessor, so those two errors
cancelled and every surface path worked. `Func3` alone was transcribed
faithfully (+0x18), so it alone got the wrong lane. **Two compensating
mistakes that cancel at four call sites and bite at the fifth** is a shape to
watch for whenever an accessor's name and its offset disagree.

Also corrected in the same commit: `CreateHeads` builds its head render target
with the single-surface ctor the binary calls (`RenderTargetD3D9(backBuffer)`),
not a constructed context plus a direct field poke.

After this the engine renders past the bloom pass and reaches the main loop;
the next blocker is [[project-lua-gc-upvalue-corruption]].

Related: [[project-render-frame-blockers-2026-08]]
