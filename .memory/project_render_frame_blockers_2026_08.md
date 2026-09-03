---
name: project-render-frame-blockers-2026-08
description: Six startup-render blockers fixed 2026-08-04 (technique guard, missing EndScene, UI self-recursion, garbage globals, render-target binder); next blocker is a D3D9 AV inside the bloom DrawPrimitive.
metadata:
  type: project
---

Session of 2026-08-04, six commits, all verified by running the engine under
`dbgrun` (`runwinlog.bat`). Each one moved the crash strictly forward.

`2efb677` **Effect-technique lane guard.** The guard read `mName.myRes`. A lane
is constructed as an empty SSO string whose capacity is 15, so it could never
answer false — the registration loop rejected the first definition of every
technique as a redundant fidelity (**371** warnings) and no lane ever got an
implementation name. The binary reads lane+0x18, which is `mySize`. Key fact:
**`msvc8::string` is 0x1C bytes** — `alVal` +0x00, `bx` +0x04, `mySize` +0x14,
`myRes` +0x18. I previously mis-derived this as an 0x18-byte string and reverted
a correct fix; the tell is `0x0042D290`, which tests lane+0x18 for zero and then
lane+0x1C `< 0x10` to pick SSO-vs-heap. `DeviceD3D9::Func3`/`Func4` had the same
swapped field.

`fedb72c` **`WRenViewport::Render` never called EndScene**, so the next frame's
`Present` failed `D3DERR_INVALIDCALL`. `CD3DDevice::EndScene` has **zero code
xrefs** — it is dispatched only through vtable slot 34 (+0x88), which is why a
call-graph walk misses it. It also returned early on an empty world-view list;
the binary jumps to `loc_7F9779`, *inside* the shared tail. Of 61 jumps in that
function exactly one leaves before the tail. The Hex-Rays output shows the tail
nested in the loop and is **wrong** — the `.c` opens with "bad sp value at call
has been detected".

`fc4706e` **The UI frame recursed into itself.** `CMauiControl::Render` seeds a
frame's rendered-children lane with the subtree root, so a frame is always entry
0 of its own lane. The walker at `0x007870F0` is **not** the virtual: no mangled
symbol (IDA inferred the name), no data xrefs, `this` in edi, and
`??_7CMauiFrame@Moho@@6B@` keeps the base no-op in that slot. Renamed to
`RenderChildControls`. **Dropping `override` does not remove virtuality** — a
derived function with the base signature overrides regardless, so it needed its
own name.

`adab78b` 15 undefined globals — see [[project-force-link-garbage-globals]].

`970cd16` **`FUN_00491280` binds a render target, not a texture.** It reads only
`px`, calls vtable slot 2 (`ID3DRenderTarget::GetSurface` → 
`shared_ptr<RenderTargetD3D9>`) and passes that to effect-variable slot 3 — never
slot 4 `SetTexture`. All 15 callers pass render targets. Callers had been
`reinterpret_cast`ing a `shared_ptr<ID3DRenderTarget>` into a
`weak_ptr<TextureD3D9>`. Renamed `SetRenderTargetTexture`; retyped every handle
that fed it. `TerrainShadowContext::primary/secondaryShadowTexture` at +0x2E0 /
+0x2F0 are the same slots as `Shadow::mShadowMap` / `mBlurTargetB`, i.e. render
targets — that context is probably a duplicate model of `Shadow`.

## End state 2026-08-04 (after 3426a18 + 60ec20f)

Three further commits closed the render path out:
`3426a18` [[project-rendertarget-lane-inversion]] (the bloom DrawPrimitive AV),
`c9c41a5` duplicate Lua allocator hooks, and `60ec20f`
[[project-lua-gc-upvalue-corruption]] (the traverseproto GC crash, actually a
CD3DPrimBatcher heap smash).

**Measured now: five consecutive runs at `fault=0`**, and `resizetest.ps1`
reports `SURVIVED all resizes` (900x700 -> 1180x860 -> 1024x768) with the
process still alive afterwards. The resize crash that opened this whole thread
is closed end-to-end; the depth-stencil framing in the older note is superseded.

## Startup is now exception-free (2026-08-04)

`cpp=0 fault=0`, three consecutive runs, down from cpp=3 plus a fatal AV.
Four more fixes after the render path closed:

`655d94f` `STR_GetToken` (see [[project-lua-gc-upvalue-corruption]]).
`c9b0858` the invented `PushStack` root-state assert (same note).

`4be3613` **`SetInvertMidMouseButton` was recovered but never registered.**
`/lua/options/options.lua` calls it from the `invert_middle_mouse_button`
option's `set` handler at startup, so every options pass died on "access to
nonexistent global variable" and nothing after it applied. Its worker cannot be
taken literally: it `VirtualProtect`s and rewrites `add`->`sub` at 0x0086E01F /
0x0086E027 inside `func_ProcessMouseScrubbing`, absolute addresses of the
*original* image. That function is itself recovered, so the choice is now a
flag (`UI_SetInvertMidMouseScrub`) the accumulation reads for its sign.
**Watch for this shape generally: `.exxt` workers that patch the shipped
image's code need a source-level equivalent, not a literal transcription.**

`69c6b76` **`cfunc_GetPreferenceL` pushed a borrowed object across states.**
The preferences table lives on the preferences LuaState; the binary copies the
looked-up value with `SCR_Copy(&out, value, callerState)` (0x004D26D0) before
pushing. Ours pushed it directly and tripped PushStack's `l_G` check - the
binary's own check. **Correction to the c9b0858 note: sim and UI do NOT share
one global_State**; the two roots really are separate, which is exactly why the
copy is required.

## How to see a swallowed Lua error

`lua_call` IS `LuaCallProtected` in this fork (FUN_0090D430 wraps `luaD_call`
in an EH region and returns a status) and `LuaFunction::operator()` discards
that status, so script errors vanish silently - the `gpg::Warnf` in
`OPTIONS_Apply`/`OPTIONS_SetCustomData` never runs, because their `catch` is
never reached. To see one, temporarily log from `LuaCallProtected`'s handlers;
add a `catch (const std::exception&)` printing `typeid(e).name()` to separate
Lua script errors from `LuaPlus::LuaAssertion`.
