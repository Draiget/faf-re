# Renderer backends

The engine draws through `gpg::gal`, the GPG abstraction layer. The shipped
binary had two backends: Direct3D 9 (the default) and Direct3D 10 (`/D3D10`).
This fork adds Direct3D 11, Direct3D 12 and Vulkan. By default the game takes
the newest renderer that starts (Direct3D 12, then Vulkan, then Direct3D 11,
then Direct3D 9; see [Choosing the renderer](#choosing-the-renderer)). A
renderer that cannot start is logged with the reason, and the next one is
tried with the same window settings (`CScApp::CreateDevice`).

| Switch | Backend | Effects | Code |
|---|---|---|---|
| `/d3d9` | Direct3D 9 | D3DX9 effect framework | `src/sdk/gpg/gal/backends/d3d9` |
| `/D3D10` | Direct3D 10, as shipped | D3DX10 | `src/sdk/gpg/gal/backends/d3d10` |
| `/d3d11` | Direct3D 11 | Effects 11 (FX11), `fx_5_0` | `src/sdk/gpg/gal/backends/d3d11` |
| `/d3d12` | Direct3D 12 | FAF effect layer, DXIL via DXC | `src/sdk/gpg/gal/backends/d3d12` |
| `/vulkan` | Vulkan 1.3 | FAF effect layer, SPIR-V via DXC | `src/sdk/gpg/gal/backends/vulkan` |

## Choosing the renderer

Players pick the renderer under Options, Video, **Graphics API**: Automatic
(newest available), Direct3D 9, Direct3D 11, Direct3D 12 or Vulkan. The choice
is stored as the option `graphics_api` (`auto`, `d3d9`, `d3d11`, `d3d12`,
`vulkan`; default `auto`) in the profile's options, like `vsync`.
`CScApp::CreateDevice` reads it once with `OPTIONS_GetString`
(`RendererAttemptOrder`), so changing it raises the options screen's standard
"requires a restart" dialog (`restart = true`), whose OK saves and exits.

| Choice | Renderers tried, in order |
|---|---|
| `auto`, unset, unknown value | Direct3D 12, Vulkan, Direct3D 11, Direct3D 9 |
| `d3d12` / `vulkan` / `d3d11` | that one, then Direct3D 9 |
| `d3d9` | Direct3D 9 |

A command-line switch (`/d3d9`, `/d3d11`, `/d3d12`, `/vulkan`, `/D3D10`)
overrides the option the same way. A renderer counts once its device is
created and set up. The log shows each step:

```
graphics_api option: auto
renderer: trying Direct3D 12
GAL Exception: ...                      (the reason it failed)
Direct3D 12 is unavailable; falling back to Vulkan
renderer: trying Vulkan
Vulkan: ready (...)
```

The window title names the renderer in use (`Forged Alliance [Vulkan] ...`;
no tag for Direct3D 9). `FAF_GAL_FAIL_SETUP` makes chosen backends fail, to
exercise the chain: `1` fails every newer backend, and a list such as
`d3d12,vulkan` fails only those (Direct3D 12 and Vulkan read the list,
Direct3D 11 only `1`).

The options entry comes from the engine's own Lua, never from edits to
FAF's gamedata:

- `data/fafengine/` in this repository holds engine-owned scripts that
  extend gamedata scripts. The build copies it next to the executable
  (`StageFafEngineHooks` in `main.vcxproj`, and into the run folder when
  `FafStageToRunDir` is on).
- At start-up the engine mounts `<exe folder>/fafengine` at `/fafengine` and
  registers `/fafengine` as a hook directory, after the init file's own
  `path` and `hook` entries (`AppendEngineHookFolder` in
  `moho/misc/StartupHelpers.cpp`). The engine does this itself because the
  init files (`init_faf.lua` and the rest) belong to the FAF client.
- A hook file is appended to the gamedata file of the same path, so
  `fafengine/lua/options/options.lua` runs at the end of
  `/lua/options/options.lua` and inserts the entry after Vertical Sync.
  The log says `engine hooks: ... mounted at /fafengine` and
  `Hooked /lua/options/options.lua with /fafengine/lua/options/options.lua`.

Switching renderers without a restart is not supported. The engine's
existing device rebind (`CD3DDevice::InitContext`, used for resolution,
vertical sync and anti-aliasing changes and for a lost device) resets the
*same* gal device. It recreates only what a Direct3D 9 reset loses, and
keeps file textures, static buffers and compiled effects.

The shipped `/D3D10` path crashes at start-up on both x86 and x64.
`DeviceD3D10::SetupDXGIDevice` copies an `AdapterD3D10` without AddRef, so
the temporary's destructor releases the adapter and its outputs, and the code
then uses them after they are freed. It is left as the binary had it.

## Effects: one source, translated at load time

The game's `.fx` files are user data. They are never copied into this
repository, and the ports below are done on them at load time.

1. **Preprocess** with the Direct3D 10 macros (`technique` becomes
   `technique10`, `vs_3_0` becomes `vs_4_0`, and so on) and
   `d3d10states.compat` prepended (`CD3DEffectTechnique`). This uses
   `D3DPreprocess` from d3dcompiler_47.
2. **Override layer** (`backends/d3d11/EffectSourceD3D11.cpp`): rewrites the
   D3D9-isms the effects still have. D3D9 pass states become state objects,
   `sampler1D` and `tex1D` become 2D, shader inputs are re-linked, and the
   D3D9 fixed-function vertex shader is emulated for pre-transformed
   vertices. Fixes go here, never into the gamedata.
3. Direct3D 11 compiles the result as `fx_5_0` and loads it into Effects 11.
4. Direct3D 12 and Vulkan hand it to the **FAF effect layer**
   (`src/sdk/gpg/gal/effects`):
   - `EffectDescription`: techniques, passes, annotations (constant
     expressions folded), blend, depth-stencil and rasterizer states,
     sampler states, and parameters with their defaults.
   - `ModernHlsl`: plain HLSL. Techniques and states are removed. The FX9
     sampler model becomes `Texture2D`/`TextureCube`/`Texture3D` plus
     `SamplerState` on fixed registers. Parameters that a function writes get
     local copies. Stage boundaries get `SV_` semantics. There is one wrapper
     entry point per (stage, function, compile-time arguments). The predicted
     `$Globals` layout matches DXC's reflection for every entry point.
   - `ShaderCompiler`: DXC (`dxcompiler.dll`), shader model 6.0, `-HV 2018 -Zpr`,
     producing DXIL or SPIR-V (`-fvk-use-dx-layout`).
   - `EffectParameters`: the `$Globals` image, written with Direct3D 9 /
     Effects 11 setter semantics and snapshotted when a pass begins.
   - `EffectRuntime`: the gal `Effect`/`EffectTechnique`/`EffectVariable`
     shared by both backends. Vulkan links stages by location while DXC
     numbers each shader's interface on its own, so `SpirvReflect` matches
     vertex inputs and the vertex-to-pixel interface by HLSL semantic.
     Shaders compile on first use and are cached in
     `%LOCALAPPDATA%\FAForever\ShaderCache` (or `FAF_SHADER_CACHE_DIR`).

The shader-language decision was made on test results. Slang and DXC were both
tried on the real effects. Both reject raw FX9 texture/sampler syntax, so a
modernisation pass is needed either way. After that pass, DXC compiled all
339 entry points of the 11 effects to DXIL and to SPIR-V. Slang failed most
entries of `water2`, `particle` and `terrain`, mostly on implicit vector
truncation and writes to globals, which FXC-era HLSL relies on.

Behaviour that D3D9 had and the D3D10 state packs lost, restored by the
newer backends:

- `Clear` covers the viewport (clipped to the targets), not the whole target.
- Binding a different colour target resets the viewport to the whole target
  (D3D9's `SetRenderTarget`). The engine clears the shadow map before it sets
  a viewport; without the reset, part of it keeps stale depth.
- Depth clipping is always on (`d3d10states.compat` turns it off, which lets
  shadow casters outside the light's range clamp onto the map).
- The compat file's fractional `DepthBias` values are D3D9 depth-range
  fractions, converted to 24-bit depth steps (fxc truncates them to 0, and
  the ground decals then z-fight the terrain).
- The alpha channel blends with the colour factors (D3D9 had separate alpha
  blending off). The compat file sets `SrcBlendAlpha = ONE`,
  `DestBlendAlpha = ZERO` on every state, which overwrites the frame's alpha,
  and that alpha is the glow mask: the commander's warp-in light then lit its
  whole quad as a hard-edged rectangle.
- Pixel centres. Direct3D 9 puts them on integer coordinates, Direct3D 10+
  and Vulkan on halves, and the engine draws for D3D9: the UI projection
  (`CD3DPrimBatcher::SetToViewport`) shifts quads by -0.5 pixel for texel
  alignment. Every backend therefore moves the native viewport origin by
  +0.5 pixel (`Direct3D9PixelCentreShift`); without it UI text sampled between
  texels and looked doubled. The fixed-function emulation's
  `faf_ViewportSize` takes the same shift.
- The alpha test. Effects still set `AlphaTestEnable`, `AlphaFunc` and
  `AlphaRef` in their passes, inside `#ifndef DIRECT3D10`, and FAF's water
  shader relies on it (`HighFidelityPS` returns the land mask in alpha, and
  `NotEqual 0` discards it). The effect layer reads these states from the
  original source (`ApplyDirect3D9PassStates`) and the pixel entry discards
  as D3D9 did, on the 8-bit alpha. The effects' own `AlphaTestD3D10` helper,
  which D3D9 never ran, is emptied. Without the alpha test the water drew
  over the land as grey polygons when zoomed out.
- Shader math as shader model 2/3 compiled it: `sqrt`/`rsqrt` of `|x|`, and
  `pow` of `|x|` (sign kept for odd integer exponents). Shader model 6 returns
  NaN for a negative operand, and a NaN blended into a target stores zero.
- Vertex-shader inputs that a vertex format lacks read as zero.
- A pass that samples the target it draws into reads zero, as on D3D10/11.

## Toolchain setup

All three live under `dependencies/`, which is git-ignored. Fetch them once
per machine.

### FX11 (Direct3D 11)

```
git clone https://github.com/microsoft/FX11 dependencies/FX11
```

`main.vcxproj` compiles FX11's sources directly (C++17, two-phase lookup off).

### DXC (Direct3D 12, Vulkan)

Download a DirectXShaderCompiler release
(https://github.com/microsoft/DirectXShaderCompiler/releases, tested with
v1.9.2609) and unpack it so that these exist:

```
dependencies/dxc/inc/dxcapi.h
dependencies/dxc/bin/x64/dxcompiler.dll   dependencies/dxc/bin/x64/dxil.dll
dependencies/dxc/bin/x86/dxcompiler.dll   dependencies/dxc/bin/x86/dxil.dll
```

At run time the game loads `dxcompiler.dll` and `dxil.dll` (the DXIL signer)
from its own directory, or from `FAF_DXC_DIR`. Copy the DLLs for the right
architecture next to the executable.

### Vulkan SDK (Vulkan)

Install the LunarG Vulkan SDK (tested with 1.4.304.1) and copy its `Include`
directory to `dependencies/vulkan/Include`. The game loads `vulkan-1.dll`
(installed with the GPU driver) at run time and links no import library, so
x86 and x64 both build from the headers alone.

### Runtime requirements

Both are optional; without them the game falls back to Direct3D 9.

- `/d3d11`, `/d3d12` and `/vulkan` decode textures with D3DX11
  (`d3dx11_43.dll`, from the DirectX End-User Runtime of June 2010), as the
  shipped D3D10 path did with D3DX10. Direct3D 12 and Vulkan run it on a
  private WARP device (`backends/common/ImageCodec`).
- `/d3d12` needs Windows 10 (d3d12.dll is loaded at run time).
- `/vulkan` needs a Vulkan 1.3 driver with dynamic rendering,
  synchronization2, timeline semaphores, scalar block layout (`$Globals`
  keeps Direct3D's packing) and BC textures. It runs windowed or borderless
  only (no exclusive full screen).

## Known issues

- Vulkan on NVIDIA: `PrintWindow(PW_RENDERFULLCONTENT)` on the game window
  (some capture tools do this) makes `PeekMessage` report a message that
  `GetMessage` then never returns. The engine's loop (`WIN_AppExecute`, as
  shipped: `Pending()` then `Dispatch()`) sleeps in `GetMessage` until the
  next input, so the game stands still until the mouse moves. Any posted
  message wakes it. The test scripts post `WM_NULL` after each capture.

## Diagnostics

| Switch / variable | Effect |
|---|---|
| `/d3d11debug`, `/d3d12debug`, `/vulkandebug` | API debug or validation layer; its warnings go to the game log |
| `/d3d11blt` | Direct3D 11: legacy blt-model swap chain |
| `FAF_GAL_FAIL_SETUP=1`, `=d3d12,vulkan` | Device creation fails (every newer backend, or the listed ones), which exercises the renderer fallback |
| `FAF_GAL_DUMP_DIR`, `FAF_GAL_DUMP_SECONDS` | Writes the back buffer as BMP every N seconds |
| `FAF_GAL_TRACE_START`, `FAF_GAL_TRACE_FRAMES` | Logs every gal call of those frames |
| `FAF_GAL_TRACE_FILE` | Direct3D 12: traces the frame after that file appears |
| `FAF_GAL_SKIP_TECHNIQUES=";A;B;"` | Draws the named techniques with no passes |
| `FAF_GAL_SOLID_PS=1` | Direct3D 12: every pass in magenta (geometry check) |
| `FAF_GAL_CLEAR_TEST=1` | Direct3D 12: clears in green (present-path check) |
| `FAF_GAL_NAN_CHECK=1` | Direct3D 12, Vulkan: NaN or infinite pixel colours draw in magenta |
| `FAF_GAL_D3D10_ALPHA_BLEND=1`, `FAF_GAL_D3D10_MATH=1`, `FAF_GAL_D3D10_DEPTH_CLIP=1`, `FAF_GAL_D3D10_PIXEL_CENTRES=1` | Direct3D 12, Vulkan: keep the D3D10 packs' alpha blend, shader model 6 math, depth-clip setting or pixel centres instead of the D3D9 behaviour |
| `FAF_EFFECT_DUMP_DIR` | Writes each effect's original source, translated source and generated HLSL (local files only) |
| `FAF_SHADER_PRECOMPILE=1` | Compiles every entry point when an effect loads |
| `FAF_DRAW_STATS_LOG=N` | Logs the average frame time over N frames |
