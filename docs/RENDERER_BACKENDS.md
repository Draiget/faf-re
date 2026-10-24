# Renderer backends

The engine draws through `gpg::gal`, the GPG abstraction layer. The shipped binary had Direct3D 9 (default) and Direct3D 10 (`/D3D10`); this fork adds Direct3D 11, Direct3D 12 and Vulkan, and by default takes the newest one that starts.

*Snapshot: 24/10/2026.*

| Switch | Backend | Effects | Code |
|---|---|---|---|
| `/d3d9` | Direct3D 9 | D3DX9 effect framework | `src/gpg/gal/backends/d3d9` |
| `/D3D10` | Direct3D 10, as shipped | D3DX10 | `src/gpg/gal/backends/d3d10` |
| `/d3d11` | Direct3D 11 | Effects 11 (FX11), `fx_5_0` | `src/gpg/gal/backends/d3d11` |
| `/d3d12` | Direct3D 12 | FAF effect layer, DXIL via DXC | `src/gpg/gal/backends/d3d12` |
| `/vulkan` | Vulkan 1.3 | FAF effect layer, SPIR-V via DXC | `src/gpg/gal/backends/vulkan` |

## Choosing the renderer

Players pick it under Options, Video, **Graphics API**: Automatic, Direct3D 9, Direct3D 11, Direct3D 12 or Vulkan. The choice is stored as the option `graphics_api` (`auto`, `d3d9`, `d3d11`, `d3d12`, `vulkan`; default `auto`) in the profile's options, like `vsync`.

| Choice | Renderers tried, in order |
|---|---|
| `auto`, unset, unknown value (x64) | Direct3D 12, Vulkan, Direct3D 11, Direct3D 9 |
| `auto`, unset, unknown value (x86) | Direct3D 11, Vulkan, Direct3D 12, Direct3D 9 (see [Known issues](#known-issues)) |
| `d3d12` / `vulkan` / `d3d11` | That one, then Direct3D 9 |
| `d3d9` | Direct3D 9 |

- **Command line wins:** `/d3d9`, `/d3d11`, `/d3d12`, `/vulkan` override the option the same way; `/D3D10` is tried alone.
- **Fallback:** a renderer counts once its device is created and set up. One that cannot start is logged with the reason, and the next is tried with the same window settings (`CScApp::CreateDevice`, order from `RendererAttemptOrder`).
- **Restart needed:** the option is read once at startup (`OPTIONS_GetString`), so changing it raises the options screen's standard "requires a restart" dialog (`restart = true`), whose OK saves and exits. Switching renderers without a restart is not supported: the existing device rebind (`CD3DDevice::InitContext`, used for resolution, vsync and anti-aliasing changes and for a lost device) resets the *same* gal device, recreating only what a Direct3D 9 reset loses and keeping file textures, static buffers and compiled effects.
- **Window title** names the renderer in use (`Forged Alliance [Vulkan] ...`; no tag for Direct3D 9). `/title <label>` appends a label, to tell side-by-side test windows apart.
- **Testing the chain:** `FAF_GAL_FAIL_SETUP=1` fails every newer backend; a list such as `d3d12,vulkan` fails only those (Direct3D 12 and Vulkan read the list, Direct3D 11 only `1`).

The log shows each step:

```
graphics_api option: auto
renderer: trying Direct3D 12
GAL Exception: ...                      (the reason it failed)
Direct3D 12 is unavailable; falling back to Vulkan
renderer: trying Vulkan
Vulkan: ready (...)
```

### Where the option comes from

The options entry comes from the engine's own Lua, never from edits to FAF's gamedata:

- **Source:** `data/fafengine/` holds engine-owned scripts that extend gamedata scripts. The build copies it next to the executable (`src/CMakeLists.txt`), and `build.ps1` copies it into the run folder.
- **Mount:** at startup the engine mounts `<exe folder>/fafengine` at `/fafengine` and registers it as a hook directory, after the init file's own `path` and `hook` entries (`AppendEngineHookFolder` in `src/moho/misc/StartupHelpers.cpp`). The engine does this itself because the init files (`init_faf.lua` and the rest) belong to the FAF client.
- **Hook:** a hook file is appended to the gamedata file of the same path, so `fafengine/lua/options/options.lua` runs at the end of `/lua/options/options.lua` and inserts the entry after Vertical Sync. The log says `engine hooks: ... mounted at /fafengine` and `Hooked /lua/options/options.lua with /fafengine/lua/options/options.lua`.

## Effects: one source, translated at load time

The game's `.fx` files are user data. They are never copied into this repository; the ports below run on them at load time.

1. **Preprocess** with the Direct3D 10 macros (`technique` becomes `technique10`, `vs_3_0` becomes `vs_4_0`, and so on) and `d3d10states.compat` prepended (`CD3DEffectTechnique`), using `D3DPreprocess` from d3dcompiler_47.
2. **Override layer** (`backends/d3d11/EffectSourceD3D11.cpp`) rewrites the D3D9-isms the effects still have: D3D9 pass states become state objects, `sampler1D` and `tex1D` become 2D, shader inputs are re-linked, and the D3D9 fixed-function vertex shader is emulated for pre-transformed vertices. Fixes go here, never into the gamedata.
3. **Direct3D 11** compiles the result as `fx_5_0` and loads it into Effects 11.
4. **Direct3D 12 and Vulkan** hand it to the FAF effect layer (`src/gpg/gal/effects`):
   - `EffectDescription`: techniques, passes, annotations (constant expressions folded), blend, depth-stencil and rasterizer states, sampler states, and parameters with their defaults.
   - `ModernHlsl`: plain HLSL. Techniques and states are removed; the FX9 sampler model becomes `Texture2D`/`TextureCube`/`Texture3D` plus `SamplerState` on fixed registers; parameters a function writes get local copies; stage boundaries get `SV_` semantics. One wrapper entry point per (stage, function, compile-time arguments). The predicted `$Globals` layout matches DXC's reflection for every entry point.
   - `ShaderCompiler`: DXC (`dxcompiler.dll`), shader model 6.0, `-HV 2018 -Zpr`, producing DXIL or SPIR-V (`-fvk-use-dx-layout`).
   - `EffectParameters`: the `$Globals` image, written with Direct3D 9 / Effects 11 setter semantics and snapshotted when a pass begins.
   - `EffectRuntime`: the gal `Effect`/`EffectTechnique`/`EffectVariable` shared by both backends. Vulkan links stages by location while DXC numbers each shader's interface on its own, so `SpirvReflect` matches vertex inputs and the vertex-to-pixel interface by HLSL semantic. Shaders compile on first use and are cached in `%LOCALAPPDATA%\FAForever\ShaderCache` (or `FAF_SHADER_CACHE_DIR`).

**Why DXC:** Slang and DXC were both tried on the real effects. Both reject raw FX9 texture/sampler syntax, so a modernisation pass is needed either way. After that pass DXC compiled all 339 entry points of the 11 effects to DXIL and to SPIR-V; Slang failed most entries of `water2`, `particle` and `terrain`, mostly on implicit vector truncation and writes to globals, which FXC-era HLSL relies on.

### D3D9 behaviour restored

The D3D10 state packs lost some of what D3D9 did; the newer backends restore it:

- **Clear** covers the viewport (clipped to the targets), not the whole target.
- **Viewport reset:** binding a different colour target resets the viewport to the whole target (D3D9's `SetRenderTarget`). The engine clears the shadow map before it sets a viewport; without the reset, part of it keeps stale depth.
- **Depth clipping** is always on (`d3d10states.compat` turns it off, which lets shadow casters outside the light's range clamp onto the map).
- **Depth bias:** the compat file's fractional `DepthBias` values are D3D9 depth-range fractions, converted to 24-bit depth steps (fxc truncates them to 0, and the ground decals then z-fight the terrain).
- **Alpha blending:** the alpha channel blends with the colour factors (D3D9 had separate alpha blending off). The compat file sets `SrcBlendAlpha = ONE`, `DestBlendAlpha = ZERO` on every state, which overwrites the frame's alpha, and that alpha is the glow mask: the commander's warp-in light then lit its whole quad as a hard-edged rectangle.
- **Pixel centres:** Direct3D 9 puts them on integer coordinates, Direct3D 10+ and Vulkan on halves, and the engine draws for D3D9 (the UI projection `CD3DPrimBatcher::SetToViewport` shifts quads by -0.5 pixel). Every backend therefore moves the native viewport origin by +0.5 pixel (`Direct3D9PixelCentreShift`); without it UI text sampled between texels and looked doubled. The fixed-function emulation's `faf_ViewportSize` takes the same shift.
- **Alpha test:** effects still set `AlphaTestEnable`, `AlphaFunc` and `AlphaRef` in their passes, inside `#ifndef DIRECT3D10`, and FAF's water shader relies on it (`HighFidelityPS` returns the land mask in alpha, and `NotEqual 0` discards it). The effect layer reads these states from the original source (`ApplyDirect3D9PassStates`) and the pixel entry discards as D3D9 did, on the 8-bit alpha. The effects' own `AlphaTestD3D10` helper, which D3D9 never ran, is emptied. Without the alpha test the water drew over the land as grey polygons when zoomed out.
- **Shader math** as shader model 2/3 compiled it: `sqrt`/`rsqrt` of `|x|`, and `pow` of `|x|` (sign kept for odd integer exponents). Shader model 6 returns NaN for a negative operand, and a NaN blended into a target stores zero.
- **Missing vertex inputs** (ones a vertex format lacks) read as zero.
- **Feedback:** a pass that samples the target it draws into reads zero, as on D3D10/11.

## GPU-driven paths

The GPU-driven renderers (strategic icons with GPU classification, fog of war, instance streams) use the small binding model in `src/gpg/gal/GpuDriven.h`: one constant block, four read buffers, two textures, two write buffers and one sampler. Every newer backend implements all of it.

| | Programs | Binding |
|---|---|---|
| Direct3D 11 | d3dcompiler `vs/ps/cs_5_0` | Registers b0, t0..t5, u0..u1, s0 directly |
| Direct3D 12 | DXC `vs/ps/cs_6_0` (`ShaderCompiler::CompileRaw`) | One root signature per sampler kind: root CBV b0, SRV table t0..t5, UAV table u0..u1, static sampler s0; `ExecuteIndirect` for indirect draws (`d3d12/GpuDrivenD3D12.cpp`) |
| Vulkan | DXC SPIR-V with `-fvk-b-shift 0 -fvk-t-shift 1 -fvk-u-shift 7 -fvk-s-shift 9` | One descriptor set, bindings 0..9; `vkCmdDrawIndirect`; compute outside the rendering scope (`vulkan/GpuDrivenVulkan.cpp`) |

GPU timestamps feed `RenderProfiler` (`FAF_GPU_PROFILE=<frames>`). `FAF_ICON_GPU_CHECK=<n>` compares every n-th GPU-classified icon frame with the CPU path, record by record.

### Turning the paths on

Each path has a console variable with three values: `-1` (default, auto: on only where the backend reports both the features the path needs and the path's verified bit), `0` (off: the original draw path), `1` (force on wherever the features exist, for testing a backend before it is verified). Two `gal::Device` queries decide it (`src/moho/render/GpuPathSettings.cpp`):

- **`GetGpuDrivenFeatures()`**: what the backend can do (`GpuDrivenFeature` bits: vertex pulling, compute, indirect draws, timestamps, buffer copy).
- **`GetGpuDrivenVerified()`**: the `GpuDrivenPath` bits the backend has passed parity on. The base `Device` returns 0, so a backend that does not override it draws everything the original way under auto.

| Console variable | Path bit | Needs |
|---|---|---|
| `ren_GpuIcons` | `kGpuPathStrategicIcons` | Vertex pulling |
| `ren_GpuIconClassify` | `kGpuPathIconClassify` | Vertex pulling, compute, indirect draws (also needs `ui_IconRecords`) |
| `ren_GpuFog` | `kGpuPathFogOfWar` | Vertex pulling |
| `ren_GpuSelectBrackets` | `kGpuPathSelectBrackets` | Vertex pulling |
| `ren_ParticleBatch` | `kGpuPathParticleBatch` | Buffer copy (`Device::CopyVertexBufferRegion` on the GPU) |
| `ren_GpuProjectileIcons` | `kGpuPathProjectileIcons` | Vertex pulling |

- **Direct3D 9** reports no features, so every path is off there whatever its variable says.
- **Direct3D 11, 12 and Vulkan** report all features and every verified bit except `kGpuPathParticleBatch`, which stays out until a paused screenshot A/B of `ren_ParticleBatch` is clean at several zooms (one showed extra particle specks with it on).
- **Verifying a path:** a backend turns a path on by default by adding its bit to `GetGpuDrivenVerified()` once it passes that path's checks (the self-check readback where one exists, and a same-process screenshot A/B against the variable at 0); no variable or default changes.
- **Log:** the resolved state is logged once at startup and by `ren_Info`, as `GPU-driven paths: ren_GpuIcons=auto:on, ...`.
- `ui_IconRecords` and `ren_CacheFogFootprint` are CPU-side and on by default on every backend. All of these variables are also listed in [Switches](SWITCHES.md).

## Toolchain setup

Configuring the CMake build fetches all three into `dependencies/` (`cmake/FafDependencies.cmake`):

- **FX11 (Direct3D 11):** git submodule `dependencies/FX11`, `microsoft/FX11` at `bec3b8fc`. The engine compiles FX11's sources directly (C++17, two-phase lookup off).
- **DXC (Direct3D 12, Vulkan):** the [DirectXShaderCompiler release](https://github.com/microsoft/DirectXShaderCompiler/releases) v1.9.2609 (`dxc_2026_09_29.zip`, SHA256-pinned), unpacked to `dependencies/dxc`. At run time the game loads `dxcompiler.dll` and `dxil.dll` (the DXIL signer) from its own directory, or from `FAF_DXC_DIR`; copy the DLLs for the right architecture next to the executable.
- **Vulkan headers (Vulkan):** git submodule `dependencies/vulkan`, `KhronosGroup/Vulkan-Headers` at `v1.4.304`. The game loads `vulkan-1.dll` (installed with the GPU driver) at run time and links no import library, so x86 and x64 both build from the headers alone.

### Runtime requirements

Both are optional; without them the game falls back to Direct3D 9.

- **D3DX11:** `/d3d11`, `/d3d12` and `/vulkan` decode textures with D3DX11 (`d3dx11_43.dll`, from the DirectX End-User Runtime of June 2010), as the shipped D3D10 path did with D3DX10. Direct3D 12 and Vulkan run it on a private WARP device (`backends/common/ImageCodec`).
- **Direct3D 12** needs Windows 10 (d3d12.dll is loaded at run time).
- **Vulkan** needs a Vulkan 1.3 driver with dynamic rendering, synchronization2, timeline semaphores, scalar block layout (`$Globals` keeps Direct3D's packing) and BC textures. It runs windowed or borderless only (no exclusive full screen).

## Known issues

- **Direct3D 12 in the 32-bit build, NVIDIA** (seen on a TITAN RTX, driver 32.0.15.7270): after minutes of play the GPU takes an SM MMU fault (`Graphics SM Warp Exception ... MMU Fault`, Xid 13 in the System event log) and the device is removed as hung (`0x887A0006`). It shows on any draw or dispatch (the bloom extract `frame.fx:TCopyGlowingStuff` and `StrategicIconClassify` most often), right after a submission split mid-frame by upload pressure, and is much more frequent with `FAF_GAL_UPLOAD_SUBMIT_KB=1024`. The debug layer, GPU-based validation and anything that slows the CPU hide it; the x64 build of the same code runs the same load cleanly. No application error was found (see the investigation notes in the commit), so `auto` starts the 32-bit build with Direct3D 11. It stays available with `/d3d12` or `graphics_api = d3d12`.
- **Vulkan on NVIDIA:** `PrintWindow(PW_RENDERFULLCONTENT)` on the game window (some capture tools do this) makes `PeekMessage` report a message that `GetMessage` then never returns. The engine's loop (`WIN_AppExecute`, as shipped: `Pending()` then `Dispatch()`) sleeps in `GetMessage` until the next input, so the game stands still until the mouse moves. Any posted message wakes it; the test scripts post `WM_NULL` after each capture.
- **`/D3D10` crashes at startup** on both x86 and x64, as shipped: `DeviceD3D10::SetupDXGIDevice` copies an `AdapterD3D10` without AddRef, so the temporary's destructor releases the adapter and its outputs, which the code then uses after they are freed. It is left as the binary had it.

## Diagnostics

| Switch / variable | Effect |
|---|---|
| `/d3d11debug`, `/d3d12debug`, `/vulkandebug` | API debug or validation layer; its warnings go to the game log |
| `/d3d12gbv` | Direct3D 12: the debug layer with GPU-based validation (very slow) |
| `/d3d12dred` | Direct3D 12: device removed extended data. On a device loss the log shows the breadcrumbs of the lists the GPU had started (each with the technique or GPU program it belongs to), numbered markers the GPU writes around every draw, dispatch and copy (the first unfinished one names the command that faulted or hung), and the allocation a page fault hit |
| `/d3d11blt` | Direct3D 11: legacy blt-model swap chain |
| `FAF_GAL_MEMORY_LOG=<seconds>` | Direct3D 12: logs the backend's CPU copies, upload pages, upload-pressure submissions, passes carried into the next submission, submissions in flight and the address space left |
| `FAF_GAL_UPLOAD_SUBMIT_KB=<n>` | Direct3D 12: submits the recorded commands after every n KB of uploads (default 48 MB on x86, 96 MB on x64), which exercises the mid-frame submission paths |
| `FAF_CRASH_NO_DIALOG=1` | The crash report and minidump are written, but no dialog waits for a click (unattended test runs) |
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
