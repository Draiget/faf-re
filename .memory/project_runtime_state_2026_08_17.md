---
name: project-runtime-state-2026-08-17
description: The engine builds, launches, initialises fully and runs a frame loop, but paints nothing. Unresolved externals cut 19 to 14. The gal::Error throws on the WM_SIZE path are expected, not the bug.
metadata:
  type: project
---

Ran the staged engine 2026-08-17. It gets **much** further than the last
recorded state.

## How to run it - use the repo's script, not a hand-rolled path

    .vscode\run-engine.bat            build + stage + run
    .vscode\run-engine.bat nobuild    run what is staged
    .vscode\run-engine.bat nobuild 30 ...and kill after 30s

Two traps cost me a full cycle each:

  - **The exe must run as the STAGED copy** at
    `C:\ProgramData\FAForever\bin\main.exe`. The engine resolves data paths
    from its own module path, so running `output\main\Win32\Debug\main.exe`
    with cwd set to the game dir dies in
    `IWinApp::AppInitCommonServices` with
    `gpg::Die("Failed to setup initial search path.")`. That Die is a
    *symptom of the wrong exe path*, not a VFS defect.
  - **Never launch from Git Bash.** MSYS rewrites `/windowed` into
    `C:/Program Files/Git/windowed`; the engine never sees the switch. The
    script exists for this reason. `NoDefaultCurrentDirectoryInExePath` is
    also set, so a bare `dbgrun.exe` after `cd` fails with 9009 - use full
    paths.

## What works now

Log reaches **`SHADERS COMPILED`** with only two benign privilege
warnings: sound banks, `Lua user environment initialized ... game version
3835 ... FAF`, all fonts, and all eleven shaders compiled
(cartographic, frame, mesh, particle, primbatcher, range, sky, terrain,
ui, vision, water2).

Process state at t+45s: window "Forged Alliance", `Responding=True`,
23 threads, CPU climbing 8 -> 24 -> 40 CPU-seconds, working set flat at
~144 MB. So there **is** a live frame loop.

## What does not work

Nothing paints. The window is foreground and reports a valid client rect,
but whatever is behind it shows through - i.e. the device never presents.
The log stops dead at `SHADERS COMPILED` and never logs again.

## The gal::Error throws are NOT the bug

Three `.?AVError@gal@gpg@@` throws fire from

    ThrowGalErrorFromHresult      D3D9Interfaces.cpp:3178
    gpg::gal::DeviceD3D9::Clear   D3D9Interfaces.cpp:8075
    moho::CD3DDevice::Clear       CD3DDevice.cpp:1843
    SyncSupComFrameClientSizeAndViewport  WxRuntimeTypes.cpp:60760

**Expected.** `CD3DDevice::Clear` carries a `catch (const gal::Error&)`
that is in the shipped binary (`__ehfuncinfo` 0x00EC2D50, handler funclet
0x00430158). The swapchain is created with `EnableAutoDepthStencil = 0`,
so clearing Z+stencil with no depth-stencil bound is `D3DERR_INVALIDCALL`
by design on the WM_SIZE path. Read the comment above that function
before "fixing" it.

## Unresolved externals: 19 -> 14

Fixed this session (`9126f2d`, `5ee4885`):

    ren_Shadows                0x00F57E53 = 1   never defined
    ren_UnitSilhouette         0x010A6422 = 0   never defined
    shaderVarFrameGlowCopyAdd  0x010BF4E0       never defined
    Silhouette::Render         struct/class mangling mismatch
    MeshRenderer::RenderSilhouette   same mismatch

Still unresolved and **rendering-relevant**:

    HardwareMeshBatch::FillBatch   virtual - the vtable slot points at
                                   garbage, so any dispatch through it
                                   is a fault waiting to happen

The rest are non-rendering: two Lua manip creators, `TryBuildStructureAt`,
`LuaPlus::LuaObject::Insert`, four wx editor symbols, two locale helpers,
three Sofdec codec symbols.

## Capture gotchas

`PrintWindow` returns a black frame for a D3D9 back buffer even when the
game is drawing - it is not evidence of a black screen. A foreground
`CopyFromScreen` of the client rect is the real test, and it must be
guarded on `GetForegroundWindow() == game hwnd` so it can never capture
the operator's desktop.

`FAF_BREAK_SYMBOLS` is documented in the init-recovery skill but is **not
compiled into** the current `dbgrun.exe` - breakpoints silently never arm.
Rebuild dbgrun from `references/dbgrun.md` before relying on it.
