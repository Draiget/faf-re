# Map editor

`FafEditor_x64.exe` (x64) / `FafEditor.exe` (x86) is the map editor: its own program, built from the same engine code as the game. It draws through Direct3D 12 or Vulkan only.

*Snapshot: 08/11/2026. Stage 0: the program, its window, device and panels. Maps, tools and play come in the later stages.*

## Building and running

```powershell
.\build.ps1 -Editor        # builds everything, copies only FafEditor_x64.exe (+ .pdb) to bin_x64
cd C:\ProgramData\FAForever\bin_x64
.\FafEditor_x64.exe /init init_faf.lua /log C:\ProgramData\FAForever\logs\FafEditor_x64.log
```

`-Editor` never replaces the game's `main_x64.exe`, its headless or the DXC DLLs in the run folder (the editor carries its own DXC); a Profile build is copied as `FafEditor_x64_profile.exe`, and `-Out` also copies it to `out\<arch>\`. The editor reads the game data the way the game does: `/init <file>` names the init file (FAF's `init_faf.lua`), else `SupComDataPath.lua` next to the exe.

| Switch | Effect |
|---|---|
| `/d3d12` | Direct3D 12 only |
| `/vulkan` | Vulkan only |
| (neither) | Direct3D 12, then Vulkan; if neither starts, the editor says why and exits |
| `/windowed` | Start in a 1600x1000 window instead of maximised |
| `/novsync` | No vertical sync |
| `/log <file>` | The engine log, as in the game; the Log panel shows it too |
| `/d3d12debug`, `/vulkandebug` | The API's debug or validation layer, as in the game ([Renderer backends](RENDERER_BACKENDS.md)) |

The window layout is kept in `%LOCALAPPDATA%\FAForever\Editor\layout.ini`; View > Reset layout restores the default.

## How it is built

- **Target:** `src/editor/CMakeLists.txt` adds `faf_editor`, which links the engine's object library `faf_engine` whole, as the engine tests do, so the engine's objects are linked in the game's order. The game's `WinMain` is one of them, so the editor starts at its own `main()` (`/ENTRY:mainCRTStartup`). It carries the DXC DLLs as the game does (`EmbeddedFiles.rc`).
- **Startup** (`EdApp.cpp`): the engine's common services as headless sets them up (`IWinApp::AppInitCommonServices`: log, reflection types, resource manager, the game data), then a Win32 window.
- **Device** (`EdDevice.cpp`): a gal device on that window, Direct3D 12 or Vulkan. The other backends are linked but never created, and their DLLs are delay-loaded (`d3d9.dll`, `d3dx9_43.dll`, `d3d10.dll`, `d3d11.dll`), so the editor starts without the June 2010 DirectX runtime and never loads Direct3D 9. Direct3D 11 still loads when Direct3D 12 or Vulkan decode a texture: they do it on a private WARP device ([Renderer backends](RENDERER_BACKENDS.md)).
- **UI:** [Dear ImGui](https://github.com/ocornut/imgui) 1.92.4, docking branch, pinned in `cmake/FafDependencies.cmake` and built by `cmake/deps/imgui`. Its Win32 backend takes the input; `ui/EdImGuiRenderer.cpp` draws it through gal's GPU programs (`gpg/gal/GpuDriven.h`), one HLSL source that DXC builds for both APIs. Each draw command is one draw whose vertex shader reads its index and vertex from structured buffers; clip rectangles are applied in the pixel shader.
- **Log panel** (`EdLog.cpp`): a `gpg::LogTarget`, so it shows every engine log line.

The plan for the rest (3D viewport, opening and saving FAF maps, terrain, textures, water, props, decals, markers, Check and Play) is kept with the project's other plans.
