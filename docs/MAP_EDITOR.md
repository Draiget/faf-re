# Map editor

`FafEditor_x64.exe` (x64) / `FafEditor.exe` (x86) is the map editor: its own program, built from the same engine code as the game. It draws through Direct3D 12 or Vulkan only, and plays maps inside its own window.

*Snapshot: 09/11/2026. The editor's window, panels and Play. Opening and saving maps, the 3D edit view and the tools come next.*

## Building and running

```powershell
.\build.ps1 -Editor        # builds everything, copies only FafEditor_x64.exe (+ .pdb) to bin_x64
cd C:\ProgramData\FAForever\bin_x64
.\FafEditor_x64.exe /init init_faf.lua /log C:\ProgramData\FAForever\logs\FafEditor_x64.log
```

`-Editor` never replaces the game's `main_x64.exe`, its headless or the DXC DLLs in the run folder (the editor carries its own DXC); a Profile build is copied as `FafEditor_x64_profile.exe`, and `-Out` also copies it to `out\<arch>\`. The editor reads the game data the way the game does: `/init <file>` names the init file (FAF's `init_faf.lua`), else `SupComDataPath.lua` next to the exe.

## Play

Pick a map in the Map panel (each map by its title, then its folder name; type to filter, double-click to play) or in Play > Map, and press **Play** or F5. The map loads and plays inside the editor's view, between the panels, with the game's own interface, the way `/map` starts it in the game (FAF's `SinglePlayerLaunch.lua`: you and AI armies). **Stop** or F5 returns to the editor. So does the game's own way out of a session: its menu's exit, quitting from the score screen, and "Exit to Windows", which stops the play instead of closing the editor. View > Panels while playing (on by default) hides the panels during play when turned off, so the game takes the whole window. The window's title says what plays.

| Switch | Effect |
|---|---|
| `/d3d12` | Direct3D 12 only |
| `/vulkan` | Vulkan only |
| (neither) | Direct3D 12, then Vulkan; if neither starts, the editor says so and exits |
| `/log <file>` | The engine log, as in the game; the Log panel shows it too |
| `/play <map>` | Plays that map (its folder or scenario name, e.g. `SCMP_009`) once the editor is up |
| `/playseconds <s>` | With `/play`: stops after s seconds of play |
| `/playcycles <n>` | With `/play`: plays and stops n times |
| `/playquit` | With `/play`: closes the editor after the last one (test runs) |
| `/playexitapp` | With `/play` and `/playseconds`: ends each play the way the game's "Exit to Windows" does (`ExitApplication()`), which the editor turns into a Stop (test runs) |
| `/d3d12debug`, `/vulkandebug` | The API's debug or validation layer, as in the game ([Renderer backends](RENDERER_BACKENDS.md)) |

`/play` takes several maps separated by commas; the runs take them in turn.

The window is always one maximized, movable, resizable window with a menu bar (File, View, Play), whatever the game's display options say; the game's own display option doesn't change it either. The panel layout is kept in `%LOCALAPPDATA%\FAForever\Editor\layout.ini`; View > Reset layout restores the default.

The Tools panel is laid out as the plan's mockup: a strip of tool icons and the chosen tool's settings (brush modes, size, strength, falloff, the symmetry modes with their diagrams). The settings are kept but act on a map only from the tool stages of the plan.

## How it is built

- **Target:** `src/editor/CMakeLists.txt` adds `faf_editor`, which links the engine's object library `faf_engine` whole, as the engine tests do, so the engine's objects are linked in the game's order. The game's `WinMain` is one of them, so the editor starts at its own `main()` (`/ENTRY:mainCRTStartup`). It carries the game's window resources and manifest and the DXC DLLs as the game does.
- **The game inside:** the editor's app (`EdApp.cpp`) holds the game's own `CScApp` and runs the game's loop (`WIN_AppExecute`), with what the game's `WinMain` sets up around it (the crash report's die handler, the accessibility hotkeys turned off and restored). The window, device, user interface, sound and world sessions are the game's, unchanged. Engine additions in `CScApp`, unused by the game: `moho::gAppRenderers` (Direct3D 12 and Vulkan only, no Direct3D 9/10 fallback), `moho::gAppWindowed` (one normal window; `SC_PrimaryAdapter` leaves it alone) and `moho::gAppBeforeDeviceCreate` (the editor's second head). The game's first-frame start (main menu or command-line session) is skipped; sessions start from Play.
- **Two heads:** the device has the game's head 0 on the game's viewport, which the editor keeps over the middle of its dock layout, and a head 1 on the editor's own child window under it, for the panels. The game draws only head 0 (its viewport was made for one head); the editor draws head 1 each frame, and the game's paint presents both. When the layout or the window changes, the viewport is moved and both heads are resized (`CD3DDevice::InitContext`). The game's interface lays itself out in the viewport and takes its input there, as in the game.
- **Panels:** [Dear ImGui](https://github.com/ocornut/imgui) 1.92.4, docking branch, pinned in `cmake/FafDependencies.cmake` and built by `cmake/deps/imgui`, drawn by `ui/EdImGuiRenderer.cpp` on gal's GPU programs (`gpg/gal/GpuDriven.h`): one HLSL source DXC builds for both APIs. Its input is the panels' window's; F5 is the editor's in either window.
- **Play** (`EdPlay.cpp`): `StartCommandLineSession` on the map's scenario starts the session; `WLD_Teardown` ends it, before the game's frame would go on to its main menu. A Lua request to quit during play (`ExitApplication`) ends the session, not the editor.
- **Older renderers:** their DLLs are delay-loaded (`d3d9.dll`, `d3dx9_43.dll`, `d3d10.dll`, `d3d11.dll`), so the editor starts without the June 2010 DirectX runtime and never loads Direct3D 9. Direct3D 11 still loads when Direct3D 12 or Vulkan decode a texture: they do it on a private WARP device ([Renderer backends](RENDERER_BACKENDS.md)).

## Known issues

- Each Play keeps about 15 MB more after it ends (20 cycles of SCMP_009 on Direct3D 12: the lowest point between sessions went from 798 to 1,101 MB). Not yet traced.
- A play takes about 4 s to load (SCMP_009: about 1.5 s loading the rules and map, 2.5 s creating the sim and the game interface), the same every time, with the game's loading screen. Keeping the rules and preparing the sim while editing is the next step.
- A popup of the panels that reaches over the game's view is hidden behind it (the view is its own window).
