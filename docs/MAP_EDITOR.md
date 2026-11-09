# Map editor

`FafEditor_x64.exe` (x64) / `FafEditor.exe` (x86) is the map editor: its own program, built from the same engine code as the game. It draws through Direct3D 12 or Vulkan only, and plays maps inside its own window.

*Snapshot: 09/11/2026. The editor's window, panels and Play. Opening and saving maps, the 3D edit view and the tools come next.*

## Building and running

```powershell
.\build.ps1 -Editor        # builds only the editor's target, copies FafEditor_x64.exe (+ .pdb) to bin_x64
.\build.ps1 -Editor -Configuration Debug
cd C:\ProgramData\FAForever\bin_x64
.\FafEditor_x64.exe /init init_faf.lua /log C:\ProgramData\FAForever\logs\FafEditor_x64.log
```

In VS Code, the Run view has "Editor (x64, Debug)" and "Editor (x64, Release)": F5 builds the editor's target of `clang-x64-debug` or `clang-x64-release`, copies it to `bin_x64` and starts it under the debugger with `/init init_local_development.lua` (the Lua of the FA checkout, as the engine's own F5 entries use). "Editor (x64, no build)" starts what is already there. Only running editors are stopped before the copy; the game is left alone. The `.vscode` files are local (not in git).

`-Editor` never replaces the game's `main_x64.exe`, its headless or the DXC DLLs in the run folder (the editor carries its own DXC); a Profile build is copied as `FafEditor_x64_profile.exe`, and `-Out` also copies it to `out\<arch>\`. The editor reads the game data the way the game does: `/init <file>` names the init file (FAF's `init_faf.lua`), else `SupComDataPath.lua` next to the exe.

## Play

Pick a map in the Map panel (each map by its title, then its folder name; type to filter, double-click to play) or in Play > Map, and press **Play** or F5. The map loads and plays inside the editor's view, between the panels, with the game's own interface. **Stop** or F5 returns to the editor. So does the game's own way out of a session: its menu's exit, quitting from the score screen, and "Exit to Windows", which stops the play instead of closing the editor. View > Panels while playing (on by default) hides the panels during play when turned off, so the game takes the whole window. The window's title says what plays.

The Map panel sets the play up, the way FAF's `/map` quick start does (`SinglePlayerLaunch.lua`) but with these choices:

- **Solo** (default) or **Against AI** with one of the game's AI types for every other army. Solo is the faster start: with no AI there is no AI map analysis (SCMP_009, second play: 2.3 s to the game solo, 4.5 s against "rush").
- **Faction**: random or one of the game's factions.
- **Fog**: fog of war ("explored") or none. The sim fixes fog when the game starts, so it applies from the next Play.
- **Keep this setup for this map**: on, the map keeps its own setup, saved at each Play; off, it plays with the setup of the last Play on any map. Picking a map takes its own setup or the last one. Kept in `%LOCALAPPDATA%\FAForever\Editor\play_setups.ini` by map folder name without its `.vNNNN` version, AI and faction by their keys. Test runs from the command line read it but don't write it.
- **See the whole map**, during play: the view switches to an observer's (no fog, every army) and back to your army. Editor plays have cheats on for this, without changing the `debug.enable_debug_facilities` preference the game reads.

Campaign maps go through FAF's own campaign setup. No replay is written.

How fast a play starts:

- The game's rules (every unit, projectile and effect blueprint, about 1.5 s to build for FAF) are built on a thread of their own when the editor starts, for the mods a skirmish uses (`RULE_PrepareKept`), and each play's rules are kept for the next one (`RULE_SetKeepBetweenSessions`). A Play pressed before they are ready waits for them. The game builds them for every session.
- Loading shows one line of text in the view ("Loading Seton's Clutch ...") instead of the game's faction movie, "IN TRANSIT" screen and loading tips, and the game's panels come in as soon as the map is ready instead of after the "IN TRANSIT" picture fades (`InstallLoadingView`, through `moho::gUIBeforeStartGameUI`).
- Solo, a Play 5 s after the editor starts reaches the game in about 2.3 s on SCMP_009 and 2.7 s on Alpha 7 Quarantine (SCMP_021, 40 km); later plays in 1.0-1.3 s and 1.6-2.0 s (Direct3D 12, Vulkan). On SCMP_021 two engine changes do it: the 3584 building skirts its start flattens update the terrain normal map one tile at a time for all of them (`IWldTerrainRes::NotifyMapChanges`, 30 ms where one update per skirt took 1.6 to 3.3 s), and a whole-map normal-map rebuild after the map changed is encoded on 4 threads as the loader's (0.4 s, from 1.6 s).

| Switch | Effect |
|---|---|
| `/d3d12` | Direct3D 12 only |
| `/vulkan` | Vulkan only |
| (neither) | Direct3D 12, then Vulkan; if neither starts, the editor says so and exits |
| `/log <file>` | The engine log, as in the game; the Log panel shows it too |
| `/logtimes <file>` | Also writes every log line with its time in seconds since the editor started (the Log panel's "Times" box shows the same), for timing where a play's start goes |
| `/play <map>` | Plays that map (its folder or scenario name, e.g. `SCMP_009`) once the editor is up |
| `/playseconds <s>` | With `/play`: stops after s seconds of play |
| `/playcycles <n>` | With `/play`: plays and stops n times |
| `/playafter <s>` | With `/play`: waits s seconds after the editor is up before the first play (timing a first play as a user would start it) |
| `/playquit` | With `/play`: closes the editor after the last one (test runs) |
| `/playai <key>` | With `/play`: against that AI (`rush`, `easy`, ...) instead of solo |
| `/memtrace` | Records every heap block's call stack (slow) and, after each play, logs the call sites of what the play before it left alive, the largest first. Without it the log still gets, two seconds after each play, the process's private memory split by heap, thread stacks and direct allocations, what grew since the last play, the Lua range's use by size class, and the engine types whose live count changed |
| `/open <map folder>` | Opens that map for editing at start (the folder name without `_scenario.lua`, any case) |
| `/openall` | Opens every map in `/maps` in turn, logs each one and a summary of those that did not open fully, then closes the editor (test runs) |
| `/playsetups <file>` | Reads and writes the remembered play setups in that file instead of `play_setups.ini` (test runs) |
| `/playwholemap` | With `/play` and `/playseconds`: switches to the whole map when play starts and back halfway (test runs) |
| `/playexitapp` | With `/play` and `/playseconds`: ends each play the way the game's "Exit to Windows" does (`ExitApplication()`), which the editor turns into a Stop (test runs) |
| `/d3d12debug`, `/vulkandebug` | The API's debug or validation layer, as in the game ([Renderer backends](RENDERER_BACKENDS.md)) |

`/play` takes several maps separated by commas; the runs take them in turn.

The window is always one maximized, movable, resizable window with a menu bar (File, View, Play), whatever the game's display options say; the game's own display option doesn't change it either. The panel layout is kept in `%LOCALAPPDATA%\FAForever\Editor\layout.ini`; View > Reset layout restores the default.

**Open for editing** (Map panel) opens the picked map into the editor's document on a thread of its own: the `.scmap` as the game loads it, `_scenario.lua` and `_save.lua`, each in the editor's own Lua state, apart from any play. The Info panel (View > Info; View > Reset layout docks it beside the Map panel) shows what was read: size, height field, water, terrain shader, the ten texture layers, props, decals, markers by type, armies and the map's files. Between plays the game's view shows the opened map (terrain, texture layers, decals, water) through the game's own renderer, as the original editor did: the editor puts its map in the renderer's map (`REN_SetWldMap`) with a world view and a camera of its own (`view/EdMapScene.cpp`), and takes them away before a play's session takes over. Camera: middle mouse button drag orbits, Shift + middle drag or right drag pans (the ground follows the cursor), WASD or the arrow keys move (Shift faster), the wheel zooms toward the point under the cursor without changing the camera's tilt, Home frames the whole map. The map's props are drawn as mesh instances from the blueprints of the rules the editor keeps for its next play (`RULE_PeekKept`), once those are built after startup.

**Terrain brush:** with the Terrain tool, the left mouse button held over the opened map paints heights with the panel's mode (Raise, Lower, Smooth, Flatten to the height under the stroke's first point, Noise), radius, strength, falloff and symmetry (`tools/EdHeightBrush.cpp`). Symmetry is exact: each group of mirrored samples gets one new height, computed from its first member, written to all of them, so mirrored halves stay identical and a stroke on a mirror line applies once (GoogleTest `faf_editor_brush_tests`). N-way turns (2 to 16 copies, the panel offers 3 to 8) can't be exact, as their copies fall between vertices: the first sector (from the map's centre towards +x, turning towards +z) is painted, and every other vertex the brush covers, plus 2 vertices past its edge, takes the height at its point turned back into the first sector, read between vertices; 4 turns are exact. The diagonal and turn modes paint without symmetry on a map that isn't square. The symmetry's mirror lines are drawn along the ground (the turn centre as a vertical axis, the sectors' edges for N-way turns), and the brush shows as rings on the terrain at every copy (white at the cursor, orange at the mirrored ones; the inner ring is where the falloff starts), drawn through the renderer's editor hook (`ED_SetHook`). Edit > Undo and Redo, Ctrl+Z and Ctrl+Y (or Ctrl+Shift+Z) in the view or the panels, take back whole strokes, byte for byte (`undo/EdHeightHistory.cpp`: the 32 x 32 tiles a stroke touched, before and after; 256 MB at most, the oldest strokes go first).

**Symmetry check** (Tools panel, Terrain, under Symmetry; `tools/EdSymmetryCheck.cpp`): Check compares every vertex with its copies under the chosen symmetry and marks the differing ones as red blocks on the terrain (Show differences), with a count and the largest difference; it is kept up to date after strokes, undo and redo. N-way turns compare a vertex with the height at its point turned back into the first sector and count differences above a quarter unit. "Copy the source part to the other copies" makes the heights symmetric from the part nearest the map's top-left corner (the first sector for turns), as one undo step. Texture masks and objects are not checked yet. `/symcheck <mode>[x<turns>][:repair]` with `/open <map>` runs the check (mode: the panel's symmetry, 0 None to 9 N-way) and the copy on the drawn map (GoogleTest `faf_editor_brush_tests`: a planted one-vertex difference is found and repaired in every mode).

**Height field import and export** (Tools panel, Terrain, Height field; `tools/EdHeightFile.cpp`): Import reads `.png`, `.bmp` or `.tif` through the Windows imaging component as 16-bit grey (8-bit images spread over 16 bits), or `.raw` / `.r16` (World Machine) as 16-bit little-endian words, square or of the map's size; it is resampled to the map's size and is one undo step. Export writes `.png` (16-bit grey), `.raw` or `.r16`, at the map's size or 257 to 4097 wide (a rectangular map keeps its proportions). Heights are times the panel's height scale both ways; a word is 1/128 of a game unit, as in the map file. `/heightexport <file>` and `/heightimport <file>` with `/open <map>` do the same from the command line, and `/heightdialog` opens the import dialog (GoogleTest `faf_editor_brush_tests`: every format reads back what it wrote).

**New map** (File > New map, Ctrl+N; `doc/EdNewMap.cpp`): a title, the folder (FAF's `name.v0001`, from the title until edited), skirmish or campaign, 5 to 81 km, 1 to 16 players, the ground's height and an optional sea with its level (deep and abyss 2.5 and 15 below). The document's worker makes the engine's empty map (`CWldMap::MapNew`, 0x00890D40: the default layers, cleared masks) at that height and sea, and writes `<vault>/maps/<folder>/` with the `.scmap` (a 256 x 256 preview, ground green or sea blue, the start positions as dots), `_scenario.lua`, `_save.lua` (start markers `ARMY_1`... in a ring at 35% of the size, the first at the top; one army entry each plus `ARMY_17` and `NEUTRAL_CIVILIAN`) and `_script.lua`. The folder is then mounted at `/maps/<folder>` (`CVFSImpl::MountDirectoryLate`, an engine addition), listed in the Map panel and opened. `/newmap <folder>[,<size 0-4>,<players>,<height>,<sea level or 0>]` does the same from the command line. The sea's water map starts empty (flat shading) until the water tools fill it.

**Saving** (`doc/EdMapFile.cpp`, `doc/EdDocument.cpp`):

- **File > Save** (Ctrl+S) writes the opened map's `.scmap` over its file, only when that file is in the vault (`<vault>/maps/...`): maps inside the game's archives or folders have no file of their own to save over and are saved as a new map folder instead. The first save over a file copies the old `.scmap` to `<folder>/.editor_backup/<date-time>/`.
- **File > Save as new map folder...** asks for a folder name (the next version, `seton.v0002` after `seton.v0001`, is offered) and writes `<vault>/maps/<folder>`: every file of the map's folder, those named after the map renamed to the folder's name without its version, the `.lua` files' paths into the old folder pointed into the new one, and the edited `.scmap`. The game lists it from its next start.
- The vault is FAF's (`Documents/My Games/Gas Powered Games/Supreme Commander Forged Alliance`), or `/vault <folder>` on the command line.
- What is written: the file header, the preview image as read (byte for byte), the terrain as the game's own writer saves it (version 60: heights, the ten texture layers, water, decals, masks and the rest), then the props. A prop the editor didn't move keeps its record byte for byte; a moved one is written from its position and rotation with scale 1, which the game ignores. The masks are written with the classic DDS header (`ImageCodec::PreferOwnDds`): the game's Direct3D 9 decoder doesn't read the newer DX10 header. The normal map and the water maps are rebuilt from the terrain, so their bytes differ from the original file's.
- `/roundtrip <folder>` (with `/openall` or alone: every map; with `/open <map>`: the drawn map) saves each map under `<folder>`, reads it back, compares heights, water, shader, layers, props and decals, saves again and compares bytes, then closes. All 63 maps of the game come back with the same data, and a second save is byte-identical to the first. `/saveas <folder>` with `/open <map>` saves the drawn map as that new folder and closes.

The Tools panel is laid out as the plan's mockup: a strip of tool icons and the chosen tool's settings (brush modes, size, strength, falloff, the symmetry modes with their diagrams). The settings are kept but act on a map only from the tool stages of the plan.

## How it is built

- **Target:** `src/editor/CMakeLists.txt` adds `faf_editor`, which links the engine's object library `faf_engine` whole, as the engine tests do, so the engine's objects are linked in the game's order. The game's `WinMain` is one of them, so the editor starts at its own `main()` (`/ENTRY:mainCRTStartup`). It carries the game's window resources and manifest and the DXC DLLs as the game does.
- **The game inside:** the editor's app (`EdApp.cpp`) holds the game's own `CScApp` and runs the game's loop (`WIN_AppExecute`), with what the game's `WinMain` sets up around it (the crash report's die handler, the accessibility hotkeys turned off and restored). The window, device, user interface, sound and world sessions are the game's, unchanged. Engine additions in `CScApp`, unused by the game: `moho::gAppRenderers` (Direct3D 12 and Vulkan only, no Direct3D 9/10 fallback), `moho::gAppWindowed` (one normal window; `SC_PrimaryAdapter` leaves it alone) and `moho::gAppBeforeDeviceCreate` (the editor's second head). The game's first-frame start (main menu or command-line session) is skipped; sessions start from Play.
- **Two heads:** the device has the game's head 0 on the game's viewport, which the editor keeps over the middle of its dock layout, and a head 1 on the editor's own child window under it, for the panels. The game draws only head 0 (its viewport was made for one head); the editor draws head 1 each frame, and the game's paint presents both. When the layout or the window changes, the viewport is moved and both heads are resized (`CD3DDevice::InitContext`). The game's interface lays itself out in the viewport and takes its input there, as in the game.
- **Panels:** [Dear ImGui](https://github.com/ocornut/imgui) 1.92.4, docking branch, pinned in `cmake/FafDependencies.cmake` and built by `cmake/deps/imgui`, drawn by `ui/EdImGuiRenderer.cpp` on gal's GPU programs (`gpg/gal/GpuDriven.h`): one HLSL source DXC builds for both APIs. Its input is the panels' window's; F5 is the editor's in either window.
- **Play** (`EdPlay.cpp`): the editor's Lua launcher builds the session info as FAF's quick start does and calls `LaunchSinglePlayerSession`; `WLD_Teardown` ends the session, before the game's frame would go on to its main menu. A Lua request to quit during play (`ExitApplication`) ends the session, not the editor.
- **Older renderers:** their DLLs are delay-loaded (`d3d9.dll`, `d3dx9_43.dll`, `d3d10.dll`, `d3d11.dll`), so the editor starts without the June 2010 DirectX runtime and never loads Direct3D 9. Direct3D 11 still loads when Direct3D 12 or Vulkan decode a texture: they do it on a private WARP device ([Renderer backends](RENDERER_BACKENDS.md)).

## Known issues

- Each Play still keeps about 1.2 MB of private memory after it ends (SCMP_009, 20 plays): the heap's caches (0.2-0.8 MB a play, textures and file lookups) and about 0.6 MB of the Lua range, mostly the editor's UI state growing slowly. Freed before: a sync packet's shared references (the sim's height field, 4 MB), the world meshes the game UI never destroys (13 a play), the cursor each UI state switch made (2 a play), and about 6 MB a play in the Lua range (freed large blocks were never merged, and a thread could take every free small block of a size).
- A popup of the panels that reaches over the game's view is hidden behind it (the view is its own window).
