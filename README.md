# faf-re

The Moho engine behind *Supreme Commander: Forged Alliance* (2007), rebuilt as readable, buildable C++20 so it can be maintained instead of staying frozen in a binary. It builds for x86 and x64, plays real games bit for bit like the retail `ForgedAlliance.exe`, and the x64 build plays replays about a quarter faster.

*Snapshot: 24/10/2026.*

> An independent preservation and interoperability effort, inspired by and indebted to the [Forged Alliance Forever](https://faforever.com) community. Not affiliated with, endorsed by, or supported by the original publisher or developer.

## Status

| | |
|---|---|
| Builds | `main.exe` (x86) and `main_x64.exe` link and run |
| Renders | Main menu, cinematic playback, in-game world view; Direct3D 9, 11, 12 and Vulkan ([Renderer backends](docs/RENDERER_BACKENDS.md)) |
| Plays | Native save/load on both architectures |
| Replay parity | All 75 replays of the current vault test set match every recorded checksum (x64 build of master `22a00a44`, MSVC, `/simworkers 8`, D3D12) ([Retail replay parity](docs/RETAIL_REPLAY_PARITY.md)) |
| Live multiplayer | Retail, rebuilt x86 and rebuilt x64 in one game: 21 min of AI-driven fighting without a desync; retail and our x64 also ran 30 min without a desync, with and without sim workers |
| Performance | x64 replays take 19 % less time than retail on average (4 % to 33 %) ([Performance](docs/PERFORMANCE.md)) |
| Recovery | Complete: every engine function the game uses is written as source (40,617 functions). The rest of the shipped exe is library code we link from source (wxWidgets, the MSVC runtime, libpng, Wild Magic, ...) or unreferenced fragments; 0 functions are outstanding |

Most symbols in the retail engine were never hand-written: they are template instantiations, folded aliases, unwind glue and static-init thunks the 2007 compiler emitted from a single source line. Those are rebuilt as that one line, so the function count understates how much is covered.

## Retail parity

Real games from the FAF replay vault (stock and community maps, 1–12 human players, games against the built-in AI and M28AI) play back on the rebuilt engine checksum-identical to retail. The earlier snapshot (20/10/2026) had 76 of 76 replays matching. Method, per-replay results and the causes of past divergences: [docs/RETAIL_REPLAY_PARITY.md](docs/RETAIL_REPLAY_PARITY.md).

## Performance

- **Against retail**: on five vault replays the x64 build saves 4 % (least), 33 % (most) and 19 % (average) of the time. The bigger the battle, the bigger the gain.
- **Scale**: x86 runs out of address space at about 60,000 units; x64 was still running at 90,000.
- **Exact**: sim work runs on worker threads only where the result is provably the same as serial, and every change has a switch that restores the original code ([docs/SWITCHES.md](docs/SWITCHES.md)).

Numbers, method and what is next: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Build

`build.ps1` (or `build.bat`) builds `src/main.vcxproj` with Visual Studio 2022 and copies the result into the FAF run folders, with its `.pdb`, the `fafengine\` hook folder, the FFmpeg DLLs and the DXC DLLs.

```powershell
.\build.ps1                    # x64 Release -> C:\ProgramData\FAForever\bin_x64\main_x64.exe
.\build.ps1 -Arch both         # x64 and x86 (x86 -> C:\ProgramData\FAForever\bin\main.exe)
.\build.ps1 -Arch x86 -Name main_test   # another exe name, to keep the current build alongside
.\build.ps1 -NoBuild           # copy the last build only
```

Other options: `-Configuration Debug`, `-FafDir`, `-Out` (also copy into `out\<arch>\`), `-NoCopy`, `-Rebuild`. Renderer toolchains (FX11, DXC, Vulkan headers) are set up as in [Renderer backends](docs/RENDERER_BACKENDS.md#toolchain-setup); FFmpeg as in [SFD compatibility](docs/FAF_SFD_COMPATIBILITY.md).

## What is and isn't here

- **Here:** C++ source, build files, and the tooling used to check behaviour against the original.
- **Not here:** any game binary, executable, asset, map, script or other copyrighted content, and nothing derived from them. `bin/`, `dumps/`, `decomp/`, `output/` and `gamedata/` are excluded by design. **You need your own legitimately obtained copy of the game.** Nothing here distributes, circumvents or replaces it.

## Layout

| Path | What |
|---|---|
| `src/` | The engine (`moho`, `gpg`, `legacy`, `lua`, `platform`, ...); project `src/main.vcxproj` |
| `data/fafengine/` | Engine-owned Lua hooks copied next to the exe (for example the Graphics API option) |
| `tools/` | Go multiplayer test harness (`mpemu`) and checkers; see [tools/README.md](tools/README.md) |
| `scripts/perf/`, `scripts/layout/` | Sampling profiler and replay helpers; vtable/RTTI comparison against the shipped binary |
| `docs/` | [Performance](docs/PERFORMANCE.md), [Switches](docs/SWITCHES.md), [Retail replay parity](docs/RETAIL_REPLAY_PARITY.md), [Renderer backends](docs/RENDERER_BACKENDS.md), [SFD compatibility](docs/FAF_SFD_COMPATIBILITY.md) |

## Libraries the engine uses

- Boost `1.34.1`
- LuaPlus `5.0` build `1081`
- wxWidgets `2.4.2` (MSW)
- Wild Magic `3.8`
- [zlib `1.2.3`](https://github.com/OSDVF/zlib-win-x64)
- BugSplat
- DirectX 9/10 with XACT audio, as shipped (the D3D10 path was already partial in the original); Direct3D 11, Direct3D 12 and Vulkan are added here.
- FFmpeg/libav* for SFD movie playback, in place of the original's CRI Middleware (Sofdec + ADX).

## SFD movie playback

The engine does not use or distribute the CRI Sofdec/ADX runtime. `.sfd` support is an independent implementation with FFmpeg and a bounded FAF metadata parser. The legacy `mwPly*`/`ADXM_*` names remain only as a compatibility facade for the recovered call sites. Embedded audio and optional external XACT sound/voice cues stay separate. Profile, dependency setup, validation and unsupported composition modes: [docs/FAF_SFD_COMPATIBILITY.md](docs/FAF_SFD_COMPATIBILITY.md).

## Support

This rebuild took a lot of time and paid AI compute. If it is useful to you, donations in ETH are welcome: `0x8f614802906dF231b8fbC9a6f11C6728D2A13DDF`

## Credits

Built on many years of engine study by the Forged Alliance Forever community. Particular thanks to [Hdt80bro](https://github.com/Hdt80bro) and [4z0t](https://github.com/4z0t).
