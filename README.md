# faf-re

The Moho engine behind *Supreme Commander: Forged Alliance* (2007), rebuilt as modern, readable, buildable C++20 — so it can be maintained instead of staying frozen in a binary nobody can change. Inspired by, and indebted to, the [Forged Alliance Forever](https://faforever.com) community.

> An independent preservation and interoperability effort. Not affiliated with, endorsed by, or supported by the original publisher or developer.

## Status

| | |
|---|---|
| Builds | ✅ `main.exe` (x86) and `main_x64.exe` link and run |
| Renders | ✅ main menu, cinematic playback, in-game world view |
| Plays | ✅ native save/load on both architectures |
| Gameplay testing | ✅ Live 3-player game with the retail exe, rebuilt x86 and rebuilt x64 together: 21 min of AI-driven fighting, no desync — see [Live multiplayer](docs/RETAIL_REPLAY_PARITY.md#live-multiplayer-retail-x86-and-x64-in-one-game) |
| Retail parity | ✅ 76 of 76 FAF vault replays tested play back checksum-identical to the retail executable on 100% of gameplay beats — see [Retail replay parity](docs/RETAIL_REPLAY_PARITY.md) |
| Source bodies written | ~39,000 functions |
| Genuinely outstanding | ~430 |

*Snapshot: 20/10/2026.*

Most symbols in the retail engine were never hand-written code — they are template instantiations, folded aliases, unwind glue and static-init thunks the 2007 compiler emitted from a single source line. Those are rebuilt as that one line, not as hundreds of separate functions, so the function count understates how much is covered.

## Retail replay parity

76 real games from the FAF replay vault (Dual Gap, Seton's Clutch and 35 other stock and community maps, 1–12 human players, games against the built-in AI and M28AI, 9–83 minutes) play back on the rebuilt engine checksum-identical to the retail `ForgedAlliance.exe` on every gameplay beat. Method, per-replay results and the causes of past divergences: [docs/RETAIL_REPLAY_PARITY.md](docs/RETAIL_REPLAY_PARITY.md).

## Performance

The simulation thread now costs about 18 % less per tick than at the start of
profiling, with every change verified against retail replays:
- hot-path diagnostics removed;
- redundant recon, intel, allocation and lookup work cut;
- recon refresh optionally on worker threads (`sim_Workers`, default 0 = the
  original serial path), which reproduces the serial result byte for byte.

The x64 build ran a stress map past 89,000 units at 3.8 GB, where the 32-bit
build's simulation runs out of address space at about 60,000.

Replays play about 1.8× faster, and huge maps run 55–60 % more ticks per
second at 30,000–60,000 units:
- replays and single-player games compute beats ahead of the one on screen
  (multiplayer keeps the original pacing);
- per-beat unit updates, strategic icons, culling and fog of war run on worker
  threads.

Each change has a console variable to restore the original path.

Next up: Direct3D 11, D3D12 and Vulkan renderer backends. Measurements, the threading rules and the roadmap:
[docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## What is and isn't here

**Here:** C++ source, build files, and the tooling used to check behaviour against the original.

**Not here:** any game binary, executable, asset, map, script or other copyrighted content, and nothing derived from them — `bin/`, `dumps/`, `decomp/`, `output/` and `gamedata/` are excluded by design. **You need your own legitimately obtained copy of the game.** Nothing here distributes, circumvents or replaces it.

## Projects

`main` — the engine, and the primary project. `inspect-injector` and `inspect` — a launcher and companion library used to observe the engine while it runs.

## Libraries the engine uses

- Boost `1.34.1`
- LuaPlus `5.0` build `1081`
- wxWidgets `2.4.2` (MSW)
- Wild Magic `3.8`
- [zlib `1.2.3`](https://github.com/OSDVF/zlib-win-x64)
- BugSplat
- CRI Middleware (Sofdec + ADX) in the original; replaced here by FFmpeg/libav* for SFD movie playback.
- DirectX 9/10 with XACT audio, where the DX10 path was already partial in the original.

## Credits

Built on many years of engine study by the Forged Alliance Forever community. Particular thanks to [Hdt80bro](https://github.com/Hdt80bro) and [4z0t](https://github.com/4z0t).

## Independent SFD movie playback

The engine does not use or distribute the CRI Sofdec/ADX runtime. `.sfd`
compatibility is independently implemented with FFmpeg and a bounded FAF metadata
parser. Legacy `mwPly*`/`ADXM_*` names are retained internally as a compatibility
facade for recovered Forged Alliance call sites, not the original CRI implementation.
Embedded audio and optional external XACT sound/voice cues remain separate.
See [the compatibility profile and dependency setup](docs/FAF_SFD_COMPATIBILITY.md)
and [validation results](docs/FAF_SFD_VALIDATION.md), including unsupported composition modes.
