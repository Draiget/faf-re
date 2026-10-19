# faf-re

The Moho engine behind *Supreme Commander: Forged Alliance* (2007), rebuilt as modern, readable, buildable C++20 — so it can be maintained instead of staying frozen in a binary nobody can change. Inspired by, and indebted to, the [Forged Alliance Forever](https://faforever.com) community.

> An independent preservation and interoperability effort. Not affiliated with, endorsed by, or supported by the original publisher or developer.

## Status

| | |
|---|---|
| Builds | ✅ `main.exe` (x86) and `main_x64.exe` link and run |
| Renders | ✅ main menu, cinematic playback, in-game world view |
| Plays | ✅ native save/load on both architectures |
| Gameplay testing | ✅ x86 ↔ x64 lockstep multiplayer: hundreds of consecutive checksum-identical beats, no desync |
| Retail parity | 🟡 FAF vault replays play back checksum-identical to the retail executable for tens of thousands of beats — see [Retail replay parity](#retail-replay-parity) |
| Source bodies written | ~39,000 functions |
| Genuinely outstanding | ~430 |

*Snapshot: 19/10/2026.*

Most symbols in the retail engine were never hand-written code — they are template instantiations, folded aliases, unwind glue and static-init thunks the 2007 compiler emitted from a single source line. Those are rebuilt as that one line, not as hundreds of separate functions, so the function count understates how much is covered.

## Retail replay parity

Real multiplayer games from the FAF replay vault are played back on both the retail `ForgedAlliance.exe` and the rebuilt engine. Both dump the full simulation checksum on every beat (`sim_ChecksumPeriod` 1), and each beat is compared. One differing bit anywhere in the sim state fails the beat.

| Replay | Game | Result |
|---|---|---|
| 26935800 | Dual Gap, 12 players, 41 min | Every beat matches from 4 to 22,636 of 24,565. The next divergence is being chased. |
| 26876279 | Seton's Clutch, 8 players, 37 min | Every gameplay beat matches, 4 to 22,155. The only difference is the final beat, where the engine deliberately keeps the commands that retail drops after a player leaves a replay. |
| 26957207 | Dual Gap, 12 players, 47 min | Retail reference capture in progress. |

Most of the remaining divergences have come from the 2007 floating-point environment: the sim keeps some intermediate results in x87 registers at 24-bit precision, where SSE rounds every step. The rest came from small call-order differences in the random-number stream.

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
