# faf-re

The Moho engine behind *Supreme Commander: Forged Alliance* (2007), rebuilt as modern, readable, buildable C++20 — so it can be maintained, ported and extended instead of staying frozen in a binary nobody can change. Inspired by, and indebted to, the [Forged Alliance Forever](https://faforever.com) community.

> An independent preservation and interoperability effort. Not affiliated with, endorsed by, or supported by the original publisher or developer.

## Status

| | |
|---|---|
| Builds | ✅ `main.exe` links and runs |
| Renders | ✅ main menu, cinematic playback, in-game world view |
| Source bodies written | ~39,000 functions |
| Genuinely outstanding | ~430 |

*Snapshot: 23/09/2026.*

Most symbols in the retail engine were never hand-written code — they are template instantiations, folded aliases, unwind glue and static-init thunks the 2007 compiler emitted from a single source line. Those are rebuilt as that one line, not as hundreds of separate functions, so the function count understates how much is covered.

## What is and isn't here

**Here:** C++ source, build files, and the tooling used to check behaviour against the original.

**Not here:** any game binary, executable, asset, map, script or other copyrighted content, and nothing derived from them — `bin/`, `dumps/`, `decomp/`, `output/` and `gamedata/` are excluded by design. **You need your own legitimately obtained copy of the game.** Nothing here distributes, circumvents or replaces it.

## Projects

`main` — the engine, and the primary project. `inspect-injector` and `inspect` — a launcher and companion library used to observe the engine while it runs.

## Libraries the engine uses

Boost `1.34.1` · LuaPlus `5.0` build `1081` · wxWidgets `2.4.2` (MSW) · Wild Magic `3.8` · [zlib `1.2.3`](https://github.com/OSDVF/zlib-win-x64) · BugSplat · CRI Middleware (Sofdec + ADX) · DirectX 9/10 with XACT audio, where the DX10 path was already partial in the original.

## Credits

Built on many years of engine study by the Forged Alliance Forever community. Particular thanks to [Hdt80bro](https://github.com/Hdt80bro) and [4z0t](https://github.com/4z0t).
