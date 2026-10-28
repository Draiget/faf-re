# Performance

The rebuilt x64 engine plays the same games as retail `ForgedAlliance.exe`, bit for bit, and about **a quarter faster**.

*Snapshot: 24/10/2026.*

## Against retail

Five FAF vault replays, played one at a time. Retail runs D3D9. Ours runs x64 with every switch at its default, 8 sim workers and D3D12. Time is wall-clock seconds from game 0:00 to the end of the replay. Every run matched every checksum the players recorded.

| Replay | Players | Game length | Retail | Ours | Faster by |
|---|---|---|---|---|---|
| 26919967 | 12 | 46 min | 1675 s | 1125 s | **33 %** |
| 26928802 | 8 | 39 min | 1123 s | 855 s | **24 %** |
| 26935800 | 12 | 41 min | 1244 s | 1032 s | **17 %** |
| 26997072 | 10 | 23 min | 180 s | 151 s | **16 %** |
| 26923388 | 2 | 45 min | 189 s | 181 s | **4 %** |

| | Time saved | Speed |
|---|---|---|
| Least (small game, both near the game's speed cap) | 4 % | 1.04× |
| Most | 33 % | 1.49× |
| Average | 19 % | 1.25× |
| All five together (4411 s → 3344 s) | 24 % | 1.32× |

The bigger the battle, the bigger the gain. In the heaviest stretch of the three large games (ticks 20,000–22,000) we are 23–38 % faster.

A few more details:

- **Without sim workers** our x64 is about 9 % faster than retail (26935800, D3D9).
- **D3D9 is faster than D3D12 in a replay at full speed**: 924 s against 1032 s on 26935800.
- **Memory**: we use 0.4–0.9 GB more than retail, because of 64-bit pointers and the D3D12 backend.
- **Scale**: x86 runs out of address space at about 60,000 units. x64 was still running at 90,000.
- **Multiplayer**: retail and our x64 played 30 minutes in one lobby without a desync, with and without sim workers.

## Where the speed comes from

- **Sim work on worker threads**: recon blips, entity coordinate updates, sync packets and the Lua garbage collector's mark and sweep. The collector alone went from 35.9 s to 9.3 s per game.
- **Less repeated work in the sim**: intel grids, recon blip refreshes, blueprint lookups, area queries and checksum hashing no longer redo work whose result is already known.
- **Pacing**: replays and single player compute a few beats ahead of the screen, on the original rate schedule.
- **Main thread on workers**: strategic icons, view culling, fog of war and applying each beat's unit updates.

## How it stays exact

The sim checksum covers every bit of game state, so a speed-up is only kept if it changes nothing:

- A step runs in parallel only when the result is provably the same as running it serially. Anything order-sensitive (Lua, random numbers, creating entities) stays on the sim thread, in the original order.
- The benchmark replay produces the same checksum on every one of its 24,565 beats with 0 and with 8 workers.
- 75 vault replays match every recorded checksum on the final build.
- Every change has a switch that brings back the original code. See [Switches](SWITCHES.md).

## What did not help

- **Lua interpreter**: about 140 CPU cycles per instruction, spent waiting on memory for table lookups. Two faster dispatch paths changed nothing, so they were dropped.
- **Running Lua callbacks in parallel**: only 2–7 % of them are independent. The rest allocate, use the random stream or call into the engine.
- **Reusing a unit's old pose object, or keeping unchanged blip lists**: in real games the conditions almost never hold.
- **Dynamic sim Lua GC threshold (`sim_GCPeriod`)**: Disabling the forced 70-tick GC reset in the sim thread (`lua_setgcthreshold(mLuaState->m_state, 0)`) or changing its interval caused multiplayer and replay desyncs because Lua garbage collection timings diverged across clients. Prerequisites for enabling this optimization in the future:
  - All players in the match must run the same new engine build (a complete transition away from the legacy/retail `ForgedAlliance.exe`, which hardcodes 70-tick resets).
  - All connected clients must share the exact same `sim_GCPeriod` setting.

## Next

1. Pose and animation on sim workers (about 14 % of sim time).
2. D3D12 cost in replays at full speed.
3. Memory use.
4. GPU-driven draws (branch `gpu-driven`, not merged).
5. Dynamic sim Lua GC threshold (`sim_GCPeriod`): eliminate periodic forced Lua GC resets in the sim once all players transition to the new engine build (completely abandoning legacy `ForgedAlliance.exe`) and share the exact same `sim_GCPeriod` setting.
