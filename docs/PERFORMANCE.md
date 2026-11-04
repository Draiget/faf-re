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
- **Added after this snapshot, not in the table above**: unit pose updates on sim workers (`sim_ParallelPose`: 7.8 % less wall time on 26954789 in one headless off/on/on/off test, with a spread between the two off runs larger than that), and the pose, bone and economy stat shortcuts from PR #30 (4.2 % less on 28007941 on D3D9, median of 6 runs, as measured in that PR). See [Simulation bottlenecks](RESEARCH_PERF_BOTTLENECKS.md).

## How many games fit on a server

Each run kept that many games going at live speed (`headless --pace`, with the server's work per player from `--view-bench`) on 8 real cores of one Xeon Gold 6144 for 60 minutes, on the Linux build of e225ad4e0. Game sizes were drawn from the replay pool's mix, and only the second half is read. 100 ms per beat is game speed 0 and 79 ms is +1. "Behind" is how much longer the games took than at exactly that speed. The last column counts places where 10 s of game ran at least one speed setting slower than the target.

| Games | ms per beat | Threads | Behind | 10 s too slow |
|---|---|---|---|---|
| 24 | 100 | one per game | 0.19 % | 0 |
| 32 | 100 | 2 workers on games of 8+ players | 0.04 % | 0 |
| 32 | 79 | one per game | 0.13 % | 0 |
| 40 | 100 | one per game | 0.83 % | 6, all after another job raised the machine's load from about 10 to 35-47 |
| 50 | 100 | one per game | 4.7 % | 21 |
| 50 | 100 | 2 workers on games of 8+ players | 10.1 % | 34 |
| 40 | 79 | one per game | 20.9 % | 67 |
| 60 | 100 | one per game | 34.1 % | 154 |

No finished game had a mismatch or crash. Games still running at the cutoff were stopped, so they have no verdict. Memory was about 230 MB per game.

So about 4 games per core holds at speed 0 and at +1. Past about 5 per core all games slow down together, small ones too, so a server has to refuse games before that point, and that isn't built yet. Nothing goes over a real network in these runs. 16 cores at 4 per core is 64 games, but no run has used 16 cores at once or any other CPU.

The heaviest games need CPUs of their own rather than a share of a core (`--cpus` in [Switches](SWITCHES.md)). These ran one game at a time at 79 ms per beat, with parallel views, on real cores of the same CPU, while other jobs used the machine at a load of about 10:

| Replay | Cores | Sim workers | Behind | Worst 30 s | Peak memory |
|---|---|---|---|---|---|
| 26978344, 8v8, 16 views | 8 | 7 | 0.44 % | 82.1 ms | 907 MB |
| 26978344, 8v8, 16 views | 4 | 3 | 5.0 % | 97.6 ms | 882 MB |
| 26885749, 12 players, 12 views | 4 | 3 | 0.10 % | 79.8 ms | 520 MB |

So 8 cores hold the heaviest game known at about +1, and 4 cores hold it at speed 0, with 95 windows of 10 s just over 100 ms near the end. All three had 0 mismatches.

## How it stays exact

The sim checksum covers every bit of game state, so a speed-up is only kept if it changes nothing:

- A step runs in parallel only when the result is provably the same as running it serially. Anything order-sensitive (Lua, random numbers, creating entities) stays on the sim thread, in the original order.
- The benchmark replay produces the same checksum on every one of its 24,565 beats with 0 and with 8 workers.
- 75 vault replays match every recorded checksum on the final build.
- Every change has a switch that brings back the original code. See [Switches](SWITCHES.md).

## What did not help

- **Lua interpreter**: about 140 CPU cycles per instruction, spent waiting on memory for table lookups. Two faster dispatch paths changed nothing, so they were dropped.
- **Running Lua callbacks in parallel**: only 2–7 % of them are independent. The rest allocate, use the random stream or call into the engine.
- **Reusing a unit's old pose object, or keeping unchanged blip lists**: in earlier trials the conditions almost never held in real games. The pose reuse later shipped as `sim_RecyclePose`, and how often it applies in a game has not been measured since. See [Simulation bottlenecks](RESEARCH_PERF_BOTTLENECKS.md).
- **Army ticks on sim workers**: a trial desynced at beat 500. Allies write into each other's resources during a tick, and platoon cleanup and AI brains run Lua. See [Simulation bottlenecks](RESEARCH_PERF_BOTTLENECKS.md).
- **Packing the spatial grid and SIMD overlap tests**: under 0.1 % change in match time, because `Sim::AdvanceCoords` is only about 3 % of a tick. See [Simulation bottlenecks](RESEARCH_PERF_BOTTLENECKS.md).

## Next

1. Pose updates still on the sim thread, such as units with aim or builder arm manipulators: about 40 % of pose updates on 26954789 when last counted (see [Simulation bottlenecks](RESEARCH_PERF_BOTTLENECKS.md)).
2. D3D12 cost in replays at full speed.
3. Memory use.
4. GPU-driven draws (branch `gpu-driven`, not merged).
