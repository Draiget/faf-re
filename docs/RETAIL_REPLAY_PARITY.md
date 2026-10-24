# Retail replay parity

Real games from the FAF replay vault, multiplayer and against the built-in AI or M28AI, are played back on the rebuilt engine and checked bit for bit against the original `ForgedAlliance.exe`. Every replay in the current test set matches.

*Snapshot: 24/10/2026.*

## Current result

- **x64 Release, master `22a00a44` (MSVC)**, `/simworkers 8`, Automatic renderer (D3D12): all 75 replays of the current vault test set matched every recorded checksum. 46 played to game end; the other 29 have no game-over event and were closed on their last frame.
- **x86, same commit**: replay 26935800 also passed (`/d3d9 /simworkers 8`).
- **The 75-replay set** is the table below without 26946725 and 27001706, plus 27028960.
- **Earlier result (20/10/2026)**: 76 of 76 replays matched, as listed in the table.

## Method

1. **Screening.** The rebuilt engine plays the replay back and compares its sim checksum with the checksums the live players' clients recorded into the replay every 50 beats.
2. **Narrowing.** When a replay diverges, the window is narrowed beat by beat: retail and the rebuilt engine both dump the full sim state on every beat (`sim_ChecksumPeriod` 1) and the dumps are diffed. One differing bit anywhere in the sim state fails the beat.
3. **Regression.** Every fix is re-screened against all replays that already matched before it is committed.

Replays are sampled at random from the vault. A game qualifies when it runs the standard FAF game version, lasts at least ten minutes and needs no sim mod other than M28AI. Custom maps and the M28AI version a game was recorded with are fetched from the FAF content server.

**M28AI version must match exactly.** A replay that uses M28AI must be played with the M28AI version it was recorded with; the wrong version desyncs within minutes (26883423, recorded with v292 and played with v293, desynced at beat 3400).

## Results

The 20/10/2026 run, sorted by replay ID. "All checksums match" means every checksum the live clients recorded, from start to end. Players: `2 + AI` means two players with AI armies in the game, `1 vs AI` one player against the AI.

| Replay | Map | Players | Length | Result |
|---|---|---|---|---|
| 26876279 | Seton's Clutch | 8 | 37 min | Every gameplay beat matches, 4 to 22,155; only the final beat differs (by design, see below) |
| 26880663 | Dual Gap | 12 | 12 min | All checksums match |
| 26881085 | Fields of Isis | 4 | 21 min | All checksums match |
| 26883423 | Dual Gap | 2 + M28AI | 18 min | All checksums match |
| 26885749 | Dual Gap | 12 | 54 min | All checksums match |
| 26896281 | Dual Gap | 12 | 53 min | All checksums match |
| 26897073 | Dual Gap | 12 | 34 min | All checksums match |
| 26898759 | Dual Gap | 12 | 46 min | All checksums match |
| 26900602 | Seraphim Glaciers | 1 vs AI | 62 min | All checksums match |
| 26902315 | The Dark Heart | 3 | 13 min | All checksums match |
| 26902701 | Esgaroth's Ruins | 2 | 48 min | All checksums match |
| 26904089 | Esgaroth's Ruins | 2 | 19 min | All checksums match |
| 26904914 | Dual Gap | 1 vs AI | 28 min | All checksums match |
| 26905122 | Cursed Souls | 3 + M28AI | 83 min | All checksums match |
| 26905489 | Dual Gap | 12 | 33 min | All checksums match |
| 26906984 | Dual Gap | 12 | 34 min | All checksums match |
| 26911139 | Strip Mine | 1 vs M28AI | 35 min | All checksums match |
| 26912041 | Skellige | 2 | 18 min | All checksums match |
| 26912284 | UK | 3 + M28AI | 39 min | All checksums match |
| 26915859 | Dunes of Arracis | 2 | 50 min | All checksums match |
| 26917867 | Dual Gap | 12 | 35 min | All checksums match |
| 26919698 | Hargreven | 2 | 14 min | All checksums match |
| 26919967 | Dual Gap | 12 | 46 min | All checksums match |
| 26923388 | Hargreven | 2 | 45 min | All checksums match |
| 26928140 | Dual Gap | 12 | 29 min | All checksums match |
| 26928211 | Astro Crater Battles 4x4 Rich Huge | 8 | 27 min | All checksums match |
| 26928802 | Seton's Clutch | 8 | 39 min | All checksums match |
| 26930624 | Open Palms | 2 | 14 min | All checksums match |
| 26935800 | Dual Gap | 12 | 41 min | Every gameplay beat matches, 4 to 24,563; only the final beat differs (by design, see below) |
| 26938626 | Adaptive Dark Liver | 2 | 41 min | All checksums match |
| 26943656 | Mechanoclastic Rush | 6 + M28AI | 15 min | All checksums match |
| 26946725 | Dual Gap | 12 | 14 min | Matches the other nine clients on every checksum; one client desynced in the live game at beat 6,700 (see below) |
| 26950767 | Miaziknog | 3 | 37 min | All checksums match |
| 26952549 | Frithen | 2 | 15 min | All checksums match |
| 26953273 | Seton's Clutch | 8 | 30 min | All checksums match |
| 26954643 | Astro Crater Battles 3x3 Rich | 3 + AI | 51 min | All checksums match |
| 26954937 | Dual Gap | 12 | 38 min | All checksums match |
| 26954959 | Dual Gap | 12 | 37 min | All checksums match |
| 26955642 | Seton's Clutch | 1 vs AI | 23 min | All checksums match |
| 26956508 | Dual Gap | 2 | 25 min | All checksums match |
| 26957207 | Dual Gap | 12 | 35 min | All 5,069 checksums match |
| 26958235 | Desolate Dunes | 2 | 10 min | All checksums match |
| 26960818 | Daroza | 2 | 27 min | All checksums match |
| 26963960 | Astro Crater Battles 4x4 Rich Huge | 8 | 22 min | All checksums match |
| 26968042 | High Noon | 2 + AI | 34 min | All checksums match |
| 26968288 | Desolate Dunes | 2 | 16 min | All checksums match |
| 26972287 | Adaptive Rainy Day | 2 | 27 min | All checksums match |
| 26975290 | Astro 7923542 | 4 + M28AI | 28 min | All checksums match |
| 26975678 | Fields of Isis | 2 + AI | 40 min | All checksums match |
| 26976406 | Adaptive Rainy Day | 2 | 26 min | All checksums match |
| 26982657 | Dual Gap | 12 | 37 min | All checksums match |
| 26989770 | High Noon | 1 vs AI | 33 min | All checksums match |
| 26989982 | Seton's Clutch | 8 | 14 min | All checksums match |
| 26992934 | Lena River | 8 | 47 min | All checksums match |
| 26993154 | Fudge | 2 | 54 min | All checksums match |
| 26994861 | Dual Gap | 12 | 35 min | All checksums match |
| 26997072 | Astro Crater Rise Reworked 5x5 | 10 | 23 min | All checksums match |
| 26997189 | Paradise Bay | 4 | 50 min | All checksums match |
| 26997230 | Adaptive Mars – Mangala Fossa | 3 | 37 min | All checksums match |
| 27001706 | Dual Gap | 12 | 39 min | All checksums match |
| 27004084 | The Wilderness | 2 | 48 min | All checksums match |
| 27009529 | Dual Gap | 12 | 39 min | All checksums match |
| 27010745 | Adaptive Mars – Mangala Fossa | 1 vs AI | 46 min | All checksums match |
| 27013791 | Ian's Cross | 1 vs AI | 24 min | All checksums match |
| 27019199 | Astro Crater Battles 4x4 Overmap | 8 | 26 min | All checksums match |
| 27019405 | Flooded Strip Mine | 2 | 26 min | All checksums match |
| 27019665 | Astro Crater Battles 4x4 | 8 | 26 min | All checksums match |
| 27023198 | Desolate Dunes | 2 | 37 min | All checksums match |
| 27025965 | Seton's Clutch | 1 vs AI | 9 min | All checksums match |
| 27029855 | Dual Gap | 12 | 40 min | All checksums match |
| 27032464 | Astro Crater Battles 4x4 Rich Huge | 8 | 19 min | All checksums match |
| 27032784 | Stairs to Heaven | 1 vs AI | 14 min | All checksums match |
| 27033400 | Rich 2v2v2v2 | 4 | 35 min | All checksums match |
| 27034831 | Astro Crater Battles 3x3 Rich | 6 | 35 min | All checksums match |
| 27037222 | Dual Gap | 1 vs AI | 31 min | All checksums match |
| 27037528 | The Great Void | 1 vs AI | 75 min | All checksums match |

**A live-game desync is not a playback desync.** Every client records its own checksum into the replay. In 26946725 nine clients recorded the same checksum at beat 6,700 and one recorded another, then left the game; the rebuilt engine's checksum is the nine clients' one, at that beat and every later one.

**The final-beat difference is deliberate.** When a player leaves, retail drops the commands that arrive after the leave within the same batch; the rebuilt engine keeps them (`CClientBase::UpdateState`, marked `[DELIBERATE-FIX]`). In a replay this only shows on the last beat, where the remaining players' command sources end.

## Live multiplayer: retail, x86 and x64 in one game

A replay checks the rebuilt engine against checksums the players recorded. A live game checks it against the original engine running next to it: every client computes each beat itself and the clients exchange checksums, so any difference between any two of them is a desync.

| Test | Clients | Result |
|---|---|---|
| `tools/scenarios/3p-retail-control-ai.yaml` | three retail `ForgedAlliance.exe` | 29 min of game time, no desync |
| `tools/scenarios/3p-original-x86-x64-ai.yaml` | retail, rebuilt x86, rebuilt x64 | 21 min of game time, no desync |

- **The game**: a three-way free-for-all on a copy of Seton's Clutch whose script hands every army to FAF's built-in rush AI before the armies are created. Each client runs that AI in its own sim, so all three make the same decisions from the same random stream: expansion, factories, armies of several hundred units, fighting.
- **The check**: each client logs a fingerprint of every army once a minute (units, factories, engineers, stored mass and energy). In the retail, x86 and x64 game all 21 fingerprints are identical on all three clients.
- **The control run** (retail on all three seats) comes first. It shows that the AI-driven game is itself lockstep-safe, so a desync in the mixed run could only come from the rebuilt engines.

## Where divergences came from

- **The 2007 floating-point environment.** The sim keeps some intermediate results in x87 registers at 24-bit precision, where SSE rounds every step: box-vs-box separating-axis radii, vector lengths, the Gaussian's logarithm. These are reproduced with x87 helpers in `src/legacy/math/X87Math*`.
- **Call order in the random-number stream.** An extra or missing call to a function that draws from the sim's random stream shifts every later draw.
- **Order validation.** Checks that accepted orders retail refuses, for example a move order for a unit riding in an ordinary transport.
- **Float-to-integer conversions.** Places that truncate where retail's `fistp` rounds to nearest, such as a unit's footprint cell.
- **Missing state updates.** For example a carrier that never removed a launched unit from its carried set.
- **Engine functions the AI scripts call.** The Lua AI is not part of the checksum, but the orders it issues are. A wrong return value from `CPlatoon:FormPlatoon` raised a Lua error in our build only, the AI stopped issuing orders retail's AI issued, and the games diverged a few hundred beats later.
- **Formation orders.** A patrol given to a group in formation must stay tied to that formation. Ours never passed the formation to the patrol task, so each unit's patrol leg ended on its own arrival check instead of the formation's.
- **Pathfinder edge costs.** The hierarchical pathfinder buckets each edge cost as `ceil(ln(cost / distance) * 6)`. Retail takes the logarithm with the x87 `fyl2x` instruction and rounds only the product to float; ours rounded the logarithm first. Where the product sits at a whole number the bucket moved by one and a unit took a different route; seen only in long AI games, which send many units across the map.
- **Signed versus unsigned cells.** The path navigator reads a cell's coordinates as unsigned 16-bit words, so a formation slot just off the map edge (z = -1) is 65,535 cells away; ours sign-extended them, saw the slot as close, probed it, failed and dropped out of the formation one beat early.
