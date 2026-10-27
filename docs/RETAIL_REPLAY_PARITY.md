# Retail replay parity

Real games from the FAF replay vault, multiplayer and against the built-in AI or M28AI, are played back on the rebuilt engine and checked bit for bit against the original `ForgedAlliance.exe`. In the current run 315 of 323 replays match every checksum the live players recorded; 8 desync and are open.

*Snapshot: 27/10/2026.*

## Current result

- **x64 Release (clang-cl), `cd595ae0d` plus source changes not yet committed then** (parity build `bbeb0758db`), `/simworkers 8`, game version 3835, played by the [parity runner](../tools/replay-parity/README.md) on 26–27/10/2026: 323 vault replays on 143 maps, 1–12 players (49 single-player games), 3 to 108 minutes, 23 with M28AI; 172 hours of game in total.
- **302 matched every checksum** to the end of the game in that run. In 5 of them one client desynced in the live game, and the rebuilt engine matches every other client (see below). The other 21 did not finish matching: 8 desynced, 12 stopped early without a mismatch (the beat stopped advancing before the end of the command stream), and 1 was stopped by the runner of the time.
- **Rerun.** On 27/10/2026 those 21 were played again on an x64 clang-cl build with the fix of `74219d154` (below), `/simworkers 8`, 4 at a time with the window shown, each to game over:
  - **27049782 is fixed.** It desynced at beat 200 on the tested build. Fixed in `74219d154`: on an alliance change an army's recon blips move to the end of the sim's dirty list together with its units, and the beat checksum hashes that list in order. On the rerun every checksum matches to the end.
  - **26988102** matches every client to game over except Auhram, who desynced in the live game at beat 8,950.
  - **11 of the 12 that stopped early** played to the end and match every checksum. **26954789** played on and desynced at beat 14,150.
  - **The other 7 desync again** at the same beat.
- **315 match** in total; **8 desync** and are open (table below).
- **Earlier results**: all 75 replays of the 24/10/2026 set on master `22a00a44` (MSVC, D3D12), and 76 of 76 on 20/10/2026.

## Method

1. **Screening.** The rebuilt engine plays the replay back and compares its sim checksum with the checksums the live players' clients recorded into the replay every 50 beats. [`tools/replay-parity`](../tools/replay-parity/README.md) does this unattended: it picks the replays, plays several at once with the window hidden, and records a verdict per replay and build.
2. **Narrowing.** When a replay diverges, the window is narrowed beat by beat: retail and the rebuilt engine both dump the full sim state on every beat (`sim_ChecksumPeriod` 1) and the dumps are diffed. One differing bit anywhere in the sim state fails the beat.
3. **Regression.** Every fix is re-screened against all replays that already matched before it is committed.

Replays are sampled at random from the vault (ids 26,860,000 to 27,065,000, which still ran game version 3835). A game qualifies when it runs the standard FAF game version, is at least five minutes long by its header, needs no sim mod other than M28AI, and its map can be downloaded (generated maps cannot). Custom maps and the M28AI version a game was recorded with are fetched from the FAF content server.

**M28AI version must match exactly.** A replay that uses M28AI must be played with the M28AI version it was recorded with; the wrong version desyncs within minutes (26883423, recorded with v292 and played with v293, desynced at beat 3400).

## Results

Build `bbeb0758db`; the 21 replays that did not match on it were rerun on the fixed build ("on the rerun"). "All checksums match" means every checksum the live clients recorded, from start to end. Players counts people; AI armies are not counted. Length is game time, from the replay's command stream.

### Not matching yet

| Replay | Map | Players | Length | Result |
|---|---|---|---|---|
| 26870309 | Up Hill Battle | 2 | 49 min | **Desync at beat 8,400**, again on the rerun |
| 26892799 | DualGap Adaptive | 12 | 48 min | **Desync at beat 21,800**, again on the rerun |
| 26906717 | DualGap Adaptive | 12 | 36 min | **Desync at beat 12,400**, again on the rerun |
| 26954789 | DualGap Adaptive | 12 | 51 min | **Desync at beat 14,150** on the rerun; the first run stopped at beat 8,840 |
| 26961234 | Adaptive Argon | 2 + M28AI v295 | 57 min | **Desync at beat 29,650**, again on the rerun |
| 27028303 | Distortion | 1 + M28AI v295 | 21 min | **Desync at beat 4,700**, again on the rerun |
| 27051951 | Proxima m | 1 | 30 min | **Desync at beat 50**, again on the rerun |
| 27053262 | Boobs | 10 | 16 min | **Desync at beat 7,150**, again on the rerun |

### Every replay

<details>
<summary>All 323 replays of the run</summary>

| Replay | Map | Players | Length | Result |
|---|---|---|---|---|
| 26860303 | Winter Duel | 2 | 7 min | All checksums match |
| 26860459 | Astro Crater Battles 4x4 rich huge | 8 | 27 min | All checksums match |
| 26861889 | Astro Crater Battles 5x5 rich huge | 10 | 30 min | All checksums match |
| 26862501 | Survival Horde EE | 2 + M28AI v292 | 30 min | All checksums match |
| 26863605 | Adaptive Salt and Pepper | 2 | 13 min | All checksums match |
| 26864824 | Gentleman's Reef | 2 | 48 min | All checksums match |
| 26869955 | Saltrock Colony | 2 | 77 min | All checksums match |
| 26870067 | Fields of Isis | 2 | 91 min | All checksums match |
| 26870309 | Up Hill Battle | 2 | 49 min | **Desync at beat 8,400**, again on the rerun |
| 26874037 | Fields of Isis | 2 | 15 min | All checksums match |
| 26874348 | Adaptive Metir | 8 | 33 min | All checksums match |
| 26874626 | DualGap Adaptive | 12 | 18 min | All checksums match the other clients'; HedgeHO desynced in the live game at beat 4,950 |
| 26876279 | Seton's Clutch | 8 | 37 min | All checksums match |
| 26876944 | Astro Crater Battles 4x4 rich huge | 8 | 27 min | All checksums match |
| 26878981 | beach battle | 2 + M28AI v292 | 25 min | All checksums match |
| 26879494 | Survival Experimental Factory | 3 | 16 min | All checksums match |
| 26880252 | Aalhaven | 2 | 26 min | All checksums match |
| 26880663 | DualGap Adaptive | 12 | 12 min | All checksums match |
| 26881085 | Fields of Isis | 4 | 21 min | All checksums match |
| 26881086 | Adaptive pass lev | 12 | 31 min | All checksums match |
| 26882322 | Four-Leaf Clover | 1 | 108 min | All checksums match |
| 26883341 | Astro Crater Battles 4x4 rich huge | 8 | 35 min | All checksums match |
| 26883423 | DualGap Adaptive | 2 + M28AI v292 | 18 min | All checksums match |
| 26883922 | Hargreven | 2 | 10 min | All checksums match |
| 26885419 | Vya-3 Protectorate | 2 | 18 min | All checksums match |
| 26885749 | DualGap Adaptive | 12 | 54 min | All checksums match |
| 26886062 | Four-Leaf Clover | 2 | 25 min | All checksums match |
| 26886346 | Concord Lake | 1 | 14 min | All checksums match |
| 26888908 | DualGap Adaptive | 12 | 34 min | All checksums match |
| 26890886 | WARTIME 5vs5 | 1 | 10 min | All checksums match |
| 26891644 | Regor VI Highlands | 2 | 13 min | All checksums match |
| 26892082 | DualGap Adaptive | 1 | 34 min | All checksums match |
| 26892799 | DualGap Adaptive | 12 | 48 min | **Desync at beat 21,800**, again on the rerun |
| 26892982 | Seton's Clutch | 4 | 57 min | All checksums match on the rerun; the first run stopped at beat 20,645 |
| 26894670 | Astro Crater Battles 4x4 rich huge | 8 | 37 min | All checksums match the other clients'; Hellpers desynced in the live game at beat 22,200 |
| 26895125 | Astro Crater Battles 4x4 rich huge | 8 | 23 min | All checksums match |
| 26895595 | sfaasd | 2 | 35 min | All checksums match |
| 26896281 | DualGap Adaptive | 12 | 53 min | All checksums match |
| 26896405 | Astro Crater Battles 4x4 v2 TeamPlay AI | 4 | 37 min | All checksums match |
| 26897073 | DualGap Adaptive | 12 | 34 min | All checksums match |
| 26897183 | Hargreven | 2 | 28 min | All checksums match |
| 26897194 | Adaptive Rainy day | 2 | 17 min | All checksums match |
| 26898540 | survival_5thdimension v9 | 2 | 31 min | All checksums match |
| 26898759 | DualGap Adaptive | 12 | 46 min | All checksums match |
| 26899616 | Arctic Refuge | 1 | 4 min | All checksums match |
| 26899626 | Seton's Clutch | 8 | 3 min | All checksums match |
| 26900602 | Seraphim Glaciers | 1 | 63 min | All checksums match |
| 26901038 | ParadiseBay 5v5 | 3 | 52 min | All checksums match |
| 26901500 | Seton's Clutch | 2 | 23 min | All checksums match |
| 26901551 | Twin Rivers | 2 | 34 min | All checksums match |
| 26902315 | The Dark Heart | 3 | 13 min | All checksums match |
| 26902701 | Esgaroth's Ruins | 2 | 48 min | All checksums match |
| 26903590 | Tesla island | 1 + M28AI v293 | 8 min | All checksums match |
| 26903696 | Seton's Clutch | 2 | 64 min | All checksums match |
| 26904089 | Esgaroth's Ruins | 2 | 19 min | All checksums match |
| 26904914 | DualGap Adaptive | 1 | 28 min | All checksums match |
| 26904985 | Emerald Crater | 1 | 11 min | All checksums match |
| 26905122 | Cursed Souls | 3 + M28AI v293 | 83 min | All checksums match |
| 26905489 | DualGap Adaptive | 12 | 33 min | All checksums match |
| 26906674 | Shards | 1 | 73 min | All checksums match |
| 26906717 | DualGap Adaptive | 12 | 36 min | **Desync at beat 12,400**, again on the rerun |
| 26906954 | DualGap Adaptive | 12 | 44 min | All checksums match |
| 26906984 | DualGap Adaptive | 12 | 34 min | All checksums match |
| 26907642 | Endless Survival Defense | 4 | 79 min | All checksums match |
| 26907862 | Astro Crater Battles 4x4 rich huge | 3 | 39 min | All checksums match |
| 26908279 | Skellige | 2 | 59 min | All checksums match |
| 26911139 | Strip Mine | 1 + M28AI v292 | 35 min | All checksums match |
| 26911889 | ambush the enemy | 1 | 12 min | All checksums match |
| 26912041 | Skellige | 2 | 18 min | All checksums match |
| 26912284 | United Kingdom 40km map | 3 + M28AI v293 | 38 min | All checksums match |
| 26912336 | Finn's Revenge | 1 | 10 min | All checksums match |
| 26913931 | Crag Dunes | 2 | 24 min | All checksums match |
| 26914129 | Skellige | 2 | 31 min | All checksums match |
| 26914763 | Seton's Clutch | 8 | 21 min | All checksums match |
| 26915161 | Astro Crater Battles 4x4 rich huge | 8 | 32 min | All checksums match |
| 26915602 | Astro Crater Battles 4x4 rich huge very long | 3 | 70 min | All checksums match |
| 26915859 | Dunes of Arracis | 2 | 50 min | All checksums match |
| 26916677 | DualGap Adaptive | 12 | 10 min | All checksums match |
| 26917150 | DualGap Adaptive | 12 | 49 min | All checksums match |
| 26917867 | DualGap Adaptive | 12 | 35 min | All checksums match |
| 26918561 | DualGap Adaptive | 12 | 12 min | All checksums match |
| 26919133 | Astro Crater Battles 5vs5 | 2 + M28AI v293 | 54 min | All checksums match |
| 26919698 | Hargreven | 2 | 14 min | All checksums match |
| 26919967 | DualGap Adaptive | 12 | 46 min | All checksums match |
| 26921104 | Astro Crater Battles 4x4 rich huge | 8 | 27 min | All checksums match |
| 26921812 | Daroza's Sanctuary | 2 | 36 min | All checksums match |
| 26922846 | Seton 80km | 1 | 17 min | All checksums match |
| 26923279 | Skellige | 2 | 27 min | All checksums match |
| 26923388 | Hargreven | 2 | 45 min | All checksums match |
| 26924552 | Finn's Revenge | 2 | 7 min | All checksums match |
| 26924580 | pass lev | 12 | 40 min | All checksums match |
| 26924888 | Astro Crater Battles 4x4 rich huge | 8 | 31 min | All checksums match |
| 26925096 | Four-Leaf Clover | 1 | 19 min | All checksums match |
| 26925538 | Adaptive Metir | 4 | 29 min | All checksums match |
| 26925548 | Finn's Revenge | 2 | 7 min | All checksums match |
| 26925645 | Emerald Crater | 1 | 18 min | All checksums match |
| 26926208 | MegaCIty | 1 + M28AI v293 | 46 min | All checksums match |
| 26926345 | Regor VI Highlands | 2 | 15 min | All checksums match |
| 26927336 | Crag Dunes | 2 | 7 min | All checksums match |
| 26927488 | Aalhaven | 1 | 7 min | All checksums match |
| 26928140 | DualGap Adaptive | 12 | 29 min | All checksums match |
| 26928211 | Astro Crater Battles 4x4 rich huge | 8 | 27 min | All checksums match |
| 26928802 | Seton's Clutch | 8 | 39 min | All checksums match |
| 26929261 | Adaptive pass lev | 12 | 67 min | All checksums match |
| 26929320 | gap_of_rohan v4_fixed_pathing | 4 | 12 min | All checksums match |
| 26930300 | DualGap Adoptive | 4 + M28AI v293 | 64 min | All checksums match on the rerun; the first run stopped at beat 10,462 |
| 26930624 | Open Palms | 2 | 14 min | All checksums match |
| 26930750 | Twin Rivers | 2 | 18 min | All checksums match |
| 26932281 | Desolate Dunes | 2 | 15 min | All checksums match |
| 26932432 | Open Palms | 2 | 23 min | All checksums match |
| 26933269 | DualGap Adaptive | 2 + M28AI v293 | 47 min | All checksums match |
| 26933703 | Adaptive Rainy day | 2 | 11 min | All checksums match |
| 26934325 | Winter Duel | 2 | 7 min | All checksums match |
| 26934456 | Astro Crater Battles 4x4 overmap | 8 | 34 min | All checksums match |
| 26935037 | Adaptive Monument Valley | 8 | 23 min | All checksums match the other clients'; Rikudo7 desynced in the live game at beat 6,850 |
| 26935255 | IsisFields3v3 | 6 | 46 min | All checksums match |
| 26935404 | Moonlight | 2 | 35 min | All checksums match |
| 26935782 | Blasted Rock | 2 | 60 min | All checksums match |
| 26935800 | DualGap Adaptive | 12 | 41 min | All checksums match |
| 26936179 | canis 4v4 spezial edition | 4 | 66 min | All checksums match |
| 26936566 | Seton's Clutch | 8 | 32 min | All checksums match |
| 26936880 | Polar Depression | 2 | 23 min | All checksums match |
| 26938254 | Astro Crater Reworked 4x4 rich | 2 | 105 min | All checksums match |
| 26938555 | astro crater survival no mods | 1 | 45 min | All checksums match |
| 26938626 | Adaptive Dark Liver | 2 | 41 min | All checksums match |
| 26939703 | Polar Depression | 4 | 21 min | All checksums match |
| 26939767 | Astro Crater Reworked 4x4 rich | 8 | 27 min | All checksums match |
| 26939800 | Concord Lake | 4 | 36 min | All checksums match |
| 26940130 | Vale of Isis | 2 | 50 min | All checksums match |
| 26942293 | DualGap Adaptive | 12 | 30 min | All checksums match |
| 26942767 | DualGap Adaptive | 1 | 5 min | All checksums match |
| 26942862 | DualGap Adaptive | 12 | 24 min | All checksums match |
| 26942923 | Finn's Revenge | 2 | 6 min | All checksums match |
| 26943656 | Mechanoclastic Rush | 6 + M28AI v294 | 15 min | All checksums match |
| 26943902 | Astro Crater Battles | 6 | 22 min | All checksums match |
| 26944503 | Vya-3 Protectorate | 2 | 14 min | All checksums match |
| 26945390 | Astro Crater Battles 5x5 rich huge | 10 | 32 min | All checksums match |
| 26945918 | Adaptive passV16 lev | 12 | 6 min | All checksums match |
| 26946725 | DualGap Adaptive | 12 | 14 min | All checksums match the other clients'; Paulosan desynced in the live game at beat 6,700 |
| 26948638 | Adaptive Omorfia Trance | 2 + M28AI v294 | 30 min | All checksums match |
| 26949427 | Open Palms | 2 | 32 min | All checksums match |
| 26949465 | Forbidden Pass - FAF version | 2 | 88 min | All checksums match |
| 26949684 | Survival Horde | 1 | 26 min | All checksums match |
| 26950767 | Miaziknog | 3 | 37 min | All checksums match |
| 26950869 | The Taylors Pass | 2 | 36 min | All checksums match |
| 26951613 | Vya-3 Protectorate | 2 | 14 min | All checksums match |
| 26952345 | Astro Crater Battles 4x4 overmap | 8 | 29 min | All checksums match |
| 26952549 | Frithen | 2 | 15 min | All checksums match |
| 26952597 | Twin Rivers | 4 | 37 min | All checksums match |
| 26953273 | Seton's Clutch | 8 | 30 min | All checksums match |
| 26954643 | Astro Crater Battles 3x3 rich | 3 | 51 min | All checksums match |
| 26954789 | DualGap Adaptive | 12 | 51 min | **Desync at beat 14,150** on the rerun; the first run stopped at beat 8,840 |
| 26954937 | DualGap Adaptive | 12 | 38 min | All checksums match |
| 26954959 | DualGap Adaptive | 12 | 37 min | All checksums match |
| 26955642 | Seton's Clutch | 1 | 23 min | All checksums match |
| 26956341 | setonscrotchsurvivalv2 | 2 | 62 min | All checksums match |
| 26956508 | DualGap Adaptive | 2 | 25 min | All checksums match on the rerun; the first run stopped at beat 14,979 |
| 26957207 | DualGap Adaptive | 12 | 35 min | All checksums match |
| 26958035 | WARZONE-WALLS | 2 | 64 min | All checksums match |
| 26958040 | Astro Crater Reworked 4x4 rich | 2 | 23 min | All checksums match |
| 26958217 | Twin Rivers | 1 | 21 min | All checksums match |
| 26958235 | Desolate Dunes | 2 | 10 min | All checksums match |
| 26958259 | Astro mini 4v4 | 8 | 8 min | All checksums match |
| 26959374 | Adaptive pass lev | 12 | 32 min | All checksums match |
| 26960309 | DualGap Adaptive | 12 | 42 min | All checksums match |
| 26960347 | Ambush Pass | 2 | 9 min | All checksums match |
| 26960349 | Hargreven | 2 | 15 min | All checksums match |
| 26960684 | Open Palms | 1 | 10 min | All checksums match |
| 26960818 | Daroza's Sanctuary | 2 | 27 min | All checksums match |
| 26961234 | Adaptive Argon | 2 + M28AI v295 | 57 min | **Desync at beat 29,650**, again on the rerun |
| 26962139 | Seton's Clutch | 8 | 53 min | All checksums match |
| 26963960 | Astro Crater Battles 4x4 rich huge | 8 | 22 min | All checksums match |
| 26964071 | Wave_of_Death_v1.20 | 2 | 29 min | All checksums match |
| 26964838 | Seton's Clutch | 8 | 62 min | All checksums match |
| 26965068 | DualGap Adaptive | 12 | 33 min | All checksums match |
| 26965172 | Hargreven | 2 | 10 min | All checksums match on the rerun; the first run stopped at beat 5,401 |
| 26965627 | DualGap Adaptive | 12 | 22 min | All checksums match |
| 26966200 | Astro Crater Battles 4x4 rich huge | 8 | 30 min | All checksums match |
| 26966510 | The Bermuda Locket - FAF version | 2 | 22 min | All checksums match |
| 26967600 | Astro Crater Battles 4x4 rich huge very long | 4 + M28AI v295 | 52 min | All checksums match on the rerun; the first run stopped at beat 25,119 |
| 26968022 | Adaptive Pass Reborn | 3 | 63 min | All checksums match |
| 26968042 | High Noon | 2 | 34 min | All checksums match |
| 26968188 | Desolate Dunes | 2 | 44 min | All checksums match |
| 26968288 | Desolate Dunes | 2 | 16 min | All checksums match |
| 26969742 | Astro Crater Battles 4x4 overmap | 8 | 38 min | All checksums match |
| 26969812 | choir and flagellant | 2 | 45 min | All checksums match |
| 26972233 | Aalhaven | 2 | 9 min | All checksums match |
| 26972255 | Astro Crater Battles 4x4 rich huge | 8 | 24 min | All checksums match |
| 26972287 | Adaptive Rainy day | 2 | 27 min | All checksums match |
| 26973426 | Hargreven | 2 | 5 min | All checksums match |
| 26973725 | DualGap Adoptive | 12 | 43 min | All checksums match |
| 26973812 | Gape of Rohan Rebuild | 1 | 43 min | All checksums match |
| 26974389 | DualGap Adaptive | 12 | 21 min | All checksums match |
| 26975290 | Astro 7923542 | 4 + M28AI v295 | 28 min | All checksums match |
| 26975604 | Fields of Isis | 4 | 44 min | All checksums match |
| 26975678 | Fields of Isis | 2 | 40 min | All checksums match |
| 26975853 | Seton's Clutch | 1 | 7 min | All checksums match |
| 26976406 | Adaptive Rainy day | 2 | 26 min | All checksums match |
| 26977249 | Boreal Nexus | 1 + M28AI v295 | 5 min | All checksums match |
| 26977448 | The Bermuda Locket | 2 | 88 min | All checksums match |
| 26977680 | Adaptive pursuit | 4 | 60 min | All checksums match |
| 26978343 | DualGap Adaptive | 12 | 55 min | All checksums match |
| 26979408 | Adaptive Monument Valley | 8 | 20 min | All checksums match |
| 26982203 | SLi-Fox - European Theater V1 | 3 | 91 min | All checksums match |
| 26982238 | Astro Crater Reworked 4x4 rich | 8 | 8 min | All checksums match |
| 26982657 | DualGap Adaptive | 12 | 37 min | All checksums match |
| 26982834 | Crimson Feud | 2 | 6 min | All checksums match |
| 26983046 | The Drunken Beetles Dance - FAF Version | 2 | 87 min | All checksums match |
| 26983648 | Crimson Feud | 2 | 9 min | All checksums match |
| 26984371 | Seton's Clutch | 2 | 95 min | All checksums match |
| 26985138 | Alpha 7 Quarantine | 1 | 31 min | All checksums match on the rerun; the first run stopped at beat 18,418 |
| 26988102 | Astro Crater Reworked 4x4 rich | 8 | 35 min | All checksums match the other clients' to game over at beat 20,044; Auhram desynced in the live game at beat 8,950 |
| 26989179 | Desert Duel | 2 | 33 min | All checksums match |
| 26989770 | High Noon | 1 | 33 min | All checksums match |
| 26989982 | Seton's Clutch | 8 | 14 min | All checksums match |
| 26991386 | Loki - FAF version | 2 | 9 min | All checksums match |
| 26992934 | Lena river | 8 | 47 min | All checksums match |
| 26993154 | Fudge | 2 | 54 min | All checksums match |
| 26994861 | DualGap Adaptive | 12 | 35 min | All checksums match |
| 26995326 | DualGap Adaptive | 12 | 42 min | All checksums match |
| 26997072 | Astro Crater Rise Reworked 5x5 | 10 | 23 min | All checksums match |
| 26997113 | Battle of Thermopylae Survival | 2 | 7 min | All checksums match on the rerun; the first run stopped at beat 4,031 |
| 26997189 | ParadiseBay | 4 | 50 min | All checksums match |
| 26997230 | Adaptive Mars - Mangala Fossa | 3 | 37 min | All checksums match |
| 26998379 | 8 - Badlands_v4 | 2 | 11 min | All checksums match |
| 26999351 | TrinityFails | 2 | 63 min | All checksums match |
| 27000265 | OpenWorld Next | 1 | 47 min | All checksums match |
| 27001706 | DualGap Adaptive | 12 | 39 min | All checksums match |
| 27003562 | Fields Of Great Phoenix | 8 | 10 min | All checksums match |
| 27004084 | The Wilderness | 2 | 48 min | All checksums match |
| 27004266 | Astro Crater Battles 4x4 rich huge | 8 | 37 min | All checksums match |
| 27005888 | Loki - FAF version | 2 | 15 min | All checksums match |
| 27006065 | Desert Joust | 2 | 13 min | All checksums match |
| 27006249 | Gates of Anubis | 2 | 13 min | All checksums match |
| 27007566 | Astro Crater Battles 4x4 rich huge | 8 | 40 min | All checksums match |
| 27009529 | DualGap Adaptive | 12 | 39 min | All checksums match |
| 27009771 | DualGap Adaptive | 12 | 44 min | All checksums match |
| 27009953 | 2V2 Sand Box | 2 | 39 min | All checksums match |
| 27010232 | Crimson Feud | 2 + M28AI v295 | 27 min | All checksums match |
| 27010745 | Adaptive Mars - Mangala Fossa | 1 | 46 min | All checksums match |
| 27011241 | DualGap Adaptive | 12 | 12 min | All checksums match |
| 27011499 | Point of Reach v4 | 2 | 28 min | All checksums match |
| 27011701 | Serenity Reef 5v5 | 2 | 28 min | All checksums match |
| 27012107 | Astro mini | 1 | 22 min | All checksums match on the rerun; the first run stopped at beat 12,534 |
| 27012452 | Seton's Clutch | 8 | 42 min | All checksums match |
| 27012862 | gap_of_rohan v4_fixed_pathing | 1 | 18 min | All checksums match |
| 27013353 | Setons Claw | 3 + M28AI v295 | 50 min | All checksums match on the rerun; the first run stopped at beat 27,914 |
| 27013791 | Ian's Cross | 1 | 24 min | All checksums match |
| 27014107 | Loki - FAF version | 2 | 31 min | All checksums match |
| 27014316 | Astro Crater Battles | 6 | 6 min | All checksums match |
| 27014439 | Setons Clutch - FAF version | 1 | 10 min | All checksums match |
| 27014542 | Astro Crater Battles 4x4 rich huge | 8 | 32 min | All checksums match |
| 27014751 | Seton's Clutch | 1 | 14 min | All checksums match |
| 27015643 | Liberiam Battles | 4 | 77 min | All checksums match |
| 27015854 | Gates of Anubis | 2 | 30 min | All checksums match |
| 27016319 | Seton's Clutch | 2 | 17 min | All checksums match |
| 27018116 | Battle of Thermopylae Survival 5vX | 5 + M28AI v295 | 21 min | All checksums match |
| 27018161 | Four-Corners | 3 | 45 min | All checksums match |
| 27018213 | Williamson's Bridge | 2 + M28AI v295 | 24 min | All checksums match |
| 27018278 | DualGap Adaptive | 12 | 35 min | All checksums match |
| 27018343 | The Ganges Chasma | 2 | 18 min | All checksums match |
| 27019199 | Astro Crater Battles 4x4 overmap | 8 | 26 min | All checksums match |
| 27019405 | Flooded Strip Mine | 2 | 26 min | All checksums match |
| 27019538 | astro crater survival no mods | 2 | 33 min | All checksums match |
| 27019599 | DualGap Adaptive | 12 | 35 min | All checksums match |
| 27019665 | Astro Crater Battles 4x4 overmap | 8 | 26 min | All checksums match |
| 27021256 | Astro Crater Battles 4x4 rich huge | 8 | 20 min | All checksums match the other clients'; Foolish_Mortal desynced in the live game at beat 1,450 |
| 27021832 | DualGap Adaptive | 12 | 43 min | All checksums match |
| 27022297 | DualGap Adaptive | 12 | 42 min | All checksums match |
| 27023198 | Desolate Dunes | 2 | 37 min | All checksums match |
| 27025203 | Skellige | 2 | 57 min | All checksums match |
| 27025965 | Seton's Clutch | 1 | 9 min | All checksums match |
| 27027788 | Williamson's Bridge | 2 | 5 min | All checksums match |
| 27028303 | Distortion | 1 + M28AI v295 | 21 min | **Desync at beat 4,700**, again on the rerun |
| 27028851 | Boobs | 12 | 24 min | All checksums match |
| 27028960 | DualGap Adaptive | 12 | 30 min | All checksums match |
| 27029296 | Asteria | 2 | 24 min | All checksums match |
| 27029855 | DualGap Adaptive | 12 | 40 min | All checksums match |
| 27030616 | Astro Crater Battles 4x4 rich huge | 8 | 31 min | All checksums match |
| 27030725 | Desolate Dunes | 2 | 73 min | All checksums match |
| 27032464 | Astro Crater Battles 4x4 rich huge | 8 | 19 min | All checksums match |
| 27032784 | Stairs to Heaven | 1 | 14 min | All checksums match |
| 27033132 | Astro Crater Battles 4x4 rich huge | 8 | 8 min | All checksums match |
| 27033145 | Seton's Clutch | 1 | 6 min | All checksums match |
| 27033400 | rich2v2v2v2 | 4 | 35 min | All checksums match |
| 27034501 | Adaptive Sand Box | 1 | 21 min | All checksums match |
| 27034831 | Astro Crater Battles 3x3 rich | 6 | 35 min | All checksums match |
| 27035419 | Adaptive Rainy day | 2 | 21 min | All checksums match |
| 27036445 | Lego Wars | 1 | 16 min | All checksums match |
| 27037222 | DualGap Adaptive | 1 | 31 min | All checksums match on the rerun; the first run stopped at beat 18,405 |
| 27037528 | The Great Void | 1 | 75 min | All checksums match |
| 27038193 | astrogap | 1 | 39 min | All checksums match |
| 27038207 | serenity desert small - FAF version | 2 | 26 min | All checksums match |
| 27038222 | Map Under Construction | 12 | 11 min | All checksums match |
| 27038818 | Winter Duel | 1 | 52 min | All checksums match |
| 27039808 | DualGap Adaptive | 12 | 30 min | All checksums match |
| 27039978 | Astro Crater Battles 4x4 rich XL | 8 | 3 min | All checksums match |
| 27040788 | Lost Wisdom | 1 | 19 min | All checksums match |
| 27042138 | DualGap Adaptive | 1 | 22 min | All checksums match |
| 27042465 | Open Palms | 2 + M28AI v296 | 6 min | All checksums match |
| 27045174 | Burial Mounds | 4 | 16 min | All checksums match |
| 27045704 | DualGap Adaptive | 12 | 34 min | All checksums match |
| 27045712 | DualGap Adaptive | 12 | 41 min | All checksums match |
| 27048226 | DualGap Adaptive | 12 | 62 min | All checksums match |
| 27048760 | Saltrock Colony | 2 | 48 min | All checksums match |
| 27049782 | Europe Fizzys Revenge | 7 | 16 min | All checksums match since the fix in `74219d154` (desynced at beat 200 on the tested build) |
| 27049809 | Astro Crater Battles 4x4 rich huge | 2 | 36 min | All checksums match on the rerun; the first run stopped at beat 19,577 |
| 27049963 | Seton's Clutch | 8 | 19 min | All checksums match |
| 27051951 | Proxima m | 1 | 30 min | **Desync at beat 50**, again on the rerun |
| 27052123 | Drake's Ravine | 2 | 43 min | All checksums match |
| 27052312 | MadSea20x20 | 12 | 38 min | All checksums match |
| 27053080 | Astro Crater Battles 4x4 rich huge | 8 | 34 min | All checksums match |
| 27053262 | Boobs | 10 | 16 min | **Desync at beat 7,150**, again on the rerun |
| 27053554 | Little Pass X05 | 2 | 9 min | All checksums match |
| 27056090 | Astro Crater Battles 4x4 rich huge | 8 | 36 min | All checksums match |
| 27056144 | Point of Reach v4 | 2 | 26 min | All checksums match |
| 27056984 | Seton's Clutch | 2 | 37 min | All checksums match |
| 27057500 | DualGap Adaptive | 12 | 41 min | All checksums match |
| 27057685 | Seton's Clutch | 8 | 29 min | All checksums match |
| 27058833 | DualGap Adaptive | 12 | 34 min | All checksums match |
| 27062933 | Four-Leaf Clover | 4 | 13 min | All checksums match |
| 27062952 | Assupian | 2 | 29 min | All checksums match |
| 27064011 | DualGap Adaptive | 12 | 42 min | All checksums match |

</details>

**A live-game desync is not a playback desync.** Every client records its own checksum into the replay. In 26946725 nine clients recorded the same checksum at beat 6,700 and one (Paulosan) recorded another, then the same as everyone again from beat 6,750; the rebuilt engine's checksum is the nine clients' one, at that beat and every later one. The parity runner counts such a beat as the live game's desync, not ours (`tools/replay-parity/README.md`, Watch).

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
- **Dirty-list order.** The beat checksum hashes the sim's list of entities that changed this beat, in order. On an alliance change retail moves every entry the army owns to the end of that list, its recon blips included; ours moved only its units, so the order alone failed the beat (27049782).
- **Engine functions the AI scripts call.** The Lua AI is not part of the checksum, but the orders it issues are. A wrong return value from `CPlatoon:FormPlatoon` raised a Lua error in our build only, the AI stopped issuing orders retail's AI issued, and the games diverged a few hundred beats later.
- **Formation orders.** A patrol given to a group in formation must stay tied to that formation. Ours never passed the formation to the patrol task, so each unit's patrol leg ended on its own arrival check instead of the formation's.
- **Pathfinder edge costs.** The hierarchical pathfinder buckets each edge cost as `ceil(ln(cost / distance) * 6)`. Retail takes the logarithm with the x87 `fyl2x` instruction and rounds only the product to float; ours rounded the logarithm first. Where the product sits at a whole number the bucket moved by one and a unit took a different route; seen only in long AI games, which send many units across the map.
- **Signed versus unsigned cells.** The path navigator reads a cell's coordinates as unsigned 16-bit words, so a formation slot just off the map edge (z = -1) is 65,535 cells away; ours sign-extended them, saw the slot as close, probed it, failed and dropped out of the formation one beat early.
