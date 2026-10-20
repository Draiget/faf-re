# Retail replay parity

Real games from the FAF replay vault — multiplayer games and games against the
built-in AI or M28AI — are played back on the rebuilt engine and checked against
the original `ForgedAlliance.exe`, bit for bit.

*Snapshot: 20/10/2026 — 67 of 67 replays match on every gameplay beat.*

## Method

1. **Screening.** The rebuilt engine plays the replay back, and its simulation
   checksum is compared with the checksums the live players' clients recorded
   into the replay every 50 beats.
2. **Narrowing.** When a replay diverges, the window is narrowed beat by beat:
   the retail `ForgedAlliance.exe` and the rebuilt engine both dump the full
   simulation state on every beat (`sim_ChecksumPeriod` 1), and the dumps are
   diffed. One differing bit anywhere in the sim state fails the beat.
3. **Regression.** Every fix is re-screened against all replays that already
   matched before it is committed.

Replays are sampled at random from the vault. A game is used when it runs the
standard FAF game version, is at least ten minutes long, and needs no sim mod
other than M28AI; custom maps and the exact M28AI version a game was recorded
with are fetched from the FAF content server.

## Results

| Replay | Game | Result |
|---|---|---|
| 26935800 | Dual Gap, 12 players, 41 min | Every gameplay beat matches, 4 to 24,563. Only the final beat differs (see below). |
| 26876279 | Seton's Clutch, 8 players, 37 min | Every gameplay beat matches, 4 to 22,155. Only the final beat differs (see below). |
| 26957207 | Dual Gap, 12 players, 35 min | All 5,069 embedded live-player checksums match, start to end. |
| 26953273 | Seton's Clutch, 8 players, 30 min | Every embedded checksum matches, start to end. |
| 26917867 | Dual Gap, 12 players, 35 min | Every embedded checksum matches, start to end. |
| 26897073 | Dual Gap, 12 players, 34 min | Every embedded checksum matches, start to end. |
| 26954959 | Dual Gap, 12 players, 37 min | Every embedded checksum matches, start to end. |
| 26994861 | Dual Gap, 12 players, 35 min | Every embedded checksum matches, start to end. |
| 26898759 | Dual Gap, 12 players, 46 min | Every embedded checksum matches, start to end. |
| 26928140 | Dual Gap, 12 players, 29 min | Every embedded checksum matches, start to end. |
| 26982657 | Dual Gap, 12 players, 37 min | Every embedded checksum matches, start to end. |
| 26954937 | Dual Gap, 12 players, 38 min | Every embedded checksum matches, start to end. |
| 26905489 | Dual Gap, 12 players, 33 min | Every embedded checksum matches, start to end. |
| 26968042 | High Noon, 2 players with AI, 34 min | Every embedded checksum matches, start to end. |
| 26975678 | Fields of Isis, 2 players with AI, 40 min | Every embedded checksum matches, start to end. |
| 26930624 | Open Palms, 2 players, 14 min | Every embedded checksum matches, start to end. |
| 27001706 | Dual Gap, 12 players, 39 min | Every embedded checksum matches, start to end. |
| 27019665 | Astro Crater Battles 4x4, 8 players, 26 min | Every embedded checksum matches, start to end. |
| 27037528 | The Great Void, 1 player against AI, 75 min | Every embedded checksum matches, start to end. |
| 26900602 | Seraphim Glaciers, 1 player against AI, 62 min | Every embedded checksum matches, start to end. |
| 27010745 | Adaptive Mars – Mangala Fossa, 1 player against AI, 46 min | Every embedded checksum matches, start to end. |
| 26911139 | Strip Mine, 1 player against M28AI, 35 min | Every embedded checksum matches, start to end. |
| 26989770 | High Noon, 1 player against AI, 33 min | Every embedded checksum matches, start to end. |
| 27037222 | Dual Gap, 1 player against AI, 31 min | Every embedded checksum matches, start to end. |
| 26904914 | Dual Gap, 1 player against AI, 28 min | Every embedded checksum matches, start to end. |
| 27013791 | Ian's Cross, 1 player against AI, 24 min | Every embedded checksum matches, start to end. |
| 26955642 | Seton's Clutch, 1 player against AI, 23 min | Every embedded checksum matches, start to end. |
| 27032784 | Stairs to Heaven, 1 player against AI, 14 min | Every embedded checksum matches, start to end. |
| 27025965 | Seton's Clutch, 1 player against AI, 9 min | Every embedded checksum matches, start to end. |
| 26905122 | Cursed Souls, 3 players with M28AI, 83 min | Every embedded checksum matches, start to end. |
| 26885749 | Dual Gap, 12 players, 54 min | Every embedded checksum matches, start to end. |
| 26954643 | Astro Crater Battles 3x3 Rich, 3 players with AI, 51 min | Every embedded checksum matches, start to end. |
| 26997189 | Paradise Bay, 4 players, 50 min | Every embedded checksum matches, start to end. |
| 27004084 | The Wilderness, 2 players, 48 min | Every embedded checksum matches, start to end. |
| 26992934 | Lena River, 8 players, 47 min | Every embedded checksum matches, start to end. |
| 26923388 | Hargreven, 2 players, 45 min | Every embedded checksum matches, start to end. |
| 26938626 | Adaptive Dark Liver, 2 players, 41 min | Every embedded checksum matches, start to end. |
| 27023198 | Desolate Dunes, 2 players, 37 min | Every embedded checksum matches, start to end. |
| 27033400 | Rich 2v2v2v2, 4 players, 35 min | Every embedded checksum matches, start to end. |
| 26906984 | Dual Gap, 12 players, 34 min | Every embedded checksum matches, start to end. |
| 26972287 | Adaptive Rainy Day, 2 players, 27 min | Every embedded checksum matches, start to end. |
| 27019405 | Flooded Strip Mine, 2 players, 26 min | Every embedded checksum matches, start to end. |
| 26956508 | Dual Gap, 2 players, 25 min | Every embedded checksum matches, start to end. |
| 26881085 | Fields of Isis, 4 players, 21 min | Every embedded checksum matches, start to end. |
| 26904089 | Esgaroth's Ruins, 2 players, 19 min | Every embedded checksum matches, start to end. |
| 26912041 | Skellige, 2 players, 18 min | Every embedded checksum matches, start to end. |
| 26968288 | Desolate Dunes, 2 players, 16 min | Every embedded checksum matches, start to end. |
| 26943656 | Mechanoclastic Rush, 6 players with M28AI, 15 min | Every embedded checksum matches, start to end. |
| 26946725 | Dual Gap, 12 players, 14 min | Matches the other nine clients on every checksum; one player's own client desynced in the live game at beat 6,700 (see below). |
| 26989982 | Seton's Clutch, 8 players, 14 min | Every embedded checksum matches, start to end. |
| 26902315 | The Dark Heart, 3 players, 13 min | Every embedded checksum matches, start to end. |
| 26896281 | Dual Gap, 12 players, 53 min | Every embedded checksum matches, start to end. |
| 26993154 | Fudge, 2 players, 54 min | Every embedded checksum matches, start to end. |
| 26915859 | Dunes of Arracis, 2 players, 50 min | Every embedded checksum matches, start to end. |
| 26902701 | Esgaroth's Ruins, 2 players, 48 min | Every embedded checksum matches, start to end. |
| 27029855 | Dual Gap, 12 players, 40 min | Every embedded checksum matches, start to end. |
| 27009529 | Dual Gap, 12 players, 39 min | Every embedded checksum matches, start to end. |
| 26928802 | Seton's Clutch, 8 players, 39 min | Every embedded checksum matches, start to end. |
| 26950767 | Miaziknog, 3 players, 37 min | Every embedded checksum matches, start to end. |
| 26975290 | Astro 7923542, 4 players with M28AI, 28 min | Every embedded checksum matches, start to end. |
| 26960818 | Daroza, 2 players, 27 min | Every embedded checksum matches, start to end. |
| 26976406 | Adaptive Rainy Day, 2 players, 26 min | Every embedded checksum matches, start to end. |
| 26963960 | Astro Crater Battles 4x4 Rich Huge, 8 players, 22 min | Every embedded checksum matches, start to end. |
| 26883423 | Dual Gap, 2 players with M28AI, 18 min | Every embedded checksum matches, start to end. |
| 26952549 | Frithen, 2 players, 15 min | Every embedded checksum matches, start to end. |
| 26880663 | Dual Gap, 12 players, 12 min | Every embedded checksum matches, start to end. |
| 26958235 | Desolate Dunes, 2 players, 10 min | Every embedded checksum matches, start to end. |

**A live-game desync is not a playback desync.** Every client records its own
checksum into the replay. In 26946725 nine clients recorded the same checksum at
beat 6,700 and one recorded another, then left the game; the rebuilt engine's
checksum is the nine clients' one, at that beat and every later one.

**The final-beat difference** is deliberate. When a player leaves, retail drops
the commands that arrive after the leave within the same batch; the rebuilt
engine keeps them (`CClientBase::UpdateState`, marked `[DELIBERATE-FIX]`). In a
replay this only shows on the last beat, where the remaining players' command
sources end.

## Where divergences came from

- **The 2007 floating-point environment.** The sim keeps some intermediate
  results in x87 registers at 24-bit precision, where SSE rounds every step —
  box-vs-box separating-axis radii, vector lengths, the Gaussian's logarithm.
  These are reproduced with x87 helpers in `src/sdk/legacy/math/X87Math*`.
- **Call order in the random-number stream.** An extra or missing call to a
  function that draws from the sim's random stream shifts every later draw.
- **Order validation.** Checks that accepted orders retail refuses — for
  example a move order for a unit riding in an ordinary transport.
- **Float-to-integer conversions.** Places that truncate where retail's
  `fistp` rounds to nearest, such as a unit's footprint cell.
- **Missing state updates.** For example a carrier that never removed a
  launched unit from its carried set.
- **Engine functions the AI scripts call.** The Lua AI is not part of the
  checksum, but the orders it issues are. A wrong return value from
  `CPlatoon:FormPlatoon` raised a Lua error in our build only, the AI stopped
  issuing orders retail's AI issued, and the games diverged a few hundred beats
  later.
- **Formation orders.** A patrol given to a group in formation must stay tied
  to that formation. Ours never passed the formation to the patrol task, so each
  unit's patrol leg ended on its own arrival check instead of the formation's.
- **Pathfinder edge costs.** The hierarchical pathfinder buckets each edge cost
  as `ceil(ln(cost / distance) * 6)`. Retail takes the logarithm with the x87
  `fyl2x` instruction and rounds only the product to float; ours rounded the
  logarithm first. Where the product sits at a whole number the bucket moved by
  one and a unit took a different route — seen only in long AI games, which send
  many units across the map.
- **Signed versus unsigned cells.** The path navigator reads a cell's
  coordinates as unsigned 16-bit words, so a formation slot just off the map
  edge (z = -1) is 65,535 cells away; ours sign-extended them, saw the slot as
  close, probed it, failed and dropped out of the formation one beat early.
