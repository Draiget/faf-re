# Retail replay parity

Real multiplayer games from the FAF replay vault are played back on the rebuilt
engine and checked against the original `ForgedAlliance.exe`, bit for bit.

*Snapshot: 19/10/2026 — 16 of 16 replays match on every gameplay beat.*

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
