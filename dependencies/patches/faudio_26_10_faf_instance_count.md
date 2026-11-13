# FAF FAudio 26.10 patch

Baseline: the FAudio 26.10 release archive (`dependencies/FAudio`, pinned by SHA256 in `cmake/FafDependencies.cmake`). `cmake/FafDependencies.cmake` applies the patch at configure time, for the Linux client only (the only build that uses FAudio).

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `src/FACT_internal.h` | `FACTCue` records which instance counts it holds: `countedInstance` (its Cue's count) and `countedCategory` (the Category whose count it raised) | **Yes** |
| `src/FACT_internal.c` | `play_sound` sets those two fields where it raises the counts, and doesn't count or limit-check a Cue a second time when it already holds its Cue count (an interactive transition); `FACT_INTERNAL_ReleaseCueInstance` and `FACT_INTERNAL_ReleaseCueCategory` lower a count only for a Cue that holds it; `FACT_INTERNAL_DestroySound`, the interactive transition and `FACT_INTERNAL_OnStreamEnd` lower the counts through them | **Yes**: without it, sounds stop playing one Cue and Category at a time over a game |
| `src/FACT.c` | `FACTCue_Stop` lowers a simple-wave Cue's count through `FACT_INTERNAL_ReleaseCueInstance` | **Yes** |

## Why

On the Linux client, explosions and other world sounds became rarer over a campaign or skirmish game until only interface sounds played. The Windows client plays the same banks on XACT and doesn't do this.

FACT keeps a count of playing instances per Cue and per Category, both `uint8_t`, and refuses a play that would go over the limit the sound banks set. `play_sound` raised the counts only once a Cue passed its limit checks, but every immediate stop lowered them, through `FACT_INTERNAL_DestroySound`, whether the Cue had raised them or not. Two common paths lowered counts that were never raised:

- A play refused by a limit whose behaviour is FAIL: `handle_instance_limit` stops the new Cue at once, and that stop runs `FACT_INTERNAL_DestroySound`.
- A Cue prepared and then destroyed without playing: `FACTSoundBank_Prepare` creates the Sound, and `FACTCue_Destroy` stops the Cue first.

Once more Cues had been taken off a count than were playing, the count went below zero and wrapped to 255. From then on every play of that Cue, or of any Cue in that Category, was over the limit and refused, and each refusal took one more off the count, so a Cue stayed silent for about 250 plays. The interactive transition had the opposite fault: it lowered only the Category count before `play_sound` raised both again, so its Cue count went up by one per transition.

The game's sound banks use FAIL with small limits for almost every world Cue (2 to 8 instances; `SupCom.xgs` limits the World, Weapons and Destroy Categories to 200, 150 and 100, also with FAIL), so large battles reach these limits constantly.

Measured with FAudio 26.10, the game's `SupCom.xgs`, `Explosions.xsb` and `Explosions.xwb`, on the Cue `UEF_Nuke_Impact` (limit 2, FAIL), reading the Cue's count with `FACTSoundBank_GetCueProperties` and the `Destroy` Category's count from the engine:

| Step | Cue / Category count, unpatched | Patched |
|---|---|---|
| Prepare, then Destroy without playing | 255 / 255 | 0 / 0 |
| Two plays, then a third refused by the limit | 1 / 1 | 2 / 2 |
| Every Cue destroyed | 255 / 255 | 0 / 0 |
| Next play, with nothing else playing | refused, 254 / 254 | plays, 1 / 1 |
| A play left to end by itself | | 1 / 1 while playing, 0 / 0 after |

FAudio 26.11 has the same code.

Not reported upstream yet.
