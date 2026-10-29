# PR replay check

Replays to play back before opening a pull request that can change what the sim does, and how to read the result. The pull request template asks for the replay IDs you played and what each one did; using the replays below means every PR is checked against the same games and results can be compared across PRs.

Every replay here is from the [retail parity set](RETAIL_REPLAY_PARITY.md): it plays back on master with every recorded checksum matching, so a mismatch on your branch comes from your change. All of them were recorded on FAF game version 3835.

## Which replays

- **Core set:** required for any PR that touches sim code, replay playback or the network layer. Eight games, 2 to 12 players, the built-in AI and two M28AI versions.
- **Extended set:** the core set plus ten longer or larger games. Run it as well for changes to pathfinding, formations, x87 math helpers, engine functions the AI scripts call, and sim worker threading, where past divergences only showed up late in long games ([Where divergences came from](RETAIL_REPLAY_PARITY.md#where-divergences-came-from)).
- **Performance switches:** play the core set with the switch on and with it off. Both runs must match ([Switches](SWITCHES.md)).
- **Server mode:** for a server-mode build, also run the [focus gate](FOCUS_GATE.md) on the core set: the sim must give the same game whichever army it builds its view for.

### Core set

| Replay | Map | Players | Length | M28AI |
|---|---|---|---|---|
| 26902315 | The Dark Heart | 3 | 13 min | |
| 26930624 | Open Palms | 2 | 14 min | |
| 26943656 | Mechanoclastic Rush | 6 + M28AI | 15 min | v294 |
| 26883423 | Dual Gap | 2 + M28AI | 18 min | v292 |
| 26881085 | Fields of Isis | 4 | 21 min | |
| 26928211 | Astro Crater Battles 4x4 Rich Huge | 8 | 27 min | |
| 26989770 | High Noon | 1 vs AI | 33 min | |
| 26897073 | Dual Gap | 12 | 34 min | |

### Extended set (in addition to the core set)

| Replay | Map | Players | Length | M28AI |
|---|---|---|---|---|
| 26975290 | Astro 7923542 | 4 + M28AI | 28 min | v295 |
| 26953273 | Seton's Clutch | 8 | 30 min | |
| 27034831 | Astro Crater Battles 3x3 Rich | 6 | 35 min | |
| 26917867 | Dual Gap | 12 | 35 min | |
| 26876279 | Seton's Clutch | 8 | 37 min | |
| 26935800 | Dual Gap | 12 | 41 min | |
| 26898759 | Dual Gap | 12 | 46 min | |
| 27004084 | The Wilderness | 2 | 48 min | |
| 26915859 | Dunes of Arracis | 2 | 50 min | |
| 26905122 | Cursed Souls | 3 + M28AI | 83 min | v293 |

26876279 and 26935800 match on every gameplay beat and differ only on the final beat, where the remaining players' commands end. That difference is deliberate ([final-beat difference](RETAIL_REPLAY_PARITY.md#results)); report it as "match except final beat".

## Playing a replay

1. **Build** your branch, for example `.\build.ps1` (x64 Release, copied to `C:\ProgramData\FAForever\bin_x64\main_x64.exe`).
2. **Download and convert** the replay. The engine reads `.scfareplay`; the vault serves `.fafreplay`:

   ```bash
   curl -o 26902315.fafreplay https://replay.faforever.com/26902315
   python scripts/perf/convert_replay.py 26902315.fafreplay 26902315.scfareplay
   ```

3. **Game data.** The installed game data must be game version 3835 (`lua/version.lua` in `gamedata/lua.nx2`); the engine refuses a replay recorded on another version. Custom maps must be in your vault's `maps` folder, and an M28AI replay needs exactly the M28AI version in the table in `mods/M28AI`: any other version desyncs within minutes and looks like an engine bug.
4. **Run** it from the build's own folder:

   ```
   main_x64.exe /init init.lua /nobugreport /replay C:\full\path\26902315.scfareplay /replayid 26902315 /nosound /windowed 1280 720 /log game.log
   ```

   Press numpad `+` a few times once the game starts so the sim runs flat out. Add `/simworkers 8` to test the threaded sim. Replays without a game-over event stop on their last frame; close the game once the game time stops moving. More options: [scripts/perf/README.md](../scripts/perf/README.md#playing-a-replay-on-the-rebuilt-engine).

## Reading the result

The engine compares its sim checksum with the checksums the players' clients recorded every 50 beats and logs each difference as a warning:

```
Checksum for beat 3400 mismatched: <md5> (sim) != <md5> (<player>).
```

- **No such line** in `game.log` from start to the end of the game: report "all checksums match".
- **One or more lines:** report "first mismatch at beat N" with the beat of the first line, and keep the log. The parity doc explains how a divergence is narrowed down to one beat.
- **Crash or hang:** report it with the last game time the log shows.

In the PR, fill one row of the testing table per replay: ID, arch (x64 or x86), `sim_Workers` (0, or the value you passed), renderer and result.
