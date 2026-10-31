# desync-diff

Compares the desync dumps that players' games wrote for one game and prints the first value that differs: which beat, which entity or army, which field. The dumps are the `desync_<game id>_beat<N>_army<A>.zip` files the engine's desync recorder writes next to the game log after a checksum mismatch (`/desyncrecorder`, [docs/SWITCHES.md](../../docs/SWITCHES.md#desync-recorder), issue #216). Python 3 with the standard library only.

```bat
python tools\desync-diff\desync_diff.py desync_11204007_beat300_army0.zip desync_11204007_beat300_army1.zip
```

With more than two dumps, the first is A and each other is compared with it.

## What it prints

1. **Header.** Every difference in build commit, architecture, dirty tree, FAF game version, active sim fixes, map, game mods, `sim_ChecksumPeriod`, sim workers in use, `/sse2`, the x87 control word and MXCSR (now and at game start), and every console switch the dump lists (the recorder's own switches excepted). Often this is already the answer: a different build, or a switch one player changed.
2. **Hashes.** From every dump's `hashes.csv`: the last beat where every player's hash matched, the first beat where any differs, and which players share which hash there (one player off, or a split). A replay run's own hash is listed as "(this run)".
3. **Beat logs.** From the last agreed beat on, the first line that differs between the two dumps' beat logs, with 10 lines of context before it and 10 after it on each side (`-C N` changes that). It names the entity (id, blueprint, army) or the army whose economy the line is in, and the field: `health`, `pos`, `rot`, `vel`, `mStored`, a call such as `SetHealth` or `MoveTo`, or a tick (`nav tick`). Each beat's log lists the hashed fields in hash order with the running hash after them, so the first line that differs is the first value that differs. When only a running hash differs, the value was hashed but printed rounded; the line before it names it.
4. **State snapshot.** `state.txt` (every entity with its float bits, every army's economy, at the dump beat): how many entities differ, those on one side only, and the first 20 differences (`--states N`).

Exit code: 0 when the dumps don't differ, 1 when they do, 2 when the input is invalid (not a dump, fewer than two, or dumps of different games; `--force` compares those anyway). Step 2 doesn't count: two copies of one dump still show the desync their game had, and exit 0.

## When only one player sent a dump

Rebuild the other side: play the game's replay in headless on the other player's build and architecture, with the recorder on and `/desyncdumpbeat` set to the dump's beat, then compare.

```bat
python tools\desync-diff\desync_diff.py rebuild desync_11204007_beat300_army0.zip ^
  --exe C:\ProgramData\FAForever\bin\headless.exe --replay 11204007.scfareplay ^
  --init C:\ProgramData\FAForever\bin\init_parity.lua -- /simworkers 8
```

`rebuild` runs `<exe> --replay <file> /init <file> /nosound /log <out>\game.log /desyncrecorder /desyncdumpbeat <beat>` plus the arguments after `--` (the other player's switches), waits until the log says the dump is written, stops the run and compares the new dump with the given one. `--out` sets the folder (default `rebuilt\` next to the dump); `--no-compare` only writes the dump. The header step then also lists `sim_LeadOnSchedule`, which headless sets for every replay run; it only paces the sim, so it is marked "not counted" and a rebuild of the same build exits 0. A rebuild on the other architecture (an x86 headless against an x64 dump) shows `build.arch` and the x87 control word in the header and exits 1 even when every beat matches.

In the forced-desync scenario (`tools/scenarios/2p-desync-recorder.yaml`), rebuilding player B from player A's dump and replay with `-- /desynctestbeat 300` gives the same first differing line as B's real dump: beat 300, the nudged unit's `health`.

This only finds differences that come from the build, the architecture or a switch: each build plays a replay the same way every time. Memory corruption, overclocked or faulty hardware, or anything else that happens on one machine and not on another, doesn't reproduce in a replay run. A player on the retail exe writes no dump, and retail has no headless to rebuild one with: that side can't be rebuilt.

## Limits

- The header names the map, the game mods (an MD5 of the launch info's mod table) and the FAF game version, not a hash of the mounted game data files: two players with the same version but different `.scd` or Lua content show no header difference, and step 3 points at the first value the content changed.
- An entity is named by the nearest line above the differing one that carries an id (`Unit[0x…]`, `0x…->`, `for 0x…`, a `Dirty Entities` row). A few sync-log lines carry none, such as `CAiPathNavigator::SetTargetPoint(%d)`; they are credited to that nearest entity.
- When the entity isn't in either dump's `state.txt` (it died before the dump beat), the army comes from the id's source bits and prints as a number, or `none` for 0xFF.
- `rebuild` needs a headless that has `/desyncdumpbeat` (this tool's commit or later). An older build writes no dump: it plays the whole replay, exits, and the tool stops with "the replay run wrote no dump" (exit 2).
- A header field that one dump's format doesn't have (a dump from an older recorder) is shown as "missing in one dump" and not counted. A damaged dump exits 2.
- Every acceptance run so far had two players; the "one off, the rest agree" and "split" shapes of step 2 haven't met a real game with three or more.
- The scenarios don't run the tool: mpemu has no step that runs a program. Its acceptance runs are scripts that play the scenario and then call the tool.
