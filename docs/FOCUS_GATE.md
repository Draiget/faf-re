# Focus gate

A game server runs one sim and builds a view for every player from it, so the sim must not depend on which army a client watches: a lockstep client's sim builds its packets for its own army (the "focus army"), and the server's sim has to give the same game whatever focus it runs with. The focus gate checks that on replays. Run it with every change to sim code and at every server milestone (plan WPR.2).

It needs a server-mode build (`clang-x64-release-server` or `clang-x86-release-server`, which produce `faf-replay.exe`, see [Switches](SWITCHES.md#faf-replay)) and Python 3.

## What it does

For each replay, `scripts/server/focus_gate.py` plays it with faf-replay at focus -1 (an observer) and then at the chosen armies, every run with `--checksum-period 1`, so the sim's checksum is taken on every beat. Each focus run's per-beat checksums are compared with the -1 run's.

- **identical**: every beat's checksum matches.
- **tail-only**: every beat both runs played matches, but one played more trailing beats. After the end of a replay's recorded commands the number of extra beats depends on thread timing, so this counts as a match.
- **differ**: the first beat whose checksums differ is reported. The sim depends on the focus army there; that is a bug to fix before merging.

Only the sim checksum is compared. faf-replay's `--state-digests` (what the sim published to its client) is filtered by the focus army on purpose, so it differs between foci by design.

## Running it

```
python scripts/server/focus_gate.py --exe C:\ProgramData\FAForever\bin_x64_replay\faf-replay.exe ^
  --init C:\ProgramData\FAForever\bin_x64\init.lua --replay-dir C:\replays --out C:\tmp\focus_gate
```

Without replay ids it plays the core set of the [PR replay check](PR_REPLAY_CHECK.md); pass ids, or `--ids-file <file>` with one id per line. The replay folder holds `<id>.scfareplay` (or `vault_<id>.scfareplay`). Put faf-replay in a folder of its own next to the game's `bin` folder, as [Switches](SWITCHES.md#faf-replay) describes.

| Option | Default | What it does |
|---|---|---|
| `--armies all\|ends\|N,M` | all | Which armies to play besides -1: every army, the first and the last, or a list |
| `--jobs N` | 2 | faf-replay processes at a time |
| `--out DIR` | `focus_gate_out` | Checksums, logs and faf-replay output of every run |
| `--simworkers N` | 8 | Passed to faf-replay |
| `--timeout MIN` | 180 | Per run |
| `--label TAG` | fg | Prefix of every run's label and file names |
| `--m28-versions F` | — | Lines `<id> <version>`: the M28AI version each replay was recorded with (0: none). With `--vault DIR` (the vault the init file mounts) and `--modcache DIR` (holding `m28ai.vNNNN/M28AI`), the vault's `mods/M28AI` is swapped before each M28AI replay, and runs of different versions never overlap |
| `--markers DIR` | — | A folder of "version in use" files shared with other replay runners on the machine; the gate waits while another runner uses a different M28AI version, and writes its own |

## Reading the result

One line per replay, then a summary:

```
FOCUSGATE 26930624 armies=2 beats=8191 foci=0,1 identical=2 tail-only=0 differ=0 | base VERDICT ...
FOCUSGATE SUMMARY ... replays=1 focus-runs=2 identical=2 tail-only=0 differ=0 failed=0
```

The exit code is 0 when no run differs and every run reported. `failed` counts runs that did not load or wrote no checksums; look at the run's `.out` and `.log` in `--out`. The base run's verdict says "recorded-checksum check skipped": the players' clients recorded checksums every 50 beats, which a run at period 1 cannot compare (the period changes only the checksum, not the sim).
