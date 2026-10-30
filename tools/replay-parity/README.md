# Replay parity runner

Plays FAF vault replays on a rebuilt engine in the background and records, per build, whether every checksum the live players recorded matches. No agent is needed while it runs: one Python process launches the games, watches their logs and writes the results.

Two modes, both on Windows:

- **headless** (the default) plays each replay in `headless_x64.exe`, the console replay player that links the simulation alone (no window, rendering or audio; [docs/SWITCHES.md](../../docs/SWITCHES.md#headless)). The sim runs flat out, so it is the fast way to screen a build: replay 26942923 (5:40 of game time) plays in about 10 s.
- **gui** plays each replay in the game (`main_x64.exe`, hidden) with `wld_RunWithTheWind 1` at `WLD_GameSpeed 50`. Slower, but it tests the client as players run it: use it for changes to the session, UI-side Lua or anything headless does not link.

Needs Python 3.14 or newer (stdlib `compression.zstd`). `parity.cmd` uses the Azure CLI Python by default; set `FAF_PY` to use another one.

## Quick start

```bat
tools\replay-parity\parity.cmd import          :: once: pool the replays already downloaded in tools/runs/replay_20261013
tools\replay-parity\parity.cmd                 :: the console: runs the games (headless) and shows them live
tools\replay-parity\parity.cmd console --mode gui   :: the same in the game, hidden
```

## Console

`parity.cmd` without arguments (or `parity.cmd console [-n N]`) opens a full-screen live view, refreshed every second: state, build, progress bar with pass/desync counts, speed and ETA, every running game with its game time, the latest results and the runner log.

| Key | |
|---|---|
| `+` / `-` | One instance more / fewer |
| `p` | Pause / resume (running games are suspended) |
| `r` | Resume: clears a pause and a pending stop; starts the runner again if it stopped |
| `m` | Mode: gui / headless. New games use the other exe (its own build); running games finish as they are |
| `a` | Auto-fetch on/off (on by default): when every ready replay has a result for the build and a slot is free, fetch `auto_fetch` (10) more for the game version the exe plays, so the runner never runs dry |
| `f` | Fetch 10 more replays from the vault. A FETCH panel shows ready replays against the target, headers read, what was skipped and why, the file being downloaded with its bytes, and each new replay's outcome |
| `s` | Stop after the running games finish (press again, or `r`, to cancel) |
| `k` | Kill the running games now (they are queued again) |
| `q` | Quit |

With no runner going, the console is the runner, like a miner: `q` kills its games, and they are played again next time. When its runner stops (after `s`, or on an error) the console stays open with the reason in LOG; `r` starts it again. Only `q` quits. A runner error is logged and the loop carries on; if it keeps failing, the runner kills its games before it stops, and the next runner kills any game a dead one left behind. With a background runner going (`start`), the console attaches to it, the keys steer it, and `q` leaves it running.

## Commands

| Command | What it does |
|---|---|
| `console [-n N] [--mode gui\|headless]` | The live console (the default command). |
| `init` | Creates `tmp/parity` with `config.json` and `control.json`. Every other command runs it. |
| `import [DIR...]` | Copies `<id>.fafreplay` files into the pool and prepares them. Without arguments it takes `tools/runs/replay_20261013/dl` and that folder itself. |
| `fetch [-n 20]` | Reads replay headers at random ids in `scan_range` (one 4 KB request each) and downloads replays that qualify until `-n` more are ready. Maps and M28AI versions are downloaded as needed. |
| `retry` | Prepares again the replays that failed on a map or M28AI download. |
| `start [-n N] [--mode gui\|headless]` | Starts the runner detached from the console. With `-n` it also sets the instance count. |
| `mode [gui\|headless]` | Shows the mode and the exe it tests, or switches it (`mode` in `config.json`). A running runner takes it for its next games. |
| `instances N` | Number of games running at once. Lowering it suspends the newest games; raising it resumes them first, then launches new ones. |
| `pause` / `resume` | Suspends every running game (their CPU drops to zero) and stops launching / resumes them. |
| `stop` | Starts no new games and exits after the running ones finish. `stop --now` kills them; they are queued again. |
| `status [-v]` | Pool size, results per build, every non-passing replay, running games. `-v` adds older builds and the reasons replays were left out. |
| `run` | The runner in the foreground (what `start` launches). |

`instances`, `pause`, `resume` and `stop` only edit `tmp/parity/control.json`; the runner reads it every second. Editing the file by hand works the same way.

## What a game does

In headless mode:

- **Launch:** `headless_x64.exe --replay <id>.scfareplay /init <exe folder>\init_parity[_m28_vNNNN].lua /nosound /log logs/<build>/<id>.log --label parity-<id> --timeout <max_wall_minutes + 5>` plus `headless_args` (default `/simworkers 8`), from the exe's folder, with no window or console (`CREATE_NO_WINDOW`). The init file is the one described under gui mode; its hook does nothing here, as headless has no user Lua state.
- **Watch:** its output goes to `logs/<build>/<id>.out`: `loaded in`, a `beat N game time` line every 30 s, each mismatch (`DESYNC-LINE Checksum for beat N mismatched: ...`, judged with the same live-client vote as in gui mode), `GAME-ENDED beat N`, and at the exit `beats=... last-beat=... game-over=...` and `VERDICT ended=... mismatches=... crash=...`. It plays the replay flat out and exits, and the verdict is taken then: pass when the sim's game ended, game over was reached or the last beat is within 2 of the stream's length; incomplete otherwise; crash on `crash=True` or no VERDICT line.

In gui mode:

- **Launch:** `<exe> /init init_parity[_m28_vNNNN].lua /replay <id>.scfareplay /replayid <id> /nosound /nomovie /windowed 1024 576 /log ... /title parity-<id>` plus `args` from the config (default `/simworkers 8`), from the exe's folder.
- **Init file:** generated next to the exe from its `init_faf.lua` at every launch. It points the vault at `tmp/parity/vault` (downloaded maps), also mounts the maps in `extra_map_dirs`, mounts the M28AI version the replay was recorded with at `/mods/m28ai`, and adds the `hook` folder.
- **Hook** (`hook/lua/ui/game/gamemain.lua`, appended to the stock file): `wld_RunWithTheWind 1` (the session frame takes every queued beat instead of waiting for the tick clock, as in the binary's `CWldSession::SessionFrame` 0x00895B40) and `WLD_GameSpeed 50` (the uncapped console rate, so the sim driver does not wait for its rate schedule either; both commands exist in retail, so the same hook drives a retail run), camera reset to the map centre and zoomed fully in, and a `PARITY heartbeat tick=... time=...` log line every 2 seconds. It runs in the user Lua state only.
- **Hidden:** the game starts minimized (the show state in its STARTUPINFO, so the window never appears) and the runner removes its taskbar button (`ITaskbarList::DeleteTab`). A minimized window keeps running the sim but skips rendering (`CScApp` frame loop), so this is close to headless. `"window_mode": "minimized"` keeps the taskbar button; `"normal"` shows the window, for watching a game. A desktop of its own (`CreateDesktop`) would hide even more, but on this sandboxed account every process started on one dies at startup (0xC0000142).
- **Watch:** the runner reads the game log. `Checksum for beat N mismatched` ends the game at once, unless the live game itself disagreed at that beat: when more of the clients recorded in the replay have the sim's checksum than the mismatching client's, that client desynced in the live game, not us. The game plays on and the note says `<client> disagreed at beat N` (26946725: nine clients and the sim agree at beat 6700, Paulosan alone differs). A client outvoted once is ignored for the rest of the game, so it cannot turn a later 1-vs-1 split into a desync (26988102: Auhram desynced live at beat 8950; by beat 20150 only Auhram and jamaker were left, and the sim matched jamaker). The heartbeat's `over=true` held for 5 seconds ends it as played to the end: the sim stops at game over, a few beats before the stream ends after a victory (the beats where players leave are never simulated), one tick past the last beat when the replay simply runs out. A replay that never reports game over ends when its beat stops advancing for `stall_seconds`.
- **Length:** the exact game length is the sum of the `CMDST_Advance` beat counts in the replay's command stream, read once when the replay is prepared. The header's `launched_at`..`game_end` is the live game's wall time with lobby, loading and pauses (26935800: 40:56 of game against 51.5 header minutes), so it is only a fallback.

## Verdicts

| Verdict | Meaning | Kept in |
|---|---|---|
| `pass` | No mismatch; the replay played to its end: game over held for 5 s, or the beat stopped within 2 of the stream's length | `logs/<build>/<id>.log` |
| `desync` | First mismatched beat recorded; the game is killed | `desyncs/<build>/<id>_beat<N>/`: both replay files, the log, `info.json` |
| `incomplete` | No mismatch, but the replay stopped well before its length | `crashes/<build>/<id>_incomplete/` |
| `crash` | The process exited, an `Ack!` box or a FATAL/assert line appeared, or no heartbeat within `startup_seconds` | `crashes/<build>/<id>_crash/` |
| `timeout` | Still running after `max_wall_minutes` | `crashes/<build>/<id>_timeout/` |
| `aborted` | Killed by `stop --now`; queued again | |
| `launchfail` | Died before its first heartbeat within 30 s: a launch problem, not a result. Queued again; three in a row pause the runner, so a broken exe or init file cannot mark the whole pool as crashed | `crashes/<build>/<id>_launchfail/` |

Every finished game is also one line in `tmp/parity/results.txt`. A desynced replay is not played again on the same build.

## Builds

The runner tests the exe of the mode: `headless_exe` in headless mode (default `C:/ProgramData/FAForever/bin_x64/headless_x64.exe`), `exe` in gui mode (default `.../bin_x64/main_x64.exe`); `build.ps1` puts both there from the x64 Release build. It copies it to `<name>_parity_<hash>.exe` next to it and labels results with that hash and the git HEAD at the time. With `follow_exe` on, a rebuilt exe (unchanged for a minute) becomes the new build for the next launches, and the whole pool is queued again for it. Games already running finish on the old build.

## Pool

A replay is ready when its featured mod is `faf`, its engine version equals the local game version (`GameVersion` in `C:/ProgramData/FAForever/fa_path.lua`, 3835 now), it is at least `min_minutes` long, it needs no sim mod other than M28AI, and its map is available or downloadable. Generated maps (`neroxis_map_generator_*`) are not on the content server and stay unsupported.

Order: the core set of `docs/PR_REPLAY_CHECK.md`, then its extended set, then everything else; within each, games with 2+ players before 1-player ones, then by id.

FAF moved past 3835 in May 2026 (3835 seen up to id 27,051,951, 3836 from 27,070,013), so `fetch` reads headers in `scan_range` (26,860,000 to 27,065,000). Newer replays would need the matching game data. A vault header read takes about 3 s, so 10 new replays take a few minutes; only the 4 KB header is requested until a replay qualifies.

The console sets the window's QuickEdit mode off while it runs: with it on, a mouse click in a console window starts a selection that blocks the program's output until Esc, which looks like a frozen screen.

## Config (`tmp/parity/config.json`)

| Key | Default | |
|---|---|---|
| `mode` | `headless` | `headless` or `gui` |
| `exe` | `C:/ProgramData/FAForever/bin_x64/main_x64.exe` | Build under test in gui mode |
| `headless_exe` | `C:/ProgramData/FAForever/bin_x64/headless_x64.exe` | Build under test in headless mode |
| `follow_exe` | `true` | Switch to a rebuilt exe automatically |
| `args` | `["/simworkers", "8"]` | Extra game arguments (gui) |
| `headless_args` | `["/simworkers", "8"]` | Extra headless arguments ([its switches](../../docs/SWITCHES.md#headless)) |
| `window`, `window_mode` | `[1024, 576]`, `hidden` | gui: `hidden`, `minimized` or `normal` |
| `stall_seconds` | 45 | No new beat for this long: the replay is over |
| `startup_seconds`, `max_wall_minutes` | 240, 120 | |
| `min_minutes` | 5 | |
| `min_players` | 2 | `fetch` takes only games with at least this many players (people, not AI armies); 1-player games already in the pool play after the others |
| `scan_range`, `request_delay` | `[26860000, 27065000]`, 0.25 | `fetch` |
| `auto_fetch` | 10 | Fetch this many new replays whenever the pool is done for the build (`a` in the console turns it off) |
| `extra_map_dirs` | the old shared vault's `maps` | |
| `launch_gap_seconds` | 8 | Spacing between launches |
