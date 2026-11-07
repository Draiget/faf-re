# Nightly releases

The [Nightly release workflow](../../.github/workflows/nightly-release.yml) publishes master's head as the latest release when that night's [Replay parity](../parity-data/README.md) run lists no new failure in its report. Replay parity starts at 20:00 UTC (00:00 UTC+4), and takes about 5 h 30 min.

| Job | What it does |
|---|---|
| `plan` | The tag: the UTC year and month, the month's next number and `-nightly`, for example `2026.11.001-nightly`, a real release being the same without `-nightly`. Releases and nightlies share the numbers, which go back to 001 each month and always have at least three digits, so a number can't be read as a day. The newest release or nightly the commit descends from, for the change list. It builds nothing when that tag's release already exists, as master did not move |
| `build` | Builds `main_x64.exe` and `main.exe` with clang-cl and zips them as a release is zipped: exe, pdb, the DXC DLLs, `fafengine\` and `INSTALL.txt` ([x64](INSTALL_x64.txt), [x86](INSTALL_x86.txt)). The exe reports the nightly tag as its version |
| `release` | Writes the notes ([nightly_notes.py](nightly_notes.py)): the parity counts, every commit since the previous release or nightly, and the checksums; and `player-notes.md`, the notes for players (below). Publishes them with the zips and the two exes on their own as a full release marked as the latest, so the repository's release link and `/releases/latest` point at it |

A parity run that failed or lists new failures publishes nothing, and neither does a parity run started by hand, which may have played any commit or set.

## Notes for players

Every release and nightly carries `player-notes.md`: one line for each `Player-Note:` trailer of the commits since the previous one, or a line saying there are none. FAF Develop's changelog in the game's lobby shows it (issue #323), so a note says in a player's words what changed for them, and most commits have none. The trailer goes in the commit message's last paragraph, one per line:

```
feat(render): Direct3D 12 and Vulkan decode textures with DirectXTex when d3dx11_43.dll is missing (#318)

Players without the DirectX End-User Runtime of June 2010 ...

Player-Note: Direct3D 12 and Vulkan work without installing the DirectX runtime.
```

## Retries

A desync never fails a parity run: the report lists it. So a failed job in the nightly is CI's own, such as a lost runner, a timeout or a download error. The run's `retry` job then starts the [Nightly retry workflow](../../.github/workflows/nightly-retry.yml), which waits for the run to end and re-runs its failed jobs. Nightly release does the same when one of its jobs fails. A run gets three attempts at most.

GitHub starts no workflow from what the workflow token does, so a parity run that Nightly retry re-ran doesn't start Nightly release when it ends. Its `release` job starts it instead, with `publish` and `parity_run`, and only when the report lists no new failures. A re-run started by a person starts Nightly release as a first attempt does.

Started by hand, the workflow builds the commit and writes the notes as artifacts. It publishes only with `publish` ticked, and such a build has passed no parity run, as its notes say. Give `parity_run` to report a run in the notes, with any new failures named, and `note` for a line of your own, such as what was fixed after that run.

Nightly tags and releases stay until someone deletes them; nothing removes old ones.

## The version a build shows

A clean build of a commit tagged `YYYY.MM.NNN` or `YYYY.MM.NNN-nightly` shows that tag in the label players see, in the lobby and on the F11 panel: `FAF-RE, Draiget & contributors, build 2026.11.001 x64`. If a commit has both, the release wins. Any other build shows its commit, with `-dirty` after it when tracked files had local edits. So tag a real release before building it, and pick the month's next number, counting nightlies. The older `v1.1.2` and `2026.05.11.001-nightly` tags stay as they are and are not shown this way.
