# Replay parity in CI

The [Replay parity workflow](../../.github/workflows/replay-parity.yml) plays FAF vault replays of one game version (3835 now) on the Linux `headless` build and checks every checksum the live players recorded, as [tools/replay-parity](../replay-parity/README.md) does on Windows, with the same verdicts and the same rule for a desync that happened in the live game. The [Parity prewarm workflow](../../.github/workflows/parity-prewarm.yml) fills the caches it plays from. The tools here fetch the game files, replays and maps from FAF, strip them, split a run into jobs packed to their time limit, play each job's replays and merge the results.

## The workflows

**Parity prewarm** (by hand, with a game version, and weekly):

| Job | What it does |
|---|---|
| `game` | Once per version: downloads FAF's packages and init file for the version from FAF's updater (`<package>.<version>.nx2`, `init_faf_<version>.lua`, no sign-in needed) and strips them |
| `retail` | Once: downloads the encrypted retail archives from `PARITY_RETAIL_URL` and checks they open with `PARITY_RETAIL_KEY` |
| `replays` | One job per bucket of 10,000 replay ids, `parallel` jobs at a time (default 4, each one request a second): downloads the corpus replays the bucket's cache lacks, checks each as the parity runner does (featured mod, engine version, sim mods, map) and records the result in the bucket's `index.jsonl`; keeps the ready ones |
| `assets` | Downloads the corpus' top and retail maps (stripped) and every M28AI version a ready replay needs, and saves every bucket's index in one file for the planner |

**Replay parity** (by hand, with the commit to test):

| Job | What it does |
|---|---|
| `build` | Builds `headless` from the commit given, with the pinned toolchain |
| `plan` | Picks the replays (`core`, `extended`, a seeded `sample` or `all`) and packs them into jobs |
| `run` | One job per shard: puts the pack together (FAF's game files and the retail archives), plays its replays four at a time, and uploads `results.jsonl` and the logs of every replay that did not pass |
| `report` | Merges the results, writes the job summary and `report.json` (passing replays with replay time, wall time and speedup), and fails on any new desync, crash, early stop, timeout or error (a replay that could not be got ready, or a shard that died) |

Run both from master: caches saved on master are the ones every run reads. Anyone with write access to the repository can start them. The weekly prewarm fetches what is still missing and keeps the caches from expiring (GitHub drops a cache unused for 7 days).

**FAF's servers.** Only the prewarm asks FAF for anything, each job one request a second (the replay buckets `parallel` jobs at a time), and only for what the cache lacks: once the caches are full, a parity run sends FAF nothing. A `run` job downloads a replay, map or M28AI version only when the caches lack it (a map outside the top maps, a replay the prewarm has not reached yet); the core and extended sets are played from shared jobs that fetch their 8 or 18 replays.

**Caches** (10 GB per repository; most keys carry an entry count, so a run saves a new one only when something was added):

| Key | Contents |
|---|---|
| `game-<version>` | FAF's packages and init file, stripped (34 MB for 3835) |
| `retail-<PARITY_RETAIL_ID>` | the retail archives, encrypted as downloaded (73 MB) |
| `replays-<version>-b<bucket>-n<count>` | one bucket's ready `.fafreplay` files and `index.jsonl` (about 80 KB a replay) |
| `maps-<version>-n<count>` | the top and retail maps, stripped |
| `m28-<version>-n<count>` | M28AI versions |
| `index-<version>-r<run>` | every bucket's index, for the planner |

A pull request's workflow can read master's caches too, a fork's included, which is why the retail archives stay encrypted there.

**Settings.** The secrets belong to an environment named `parity` (repository Settings, Environments) whose deployment branches are `master` only: the jobs that use them (`retail` in the prewarm, `run`) name that environment, and a workflow on any other branch gets nothing.

| Name | Where | |
|---|---|---|
| `PARITY_RETAIL_URL` | `parity` environment secret or variable | where the encrypted retail file is downloaded from: a direct link, or a Google Drive share link (`drive.google.com/file/d/<id>/...`, shared with anyone who has the link); it need not be secret, as the file is useless without the key |
| `PARITY_RETAIL_KEY` | `parity` environment secret | the file's passphrase |
| `PARITY_RETAIL_ID` | `parity` environment variable | names the retail file, for example `v1`; change it when the file changes (only the jobs in the environment use it) |

## The corpus

[corpus/3835.tsv.gz](corpus/3835.tsv.gz) lists the replays CI may play: every 3835 game in the vault with 2 or more players, at least 5 minutes of game, a replay, and a map that can be had (generated maps cannot), plus the core and extended sets of [PR_REPLAY_CHECK.md](../../docs/PR_REPLAY_CHECK.md). One line per replay: id, ticks, players, map folder, and where its map comes from: `retail` (a map the game ships, cached from FAF's map vault), `cached` (one of the 500 most played vault maps) or `download` (fetched by the job that plays it). On 29/10/2026: 43,091 replays, 9,194 on retail maps, 28,989 on the top 500 maps, 4,908 on others. About 30% of them need a sim mod and are left out when the prewarm reads them.

It is made from the FAF API, which needs a signed-in user:

```
python corpus.py login                                  # prints a link and a code; tokens go to tmp/claude/
python corpus.py export --first 26825749 --last 27067140 --out tmp/claude/export3835
python corpus.py build --export tmp/claude/export3835 --retail-maps <pack>/fa/maps --top-maps 500 \
  --out tools/parity-data/corpus/3835.tsv.gz
```

26,825,749 to 27,067,140 are the vault ids of game version 3835: the first replay whose engine version (inside the replay, `Supreme Commander v1.50.3835`) is 3835, and the last whose header names 3835. Headers name 3835 from 26,825,350 on, but the replays up to 26,825,721 were recorded by the 3834 engine. The export asks for one page of 100 games a second, about 1,000 requests. The login is the FAF client's (its client id and the device-code sign-in of `api/TokenRetriever.java`), as FAF has no client registered for this project.

Known failures, which the report lists but does not fail on, are in [expected/3835.json](expected/3835.json).

## The pack

The game data a headless replay parity run needs, cut down from the full game: every file headless reads keeps its bytes, every other file stays as an empty file of the same name, at the same path, with the same timestamp. On 3835 the game archives go from about 3.7 GB to 111 MB: FAF's packages to 34 MB, the retail archives to 76 MB.

### Why empty files, not no files

Headless never reads a texture, a sound or a movie, but it does ask whether some textures exist. The session checksum is seeded with every blueprint's reflected value (`RRuleGameRulesImpl::UpdateChecksum`, 0x0052B2B0), and a mesh blueprint's LOD texture names are filled in only when `<mesh>_albedo.dds`, `_normalsTS.dds`, `_SpecTeam.dds` or `_lookup.dds` exists next to the mesh (`RMeshBlueprintLOD::Init`, 0x00518870). Removing the textures, or skipping that lookup in headless, changes the checksum at beat 0 (26902315: every recorded checksum mismatched from beat 0 on, 29/10/2026). An empty file answers the lookup as the real one does, and a read of one returns no bytes.

### Layout

| Folder | From |
|---|---|
| `bin/init_ci.lua` | FAF's `init_faf_<version>.lua` with the vault set to the pack's (`custom_vault_path`, right before `if custom_vault_path then`) |
| `fa_path.lua` | written for the pack: `fa_path` relative to `InitFileDir`, the game version |
| `gamedata/*.nx2` | FAF's packages for the version, from FAF's updater |
| `fa/gamedata/*.scd` | the retail archives: the one part FAF does not publish. Kept private: encrypted, behind a secret |
| `vault/` | empty; `shard.py` gives each replay a vault of its own with its map and M28AI version |
| `manifest.json` | game version, kept types, SHA-256 of every source file |

The retail maps come from FAF's map vault like any other map: their `.scmap` and Lua files are the game's (x1mp_005 and scmp_009 compared file for file; FAF adds previews and leaves out the editor's `.raw` files), and 26902315 matches every checksum on FAF's x1mp_005. The retail archives FAF's init never mounts (`schook`, `moholua`, `mohodata`, `lua`, `editor`, `ambience`) are left out.

### Making the retail file

For a new copy of the retail archives (they do not change between FAF versions):

```
python make_pack.py retail --fa <game install> --out <dir>
tar -C <dir> -cf - . | xz -9 | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:KEY -out faf-parity-retail-v1.tar.xz.enc
```

Put it where `PARITY_RETAIL_URL` points, the passphrase in `PARITY_RETAIL_KEY`, and a new `PARITY_RETAIL_ID`.

### Checking the stripping rule

When headless or the game data changes, check that the pack still holds every file headless reads:

1. Trace a set of replays with headless `--disk-trace` ([SWITCHES.md](../../docs/SWITCHES.md#headless)) and check which file types it reads:

   ```
   python make_pack.py types runs/*.disk
   ```

   `content types:` lists them; `NOT IN CONTENT_TYPES:` means headless read a type the pack would empty, so add it to `CONTENT_TYPES` first.

2. Build a whole pack from local data (with `--vault` and `--m28` also the vault maps and M28AI versions, to play from locally):

   ```
   python make_pack.py build --fa <game install> --faf <FAF data folder> --init <FAF data folder>/bin/init_faf.lua --out <pack>
   ```

3. Check that every file the traces read is in the pack with its bytes:

   ```
   python make_pack.py verify --pack <pack> --root <game install>/maps=fa/maps --root <vault>/maps=vault/maps runs/*.disk
   ```

4. Play the replays on the pack (`/init <pack>/bin/init_ci.lua`) and compare their `--digests` files with the runs on the full data: they must be identical. On 29/10/2026 the core set's nine traced runs matched, digest file for digest file.
