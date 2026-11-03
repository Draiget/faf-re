# Nightly releases

The [Nightly release workflow](../../.github/workflows/nightly-release.yml) publishes a pre-release of master's head when that night's [Replay parity](../parity-data/README.md) run has passed. Replay parity starts at 20:00 UTC (00:00 UTC+4), and takes about 5 h 30 min.

| Job | What it does |
|---|---|
| `plan` | The tag: the last real release the commit descends from, `-nightly-` and the short commit, for example `v1.1.2-nightly-168078f`. The previous nightly, for the change list. It builds nothing when that tag's release already exists, as master did not move |
| `build` | Builds `main_x64.exe` and `main.exe` with clang-cl and zips them as a release is zipped: exe, pdb, the DXC DLLs, `fafengine\` and `INSTALL.txt` ([x64](INSTALL_x64.txt), [x86](INSTALL_x86.txt)). The exe reports the nightly tag as its version |
| `release` | Writes the notes ([nightly_notes.py](nightly_notes.py)): the parity counts, every commit since the previous nightly, and the checksums. Publishes them with the zips as a pre-release, never marked as the latest release |

A failed parity run publishes nothing, and neither does a parity run started by hand, which may have played any commit or set.

Started by hand, the workflow builds the commit and writes the notes as artifacts. It publishes only with `publish` ticked, and such a build has passed no parity run, as its notes say.

Nightly tags and releases stay until someone deletes them; nothing removes old ones.
