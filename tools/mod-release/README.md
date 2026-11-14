# Microchip mod releases

Work on `codex/microchip-mods`. Branch pushes test ZIP packaging and save downloadable
ZIPs under the Actions run's **microchip-mod-packages** artifact, without publishing.

For a release, update the mod's `mod_info.lua` version, commit and push it, then
create and push the matching version tag on that commit. A tag creates a GitHub
release with one installation ZIP, a SHA-256 checksum and requirements/install notes.
Existing releases are never replaced. These releases do not change the global Latest release.

| Mod | Tag prefix | Installation folder |
|---|---|---|
| Chat Mention | `chat-mention-v` | `Microchip-Chat-Mention` |
| Client Test Recorder | `client-test-v` | `Microchip-Client-Test` |
| Eco Sharing | `eco-sharing-v` | `Microchip-Eco-Sharing` |
| Logo Stamps | `logo-stamps-v` | `Microchip-Evil-Stamp` |
| F11 Connectivity | `connectivity-v` | `Microchip-F11-Lag-Connectivity-Screen` |
| Icon Mod | `icon-mod-v` | `Microchip-Icon-Mod` |
| Offline Chat | `offline-chat-v` | `Microchip-Offline-Chat` |
| Team Colour Bands | `team-colours-v` | `Microchip-Team-Colour-Bands` |

Example, if the committed Eco Sharing version is 4:

```sh
git switch codex/microchip-mods
git tag eco-sharing-v4
git push github eco-sharing-v4
```

Use the exact version from mod_info.lua (`4` means `v4`, not `v4.0.0`). Do not
move published tags or create a release manually while this workflow is running.
Wait for **Microchip mod releases** to finish in Actions.

Local verification (no publishing):

```sh
python -m unittest discover -s tools/mod-release -p 'test_*.py' -v
python tools/mod-release/package.py --all --output out/mod-release-check
```

Choose a fresh output directory each time. ZIPs keep the required mod folder name
and contain only runtime assets and documentation. Preview tools, desktop metadata,
Python scripts, logs, personal settings and other mods are excluded. Versions are
read without executing Lua; fixed ZIP timestamps make unchanged packages reproducible.

Keep original third-party icon attribution. Requirements for engine-dependent mods
are included in release notes. Offline Chat's ZIP excludes its separately installed
translator worker and language packs. No executables are bundled.

The workflow runs from tags on this branch; the fork's master stays unchanged.
It uses GitHub's temporary token for publishing, with no additional saved secret.
Creating a release tag will publish that version publicly.
