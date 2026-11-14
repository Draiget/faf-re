# Microchip offline chat translation

Russian, German, French and Spanish player chat gains a local `[English / RU]`
(or DE/FR/ES) line in the game lobby and in-game chat. Originals remain visible.
Private/allied messages retain their existing visibility. Translations are never
sent to players, saved as chat logs by the worker, or submitted to an online API.
The FAF desktop client's separate global chat is outside this mod.

Requires the custom x64 engine from this branch and Windows Python 3.12 x64.
From the repository, after building `faf_main`:

```powershell
python tools/offline-translation/install.py "$env:LOCALAPPDATA/Microchip/faf-translator"
# Close the game, then:
./tools/offline-translation/install-game.ps1
```

Setup downloads dependencies and official Argos language packs. Translation after
setup runs offline using anonymous pipes, without a listening network service.
The runtime is private to `%LOCALAPPDATA%/Microchip/faf-translator`; it does not
change system Python packages. Existing engine files and preferences are backed
up beneath `bin_x64/lag-test-backups/offline-chat-*`.

Enable/disable **Microchip Offline Chat Translation** in the game's UI Mod
Manager, then rejoin the lobby/restart the game. Other players need nothing.
Classic engines safely skip this mod; they do not supply the translation bridge.

The worker runs below normal priority with one inference thread, a bounded queue,
and limited message/token lengths. It does not delay original chat or simulation.
The first message in each language loads its model and can take a few seconds.
Short ambiguous messages may be skipped; automatic detection and translations
can be imperfect. English is left alone. Only the four installed source languages
are supported initially.

Model data comes from the official [Argos package index](https://github.com/argosopentech/argospm-index).
Model attribution accompanies each pack in `models/<language>/README.md`.
`source.json` records the download address and local SHA-256; the index supplies
no independent published checksum.

Validation: 269 engine network checks; chat routing tests; real classic/x64 local
lobby and game checks displaying Russian translations; all four languages tested
with Python network connections blocked. The Spanish pack uses float32 because
its int8 output failed translation checks on this machine.
