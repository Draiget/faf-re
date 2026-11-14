# Lobby connection test

The rebuilt engine's lobby has a **Lag Test** button. Open it, then the host
presses **Lag Test** in the results panel to run the test. Each row shows the
player's lowest score and the peer on that connection:

```text
Alice: 90.0% -> Carol
Bob: 100.0% -> Alice
Carol: 100.0% -> Alice
```

The score is the percentage of 240 round-trip probe replies received within
500 ms, over about one minute. Probes use the actual reliable lobby peer
connections, including their routing and retransmissions. A missing or late
reply counts against the sending player's score. Duplicate replies do not
increase it. Equal scores choose the peer name alphabetically.

This is **not a hidden simulation**, packet-loss measurement, or measurement of
actual in-game command deadlines. Probe RTT includes both network directions
and application scheduling. A bad pair does not identify which person or ISP is
responsible. CPU scores remain unchanged. A score of 100% means all probes met
this test's deadline, not that a match is guaranteed to run without lag.

Every connected participant (observers included) needs the same hook. The host
cannot start while any peer has not advertised support. An unmodified FAF
client is not assigned a made-up score. Each participant reports only its own
outgoing probe results; reports are self-reported diagnostics, not anti-cheat
evidence. A detected local scheduling pause of more than 200 ms makes the run
inconclusive, rather than attributing the pause to a network route. Smaller
endpoint pauses can still affect the score.

Joining or leaving invalidates the results. Missing reports remain unknown and
are labelled after a five-second grace period. Only the host can start a run;
another run can replace the completed results.

## Install

Run **`Microchip faf-re builder.exe`** (author: **Microchip**). The window
checks FAF's saved engine paths and common folders for an existing x64 faf-re
installation. Use **Browse** beside “Installed faf-re” for a custom folder.
Close the game and FAF client before changing files or settings.

- **Version:** defaults to the latest upstream commit. Tagged versions are also
  listed. **Refresh** checks upstream again. The selected full commit is held
  fixed throughout that build, even if upstream changes during installation.  The previously working 26 October revision (`e4cc5d8b`) is also offered as a  fallback. Latest remains the default.
- **Install faf-re / Update / install version:** downloads the selected upstream
  source, installs missing Git, LLVM, Visual Studio 2022 C++/ATL/CMake/Windows SDK
  tools and the DirectX runtime, then builds x64 Release. It stages the engine,
  shader libraries, engine hooks and local FAF initialization scripts, installs
  Lag Test, and creates a desktop shortcut with the compiled-mod and selection-
  ring settings from the HTML guide. Existing detected installations are updated
  in their selected directory. This button **does not change FAF client settings**.
- **Install Lag Test:** adds/updates only the three lobby hooks in the selected
  existing faf-re directory. It checks the required x64 DirectX runtime and
  installs it if missing. It does not rebuild or replace the engine.
- **Connect with FAF client:** separately backs up and changes only the current
  user's FAF execution directory and executable command to use the selected
  engine, including the mod and selection-ring settings. Relaunch FAF afterward.

The FAF data folder normally is `C:\ProgramData\FAForever`; select another
folder if yours is customized. FAF and your own Forged Alliance installation
must already work; launch a normal FAF game once before setup. Commercial game
assets and the FAF desktop client are not included. Every test participant
needs faf-re and Lag Test installed.

Windows administrator prompts may appear while installing prerequisites. If a
prerequisite requires restarting Windows, setup reports it and can be run again
afterward. Build downloads and source checkouts are cached per version under
`%LOCALAPPDATA%\Microchip\faf-re-builder`; compilation uses up to four jobs.
Progress and per-run logs appear in the window. Success shows **“All installed,
ready to go.”** A failed download/build never triggers that success message or
installs an incomplete build.Validation on 8 November: upstream revision `a9583624` compiled but failed itsown post-build `faf_math_dump` parity check (`acos`, two blocks). Setup preservesthat failure and does not install that build. Choose the previously workingrevision or a later upstream revision that passes its checks; do not disablethe check to force installation.

Archives are checked against the selected source's SHA-256 manifest. Git/LLVM
installers use official release SHA-256 metadata; Microsoft prerequisite
installers require a valid Microsoft publisher signature. Downloads retry up
to three times, use the official GitHub asset API when the release route fails,
and use Boost's official archive mirror if SourceForge returns an error page.
The application remains unsigned and changes no firewall settings.

Replaced files are backed up with a `restore-map.json` listing their original
locations. Engine builds use `FAForever/lag-test-backups/<id>`; Lag Test and
connection changes use `<engine-folder>/lag-test-backups/<id>`. Failed writes
attempt rollback and identify the backup if any restoration needs attention.
To return to classic FAF, close the client and restore its backed-up
`client.prefs` to its recorded location. Source/build script:
`tools/lag-test-installer/`.

The standard build stages `data/fafengine/` beside the engine executable. For
an already-built engine, copy the **contents** of that directory into the
`fafengine` directory beside the executable, keeping the `lua/ui/lobby/` layout.
Do this on each participating PC. Relaunch the game and create/join a lobby.
FAF's downloaded `lua.nx2`/`lua.nx4` archives are not modified.

Remove the three files under `fafengine/lua/ui/lobby/` to uninstall this feature.

## Tests

Install the Python `lupa` package and run:

```powershell
python tests/lobby/test_connection_score.py
```

The tests use Lua 5.1 and a simulated three-peer transport to check deadlines,
loss, duplicate replies, shared worst-peer results, unsupported clients,
membership changes, scheduling pauses, and malformed reports. These tests do
not replace a live multi-PC lobby test.
