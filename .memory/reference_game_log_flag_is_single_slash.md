---
name: reference-game-log-flag-is-single-slash
description: The engine's log flag is `/log <name>` (SINGLE slash, one argument). `//log` matches nothing and silently writes no file — which is why sessions kept "checking logs" with no log.
metadata:
  type: reference
---

# Getting the game's own log: `/log <name>`, single slash

`IWinApp.cpp`'s `TryInitializeStartupLogTarget` does:

    msvc8::vector<msvc8::string> logArgs;
    if (!CFG_GetArgOption("/log", 1, &logArgs) || logArgs.empty()) {
        return;                                  // <-- silent no-op
    }
    const msvc8::string logFileName = FILE_SuggestedExt(logArgs[0].c_str(), "sclog");

So the flag is **`/log`**, it takes **one argument**, and the extension is added
for you. Correct invocation:

    dbgrun.exe main.exe <workdir> /map SCMP_009 /log spawn12
    -> C:\ProgramData\FAForever\bin\spawn12.sclog

**`//log` matches nothing and returns silently — no file, no diagnostic.** An
older note recommended `//log` because a double slash escapes Git-Bash path
mangling; that is only relevant when invoking through Git-Bash. Launched from
PowerShell / `Start-Process`, the `//` is passed through literally and never
matches. Several sessions ran "check the logs" with no log at all because of
this.

The file appears immediately (not only on exit) and grows live, so it can be
tailed while the game runs — much better than the Fatal Error dialog's
last-100-lines screenshot, which was the previous fallback.

## Benign noise to expect, so it is not mistaken for a bug

- **`Unable to find file /env/.../<prop>_script.lua`** followed by a stack
  traceback and `Problems loading module ... Falling back to 'Prop' in
  '/lua/sim/prop.lua'`. This is FAF's designed optional-per-prop-script
  fallback. Each fallback raises a Lua error that the engine catches, i.e. **one
  C++ throw per prop**. On SCMP_009 that is `NUM PROPS = 5182`, which is
  exactly why dbgrun reports its 3000-throw cap. Not a bug — do not chase it.
- `access to nonexistent global variable "ScriptedIconAssignments"`
  (blueprints.lua:338) and the `SessionIsReplay` variant — routine FAF warnings.
- `Evaluating LazyVar failed` from `score_mini.lua` / `control.lua` — UI layout
  lazy-var churn, non-fatal.
- `CDiskWatch::EnablePrivileges` SeBackup/SeRestore failures — needs elevation,
  irrelevant.
- Hotbuild "Shift modifier ... already bound" warnings — user keybind config.

Related: [[project_commander_spawn_initializearmies_nil_binding]],
[[project_startup_debugging_harness]].
