---
name: feedback_gitbash_path_mangling_dbgrun_args
description: Passing /map, /windowed, /log etc. to main.exe via dbgrun from a Git Bash command silently mangles them into fake Windows paths (Git Bash's automatic Unix->Windows path conversion fires on any bare /word argument). Use // (double leading slash) to escape it, and ALWAYS verify with Get-CimInstance Win32_Process before trusting a test run.
metadata:
  type: feedback
---

## The bug (cost ~25 minutes and 5 wasted test runs, 2026-09-02)

Launched `dbgrun.exe main.exe workdir /windowed 1024 768 /map SCMP_009 /log
<tag>` from a **Bash tool call** (Git Bash / MSYS2). Git Bash's automatic
argument path-conversion — the same mechanism that turns `/c/Users/...` into
`C:\Users\...` for genuine paths — also fires on bare `/word` tokens that
were never meant to be paths at all. Confirmed via
`Get-CimInstance Win32_Process -Filter "ProcessId=<pid>" | Select
CommandLine`:

    intended: /windowed 1024 768 /map SCMP_009 /log cmdrverify5
    actual:   C:/Program Files/Git/windowed 1024 768 C:/Program Files/Git/map
              SCMP_009 C:/Program Files/Git/log cmdrverify5

**The game never received `/map SCMP_009` at all.** It just booted normally
to the main menu — the "stuck loading screen" observed for ~290 seconds
across 4 separate test runs (verify1 through verify5) was the engine's
ordinary boot/splash sequence, not a skirmish-load hang. This produced a
completely fabricated lead: a deep dive into `CSimDriver::ThreadCreateSim` /
`Sim::Setup` / `CreateArmies` as a "the sim thread never produces its first
sync data" blocker, which was chasing a symptom that had nothing to do with
map loading at all. That source-reading (documented in
[[project_commander_spawn_goal_synthesis_2026_09_02]]) is still valid
*reference material* for how `HasSyncData()`/`WLD_DoInitializing` work, but
the "it's stuck" conclusion built on top of it was wrong.

## The fix

Prefix every bare-slash argument passed to a Windows exe from a Bash tool
call with a **second leading slash**: `//windowed 1024 768 //map SCMP_009
//log <tag>`. Git Bash's MSYS path converter only rewrites single-leading-
slash tokens; `//` survives as a literal `/` once passed through. Confirmed
via the same `Get-CimInstance` check:

    "C:\ProgramData\FAForever\bin\main.exe" /windowed 1024 768 /map SCMP_009 /log cmdrverify6

This matches a note already buried in an earlier compacted-summary mention
("`//map` escapes Git-Bash path mangling") — it just wasn't surfaced/applied
this session until the mangled command line was actually inspected. **Read
this file before the next dbgrun invocation from Bash**, don't re-derive it
by trial and error again.

## The verification habit this should have caught immediately

**Before spending any test-run time analyzing "why is it stuck", first
confirm the process actually received the arguments you intended.** One
`Get-CimInstance Win32_Process -Filter "ProcessId=<pid>" | Select
CommandLine` (or `Get-Process -Id <pid> | Select Path` for a coarser check)
costs one PowerShell call and would have caught this on the FIRST run, not
the fifth. Do this as a standing first step of any dbgrun launch, right after
capturing the PID and before any waiting/polling begins.

## Also worth remembering: this does NOT apply to PowerShell-tool invocations

This mangling is specific to arguments passed through a **Bash** (Git
Bash/MSYS2) command line. Launching the same exe via the **PowerShell**
tool does not go through MSYS's path converter, so `/map SCMP_009` there
needs no escaping. Only escape when the launch command itself is a Bash
tool call.

Related: [[reference_game_log_flag_is_single_slash]] (the OTHER `/log`
gotcha — `//log` alone, i.e. without a filename, silently writes no file;
that note is about the flag's own argument count, unrelated to this Git
Bash mangling, but easy to conflate since both involve slash-prefixed
`main.exe` arguments passed through a Unix-ish shell).
