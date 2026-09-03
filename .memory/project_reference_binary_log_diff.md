---
name: project-reference-binary-log-diff
description: The shipped ForgedAlliance.exe runs standalone from the same bin dir and reaches the main menu - diff its /log output against ours to find missing startup steps. Recipe plus the divergences it has already found.
metadata:
  type: project
---

Established 2026-08-04. **The single highest-signal debugging tool available
on this project, and it went unused for a long time.**

## The recipe

`C:\ProgramData\FAForever\bin\ForgedAlliance.exe` is the real FAF binary, in
the same directory as our staged `main.exe`, reading the same data. It runs
**standalone** - no FAF client, no auth, no `/init` argument needed - and
reaches the main menu. `scratchpad/runref.bat` launches it under the same
always-windowed-through-cmd contract as `runwinlog.bat` and writes
`scratchpad/ref.sclog`.

Then diff by category rather than line-by-line (our log is ~38k lines of
`duplicate entries` spam against the reference's 541):

```
for pat in "adding font file" "Wavebank prepared" "OpenMovie" "Playing movie" \
           "Compiled shader" "AddSearchPath" "mounting content"; do
  echo "$pat : ours=$(grep -c "$pat" engine.sclog) ref=$(grep -c "$pat" ref.sclog)"
done
```

A category at `ours=0 ref=N` is a whole engine step we never call.

`scratchpad/shot3.ps1` is `shot2.ps1` with a `-Proc` parameter so the
reference can be captured too. Reference at the menu reads `nonblack
4802/7227`; a black window reads `96/6596` (the 96 is title bar).

## What it found immediately

| Category | ours | ref | verdict |
|---|---|---|---|
| AddSearchPath | 81 | 81 | VFS is fine |
| mounting content | 20 | 20 | mounts are fine |
| Compiled shader | 11 | 11 | shaders are fine |
| **adding font file** | **0** | **14** | `REN_Init` never called - fixed, 88f1b6b |
| Wavebank prepared | 0 | 90 | audio init never runs - OPEN |
| Playing movie | 0 | 4 | `.sfd` rejected as "not a valid SFD file" - OPEN |

So VFS/mount/shader work was never the problem, which had been suspected.

## Still-open divergences

- **No audio at all.** The reference logs `Unknown DirectSound speaker
  configuration 8`, `MD5 of global settings`, then 90 wavebanks - all before
  `REN_Init`. So it happens inside `AppInitCommonServices` or
  `USER_LoadPreferences`. We log none of it. `AudioEngine.cpp` has the bodies
  (`MD5 of global settings`, `Wavebank prepared`), so this is wiring, not
  recovery.
- **Movies never play.** `OpenMovie /movies/thqlogo.sfd` then `is not a valid
  SFD file`. The reference opens and plays four. Our log ends there.
- Ours emits 38k `duplicate entries for units/...` lines the reference never
  emits, including ~140 repeats of the *same* entry in the *same* archive.
  Re-inserting the same archive index repeatedly, or a broken dedup compare.
- 54x `Key map contains unrecognized modifier string: Ctrl` - the reference
  has none. `IN_ParseKeyModifiers` does not recognise `Ctrl`.

## FAF launch facts

- No `/init` argument means the engine loads `SupComDataPath.lua`, which
  `dofile`s `init_faf.lua` - so our default launch *does* mount FAF content.
  `/init init.lua` is what the FAF client passes; it is nearly the same file.
- The 5 failing `scx_menu` textures (`profile/panel_bmp.dds`, four
  `panel-brackets/bracket-*_bmp.dds`) are **genuinely absent** from every
  archive - confirmed by scanning all `.nx2/.nx5/.faf/.cop/.nxt` for
  `scx_menu/profile` and `panel-brackets`: zero hits. Red herring, closed.
- `faf-pioneer` (`G:\projects\faf-pioneer`) documents the hosted-lobby launch:
  `ForgedAlliance.exe /init init.lua /nobugreport /gpgnet 127.0.0.1:21000
  /numgames N /log <path>`. Needs a GPGNet TCP peer to drive it.

Related: [[project-black-screen-next-steps]],
[[project-resize-crash-depth-stencil-binding]]
