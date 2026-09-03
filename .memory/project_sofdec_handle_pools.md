---
name: project-sofdec-handle-pools
description: LANDED b4393c3 - three Sofdec teardown entry points were no-arg C-linkage stubs, so every movie open leaked an SFD/MPS/SFXZ handle out of pools that hold 32. Records the diagnosis recipe for "works 32 times then fails".
metadata:
  type: project
---

# Sofdec: closing a movie freed nothing

Symptom: the first 32 movies of a session play, then every `OpenMovie` fails
with `SFD ERROR(FF000D08)` -> `E2012 mwPlyCreate:can't create SFD`. A skirmish
load hit it in seconds because the loading screen reopens its movie on every
loop.

**"Works exactly N times then fails" means a pool leak, and in this codebase a
pool leak almost always means a no-argument stub on the destroy path.** C
linkage ignores parameters when mangling, so `void* f() { return nullptr; }`
silently satisfies a properly-declared `f(handle)` call. Grep
`SofdecExternalStubs.cpp` for the destroy/free/finish names on the path before
theorising anything else.

Three were stubs, all reached from `mwply_Destroy`:

| token | what it does | what the stub cost |
|---|---|---|
| `MWSFCRE_DestroySfd` 0x00AC7F40 | the only caller of `SFD_Destroy` | nothing on the SFD teardown path ran at all |
| `sfply_ResetHn` 0x00AD7FF0 | rebuilds a handle in place after `SFPLY_Stop` zeroes its state lane | every stopped handle stayed at state 0, `SFLIB_CheckHn` rejected it, `SFD_Destroy` answered `SFD ERROR(FF000131)` and the MPS parser was never returned |
| `SFXZ_Destroy` 0x00ACD670 | returns an SFXZ slot | second pool, surfaced only after the first was fixed: `E201185: can't create SfxHn` |

`sfply_ResetHn` is the interesting one - it snapshots the create template, error
callback, user-time/ext-clock/skip callbacks, speed, PTS lanes, sfsee geometry
and MPV conditions, runs `sfply_TrDestroy` + `sfply_InitHn` over the same work
buffer, then re-applies the snapshot. It restores the conditions block from the
handle's **default** set, not the live one.

Diagnosis recipe that worked: probe `mwply_Destroy` for
`handle->handleState` before and after `mwSfdStopDec`, which pinned the zeroing
to `SFPLY_Stop` -> missing `sfply_ResetHn` in one run.

Verified: `/map SCMP_009` went from 104 opens / 32 plays / 72 failures to 69
opens / 69 plays / 0 failures.

Related: [[project-sofdec-movie-crash]], [[project-skirmish-doloading-loop]].
