---
name: project_splash_sequence_advances
description: Intro movies now PLAY and the splash sequence advances (thqlogo then gpglogo); the remaining blocker is 0x10101010 landing at SFPLY workctrl+0x58 during the second movie. Records the 4 landed fixes and the exact state of the open hunt.
metadata:
  type: project
---

# Splash movies play; sequence advances to movie 2

Runtime-verified. The engine now matches the shipped binary through the
first two splash movies.

## Landed this session

| Commit | Fix |
|---|---|
| `596e56d` | `GetSystemTimer` (FUN_00955730) holds `system_timer` as a **function-local static** (guard byte 0x00F8ED80, ctor inlined as `mTime = GetCycle()`). We had a namespace-scope global with a user ctor, so it sampled `GetCycle()` during static init - an extra call the original never makes. See [[project_frozen_clock_blocks_ui_coroutines]]. |
| `e540716` | Three Sofdec offset errors (below). |
| `b279eb0` | `mwsffrm_SetFrmApi` (0x00ACA1A0) was a no-argument stub; real body latches `ply->apiType` at +0x2A4. |

### The three offset errors in e540716

1. **`SFTIM_SetTimeFn` (0x00ADB600)** writes `*(handle + 4*mode + 3376)` -
   the callback table lives at **workctrl+0xD30**, where `SFTIM_GetNowTime`
   (0x00ADB170) reads it. We wrote it at workctrl+0x00, so the dispatch slot
   was null, `sftim_GetTimeNone` ran, and the clock returned the `(-2, 1)`
   sentinel forever. Constant is now `kSftimVblankCounterLaneOffset`.
2. **SFLIB time block** = `{vblank count, reserved, timer unit}`. Base is
   `0x011F8EC0` (anchored: `_SFLIB_libwork.objs` = 0x011F90C4 = `objectHandles`
   at +0x204). The lane every reader uses, 0x011F9078, is **+0x08**, which
   `SFTIM_Init` fills with `[p+8] = rate`. **Nothing references +0x04.** Four of
   our seven readers used +0x04 → time denominator 0 → `sfply_IsPlayTimeAutoStop`
   declared the movie over on frame 1.
3. **`SFX_Destroy` (0x00ACC9E0)** reads SFXZ at `[hn+0x24]` and SFXA at
   `[hn+0x30]`; we had +0x08/+0x0C. Tearing down a finished movie passed garbage
   to both child destroyers and `SFXA_Destroy` wild-wrote through it, killing the
   process mid-teardown - which is why the sequence died exactly when it tried to
   advance.

## Why the clock mattered

`splash.lua` only calls `Play` via `OnLoaded`; `movie.lua` fires that from a
coroutine polling `WaitSeconds(0.01)`. A frozen `CurrentTime()` stalls every UI
coroutine. Fixing it unblocked the whole splash flow.

Separately: something maps an **inline jmp hook over
`kernel32!QueryPerformanceCounter`** shortly after process start and rebases the
clock to exactly 86400 s (`GetTickCount64` is hooked with it). Bytes at the
import go from `8B FF 55 8B EC ...` to `E9 5B A1 B8 E7 ...` between GetCycle
call 1 and call 2. QPC is uniform across all 36 CPUs and matches uptime, so the
pre-hook sample is the real one. Do not "fix" `GetCycle`'s clamp - it is faithful
to FUN_00955400; the rule is simply never to sample the clock before the hook.

## OPEN: the remaining blocker

After gpglogo starts playing, `SFD ERROR(FF000207)` spams every frame and
`mwPlyGetStat` sticks at 4 (error), so movie 3 never starts.

`FF000207` is `sfply_CheckGetFrmApi` (FUN_00AD86E0, faithful): the frame-API
lane at **workctrl+0x58** is latched to something other than the requested type.
Probe result:

```
ApiMismatch latched=0x10101010 requested=1 wc=416B58A0   (x4, same handle)
```

**Ruled out so far**
- `concealOnExec` (FUN_00B00EB0) is the only code in `src/sdk/**` that writes
  0x10101010 (luma black fill) - a probe proved **it is never called**. It is
  also byte-faithful to the binary (all six plane/stride offsets + both row
  advances verified).
- `sfply_InitHn` (FUN_00AD7AE0) is faithful, including the
  `sfply_last_hnctrl_wksiz` latch and the 0x6CC0 cap; it memsets the whole work
  buffer to 0 and the handle base is `(buf+31) & ~0x1F` (asm confirmed).
- `sfply_CheckGetFrmApi` offset +0x58 confirmed from asm (`mov eax,[ecx+58h]`).
- Only type-1 callers (`SFD_GetFrm`/`SFD_RelFrm`) exist in our source; the
  id-frame pair is never called. So the lane is being *corrupted*, not contended.

**Bisected**: a probe reading `wc+0x58` at three points inside `sfply_ExecOne`
(0x00AD6F00) showed the lane **clean at entry** and **already 0x10101010 after
`sfply_ExecOneSub`**:

```
lane58 clobbered at after-ExecOneSub:   0x10101010 wc=40D5F8A0
lane58 clobbered at after-state-switch: 0x10101010 wc=40D5F8A0
```

A second bisect inside `sfply_ExecOneSub` narrowed it further - clean at
`sub-entry`, dirty at `after-TrExecServer`:

```
lane58 after-TrExecServer     -> 0x10101010
lane58 after-SFSEE_ExecServer -> 0x10101010
```

So the writer is under **`sfply_TrExecServer` → `SFTRN_CallTrSetup(wc, 2)`**
(0x00ADFC60). That function is faithful: the binary does
`lea esi,[ebx+1F3Ch]`, `mov ecx,[esi]`, `call [ecx + index*4]`,
`add esi,44h`, 9 iterations - which matches our model of lanes at **+0x1F30**
with `transferDescriptorAddress` at **lane+0x0C** (0x1F30+0x0C = 0x1F3C),
stride 0x44, 9 lanes. Verified, do not re-audit.

A third bisect, around the `callbacks[callbackIndex](...)` call inside
`SFTRN_CallTrSetup`'s 9-lane loop, named the culprit exactly:

```
lane58 dirtied by lane=2 cbIndex=2 desc=0x01AAA4E0 fn=01125D00
       before=0x00000001 after=0x10101010
```

**Lane 2 is `&SFD_tr_vd_mpv`** in every entry of `gMwsfdMpsStrategyTable` /
`gMwsfdMpvStrategyTable` / `gMwsfdVideoOnlyStrategyTable` /
`gMwsfdMpeg2TsStrategyTable` (SofdecAdxPlatformRuntime.cpp ~2111), and
`callbacks[2]` is the `execServer` slot (`SofdecTransferStrategy` +0x08,
SofdecFoundationRuntime.cpp:1067).

**So: `SFD_tr_vd_mpv.execServer` - the MPV video-decode server - writes a
black-macroblock pattern (0x10101010) into the SFPLY workctrl at +0x58.**
It overwrites a *correct* value (0x00000001, the latched frame-API type), so
this is a stray write from a mis-computed destination pointer in the decode
output path, not a state-machine bug. Start at `sfmpv_ExecServer` /
`sfmpv_ExecServerSub` (FUN_00AD1C10) and follow the frame/plane destination
arithmetic. This is very likely the same root cause as the long-standing
"residual decode error on late frames" item. 0x10101010 is not a concealment fill (`concealOnExec` is the
only `0x10` fill in the tree and it never runs); it is far more likely a
**decoded all-black macroblock or IDCT clamp output written through a bad
destination pointer** that lands inside the workctrl. Look for a frame/plane
destination computed from a stale or mis-offset base in the transfer lane.
Note thqlogo survives and gpglogo does not, so prefer explanations that depend
on a *second* create in the same process.

Still stubbed in `SofdecExternalStubs.cpp` and worth recovering:
`mpvhdec_ReadKernelIntraIdcPrec3` (no matching IDA symbol - the name is
invented, find its real address from the caller), `mpvcdec_InitDct`
(FUN_00AF5E80, 33 instrs), `M2VAPRD_Init` (FUN_00AF6040, 33 instrs),
`mwPlyIsNextFrmReady`, `mwPlyFinishSfdFx`.
