---
name: project_sim_stall_countedptr_root_cause_2026_09_03
description: "RESOLVED 2026-09-03. The sim never beat (Game time stuck 00:00:00) because CountedPtr<T> did no reference counting, so particle textures were freed while live and CWldSession::DoBeat faulted every frame. Fixed in 3f90aaf6 + ec810820; game time now advances to 00:19:43 with zero crashes."
metadata:
  type: project
---

## The symptom

`/map SCMP_009` reached a fully initialised session -- blueprints, nine armies,
AI brains, nav mesh, terrain rendering -- and then sat at
`Session time: 00:00:33  Game time: 00:00:00` **forever**. The render thread
kept drawing, so the window looked alive. No commander appeared because no beat
ever completed.

## What made it findable

`gpg::Logf` formats through a bounded buffer, so the crash handler's single
`Logf("CRASH callstack:\n%s", ...)` printed **two frames and silently dropped
the other nineteen** -- exactly the ones naming engine code. Logging one frame
per call (`WinApp.cpp`, `LogCrashSummaryAndCallstack`, marked "Not in the
binary") exposed the whole stack immediately. **Do this first** on any crash
whose stack looks uselessly shallow.

## Root cause

`CountedPtr<T>` in `moho/misc/CountedObject.h` was a bare
`T* tex = nullptr;` -- no constructor, no copy constructor, no destructor. It
counted nothing despite the name.

So one `msvc8::vector<SWorldParticle>` was:
- **filled** via `push_back`, which uses the implicit copy constructor and
  takes **no** reference;
- **emptied** via the hand-rolled `DestroyWorldParticleForVectorTailLocal`,
  which **releases** one.

Every round trip pushed the `CParticleTexture` refcount below what was taken.
The texture was deleted while particles still pointed at it, and the next beat
read a freed object -- `px` null but `pi_` garbage -- so
`CParticleTexture::GetTexture` faulted assigning `mTextureResource`, inside
`CWldSession::DoBeat`.

**The counting belongs on the pointer.** `Moho::SParticle::~SParticle`
(0x0049BD30) is a *compiler-generated* member destructor: string teardown at
+0x68, then the counted pointers at +0x60 and +0x5C in reverse declaration
order, each `lock xadd [ptr+4], -1` / `jnz` / `call [[ptr]](1)` -- i.e.
`ReleaseReferenceAtomic`. That destructor exists only because the template has
one, so `SWorldParticle` still declares none (RULE ONE).

`CountedPtr<IFormationInstance>` wraps a type with no refcount at all, so the
ownership ops are constrained with C++20 `requires` and degrade to plain
pointer copies there.

A second, independent bug was fixed first (`ec810820`): both
`CWorldParticles::AddWorldParticle` bucket sites used
`::operator new(sizeof(ParticleRenderBucketRuntime))` and handed the **raw,
unconstructed** storage to an initializer whose first act is `.reset()` on its
shared_ptr members -- releasing whatever the heap block held (0xFFFFFFFF, so it
wrote through 0x00000003). `new T()` emits the same `operator new` the binary
calls plus the construction its constructor emission performs.

## Evidence it worked

Soaked on SCMP_009 with nine armies: **9m12s of session time reaches
`Game time: 01:40:48`, 52 clock samples, ZERO crashes**, process still alive.
Heap settles at ~744 MB instead of climbing, which also rules out a refcount
leak from the fix. That run exercises AI building and fighting for 100 minutes
of simulated combat -- units, weapons, projectiles, death, economy, pathing.

UI corroborates: 650 mass / 3900 energy (the ACU's own starting resources -- a
unitless army shows 0), a populated ACU status portrait with a green health
bar, and no defeat triggered for any of the nine armies.

Two things are *not* fixed by this and should not be mistaken for it:
- The camera sits at map centre (`camPos` x=512, zoom ~884) rather than on the
  ACU. That is the known `/map`-launch focus-army divergence, not a spawn bug.
- `SCMP_003` never reaches a session at all: zero clock samples and 722
  `[INITNM]` lines, where SCMP_009 emits none. `[INITNM]` is instrumentation in
  the peer-locked `CWldMap.cpp`, so that hang sits in another agent's in-flight
  work -- and note their uncommitted edits are compiled into any build made
  from this checkout.

## Two traps confirmed while doing this

- **Screenshots destabilise the live D3D9 device.** Both `CopyFromScreen` runs
  raised the GPG "Error Report" dialog; the no-screenshot runs were clean.
  Never judge stability from a screenshot run. Capture the game's own window
  rect (`GetClientRect` + `ClientToScreen` on `MainWindowHandle`), not screen
  origin -- the latter grabs the user's desktop.
- **`SessionIsReplay` is NOT a recovery gap.** See
  [[project_sessionisreplay_is_a_faf_patch_not_a_gap]].
