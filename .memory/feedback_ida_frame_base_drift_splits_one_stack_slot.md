---
name: feedback_ida_frame_base_drift_splits_one_stack_slot
description: IDA can split ONE stack slot into two variables when it applies a wrong demangled calling convention to a callee, drifting its frame base mid-function. Detect it by checking whether a loop is esp-balanced against the epilogue; found and fixed a major render bug this way (commit 3dff30e6).
metadata:
  type: feedback
---

## The failure mode

IDA derives each `[esp+N]` reference's *identity* from its own esp tracking.
When it applies a demangled signature whose stack cleanup is wrong, esp
tracking drifts from that call onward — and **two references to the same slot
get two different variable names**. The decompile then reads as if two
independent values are in play, and a faithful-looking transcription of it is
wrong.

Real case (`Moho::MeshRenderer::Batch`, `FUN_007DFA00`):

  - `0x007DFBED  mov [esp+20h], eax`  → IDA calls it `var_1D0` (frame base 1F0h)
  - `0x007DFCDC  mov eax, [esp+20h]`  → IDA calls it `var_1D4` (frame base 1F4h)

Same displacement, "different" variables. The decompile therefore showed
`v29.lod = v26` where `v26` was a loop-invariant buffer base set before the
loop, instead of `v29.lod = <ComputeLOD result>`.

Cause: IDA applied `?UpdateInterpolatedFields@MeshInstance@Moho@@ABEXXZ`
(`ABE` = `__thiscall`, `XZ` = void params ⇒ `retn 0`) to a body that actually
ends `retn 4` at `0x007DEF5C`. The two `push edi` argument slots in the loop
looked unreclaimed, so the frame base walked 1ECh → 1F0h → 1F4h.

## How to detect it — the esp-balance check

**A loop must be esp-balanced.** If IDA's frame base differs between the top
and the bottom of a loop body, IDA is wrong, not the binary. Confirm the true
esp from the epilogue and prologue, which cannot lie:

    prologue: 3 pushes + `sub esp, 1D4h` + 4 pushes
    epilogue: `pop edi/esi/ebp` + `add esp, 1E0h` + `retn 10h`
            ⇒ esp before the pops = E - 0x1EC, the same value the loop starts at

Then check each callee's *actual* last instruction (`tail -12` on its `.asm`)
rather than trusting the demangled convention. `retn 4` on a nominally
zero-argument `__thiscall` is the tell.

## Why it matters

Two "different" variables that are really one slot is exactly the shape that
survives review: the decompile is self-consistent, and a recovery that
transcribes it literally passes `tucheck`. Here the consequence was that every
mesh render pass read its material and hardware batch out of a
`fastvector<UserEntity*>` heap buffer — untextured meshes flickering as the
camera panned. See [[project_meshbatchkey_lod_lane_bug]].

**Rule of thumb:** when a decompiled struct-field assignment takes a
loop-invariant where a per-iteration value is obviously required, check the
raw `[esp+N]` displacements and the callees' real `retn` before believing it.
