---
name: feedback-recover-input-not-compiler-output
description: "HARD STOP (PreToolUse hook): container/template emissions are recovered as calls to the canonical msvc8 template, never as per-type lane functions or *_runtime_view escapes"
metadata:
  node_type: memory
  type: feedback
---

Operator directive, 2026-08-21, on commit `4e8030e0` and the `ReconBlip.cpp`
lanes that predated it. Verbatim:

> "We have msvc8 namespace and those are literally std things we just need to
> made the same way but for old msvc8 compiler. What the fuck is the
> vector_runtime_view? [...] Whole code looks like a dirt-shit that should be
> replaced with a single template of msvc8::vector or similar. [...] Can we
> patch our skills so they will HARDLY PROHIBIT, LIKE A HARD STOP."

> "we need not just recover functions, we need to recover behaviour [...] we
> should follow enchantment way, keeping behaviour over exactly 1:1 amount of
> functions even if those are dirty-shit made by compiler. We need to predict
> what compiler will make, compile single file and see for example. No-one
> doing that shit [...] in real game engines."

> "Whole concept of AsVectorRuntimeView is completely against STD and how
> usually normal people write engines, we should recover source code that will
> be compiled 1:1 to binary (same behaviour), not each function blindly."

**Why:** the deliverable is *source that compiles to this binary*, not one C++
function per symbol IDA found. MSVC emits one out-of-line body per (template,
element type), so the single 2007 line `mReconDat.resize(n, val)` emitted
**twelve** symbols. `4e8030e0` recovered the twelve as free functions in
`moho/sim/ReconBlip.cpp`. The duplication is not just noise — it hides
divergence: that hand-copied growth path **doubled** where MSVC8's `_Grow_to`
grows **1.5x**, and the template's `insert` had no `max_size` guard and no
local copy of `_Val`, so inserting an element aliased into the same vector read
freed memory. Collapsing the lanes is what surfaced all three bugs.

**How to apply:**

- Enforced mechanically by
  `.claude/skills/continue-recovery/scripts/container_lane_guard.py`
  (`PreToolUse` on `Write|Edit|MultiEdit`, exit 2 = deny). It denies, outside
  `legacy/containers/`, `legacy/algorithms/`, `gpg/core/containers/`: per-type
  container ops (`Destroy*Range`, `Fill*Span`, `Insert*Range`, `*Lane`, …),
  any `*_runtime_view` / `AsVectorRuntimeView`, open-coded
  `0xFFFFFFFF/sizeof(T)` or `capacity + capacity/2`, and hand-rolled
  placement-new element loops. `FAF_LANE_GUARD_OFF=1` disables it.
- Procedure: find the canonical template member → add an `Address:` line to it
  → write the **call** at the instantiating site. That call *is* the recovery
  and is also the source-level invocation the linker needs.
- **Template diverges from the binary? Fix the template.** One fix covers every
  element type; forking a per-type copy around a divergence is how the bugs
  above survived.
- Some emissions map to **no source line at all**: member destructors, base
  ctor/dtor chaining, vbase fixups, EH funclets, implicit copy/move ctors.
  `~ReconBlip` calls the vector dtor at `0x005BECBB` only because `mReconDat`
  is its last-declared member. Writing that call by hand is fabrication.
- The test: write the natural source, `tucheck` it, confirm MSVC emits the same
  family of out-of-line bodies. If you hand-wrote the emissions, you have not
  recovered the source.

Landed `a83c6cc7` (net -616 lines, 18 addresses relocated onto template
members, 9 per-width allocators collapsed into one `allocate_slots_checked`).
Written out in full as **RULE ONE** in the project `CLAUDE.md`.

Remaining debt of the same shape: `legacy/containers/Vector.cpp` (~8k lines),
the `gpg` `*Lanes.cpp` files, and the local `_Insert_n` copy in
`moho/sim/CWldSession.cpp`. Extends [[feedback-no-duplicate-container-helpers]].
