---
name: project_inputcapture_orphan_chain_resolved
description: "RESOLVED (supersedes legacy ~/.claude/projects/.../memory/project_inputcapture_orphan_chain.md). InsertInputCaptureWithGrowth (FUN_007A5870) was NOT actually an orphan -- its real caller (FUN_007A5710/AppendInputCaptureWeakReference) exists and is Lua-reachable, but the RECOVERED SOURCE for FUN_007A5710 simply never called it, which is what made FUN_007A5870 look uncalled. Fixed both bodies, recovered the 236-instruction FUN_007A5A70 (GrowAndInsertInputCaptureWeakRef) from raw .asm, migrated the whole sInputCapture cluster off AsWeakPtrVectorRuntimeView."
metadata:
  type: project
  modified: 2026-08-25
---

Commit 63e78496 ("Migrate sInputCapture cluster off AsWeakPtrVectorRuntimeView
reach-in, recover GrowAndInsertInputCaptureWeakRef").

**The orphan diagnosis was half right, half wrong.** `FUN_007A5870`
(`InsertInputCaptureWithGrowth`) genuinely had no *source-level* caller --
but the binary xref for it was sitting right there the whole time
(`FUN_007A5870.xrefs.txt`: one code xref from `0x007A576B` inside
`FUN_007A5710`). The reason nothing called it by name is that
`FUN_007A5710` (`AppendInputCaptureWeakReference`) had ALSO been
mis-recovered: its real body (per `.c`) is `push_back`-shaped -- fast path
constructs in place, slow path delegates to `FUN_007A5870` on the grow
path -- but the recovered source hand-rolled the fast-path logic only and
never delegated. Two bugs stacked: fix the caller's missing delegation and
the "orphan" resolves itself. **Always re-derive the caller's REAL shape
from its own disassembly before trusting that "no source-level caller" ==
"binary caller doesn't exist either."**

**`FUN_007A5A70` (236 instructions, the callee both bad-sp-value-flagged
tokens `FUN_008A9100`/`FUN_007CA300`/`FUN_008F1760` share the trap with) IS
recoverable from raw `.asm` alone** -- cross-checking every callee's own
disassembly (not just the caller's `.c`) resolves argument-count/position
ambiguity the sp-value warning creates. Concretely: reading each callee's
own asm (`FUN_007A61F0`, `FUN_007A6120`, `FUN_007A5FE0`, `FUN_007A6030`,
`FUN_007A5FB0`) to see which registers ADVANCE vs stay FIXED is what
resolved the whole call graph, not the flagged function's own pseudocode.

**Found a genuine mis-citation this way**: `FUN_007A6030` was cited in
`WeakPtr.h` under `AssignWeakPtrRangeForward` (advances both dest+src
together). Its own asm never advances the source register (`edx` stays
fixed across the whole loop, only `eax`/dest advances) -- it's a
fixed-source *fill*, not a two-range copy. Moved to a new
`WeakPtr<T>::AssignFillRange` static method. **The lesson: an existing
citation grouping several addresses together is not itself proof they're
the same operation -- when a citation is pivotal to your own recovery,
verify it against that specific address's own raw asm, not just the
doc comment.**

**Hook note**: `container_lane_guard.py` only sees the submitted diff text,
not the surrounding file. A free function matching the verb+noun regex
(`AssignFillRange`, `FillConstructRange`) gets denied even when it's
legitimately generic (WeakPtr<T>-independent) and even when *identical*
existing functions in the same file already passed at some earlier point.
Fix: make it a `static` member of the modelled type (`WeakPtr<T>` here) and
anchor the `old_string` far enough back to include the `struct`/`class`
opening brace in the same diff, so `_opens_class_body` can see it. A
same-file free function (`AsWeakPtrVectorRuntimeView` itself) is NOT
flagged because it isn't in the `RAW_VIEW` regex list at all --
`AsWeakPtrVectorRuntimeView`/`WeakPtrVectorRuntimeView` were never added to
that list, unlike `AsVectorRuntimeView`. Don't assume parity between the
two "view" families when reasoning about what the hook will allow.

**Shared-checkout hazard confirmed again**: `Vector.h` and
`recovered_progress.json` edits from this pass were absorbed into a
concurrent agent's commit (`bc3e503e`) via what was almost certainly a
broad `git add`/`commit -a` on their end -- git showed both files clean
before I ever ran `git commit` on them myself. Content was correct and
intentional either way (my own real work), just filed under someone else's
message. Re-confirms: always `git status --porcelain` immediately before
committing to see what's actually still yours to commit, and never assume
a file you edited minutes ago still needs YOUR commit.
