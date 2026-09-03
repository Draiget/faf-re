---
name: project_issue_setcommandtarget_next_target
description: RESOLVED (commit b5bd57a7). ISSUE_SetCommandTarget was already fully recovered in Sim.cpp - it just sat in that file's anonymous namespace while CWldSession.cpp called it as moho::. Also records the truncated-grep mistake that made it look like a missing body.
metadata:
  type: project
---

## RESOLVED — commit `b5bd57a7`

`moho::ISSUE_SetCommandTarget` (`0x008B0EE0`) was **already fully and
faithfully recovered** in `Sim.cpp` — the no-rush gate, the command-type 22
pickup restriction, the three category checks, all of it. It simply sat inside
that file's **anonymous namespace**, while `CWldSession.h:1865` declares it and
`CWldSession.cpp` calls it from `:11422`, `:11448`, `:11467` as `moho::`.
Nothing could resolve against an internal-linkage body, so it was one of the
LNK2019s `/FORCE` turns into a live call site pointing at nothing.

Fix was the same one-line-scope change as `func_DecodeEntIdSet` (`25b63595`):
move it out of the anonymous namespace into `namespace moho`. The body is
untouched.

## The mistake worth not repeating

I concluded "declared and called but **never defined**" and wrote a whole
escalation note planning a 141-line recovery from scratch. That was wrong, and
the cause was mundane: the search was

```
rg -n "ISSUE_SetCommandTarget" src/sdk/ | head -8
```

`head -8` cut the output at the `CWldSession.h`/`CWldSession.cpp` hits, and
`Sim.cpp` sorts after both. The definition was there the whole time.

**Never conclude "not recovered" from a truncated grep.** Drop the `head`, or
use `rg -c` / `rg -l` first to see how many files actually match. This is the
same class of error as the DAG's "false negative: the candidate is already
implemented under an intent-first name" warning in the skill — except here it
was not even renamed, just scrolled off.

## Reusable: the anonymous-namespace linkage split

Two instances in one session (`func_DecodeEntIdSet`, `ISSUE_SetCommandTarget`),
both in `Sim.cpp`'s big anon namespace at line 946:

> The shipped binary kept the helper file-static beside its only caller. Our
> tree recovers that caller into a **different** translation unit. Once the two
> are split, one side must gain external linkage — and the helper is the
> smaller, safer change, especially when the caller's file is peer-locked.

When triaging an LNK2019 whose symbol *is* present in the tree, check the
enclosing namespace before assuming a missing body. See also
[[feedback_msvc_param_const_breaks_cross_tu_linkage]] for the other way a
present-and-compiling function fails to link.
