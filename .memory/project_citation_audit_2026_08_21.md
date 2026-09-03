---
name: project-citation-audit-2026-08-21
description: "Whole-tree citation audit: 5,932 of 53,657 recovered tokens (11.1%) have no Address citation anywhere in src/sdk; 139 were genuine contamination and were reverted, the rest are a status-taxonomy problem"
metadata:
  node_type: project
---

Run 2026-08-21 (batch 32). Extends
[[project-fake-recovered-status-contamination]] (which had found 192) with a
whole-tree mechanical audit.

## Method (reusable, and immune to the earlier false-positive mode)

1. Build ONE index over all of `src/sdk/**/*.{cpp,h}`:
   - every `0x` + 8 hex digits -> 54,617 distinct
   - every `FUN_` + 8 hex digits -> 47,813 distinct
2. Test every `status=recovered` token against **both** sets.

Scanning the **whole tree** rather than the file the note names is the point:
that is exactly what makes it immune to the ICF-fused-multi-address-citation
false positive that produced **54 bad reverts** in the earlier broad audit
(see [[project-rpointertype-dbintegrity-falsepositives]]).

Gotchas hit while building it: `subprocess.run` capture truncates a 79k-line
grep -- write to a file and read it back. `/tmp` in Git Bash is not Python's
`/tmp`; use the scratchpad path. And use a **quoted** heredoc (`<<'PY'`) or
backticks in the note text get shell-expanded (had to repair 139 notes).

## Result: 5,932 / 53,657 (11.1%) uncited. Three distinct groups.

| group | count | verdict |
|---|---|---|
| static-init / cleanup registrars (`register_*`) | 1,847 | **not fabrication** - compiler/linker glue with no source line |
| compiler + dtor thunks (`j_??1...`, scalar-deleting) | 1,193 | **not fabrication** - same |
| unclassified | 2,751 | needs review; sample suggests template emissions cited on a canonical under another address |
| **claims "Recovered in &lt;named file&gt;" but absent** | **138** | **genuine contamination** |
| import/IAT trampolines | 3 | not fabrication |

The 3,040 glue entries are a **status-taxonomy problem, not fraud**: RULE ONE
says these emissions map to no source line, so they should be `skip` /
`external_dependency`, not `recovered` (which implies source exists). Worth a
dedicated reclassification pass; do NOT mass-flip them as fake.

## Action taken

**139 tokens reverted to `blocked` / `needs_evidence`** (the 138 + `FUN_007B4640`,
which I hit independently while walking the HandleEvent tree). 64 + 36 of them
name `CrtRuntimeHelpers.cpp`, which exists and is 13,275 lines - so this is not
a deleted-file artifact. Hand-verified a sample plus a known-good control
(`0x005C6F90` found).

`FUN_007B4640` specifically is `std::map<unsigned, WeakPtr<UserEntity>>::_Buynode`
(16 instrs: allocate 1 node via FUN_007B4FA0, null Left/Parent/Right, `_Color=1`,
`_Isnil=0`; the null checks on `eax+4`/`eax+8` are compiler artifacts that can
never fire). It belongs as an `Address:` citation on `buy_node` in
`legacy/containers/RbTree.h`. It is on the critical path: `FUN_00870310` needs
it, and that is the last gap in the CUIWorldView::HandleEvent tree.
