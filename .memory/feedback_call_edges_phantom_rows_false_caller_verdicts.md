---
name: feedback_call_edges_phantom_rows_false_caller_verdicts
description: "The callgraph DB's call_edges table contains 224 phantom rows over 57 destination tokens whose asserted caller does not reference the callee at all. They manufacture false OK_RECOVERED_CALLER verdicts -- the trap CLAUDE.md calls the project's most expensive mistake. Detection rule + the find_callers.py fix (which lives in gitignored skills/, so it is checkout-local)."
metadata:
  type: feedback
---

## What happens

`fa-find-callers` built its `code_callers` list straight out of the
`call_edges` table with nothing corroborating it. That table carries rows whose
asserted caller contains **no reference to the callee at all**, so a token with
only phantom edges is reported as `OK_RECOVERED_CALLER` and looks like a
ready-to-land recovery target.

**Why:** recovering it would produce an orphan -- there is no call site in the
binary to wire it to. This is exactly the false-recovered-caller trap
`CLAUDE.md` names as the single most expensive mistake in this project, except
it arrives through the tooling rather than a misattached `Address:` comment.

**How to apply:** never accept `OK_RECOVERED_CALLER` on its own. Confirm the
call site exists in the disassembly before writing any code:

```bash
grep -c "<callee-addr-without-0x>" FUN_<caller>.asm     # must be > 0
```

## The worked example

`FUN_00815A00` -- three `call_edges` naming `FUN_00814CD0`, `FUN_008E76D0` and
`FUN_00944630`, all three marked `recovered`, verdict `OK_RECOVERED_CALLER`.
Grepping each caller's `FUN_*.asm` for `815A00` returns **0** in all three.
`FUN_00815A00.xrefs.txt` says `xrefs_total: 0`, and `incoming_xrefs` is empty.
The call sites do not exist.

Contrast `FUN_009894E0`, which is genuine: `incoming_xrefs` has a real row and
`FUN_004A3B50.asm` line 35 shows `0x004A3BB4: call sub_9894E0`.

## The detection rule (measured, not guessed)

On `fa_full_2026_03_26`:

- **224** edges over **57** distinct destination tokens have a destination with
  **zero** `kind='code'` rows in `incoming_xrefs`.
- **139,986 of 140,210** edges have a destination that *does* carry code
  xrefs -- so "destination has no code xref whatsoever" is specific to the bad
  rows, not a gap in the xref export.
- **88.7%** of all edges have `src_ea == the caller's start_ea`. That is the
  table's *normal* encoding, **not** the tell -- do not use it as one.

Biggest phantom clusters: `FUN_005E3E80` (68 edges), `FUN_0046D380` (24),
`FUN_007227B0` (10), `FUN_00863870` (8). Spot-checked four caller/callee pairs
against the `.asm`; all four had zero references.

## The fix, and where it lives

`skills/fa-find-callers/scripts/find_callers.py`, in `compute_verdict`: when the
target has no `incoming_code` rows, `recovered_callers` is forced to 0 and the
verdict becomes **`UNCORROBORATED_CALL_EDGE`** instead of
`OK_RECOVERED_CALLER` / `NEEDS_RECOVERED_CALLER`.

Verified: `FUN_00815A00` flips to `UNCORROBORATED_CALL_EDGE`, `FUN_009894E0`
stays `OK_RECOVERED_CALLER`, and across the whole 330-token blocked set only
the two phantom tokens change.

> **`skills/` is gitignored** (`.gitignore:34`), so this edit is **local to this
> checkout and cannot be committed**. If the tree is re-cloned it is gone --
> re-apply it from this note.

## Related state (2026-09-02)

Scanning all 330 non-terminal tokens for a landable target found **none**
available: 5 `OK_RECOVERED_CALLER`, of which two have callers in
`WxRuntimeTypes.cpp` (peer-locked), one caller is `skip`, one caller is
`recovered` with **empty `source_paths`** (the null-source-path contamination in
[[project_null_source_paths_recovered_12294]]), and one is the phantom above.
The two largest blocked clusters (80 tokens) cite
`moho/misc/CrtRuntimeHelpers.cpp`, which is **excluded from the build**.

Also: always list the full candidate set before concluding. A `head -25` on the
first scan hid three of the five `OK_RECOVERED_CALLER` tokens.
