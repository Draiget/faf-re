---
name: reference_home_file_predictor
description: Address-locality trick that predicts which src/sdk file a blocked FUN_ belongs in, and which of those files a concurrent agent is holding.
metadata:
  type: reference
---

With 4+ agents on one checkout, the expensive mistake is picking a target whose
home file someone else is already editing (it cost two duplicate recoveries of
`FUN_008A6220` on 2026-08-20, resolved in commit `6bea0e6c`).

**Why:** the callgraph index knows nothing about file placement, and
`fa-find-callers` will happily hand you a clean-looking token that lands in a
file another agent is mid-refactor on.

**How to apply:** harvest every `0x00XXXXXX` address annotation in `src/sdk`
into an `address -> file` map (~52k anchors), then for a candidate `FUN_`, the
file owning the *nearest* annotated address is almost always its real home —
MSVC laid functions out in source order, so neighbours in the address space are
neighbours in the file. Cross it against `git status --short src/sdk` to drop
the contested ones, and group survivors by predicted file to find whole clusters
in one place.

Script kept at
`%TEMP%\claude\g--projects-faf-main\<session>\predict_home.py` (regenerate it,
it is cheap: rg the addresses, bisect for nearest, join against git status).
Distances under about 0x400 are reliable; past ~0x4000 the guess is noise.

Caveats:
- The prediction is a *neighbourhood* guess, not ownership. Reflection template
  instantiations (`gpg::RPointerType_*`, `RFastVectorType_*`) sit next to
  unrelated code and really belong in `gpg/core/reflection/Reflection.{h,cpp}`.
- A `.h` can be predicted where the body belongs in the matching `.cpp`.
- Contention moves fast — re-run `git status` right before you dispatch, not
  once at the top of the run.

Related: [[project_concurrent_commit_race_orphans_commits]],
[[project_frontier_not_exhausted_2026_08]].
