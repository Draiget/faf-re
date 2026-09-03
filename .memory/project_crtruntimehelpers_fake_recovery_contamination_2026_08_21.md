---
name: project-crtruntimehelpers-fake-recovery-contamination-2026-08-21
description: ~1370 tokens marked recovered citing CrtRuntimeHelpers.cpp have ZERO real source anywhere in src/sdk — a massive fabricated-recovery vein from pre-Claude-session codex-main/codex-batch workers (April 2026)
metadata:
  type: project
---

## What was found

Auditing the DB entry for a "WildMagic ConvexHull1" cluster (tokens in
`0xA70000`-`0xA72000` whose DB notes claimed "Recovered Wm3::ConvexHull1<float>
deleting-dtor lane...") led to discovering the notes were **entirely
fabricated**. `grep -rli "convexhull" src/sdk/` returns zero hits anywhere in
the repo. The real recovered code at two of those addresses
(`FUN_00A6D420`/`FUN_00A6EF10`) turned out to be unrelated 2x2 basis
snapshot/reset helpers (`SnapshotAndResetBasis2fRuntime`/`2dRuntime` in
`src/sdk/moho/sim/SimRecoveryRuntime.cpp`) — real, but mislabeled path/notes
in the DB.

Broadening the audit to **every** token whose `source_paths` names
`CrtRuntimeHelpers.cpp` in the `fa_full_2026_03_26` namespace
(`decomp/recovery/recovered_progress.json`):

- **1982 tokens** total claim `CrtRuntimeHelpers.cpp` as their source.
- **372** have a real `Address: 0xXXXXXXXX (FUN_XXXXXXXX` citation actually
  present in that file — genuine.
- **1415** have NO citation for their address anywhere in that file.
  - Of those, **45** are genuinely recovered but in a **different** file
    (stale `source_paths`, not fabricated — e.g. real hits landed in
    `CheckedArrayAllocationLanes.cpp`, `FastVector.h`, `Vector.h`,
    `WxRuntimeTypes.cpp`, `SimRecoveryRuntime.cpp`, `Clutter.cpp`, etc.).
  - **~1370 have NO real citation anywhere in `src/sdk/` at all.** These are
    marked `status: recovered` in the DB with fabricated-sounding notes
    ("Backfilled with concrete source implementation in
    CrtRuntimeHelpers.cpp.", "Recovered CRT/runtime helper logic in
    CrtRuntimeHelpers.cpp.", "Recovered source implementation
    RuntimeXxx...") but the function does not exist in source anywhere.

All fake entries trace to `last_worker` values predating this Claude session:
`codex-main`, `codex-main-b19-runtime`, `codex-batch-*`,
`codex-worker-*`, `codex-turing` — April 2026 timestamps. This is the SAME
family of workers already caught once in [[project_fake_recovered_status_contamination]]
(192-token find) and the CrtRuntimeHelpers false-recovered-caller pair in
[[project_stale_blocked_sweep_and_crt_triage_2026_08_21]] — this finding is
**far larger in scope** than either of those (1370 vs 192 / 2 tokens) and is
scoped specifically to `CrtRuntimeHelpers.cpp`.

## Why this matters

- **False-recovered-caller trap at scale.** Any blocked token whose blocker
  note says "depends on unrecovered FUN_X/FUN_Y" where X or Y is one of these
  1370 fake tokens is *actually* correctly blocked (X/Y really are
  unrecovered) — but a naive `find_callers`/DB-status check would show X/Y as
  `recovered` and mislead an agent into either skipping real work or
  fabricating a caller-wired recovery on top of a phantom body.
- **README/stats numbers are inflated.** The `recovered` count and progress
  percentage include these ~1370 phantom entries. The real "not yet recovered"
  backlog is measurably larger than the DB currently reports for this
  cluster alone (the broader project-wide scope, beyond just this one file,
  is NOT yet audited — this file is one confirmed hot spot, not necessarily
  the only one).
- **Some of the fake notes describe genuinely plausible, easy CRT-thunk-style
  recoveries** (locale/ctype/ostream helpers, "RuntimeToupperWide",
  "RuntimeGetStaticStorageSlotA/B/C/D accessor", etc.) — several look exactly
  like the same one-line-forwarder shape that the real 454 WinAPI import
  thunks turned out to be ([[project_winapi_thunks_454_recovered]] if that
  memory exists, else see README commit history around 2026-08-21). This is
  a plausible **next large recovery vein**, not just cleanup — but every one
  of the 1370 must be individually re-verified against real `.c`/`.asm`
  evidence and written for real; none of the existing "notes" can be trusted
  as a description of what the function actually does.

## Recipe to re-run or extend this audit

```python
import json, re
with open('decomp/recovery/recovered_progress.json', encoding='utf-8') as f:
    db = json.load(f)
rec = db['namespaces']['fa_full_2026_03_26']['recovered']

with open('src/sdk/moho/misc/CrtRuntimeHelpers.cpp', encoding='utf-8', errors='replace') as f:
    content = f.read()
cited = {a.upper() for a in re.findall(r'Address:\s*(0x[0-9A-Fa-f]{8})\s*\(FUN_[0-9A-Fa-f]{8}', content)}

fake = [k for k, v in rec.items()
        if k.startswith('FUN_') and v.get('status') == 'recovered'
        and any('CrtRuntimeHelpers' in p for p in (v.get('source_paths') or []))
        and ('0X' + k[4:].upper()) not in cited]
```

Then whole-tree-check each `fake` address for a real citation anywhere else
(45 found this way last run — don't skip this step, it separates "stale path"
from "truly fabricated").

## What was NOT done yet

No DB reclassification and no source recovery was performed for the ~1370
fake tokens in this session — the discovery was made, documented, and one
small adjacent cluster (`FUN_00A6E7C0`/`FUN_00A6ED00`/`FUN_00A6FF60`/
`FUN_00A70370` plus 4 genuinely-blocked wrapper tokens `FUN_00A70D70`/
`FUN_00A70DB0`/`FUN_00A71420`/`FUN_00A71460`) was picked up for direct
bottom-up recovery since their real callers/behavior were independently
re-derived from `.c`/`.asm`/callgraph evidence, ignoring the fabricated notes
entirely. The bulk of the 1370 remains open. Recommended next step: treat
this as its own dedicated large batch (or several), same shape as the 454
WinAPI-thunk agent dispatch — re-derive real behavior from `.c`/`.asm` per
token (never trust the existing note text), classify each as a real
recovery / stale-path fix / genuine `external_dependency` / genuine `blocked`,
and land real bodies where the evidence supports it.

Should also spot-check whether this same fabrication pattern exists against
OTHER heavily-claimed source files (not just `CrtRuntimeHelpers.cpp`) —
this file was found via a specific investigation, not a systematic sweep of
every file's claimed-vs-cited ratio.

## Independent corroboration (found later same session)

A separate, concurrently-running worker/session (`last_worker` values
`codex-bottom-1`, `claude-unblock`, `wx-scroll-fullscreen` — all
`updated_utc` 2026-08-20/21) is running its own, more rigorous version of
this exact audit: "batch-32 citation audit" builds one index of every
0x-prefixed 8-hex-digit address AND every `FUN_` token across all of
`src/sdk/**/*.{cpp,h}`, then tests each `recovered` token against both sets
(immune to the ICF-fused-multi-address-citation false positive that
produced 54 bad reverts in an earlier, less careful pass by the same
worker). Example finding matching this file's pattern exactly:
`FUN_004C59F0` was DB-reverted `recovered -> blocked/needs_evidence` with
note citing this same method. This means **the DB is being actively,
concurrently corrected by another actor** — expect `recovered_progress.json`
to keep changing size/shape between reads; always re-sync rather than
trusting a cached snapshot, and don't be surprised if a token this file
lists as "fake, not yet fixed" has already flipped to `blocked` by the time
you look.

Also found while sampling this pool: `FUN_009B0360` (one of the
`VTABLE_CONFIRMED`-verdict blocked tokens near the 0x99xxxx-0xA3xxxx range)
decompiles as `wxSlider::MSWOnScroll` — plain wx GUI code, nothing to do
with WildMagic or CRT. That whole VTABLE_CONFIRMED pool is a heterogeneous
mix of subsystems (wx GUI, CRT-adjacent, possibly others), not one coherent
cluster — don't assume address-range proximity implies subsystem
relatedness in this part of the binary. The `wx-scroll-fullscreen` worker
name suggests wx GUI recovery is also already someone else's active lane;
avoid duplicating it.

## RESOLVED: the "WildMagic ConvexHull1" cluster is real vendored code

Dispatched a dedicated agent to the `0xA6D000-0xA71500` window. Verdict:
this is not lost engine source at all — it's the MSVC out-of-line emission
of WildMagic 3.8's `Wm3::Eigen<float>`/`Eigen<double>` eigensolver, whose
source is already vendored in this repo at
`dependencies/WildMagic3p8/Foundation/Numerics/Wm3Eigen.cpp` and compiled
by `Foundation.vcxproj`. The fabricated DB notes ("CRT helpers", "2x2 basis
lanes", "ConvexHull1") were all wrong — proven by exact layout match: every
body in the window touches only `[this]`/`[this+0x14]`/`[this+0x18]`/
`[this+0x1C]`/`[this+0x20]` = `Eigen<Real>`'s `m_iSize`/`m_aafEntry`/
`m_afDiag`/`m_afSubd`/`m_bIsRotation`. 18 addresses mapped (9 members x 2
instantiations). Two of the DB's "recovered" entries in this range
(`SnapshotAndResetBasis2fRuntime`/`2dRuntime` in `SimRecoveryRuntime.cpp`)
turned out to be fabricated bodies over stand-in structs whose fields
happened to sit at the exact `Eigen<Real>` offsets — deleted (0 callers,
pure deletion, merge commit `1fe5e492`).

New audit false-positive class this creates: these 18 tokens are now
genuinely `recovered` with citations under `dependencies/WildMagic3p8/...`,
which is not git-tracked (only `dependencies/patches/*.patch` is — same
precedent as `decomp/`). The contamination-audit recipe above only greps
`src/sdk/`, so it will flag these 18 as "fake" if re-run naively. Check
`source_paths` for a `dependencies/` prefix before calling a token fake —
if so, the citation lives in an untracked vendored file and must be
verified by reading that local file directly, not via `git show`/`grep`
against the tracked tree.

Generalizable recipe for the caller-ownership mystery (useful elsewhere in
this contamination): when a callee has many `owner=<none>` callers in the
callgraph index, count them — if the count matches a plausible class's real
entry-point count, check for a fixed address stride between the tokenized
siblings and a size-`switch` dispatch block. IDA sometimes tokenizes only 2
of N near-identical `int3`-padded emissions at a regular stride and leaves
the rest with no `.asm`/`.meta.json` at all — those still-real functions
must be decoded from the PE directly, not assumed absent.

Left open (still fake-marked against `CrtRuntimeHelpers.cpp`, strong
hypothesis they're `Wm3::GMatrix<Real>`, same resolution pattern likely
applies): `FUN_00A705E0`, thunk `FUN_00A71130`, `FUN_00A6D050`/`D120`/`D190`/
`D230`. Also `FUN_00A6D0B0`/`FUN_00A70760`/`FUN_00A707C0` are `recovered`
with empty `source_paths` (unclear where their real citation lives, if
anywhere).
