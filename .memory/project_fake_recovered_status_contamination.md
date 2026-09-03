---
name: fake-recovered-status-contamination
description: 192 tokens found marked `recovered` in recovered_progress.json with zero real implementation anywhere in src/sdk, across 4 distinct fabrication shapes (verified via whole-tree grep, never via DB status alone). Reverted to blocked 2026-08-19/20. This is a DB-wide integrity problem, NOT limited to one note pattern - only a small fraction of the DB has been audited. Read before trusting any "recovered" status you haven't independently verified.
metadata:
  type: project
---

## What was found

Tracing `CDecalBuffer`'s RB-tree chain hit `FUN_0077C5E0`/`FUN_0077C640`
(rotate helpers), marked `recovered` with `source_paths` pointing at
`CrtRuntimeHelpers.cpp` and a plausible-sounding note ("typed swizzled
RB-tree rotate helpers specialized by sentinel-byte lane") - but the address
does not appear anywhere in that file, or anywhere in `src/sdk`. A
background agent's own trace of this same chain had ALSO cited these two
(plus `FUN_0077C740`/`FUN_0077CE50`) as "confirmed present and recovered" -
it was wrong, because it trusted the DB note instead of grepping the actual
file. That's the exact false-recovered-caller trap CLAUDE.md warns about,
and it fooled an agent that was explicitly tasked with avoiding it.

Auditing every token whose note contains "codex batch"/"codex-batch"
(524 tokens) found **185 fake entries**: 156 with a real-looking
`source_paths` where the address is absent from that file (checked via
direct file read, not `rg` which can garble symbol text), and 29 with
`status=recovered` and **no** `source_paths` at all. Two more
(`FUN_0077C740`, `FUN_0077CE50`) were found with a **different, non-"codex
batch" note text** ("Mapped as alias address on canonical nil-17
tree-iterator advance helper" / "Recovered and validated against canonical
source address ownership") - proving the fabrication isn't confined to one
note fingerprint. A further token (`FUN_0077BE80`) was found with a
**completely blank** entry (`note=None`, `source_paths=None`,
`confidence=None`) despite `status=recovered` - a third shape.

A 4th shape surfaced later the same session, chasing an unrelated
`std::map<uint,WeakPtr<UserEntity>>::find` candidate: `FUN_007FDD50`
(`CWldSession.cpp:9562`) had a completely genuine-looking `Address:`/
`What it does:` doxygen block - and NO function definition after it. The
very next lines were a *different* function's doxygen and body. Grepping
the method name (`WeakSet_UserEntity::Find`) across the whole file found
nothing else. So the 4 known shapes are: (1) plausible note + wrong/absent
file citation, (2) plausible note + no citation at all, (3) a completely
blank DB entry, (4) a real-looking doxygen comment with no code behind it.
None of the four are detectable from the DB alone - each needed an actual
open-the-file check.

**Net: at least 192 confirmed fakes found this session, all reverted to
`blocked`/`needs_callsite_evidence`.** Given 4 distinct shapes were each
found by accident while chasing unrelated dependency chains, the true scope
across the whole DB (tens of thousands of tokens) is unknown and likely
larger. This was NOT a full audit - only tokens actually touched while
working other targets were checked.

## Why this matters more than any single recovery

A `recovered` status is supposed to mean "read `fa-find-callers`'s verdict,
trust `OK_RECOVERED_CALLER`, build on it." These entries make that trust
model unsafe for an unknown fraction of the DB. Any agent that filtered a
target pool by "caller status = recovered" and did NOT personally open the
caller's source file may have built on a body that was never written -
compounding the problem by producing a SECOND function that also has no
real implementation backing its claimed dependency.

## Verification recipe (fast, use before trusting ANY "recovered" caller)

```python
import json
with open('decomp/recovery/recovered_progress.json', encoding='utf-8') as f:
    db = json.load(f)
rec = db['namespaces']['fa_full_2026_03_26']['recovered']
v = rec['FUN_XXXXXXXX']
print(v.get('status'), v.get('source_paths'), v.get('note'))
```
Then **grep the address across the whole `src/sdk` tree** (not just the
claimed file - one contaminated batch cited the wrong file entirely) with
the Grep tool directly (case-insensitive), not `rg`/bash grep (output can
be garbled/redacted for symbol-shaped text per the project's own trap
notes). Zero hits + `status=recovered` = fake, revert it.

**This catches shapes 1-3 but not shape 4** (doxygen comment present, no
function body) - the address grep gets a hit on the comment itself. For
shape 4 you additionally need to confirm a real definition follows the
doxygen: read the lines immediately after the `Address:` block, or grep
the method's actual name (e.g. `ClassName::MethodName(`) rather than just
its hex address.

## Revert recipe (bulk, atomic, safe for the shared checkout)

```
python skills/fa-recovery-iteration/scripts/recovered_progress.py bulk-mark \
  --namespace fa_full_2026_03_26 \
  --functions-file <path-to-txt-list-one-token-per-line> \
  --status blocked --worker <id> --allow-missing \
  --note "DB integrity revert: marked recovered but address has zero citation anywhere in src/sdk."
```
`bulk-mark` does one DB write for the whole list (not one CLI call per
token) and auto-regenerates README.md. This is safe to run mid-session
against the shared `recovered_progress.json` other agents are also writing.

## How to apply going forward

- Before recovering ANYTHING whose evidence chain includes a "recovered"
  caller/dependency you have not personally opened in `src/sdk`, grep the
  address yourself. Do not trust `source_paths` non-empty as proof.
- If you find another fake entry, check whether its note text matches one
  of the known-bad fingerprints (`codex batch` family, "alias address on
  canonical..." family, a blank entry, or a doxygen-with-no-body) to gauge
  whether it's an isolated case or another whole contaminated batch worth
  sweeping - but sweep by grepping the ACTUAL claimed addresses/method names,
  not by trusting the note fingerprint alone (the blank-entry and
  doxygen-only shapes have no distinctive note text to fingerprint by; the
  doxygen-only shape needs a name grep, not just an address grep, since the
  address literally appears in the file - just with nothing after it).
- A full DB-wide sweep (every `recovered` token, not just ones a chain
  happens to touch) has not been done and would be high value, but is a
  large enough job (DB has many thousands of `recovered` entries) to warrant
  its own dedicated session/workflow rather than doing it inline while
  chasing an unrelated recovery target.
