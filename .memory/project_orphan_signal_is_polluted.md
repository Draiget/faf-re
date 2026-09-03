---
name: project-orphan-signal-is-polluted
description: The [[maybe_unused]] marker is unreliable as an orphan signal - some carry it while having dozens of call sites. Sweeps that treat it as "unwired" surface false candidates and bury the real ones.
metadata:
  type: project
---

`[[maybe_unused]]` is the obvious way to find recovered-but-unwired
helpers, and it is **not trustworthy**. `ValidateIssueCommandUnits`
(0x006EECF0) carried the marker while having **22 call sites** - exactly
matching the 22 callers the binary has, so it is perfectly wired. Fixed in
`5b170d7`.

That matters beyond tidiness: an orphan sweep has to treat every
`[[maybe_unused]]` as a candidate, so stale ones dilute the signal. A
first pass over the tree returned **791** "recovered-but-orphaned helpers
whose binary callers live elsewhere", and the top hits were mostly noise
of two kinds:

  - **stale markers** - the helper is called, the attribute was never
    removed;
  - **same-TU false positives** - the sweep maps an address to the first
    file it appears in, which for a class method is the *header* (the
    declaration doc), so "defined in X.cpp, caller in X.h" looks
    cross-file but is one translation unit.

## The signal that did work

Not the marker - the **reachability**. `EnsurePtrContainerPushBackInputNotNull`
(0x004DBBC0) was genuinely unreachable: defined in `BoostWrappers.cpp`
inside `namespace boost` with **no declaration in the header**, so no
other TU could call it even though the sim driver needed exactly that
guard. That is the real shape worth hunting (`ca1d5ac`):

    recovered helper, defined in a .cpp, no header declaration,
    and a binary caller that lives in a different .cpp

The cross-TU file-private helper is already a known trap for *writing*
recoveries. This is the same trap seen from the other side - it also
silently blocks fixes, because the fix looks impossible when the helper
you need is unreachable.

## Practical

Before believing any `[[maybe_unused]]`, count call sites of the name in
its own file. Cheap, and it removes most of the noise. Do not run a
per-name `rg` across the tree for hundreds of names - it takes minutes
and times out; read each file once and count in-process.
