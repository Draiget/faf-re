---
name: project-wx-library-tokens-in-queue
description: "175 blocked tokens are vendored wxWidgets 2.4.2 library code whose source is already in the repo; they are terminal leaves, but do NOT mass-flip them"
metadata:
  node_type: project
  type: project
---

Found 2026-08-21 (batch 55) while the landable queue kept surfacing
`FUN_00A09BB0`, which turned out to be wx library code.

## The finding

`rg` over blocked tokens for bodies calling two or more wx-internal symbols
(`wxGetLocale`, `wxLocale::GetString`, `wxArrayString::*`, `wxString::*`)
returns **175 tokens**. The dense ones are unmistakable -- `FUN_009DA7B0`
makes 44 wx calls, `FUN_009F8A80` 42, `FUN_009B83C0` 34.

**wxWidgets 2.4.2 is vendored with full source** at
`dependencies/wxWindows-2.4.2/src/`, including `common/fileconf.cpp` and
`common/intl.cpp`. So these bodies already have source in the repo, and
recovering them into `src/sdk` would duplicate it. The terminal-leaf rule
names wx explicitly.

Resolved one with per-token evidence: `FUN_00A09BB0` ->
`external_dependency` (calls wxGetLocale, wxLocale::GetString,
wxArrayString::Add/Empty, wxString::append/Empty).

## Do NOT mass-flip the other 174

Two reasons, both recorded elsewhere and both learned the hard way:

  1. **wx is a hybrid link** -- see [[project-wx-is-a-hybrid-link]]. 63 of 70
     wx functions examined there were defined *twice*, and "it looks like wx so
     it must be vendored" is exactly the reasoning that note warns against.
     `WxRuntimeTypes.cpp` genuinely recovers wx-shaped functions that the
     engine, not the library, defines.
  2. Batch-marking without per-token proof is the process bug CLAUDE.md calls
     out, and an earlier broad audit in this project produced 54 bad reverts
     doing precisely that ([[project-rpointertype-dbintegrity-falsepositives]]).

The right shape for a dedicated pass: for each token, check whether a matching
function exists in the vendored wx source *and* whether `WxRuntimeTypes.cpp`
already models it. Only flip where the vendored source is the real owner.
