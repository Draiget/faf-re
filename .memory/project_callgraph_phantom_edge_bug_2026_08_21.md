---
name: project-callgraph-phantom-edge-bug-2026-08-21
description: The callgraph index (_callgraph_index.sqlite) has a real bug — functions that co-own a shared EH tail chunk get spurious mutual call_edges, making find_callers report fake callers/OK_RECOVERED_CALLER for functions with ZERO real references. Distrust callers_count=0/incoming_xrefs_count=0 tokens even when call_edges says otherwise.
metadata:
  type: project
---

Discovered 2026-08-21 investigating `FUN_00815A00` (a `Moho::SkyDome` cubemap-render candidate,
dispatched to a background agent as a "VTABLE_CONFIRMED... 3 real recovered callers" target based
on `find_callers.py` output). The agent's own independent PE byte-scan (rel32 call/jcc, rel8, and
unaligned absolute-dword sweep across every section of BOTH `bin/external/ForgedAlliance.exe` and
`bin/2025.7.1/ForgedAlliance.exe`, validated 20/20 against known-referenced control tokens) found
**zero references of any kind** to `0x00815A00` in either shipped binary. `FUN_00815A00.meta.json`
independently confirms `callers_count=0`, `incoming_xrefs_count=0`.

**Root cause**: `FUN_00815A00`'s three "callers" (`SkyDome::~SkyDome`, `OutputContext::~OutputContext`,
`EffectVariableD3D9::SetTexture1`) don't actually call it — all four functions **share ownership of
the same IDA tail chunk** at `0x00430530–0x00430564` (a shared_ptr release-on-throw EH funclet).
The callgraph exporter walks `FuncItems()` including tail chunks, so every function that shares a
tail chunk with another gets a spurious mutual call edge to/from every other co-owner — forming a
clique. This is why `find_callers` reported `verdict: OK_RECOVERED_CALLER` and `reach: yes
via=vtable depth=13` for a token that is provably dead code (a cut feature whose TU wasn't compiled
with `/Gy`, so `/OPT:REF` couldn't strip it at link time — same situation as neighbors 0x00815560,
0x00815660, 0x008157C0, 0x008168F0, 0x00816E10, which are likely equally dead).

**Detection rule going forward**: before trusting a `find_callers` verdict of `OK_RECOVERED_CALLER`
or treating any `code_callers` entry as real evidence, cross-check the CANDIDATE's own
`FUN_XXXXXXXX.meta.json` for `callers_count`/`incoming_xrefs_count`. If both are 0 despite
`call_edges` showing entries, the edges are almost certainly phantom tail-chunk artifacts — do NOT
recover the function; it may be genuinely dead/unreferenced code. A bidirectional pair (candidate
appears as both caller AND callee of the same other function) is a strong additional signal of
this bug, per the agent's finding on `FUN_008E76D0`.

**Scope of risk to this session's other work**: this bug means any `OK_RECOVERED_CALLER`/
`VTABLE_CONFIRMED` verdict produced by `find_callers.py` this entire session could theoretically be
similarly contaminated if the candidate shares a tail chunk with its claimed caller. Most of this
session's landed work used STRONGER evidence than a single-hop `find_callers` verdict (direct
source-reading of the caller's real body, confirmed vtable construction via `vt_constructed=1` +
`vptr-writers`, or citing already-established sibling patterns) — but any candidate accepted on
`find_callers` output alone without reading the caller's actual source body is at some risk. This
reinforces (does not replace) the pre-existing CLAUDE.md mandate to always read the caller's real
current body, never trust the tool's verdict as sufficient proof by itself.

**This exact task (`FUN_00815A00`) has now been independently reached by THREE separate
sessions/agents** (per the DB's pre-existing `last_worker: skydome-agent` note from an earlier run
today, plus this run) — the phantom edge keeps re-surfacing the same false candidate. Whoever owns
`skills/fa-binary-reassembly/scripts/callgraph_index.py` (or the enrichment step that populates
`call_edges`) should fix tail-chunk edge attribution: an edge should only count as real if it
originates from the OWNING function's own primary chunk, not from a shared tail chunk another
function also claims.

**How to apply**: when a `find_callers` verdict looks suspiciously convenient (a small,
well-evidenced-looking candidate with real recovered callers) but the recovery would otherwise be
easy, spend the extra 30 seconds to check the candidate's own `.meta.json` `callers_count` before
committing effort — cheap insurance against wasting a full recovery pass (or a whole background
agent dispatch) on a phantom.
