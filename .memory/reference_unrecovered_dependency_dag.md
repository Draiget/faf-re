---
name: reference-unrecovered-dependency-dag
description: "The bottom-up dependency DAG tool over open tokens: where it lives, what its columns mean, and the three data-quality findings it produced."
metadata:
  node_type: memory
  type: reference
---

`skills/fa-callgraph-recovery/scripts/build_unrecovered_dag.py` (+ `asm_edges.py`)
builds a verified DAG over every open token (status not `recovered`/`skip`/
`external_dependency`), condenses cycles with Tarjan, and ranks the leaves.
Documented in that skill's `SKILL.md` and `CLAUDE.md`. Run after `enrich` — it
reads `reachable` and `vtable_writers`. Outputs to
`decomp/recovery/reports/dag/`; read `unrecovered_queue.md` first.

**Do not trust the SQLite call edges.** The tool re-derives every open-set edge
by decoding `E8`/`E9` rel32 bytes from the caller's `.asm`. ~1.4% are phantom,
and dropping them cut the apparent cycle count 9 → 4. Confirms
[[reference_pe_byte_reference_scan]]. IDA function tails (EH funclets, outlined
chunks) sit outside `function_start..function_end` but their calls are real
dependencies — tag them `tail`, do not range-filter them away.

**Three findings from the first run (2026-08-20, 2494 open tokens):**

1. **Depth is not the bottleneck.** 1738 of 2494 open functions (70%) are already
   leaves with nothing open beneath them. Height histogram collapses fast (386 at
   h=1, 3 at h=7). Bottom-up ordering is real but small; the binding constraints
   are a recovered caller and a usable symbol. Only **45** are ready + wired + named.
2. **459 open tokens (18%) are IAT thunks** — body is a single
   `jmp dword ptr [__imp_*]`, proven from the encoding, not the symbol name
   (plenty of engine functions carry Win32-looking names). `external_dependency`
   by definition. List in `import_thunks.txt`. NOT bulk re-marked — that rewrites
   459 entries in a shared gitignored DB, so it needs the user's call.
3. **73 tokens carry a blocker the graph refutes** (11,690 instructions): marked
   `missing_dependency`/`owner_layout`/`thunk_target`/`triage_needed` while being
   verified leaves at 100% callee health with a recovered caller. Notes left over
   from passes that ran before their callees landed. `stale_blockers.txt`.
   Same family as [[feedback_stale_absorbed_status_pattern]].

**Caller-rule correction worth remembering:** counting all *terminal* callers as
"recovered callers" is wrong and inflates the queue badly (was 438 ready+wired,
truly 254; actionable 61 → 45; refuted blockers 227 → 73). Only status
`recovered` counts — a `skip` or `external_dependency` caller has no source to
wire a call into. The tool now reports those separately as `inert_caller_count`.

Split parallel agents by `component` (weakly-connected cluster): no call edge
crosses a boundary. But **also check patch-target files are disjoint** — cluster
85 (`CUIWorldView::HandleEvent`, 48 fns) and cluster 550 both land in
`CWldSession.cpp` despite being graph-independent.

Only direct calls are edges; virtual dispatch and Lua binder tables are invisible,
so `open_callees=0` does not prove a node reaches no open code at runtime. Read
`indirect_sites` alongside it.
