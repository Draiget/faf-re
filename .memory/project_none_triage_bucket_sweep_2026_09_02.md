---
name: project-none-triage-bucket-sweep-2026-09-02
description: "Worked the 226-token None-blocker + 8-token triage_needed buckets. Resolved 164 (120 skip, 44 external_dependency), all correct DB reclassifications with zero src/sdk changes -- the whole pool turned out to be orphan compiler duplicates and CRT internals, not missing engine behavior. Technique: address-clustering + an automated orphan-forwarder detector script. 6 real leads flagged for a future pass."
metadata:
  type: project
---

## TL;DR

The 226 `blocker_type=None` tokens (per [[feedback_dag_blindspot_file_contention]]'s
sibling finding that most "blocked" markings are under-researched, not stuck) were
almost entirely **stale CrtRuntimeHelpers.cpp DB-integrity-revert residue**: the
2026-08-24 sweep that reverted ~1370 fake "recovered, source in CrtRuntimeHelpers.cpp"
claims back to `blocked` (see [[project-crtruntimehelpers-fake-recovery-contamination]])
never re-triaged what it reverted, so `blocker_type` stayed `None` and these tokens
just sat as noise in every subsequent DAG snapshot. Actually reading them showed they
were never real unrecovered engine functions -- they're compiler-emitted **orphan
duplicates**: thin forwarders, EH unwind funclets, and CRT/STL internals, every one of
which already has its real behavior recovered/classified at a *different* address that
DOES have live callers.

**Landed 164 of 234 candidates (70%) with zero `src/sdk` edits** -- every resolution
was a correct terminal-status classification (`skip` or `external_dependency`), not new
source, because there was no missing behavior to recover. `blocked/needs_evidence`
count dropped from 497 to 333 session-wide. Commit `fe92e341` (README.md progress
snapshot only -- `recovered_progress.json` is gitignored).

## The dominant pattern: orphan forwarder into an already-terminal target

Shape: a 2-18 instruction function that does pure argument shuffling (or nothing at
all) and tail-calls (via `call` or a `jmp`-tail-thunk) exactly one other function,
where:
- the candidate itself has **zero code_callers AND zero incoming_xrefs** anywhere in
  the binary (`callers_count=0`, `incoming_xrefs_count=0` in its own `.meta.json` --
  not just "our index missed it", IDA's own analysis found nothing either), and
- the tail-call **target** is already `recovered` or `skip` with **other, real,
  independently-recovered callers** that fully account for that operation.

Four concrete sub-families, all verified by direct `.asm` read before bulk-marking:

1. **"advance-returning `_Ufill` adapter"** (`push ecx; mov byte ptr [local],0; ...;
   call target`) -- already a named, documented shape in this project (CMauiHistogram's
   `SHistogramColumn` subsystem), just not yet applied to these specific addresses.
2. **Checked-allocator `count=1` forwarders** (`mov ecx,1; jmp allocate_slots_checked<T>`)
   -- e.g. `FUN_0089AAC0` vs. its target's real caller `FUN_0089A130`
   (`std::map<EntId,UserEntity*>::_Buynode`), which the RbTree.h citation for that
   token *already* documents as calling `FUN_0089B1A0(1u)` **inline**, byte-verified
   in the asm (`mov ecx,1; call sub_89B1A0` at the real call site) -- proving the
   standalone thunk is a redundant, never-invoked duplicate of what the real caller
   already does itself.
3. **"buy_head-init forwarder"** (`push esi; mov esi,ecx; call subX; mov[esi+4],eax;
   mov byte[eax+N],1; ...`) -- RB-tree/list head-node construction, same shape.
4. **EH unwind funclets** (`push eax; call operator delete; pop ecx; retn`, or
   `lea/mov ecx,[ebp-N]; jmp SomeClass::~SomeClass()`) and **msvc8::vector/string
   `_Tidy`-shaped teardown** (`if (begin) delete begin; zero begin/end/capacityEnd`,
   or the SBO-conditional `cmp [x+N],0x10; jb skip; delete [heapPtr]` -- verified
   against `String.h`'s real SSO threshold: `myRes<=15` is inline, `>=16=0x10` is
   heap). RULE ONE's own "compiler-emitted glue is not source at all" section covers
   EH funclets explicitly; the `_Tidy` shapes are the same idea one level up (the
   *operation* is already modeled generically, this specific out-of-line copy of it
   is just uncalled).

## Method (reusable, fast)

1. **Address-cluster the None-bucket** (or any blocker-type slice): sort by address,
   group where consecutive gaps are `<0x2000`. This immediately separates "batch of
   isolated singletons needing real research" from "coherent vein worth a pattern
   pass" -- every cluster investigated this session (sizes 2-19, about a dozen of
   them) turned out to be one homogeneous family.
2. **Read 2-3 raw `.asm` bodies per cluster** (never trust the `.c` decompile alone
   for these -- it obscures the tail-call shape). Identify the family.
3. **Extract the tail-call target, check its DB status.** If terminal
   (`recovered`/`skip`/`external_dependency`) and the candidate's own
   `callers_count`/`incoming_xrefs_count` are both 0, that's the whole evidence
   chain: the operation is covered elsewhere, this address is dead in practice.
4. **Automate once the pattern is confirmed**: `find_orphan_forwarders.py` (this
   session's script, not committed -- recipe below) scans every remaining None-bucket
   token, and flags one **only if**: `callers_count==0 AND incoming_xrefs_count==0
   AND instructions<=18 AND callees_count<=2 AND every call target is
   already-terminal AND the body contains no conditional jump** (`jz`/`jnz`/`jb`/
   etc. -- see gotcha below). One run found 57 more candidates in the same pass that
   a manual cluster-by-cluster sweep would have taken much longer to reach.
5. **Bulk-mark** with `recovered_progress.py mark` (or `bulk-mark` for a
   single-shared-note batch, e.g. the WildMagic and CRT-section groups) --
   individual `--note` per token citing the real target + its real callers is worth
   the extra calls for anything with per-token-distinct evidence; `bulk-mark` is fine
   when the whole batch shares one justification (e.g. "CRT-section address
   >=0xA80000 with NO_CALLSITE_EVIDENCE", already a 54-token precedent in this DB).

### Gotcha: exclude anything with a conditional jump before trusting the shape

Two auto-flagged candidates (`FUN_00A55150`, `FUN_009544F0`) looked like thin
forwarders by instruction count alone but had a **conditional call** gating real
logic -- both turned out to be genuine comparison/bounds-check operators, not glue.
`FUN_00A55150` specifically is part of the documented
[[project-rbtree-secure-scl-iterator-gap-2026-08-21]] family (calls `sub_A84A40`,
the `_Compat`/orphan-check debug validator, conditionally). Filtering out any body
containing a `j[a-z]+ short/loc_/locret_` before generating the candidate list is
what caught this -- **do this filtering before spot-checking, not instead of it**;
manual read-through of ~15 sample candidates (across both the pre-filter and
post-filter runs) is what found the gotcha in the first place. Don't skip the manual
verification step even when the automation looks clean.

## Real leads found, NOT landed (flagged for a future pass)

- **`FUN_00A55150`/`A552D0`/`A55670`/`A55750`/`A557A0`/`A55A50`/`A55AB0`** (7 tokens,
  cluster `0xA55150-0xA55AB0`): all call `sub_A84A40` (the `_Compat` debug
  iterator-validation helper). Direct, fresh corroboration of the existing
  [[project-rbtree-secure-scl-iterator-gap-2026-08-21]] finding ("likely affects the
  WHOLE template, not just FUN_00A52760/A52930... needs a dedicated pass"). Read
  in full: `A55150`/`A552D0`/`A55670` are `operator!=`-shaped iterator-compat
  checks; `A55750`/`A557A0` are bitset/deque-style random-access dereference with a
  word/sub-index split; `A55A50`/`A55AB0` are range-validated iterator
  constructors. All real, all currently blocked on the same missing `_Compat`
  modeling. Left `blocked`/`None` -- do not skip these, they're genuine gaps.
- **`FUN_009DEAC0`** (triage_needed): a real 112-instruction wide-char
  (UTF-16) path-parsing function (splits on `\` and `.`, calls a length-helper
  first). Its only 2 recorded callers (`FUN_009DEC10`, `FUN_009DFAE0`) are both
  marked `skip` as "exhaustively verified dead" (zero references anywhere in the PE,
  per a prior byte-scan pass). Given this function's own substance, that dead
  classification is now suspect -- dead-code elimination guarantees *something*
  reaches a 112-instruction function that survived linking. Worth re-auditing
  `FUN_009DEC10`/`FUN_009DFAE0`'s "dead" verdict before concluding this one is
  unreachable too. Did not force a resolution either way.

  **Re-audited 2026-09-02 (faf-main-f7, same session, later pass): the doubt does
  NOT hold up, `skip` stands.** Walked the FULL caller chain via `fa-find-callers`,
  one more hop than the original pass reached: `FUN_009DEC10` actually has TWO
  callers, not one (`FUN_009DFAE0` skip -- already known -- AND `FUN_009DFF60`
  skip, previously unlisted here). Continued walking: `FUN_009DFF60`'s own sole
  caller is `FUN_009E0230`, which itself has `code_callers=0` AND
  `incoming_xrefs_count=0` in its own `.meta.json` -- a genuine terminus, not
  another link. So the real chain is `FUN_009DEAC0` <- `FUN_009DEC10` <-
  `{FUN_009DFAE0, FUN_009DFF60}` <- `FUN_009E0230` <- *(nothing)*, four hops, and
  the top of it has zero evidence of any kind, matching (not contradicting) the
  original byte-scan's "dead" verdict. Also ran `audit_indirect_calls.py` across
  the whole binary looking for a missed dispatcher-table pattern that might
  explain an unindexed caller -- the top 20 "missed family" xref clusters it
  surfaced (SEH/M2 audio-codec internals, wx destructor thunks, CRT locale
  helpers) share no address-range or naming affinity with this
  `0x9DE000-0x9E0230` cluster, so nothing there explains it either. Conclusion:
  the "substantial function survived linking" intuition that motivated this lead
  was reasonable to check but doesn't pan out here -- most likely explanation is
  an editor/tool-only code path (dead-code elimination only guarantees reachability
  *from the actual shipped entry points*, and a few legitimately-orphaned
  full-featured functions from a stripped editor build are a known, if
  uncommon, shape in this binary). Leave `skip` on all four tokens; do not
  re-open this specific lead again without genuinely new evidence (a fresh IDA
  export revealing a xref none of the current tooling finds, for example).
- **`FUN_009DA620`** = `wxANIHandler::GetImageCount(wxInputStream&)` (triage_needed,
  VTABLE_CONFIRMED at `wxANIHandler::vftable+0x18`) and **`FUN_009CA100`** =
  `wxDC::GetSizeMM(int*,int*)` (triage_needed, VTABLE_CONFIRMED across the whole
  wxDC hierarchy at `+0xEC`, matches vendored `wxWidgets-2.4.2/src/common/imagbmp.cpp`
  byte-for-byte for the ANI one). Both need a new "Runtime" wrapper class
  (`wxAniHandlerRuntime`/`wxDCRuntime`) in `WxRuntimeTypes.h`/`.cpp` following the
  established `wxImageHandlerRuntime`/`wxPngHandlerRuntime`/etc. pattern --
  `WxRuntimeTypes.cpp` was **locked** by a concurrent agent all session, so these
  couldn't land. Confirms the existing note
  [[project-wxdc-regconfig-vtable-cluster-researched]]. **Caution for whoever
  picks this up**: the existing flattened `wxBmpHandlerRuntime : wxImageHandlerRuntime`
  pattern is *not* safe to copy verbatim for the ANI/ICO/CUR chain --
  `wxICOHandler` (real chain: `wxImageHandler -> wxBMPHandler -> wxICOHandler ->
  wxCURHandler -> wxANIHandler`) introduces a *new* virtual (`DoLoadFile`) not
  present in the base, which shifts absolute vtable slot offsets for everything
  declared after it. A naive flatten would silently break the `+0x18` slot math.
- **`FUN_007B0C50`** (`0x7B0C50`, cluster-adjacent to a resolved `LegacyContainerFillLanes.cpp`-predicted
  group but NOT itself glue): a real ~55-instruction SSE cubic
  spline/Bezier-style evaluator -- reads a 0x40-byte control-point struct (4x
  {x,y,z,extra} at +0x00/+0x10/+0x20/+0x30) plus 3 more 3-float vector args, blends
  by parameter `t` and its powers, writes a 3-float result. Zero callers found.
  Possibly connects to the already-open [[project-caipathspline-generate-formation-gap-resolved-not-landed]]
  or [[project-caiformationinstance-runscript-chain-mapped]] path-spline work --
  worth checking against those before independent re-investigation.

  **Checked 2026-09-02 (faf-main-f7, later pass): NOT cross-referenced in
  either path-spline note** (grepped both files for this address, zero
  hits) -- not the same lead. Re-ran `fa-find-callers`: still zero
  callers/xrefs, `NO_CALLSITE_EVIDENCE`, `UNREACHED`. `source_paths` in
  the progress DB already puts this token in
  `src/sdk/moho/containers/LegacyContainerFillLanes.cpp` -- per this
  project's own prior (pre-2026-09-01, legacy-location memory) finding on
  that specific file, 1318 of 1328 candidate tokens sourced there were
  independently confirmed dead-COMDAT with zero evidence of any kind
  (not glue-shaped, just genuinely unreferenced real bodies the linker
  kept). "Real logic, not glue" is consistent with dead-COMDAT (dead
  COMDATs are typically complete function bodies, not stub shapes) --
  does not on its own overturn that established pattern for this file.
  Leaving `blocked`/`None` rather than re-running that file's already-
  exhaustive investigation from scratch for one token; only worth
  revisiting if a FUTURE pass finds a genuinely new xref-discovery
  mechanism this project's tooling currently misses for the whole file,
  not per-token.
- **`FUN_0128C050`** (`0x128C050`): NOT CRT despite being address-huge (>18MB into
  the image) -- real ~50-instruction function with genuine `___CxxFrameHandler3_0`
  EH wiring, allocates a 0x218-byte object, does `std::string` construction, and
  calls `luaA_index` (real, recovered Lua binding). A genuine Lua-reflection-adjacent
  engine function that the naive ">=0xA80000 => CRT" heuristic would have
  misclassified if I hadn't checked its callees individually -- this is the concrete
  reason that heuristic must never be applied without checking what a candidate
  actually calls, not just its address.
- **`FUN_008B6B80`** (packs 1 register + 3 stack dwords into a 4-field/16-byte
  struct via a `this`-in-`eax` convention) and **`FUN_00946950`** (conditional
  single-virtual-call-through-optional-pointer helper, `if(*ppObj) (*ppObj)->vtbl[1]()`)
  and **`FUN_0094F430`/`FUN_0094F520`/`FUN_0094EA30`/`FUN_0094EB30`/`FUN_0094F180`**
  and **`FUN_008D9300`/`FUN_008D94B0`** (real `_memmove_s`-based erase-shift
  helpers, not glue): all zero-caller, all real small pieces of logic, none fit the
  orphan-forwarder pattern cleanly. Not investigated in depth -- left `blocked`/
  `None` for a future pass rather than force either a fabricated recovery or an
  unjustified skip.

## What's left

- **None bucket: 62 remaining** (was 226). Mix of the "real leads" above plus
  isolated singletons not yet clustered/read.
- **triage_needed: 8 remaining, unchanged count** but all 8 now have documented
  research findings above (2 wx/vtable-confirmed-but-locked, 1 real-function-
  transitively-dead-callers, 1 real-iterator-gap-family x acting as 5 more distinct
  members once the cluster was traced -- wait, the 7-member `A84A40` cluster
  overlaps with triage_needed's `FUN_009C7F70`/`FUN_00A3D540` chains too; see the
  full chase in-session for the caller-chain detail, not repeated here). None
  force-resolved -- all have a real, evidenced reason they're still open, not
  laziness.
- The **`no_block_guard.py status` blocker-type summary line reads from a cached
  DAG snapshot, not live `recovered_progress.json`** -- it did not update during
  this session despite real progress. Use direct DB queries (see recipe in
  [[project-citation-audit-2026-08-21]]-style scripts) for a live count; re-run
  `build_unrecovered_dag.py` before trusting the cached figures again.

## Script recipe (not committed -- recreate if needed)

```python
# For each blocked/None-blocker token: read its own .meta.json metrics
# (callers_count, incoming_xrefs_count, instructions, callees_count) and its
# .asm. Skip if it has any callers/xrefs of its own, is >18 instructions, calls
# more than 2 things, or contains a conditional jump. Extract every `call sub_X`
# target; require ALL of them already terminal (recovered/skip/external_dependency/
# accepted/done) in recovered_progress.json. What's left is the auto-candidate list.
```
