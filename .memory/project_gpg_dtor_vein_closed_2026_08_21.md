---
name: project-gpg-dtor-vein-closed-2026-08-21
description: The 39-candidate gpg::-prefixed ::dtr citation-gap vein (half of the systemic ::dtr citation gap) is now fully closed.
metadata:
  type: project
---

Follow-up to the "systemic `::dtr` citation gap" finding from the 2026-08-20/21 session: 853
`recovered`-status `::dtr` tokens were audited against a full `src/sdk` address grep and 301 had
zero citation anywhere. Split: 222 `Moho::`-prefixed (dispatched to a background agent), 53
`gpg::`-prefixed (worked directly), rest wx/CRT/std-prefixed (not chased).

**Status: the `gpg::`-prefixed half is now fully closed.** Regenerated the candidate list fresh
from the callgraph DB (`function_name LIKE 'gpg::%dtr'`, cross-referenced against a fresh
`src/sdk` grep) mid-session and found 39 genuinely missing (the original ~53 estimate included
some already-fixed and a couple mis-scoped). All 39 landed as individual small commits, each
`tucheck EXITCODE=0` before commit, each address verified against its own `.c` decompiler output
first.

**Recipe validated across all 39:**
1. Regenerate the candidate list fresh each time — do not trust a stale scratchpad list, several
   addresses get fixed out from under you by concurrent agents mid-session.
2. Read the `.c` decompiler output at the exact candidate address before touching source. Every
   one of the 39 matched the identical shape: free `this+11`/`this+15` pointer pairs (or the named
   `mFields`/`mBases` `msvc8::vector` triplets when IDA recovered struct layout), reset vftable to
   `gpg::RObject::vftable`, conditional `operator delete(this)` on the scalar-deleting flag. This
   is the base `RType`'s own field/base-descriptor vector cleanup — safe to model as `= default`.
3. **Three sub-patterns, all fixed the same way (citation only, never a logic change):**
   - No dtor declared at all → add `~ClassName() override;` (or `override = default;` inline for
     `RType`-only classes with no `RIndexed`) + out-of-line `= default` definition.
   - Dtor already declared with a real `= default` body but missing its Doxygen address block
     entirely (found ×3 in `SConditionTriggerReflection.cpp`, plus
     `CAiFormationDBImplTypeInfo.cpp`) — add the comment, zero code change.
   - Second-address "vtable-slot vs atexit-thunk" duplicate — one address already cited via the
     mangled/atexit lane, the `::dtr` vtable-slot address was the uncited twin
     (`Rect2iTypeInfo`, `Rect2fTypeInfo`, `EntityCategorySetVectorReflection`).
4. **Insertion bug to watch for**: when `GetName()`'s definition already has its own Doxygen
   `/** Address: ... GetName ... */` block right above it, inserting the new dtor definition
   "before GetName" via Edit can land INSIDE that block instead of before the comment. Hit this
   twice (`CDecalTypes.cpp`, `RMeshBlueprintLODTypeInfo.cpp`,
   `ManipulatorStartupRegistrations.cpp`) — always re-read the surrounding lines after an
   out-of-line `= default` insertion near an existing commented definition; swap order if
   misplaced.
5. Two candidates needed real hunting instead of a direct grep hit: `RFastVectorType_SAniManipBinding`
   (a shallow grep found only the sibling *element* TypeInfo — the real fastvector wrapper class
   was in the SAME file, `SAniManipBindingReflection.cpp`, just missed on first read) and
   `RVectorType_EntityP`/`RVectorType_BVSet_..EntityCategoryHelper` (source comments spell them
   `RVectorType_Entity_P`/`RVectorType_BVSet_PRBlueprint` — different from the DB's
   `function_name`). When a direct name grep fails, query the DB for a sibling `GetName` address
   instead and grep for that hex address — far more reliable than name matching for these
   shortened/underscore-variant spellings.

**How to apply:** the `Moho::`-prefixed half (222 candidates, originally in a scratchpad file
`dtr_missing_moho.txt`, worked by a separate background agent in parallel this session) uses the
identical per-candidate recipe above. Re-verify any cached candidate list is still current before
trusting it — concurrent agents fix items out from under a stale list.

Multiple agents worked this same general area concurrently this session with zero file
collisions, because the `Moho::` half and `gpg::` half live in almost entirely disjoint subsystem
files.
