---
name: feedback_maybe_unused_is_not_orphan_evidence
description: "[[maybe_unused]] means the author expected a function might be unused - it is NOT evidence nothing calls it. Count references tree-wide before deleting. Includes the working orphan-detector script and the three collapse patterns that came out of it."
metadata:
  type: feedback
---

## The trap

`[[maybe_unused]]` is the marker this tree uses on recovered helpers with no
obvious caller, so it *looks* like an orphan flag. It is not one.

I tried to collapse all 23 `[[maybe_unused]]` functions in
`moho/particles/ParticleRenderBuckets.cpp` onto `msvc8::vector` and the compiler
rejected it: **fifteen of them are called from other functions in the same
file**. I had counted references properly for `CAniPose.cpp` one batch earlier
and then skipped the step. Reverted, re-counted, and the honest total was eight.

**Count references before deleting. Every time.**

```bash
# within a file
for n in Name1 Name2 ...; do echo "$(grep -c "\b$n\b" "$f") $n"; done | sort -n
# tree-wide (what the vptr-lane batch used)
grep -rc "\b$n\b" src/sdk --include=*.cpp --include=*.h | awk -F: '{s+=$2} END{print s}'
```

A count of **1** is definition-only. Anything higher has a caller, and that
caller has to be rewritten onto the container API first -- which is a real pass,
not a deletion.

## Finding candidates in the first place

```python
namere = re.compile(r'\[\[maybe_unused\]\].*?\b([A-Z][A-Za-z0-9_]{4,})\s*\(')
# for each .cpp: if txt.count(name) == 1 -> file-local orphan candidate
```

Run over `src/sdk/moho` + `src/sdk/gpg` (skipping peer-locked files) this found
**1123 candidates across 258 files**. Biggest: `Reflection.cpp` 74,
`WinApp.cpp` 35, `RangeExtractor.cpp` 25, `UiRuntimeTypeUpcastBridges.cpp` 23,
`PipeStream.cpp` 20. Still verify tree-wide before acting -- the script only
checks the defining file.

## The three things these turn out to be

1. **Container emissions.** `Copy*RangeAndReturnEnd`, `Fill*RangeFromPrototype`,
   `*RangeBackward`, `Destroy*Range`, `Clone*VectorStorage`. The tell is
   suffixes no human writes: `AdapterAlternateA/B/C`, `LaneA`, `DuplicateB`.
   MSVC emits one out-of-line body per instantiating context, so several bodies
   for one element type is normal. Fix: move the `Address:` onto the
   `msvc8::vector<T>` member that owns it and delete the transcription.
   (`88fdc05e` GeomCamera3 -- 17 of them.)
2. **A container's own header exposed from outside.** `PoseBoneArrayAt`,
   `StorePoseBoneEndLanePrimary`, `PoseBoneArrayCapacityFromBegin`. Fix: give
   the container real members (`size()`, `capacity()`, `operator[]`) carrying
   those addresses, and cite the raw pointer stores as the emissions they are.
   (`27d6640a` CAniPoseBoneArray -- 13 of them.)
3. **Things that correspond to no source line at all.** IDA `nullsub_*` empty
   bodies, and ctor/dtor vptr fixups (`Rebind*Vtable*Lane*`, often literally
   `return LaneA(view);`). RULE ONE names these explicitly. Fix: delete, keeping
   the addresses in one citation block so they stay traceable.
   (`de74cb9f` 8 stubs, `50c341c4` 17 vptr lanes.)

None of these should have a caller invented for them. That is the mistake the
`[[maybe_unused]]` attribute was papering over in the first place.

Related: [[feedback_no_duplicate_container_helpers]],
[[feedback_recover_input_not_compiler_output]],
[[project_orphan_debt_is_9890_functions]].
