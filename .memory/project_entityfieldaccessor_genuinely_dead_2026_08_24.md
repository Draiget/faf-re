---
name: entityfieldaccessor-genuinely-dead-2026-08-24
description: LegacyContainerFillLanes.cpp triage cluster #2 (EntityFieldAccessorRuntimeView, 7 wrapper fns FUN_005795D0/E0/F0/579600/610/630/660) was field-for-field correct against Entity.h/Unit.h but had ZERO callers anywhere - not src/sdk, not IDA's own .xrefs.txt (code=0/data=0), not the callgraph index, not a raw absolute-address byte scan of the complete shipped ForgedAlliance.exe. Deleted + marked skip 19b0f065. Records the byte-scan technique and the "whole-TU linked without /Gy" explanation for genuinely dead code surviving /OPT:REF.
metadata:
  type: project
---

## What was checked (cluster #2 from legacycontainerfilllanes_triage.md)

`EntityFieldAccessorRuntimeView` (was `src/sdk/moho/containers/LegacyContainerFillLanes.cpp`
~line 5585) reached into `Moho::Entity`/`Moho::unit::Unit` via 7 raw offsets:
coord-node link@0x60, id_@0x68, blueprint@0x6C, dead flag@0x99, army@0x14C,
destroy-queued flag@0x1B9, `Unit::AiBuilder`@0x554. Every offset matched the
real, already-typed, `static_assert`-verified field in `Entity.h`
(~2767-2802) / `Unit.h` (`AiBuilder` at line 2160, `sizeof(Unit)==0x6A8` at
2234) exactly - the triage survey's field identification was correct.

The 7 wrapper functions built on it were each read from their decompiled
`.c` export: single 1-3 instruction bodies (`mov eax,[ecx+N]; retn` shape, or
a `(output,source)` copy-out variant for the id_ getter).

## The caller search (all five layers, all zero)

1. `Grep` for each of the 7 function names across all of `src/sdk` -> zero
   hits outside their own definitions (they're anonymous-namespace-local
   anyway, so this was expected, but confirms nothing else in the file calls
   them either).
2. Each `FUN_*.xrefs.txt` in `decomp/recovery/disasm/fa_full_2026_03_26/` -
   `xrefs_total: 0`, `xrefs_code: 0`, `xrefs_data: 0` for all 7, straight
   from IDA's own analysis (not our index - IDA itself found nothing).
3. `_callgraph_index.sqlite` `incoming_xrefs` table, queried directly by
   `target_token` - zero rows for all 7.
4. `fa-find-callers` - `verdict: NO_CALLSITE_EVIDENCE`, `reach: UNREACHED`
   for all 7 (2 of them have `icf_twins` but those are byte-coincidental:
   `mov eax,[ecx+108]; retn` is identical machine code for ANY class with a
   4-byte field at that offset, not evidence of a shared logical function).
5. **Raw PE byte scan** (new technique, not previously documented in
   `.memory/`): parsed `bin/2025.7.1/ForgedAlliance.exe`'s PE section table,
   then searched the ENTIRE file (every section: `.text`, `PSFD00`,
   `.rdata`, `.data`, `.tls`, `.rsrc`, `.exxt`) for each target address as a
   little-endian `<I` dword. Zero occurrences for all 7 addresses anywhere
   in the file. This rules out both an IDA-missed data-table/jump-table
   entry (which would need the raw address bytes to exist *somewhere*, code
   xref or not) and a missed direct call/jmp (relative call encoding
   doesn't need the absolute address as bytes, but IDA's own disassembly
   pass would still have generated a code xref for that, which step 2
   already ruled out).

```python
import struct
path = 'bin/2025.7.1/ForgedAlliance.exe'
data = open(path, 'rb').read()
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
opt_hdr_off = pe_off + 24
image_base = struct.unpack_from('<I', data, opt_hdr_off + 28)[0]
num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]
sec_table_off = opt_hdr_off + opt_hdr_size
sections = []
for i in range(num_sections):
    off = sec_table_off + i*40
    name = data[off:off+8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, off+8)
    sections.append((name, vaddr, vsize, rawptr, rawsize))
pattern = struct.pack('<I', target_va)
idx = data.find(pattern)  # -1 if truly nowhere in the file
```

## Why this can happen despite "no orphan functions in this binary"

CLAUDE.md's dead-code-elimination doctrine (RULE TWO) is about `/OPT:REF`
folding whole COMDAT sections. `/OPT:REF` only strips at *function*
granularity when the TU was compiled with `/Gy` (function-level linking).
For a 2007 MSVC8 codebase it's entirely plausible not every TU used `/Gy` -
if this `.obj` had even one other symbol genuinely referenced, the WHOLE
object file (including these dead trivial getters) gets pulled into the
final image together. That is the most likely explanation for real,
correctly-decompiled, non-misclassified machine code that is nonetheless
unreferenced by anything, anywhere, in the shipped binary.

This is a **distinct failure mode** from every previously-recorded
`project_fake_recovered_status_contamination.md` shape (wrong-file citation,
no citation, blank entry, doxygen-with-no-body) - those were fabricated
recoveries with nothing real behind them. This is the opposite: a
genuinely-correct recovery of a genuinely-dead function. Both end up
needing the same fix (don't leave it as `recovered` in `src/sdk/**`), but
the diagnosis and the terminal status differ (`skip` here, not `blocked`/
revert).

## Resolution (commit 19b0f065)

Deleted `EntityFieldAccessorRuntimeView` and all 7 wrappers from
`LegacyContainerFillLanes.cpp` (RULE ONE forbids the reach-in struct
regardless of caller status; the source-level invocation rule forbids
keeping a function with zero possible callers). `CopyWordToOutput` (the
shared 2-line helper one of the 7 called) was kept - it has ~14 other real
call sites in the same file. Marked all 7 tokens `skip` in
`recovered_progress.json` with the full evidence chain in the note. Full
writeup in
`decomp/recovery/reports/by-source/src/sdk/moho/containers/LegacyContainerFillLanes.cpp.reconstruction.md`
(gitignored, local only).

## Applying this elsewhere

If a future cluster in this same file (or anywhere) has a struct whose
field identification checks out field-for-field against a real recovered
class, but `fa-find-callers` reports `NO_CALLSITE_EVIDENCE`/`UNREACHED`,
don't stop at the callgraph index - it can genuinely be incomplete for
EXE-vs-DLL reasons (no `.reloc` section means IDA has to heuristically spot
data-embedded function pointers rather than reading them off a relocation
table). Run the raw byte scan above before concluding "the index missed
it" vs. "this is genuinely dead". Only after ALL FIVE layers come back
empty is `skip` the honest terminal status - a single empty layer is not
enough given RULE TWO's presumption that a reference exists.
