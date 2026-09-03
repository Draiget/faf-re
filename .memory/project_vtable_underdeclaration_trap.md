---
name: project-vtable-underdeclaration-trap
description: Recovered classes that declare binary virtuals as ordinary members send every vtable dispatch into unmapped memory; how to detect and fix it.
metadata:
  type: project
---

Two map-load crashes on 2026-08-12 were the same defect wearing different
clothes, and it is worth recognising on sight.

**The shape.** A recovered class declares its members as ordinary
(non-virtual) functions with correct addresses and correct bodies. Somewhere
else, a caller dispatches one of them through a vtable slot, because that is
what the binary does. Our object's vtable is a fraction of the real one, so
the slot index runs off the end and the call lands in whatever follows —
an unmapped page, a wild jump, a crash whose top stack frame will not
symbolise (`lua_atpanic + 4294967295 bytes` and similar nonsense).

**Case 1 (`a18c875`).** `CWldMap.cpp` carried a locally-written
`IDecalManagerRuntimeView` with four pure virtuals and a `reinterpret_cast`
from the `CDecalManager` the terrain resource actually creates. The slot
numbering in the stand-in was *right*; `CDecalManager` declared `Load`/`Save`
as ordinary members, so its real vtable was one slot long.

**Case 2 (`f13fcd8`).** `SkyDome::Load` was declared and never defined, so the
call linked through `/FORCE` and jumped to address zero-ish garbage. Same
symptom, different cause — check both.

**Detection recipe.**
1. Get the vtable head: `select to_name, to_ea from data_refs where to_name
   like '%ClassName%'` in the callgraph index — the ctor/dtor write it.
   *The `to_ea` is decimal;* converting it wrong sends you to a neighbouring
   class's table and wastes a pass.
2. Read the slots straight out of `bin/2025.7.1/ForgedAlliance.exe` (image
   base 0x400000, walk the section headers for VA→file offset) and resolve
   each entry against `functions.ea`. The table ends at the first entry that
   is not a known function.
3. Compare against the header. `CDecalManager`'s real table is **30 slots**;
   we modelled 1.

**Fixing.** MSVC assigns slots in *declaration order*, so the virtuals must be
declared in binary slot order and no slot may be skipped — a gap shifts
everything after it. Where only a prefix can be supported (bodies for later
slots not recovered yet), declare the prefix and say so in a comment, and do
not let anything dispatch the rest virtually. `CDecalManager` currently
declares slots 0–3; slots 4–29 (including `AddDecals`, `FUN_00878650`, 323
instructions) are still ordinary members.

See [[project-skirmish-load-completes]] for where this sat in the load chain.
