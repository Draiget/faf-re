---
name: reference-have-set-detection-gap
description: The have-set used to test "is this function recovered" matches only the 0x00XXXXXX address form, so bodies annotated purely as FUN_XXXXXXXX are invisible. Audited 2026-08-17 - real but small, 3 cases found and fixed.
metadata:
  type: reference
---

Every sweep in this repo tests recovery with

    rg -o -N --no-filename '0x00[0-9A-Fa-f]{6}' src/sdk

and turns the hits into `FUN_<ADDR>` tokens. A recovered body whose doc
block names it only as `FUN_XXXXXXXX`, with no `0x`-form address
anywhere, is therefore reported as **missing code** forever.

## Audit result (2026-08-17)

154 addresses appear in `src/sdk` only in `FUN_` form; 149 of those are
real functions in the index. Splitting them by whether the mention sits
on an `Address:` line:

  - **150 are prose-only mentions** - comments like "blocked on FUN_X",
    "see FUN_Y". Those functions are genuinely unrecovered. No action.
  - **4 sit on an `Address:` line**, and all four are already correct:
    `CDecoder.cpp:659` documents an ICF-folded triple
    (`0x006E4E90 (FUN_006E4E90 / FUN_006E4F30 / FUN_006E4FC0)`), and
    `PrefetchHandleBase.h:58` says "helper around
    FUN_004A5AA0/FUN_004A5BB0 map lanes" for `RES_FindPrefetchType`,
    whose two lanes are `std::map<string, RType*>` emissions.

So the detection gap is **real but narrow**. It cost three functions,
fixed in `9c23296`:

    0x00724920  ConstructCSquadForSerializer        CPlatoon.cpp
    0x00724910  ConstructCSquadForSerializerThunk   CPlatoon.cpp
    0x00408B00  InitializeCTaskTypeInfoStorage      CTask.cpp

The CSquad pair was the worst case: its doc text named `FUN_00724920`
in prose while no `0x` form existed in the tree at all, so it looked
like a 47-instruction gap with a clean recovered caller - a perfect
false candidate.

## How to avoid burning a batch on this

Before writing any body from a sweep hit, grep the *behaviour*, not the
address - the same rule [[project-reflected-upcast-vein]] records. For
reflection/serializer candidates specifically, grep the owning `.cpp`
for the type name plus `ForSerializer` / `Initialize` / `Register`
before concluding it is missing.

A stronger have-set would union both forms:

    0x00[0-9A-Fa-f]{6}   ->  FUN_<upper>
    FUN_00[0-9A-Fa-f]{6} ->  as-is

but note that would also swallow the 150 prose mentions of genuinely
unrecovered functions, making the pool look smaller than it is. Prefer
keeping the `0x` test and spot-checking behaviour.

## Related trap found in the same pass

`CTaskThreadConstruct::Construct` carried **three** addresses, one of
which (`0x00724910`) is really the CSquad four-argument construct
adapter - it returns `sub_724920(a4)`, which allocates a `CSquad`.
Mis-attached extra addresses on a multi-address doc block are worth
checking whenever one of them looks like a different class.
See [[project-elided-caller-false-positives]].

## Correction: prose mentions are NOT all "genuinely unrecovered"

The audit above split `FUN_`-only mentions into "4 on Address: lines" and
"150 prose-only mentions of genuinely unrecovered functions". That second
label was too strong. `a8502a0` found two functions in that bucket that
were fully implemented under intent-first names, with the `sub_` token
named in **their own** comment:

    0x00472380  IsAabbNotOutsidePlane   CGeomSolid3.cpp
    0x00472430  IsAabbFullyInsidePlane  CGeomSolid3.cpp

Re-auditing across every `.cpp` for `sub_`/`FUN_` tokens >= 20 instrs
whose `0x` form is absent gives **102 tokens**. Spot-checking says most
really are references rather than gaps, in three recognisable shapes:

  - **Pending-work lists** - `SofdecExternalStubs.cpp` enumerating the
    biggest unrecovered Sofdec functions by size.
  - **IDA-name breadcrumbs** - `CrtRuntimeHelpers.cpp` naming the CRT
    worker a wrapper forwards to.
  - **Container-emission coverage notes** - e.g. `UserUnit.cpp:2735`,
    "Source-level coverage for FUN_008B5EB0: this is the original
    `std::map::erase(iterator)` construct". Those are correct as-is;
    the container process covers them and they should NOT get an address.

The ones that *do* deserve an address are real behavioural functions
recovered under an intent-first name. The tell is a doc comment that
describes behaviour rather than listing work or naming a CRT worker.

**Practical rule:** when a candidate's `sub_` token appears in a `.cpp`
comment, read that comment before writing anything. If it says "this is
the original <container op>", skip. If it describes behaviour, the
function is already there and only the address is missing.



## 2026-08-17: this is the dominant false-positive, not a narrow one

The audit above concluded the gap was "real but narrow" and cost three
functions. That undercounts it badly. In one session, **four** of the
top-ranked closure-1 candidates were already implemented under
intent-first names:

    0x00475550  ProjectBoxOntoAxis        EntityCollisionUpdater.cpp   2eb03ba
    0x005EDCE0  LowerBoundUnitEntityById  ArmyUnitSet.cpp              c2622da
    0x004496E0  map::operator[]           CD3DSolidBatchTexture.cpp    c5ce3f1
    0x00472380  IsAabbNotOutsidePlane     CGeomSolid3.cpp              a8502a0

Every one had the profile that any "recoverable now" query sorts to the
top: a recovered caller, a closure of exactly 1, no address in the tree.
Two of them were *already called by name* from the recovered caller sitting
a few lines above them in the same file.

**Screen for it mechanically before writing.** Three checks, cheapest
first:

  1. **Body hash** - does any token sharing this candidate's
     `function_sha256` already appear in the have-set?
     See [[project-icf-twin-pool]].
  2. **Read the recovered caller's body.** If it already calls something
     by name that does what the candidate does, the candidate is that
     function. This catches the two cases above that no address search
     could.
  3. **Grep the owning subsystem for the behaviour**, not the address -
     "ProjectBox", "LowerBound", "Insert" - before concluding it is
     missing.

The variant worth naming separately: the caller may *open-code* the
operation instead of calling it, which leaves the emission genuinely
unrecovered but fixable by rewriting the caller rather than writing a new
body. See [[project-solid-texture-operator-index]].
