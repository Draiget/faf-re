---
name: project-solid-texture-operator-index
description: CD3DBatchTexture::FromSolidColor hand-rolls map::operator[] as find-hint-plus-insert, so the binary's operator[] emission at 0x004496E0 has no source origin. Fix is one line but re-homes an address annotation.
metadata:
  type: project
---

`FUN_004496E0` (31 instrs) is
`std::map<uint32, weak_ptr<CD3DSolidBatchTexture>>::operator[]` - the
standard MSVC emission: inlined lower_bound, return `node + 16` on hit,
otherwise default-construct an entry through `_Insert` and return the new
slot.

Its only caller is `CD3DBatchTexture::FromSolidColor` (0x004478C0), which
**is** recovered, at
`moho/render/textures/CD3DSolidBatchTexture.cpp:396`. But the recovered
body hand-rolls what `operator[]` does:

    const SolidTextureMap::iterator hint = FindSolidTextureInsertHint(rgba);
    if (hint != SolidTextureMapEnd() && hint->first == rgba) {
      hint->second = createdTexture;
    } else {
      solidTextureMap.insert(hint, SolidTextureMap::value_type(rgba, createdTexture));
    }

The binary does one call there:

    v13 = sub_4496E0(&col);   // sSolidTextureMap[col]
    *v13 = a2;                // assign the weak handle into the slot
    v15[1] = v2;

so the faithful source is simply

    solidTextureMap[rgba] = createdTexture;

Note the lower_bound at the *front* of `FromSolidColor` (the cache-hit
probe) really is inlined in the binary - that part of the recovered body
is correct. Only the insert branch is wrong.

## LANDED c5ce3f1

Done. `solidTextureMap[rgba] = createdTexture;` replaced the branch, and
`FindSolidTextureInsertHint` + `LowerBoundSolidTextureEntry` were deleted
as the only things that served it. tucheck EXITCODE=0.

All three addresses kept a source origin: 0x004496E0 and 0x0044B070 now
come from the `operator[]` instantiation (recorded in a comment at the
call site), and 0x0044B1A0 was never at risk because
`FindSolidTextureEntry` calls `GetMapLowerBound` directly for the
cache-hit probe - which is correct, that lower_bound really is inlined in
the binary. Only the insert branch had been wrong.

## Why it was not a one-line commit

`FindSolidTextureInsertHint` is used **only** in the branch being
replaced, and it carries `Address: 0x0044B070`. That address is the
map's `_Insert` helper, which `operator[]` calls internally - so once the
source says `map[key]`, the compiler emits both 0x004496E0 and
0x0044B070 from the same instantiation and the hand-rolled helper must be
deleted, not left behind as an orphan.

So the change is: rewrite the branch, delete `FindSolidTextureInsertHint`,
and move its address record onto whatever documents the `operator[]`
instantiation. Do it with the TU build-gated - this is a live texture
cache path, not dead code.

Also check `FindSolidTextureInsertHint`'s doc line while you are there:
it says "computes insertion hint lane", but 0x0044B070 is the insert
itself. Likely a mis-attribution of the kind
[[project-elided-caller-false-positives]] records.

## The general shape

This is the [[feedback-canonical-template-helper-pattern]] case seen from
the other side: not a missing helper, but a helper written *instead of*
the container operation the binary actually used. A hand-rolled
find-then-insert always leaves the real `operator[]` emission with no
source origin. When a container emission has a recovered caller and still
looks unrecovered, read the caller for an open-coded version of the same
operation before assuming the emission is unreachable.
