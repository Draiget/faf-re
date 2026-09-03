---
name: project-prop-record-layout
description: The map's prop records are msvc8::string first then VTransform; Sim::Setup carried a duplicate declaration with the fields reversed.
metadata:
  type: project
---

`LaunchInfoNew::mProps` (+0x8C) points at the map's `CWldProps` - the same
object `CWldMap` loaded, handed straight over by the session
(`CWldSession.cpp`, `newLaunchInfo->mProps = wldSession->mWldMap->mProps`). It
is an ordinary msvc8 vector header: allocator proxy at +0x00, first/last/end at
+0x04/+0x08/+0x0C.

Each entry is 0x38 bytes and the **string comes first**:

    +0x00  msvc8::string mBlueprintPath   (0x1C)
    +0x1C  VTransform    mTransform       (0x1C: Quatf orient_, Vec3f pos_)

Read straight off the `Sim::Setup` loop at 0x007447B0, which tests `_Myres` at
`+0x18` of each record and takes `_Bx` from `+0x04` - both only consistent with
the string at +0x00 - then hands `PROP_Create` the entry plus 0x1C as the
`VTransform`.

`Sim.cpp` had declared its own `SPropInfo` with the two fields in the opposite
order, so the blueprint pointer it read was really the middle of a quaternion
and the first prop on the map killed the sim thread. Fixed in `f67100f` by
deleting the duplicate and walking `CWldPropEntry` directly.

Two things worth carrying forward from that fix:

- `LaunchInfoNew::mProps` is typed `CWldProps*` now, not `void*`. A `void*`
  field that something casts on use is where duplicate layouts breed.
- `CWldProps::Load`/`Save` still read and write the transform lane by lane
  (position, then a 3x3 rotation matrix converted to/from the quaternion), which
  is what the binary does; the storage is a typed `VTransform` and the
  serialiser names its fields.
