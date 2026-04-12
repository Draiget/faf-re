# FAF WildMagic 3.8 Patch

This repo uses an external `WildMagic3p8` tree (Geometric Tools' Wild Magic 3.8,
circa 2006). FAF reuses Wild Magic's `Foundation` math library and `Dx9Renderer`
helpers, but the SDK consumer code (`src/sdk/**`) was originally hand-recovered
against an FA-specific extension of `Wm3::Vector2/3`, `Wm3::Quaternion`,
`Wm3::AxisAlignedBox3`, `Wm3::Box3`, and `Wm3::Sphere3`. The patch file
`wildmagic3p8_faf_required.patch` re-applies those extensions on top of pristine
upstream Wild Magic 3.8 so the SDK can build directly against the upstream tree
instead of carrying a parallel `src/sdk/wm3/` fork.

The patch is also needed for one modern-toolchain fix in the Dx9 renderer: the
`dxerr9.h` header was renamed to `DxErr.h` in the June 2010 DirectX SDK, and
the upstream include no longer resolves on a current Windows SDK + DirectX
install.

## Current patch scope

Patched files in `wildmagic3p8_faf_required.patch`:

- `Foundation/Math/Wm3AxisAlignedBox3.h`
- `Foundation/Math/Wm3Box3.h`
- `Foundation/Math/Wm3Quaternion.h`
- `Foundation/Math/Wm3Quaternion.inl`
- `Foundation/Math/Wm3Sphere3.h`
- `Foundation/Math/Wm3Vector2.h`
- `Foundation/Math/Wm3Vector2.inl`
- `Foundation/Math/Wm3Vector3.h`
- `Foundation/Math/Wm3Vector3.inl`
- `Renderers/Dx9Renderer/Wm3Dx9Utility.h`

Every modification is fenced by a `// FAF MOD:` comment block in the patched
file so the FAF additions can be told apart from upstream Wild Magic source at
a glance.

### Vector2 / Vector3 / Quaternion: constexpr ctors + xyz union

The default ctor and the element-wise ctor (`(Real, Real)`, `(Real, Real, Real)`,
`(Real, Real, Real, Real)`) move from the corresponding `.inl` into the header
as `constexpr ... noexcept` inline bodies so consumer code can write things like
`constexpr Wm3::Vec3f kZero{0,0,0};`. The remaining ctors stay as out-of-line
definitions in the `.inl`.

The original `private: Real m_afTuple[N];` storage member is replaced with a
`public:` `union { Real m_afTuple[N]; struct { Real x[, y[, z[, w]]]; }; };`
overlay. `sizeof` and binary layout are unchanged — every upstream `.inl` method
that does `m_afTuple[i]` continues to work — but FAF SDK consumers can also use
the field-style `v.x` / `v.y` / `v.z` / `q.w` accessors they were originally
hand-written against.

A small set of static helper methods (`Zero()`, `Add(a,b)`, `Sub(a,b)`,
`Scale(v,s)`, `Dot(a,b)`, `Cross(a,b)`, `Length(v)`, `LengthSq(v)`,
`Normalize(v)`, `NormalizeOrZero(v)`, `LimitLengthTo(v,maxLen)`, `IsntNaN(v)`,
`Compare(a,b,eps)`, `DistanceSq3D`, `DistanceSqXZ`, `Quaternion::Identity()`,
`Quaternion::Multiply`, `Quaternion::MakeFromAxisAngle`, `Quaternion::ToMat3`,
`Quaternion::Slerp`, `Quaternion::Nlerp`, `Quaternion::FromEulerXYZ`, etc.) is
added to mirror the static-method shape consumers expect. They overload — but
do not collide with — upstream's instance methods (`Length`, `Dot`, `Cross`,
`Normalize`).

A handful of FAF SDK aliases are also added next to the upstream typedefs:
`Vector2i`/`Vec2`/`Vec2f`/`Vec2i`, `Vector3i`/`Vec3`/`Vec3f`/`Vec3i`, and
`Quat`/`Quatf`. Two free-function helpers are added at the end of
`Wm3Vector3.h` (`Wm3::Vector3fIsntNaN` and `Wm3::SqrtfBinary`, both originally
recovered from the FA binary), and one at the end of `Wm3Quaternion.h`
(`Wm3::MultiplyQuaternionVector`, the FA `FUN_00452D40` quaternion-vector
helper).

### AxisAlignedBox3: typed Min/Max as Vector3<Real>

The upstream `Real Min[3]; Real Max[3];` storage is replaced with
`Vector3<Real> Min; Vector3<Real> Max;`. Because `Vector3<Real>` is itself a
union over `Real m_afTuple[3]` after the Vector3 patch, every `.inl` method that
indexes `Min[0]`/`Max[2]` continues to work via `Vector3<Real>::operator[]`. FAF
SDK consumers gain `bounds.Min.x` / `bounds.Max.z` field-style access. A
two-vector brace ctor `AxisAlignedBox3(const Vector3<Real>& min, const
Vector3<Real>& max)` is added so the SDK helpers that build empty/invalid
sentinels via `{minVec, maxVec}` keep compiling.

### Box3: helper API for the FAF OBB consumers

Adds the methods the FAF SDK's hand-recovered `Box3.h` exposed:

- a 5-arg ctor that takes the three extents packed into a single `Vector3<Real>`
- `GetCorners(out[8])` — alias for upstream `ComputeVertices`
- `ComputeAABB(outMin, outMax)` — derive a world-space AABB from the OBB,
  used by `EntityCollisionUpdater::GetBoundingBox`
- `ContainsPoint(point)` — point-in-OBB test that projects the delta onto each
  box axis and checks `|projection| <= half-extent`
- `MemberSerialize` / `MemberDeserialize` declarations — the float
  specializations are defined in
  `src/sdk/moho/collision/CColPrimitiveBox3f.cpp` and use the FAF reflection
  archives forward-declared at the top of the header
  (`gpg::ReadArchive` / `gpg::WriteArchive`)

### Sphere3: serialize hooks

Adds `MemberSerialize` / `MemberDeserialize` declarations on `Wm3::Sphere3<Real>`
backed by FAF `gpg::ReadArchive` / `gpg::WriteArchive` forward declarations.
The float specializations live in
`src/sdk/moho/collision/CColPrimitiveSphere3f.cpp`.

### Wm3Dx9Utility.h: DxErr.h rename

Replaces `#include <dxerr9.h>` with `#include <DxErr.h>` (renamed in the June
2010 DirectX SDK, which was subsequently merged into the Windows SDK). Without
this, the Dx9 renderer translation units won't compile against any Windows SDK
shipped this decade.

## Manual steps

This patch assumes you already have a pristine Wild Magic 3.8 tree on disk.
Wild Magic 3.8 is no longer hosted by Geometric Tools, and the
`WildMagicInstaller.exe` shipped under `dependencies/WildMagic3p8/` is only a
~287 KB network-install stub from the original Geometric Tools download
mirror — it does not contain an embedded payload and the upstream URL it tried
to fetch from is dead. There is no automated bootstrap script.

1. Obtain a pristine Wild Magic 3.8 source tree from your own archive (or from
   an existing checkout) and place it at
   `dependencies/WildMagic3p8/`. The tree must contain `Foundation/Math/`,
   `Renderers/Dx9Renderer/`, and the upstream `*_VC80.vcproj` files at minimum.

2. Apply the patch from inside that tree:

```bat
git -C "<path to dependencies\WildMagic3p8>" apply "<path to this repo>\\dependencies\\patches\\wildmagic3p8_faf_required.patch"
```

   If the target tree is not a git checkout, use a portable patch tool instead:

```bat
patch -p1 -d "<path to dependencies\WildMagic3p8>" < "<path to this repo>\\dependencies\\patches\\wildmagic3p8_faf_required.patch"
```

3. Build via the FAF-side `Foundation.vcxproj` / `Dx9Renderer.vcxproj`
   project files that already live next to the upstream `*_VC80.vcproj`s under
   `dependencies/WildMagic3p8/`. Those `.vcxproj`s are tracked separately from
   this patch — they are not upstream Wild Magic files and so do not belong in
   the patch payload.

## Notes on the pristine reconstruction

Because there is no upstream baseline tree under version control to diff
against, the pristine form for each patched file was reconstructed by removing
the FAF additions in place. The reconstruction is high-confidence for every
file because:

- every FAF modification is cleanly fenced with a `// FAF MOD:` comment block
- the `.inl` files for `Wm3AxisAlignedBox3` are unmodified, so the upstream
  member naming (`Min` / `Max` rather than `m_afMin` / `m_afMax`) is directly
  observable from the `Min[0] = fXMin;` lines in `Wm3AxisAlignedBox3.inl`
- every other Wild Magic 3.8 vector/quaternion class follows an identical
  layout convention (default ctor + element-wise ctor declared in the header,
  defined in the `.inl`; private `Real m_afTuple[N]` storage; comparison helper
  declared just above the storage in a `private:` block) which the
  reconstruction reproduces exactly

The single low-confidence detail is the body of the upstream default `Vector2`
/ `Vector3` ctor (the `.inl` reconstruction uses `// the vector is
uninitialized` matching upstream's commented-out behavior, but the exact
comment text in the original 3.8 release is not preserved in any binary
evidence available to FAF). This affects only a single `.inl` comment line per
file and has no effect on generated code.
