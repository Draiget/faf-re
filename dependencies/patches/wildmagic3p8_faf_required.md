# FAF WildMagic 3.8 Patch

> **Baseline (2026-10-24).** The original Geometric Tools release of Wild Magic 3.8 (files dated 2006-01-11), published for this project as `Draiget/wild-magic-3-8`, with `wildmagic3p8_faf_required.patch` (sources) and `wildmagic3p8_faf_projects.patch` (VS2022 projects and helper tools) applied. The result is byte-identical to `dependencies/WildMagic3p8` (2,503 files); the only other file there is the build output `Foundation/vc140.pdb`.
>
> Regenerated 2026-10-24 from that original. The previous patches were cut against `WildMagic3p8.7z`, a snapshot that already contained most of these changes, and had gone stale: later edits to `Wm3Vector2.h`, `Wm3Vector3.h`, `Wm3Quaternion.h`, `Wm3AxisAlignedBox3.h` and `Foundation.vcxproj`, the new `Wm3IVector2.h`/`Wm3IVector3.h`, and comment-only FAF traceability notes in thirteen sources were in no patch.
>
> Apply from inside the dependency tree with `GIT_CEILING_DIRECTORIES` set to its parent and `git -c core.autocrlf=false apply --unsafe-paths --whitespace=nowarn <patch>`. The `-c core.autocrlf=false` matters: Git for Windows sets `core.autocrlf=true` system-wide, which rewrites the line endings of the files a patch creates, and later patches written against the real endings then fail.

This repo uses an external `WildMagic3p8` tree (Geometric Tools' Wild Magic 3.8, circa 2006). FAF reuses Wild Magic's `Foundation` math library and `Dx9Renderer` helpers, but the SDK consumer code (`src/**`) was originally hand-recovered against an FA-specific extension of `Wm3::Vector2/3`, `Wm3::Quaternion`, `Wm3::AxisAlignedBox3`, `Wm3::Box3`, and `Wm3::Sphere3`. The patch file `wildmagic3p8_faf_required.patch` re-applies those extensions on top of pristine upstream Wild Magic 3.8 so the SDK can build directly against the upstream tree instead of carrying a parallel `src/wm3/` fork.

The patch is also needed for one modern-toolchain fix in the Dx9 renderer: the `dxerr9.h` header was renamed to `DxErr.h` in the June 2010 DirectX SDK, and the upstream include no longer resolves on a current Windows SDK + DirectX install.

## Current patch scope

Patched files in `wildmagic3p8_faf_required.patch`:

- `Foundation/Approximation/Wm3ApprGaussPointsFit2.cpp`
- `Foundation/Approximation/Wm3ApprGaussPointsFit3.cpp`
- `Foundation/Containment/Wm3ContBox2.cpp`
- `Foundation/Containment/Wm3ContBox3.cpp`
- `Foundation/Distance/Wm3Distance.cpp`
- `Foundation/Distance/Wm3Distance.h`
- `Foundation/Intersection/Wm3IntrLine3Box3.cpp`
- `Foundation/Intersection/Wm3IntrSegment3Box3.cpp`
- `Foundation/Intersection/Wm3IntrSegment3Sphere3.cpp`
- `Foundation/Math/Wm3AxisAlignedBox3.h`
- `Foundation/Math/Wm3Box3.h`
- `Foundation/Math/Wm3GMatrix.inl`
- `Foundation/Math/Wm3GVector.inl`
- `Foundation/Math/Wm3IVector2.h`
- `Foundation/Math/Wm3IVector3.h`
- `Foundation/Math/Wm3Quaternion.h`
- `Foundation/Math/Wm3Quaternion.inl`
- `Foundation/Math/Wm3Sphere3.h`
- `Foundation/Math/Wm3Vector2.h`
- `Foundation/Math/Wm3Vector2.inl`
- `Foundation/Math/Wm3Vector3.h`
- `Foundation/Math/Wm3Vector3.inl`
- `Foundation/Numerics/Wm3Eigen.cpp`
- `Foundation/RationalArithmetic/Wm3TRational.inl`
- `Foundation/System/Wm3System.cpp`
- `Foundation/Terrain/Wm3ClodTerrainPage.cpp`
- `Renderers/Dx9Renderer/Wm3Dx9Utility.h`

Every modification is fenced by a `// FAF MOD:` comment block in the patched file so the FAF additions can be told apart from upstream Wild Magic source at a glance.

### Vector2 / Vector3 / Quaternion: constexpr ctors + xyz union

The default ctor and the element-wise ctor (`(Real, Real)`, `(Real, Real, Real)`, `(Real, Real, Real, Real)`) move from the corresponding `.inl` into the header as `constexpr ... noexcept` inline bodies so consumer code can write things like `constexpr Wm3::Vec3f kZero{0,0,0};`. The remaining ctors stay as out-of-line definitions in the `.inl`.

The original `private: Real m_afTuple[N];` storage member is replaced with a `public:` `union { Real m_afTuple[N]; struct { Real x[, y[, z[, w]]]; }; };` overlay. `sizeof` and binary layout are unchanged — every upstream `.inl` method that does `m_afTuple[i]` continues to work — but FAF SDK consumers can also use the field-style `v.x` / `v.y` / `v.z` / `q.w` accessors they were originally hand-written against.

A small set of static helper methods (`Zero()`, `Add(a,b)`, `Sub(a,b)`, `Scale(v,s)`, `Dot(a,b)`, `Cross(a,b)`, `Length(v)`, `LengthSq(v)`, `Normalize(v)`, `NormalizeOrZero(v)`, `LimitLengthTo(v,maxLen)`, `IsntNaN(v)`, `Compare(a,b,eps)`, `DistanceSq3D`, `DistanceSqXZ`, `Quaternion::Identity()`, `Quaternion::Multiply`, `Quaternion::MakeFromAxisAngle`, `Quaternion::ToMat3`, `Quaternion::Slerp`, `Quaternion::Nlerp`, `Quaternion::FromEulerXYZ`, etc.) is added to mirror the static-method shape consumers expect. They overload — but do not collide with — upstream's instance methods (`Length`, `Dot`, `Cross`, `Normalize`).

A handful of FAF SDK aliases are also added next to the upstream typedefs: `Vec2`/`Vec2f`, `Vec3`/`Vec3f`, and `Quat`/`Quatf`. `Vector2i`/`Vec2i` and `Vector3i`/`Vec3i` are not `Vector2<int>`/`Vector3<int>`: see the IVector section below. Two free-function helpers are added at the end of `Wm3Vector3.h` (`Wm3::Vector3fIsntNaN` and `Wm3::SqrtfBinary`, both originally recovered from the FA binary), and one at the end of `Wm3Quaternion.h` (`Wm3::MultiplyQuaternionVector`, the FA `FUN_00452D40` quaternion-vector helper).

`Vector2`, `Vector3` and `Quaternion` also get `MemberSerialize` / `MemberDeserialize` declarations, the hooks `gpg::SerSaveLoadHelper<T>` calls. The float specializations are defined in `src/moho/math/MathReflection.cpp`.

### IVector2 / IVector3: GPG's integer vectors (new files)

The FA binary has no `Wm3::Vector2<int>` or `Wm3::Vector3<int>`. Its RTTI names GPG's own `Wm3::IVector2<int>` and `Wm3::IVector3<int>`: the key of `CAiBrain::mBuildStructureMap`, the two `gpg::SerSaveLoadHelper` instantiations, and the return type in `RD3DTextureResource::SheetGetOriginalTextureDimensions`'s mangled name. `Wm3IVector2.h` / `Wm3IVector3.h` define them (x/y[/z] over an `Int[N]` union, `operator[]`, `X()`/`Y()`/`Z()`, `==`/`!=`, serialize hooks), and `Wm3Vector2.h` / `Wm3Vector3.h` include them and drop their `int` typedefs, so `Vector2i`/`Vec2i`/`Vector3i`/`Vec3i` now name the GPG types.

`IVector2::operator<` compares component by component as signed ints, the two-iteration `jl`/`jg` loop the map lower-bound walk at 0x005808D0 inlines. `Vector2<int>`'s `memcmp` ordering, which the SDK used before, sorts little-endian bytes and put the build-structure map in a different order.

### AxisAlignedBox3: typed Min/Max as Vector3<Real>

The upstream `Real Min[3]; Real Max[3];` storage is replaced with `Vector3<Real> Min; Vector3<Real> Max;`. Because `Vector3<Real>` is itself a union over `Real m_afTuple[3]` after the Vector3 patch, every `.inl` method that indexes `Min[0]`/`Max[2]` continues to work via `Vector3<Real>::operator[]`. FAF SDK consumers gain `bounds.Min.x` / `bounds.Max.z` field-style access. A two-vector brace ctor `AxisAlignedBox3(const Vector3<Real>& min, const Vector3<Real>& max)` is added so the SDK helpers that build empty/invalid sentinels via `{minVec, maxVec}` keep compiling. `MemberSerialize` / `MemberDeserialize` are declared as on `Box3`; the float specializations are in `src/moho/math/MathReflection.cpp`.

### Box3: helper API for the FAF OBB consumers

Adds the methods the FAF SDK's hand-recovered `Box3.h` exposed:

- a 5-arg ctor that takes the three extents packed into a single `Vector3<Real>`
- `GetCorners(out[8])` — alias for upstream `ComputeVertices`
- `ComputeAABB(outMin, outMax)` — derive a world-space AABB from the OBB, used by `EntityCollisionUpdater::GetBoundingBox`
- `ContainsPoint(point)` — point-in-OBB test that projects the delta onto each box axis and checks `|projection| <= half-extent`
- `MemberSerialize` / `MemberDeserialize` declarations — the float specializations are defined in `src/moho/collision/CColPrimitiveBox3f.cpp` and use the FAF reflection archives forward-declared at the top of the header (`gpg::ReadArchive` / `gpg::WriteArchive`)

### Sphere3: serialize hooks

Adds `MemberSerialize` / `MemberDeserialize` declarations on `Wm3::Sphere3<Real>` backed by FAF `gpg::ReadArchive` / `gpg::WriteArchive` forward declarations. The float specializations live in `src/moho/collision/CColPrimitiveSphere3f.cpp`.

### Wm3Dx9Utility.h: DxErr.h rename

Replaces `#include <dxerr9.h>` with `#include <DxErr.h>` (renamed in the June 2010 DirectX SDK, which was subsequently merged into the Windows SDK). Without this, the Dx9 renderer translation units won't compile against any Windows SDK shipped this decade.

## Applying it

`dependencies/WildMagic3p8` is a git submodule of `Draiget/wild-magic-3-8`, the original release. CMake configure (`cmake/FafDependencies.cmake`) applies the patches in order and records them in the tree's `.faf-patches` stamp; a changed patch re-applies on the next configure. By hand, from inside the tree with `GIT_CEILING_DIRECTORIES` set to its parent:

```bat
git -c core.autocrlf=false apply --unsafe-paths --whitespace=nowarn <repo>\dependencies\patches\wildmagic3p8_faf_required.patch
```

Add `--check --reverse` to test whether it is already applied.

Then the same for `wildmagic3p8_faf_projects.patch`. The CMake build compiles Foundation and the Dx9 renderer itself (`cmake/deps/wildmagic`); `main.vcxproj` builds them through the `ProjectReference`s the second patch adds.
