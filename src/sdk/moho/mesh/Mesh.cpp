#include <cstdio>
#include "Mesh.h"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <set>
#include <stdexcept>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/audio/AudioEngine.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector4f.h"
#include "moho/math/VMatrix4.h"
#include "moho/mesh/MeshBatch.h"
#include "moho/mesh/ShaderDictionary.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/Shadow.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaterSurface.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/gal/Matrix.h"
#include "gpg/gal/MeshFormatter.h"
#include "gpg/core/utils/Logging.h"
#include "moho/render/d3d/CD3DRenderTarget.h"

extern "C" int FafProbeFrameSeq(); extern "C" int FafProbeFrameDiag(); // TEMPORARY PROBE (do not commit)
namespace { // TEMPORARY PROBE (do not commit)
  // TEMPORARY PROBE (do not commit): describe a native IDirect3DTexture9 (level 0).
  void ProbeLogTextureDesc(const char* const tag, IDirect3DTexture9* const nativeTexture)
  {
    if (nativeTexture == nullptr) { gpg::Warnf("[TEXDESC] %s native=null", tag); return; }
    D3DSURFACE_DESC desc{};
    const HRESULT hr = nativeTexture->GetLevelDesc(0U, &desc);
    const DWORD levels = nativeTexture->GetLevelCount();
    gpg::Warnf("[TEXDESC] %s native=%p hr=%08lX fmt=%u type=%u usage=%08lX pool=%u %ux%u levels=%lu",
               tag, static_cast<void*>(nativeTexture), static_cast<unsigned long>(hr), static_cast<unsigned>(desc.Format),
               static_cast<unsigned>(desc.Type), static_cast<unsigned long>(desc.Usage), static_cast<unsigned>(desc.Pool),
               desc.Width, desc.Height, static_cast<unsigned long>(levels));
  }

  // TEMPORARY PROBE (do not commit): the native texture behind a gal texture,
  // or null when it is not a D3D9 one (these probes only speak D3D9).
  IDirect3DTexture9* ProbeNativeTexture1(gpg::gal::Texture* const texture)
  {
    const auto* const d3d9 = dynamic_cast<const gpg::gal::TextureD3D9*>(texture);
    return d3d9 != nullptr ? d3d9->GetTexture1() : nullptr;
  }
  // TEMPORARY PROBE (do not commit): the native texture behind a gal texture,
  // or null when it is not a D3D9 one (these probes only speak D3D9).
  IDirect3DVolumeTexture9* ProbeNativeTexture3(gpg::gal::Texture* const texture)
  {
    const auto* const d3d9 = dynamic_cast<const gpg::gal::TextureD3D9*>(texture);
    return d3d9 != nullptr ? d3d9->GetTexture3() : nullptr;
  }
}
namespace moho
{
  static int gPropSeen = 0, gPropLod = 0, gPropFrustum = 0, gPropPushed = 0; // TEMPORARY PROBE (do not commit)

  class IWldTerrainRes;

  [[nodiscard]] float REN_GetSimDeltaSeconds();

  // Active render-time terrain resource accessor (defined in WxRuntimeTypes.cpp,
  // 0x007FA170) — returns `sWldMap->mTerrainRes` or nullptr when no map/terrain.
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();
}

namespace moho
{
  float ren_MeshDissolve = 0.0f;
  float ren_MeshDissolveCutoff = 0.0f;

  // Mesh-pass inclusion flags read by MeshRenderer::Batch. Byte-verified
  // defaults from ForgedAlliance.exe: ?ren_MeshSkinned@Moho@@3_NA = 1 and
  // ?ren_MeshStatic@Moho@@3_NA = 1 (both `bool`, .data VA 0xF57E56/0xF57E57).
  bool ren_MeshSkinned = true;
  bool ren_MeshStatic = true;

  // Shadow depth bias read by MeshRenderer::ConfigureShader's shadow lane
  // (?ren_ShadowBias@Moho@@3MA). Byte-verified default from ForgedAlliance.exe:
  // .data VA 0x00F57DFC = 0.005f.
  float ren_ShadowBias = 0.005f;

  /**
   * Address: 0x007E5150 (FUN_007E5150, boost::shared_ptr_MeshMaterial::shared_ptr_MeshMaterial)
   *
   * What it does:
   * Constructs one `shared_ptr<MeshMaterial>` from one raw material pointer
   * lane.
   */
  boost::shared_ptr<MeshMaterial>* ConstructSharedMeshMaterialFromRaw(
    boost::shared_ptr<MeshMaterial>* const outMaterial,
    MeshMaterial* const material
  )
  {
    return ::new (outMaterial) boost::shared_ptr<MeshMaterial>(material);
  }

  /**
   * Address: 0x007E5420 (FUN_007E5420, boost::shared_ptr_Mesh::shared_ptr_Mesh)
   *
   * What it does:
   * Constructs one `shared_ptr<Mesh>` from one raw mesh pointer lane.
   */
  boost::shared_ptr<Mesh>* ConstructSharedMeshFromRaw(
    boost::shared_ptr<Mesh>* const outMesh,
    Mesh* const mesh
  )
  {
    return ::new (outMesh) boost::shared_ptr<Mesh>(mesh);
  }

  /**
   * Address: 0x007E6280 (FUN_007E6280, boost::shared_ptr_MeshBatch::shared_ptr_MeshBatch)
   *
   * What it does:
   * Constructs one `shared_ptr<MeshBatch>` from one raw batch pointer lane.
   */
  boost::shared_ptr<MeshBatch>* ConstructSharedMeshBatchFromRaw(
    boost::shared_ptr<MeshBatch>* const outBatch,
    MeshBatch* const batch
  )
  {
    return ::new (outBatch) boost::shared_ptr<MeshBatch>(batch);
  }

  /**
   * Address: 0x007E6CE0 (FUN_007E6CE0)
   *
   * What it does:
   * Refreshes interpolation state and copies `MeshInstance::curPose` into one
   * shared-pose out lane while retaining the copied control block.
   */
  boost::shared_ptr<CAniPose>* CaptureMeshInstanceCurrentPose(
    boost::shared_ptr<CAniPose>* const outPose,
    MeshInstance* const meshInstance
  )
  {
    if (outPose == nullptr || meshInstance == nullptr) {
      return outPose;
    }

    meshInstance->UpdateInterpolatedFields();
    *outPose = meshInstance->curPose;
    return outPose;
  }

  /**
   * Address: 0x007E6D20 (FUN_007E6D20, sub_7E6D20)
   *
   * IDA signature:
   * float *__usercall sub_7E6D20@<eax>(float *result@<eax>, float *a2@<ecx>);
   *
   * What it does:
   * Copies one whole 4x4 transform, element by element, and returns the
   * destination. MSVC emitted the `VMatrix4` copy assignment out of line for the
   * two batch-fill call sites (`HardwareMeshBatch::FillBatch`, 0x007E7EA0), which
   * stage a per-instance transform into an unaligned vertex record; the sixteen
   * scalar stores are what that emission looks like.
   */
  VMatrix4* CopyTransform4x4(VMatrix4* const destination, const VMatrix4& source)
  {
    for (std::size_t row = 0; row < 4; ++row) {
      destination->r[row].x = source.r[row].x;
      destination->r[row].y = source.r[row].y;
      destination->r[row].z = source.r[row].z;
      destination->r[row].w = source.r[row].w;
    }

    return destination;
  }

  // Two dead reach-in lanes and their view structs used to live here.
  // 0x0086AF80 and 0x0086AFC0 both read the owning object through a
  // a deleted overlay whose only member sat at +0x34 -- which is
  // exactly `CUIWorldMesh::mMeshInstance`. They are `CUIWorldMesh` accessors,
  // not free functions over an offset struct, and they now live there as
  // `GetWorldSphere` / `GetWorldBounds` against real `Wm3::Sphere3f` and
  // `Wm3::AxisAlignedBox3f` (spatial locality agrees: both predict
  // `moho/ui/CUIWorldMesh.cpp`). The sphere/bounds view structs they copied
  // into were stand-ins for those same Wm3 types.
  //
  // 0x004FE260 went with them: it expanded one of those sphere views into one
  // of those bounds views, so it has no reason to exist once both are real Wm3
  // types. Nothing in the tree referenced any of the three -- each was counted
  // with `grep -rc` across `src/sdk`, and all three report `xrefs_total: 0`
  // with no code, data, vtable or RTTI reference in the binary either.


  /**
   * Address: 0x007E51E0 (FUN_007E51E0, boost::shared_ptr_MeshBatch::operator=)
   *
   * What it does:
   * Rebinds one `shared_ptr<MeshBatch>` from a raw batch pointer and releases
   * the previous ownership lane.
   */
  boost::shared_ptr<MeshBatch>* AssignSharedMeshBatchFromRaw(
    boost::shared_ptr<MeshBatch>* const outBatchHandle,
    MeshBatch* const batch
  )
  {
    outBatchHandle->reset(batch);
    return outBatchHandle;
  }

  // The shard/map/database types that used to be defined here now live in
  // moho/mesh/SpatialDb.h, so the owners that embed a SpatialDB<T> by value
  // can see its layout. Their bodies stay in this file.
} // namespace moho

namespace
{
  [[nodiscard]] float NanValue() noexcept
  {
    return std::numeric_limits<float>::quiet_NaN();
  }

  [[nodiscard]] bool FloatEqual(const float lhs, const float rhs) noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] bool Vec3EqualExact(const Wm3::Vec3f& lhs, const Wm3::Vec3f& rhs) noexcept
  {
    return FloatEqual(lhs.x, rhs.x) && FloatEqual(lhs.y, rhs.y) && FloatEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] bool QuatEqualExact(const Wm3::Quatf& lhs, const Wm3::Quatf& rhs) noexcept
  {
    return FloatEqual(lhs.w, rhs.w) && FloatEqual(lhs.x, rhs.x) && FloatEqual(lhs.y, rhs.y) && FloatEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] float Clamp01(const float value) noexcept
  {
    return std::clamp(value, 0.0f, 1.0f);
  }

  constexpr std::uint32_t kSpatialEntityTypeUnit = 0x00000100u;
  constexpr std::uint32_t kSpatialEntityTypeProjectile = 0x00000400u;
  constexpr std::uint32_t kSpatialEntityTypeProp = 0x00000200u;
  constexpr std::uint32_t kSpatialEntityTypeEntity = 0x00000800u;
  constexpr std::int32_t kSpatialShardSlotCount = 16;
  constexpr std::int32_t kSpatialShardGridDimension = 4;
  constexpr std::int32_t kSpatialShardLevelSmall = 1;
  constexpr std::int32_t kSpatialShardLevelMedium = 2;
  constexpr std::int32_t kSpatialShardLevelLarge = 3;
  constexpr std::int32_t kSpatialShardLevelSmallThreshold = 0x100;
  constexpr std::int32_t kSpatialShardLevelMediumThreshold = 0x400;
  constexpr std::int32_t kSpatialShardCellSizeByLevel[4] = {
    16,   // index 0 (unused by shard constructors)
    64,   // index 1
    256,  // index 2
    1024, // index 3
  };

  [[nodiscard]] std::uint32_t EntityTypeBits(const moho::EEntityType type) noexcept
  {
    return static_cast<std::uint32_t>(type);
  }

  template <class T>
  [[nodiscard]] bool SpatialShardHasNoRequestedType(const moho::SpatialShard<T>& shard, const moho::EEntityType type) noexcept
  {
    return shard.CountType(type);
  }

  template <class T>
  [[nodiscard]] bool SpatialShardDataHasNoRequestedType(
    const moho::SpatialShardData<T>& data,
    const moho::EEntityType type
  ) noexcept
  {
    return moho::SpatialShardData<T>::HasType(&data, type);
  }

  [[nodiscard]] bool AxisAlignedBoxContains(
    const Wm3::AxisAlignedBox3f& outerBounds,
    const Wm3::AxisAlignedBox3f& innerBounds
  ) noexcept
  {
    return outerBounds.Min.x <= innerBounds.Min.x && innerBounds.Max.x <= outerBounds.Max.x &&
      outerBounds.Min.y <= innerBounds.Min.y && innerBounds.Max.y <= outerBounds.Max.y &&
      outerBounds.Min.z <= innerBounds.Min.z && innerBounds.Max.z <= outerBounds.Max.z;
  }

  [[nodiscard]] bool SolidContainsAabb(const moho::CGeomSolid3& solid, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    for (const Wm3::Plane3f& plane : solid.planes_) {
      const float supportX = std::signbit(plane.Normal.x) ? bounds.Min.x : bounds.Max.x;
      const float supportY = std::signbit(plane.Normal.y) ? bounds.Min.y : bounds.Max.y;
      const float supportZ = std::signbit(plane.Normal.z) ? bounds.Min.z : bounds.Max.z;

      const float signedDistance =
        (plane.Normal.x * supportX) + (plane.Normal.y * supportY) + (plane.Normal.z * supportZ) - plane.Constant;
      if (signedDistance > 0.0f) {
        return false;
      }
    }

    return true;
  }

  using moho::SphereBoundsProbe;
  static_assert(sizeof(SphereBoundsProbe) == 0x10, "SphereBoundsProbe size must be 0x10");

  /**
   * Address: 0x00500C50 (FUN_00500C50)
   *
   * What it does:
   * Returns true when the sphere defined by `probe.center` / `probe.radius`
   * intersects (or fully contains) the axis-aligned box `bounds`. Implements
   * the classic "closest-point-on-AABB to sphere center, then compare to
   * radius squared" test — the binary computes per-axis distance via two
   * `max(min - p, p - max, 0)` reductions then sums their squares.
   *
   * IDA signature:
   *   BOOL sub_500C50(float *bounds@<eax>, float *sphere@<ecx>);
   * where `bounds = {minX, minY, minZ, maxX, maxY, maxZ}` and
   *       `sphere = {x, y, z, radius}`.
   */
  [[nodiscard]] bool SphereIntersectsAabb(
    const Wm3::AxisAlignedBox3f& bounds,
    const SphereBoundsProbe& probe
  ) noexcept
  {
    const auto axisDistance = [](const float minLane, const float maxLane, const float centerLane) noexcept {
      float gap = centerLane - maxLane;
      const float belowLane = minLane - centerLane;
      if (belowLane > gap) {
        gap = belowLane;
      }
      return gap < 0.0f ? 0.0f : gap;
    };

    const float dx = axisDistance(bounds.Min.x, bounds.Max.x, probe.center.x);
    const float dy = axisDistance(bounds.Min.y, bounds.Max.y, probe.center.y);
    const float dz = axisDistance(bounds.Min.z, bounds.Max.z, probe.center.z);

    return (probe.radius * probe.radius) >= ((dx * dx) + (dy * dy) + (dz * dz));
  }

  /**
   * Address: 0x00500D00 (FUN_00500D00)
   *
   * What it does:
   * Returns true when both the minimum-corner and the maximum-corner of
   * `bounds` lie strictly within the sphere. For an axis-aligned box the two
   * opposite corners are the furthest pair of vertices, so this serves as a
   * conservative "sphere contains AABB" test used by the spatial-shard sphere
   * collect leaf path to short-circuit per-entity intersection checks: when
   * it returns true the entire shard-data lane is inside the sphere and
   * every node owner is accepted unconditionally.
   *
   * IDA signature:
   *   bool sub_500D00(float *sphere@<edi>, float *bounds@<esi>);
   */
  [[nodiscard]] bool SphereContainsAabbDiagonal(
    const SphereBoundsProbe& probe,
    const Wm3::AxisAlignedBox3f& bounds
  ) noexcept
  {
    const auto distanceSquaredTo = [&probe](const float x, const float y, const float z) noexcept {
      const float dx = std::fabs(x - probe.center.x);
      const float dy = std::fabs(y - probe.center.y);
      const float dz = std::fabs(z - probe.center.z);
      return (dx * dx) + (dy * dy) + (dz * dz);
    };

    const float radiusSquared = probe.radius * probe.radius;
    if (distanceSquaredTo(bounds.Min.x, bounds.Min.y, bounds.Min.z) > radiusSquared) {
      return false;
    }
    return distanceSquaredTo(bounds.Max.x, bounds.Max.y, bounds.Max.z) <= radiusSquared;
  }

  /**
   * Address: 0x00500E50 (FUN_00500E50, Moho::CGeomSolid3::Intersects helper lane)
   *
   * What it does:
   * Dispatches one convex-volume vs AABB reject test used by spatial-shard
   * volume collection hot paths.
   */
  [[nodiscard]] bool IntersectsShardVolumeBounds(
    const moho::CGeomSolid3& volume,
    const Wm3::AxisAlignedBox3f& bounds
  ) noexcept
  {
    return volume.Intersects(bounds);
  }

  // The spatial maps are `moho::SpatialMap<T>` -- an `msvc8::multiset` of
  // `SpatialEntry<T>` in `SpatialEntryLess` order -- and the shard arrays are
  // `msvc8::vector`s (SpatialDb.h). Every tree and vector body the database
  // emitted in 0x00504310..0x00506230 (insert, hinted insert, `_Insert`,
  // erase, the rotations, `_Inc`/`_Dec`, `_Min`/`_Max`, `_Buynode`, `~_Tree`,
  // `resize`, `_Insert_n`, `_Xlen`, the word moves) is the containers' own and
  // is cited on `msvc8::multiset`, `msvc8::detail::rb_tree` and
  // `msvc8::vector`. The hand-rolled copies that used to live here implemented
  // all of it a second time over the same nodes -- the erase as a silent no-op
  // for a while (564d7e57d) -- so they are gone, and the source says
  // `map.insert(entry)` and `mShards.resize(16)`.

  [[nodiscard]] std::int32_t FloorSpatialCellCoordinate(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value * 0.0625f));
  }

  /**
   * Address: 0x00501990 (FUN_00501990, sub_501990)
   *
   * What it does:
   * Returns true when min-x/min-z cell coordinates changed between two AABBs
   * in 16-unit spatial bins.
   */
  [[nodiscard]] bool HasSpatialCellChanged(
    const Wm3::AxisAlignedBox3f& previousBounds,
    const Wm3::AxisAlignedBox3f& updatedBounds
  ) noexcept
  {
    return FloorSpatialCellCoordinate(previousBounds.Min.x) != FloorSpatialCellCoordinate(updatedBounds.Min.x)
      || FloorSpatialCellCoordinate(previousBounds.Min.z) != FloorSpatialCellCoordinate(updatedBounds.Min.z);
  }

  /**
   * Address: 0x00501620 (FUN_00501620, sub_501620)
   *
   * What it does:
   * Expands shard bounds with one AABB and propagates the merge through all
   * parent shards.
   */
  template <class T>
  void PropagateBoundsToShardChain(moho::SpatialShard<T>* shard, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    for (moho::SpatialShard<T>* current = shard; current != nullptr; current = current->mParent) {
      current->mBounds.Min.x = std::min(current->mBounds.Min.x, bounds.Min.x);
      current->mBounds.Min.y = std::min(current->mBounds.Min.y, bounds.Min.y);
      current->mBounds.Min.z = std::min(current->mBounds.Min.z, bounds.Min.z);
      current->mBounds.Max.x = std::max(current->mBounds.Max.x, bounds.Max.x);
      current->mBounds.Max.y = std::max(current->mBounds.Max.y, bounds.Max.y);
      current->mBounds.Max.z = std::max(current->mBounds.Max.z, bounds.Max.z);
    }
  }

  /**
   * Address: 0x005016C0 (FUN_005016C0, sub_5016C0)
   *
   * What it does:
   * Increments one type-lane counter on a shard and all parent shards.
   */
  template <class T>
  void IncrementShardTypeCountChain(moho::SpatialShard<T>* shard, const std::uint32_t typeBits) noexcept
  {
    for (moho::SpatialShard<T>* current = shard; current != nullptr; current = current->mParent) {
      if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
        ++current->mUnitCount;
      } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
        ++current->mProjectileCount;
      } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
        ++current->mPropCount;
      } else if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
        ++current->mEntityCount;
      }
    }
  }

  /**
   * Appends the owner of every entry in `map` whose box `accept` takes -- the
   * range walk (`_Inc` 0x00505B40) and `push_back` (0x005050A0) every leaf
   * collect body runs over up to four maps.
   */
  template <class T, class Predicate>
  void CollectEntries(const moho::SpatialMap<T>& map, gpg::fastvector<T*>& destination, const Predicate& accept)
  {
    for (const moho::SpatialEntry<T>& entry : map) {
      if (accept(entry.mBox)) {
        destination.push_back(entry.mOwner);
      }
    }
  }

  /**
   * Address: 0x00502C60 (FUN_00502C60, Spatial shard AABB leaf collect helper)
   *
   * What it does:
   * Scans one leaf `SpatialShardData` lane and appends all entity owners whose
   * node AABBs intersect the query `bounds` for requested type masks.
   *
   * The box tests here and in `CollectInBox` are Wild Magic's inline
   * `AxisAlignedBox3<float>::TestIntersection` (Wm3AxisAlignedBox3.inl),
   * emitted into this code as one out-of-line body:
   * Address: 0x00506010 (FUN_00506010, Wm3::AxisAlignedBox3<float>::TestIntersection)
   * `this` is the query `bounds` (edi) and the argument the stored box (edx) at
   * 0x00502972, 0x00502A00 and 0x00503C1B, which is the binary's comparison
   * order: `Max[i] < box.Min[i]`, then `Min[i] > box.Max[i]`.
   */
  template <class T>
  void CollectInBoxFromLeafData(
    const Wm3::AxisAlignedBox3f& bounds,
    moho::SpatialShardData<T>& data,
    const moho::EEntityType type,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardDataHasNoRequestedType(data, type) || !bounds.TestIntersection(data.mBounds)) {
      return;
    }

    if (data.mTimeSinceRecalc > 500) {
      data.RecalculateBounds();
    }

    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto intersectsQuery = [&bounds](const Wm3::AxisAlignedBox3f& nodeBox) {
      return bounds.TestIntersection(nodeBox);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectEntries(data.mMapUnits, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectEntries(data.mMapProjectiles, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectEntries(data.mMapProps, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectEntries(data.mMapEntities, destination, intersectsQuery);
    }
  }

  template <class T>
  void CollectInVolumeFromLeafData(
    gpg::fastvector<T*>& destination,
    moho::SpatialShardData<T>& data,
    const moho::EEntityType type,
    const moho::CGeomSolid3& volume
  )
  {
    if (SpatialShardDataHasNoRequestedType(data, type) || !IntersectsShardVolumeBounds(volume, data.mBounds)) {
      return;
    }

    if (data.mTimeSinceRecalc > 500) {
      data.RecalculateBounds();
    }

    const bool boundsContainData = SolidContainsAabb(volume, data.mBounds);
    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto intersectsOrContained = [&volume, boundsContainData](const Wm3::AxisAlignedBox3f& nodeBox) {
      return boundsContainData || IntersectsShardVolumeBounds(volume, nodeBox);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectEntries(data.mMapUnits, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectEntries(data.mMapProjectiles, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectEntries(data.mMapProps, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectEntries(data.mMapEntities, destination, intersectsOrContained);
    }
  }

  [[nodiscard]] float SelectSupportCoordinate(
    const float minValue,
    const float maxValue,
    const float supportSelectorLane
  ) noexcept
  {
    // FUN_00503730 bit-pack path chooses Max when sign bit is set and Min
    // otherwise for each lane.
    return std::signbit(supportSelectorLane) ? maxValue : minValue;
  }

  [[nodiscard]] float ComputeFadeThresholdForBounds(
    const moho::Vector4f& fadePlane,
    const Wm3::Vector3f& supportSelector,
    const Wm3::AxisAlignedBox3f& bounds
  ) noexcept
  {
    const float supportX = SelectSupportCoordinate(bounds.Min.x, bounds.Max.x, supportSelector.x);
    const float supportY = SelectSupportCoordinate(bounds.Min.y, bounds.Max.y, supportSelector.y);
    const float supportZ = SelectSupportCoordinate(bounds.Min.z, bounds.Max.z, supportSelector.z);
    return fadePlane.x * supportX + fadePlane.y * supportY + fadePlane.z * supportZ + fadePlane.w;
  }

  [[nodiscard]] Wm3::Vector3f BuildViewSupportSelector(const moho::GeomCamera3& camera) noexcept
  {
    Wm3::Vector3f supportSelector{};
    supportSelector.x = -camera.inverseView.r[2].x;
    supportSelector.y = -camera.inverseView.r[2].y;
    supportSelector.z = -camera.inverseView.r[2].z;
    return supportSelector;
  }

  /**
   * Address: 0x00503AA0 (FUN_00503AA0, sub_503AA0)
   *
   * What it does:
   * Builds view-space support selector lanes from camera inverse-view row 2
   * and runs leaf-data frustum/fade collection.
   */
  template <class T>
  void CollectInViewFromLeafData(
    gpg::fastvector<T*>& destination,
    moho::SpatialShardData<T>* const data,
    moho::GeomCamera3* const camera,
    const moho::EEntityType type
  )
  {
    const Wm3::Vector3f supportSelector = BuildViewSupportSelector(*camera);
    moho::SpatialShardData<T>::FindInVolumeFromData(
      camera->viewport.r[1],
      supportSelector,
      data,
      type,
      &camera->solid2,
      destination
    );
  }

  /**
   * Address: 0x00503EB0 (FUN_00503EB0, sub_503EB0)
   *
   * What it does:
   * Builds view-space support selector lanes from camera inverse-view row 2
   * and runs one shard frustum/fade collection pass.
   */
  template <class T>
  void CollectInViewFromShard(
    moho::GeomCamera3* const camera,
    gpg::fastvector<T*>& destination,
    moho::SpatialShard<T>* const shard,
    const moho::EEntityType type
  )
  {
    const Wm3::Vector3f supportSelector = BuildViewSupportSelector(*camera);
    moho::SpatialShardData<T>::FindInVolume(shard, type, &camera->solid2, supportSelector, camera->viewport.r[1], destination);
  }

  /**
   * The view collect's map walk. The map is in `SpatialEntryLess` order, so
   * once a fading entry's cutoff is within the view's threshold every entry
   * after it fades sooner and the walk stops.
   */
  template <class T>
  void CollectVolumeCandidatesWithFade(
    const moho::SpatialMap<T>& map,
    const moho::CGeomSolid3& volume,
    const bool dataBoundsContained,
    const float fadeThreshold,
    gpg::fastvector<T*>& destination
  )
  {
    for (const moho::SpatialEntry<T>& entry : map) {
      if (entry.mFadeOut > 0.0f && fadeThreshold >= entry.mFadeOut) {
        break;
      }

      if (dataBoundsContained || volume.Intersects(entry.mBox)) {
        destination.push_back(entry.mOwner);
      }
    }
  }

  /**
   * Address: 0x007DAC10 (FUN_007DAC10, sub_7DAC10)
   *
   * What it does:
   * Multiplies local mesh bounds by per-axis instance scale.
   */
  [[nodiscard]] Wm3::AxisAlignedBox3f ScaleLocalMeshBounds(
    const Wm3::Vec3f& scale,
    const Wm3::AxisAlignedBox3f& localBounds
  ) noexcept
  {
    Wm3::AxisAlignedBox3f scaled{};
    scaled.Min.x = scale.x * localBounds.Min.x;
    scaled.Min.y = scale.y * localBounds.Min.y;
    scaled.Min.z = scale.z * localBounds.Min.z;
    scaled.Max.x = scale.x * localBounds.Max.x;
    scaled.Max.y = scale.y * localBounds.Max.y;
    scaled.Max.z = scale.z * localBounds.Max.z;
    return scaled;
  }

  /**
   * Address: 0x007DAB00 (FUN_007DAB00, sub_7DAB00)
   *
   * What it does:
   * Merges two AABB lanes into one min/min + max/max result.
   */
  [[nodiscard]] Wm3::AxisAlignedBox3f MergeAxisAlignedBounds(
    const Wm3::AxisAlignedBox3f& first,
    const Wm3::AxisAlignedBox3f& second
  ) noexcept
  {
    Wm3::AxisAlignedBox3f merged = second;
    merged.Min.x = std::min(first.Min.x, merged.Min.x);
    merged.Min.y = std::min(first.Min.y, merged.Min.y);
    merged.Min.z = std::min(first.Min.z, merged.Min.z);
    merged.Max.x = std::max(first.Max.x, merged.Max.x);
    merged.Max.y = std::max(first.Max.y, merged.Max.y);
    merged.Max.z = std::max(first.Max.z, merged.Max.z);
    return merged;
  }

  /**
   * Address: 0x00472CF0 (FUN_00472CF0, sub_472CF0)
   *
   * IDA signature:
   * float* __usercall sub_472CF0@<eax>(Wm3::Quaternionf* a1@<ecx>,
   *                                   float* localAabb@<esi>,
   *                                   Wm3::Box3f* dest@<edx>);
   *
   * What it does:
   * Builds a world-space oriented box from a quaternion + a local AABB
   * (`[xMin, yMin, zMin, xMax, yMax, zMax]` packed as 6 floats) plus the
   * world-space position lane that follows the quaternion in memory
   * (interpolated mesh position). Result is `Box3f{ center, vX, vY, vZ,
   * halfExtents }` written into `dest`.
   *
   * Used by `MeshInstance::UpdateInterpolatedFields` and
   * `MeshInstance::GetSweptAlignedBox` to derive the renderer-facing
   * oriented box from the current interpolated stance.
   */
  void BuildOrientedBoxFromLocalAabb(
    const Wm3::Quaternionf& orientation,
    const Wm3::Vec3f& worldPosition,
    const float xMinL,
    const float yMinL,
    const float zMinL,
    const float xMaxL,
    const float yMaxL,
    const float zMaxL,
    Wm3::Box3f& dest
  ) noexcept
  {
    moho::VAxes3 axes{orientation};

    const float halfX = (xMaxL - xMinL) * 0.5f;
    const float halfY = (yMaxL - yMinL) * 0.5f;
    const float halfZ = (zMaxL - zMinL) * 0.5f;

    const float centerLX = (xMinL + xMaxL) * 0.5f;
    const float centerLY = (yMinL + yMaxL) * 0.5f;
    const float centerLZ = (zMinL + zMaxL) * 0.5f;

    const float worldOffsetX = axes.vZ.x * centerLZ + axes.vY.x * centerLY + axes.vX.x * centerLX;
    const float worldOffsetY = axes.vZ.y * centerLZ + axes.vY.y * centerLY + axes.vX.y * centerLX;
    const float worldOffsetZ = axes.vZ.z * centerLZ + axes.vY.z * centerLY + axes.vX.z * centerLX;

    dest.Center.x = worldPosition.x + worldOffsetX;
    dest.Center.y = worldPosition.y + worldOffsetY;
    dest.Center.z = worldPosition.z + worldOffsetZ;

    dest.Axis[0] = axes.vX;
    dest.Axis[1] = axes.vY;
    dest.Axis[2] = axes.vZ;

    dest.Extent[0] = halfX;
    dest.Extent[1] = halfY;
    dest.Extent[2] = halfZ;
  }

  [[nodiscard]] std::uintptr_t PointerOrderKey(const void* const ptr) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(ptr);
  }

  constexpr std::int32_t kMeshSpatialDbRoutingMask = 0x800;


  /**
   * Address: 0x00503B10 (FUN_00503B10, sub_503B10)
   *
   * What it does:
   * Walks shard children by x/z cell index until it reaches one leaf-data lane.
   */
  template <class T>
  [[nodiscard]] moho::SpatialShardData<T>*
  ResolveSpatialLeafDataForPoint(moho::SpatialShard<T>* shard, const float worldZ, const float worldX)
  {
    for (;;) {
      const std::int32_t level = shard->mLevel;
      const float cellSize = static_cast<float>(kSpatialShardCellSizeByLevel[level]);
      const std::int32_t laneX = static_cast<std::int32_t>((worldX - static_cast<float>(shard->mAreaRect.x0)) / cellSize);
      const std::int32_t laneZ = static_cast<std::int32_t>((worldZ - static_cast<float>(shard->mAreaRect.z0)) / cellSize);
      const std::int32_t laneIndex = laneX + kSpatialShardGridDimension * laneZ;

      if (level <= 0) {
        return shard->mData[laneIndex];
      }

      shard = shard->mShards[laneIndex];
    }
  }

  /**
   * Address: 0x00502120 (FUN_00502120, sub_502120)
   *
   * What it does:
   * Resolves one world position to leaf shard-data lane; falls back to inline
   * root shard-data lane when position is outside shard-grid coverage.
   *
   * Inside the 16-unit cell grid the top-level shard is indexed without a
   * null test, as the binary does: `ResizeForMap` leaves a slot null only
   * past the map extent, and the cell grid (`mShardWidth`/`mShardHeight`)
   * ends there.
   */
  template <class T>
  [[nodiscard]] moho::SpatialShardData<T>*
  ResolveSpatialLeafDataFromStoragePoint(const Wm3::Vec3f& point, moho::SpatialDB<T>& storage)
  {
    const std::int32_t coarseX = static_cast<std::int32_t>(std::floor(point.x * 0.0625f));
    const std::int32_t coarseZ = static_cast<std::int32_t>(std::floor(point.z * 0.0625f));
    if (coarseX < 0 || coarseZ < 0 || coarseX >= storage.mShardWidth || coarseZ >= storage.mShardHeight) {
      return &storage.mShardData;
    }

    const float shardCellSize = static_cast<float>(kSpatialShardCellSizeByLevel[storage.mShardLevel]);
    const std::int32_t shardX = static_cast<std::int32_t>(point.x / shardCellSize);
    const std::int32_t shardZ = static_cast<std::int32_t>(point.z / shardCellSize);
    const std::int32_t topIndex = shardX + kSpatialShardGridDimension * shardZ;
    return ResolveSpatialLeafDataForPoint(storage.mShards[topIndex], point.z, point.x);
  }

  [[nodiscard]] moho::VTransform IdentityTransform() noexcept
  {
    moho::VTransform transform{};
    transform.orient_.w = 1.0f;
    transform.orient_.x = 0.0f;
    transform.orient_.y = 0.0f;
    transform.orient_.z = 0.0f;
    transform.pos_.x = 0.0f;
    transform.pos_.y = 0.0f;
    transform.pos_.z = 0.0f;
    return transform;
  }

  void AssignMaterialTextureSheet(
    boost::shared_ptr<moho::ID3DTextureSheet>& destination,
    const msvc8::string& textureName,
    moho::CResourceWatcher* const resourceWatcher
  )
  {
    // 0x007DC280: an empty path skips the lookup entirely -- the field keeps
    // whatever it already held. 0x007DC2AE dispatches vtable slot 10 on the
    // device's resource set, with the fallback flag set (`push 1`, 0x007DC292),
    // so a missing texture resolves to the fallback rather than to null.
    if (textureName.empty()) {
      return;
    }

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr) {
      return;
    }

    moho::ID3DDeviceResources* const resources = device->GetResources();
    if (resources == nullptr) {
      return;
    }

    moho::ID3DDeviceResources::TextureResourceHandle texture{};
    resources->GetTexture(texture, textureName.c_str(), resourceWatcher, true);
    destination = texture;
  }

  [[nodiscard]] boost::shared_ptr<const moho::CAniSkel>
  ResolveInitialPoseSkeleton(const boost::shared_ptr<moho::Mesh>& mesh, const bool isStaticPose)
  {
    if (!isStaticPose || !mesh) {
      return moho::CAniSkel::GetDefaultSkeleton();
    }

    const boost::shared_ptr<moho::RScmResource> resource = mesh->GetResource(0);
    if (!resource) {
      return moho::CAniSkel::GetDefaultSkeleton();
    }

    const boost::shared_ptr<const moho::CAniSkel> skeleton = resource->GetSkeleton();
    if (skeleton) {
      return skeleton;
    }

    return moho::CAniSkel::GetDefaultSkeleton();
  }

  [[nodiscard]] float ComputeSpatialDissolveCutoff(const boost::shared_ptr<moho::Mesh>& mesh)
  {
    if (!mesh) {
      return -1.0f;
    }

    moho::MeshLOD* const* const begin = mesh->lods.begin();
    moho::MeshLOD* const* const end = mesh->lods.end();
    if (!begin || !end || begin == end) {
      return -1.0f;
    }

    const moho::MeshLOD* const lastLod = *(end - 1);
    if (!lastLod || lastLod->cutoff <= 0.0f) {
      return -1.0f;
    }

    return lastLod->cutoff + moho::ren_MeshDissolve;
  }

  // The mesh-cache tree is `msvc8::map<MeshKey, boost::weak_ptr<Mesh>,
  // MeshKeyLess>` (Mesh.h). Its storage lifecycle - header sentinel
  // allocation (0x007E4770/0x007E2B50), buy_node (0x007E6090),
  // insert_unique/insert_at/link_and_rebalance (0x007E5B20/0x007E5DF0),
  // rb_decrement (0x007E60F0), lower_bound_node/find_node (0x007E6050/
  // 0x007E5C00), and the full tidy that frees every node plus the header
  // (0x007DF2D0) - is the container's own ctor / dtor, all cited on the
  // matching `rb_tree<Traits>` members in RbTree.h. The hand-rolled copies
  // that used to live here re-implemented all of that a second time over
  // the same nodes, so they are gone; call sites use the map's own API
  // (FindOrCreateMesh, below).

  // The mesh-batch bucket tree is `msvc8::map<MeshBatchKey,
  // msvc8::vector<MeshInstance*>, MeshBatchKeyLess>` (MeshBatchKey.h). Its
  // storage lifecycle - header sentinel allocation (0x007E2C30), the recursive
  // payload teardown plus header relink (0x007E2D90) and the full tidy that
  // frees the header too (0x007E2B20) - is the container's own ctor / `clear()`
  // / dtor, and `msvc8::vector` owns the bucket payload's growth and release.
  // The hand-rolled copies that used to live here re-implemented all of that a
  // second time over the same nodes, so they are gone; call sites use the
  // container operations directly.

  /**
   * Drops every live instance's cached LOD batches -- the loop `Reset`
   * (0x007E1370) and `Shutdown` (0x007E1510) both carry inline: walk the
   * ring, downcast each node to its `MeshInstance` (`node - 4`, the base's
   * offset), and reset every LOD of an instance that has a mesh.
   */
  void ResetInstanceBatches(moho::TDatList<moho::MeshInstance, void>& instances) noexcept
  {
    for (moho::MeshInstance* const instance : instances.owners()) {
      if (moho::Mesh* const mesh = instance->mesh.get(); mesh != nullptr) {
        for (moho::MeshLOD* const lod : mesh->lods) {
          lod->ResetBatches();
        }
      }
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005011A0 (FUN_005011A0, Moho::SpatialShard::SpatialShard)
   *
   * What it does:
   * Initializes one spatial shard node and recursively allocates either child
   * shards (non-leaf levels) or 16 leaf-data lanes.
   */
  template <class T>
  SpatialShard<T>::SpatialShard(const std::int32_t level, SpatialShard<T>* const parent, const gpg::Rect2i& areaRect)
    : mParent(parent)
    , mAreaRect(areaRect)
    , mLevel(level)
    , mUnitCount(0)
    , mProjectileCount(0)
    , mPropCount(0)
    , mEntityCount(0)
    , mBounds()
    , mShards()
    , mData()
  {
    mBounds.Min.x = FLT_MAX;
    mBounds.Min.y = FLT_MAX;
    mBounds.Min.z = FLT_MAX;
    mBounds.Max.x = -FLT_MAX;
    mBounds.Max.y = -FLT_MAX;
    mBounds.Max.z = -FLT_MAX;

    if (mLevel > 0) {
      const std::int32_t dx = (mAreaRect.x1 - mAreaRect.x0) / kSpatialShardGridDimension;
      const std::int32_t dz = (mAreaRect.z1 - mAreaRect.z0) / kSpatialShardGridDimension;

      mShards.resize(kSpatialShardSlotCount);
      for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
        const std::int32_t col = index % kSpatialShardGridDimension;
        const std::int32_t row = index / kSpatialShardGridDimension;

        gpg::Rect2i childRect{};
        childRect.x0 = mAreaRect.x0 + dx * col;
        childRect.z0 = mAreaRect.z0 + dz * row;
        childRect.x1 = mAreaRect.x0 + dx * (col + 1);
        childRect.z1 = mAreaRect.z0 + dz * (row + 1);
        mShards[index] = new SpatialShard<T>(mLevel - 1, this, childRect);
      }
      return;
    }

    mData.resize(kSpatialShardSlotCount);
    for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
      mData[index] = new SpatialShardData<T>(this);
    }
  }

  /**
   * Address: 0x00501370 (FUN_00501370, Moho::SpatialShard::~SpatialShard)
   * Address: 0x00501790 (FUN_00501790 -- the scalar deleting destructor
   * `??_G`: this body, then `operator delete` when bit 0 of the flag is set;
   * what `delete mShards[index]` calls here, in `~SpatialDB` and in
   * `ResizeForMap`, since the recursion keeps the destructor out of line.)
   *
   * What it does:
   * Deletes the 16 owned child shards (or leaf lanes) and clears whichever
   * vector held them; both vectors then free their storage as members.
   */
  template <class T>
  SpatialShard<T>::~SpatialShard()
  {
    if (mLevel > 0) {
      for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
        delete mShards[index];
      }
      mShards.clear();
    } else {
      for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
        delete mData[index];
      }
      mData.clear();
    }
  }

  /**
   * Address: 0x00501490 (FUN_00501490, Moho::SpatialShard::CountType)
   *
   * What it does:
   * Returns true when the shard has no entries for requested type lanes.
   */
  template <class T>
  bool SpatialShard<T>::CountType(const EEntityType type) const
  {
    const std::uint32_t typeBits = EntityTypeBits(type);
    if (typeBits != 0u) {
      return ((typeBits & kSpatialEntityTypeUnit) == 0u || mUnitCount <= 0)
        && ((typeBits & kSpatialEntityTypeProjectile) == 0u || mProjectileCount <= 0)
        && ((typeBits & kSpatialEntityTypeProp) == 0u || mPropCount <= 0)
        && ((typeBits & kSpatialEntityTypeEntity) == 0u || mEntityCount <= 0);
    }

    return mUnitCount <= 0 && mProjectileCount <= 0 && mPropCount <= 0 && mEntityCount <= 0;
  }

  /**
   * Address: 0x00501710 (FUN_00501710, Moho::SpatialShard::DecrementCount)
   *
   * What it does:
   * Decrements the requested entity-lane count on this shard and every parent.
   */
  template <class T>
  void SpatialShard<T>::DecrementCount(SpatialShard<T>* shard, const EEntityType type)
  {
    for (SpatialShard<T>* current = shard; current != nullptr; current = current->mParent) {
      const std::uint32_t typeBits = EntityTypeBits(type);
      if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
        --current->mUnitCount;
      } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
        --current->mProjectileCount;
      } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
        --current->mPropCount;
      } else if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
        --current->mEntityCount;
      }
    }
  }

  /**
   * Address: 0x00501500 (FUN_00501500, Moho::SpatialShard::RecalculateBounds)
   *
   * What it does:
   * Rebuilds each shard lane bounds from child shard/data lanes and
   * propagates the update through parent shards.
   */
  template <class T>
  void SpatialShard<T>::RecalculateBounds()
  {
    for (SpatialShard<T>* shard = this; shard != nullptr; shard = shard->mParent) {
      Wm3::AxisAlignedBox3f mergedBounds{};
      mergedBounds.Min.x = FLT_MAX;
      mergedBounds.Min.y = FLT_MAX;
      mergedBounds.Min.z = FLT_MAX;
      mergedBounds.Max.x = -FLT_MAX;
      mergedBounds.Max.y = -FLT_MAX;
      mergedBounds.Max.z = -FLT_MAX;

      for (std::int32_t index = 0; index < 16; ++index) {
        const Wm3::AxisAlignedBox3f* sourceBounds = nullptr;
        if (shard->mLevel <= 0) {
          sourceBounds = &shard->mData[index]->mBounds;
        } else {
          sourceBounds = &shard->mShards[index]->mBounds;
        }

        mergedBounds.Min.x = std::min(mergedBounds.Min.x, sourceBounds->Min.x);
        mergedBounds.Min.y = std::min(mergedBounds.Min.y, sourceBounds->Min.y);
        mergedBounds.Min.z = std::min(mergedBounds.Min.z, sourceBounds->Min.z);
        mergedBounds.Max.x = std::max(mergedBounds.Max.x, sourceBounds->Max.x);
        mergedBounds.Max.y = std::max(mergedBounds.Max.y, sourceBounds->Max.y);
        mergedBounds.Max.z = std::max(mergedBounds.Max.z, sourceBounds->Max.z);
      }

      shard->mBounds = mergedBounds;
    }
  }

  /**
   * Address: 0x00501070 (FUN_00501070, Moho::SpatialShardData::HasType)
   *
   * What it does:
   * Returns true when leaf map lanes have no entries for requested type lanes.
   */
  template <class T>
  bool SpatialShardData<T>::HasType(const SpatialShardData<T>* const data, const EEntityType type)
  {
    const std::uint32_t typeBits = EntityTypeBits(type);
    if (typeBits != 0u) {
      return ((typeBits & kSpatialEntityTypeUnit) == 0u || data->mMapUnits.empty())
        && ((typeBits & kSpatialEntityTypeProjectile) == 0u || data->mMapProjectiles.empty())
        && ((typeBits & kSpatialEntityTypeProp) == 0u || data->mMapProps.empty())
        && ((typeBits & kSpatialEntityTypeEntity) == 0u || data->mMapEntities.empty());
    }

    return data->mMapUnits.empty() && data->mMapProjectiles.empty() && data->mMapProps.empty() &&
      data->mMapEntities.empty();
  }

  /**
   * Address: 0x00500F60 (FUN_00500F60, Moho::SpatialShardData::SpatialShardData)
   *
   * What it does:
   * Names the owning shard, zeroes the unnamed header and the staleness
   * counter, and seeds the bounds inverted. The four maps construct their
   * own heads (`_Buynode` 0x00505D20, self-linked, size zero).
   */
  template <class T>
  SpatialShardData<T>::SpatialShardData(SpatialShard<T>* const ownerShard)
    : mShard(ownerShard)
    , mUnknown_04_13{}
    , mTimeSinceRecalc(0)
    , mBounds()
    , mMapUnits()
    , mMapProjectiles()
    , mMapProps()
    , mMapEntities()
  {
    mBounds.Min.x = FLT_MAX;
    mBounds.Min.y = FLT_MAX;
    mBounds.Min.z = FLT_MAX;
    mBounds.Max.x = -FLT_MAX;
    mBounds.Max.y = -FLT_MAX;
    mBounds.Max.z = -FLT_MAX;
  }

  /**
   * Address: 0x005017E0 (FUN_005017E0, Moho::SpatialShardData::~SpatialShardData)
   *
   * What it does:
   * Member destruction only: each map's `~_Tree` (`erase(begin(), end())`
   * through 0x00505200, then the head freed), entities first, inlined here.
   */
  template <class T>
  SpatialShardData<T>::~SpatialShardData() = default;

  /**
   * Address: 0x005023B0 (FUN_005023B0, Moho::SpatialShardData::RecalculateBounds)
   *
   * What it does:
   * Rebuilds aggregate bounds from all leaf-map lanes, then propagates shard
   * bounds through the owning shard chain.
   */
  template <class T>
  void SpatialShardData<T>::RecalculateBounds()
  {
    Wm3::AxisAlignedBox3f mergedBounds{};
    mergedBounds.Min.x = FLT_MAX;
    mergedBounds.Min.y = FLT_MAX;
    mergedBounds.Min.z = FLT_MAX;
    mergedBounds.Max.x = -FLT_MAX;
    mergedBounds.Max.y = -FLT_MAX;
    mergedBounds.Max.z = -FLT_MAX;

    const auto accumulateTreeBounds = [&mergedBounds](const SpatialMap<T>& map) {
      for (const SpatialEntry<T>& entry : map) {
        const Wm3::AxisAlignedBox3f& entryBox = entry.mBox;
        mergedBounds.Min.x = std::min(mergedBounds.Min.x, entryBox.Min.x);
        mergedBounds.Min.y = std::min(mergedBounds.Min.y, entryBox.Min.y);
        mergedBounds.Min.z = std::min(mergedBounds.Min.z, entryBox.Min.z);
        mergedBounds.Max.x = std::max(mergedBounds.Max.x, entryBox.Max.x);
        mergedBounds.Max.y = std::max(mergedBounds.Max.y, entryBox.Max.y);
        mergedBounds.Max.z = std::max(mergedBounds.Max.z, entryBox.Max.z);
      }
    };

    accumulateTreeBounds(mMapUnits);
    accumulateTreeBounds(mMapProjectiles);
    accumulateTreeBounds(mMapProps);
    accumulateTreeBounds(mMapEntities);

    mBounds = mergedBounds;
    if (mShard != nullptr) {
      mShard->RecalculateBounds();
    }

    mTimeSinceRecalc = 0;
  }

  /**
   * Address: 0x00502340 (FUN_00502340, Moho::SpatialShardData::RemoveNode)
   *
   * What it does:
   * Erases one entry from the map its routing mask selects and updates shard
   * counts up the owner chain.
   */
  template <class T>
  void SpatialShardData<T>::RemoveNode(const iterator node)
  {
    ++mTimeSinceRecalc;
    const EEntityType type = static_cast<EEntityType>(node->mEntityType);

    const std::uint32_t typeBits = EntityTypeBits(type);
    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      mMapUnits.erase(node);
    } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      mMapProjectiles.erase(node);
    } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      mMapProps.erase(node);
    } else {
      mMapEntities.erase(node);
    }

    if (mShard != nullptr) {
      SpatialShard<T>::DecrementCount(mShard, type);
    }
  }

  /**
   * Address: 0x00502200 (FUN_00502200, sub_502200)
   *
   * What it does:
   * Inserts one entry into the map its routing mask selects, widens this
   * lane's bounds by the entry's box, stores this lane into the entry through
   * the new iterator, and propagates the bounds and the type count up the
   * shard chain.
   */
  template <class T>
  typename SpatialShardData<T>::iterator SpatialShardData<T>::Insert(const SpatialEntry<T>& entry)
  {
    iterator inserted;
    const std::uint32_t typeBits = entry.mEntityType;
    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      inserted = mMapUnits.insert(entry);
    } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      inserted = mMapProjectiles.insert(entry);
    } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      inserted = mMapProps.insert(entry);
    } else {
      inserted = mMapEntities.insert(entry);
    }

    mBounds.Min.x = std::min(mBounds.Min.x, entry.mBox.Min.x);
    mBounds.Min.y = std::min(mBounds.Min.y, entry.mBox.Min.y);
    mBounds.Min.z = std::min(mBounds.Min.z, entry.mBox.Min.z);
    mBounds.Max.x = std::max(mBounds.Max.x, entry.mBox.Max.x);
    mBounds.Max.y = std::max(mBounds.Max.y, entry.mBox.Max.y);
    mBounds.Max.z = std::max(mBounds.Max.z, entry.mBox.Max.z);
    ++mTimeSinceRecalc;

    inserted->mShardData = this;

    if (mShard != nullptr) {
      PropagateBoundsToShardChain(mShard, mBounds);
      IncrementShardTypeCountChain(mShard, entry.mEntityType);
    }

    return inserted;
  }

  /**
   * Address: 0x00502780 (FUN_00502780, Moho::SpatialShardData::CollectFromData)
   *
   * What it does:
   * Appends all entity pointers from selected leaf maps to destination.
   */
  template <class T>
  void SpatialShardData<T>::CollectFromData(const EEntityType type, gpg::fastvector<T*>& destination, SpatialShardData<T>* const data)
  {
    if (SpatialShardDataHasNoRequestedType(*data, type)) {
      return;
    }

    const std::uint32_t typeBits = EntityTypeBits(type);
    const auto collectAll = [&destination](const SpatialMap<T>& map) {
      CollectEntries(map, destination, [](const Wm3::AxisAlignedBox3f&) { return true; });
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      collectAll(data->mMapUnits);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      collectAll(data->mMapProjectiles);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      collectAll(data->mMapProps);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      collectAll(data->mMapEntities);
    }
  }

  /**
   * Address: 0x00503BB0 (FUN_00503BB0, Moho::SpatialShardData::Collect)
   *
   * What it does:
   * Recursively walks shard children (or leaf shard-data lanes at level 0)
   * and appends all entities matching `type`.
   */
  template <class T>
  void SpatialShardData<T>::Collect(
    SpatialShard<T>* const shard,
    const EEntityType type,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        CollectFromData(type, destination, shard->mData[index]);
      } else {
        Collect(shard->mShards[index], type, destination);
      }
    }
  }

  /**
   * Address: 0x00503C00 (FUN_00503C00, Moho::SpatialShardData::CollectInBox)
   *
   * What it does:
   * Recursively collects selected entities that intersect one AABB query.
   */
  template <class T>
  void SpatialShardData<T>::CollectInBox(
    SpatialShard<T>* const shard,
    const EEntityType type,
    const Wm3::AxisAlignedBox3f& bounds,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !bounds.TestIntersection(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        shard->mData[index]->CollectInBoxFromData(bounds, type, destination);
      } else {
        CollectInBox(shard->mShards[index], type, bounds, destination);
      }
    }
  }

  /**
   * Address: 0x00502950 (FUN_00502950, Moho::SpatialShardData::CollectInBoxFromData)
   *
   * What it does:
   * Collects entities from this leaf-data lane that intersect one AABB query.
   */
  template <class T>
  void SpatialShardData<T>::CollectInBoxFromData(
    const Wm3::AxisAlignedBox3f& bounds,
    const EEntityType type,
    gpg::fastvector<T*>& destination
  )
  {
    CollectInBoxFromLeafData(bounds, *this, type, destination);
  }

  /**
   * Address: 0x00503DB0 (FUN_00503DB0, Moho::SpatialShardData::CollectInVolume)
   *
   * What it does:
   * Recursively collects selected entities that intersect one convex volume.
   */
  template <class T>
  void SpatialShardData<T>::CollectInVolume(
    SpatialShard<T>* const shard,
    const EEntityType type,
    CGeomSolid3* const volume,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume->Intersects(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        shard->mData[index]->CollectInVolumeFromData(destination, type, volume);
      } else {
        CollectInVolume(shard->mShards[index], type, volume, destination);
      }
    }
  }

  /**
   * Address: 0x00503490 (FUN_00503490, Moho::SpatialShardData::CollectInVolumeFromData)
   *
   * What it does:
   * Collects entities from this leaf-data lane that intersect one convex
   * volume query.
   */
  template <class T>
  void SpatialShardData<T>::CollectInVolumeFromData(
    gpg::fastvector<T*>& destination,
    const EEntityType type,
    CGeomSolid3* const volume
  )
  {
    if (volume == nullptr) {
      return;
    }

    if (SpatialShardDataHasNoRequestedType(*this, type) || !IntersectsShardVolumeBounds(*volume, mBounds)) {
      return;
    }

    CollectInVolumeFromLeafData(destination, *this, type, *volume);
  }

  /**
   * Address: 0x005030C0 (FUN_005030C0, Moho::SpatialShardData::CollectInSphereFromData)
   *
   * What it does:
   * Sphere-collect leaf variant. Mirrors `CollectInVolumeFromData` but uses a
   * bounding sphere as the culling primitive. Returns `true` when the shard
   * had no entities of the requested type (the early-out path that mirrors
   * the recursive walker's reuse of the per-shard `CountType` reject), which
   * the recursive caller treats as a hint to short-circuit.
   */
  template <class T>
  bool SpatialShardData<T>::CollectInSphereFromData(
    const EEntityType type,
    const SphereBoundsProbe& probe,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardDataHasNoRequestedType(*this, type)) {
      return true;
    }

    if (!SphereIntersectsAabb(mBounds, probe)) {
      return false;
    }

    if (mTimeSinceRecalc > 500) {
      RecalculateBounds();
    }

    const bool dataBoundsContained = SphereContainsAabbDiagonal(probe, mBounds);
    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto includeIfRelevant = [&probe, dataBoundsContained](
      const Wm3::AxisAlignedBox3f& nodeBox
    ) {
      return dataBoundsContained || SphereIntersectsAabb(nodeBox, probe);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectEntries(mMapUnits, destination, includeIfRelevant);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectEntries(mMapProjectiles, destination, includeIfRelevant);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectEntries(mMapProps, destination, includeIfRelevant);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectEntries(mMapEntities, destination, includeIfRelevant);
    }

    return dataBoundsContained;
  }

  /**
   * Address: 0x00503D40 (FUN_00503D40, Moho::SpatialShardData::CollectInSphere)
   *
   * What it does:
   * Sphere variant of the recursive `CollectInBox` / `CollectInVolume`
   * walker. Early-outs when the shard has no entities of the requested type
   * or when the sphere does not touch the shard's bounds, otherwise descends
   * each of the 16 child slots — recursing on non-leaf children and
   * delegating to the per-leaf `CollectInSphereFromData` at level 0.
   */
  template <class T>
  bool SpatialShardData<T>::CollectInSphere(
    SpatialShard<T>* const shard,
    const EEntityType type,
    const SphereBoundsProbe& probe,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type)) {
      return true;
    }

    if (!SphereIntersectsAabb(shard->mBounds, probe)) {
      return false;
    }

    bool result = false;
    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        result = shard->mData[index]->CollectInSphereFromData(type, probe, destination);
      } else {
        result = CollectInSphere(shard->mShards[index], type, probe, destination);
      }
    }
    return result;
  }

  /**
   * Address: 0x00503730 (FUN_00503730, Moho::SpatialShardData::FindInVolumeFromData)
   *
   * What it does:
   * Collects matching entities from one leaf shard-data lane using view-volume
   * culling plus per-node fade threshold early-out.
   */
  template <class T>
  void SpatialShardData<T>::FindInVolumeFromData(
    const Vector4f& fadePlane,
    const Wm3::Vector3f& supportSelector,
    SpatialShardData<T>* const data,
    const EEntityType type,
    CGeomSolid3* const volume,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardDataHasNoRequestedType(*data, type) || !IntersectsShardVolumeBounds(*volume, data->mBounds)) {
      return;
    }

    if (data->mTimeSinceRecalc > 500) {
      data->RecalculateBounds();
    }

    const bool dataBoundsContained = SolidContainsAabb(*volume, data->mBounds);
    const float fadeThreshold = ComputeFadeThresholdForBounds(fadePlane, supportSelector, data->mBounds);
    const std::uint32_t typeBits = EntityTypeBits(type);

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectVolumeCandidatesWithFade(data->mMapUnits, *volume, dataBoundsContained, fadeThreshold, destination);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectVolumeCandidatesWithFade(data->mMapProjectiles, *volume, dataBoundsContained, fadeThreshold, destination);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectVolumeCandidatesWithFade(data->mMapProps, *volume, dataBoundsContained, fadeThreshold, destination);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectVolumeCandidatesWithFade(data->mMapEntities, *volume, dataBoundsContained, fadeThreshold, destination);
    }
  }

  /**
   * Address: 0x00503E30 (FUN_00503E30, Moho::SpatialShardData::FindInVolume)
   *
   * What it does:
   * Recursively collects entities intersecting one query volume while passing
   * view/fade cull inputs into leaf shard-data filtering.
   */
  template <class T>
  void SpatialShardData<T>::FindInVolume(
    SpatialShard<T>* const shard,
    const EEntityType type,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume->Intersects(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        FindInVolumeFromData(fadePlane, supportSelector, shard->mData[index], type, volume, destination);
      } else {
        FindInVolume(shard->mShards[index], type, volume, supportSelector, fadePlane, destination);
      }
    }
  }

  /**
   * Address: 0x00501D80 (FUN_00501D80, Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance)
   * Address: 0x007E2AA0 (FUN_007E2AA0 -- a placement-construct bridge that
   * moves `this` onto the stack and calls this constructor; zero callers, no
   * references, a linker-retained copy nothing runs.)
   *
   * What it does:
   * Member construction -- the shard vector empty, the root lane with no
   * owning shard, the extents zero, the overflow map's head -- then a
   * `clear()` of the shard vector, as the body at 0x00501DFD does.
   */
  template <class T>
  SpatialDB<T>::SpatialDB()
    : mShards()
    , mShardData(nullptr)
    , mMapWidth(0)
    , mMapHeight(0)
    , mShardWidth(0)
    , mShardHeight(0)
    , mShardLevel(0)
    , mMapTree()
  {
    mShards.clear();
  }

  /**
   * Address: 0x00501F50 (FUN_00501F50, Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance)
   *
   * What it does:
   * On an extent change, records the new extents, deletes the old top-level
   * shards, and -- for a non-empty map -- picks the shard level from the
   * larger extent and builds the 4x4 top level, leaving null every slot that
   * would reach past the map.
   */
  template <class T>
  void SpatialDB<T>::ResizeForMap(const std::int32_t width, const std::int32_t height)
  {
    if (width == mMapWidth && height == mMapHeight) {
      return;
    }

    mMapWidth = width;
    mShardWidth = width / kSpatialShardSlotCount;
    mShardHeight = height / kSpatialShardSlotCount;
    mMapHeight = height;

    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        delete shard;
      }
    }
    mShards.clear();

    if (mMapWidth <= 0 || mMapHeight <= 0) {
      return;
    }

    const std::int32_t dominantExtent = std::max(mMapWidth, mMapHeight);
    if (dominantExtent <= kSpatialShardLevelSmallThreshold) {
      mShardLevel = kSpatialShardLevelSmall;
    } else if (dominantExtent <= kSpatialShardLevelMediumThreshold) {
      mShardLevel = kSpatialShardLevelMedium;
    } else {
      mShardLevel = kSpatialShardLevelLarge;
    }

    const std::int32_t shardSize = kSpatialShardCellSizeByLevel[mShardLevel];
    mShards.resize(kSpatialShardSlotCount);
    for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
      const std::int32_t col = index % kSpatialShardGridDimension;
      const std::int32_t row = index / kSpatialShardGridDimension;

      gpg::Rect2i cellRect{};
      cellRect.x0 = shardSize * col;
      cellRect.z0 = shardSize * row;
      cellRect.x1 = shardSize * (col + 1);
      cellRect.z1 = shardSize * (row + 1);

      if (cellRect.x1 <= mMapWidth && cellRect.z1 <= mMapHeight) {
        mShards[index] = new SpatialShard<T>(mShardLevel - 1, nullptr, cellRect);
      } else {
        mShards[index] = nullptr;
      }
    }
  }

  /**
   * Address: 0x00501E50 (FUN_00501E50, Moho::SpatialDB<T>::~SpatialDB)
   *
   * What it does:
   * Deletes the top-level shards and clears the vector; the overflow map,
   * the root lane and the vector's storage then go as members.
   */
  template <class T>
  SpatialDB<T>::~SpatialDB()
  {
    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        delete shard;
      }
    }
    mShards.clear();
  }

  /**
   * Address: 0x00501A80 (FUN_00501A80, sub_501A80)
   * Address: 0x007E2AD0 (FUN_007E2AD0 -- a register-shape bridge into this
   * body with the mesh routing mask 0x800; zero callers, no references, a
   * linker-retained copy nothing runs.)
   * Address: 0x0089E520 (FUN_0089E520 -- a register-shape bridge that moves
   * the entry/database pair onto the stack shape this body expects; zero
   * callers, no references. Formerly `RegisterSpatialDbEntryAdapter` in
   * moho/entity/UserEntity.cpp, removed 2026-09-29.)
   *
   * What it does:
   * Drops any previous registration, then records the database and inserts
   * a fresh entry -- routing mask, owner, no leaf lane, no cutoff -- into its
   * overflow map at `end()`. The entry's box is left as
   * `AxisAlignedBox3f()` leaves it, unwritten, exactly as the binary's stack
   * temporary is: nothing reads it before the owner's first `UpdateBounds`,
   * which relinks an overflow entry unconditionally.
   */
  template <class T>
  void SpatialDBEntry<T>::Register(SpatialDB<T>* const db, T* const owner, const std::int32_t routingMask)
  {
    if (mDb != nullptr) {
      Unregister();
    }

    SpatialEntry<T> entry;
    entry.mEntityType = static_cast<std::uint32_t>(routingMask);
    entry.mShardData = nullptr;
    entry.mFadeOut = 0.0f;
    entry.mOwner = owner;

    mDb = db;
    mNode = db->mMapTree.insert(db->mMapTree.end(), entry);
  }

  /**
   * Address: 0x00501B00 (FUN_00501B00, sub_501B00)
   *
   * What it does:
   * Re-inserts this entry under a new dissolve cutoff -- the cutoff is the
   * map's sort key, so the entry is taken out and put back in order, into
   * its leaf lane when it has one and at the overflow map's `end()` when it
   * does not.
   */
  template <class T>
  void SpatialDBEntry<T>::UpdateDissolveCutoff(const float cutoff)
  {
    SpatialEntry<T> entry = *mNode;
    entry.mFadeOut = cutoff;

    if (SpatialShardData<T>* const data = mNode->mShardData; data != nullptr) {
      data->RemoveNode(mNode);
      mNode = data->Insert(entry);
    } else {
      mDb->mMapTree.erase(mNode);
      mNode = mDb->mMapTree.insert(mDb->mMapTree.end(), entry);
    }
  }

  /**
   * Address: 0x00501C10 (FUN_00501C10, sub_501C10)
   *
   * What it does:
   * Publishes the owner's new world box into its entry. An entry still in
   * the overflow map, or one whose box moved to another 16-unit cell, is
   * taken out and re-inserted into the leaf lane under its box's minimum
   * corner; otherwise the lane's bounds just widen to take the new box.
   */
  template <class T>
  void SpatialDBEntry<T>::UpdateBounds(const Wm3::AxisAlignedBox3f& bounds)
  {
    const bool requiresRelink = mNode->mShardData != nullptr ? HasSpatialCellChanged(mNode->mBox, bounds) : true;
    mNode->mBox = bounds;

    if (requiresRelink) {
      const SpatialEntry<T> entry = *mNode;
      if (entry.mShardData != nullptr) {
        entry.mShardData->RemoveNode(mNode);
      } else {
        mDb->mMapTree.erase(mNode);
      }

      mNode = ResolveSpatialLeafDataFromStoragePoint(bounds.Min, *mDb)->Insert(entry);
      return;
    }

    SpatialShardData<T>* const data = mNode->mShardData;
    data->mBounds.Min.x = std::min(data->mBounds.Min.x, bounds.Min.x);
    data->mBounds.Min.y = std::min(data->mBounds.Min.y, bounds.Min.y);
    data->mBounds.Min.z = std::min(data->mBounds.Min.z, bounds.Min.z);
    data->mBounds.Max.x = std::max(data->mBounds.Max.x, bounds.Max.x);
    data->mBounds.Max.y = std::max(data->mBounds.Max.y, bounds.Max.y);
    data->mBounds.Max.z = std::max(data->mBounds.Max.z, bounds.Max.z);

    if (data->mShard != nullptr) {
      PropagateBoundsToShardChain(data->mShard, data->mBounds);
    }
    ++data->mTimeSinceRecalc;
  }

  /**
   * Address: 0x00501BC0 (FUN_00501BC0, ??1SpatialDB_MeshInstance@Moho@@QAE@XZ)
   *
   * What it does:
   * Erases this entry from the leaf lane holding it (counts and all) or from
   * the overflow map, and clears `mDb`. `mNode` is left as it was; nothing
   * reads it again before the next `Register`.
   */
  template <class T>
  void SpatialDBEntry<T>::Unregister()
  {
    if (SpatialShardData<T>* const data = mNode->mShardData; data != nullptr) {
      data->RemoveNode(mNode);
    } else {
      mDb->mMapTree.erase(mNode);
    }
    mDb = nullptr;
  }

  /**
   * Address: 0x00504090 (FUN_00504090)
   *
   * What it does:
   * Walks all shard lanes in one mesh-instance view, collects node owners whose
   * AABBs intersect `bounds`, then appends matches from inline root shard data.
   */
  template <class T>
  [[maybe_unused]] std::int32_t CollectShardsInBoxIntoDestination(
    const Wm3::AxisAlignedBox3f& bounds,
    gpg::fastvector<T*>& destination,
    moho::SpatialDB<T>& db,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : db.mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::CollectInBox(shard, type, bounds, destination);
      }
    }

    db.mShardData.CollectInBoxFromData(bounds, type, destination);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Helper lane (no canonical address — inlined into
   * `SpatialDB<T>::CollectInVolume` at FUN_00504130 in the
   * binary). The previous recovery mis-attributed this helper to FUN_005040E0
   * which is in fact the bounding-sphere collect variant, recovered below.
   *
   * What it does:
   * Walks all shard lanes in one mesh-instance view, collects node owners that
   * intersect `volume`, then appends matches from inline root shard data.
   */
  template <class T>
  [[nodiscard]] std::int32_t CollectShardsInVolumeIntoDestination(
    CGeomSolid3* const volume,
    gpg::fastvector<T*>& destination,
    moho::SpatialDB<T>& db,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : db.mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::CollectInVolume(shard, type, volume, destination);
      }
    }

    db.mShardData.CollectInVolumeFromData(destination, type, volume);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Helper lane shared by `SpatialDB<T>::CollectInSphere` (the
   * canonical FUN_005040E0 body). Walks all child shards in one
   * mesh-instance view, sphere-collecting node owners that touch the
   * bounding sphere into `destination`, then runs one sphere collect over
   * the inline root shard-data lane. Returns the count of destination
   * entries appended so far.
   */
  template <class T>
  std::int32_t CollectShardsInSphereIntoDestination(
    const SphereBoundsProbe& probe,
    gpg::fastvector<T*>& destination,
    moho::SpatialDB<T>& db,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : db.mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::CollectInSphere(shard, type, probe, destination);
      }
    }

    db.mShardData.CollectInSphereFromData(type, probe, destination);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x00503F80 (FUN_00503F80, Moho::SpatialDB<T>::Collect)
   * Address: 0x0082BA50 (FUN_0082BA50 -- a register-order bridge into this
   * body for `SpatialDB<MeshInstance>`; zero callers, no references, a
   * linker-retained copy nothing runs. Formerly
   * `CollectMeshInstanceRegisterAdapter`, removed 2026-09-29.)
   *
   * What it does:
   * Collects requested entity lanes from shard hierarchy, inline root
   * shard-data lane, and every owner in the overflow map.
   */
  template <class T>
  std::int32_t SpatialDB<T>::Collect(
    gpg::fastvector<T*>& destination,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::Collect(shard, type, destination);
      }
    }

    SpatialShardData<T>::CollectFromData(type, destination, &mShardData);
    for (const SpatialEntry<T>& entry : mMapTree) {
      destination.push_back(entry.mOwner);
    }
    return static_cast<std::int32_t>(destination.size());
  }


  /**
   * Address: 0x00504040 (FUN_00504040, Moho::SpatialDB<T>::CollectInBox)
   * Address: 0x008C5A90 (FUN_008C5A90 -- a register-shape bridge into this
   * body; zero callers, no references, a linker-retained copy nothing runs.)
   *
   * What it does:
   * Walks all child shard pointers, collects unit entities intersecting
   * `bounds`, then collects from the inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInBox(
    gpg::fastvector<T*>& destination,
    const Wm3::AxisAlignedBox3f& bounds
  )
  {
    constexpr EEntityType kUnitType = static_cast<EEntityType>(kSpatialEntityTypeUnit);
    return CollectShardsInBoxIntoDestination(bounds, destination, *this, kUnitType);
  }

  /**
   * Address: 0x005040E0 (FUN_005040E0, Moho::SpatialDB<T>::CollectInSphere)
   *
   * What it does:
   * Walks all child shard pointers, sphere-collecting matching entity owners
   * that touch the bounding sphere into `destination`, then collects from
   * the inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInSphere(
    gpg::fastvector<T*>& destination,
    const EEntityType type,
    const SphereBoundsProbe& probe
  )
  {
    return CollectShardsInSphereIntoDestination(probe, destination, *this, type);
  }

  /**
   * Address: 0x00504130 (FUN_00504130, Moho::SpatialDB<T>::CollectInVolume)
   *
   * What it does:
   * Walks all child shard pointers, collects matching entities intersecting
   * `volume`, then collects from the inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInVolume(
    gpg::fastvector<T*>& destination,
    const EEntityType type,
    CGeomSolid3* const volume
  )
  {
    return CollectShardsInVolumeIntoDestination(volume, destination, *this, type);
  }

  /**
   * Address: 0x00504180 (FUN_00504180, Moho::SpatialDB<T>::CollectAllInVolume)
   * Address: 0x007E2AC0 (FUN_007E2AC0 -- a register-shape bridge into this
   * body for `SpatialDB<MeshInstance>`; zero callers, no references, a
   * linker-retained copy nothing runs.)
   *
   * What it does:
   * Collects all render-relevant entity lanes (unit/prop/projectile/entity)
   * intersecting `volume` with fade-threshold cull inputs.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectAllInVolume(
    gpg::fastvector<T*>& destination,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane
  )
  {
    constexpr EEntityType kAllRenderableTypes = static_cast<EEntityType>(
      kSpatialEntityTypeUnit | kSpatialEntityTypeProjectile | kSpatialEntityTypeProp | kSpatialEntityTypeEntity
    );

    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::FindInVolume(shard, kAllRenderableTypes, volume, supportSelector, fadePlane, destination);
      }
    }

    SpatialShardData<T>::FindInVolumeFromData(
      fadePlane,
      supportSelector,
      &mShardData,
      kAllRenderableTypes,
      volume,
      destination
    );
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x005041E0 (FUN_005041E0, Moho::SpatialDB<T>::CollectInView)
   * Address: 0x007AE170 (FUN_007AE170 -- a register-shape bridge into this
   * body; zero callers, no references, a linker-retained copy nothing runs.)
   *
   * What it does:
   * Collects entities intersecting camera view/fade lanes from child shards
   * and inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInView(
    GeomCamera3* const camera,
    gpg::fastvector<T*>& destination,
    const EEntityType type
  )
  {

    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        CollectInViewFromShard(camera, destination, shard, type);
      }
    }

    CollectInViewFromLeafData(destination, &mShardData, camera, type);
    return static_cast<std::int32_t>(destination.size());
  }


  /**
   * Address: 0x007DBEE0 (FUN_007DBEE0, ??0MeshMaterial@Moho@@QAE@XZ)
   */
  MeshMaterial::MeshMaterial()
    : mShaderAnnotation()
    , mAlbedoSheet()
    , mNormalsSheet()
    , mSpecularSheet()
    , mLookupSheet()
    , mSecondarySheet()
    , mEnvironmentSheet()
    , mShaderIndex(-1)
    , mCartographicTechnique()
    , mDepthTechnique()
    , mCartographicTechniqueResolved(false)
    , mDepthTechniqueResolved(false)
    , mPad8E_8F{}
  {}

  /**
   * Address: 0x007DBFC0 (FUN_007DBFC0, ??1MeshMaterial@Moho@@UAE@XZ)
   * Deleting thunk: 0x007DBFA0 (FUN_007DBFA0)
   */
  MeshMaterial::~MeshMaterial()
  {
    mDepthTechnique.tidy(true, 0U);
    mCartographicTechnique.tidy(true, 0U);
    mEnvironmentSheet.reset();
    mSecondarySheet.reset();
    mLookupSheet.reset();
    mSpecularSheet.reset();
    mNormalsSheet.reset();
    mAlbedoSheet.reset();
    mShaderAnnotation.tidy(true, 0U);
  }

  /**
   * Address: 0x007DCBF0 (FUN_007DCBF0, ??4MeshMaterial@Moho@@QAEAAV01@ABV01@@Z)
   *
   * What it does:
   * Copies annotation/texture-sheet handles and runtime tags from one material.
   */
  MeshMaterial& MeshMaterial::operator=(const MeshMaterial& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    mShaderAnnotation.assign_owned(rhs.mShaderAnnotation.view());
    mAlbedoSheet = rhs.mAlbedoSheet;
    mNormalsSheet = rhs.mNormalsSheet;
    mSpecularSheet = rhs.mSpecularSheet;
    mLookupSheet = rhs.mLookupSheet;
    mSecondarySheet = rhs.mSecondarySheet;
    mEnvironmentSheet = rhs.mEnvironmentSheet;
    mShaderIndex = rhs.mShaderIndex;
    mCartographicTechnique.assign_owned(rhs.mCartographicTechnique.view());
    mDepthTechnique.assign_owned(rhs.mDepthTechnique.view());
    mCartographicTechniqueResolved = rhs.mCartographicTechniqueResolved;
    mDepthTechniqueResolved = rhs.mDepthTechniqueResolved;
    return *this;
  }

  /**
   * Address: 0x007DC760 (FUN_007DC760,
   * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABVRMeshBlueprintLOD@2@PAVCResourceWatcher@2@@Z)
   *
   * What it does:
   * Builds one material from one mesh LOD blueprint descriptor.
   */
  boost::shared_ptr<MeshMaterial>
  MeshMaterial::Create(const RMeshBlueprintLOD& blueprintLod, CResourceWatcher* const resourceWatcher)
  {
    return Create(
      blueprintLod.mShaderName,
      blueprintLod.mAlbedoName,
      blueprintLod.mNormalsName,
      blueprintLod.mSpecularName,
      blueprintLod.mLookupName,
      blueprintLod.mSecondaryName,
      resourceWatcher
    );
  }

  /**
   * Address: 0x007DC1B0 (FUN_007DC1B0,
   * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00000PAVCResourceWatcher@2@@Z)
   *
   * What it does:
   * Creates one mesh material and resolves per-texture sheet handles from paths.
   */
  boost::shared_ptr<MeshMaterial> MeshMaterial::Create(
    const msvc8::string& shaderName,
    const msvc8::string& albedoName,
    const msvc8::string& normalsName,
    const msvc8::string& specularName,
    const msvc8::string& lookupName,
    const msvc8::string& secondaryName,
    CResourceWatcher* const resourceWatcher
  )
  {
    boost::shared_ptr<MeshMaterial> material(new MeshMaterial());
    const msvc8::string resolvedShaderName = ResolveShaderAnnotationName(shaderName);
    material->mShaderAnnotation.assign_owned(resolvedShaderName.view());
    AssignMaterialTextureSheet(material->mAlbedoSheet, albedoName, resourceWatcher);
    AssignMaterialTextureSheet(material->mNormalsSheet, normalsName, resourceWatcher);
    AssignMaterialTextureSheet(material->mSpecularSheet, specularName, resourceWatcher);
    AssignMaterialTextureSheet(material->mLookupSheet, lookupName, resourceWatcher);
    AssignMaterialTextureSheet(material->mSecondarySheet, secondaryName, resourceWatcher);

    // Pump the sound engine after the texture loads above, so a long material
    // build cannot starve audio. MSVC inlined this at 0x007DC71E: gate on
    // `snd_ExtraDoWorkCalls`, then `sSoundConfiguration->mTime
    // .ElapsedMilliseconds()` against flt_E4F744 (0000c842 = 100.0f, verified
    // from the PE) with `fcomip`/`jbe`, i.e. fire only when elapsed > 100ms.
    // That is exactly SND_FrameExtraDoWorkTick (0x004D8F90), so the source line
    // is the call to it.
    SND_FrameExtraDoWorkTick();

    return material;
  }

  /**
   * Address: 0x007DC7A0 (FUN_007DC7A0, ??0MeshLOD@Moho@@IAE@XZ)
   *
   * What it does:
   * Initializes one empty runtime LOD lane with default cutoff/material state
   * and null shared-resource handles.
   */
  MeshLOD::MeshLOD()
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res()
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {}

  /**
   * Address: 0x007DC8C0 (FUN_007DC8C0,
   * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@ABVRMeshBlueprintLOD@1@V?$shared_ptr@VMeshMaterial@Moho@@@3@PAVCResourceWatcher@1@@Z)
   *
   * What it does:
   * Initializes one runtime LOD from blueprint/material/resource fallback state.
   */
  MeshLOD::MeshLOD(
    const RMeshBlueprintLOD& blueprintLod,
    const boost::shared_ptr<RScmResource> previousResourceArg,
    const boost::shared_ptr<MeshMaterial> materialArg,
    CResourceWatcher* const ownerWatcher
  )
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res()
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {
    Load(blueprintLod, previousResourceArg, materialArg, ownerWatcher);
  }

  /**
   * Address: 0x007DCA40 (FUN_007DCA40,
   * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
   *
   * What it does:
   * Initializes one runtime LOD from already-resolved resource/material
   * pointers and clears batch/runtime flag lanes.
   */
  MeshLOD::MeshLOD(const boost::shared_ptr<RScmResource> resourceArg, const boost::shared_ptr<MeshMaterial> materialArg)
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res(resourceArg)
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {
    if (materialArg) {
      mat = *materialArg;
      return;
    }

    MeshMaterial defaultMaterial;
    mat = defaultMaterial;
  }

  /**
   * Address: 0x007DD4D0 (FUN_007DD4D0)
   *
   * What it does:
   * Releases loaded resource/material state for this LOD.
   */
  void MeshLOD::Clear()
  {
    res.reset();
    lodBlueprintCopy.reset();
    mat = MeshMaterial();
    ResetBatches();
    cutoff = 1000.0f;
  }

  /**
   * Address: 0x007DD190 (FUN_007DD190)
   *
   * What it does:
   * Clears cached batch handles for this LOD.
   */
  void MeshLOD::ResetBatches()
  {
    staticBatch.reset();
    dynamicBatch.reset();
  }

  namespace
  {
    /**
     * Address: 0x007E8C70 (FUN_007E8C70, sub_7E8C70)
     *
     * IDA signature:
     * Moho::HardwareMeshBatch* __usercall sub_7E8C70@<eax>(
     *   char remap@<bl>, int lod@<edi>,
     *   boost::shared_ptr<RScmResource> referenceResource,
     *   boost::shared_ptr<RScmResource> currentResource);
     *
     * What it does:
     * Shared lazy-init factory behind MeshLOD::GetStaticBatch/GetSkinnedBatch.
     * Allocates and initializes one GPU-instanced HardwareMeshBatch for a LOD,
     * but only when the LOD has a current mesh resource, the batch is either
     * non-remapped or has a reference resource, and runtime mesh instancing is
     * enabled for the active device. Returns the batch, or nullptr when the
     * batch cannot be built. The `boost::shared_ptr` reference/current arguments
     * are consumed (released) exactly once, so the caller passes retained copies.
     */
    MeshBatch* BuildHardwareMeshBatchForLod(
      const bool remapToReferenceResource,
      MeshLOD* const lod,
      boost::shared_ptr<RScmResource> referenceResource,
      boost::shared_ptr<RScmResource> currentResource
    )
    {
      // Gate (binary: `a2 && a4.res && (!a1 || result.res)`): need a LOD, a
      // current resource, and — for remapped batches — a reference resource.
      if (lod == nullptr || !currentResource || (remapToReferenceResource && !referenceResource)) {
        return nullptr;
      }

      // Instancing capability gate: with no hardware instancing the LOD keeps a
      // null cached batch and falls back to the non-batched draw path.
      if (!gpg::gal::MeshInstancingEnabled()) {
        return nullptr;
      }

      return new HardwareMeshBatch(lod, remapToReferenceResource, referenceResource, currentResource);
    }
  } // namespace

  /**
   * Address: 0x007DD220 (FUN_007DD220,
   * ?GetStaticBatch@MeshLOD@Moho@@QAE?AV?$shared_ptr@VMeshBatch@Moho@@@boost@@XZ)
   *
   * IDA signature:
   * boost::shared_ptr<MeshBatch>* __stdcall Moho::MeshLOD::GetStaticBatch(
   *   MeshLOD* this, boost::shared_ptr<MeshBatch>* out);
   *
   * What it does:
   * Lazily builds and caches this LOD's static (non-remapped) hardware mesh
   * batch, then returns a retained copy in `outBatch`. The reference resource is
   * the LOD's `previousResource`, the current resource is `res`.
   */
  boost::shared_ptr<MeshBatch>& MeshLOD::GetStaticBatch(boost::shared_ptr<MeshBatch>& outBatch)
  {
    if (!staticBatch) {
      MeshBatch* const built = BuildHardwareMeshBatchForLod(false, this, previousResource, res);
      staticBatch.reset(built);
    }
    outBatch = staticBatch;
    return outBatch;
  }

  /**
   * Address: 0x007DD420 (FUN_007DD420,
   * ?GetSkinnedBatch@MeshLOD@Moho@@QAE?AV?$shared_ptr@VMeshBatch@Moho@@@boost@@XZ)
   *
   * IDA signature:
   * boost::shared_ptr<MeshBatch>* __userpurge Moho::MeshLOD::GetSkinnedBatch(
   *   MeshLOD* this, boost::shared_ptr<MeshBatch>* out);
   *
   * What it does:
   * Lazily builds and caches this LOD's skinned (bone-remapped) hardware mesh
   * batch, then returns a retained copy in `outBatch`. Identical to
   * GetStaticBatch except the reference-resource bone remap is enabled.
   */
  boost::shared_ptr<MeshBatch>& MeshLOD::GetSkinnedBatch(boost::shared_ptr<MeshBatch>& outBatch)
  {
    if (!dynamicBatch) {
      MeshBatch* const built = BuildHardwareMeshBatchForLod(true, this, previousResource, res);
      dynamicBatch.reset(built);
    }
    outBatch = dynamicBatch;
    return outBatch;
  }

  /**
   * Address: 0x007DD5D0 (FUN_007DD5D0, ?SetCutoff@MeshLOD@Moho@@QAEXM@Z)
   *
   * What it does:
   * Stores one LOD cutoff distance threshold.
   */
  void MeshLOD::SetCutoff(const float cutoffValue)
  {
    cutoff = cutoffValue;
  }

  /**
   * Address: 0x007DCED0 (FUN_007DCED0)
   *
   * What it does:
   * Reloads model/material resources from one blueprint LOD entry.
   */
  void MeshLOD::Load(
    const RMeshBlueprintLOD& blueprintLod,
    const boost::shared_ptr<RScmResource> previousResourceArg,
    const boost::shared_ptr<MeshMaterial> materialArg,
    CResourceWatcher* const ownerWatcher
  )
  {
    Clear();

    lodBlueprintCopy.reset(new RMeshBlueprintLOD(blueprintLod));
    // 0x007DCF58: the LOD's model path goes straight through the shared
    // `GetModel` resource lane; there is no local caching or empty-path guard.
    res = GetModel(blueprintLod.mMeshName.c_str(), ownerWatcher);
    previousResource = previousResourceArg ? previousResourceArg : res;
    cutoff = blueprintLod.mLodCutoff;
    scrolling = blueprintLod.mScrolling;
    occlude = blueprintLod.mOcclude;
    silhouette = blueprintLod.mSilhouette;

    if (materialArg) {
      mat = *materialArg;
    } else {
      const boost::shared_ptr<MeshMaterial> createdMaterial = MeshMaterial::Create(blueprintLod, ownerWatcher);
      if (createdMaterial) {
        mat = *createdMaterial;
      }
    }
  }

  /**
   * Address: 0x007DCD60 (FUN_007DCD60, ??1MeshLOD@Moho@@UAE@XZ)
   */
  MeshLOD::~MeshLOD()
  {
    Clear();
  }

  /**
   * Address: 0x007DD5E0 (FUN_007DD5E0, ??0Mesh@Moho@@IAE@XZ)
   *
   * What it does:
   * Initializes base mesh lanes and clears resource/material/LOD ownership.
   */
  Mesh::Mesh()
    : bp(nullptr)
    , material()
    , unk2C(0)
    , lods()
    , unk3C(0)
  {
  }

  /**
   * Address: 0x007DD680 (FUN_007DD680,
   * ??0Mesh@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  Mesh::Mesh(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg)
    : Mesh()
  {
    Load(blueprint, materialArg);
  }

  /**
   * Address: 0x007DD750 (FUN_007DD750,
   * ??0Mesh@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
   *
   * What it does:
   * Initializes one mesh with a pre-resolved resource/material LOD lane.
   */
  Mesh::Mesh(const boost::shared_ptr<RScmResource> resourceArg, const boost::shared_ptr<MeshMaterial> materialArg)
    : Mesh()
  {
    (void)CreateLOD(resourceArg, materialArg);
  }

  /**
   * Address: 0x007E5250 (FUN_007E5250)
   * Address: 0x0087CFF0 (FUN_0087CFF0)
   * Address: 0x0087D020 (FUN_0087D020)
   * Address: 0x0087D050 (FUN_0087D050)
   *
   * What it does:
   * Destroys one half-open `MeshLOD*` range and returns the caller-supplied
   * completion flag unchanged.
   */
  [[maybe_unused]] std::uint8_t DestroyMeshLodPointerRange(
    MeshLOD** begin,
    MeshLOD** const end,
    const std::uint8_t completionFlag
  ) noexcept
  {
    for (MeshLOD** it = begin; it != end; ++it) {
      if (*it != nullptr) {
        delete *it;
      }
    }
    return completionFlag;
  }

  /**
   * Address: 0x007DDAC0 (FUN_007DDAC0)
   */
  void Mesh::Clear()
  {
    (void)DestroyMeshLodPointerRange(lods.begin(), lods.end(), 0u);
    lods.clear();
    material.reset();
    bp = nullptr;
  }

  /**
   * Address: 0x007DE030 (FUN_007DE030)
   *
   * What it does:
   * Resets cached batch handles for every loaded LOD.
   */
  void Mesh::ResetBatches()
  {
    for (MeshLOD** it = lods.begin(); it && it != lods.end(); ++it) {
      if (*it) {
        (*it)->ResetBatches();
      }
    }
  }

  /**
   * Address: 0x007DD880 (FUN_007DD880, ??1Mesh@Moho@@UAE@XZ)
   */
  Mesh::~Mesh()
  {
    Clear();
  }

  /**
   * Address: 0x007DDB50 (FUN_007DDB50,
   * ?Load@Mesh@Moho@@AAEXPBVRMeshBlueprint@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  void Mesh::Load(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    Clear();
    bp = blueprint;
    material = materialArg;

    if (!bp) {
      return;
    }

    const RMeshBlueprintLOD* const begin = bp->mLods.begin();
    if (!begin) {
      return;
    }

    for (const RMeshBlueprintLOD* lod = begin; lod != bp->mLods.end(); ++lod) {
      CreateLOD(*lod, materialArg);
    }

    if (!lods.empty() && lods.back()) {
      lods.back()->useDissolve = 1;
    }
  }

  /**
   * Address: 0x007DDC50 (FUN_007DDC50,
   * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@ABVRMeshBlueprintLOD@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshLOD* Mesh::CreateLOD(const RMeshBlueprintLOD& blueprintLod, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    boost::shared_ptr<RScmResource> previousResource;
    if (!lods.empty() && lods.front()) {
      previousResource = lods.front()->res;
    }

    MeshLOD* const lod = new MeshLOD(blueprintLod, previousResource, materialArg, this);
    lods.push_back(lod);
    return lod;
  }

  /**
   * Address: 0x007DDE50 (FUN_007DDE50,
   * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@5@@Z)
   *
   * What it does:
   * Adds one direct resource/material-backed mesh LOD entry.
   */
  MeshLOD* Mesh::CreateLOD(const boost::shared_ptr<RScmResource> resourceArg, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    MeshLOD* const lod = new MeshLOD(resourceArg, materialArg);
    lods.push_back(lod);
    return lod;
  }

  /**
   * Address: 0x007DD930 (FUN_007DD930, Moho::Mesh::GetSortOrder)
   *
   * What it does:
   * Returns the mesh blueprint sort-order lane when present, else `0.0f`.
   */
  float Mesh::GetSortOrder() const
  {
    return bp != nullptr ? bp->mSortOrder : 0.0f;
  }

  /**
   * Address: 0x007DD950 (FUN_007DD950, ?GetResource@Mesh@Moho@@QBE?AV?$shared_ptr@VRScmResource@Moho@@@boost@@H@Z)
   */
  boost::shared_ptr<RScmResource> Mesh::GetResource(const std::int32_t /*lodIndex*/) const
  {
    MeshLOD* const* const begin = lods.begin();
    if (!begin || begin == lods.end() || !*begin) {
      return {};
    }

    return (*begin)->res;
  }

  /**
   * Address: 0x007DDA50 (FUN_007DDA50, ?ComputeLOD@Mesh@Moho@@QBEPBVMeshLOD@2@M@Z)
   *
   * What it does:
   * Walks mesh LODs in order and returns the first lane accepted by cutoff
   * and dissolve rules for the supplied distance.
   */
  const MeshLOD* Mesh::ComputeLOD(const float distance) const
  {
    MeshLOD* const* const begin = lods.begin();
    if (begin == nullptr) {
      return nullptr;
    }

    MeshLOD* const* const end = lods.end();
    if (begin == end) {
      return nullptr;
    }

    for (MeshLOD* const* it = begin; it != end; ++it) {
      const MeshLOD* const lod = *it;
      if (lod == nullptr) {
        continue;
      }

      const float cutoff = lod->cutoff;
      if (cutoff <= 0.0f) {
        return lod;
      }

      if (lod->useDissolve != 0u) {
        if (distance <= (cutoff + ren_MeshDissolve)) {
          return lod;
        }
        return nullptr;
      }

      if (distance <= cutoff) {
        return lod;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x007DDA20 (FUN_007DDA20, ?GetMaxCutoff@Mesh@Moho@@QBEMXZ)
   *
   * What it does:
   * Returns the cutoff value from the last loaded mesh LOD, or zero when no
   * LODs are available.
   */
  float Mesh::GetMaxCutoff() const
  {
    MeshLOD* const* const begin = lods.begin();
    if (begin == nullptr) {
      return 0.0f;
    }

    MeshLOD* const* const end = lods.end();
    if (begin == end) {
      return 0.0f;
    }

    const MeshLOD* const lastLod = *(end - 1);
    return lastLod != nullptr ? lastLod->cutoff : 0.0f;
  }

  /**
   * Address: 0x007DDFC0 (FUN_007DDFC0, ?OnResourceChanged@Mesh@Moho@@EAEXVStrArg@gpg@@@Z)
   */
  void Mesh::OnResourceChanged(const gpg::StrArg /*resourcePath*/)
  {
    // Binary path may resync global resource manager before reloading watched assets.
    Load(bp, material);
  }

  /**
   * Address: 0x007DAF00 (FUN_007DAF00,
   * ??0MeshKey@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshKey::MeshKey(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> meshMaterial)
    : blueprint(blueprint)
    , meshMaterial(meshMaterial)
  {}

  /**
   * Address: 0x007DF6E0 (FUN_007DF6E0, copy ctor)
   */
  MeshKey::MeshKey(const MeshKey& rhs)
    : blueprint(rhs.blueprint)
    , meshMaterial(rhs.meshMaterial)
  {}

  /**
   * Address: 0x007DAF60 (FUN_007DAF60, ??1MeshKey@Moho@@QAE@XZ)
   * Deleting thunk: 0x007DAFC0 (FUN_007DAFC0, sub_7DAFC0)
   */
  MeshKey::~MeshKey() = default;

  bool MeshKey::Equals(const MeshKey& rhs) const noexcept
  {
    return !LessThan(rhs) && !rhs.LessThan(*this);
  }

  /**
   * No standalone binary address: this trivial two-field comparison is
   * compiler-inlined at every call site. `0x007E5B20` (FUN_007E5B20) was
   * previously cited here in error -- that address is actually an RB-tree
   * lower-bound/insertion-point traversal (distinct from the already-typed
   * `MeshCacheTreeLowerBound` at 0x007E6050) that happens to inline this
   * same two-field comparison internally; see the by-source reconstruction
   * report for the traced evidence.
   *
   * What it does:
   * Orders keys lexicographically by (blueprint pointer, material object pointer).
   */
  bool MeshKey::LessThan(const MeshKey& rhs) const noexcept
  {
    const std::uintptr_t lhsBlueprint = PointerOrderKey(blueprint);
    const std::uintptr_t rhsBlueprint = PointerOrderKey(rhs.blueprint);
    if (lhsBlueprint < rhsBlueprint) {
      return true;
    }
    if (lhsBlueprint > rhsBlueprint) {
      return false;
    }

    return PointerOrderKey(meshMaterial.get()) < PointerOrderKey(rhs.meshMaterial.get());
  }

  std::uint8_t MeshInstance::sFrameCounter = 0;
  float MeshInstance::sCurrentInterpolant = 0.0f;

  /**
   * Address: 0x007DE6A0 (FUN_007DE6A0, ?SetCurrentInterpolant@MeshInstance@Moho@@SAXM@Z)
   *
   * What it does:
   * Advances the global mesh frame counter and snapshots the current render
   * frame interpolation value.
   */
  // TEMPORARY PROBE (do not commit)
  static std::set<const void*>& ProbePreviewMeshSet();

  void MeshInstance::SetCurrentInterpolant()
  {
    ++sFrameCounter;
    sCurrentInterpolant = REN_GetSimDeltaSeconds();

    { // TEMPORARY PROBE (do not commit) -- roll call of every live preview/ghost mesh
      static unsigned frames = 0;
      if ((++frames % 300u) == 0u && !ProbePreviewMeshSet().empty()) {
        for (const void* const entry : ProbePreviewMeshSet()) {
          auto* const inst = static_cast<MeshInstance*>(const_cast<void*>(entry));
          inst->UpdateInterpolatedFields();
          gpg::Warnf("[PVLIVE] inst=%p color=%08X hidden=%d pos=(%.1f,%.1f,%.1f)", entry,
                     static_cast<unsigned>(inst->color), static_cast<int>(inst->isHidden),
                     inst->interpolatedPosition.x, inst->interpolatedPosition.y, inst->interpolatedPosition.z);
        }
      }
    }
  }

  /**
   * Address: 0x007DE060 (FUN_007DE060,
   * ??0MeshInstance@Moho@@QAE@PAV?$SpatialDB@VMeshInstance@Moho@@@1@HIV?$shared_ptr@VMesh@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_N@Z)
   */
  // TEMPORARY PROBE (do not commit)
  static std::set<const void*>& ProbePreviewMeshSet()
  {
    static std::set<const void*> sSet;
    return sSet;
  }

  MeshInstance::MeshInstance(
    const Wm3::Vec3f& scaleArg,
    SpatialDB<MeshInstance>* const spatialDbStorage,
    const std::int32_t gameTickArg,
    const std::int32_t colorArg,
    const bool isStaticPoseArg,
    const boost::shared_ptr<Mesh> meshArg
  )
    : TDatListItem<MeshInstance, void>()
    , db()
    , mesh(meshArg)
    , color(colorArg)
    , meshColor(0.0f)
    , unk24(0)
    , isHidden(0)
    , isReflected(1)
    , pad_2A_2B{}
    , gameTick(gameTickArg)
    , uniformScale(1.0f)
    , scale(scaleArg)
    , endTransform(IdentityTransform())
    , startTransform(IdentityTransform())
    , curOrientation(1.0f, 0.0f, 0.0f, 0.0f)
    , interpolatedPosition(0.0f, 0.0f, 0.0f)
    , scroll1(0.0f, 0.0f)
    , scroll2(0.0f, 0.0f)
    , hasStanceUpdatePending(1)
    , isStaticPose(static_cast<std::uint8_t>(isStaticPoseArg ? 1 : 0))
    , isLocked(0)
    , pad_A7(0)
    , startPose()
    , endPose()
    , curPose()
    , dissolve(1.0f)
    , parameters(0.0f)
    , fractionCompleteParameter(1.0f)
    , fractionHealthParameter(1.0f)
    , lifetimeParameter(0.0f)
    , auxiliaryParameter(0.0f)
    , frameCounter(0xFFu)
    , interpolationStateFresh(0)
    , pad_DA_DB{}
    , currInterpolant(-1.0f)
    , sphere{}
    , xMin(NanValue())
    , yMin(NanValue())
    , zMin(NanValue())
    , xMax(NanValue())
    , yMax(NanValue())
    , zMax(NanValue())
    , box{}
    , renderMinX(NanValue())
    , renderMinY(NanValue())
    , renderMinZ(NanValue())
    , renderMaxX(NanValue())
    , renderMaxY(NanValue())
    , renderMaxZ(NanValue())
    , boundsValid(1)
    , pad_15D_15F{}
  {
    sphere.Center = {NanValue(), NanValue(), NanValue()};
    sphere.Radius = NanValue();
    const boost::shared_ptr<const CAniSkel> skeleton = ResolveInitialPoseSkeleton(meshArg, isStaticPoseArg);
    curPose.reset(new CAniPose(skeleton, 1.0f));

    db.Register(spatialDbStorage, this, kMeshSpatialDbRoutingMask);
    const float dissolveCutoff = ComputeSpatialDissolveCutoff(meshArg);
    db.UpdateDissolveCutoff(dissolveCutoff);

    // TEMPORARY PROBE (do not commit)
    if (colorArg == static_cast<std::int32_t>(0xD800D800u) || colorArg == static_cast<std::int32_t>(0xFF00FF00u)) {
      ProbePreviewMeshSet().insert(this);
      gpg::Warnf("[PVMESH] + inst=%p color=%08X live=%u", static_cast<void*>(this),
                 static_cast<unsigned>(colorArg), static_cast<unsigned>(ProbePreviewMeshSet().size()));
    }
  }

  /**
   * Address: 0x007DE550 (FUN_007DE550, ??1MeshInstance@Moho@@UAE@XZ)
   * Address: 0x007DE510 (FUN_007DE510, the scalar deleting destructor in
   * vftable 0xE3F48C's only slot: this body, then `operator delete` on flag
   * bit 0. `delete instance` reaches it; it was hand-written as a virtual
   * `Release(int)`.)
   */
  MeshInstance::~MeshInstance()
  {
    // TEMPORARY PROBE (do not commit)
    if (ProbePreviewMeshSet().erase(this) != 0) {
      gpg::Warnf("[PVMESH] - inst=%p color=%08X live=%u", static_cast<void*>(this),
                 static_cast<unsigned>(color), static_cast<unsigned>(ProbePreviewMeshSet().size()));
    }
    // The rest is member destruction, as 0x007DE550 is: the pose and mesh
    // shared_ptrs in reverse order, `db` (its inlined `if (mDb)` unregister at
    // 0x007DE663), then the TDatListItem base's unlink.
  }

  /**
   * Address: 0x007DADD0 (FUN_007DADD0, ?GetMesh@MeshInstance@Moho@@QBE?AV?$shared_ptr@VMesh@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<Mesh> MeshInstance::GetMesh() const
  {
    return mesh;
  }

  /**
   * Address: 0x007DE6C0 (FUN_007DE6C0, ?Cull@MeshInstance@Moho@@QAEX_N@Z)
   *
   * What it does:
   * Stores one per-instance hidden/cull visibility flag.
   */
  void MeshInstance::Cull(const bool hidden)
  {
    isHidden = hidden ? 1u : 0u;
  }

  /**
   * Address: 0x007DE6D0 (FUN_007DE6D0, ?Reflect@MeshInstance@Moho@@QAEX_N@Z)
   *
   * What it does:
   * Clears one per-instance reflection-visibility flag.
   */
  void MeshInstance::Reflect([[maybe_unused]] const bool reflected)
  {
    isReflected = 0u;
  }

  /**
   * Address: 0x007DE880 (FUN_007DE880, ?SetParameter@MeshInstance@Moho@@QAEXW4PARAM@MeshMaterial@2@M@Z)
   *
   * What it does:
   * Writes one shader parameter lane selected by `MeshMaterial::PARAM`.
   */
  void MeshInstance::SetParameter(const MeshMaterial::PARAM parameter, const float value)
  {
    switch (parameter) {
    case MeshMaterial::PARAM_GENERIC:
      parameters = value;
      break;
    case MeshMaterial::PARAM_FRACTION_COMPLETE:
      fractionCompleteParameter = value;
      break;
    case MeshMaterial::PARAM_FRACTION_HEALTH:
      fractionHealthParameter = value;
      break;
    case MeshMaterial::PARAM_LIFETIME:
      lifetimeParameter = value;
      break;
    case MeshMaterial::PARAM_AUXILIARY:
      auxiliaryParameter = value;
      break;
    default:
      break;
    }
  }

  /**
   * Address: 0x007DE850 (FUN_007DE850, ?SetInterpolantScale@MeshInstance@Moho@@QAEXM@Z)
   *
   * What it does:
   * Stores one per-instance interpolation scale and invalidates cached
   * interpolant lane for refresh.
   */
  void MeshInstance::SetInterpolantScale(const float interpolantScale)
  {
    uniformScale = interpolantScale;
    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
  }

  /**
   * Address: 0x007DE8C0 (FUN_007DE8C0, ?SetScale@MeshInstance@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Stores one per-instance render scale vector.
   */
  void MeshInstance::SetScale(const Wm3::Vec3f& scaleArg)
  {
    scale = scaleArg;
  }

  /**
   * Address: 0x007DE8E0 (FUN_007DE8E0, ?SetColor@MeshInstance@Moho@@QAEXI@Z)
   *
   * What it does:
   * Stores one packed per-instance color value.
   */
  void MeshInstance::SetColor(const std::uint32_t colorArg)
  {
    color = static_cast<std::int32_t>(colorArg);
  }

  /**
   * Address: 0x007DE900 (FUN_007DE900, ?SetScroll@MeshInstance@Moho@@QAEXABV?$Vector2@M@Wm3@@0@Z)
   *
   * What it does:
   * Stores two texture-scroll vector lanes for this mesh instance.
   */
  void MeshInstance::SetScroll(const Wm3::Vec2f& scroll1Arg, const Wm3::Vec2f& scroll2Arg)
  {
    scroll1 = scroll1Arg;
    scroll2 = scroll2Arg;
  }

  /**
   * Address: 0x007DF140 (FUN_007DF140, ?ResetBatches@MeshInstance@Moho@@QAEXXZ)
   *
   * What it does:
   * Resets mesh LOD batch handles for this instance when a mesh owner exists.
   */
  void MeshInstance::ResetBatches()
  {
    Mesh* const meshObject = mesh.get();
    if (meshObject != nullptr) {
      meshObject->ResetBatches();
    }
  }

  /**
   * Address: 0x007DE890 (FUN_007DE890, ?SetDissolve@MeshInstance@Moho@@QAEXM@Z)
   *
   * What it does:
   * Clamps and stores dissolve value in `[0.0f, 1.0f]`.
   */
  void MeshInstance::SetDissolve(const float dissolveAmount)
  {
    float clampedValue = 1.0f;
    if (dissolveAmount < 1.0f) {
      clampedValue = dissolveAmount;
    }

    if (clampedValue < 0.0f) {
      dissolve = 0.0f;
      return;
    }
    dissolve = clampedValue;
  }

  /**
   * Address: 0x007DE930 (FUN_007DE930, ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0@Z)
   *
   * What it does:
   * Applies start/end stance transforms, flags interpolation refresh, and
   * marks stance/bounds state dirty when transform data changed.
   */
  void MeshInstance::SetStance(const VTransform& startTransformArg, const VTransform& endTransformArg)
  {
    const bool changed = !Vec3EqualExact(endTransform.pos_, endTransformArg.pos_) ||
      !QuatEqualExact(endTransform.orient_, endTransformArg.orient_) ||
      !Vec3EqualExact(startTransform.pos_, startTransformArg.pos_) ||
      !QuatEqualExact(startTransform.orient_, startTransformArg.orient_);
    if (!changed) {
      hasStanceUpdatePending = 0;
      return;
    }

    hasStanceUpdatePending = 1;
    endTransform = endTransformArg;
    startTransform = startTransformArg;
    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
    boundsValid = 1;

    // Same republish as the pose overload, at 0x007DEA0B..0x007DEA1A.
    db.UpdateBounds(GetSweptAlignedBox());
  }

  /**
   * Address: 0x007DE6E0 (FUN_007DE6E0, ?LockPose@MeshInstance@Moho@@QAEX_N@Z)
   *
   * What it does:
   * Toggles static-pose lock state; when locking, snapshots `curPose` into
   * `endPose`, and when unlocking, invalidates interpolation cache lanes.
   */
  void MeshInstance::LockPose(const bool lockPose)
  {
    const std::uint8_t lockValue = lockPose ? 1u : 0u;
    if (isLocked == lockValue) {
      return;
    }

    isLocked = lockValue;
    if (lockValue != 0u) {
      CAniPose* const endPoseValue = endPose.get();
      if (endPoseValue != nullptr) {
        endPoseValue->CopyPose(curPose.get(), true);
      }
      return;
    }

    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
  }

  /**
   * Address: 0x007DEA30 (FUN_007DEA30,
   * ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0V?$shared_ptr@VCAniPose@Moho@@@boost@@1@Z)
   *
   * What it does:
   * Applies the static-pose stance lane used by UserEntity updates, including
   * pose-handle assignment and optional transform/bounds refresh.
   */
  void MeshInstance::SetStance(
    const VTransform& startTransformArg,
    const VTransform& endTransformArg,
    const bool forceRefresh,
    boost::shared_ptr<CAniPose> startPoseArg,
    boost::shared_ptr<CAniPose> endPoseArg
  )
  {
    if (isStaticPose == 0) {
      SetStance(startTransformArg, endTransformArg);
      return;
    }

    startPose = startPoseArg;
    endPose = endPoseArg;

    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
    hasStanceUpdatePending = 1;

    const bool changed = !Vec3EqualExact(endTransform.pos_, endTransformArg.pos_) ||
      !QuatEqualExact(endTransform.orient_, endTransformArg.orient_) ||
      !Vec3EqualExact(startTransform.pos_, startTransformArg.pos_) ||
      !QuatEqualExact(startTransform.orient_, startTransformArg.orient_);
    if (!changed && !forceRefresh) {
      return;
    }

    endTransform = endTransformArg;
    startTransform = startTransformArg;
    boundsValid = 1;

    // Republish the swept bounds into this instance's spatial-db entry
    // (0x007DEBD4..0x007DEBE4: set the dirty byte, GetSweptAlignedBox, then
    // UpdateBounds on `this + 0x0C`, which is `db`). Without it the entry keeps
    // the NaN box the ctor gave it, `MeshRenderer::Batch`'s
    // CollectAllInVolume never matches the instance, and the mesh is never
    // drawn at all.
    db.UpdateBounds(GetSweptAlignedBox());
  }

  /**
   * Address: 0x007DEC80 (FUN_007DEC80, ?UpdateInterpolatedFields@MeshInstance@Moho@@ABEXXZ)
   *
   * What it does:
   * Recomputes interpolated transform fields for the current global
   * interpolant. When a stance update is pending, also re-blends the
   * skinned pose (`curPose`) from `startPose`/`endPose` for static-pose
   * (unit) instances that are not locked, and rebuilds the world
   * sphere/oriented-box/AABB from the mesh resource's own local bounds.
   */
  void MeshInstance::UpdateInterpolatedFields()
  {
    // Ground truth (FUN_007DEC80.c) enters when the interpolant changed AND
    // (the frame counter is stale OR interpolation state isn't fresh yet
    // this frame) - i.e. it returns early only when NEITHER half fired.
    // SetStance resets currInterpolant to -1.0f but leaves frameCounter/
    // interpolationStateFresh untouched, so the second half is what lets a
    // fresh stance be picked up even on a call where sCurrentInterpolant
    // already happens to equal that reset sentinel.
    if (sCurrentInterpolant == currInterpolant ||
        (frameCounter == sFrameCounter && interpolationStateFresh != 0u)) {
      return;
    }

    float interpolation = uniformScale * sCurrentInterpolant;
    currInterpolant = sCurrentInterpolant;
    interpolationStateFresh = 1;
    interpolation = Clamp01(interpolation);

    const Wm3::Vec3f startPos = startTransform.pos_;
    const Wm3::Vec3f endPos = endTransform.pos_;
    interpolatedPosition.x = endPos.x + (startPos.x - endPos.x) * interpolation;
    interpolatedPosition.y = endPos.y + (startPos.y - endPos.y) * interpolation;
    interpolatedPosition.z = endPos.z + (startPos.z - endPos.z) * interpolation;

    Wm3::Quatf blendedOrientation{};
    QuatLERP(&startTransform.orient_, &endTransform.orient_, &blendedOrientation, interpolation);
    curOrientation = blendedOrientation;

    if (hasStanceUpdatePending == 0) {
      return;
    }

    // Ground truth reads the LOD-0 mesh resource unconditionally here and
    // dereferences it with no null check; `mesh` is set once at construction
    // and never cleared, so this should never actually be empty on a live
    // instance. Guarded anyway, matching GetSweptAlignedBox's own established
    // pattern in this class.
    const boost::shared_ptr<RScmResource> resource = mesh ? mesh->GetResource(0) : boost::shared_ptr<RScmResource>{};
    if (!resource) {
      return;
    }

    // Re-blend the skinned pose from start/end at the current interpolant so
    // `curPose` - which HardwareMeshBatch::FillBatch reads directly to fill
    // the GPU skinning palette (FillInstanceBonePalettes) - tracks the
    // instance's live animation state. Only static-pose (real unit)
    // instances that are not locked carry start/end pose handles (see
    // MeshInstance::SetStance's pose-carrying overload).
    if (isStaticPose != 0u && isLocked == 0u) {
      curPose->InterpolatePose(
        interpolation, startPose.get(), endPose.get(), static_cast<std::int32_t>(resource->mFile->mSkinBoneCount)
      );
    }

    float maxScale = scale.x;
    if (scale.y > maxScale) {
      maxScale = scale.y;
    }
    if (scale.z > maxScale) {
      maxScale = scale.z;
    }

    float radius = maxScale * resource->mSize * 0.5f;
    const float maxOffset = curPose->mMaxOffset;
    if (maxOffset > radius) {
      radius = maxOffset;
    }
    // curPose->mMaxOffset starts at -infinity (CAniPose's ctor default) and is
    // only ever raised by InterpolatePose, so this really tests "has a pose
    // blend ever actually run for this instance".
    const bool maxOffsetUnset = maxOffset <= gpg::nInf;

    sphere.Center = interpolatedPosition;
    if (!maxOffsetUnset) {
      sphere.Center.y += maxOffset;
    }
    sphere.Radius = radius;

    // Rebuild the world oriented box (and its derived AABB) from the mesh
    // resource's own local bounds scaled by the instance, not by recentering
    // whatever xMin..zMax happened to hold before - this is what ground
    // truth actually does (FUN_007DAC10 + FUN_00472CF0 chained together),
    // matching MeshInstance::GetSweptAlignedBox's already-correct pattern.
    const Wm3::AxisAlignedBox3f scaledLocalBounds = ScaleLocalMeshBounds(scale, resource->mBounds);
    BuildOrientedBoxFromLocalAabb(
      curOrientation, interpolatedPosition,
      scaledLocalBounds.Min.x, scaledLocalBounds.Min.y, scaledLocalBounds.Min.z,
      scaledLocalBounds.Max.x, scaledLocalBounds.Max.y, scaledLocalBounds.Max.z,
      box
    );

    Wm3::AxisAlignedBox3f fromOrientedBox{};
    box.ComputeAABB(fromOrientedBox.Min, fromOrientedBox.Max);
    xMin = fromOrientedBox.Min.x;
    yMin = fromOrientedBox.Min.y;
    zMin = fromOrientedBox.Min.z;
    xMax = fromOrientedBox.Max.x;
    yMax = fromOrientedBox.Max.y;
    zMax = fromOrientedBox.Max.z;
  }

  /**
   * Address: 0x007DAE20 (FUN_007DAE20, Moho::MeshInstance::GetInterpolatedPos)
   *
   * What it does:
   * Refreshes interpolation state and copies current interpolated position.
   */
  Wm3::Vec3f MeshInstance::GetInterpolatedPos() const
  {
    MeshInstance& self = *const_cast<MeshInstance*>(this);
    self.UpdateInterpolatedFields();
    return self.interpolatedPosition;
  }

  /**
   * Address: 0x007DE730 (FUN_007DE730, ?GetDebugBoneCount@MeshInstance@Moho@@QBEHXZ)
   *
   * What it does:
   * Returns zero for dynamic meshes; static meshes report SCM bone count.
   */
  std::int32_t MeshInstance::GetDebugBoneCount() const
  {
    if (isStaticPose == 0u) {
      return 0;
    }

    const boost::shared_ptr<RScmResource> resource = mesh->GetResource(0);
    return static_cast<std::int32_t>(resource->mFile->mBoneTotalCount);
  }

  /**
   * Address: 0x007DE7A0 (FUN_007DE7A0,
   * ?ComputeDebugPose@MeshInstance@Moho@@QAE?AV?$shared_ptr@VCAniPose@Moho@@@boost@@XZ)
   * Mangled: ?ComputeDebugPose@MeshInstance@Moho@@QAE?AV?$shared_ptr@VCAniPose@Moho@@@boost@@XZ
   *
   * IDA signature:
   * boost::shared_ptr_CAniPose* __userpurge Moho::MeshInstance::ComputeDebugPose@<eax>(
   *   Moho::MeshInstance* a1@<eax>, boost::shared_ptr_CAniPose* a2);
   *
   * What it does:
   * Refreshes the skeleton-debug pose and returns it as an additional
   * shared reference. For static-pose, unlocked meshes: fetches the
   * backing mesh's LOD-0 `RScmResource`, calls
   * `CAniPose::InterpolatePose(currInterpolant, startPose, endPose,
   * resource.mFile.mBoneCount)` on `curPose`, then returns one shared
   * handle to `curPose` to the caller. For non-static or locked meshes
   * returns an empty shared handle so skeleton-debug callers can render
   * nothing. The binary path bypasses any `shared_ptr` swap by hand and
   * inlines the control-block `use_count` bump; the typed return here
   * preserves the same semantics.
   */
  boost::shared_ptr<CAniPose> MeshInstance::ComputeDebugPose()
  {
    if (isStaticPose == 0u || isLocked != 0u) {
      return boost::shared_ptr<CAniPose>{};
    }

    const boost::shared_ptr<RScmResource> resource = mesh->GetResource(0);
    const std::int32_t boneCount = static_cast<std::int32_t>(resource->mFile->mBoneTotalCount);

    curPose->InterpolatePose(currInterpolant, startPose.get(), endPose.get(), boneCount);
    return curPose;
  }

  /**
   * Address: 0x007DEFC0 (FUN_007DEFC0,
   * ?GetSweptAlignedBox@MeshInstance@Moho@@QBE?AV?$AxisAlignedBox3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns cached swept AABB lanes; when stale, rebuilds sweep from start/end
   * stance OBBs using scaled mesh-resource bounds.
   */
  Wm3::AxisAlignedBox3f MeshInstance::GetSweptAlignedBox() const
  {
    MeshInstance& self = *const_cast<MeshInstance*>(this);
    if (self.boundsValid != 0u) {
      const boost::shared_ptr<RScmResource> resource = self.mesh ? self.mesh->GetResource(0) : boost::shared_ptr<RScmResource>{};
      if (resource) {
        const Wm3::AxisAlignedBox3f scaledLocalBounds = ScaleLocalMeshBounds(self.scale, resource->mBounds);

        Wm3::Box3f endOriented{};
        BuildOrientedBoxFromLocalAabb(
          self.endTransform.orient_,
          self.endTransform.pos_,
          scaledLocalBounds.Min.x,
          scaledLocalBounds.Min.y,
          scaledLocalBounds.Min.z,
          scaledLocalBounds.Max.x,
          scaledLocalBounds.Max.y,
          scaledLocalBounds.Max.z,
          endOriented
        );

        Wm3::Box3f startOriented{};
        BuildOrientedBoxFromLocalAabb(
          self.startTransform.orient_,
          self.startTransform.pos_,
          scaledLocalBounds.Min.x,
          scaledLocalBounds.Min.y,
          scaledLocalBounds.Min.z,
          scaledLocalBounds.Max.x,
          scaledLocalBounds.Max.y,
          scaledLocalBounds.Max.z,
          startOriented
        );

        Wm3::AxisAlignedBox3f endBounds{};
        endOriented.ComputeAABB(endBounds.Min, endBounds.Max);

        Wm3::AxisAlignedBox3f startBounds{};
        startOriented.ComputeAABB(startBounds.Min, startBounds.Max);

        const Wm3::AxisAlignedBox3f sweptBounds = MergeAxisAlignedBounds(endBounds, startBounds);
        self.renderMinX = sweptBounds.Min.x;
        self.renderMinY = sweptBounds.Min.y;
        self.renderMinZ = sweptBounds.Min.z;
        self.renderMaxX = sweptBounds.Max.x;
        self.renderMaxY = sweptBounds.Max.y;
        self.renderMaxZ = sweptBounds.Max.z;
      }

      self.boundsValid = 0u;
    }

    Wm3::AxisAlignedBox3f result{};
    result.Min.x = self.renderMinX;
    result.Min.y = self.renderMinY;
    result.Min.z = self.renderMinZ;
    result.Max.x = self.renderMaxX;
    result.Max.y = self.renderMaxY;
    result.Max.z = self.renderMaxZ;
    return result;
  }

  namespace
  {
    MeshRenderer* gMeshRendererInstance = nullptr;
  }

  /**
   * Address: 0x007DF150 (FUN_007DF150, ??0MeshRenderer@Moho@@QAE@XZ)
   */
  MeshRenderer::MeshRenderer()
    : meshEnvironment()
    , meshCacheTree()
    , dissolveTex()
    , meshEnvironmentTex()
    , anisotropiclookupTex()
    , insectlookupTex()
    , instances()
    , instanceListSize(0)
    , deltaFrame(0.0f)
    , instanceListStateFlags(0)
    , meshes()
    , meshSpatialDb{}
  {
    // `meshCacheTree` and `meshes` both stand their own header sentinel up in
    // the map constructor (0x007E4770+0x007E2B50 / 0x007E2C30 `_Tree::_Tree`
    // emissions the binary's ctor inlines here).

    // The binary's constructor ends by constructing this member:
    //   0x007DF23A  push offset Moho__sMeshRenderer.bd   ; +0xAC
    //   0x007DF244  call ??0SpatialDB_MeshInstance@Moho@@QAE@@Z
    // which is InitializeStorage (0x00501D80). Without it the shard vector is
    // never brought to a consistent empty state and the first CollectAllInVolume
    // of the first world-view frame walks from a null begin to a garbage end.

    gMeshRendererInstance = this;
  }

  /**
   * Address: 0x007DF330 (FUN_007DF330, ??1MeshRenderer@Moho@@UAE@XZ)
   * Address: 0x007DF260 (FUN_007DF260, the scalar deleting destructor in
   * vftable 0xE3F494's only slot; it was hand-written as a static
   * `DeleteWithFlag`.)
   */
  MeshRenderer::~MeshRenderer()
  {
    Reset();
    // meshSpatialDb tears itself down: 0x00501E50 is SpatialDB<T>::~SpatialDB,
    // which runs as ordinary member destruction after this body.
    // `meshes` frees its nodes and header sentinel right here, inline
    // (0x007E2B20's tidy) - confirmed from FUN_007DF330.c: `sub_7E3E20` +
    // `operator delete(this->mMeshes._Myhead)` fire immediately after
    // ~SpatialDB_MeshInstance, before the instance-list unlink below. Real,
    // automatic here via implicit member destruction (meshSpatialDb is the
    // last-declared member with a destructor, meshes the next).
    //
    // `meshCacheTree` (the binary's `mMap`) frees its own nodes and header
    // sentinel (0x007DF2D0's tidy) LAST, right before ~MeshEnvironment's
    // inline string cleanup - confirmed the same way: `sub_7E3B70` +
    // `operator delete(this->mMap._Myhead)` are the last two statements in
    // FUN_007DF330.c before mEnvironment's teardown, AFTER all four texture
    // shared_ptr releases. The previous recovery here called
    // DestroyMeshCacheTree(meshCacheTree) explicitly, right after the
    // instance-list unlink below - years too early relative to the real
    // binary's actual reverse-declaration-order destruction sequence. Both
    // trees are real typed `msvc8::map` members now, so both teardowns are
    // just implicit member destruction, naturally landing in the same
    // reverse-declaration order the binary shows: meshSpatialDb, meshes,
    // ..., insectlookupTex, anisotropiclookupTex, meshEnvironmentTex,
    // dissolveTex, meshCacheTree, meshEnvironment - no explicit call needed
    // for either, and none for meshCacheTree specifically fixes the
    // ordering bug. `instances` unlinks the same way, in its own
    // destructor between `meshes` and the textures (0x007DF2B0 is that
    // destructor's unwind copy).
    if (gMeshRendererInstance == this) {
      gMeshRendererInstance = nullptr;
    }
  }

  /**
   * Address: 0x007E16C0 (FUN_007E16C0, ?GetInstance@MeshRenderer@Moho@@SAPAV12@XZ)
   */
  MeshRenderer* MeshRenderer::GetInstance()
  {
    if (!gMeshRendererInstance) {
      static MeshRenderer sMeshRenderer;
      gMeshRendererInstance = &sMeshRenderer;
    }

    return gMeshRendererInstance;
  }

  /**
   * Address: 0x007E1370 (FUN_007E1370, ?Reset@MeshRenderer@Moho@@QAEXXZ)
   *
   * What it does:
   * Releases global sheet handles, clears per-instance LOD batches, and resets batch-bucket state.
   */
  void MeshRenderer::Reset()
  {
    dissolveTex.reset();
    meshEnvironmentTex.reset();
    anisotropiclookupTex.reset();
    insectlookupTex.reset();
    ResetInstanceBatches(instances);
    meshes.clear();

    // FAF: the default-pool buffers the hardware batches share go too; a
    // device reset needs every one of them released.
    HardwareMeshBatch::ReleaseSharedBuffers();
  }

  /**
   * Address: 0x007E1510 (FUN_007E1510, ?Shutdown@MeshRenderer@Moho@@QAEXXZ)
   *
   * What it does:
   * Performs reset-time cleanup and detaches the intrusive instance-list sentinel.
   */
  void MeshRenderer::Shutdown()
  {
    dissolveTex.reset();
    meshEnvironmentTex.reset();
    anisotropiclookupTex.reset();
    insectlookupTex.reset();
    ResetInstanceBatches(instances);
    instances.ListUnlink();
    meshes.clear();

    // FAF: see Reset.
    HardwareMeshBatch::ReleaseSharedBuffers();
  }

  /**
   * Address: 0x007DF510 (FUN_007DF510, ?UpdateMapSize@MeshRenderer@Moho@@QAEXHH@Z)
   *
   * What it does:
   * Resizes renderer-owned mesh spatial-db storage for current map dimensions.
   */
  void MeshRenderer::UpdateMapSize(const std::int32_t width, const std::int32_t height)
  {
    meshSpatialDb.ResizeForMap(width, height);
  }

  /**
   * Address: 0x007E5280 (FUN_007E5280,
   * ?FindOrCreateMesh@MeshRenderer@Moho@@QAE?AV?$shared_ptr@VMesh@Moho@@@boost@@PBVRMeshBlueprint@2@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
   * Address: 0x007E59C0 (FUN_007E59C0, the compiler-outlined cold-path chunk
   * for the cache-miss branch: reserves the tree slot with a placeholder
   * `weak_ptr`, builds the new `Mesh` + evicting-deleter `shared_ptr`, then
   * fills the slot's weak reference in)
   *
   * What it does:
   * Looks up an existing cached mesh by (blueprint, material) key and, if its
   * weak entry is still alive, locks and returns it. On a genuine miss, or a
   * key whose cached mesh has since been destroyed (the ground truth, FUN_
   * 007E5900, checks the found node's control block use_count_ before
   * trusting it - a `weak_ptr<Mesh>::lock()` in every way but name), inserts
   * (or reuses) the tree slot for `key` first -- matching FUN_007E59C0's real
   * operand order, and its exception safety: if `new Mesh(...)` throws, the
   * placeholder `weak_ptr` left in the tree is already empty/expired rather
   * than leaking a stray strong reference -- then builds the new `Mesh`
   * with its cache-evicting deleter and fills the slot's weak reference in.
   * The unconditional final assignment is correct for both outcomes of
   * `insert`: a fresh slot starts out default-constructed-empty, and an
   * existing slot only reaches here when the top check has already proven it
   * expired (single-threaded -- nothing runs between that check and here),
   * so `insert_unique`'s own find-or-insert semantics (RbTree.h) need no
   * extra conditional on this side.
   */
  boost::shared_ptr<Mesh> MeshRenderer::FindOrCreateMesh(
    const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    MeshKey key(blueprint, materialArg);
    if (boost::weak_ptr<Mesh>* const found = meshCacheTree.try_get(key)) {
      if (boost::shared_ptr<Mesh> locked = found->lock()) {
        return locked;
      }
    }

    const std::pair<MeshRendererMeshCacheTree::iterator, bool> result =
      meshCacheTree.insert({key, boost::weak_ptr<Mesh>()});

    boost::shared_ptr<Mesh> mesh;
    ConstructSharedMeshWithCacheEvictingDeleter(mesh, new Mesh(blueprint, materialArg), meshCacheTree, key);
    result.first->second = mesh;

    return mesh;
  }

  /**
   * Address: 0x007DF530 (FUN_007DF530,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIPBVRMeshBlueprint@2@ABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const RMeshBlueprint* const blueprint,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    if (!blueprint) {
      return nullptr;
    }

    const RMeshBlueprintLOD* const lodBegin = blueprint->mLods.begin();
    if (!lodBegin || lodBegin == blueprint->mLods.end()) {
      return nullptr;
    }

    // 0x007DF5AB..0x007DF5BC: the front LOD's model is resolved up front and
    // the whole call is abandoned when it does not load. Without this the
    // renderer hands back an instance whose mesh has a LOD but no resource,
    // and `UserEntity::CreateMeshInstance` faults on the null skeleton.
    if (!GetModel(lodBegin->mMeshName.c_str(), nullptr)) {
      return nullptr;
    }

    boost::shared_ptr<Mesh> mesh = FindOrCreateMesh(blueprint, materialArg);
    return CreateMeshInstance(gameTick, color, scale, isStaticPose, mesh);
  }

  /**
   * Address: 0x007DF8E0 (FUN_007DF8E0,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMesh@Moho@@@boost@@@Z)
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<Mesh> meshArg
  )
  {
    if (!meshArg) {
      return nullptr;
    }

    MeshInstance* const instance = new MeshInstance(scale, &meshSpatialDb, gameTick, color, isStaticPose, meshArg);
    instance->ListLinkBefore(&instances);
    return instance;
  }

  /**
   * Address: 0x007DF710 (FUN_007DF710,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIV?$shared_ptr@VRScmResource@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMeshMaterial@Moho@@@5@M@Z)
   *
   * IDA signature:
   * Moho::MeshInstance *__userpurge CreateMeshInstance(
   *   Moho::MeshRenderer *this@<ecx>, int gameTick, unsigned int color,
   *   boost::shared_ptr<RScmResource> resource, const Wm3::Vector3<float> &scale,
   *   bool isStaticPose, boost::shared_ptr<MeshMaterial> material, float lodCutoff);
   *
   * What it does:
   * Constructs a standalone one-LOD mesh from an already-resolved
   * resource/material pair, applies the LOD cutoff distance to that single
   * LOD, then creates and links a mesh instance via the shared_ptr<Mesh>
   * overload. The resource/material ctor (0x007DD750) always creates exactly
   * one LOD, so the front LOD is always valid.
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const boost::shared_ptr<RScmResource> resource,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<MeshMaterial> material,
    const float lodCutoff
  )
  {
    boost::shared_ptr<Mesh> mesh(new Mesh(resource, material));
    mesh->lods.front()->SetCutoff(lodCutoff);
    return CreateMeshInstance(gameTick, color, scale, isStaticPose, mesh);
  }

  /**
   * Constructs the mesh-render shader-var set, registering every variable
   * against the `"mesh"` effect file. The HLSL names are byte-verified as the
   * exact strings passed to the binary's per-var `RegisterShaderVar` calls
   * (`register_ShaderVarMesh*`, 0x00BE0540..0x00BE0840) — read directly from
   * bin/2025.7.1/ForgedAlliance.exe. The two cartographic elevation vars are
   * registered by register_ShaderVarMeshMinimumElevation (0x00BE0780, literal
   * "minimumElevation" @VA 0xE3F66C, global 0x010BED78) and
   * register_ShaderVarMeshMaximumElevation (0x00BE07A0, literal
   * "maximumElevation" @VA 0xE3F680, global 0x010BE9D0). Mirrors
   * `TerrainShaderVarSet`.
   */
  MeshShaderVarSet::MeshShaderVarSet()
  {
    RegisterShaderVar("anisotropicTexture", &anisotropicTexture, "mesh"); // 0x00BE0540
    RegisterShaderVar("insectTexture", &insectTexture, "mesh");           // 0x00BE0560
    RegisterShaderVar("dissolveTexture", &dissolveTexture, "mesh");
    RegisterShaderVar("time", &time, "mesh");
    RegisterShaderVar("mirrored", &mirrored, "mesh");
    RegisterShaderVar("lodBasis", &lodBasis, "mesh");
    RegisterShaderVar("viewMatrix", &viewMatrix, "mesh");
    RegisterShaderVar("projMatrix", &projMatrix, "mesh");
    RegisterShaderVar("terrainScale", &terrainScale, "mesh");
    RegisterShaderVar("lightMultiplier", &lightMultiplier, "mesh");
    RegisterShaderVar("sunDirection", &sunDirection, "mesh");
    RegisterShaderVar("sunDiffuse", &sunDiffuse, "mesh");
    RegisterShaderVar("sunAmbient", &sunAmbient, "mesh");
    RegisterShaderVar("shadowFill", &shadowFill, "mesh");
    RegisterShaderVar("surfaceElevation", &surfaceElevation, "mesh");
    RegisterShaderVar("abyssElevation", &abyssElevation, "mesh");
    RegisterShaderVar("minimumElevation", &minimumElevation, "mesh"); // 0x00BE0780
    RegisterShaderVar("maximumElevation", &maximumElevation, "mesh"); // 0x00BE07A0
    RegisterShaderVar("waterRamp", &waterRamp, "mesh");
    RegisterShaderVar("shadowsEnabled", &shadowsEnabled, "mesh");
    RegisterShaderVar("shadowMatrix", &shadowMatrix, "mesh");
    RegisterShaderVar("shadowTexture", &shadowTexture, "mesh");
    RegisterShaderVar("shadowBias", &shadowBias, "mesh");
    RegisterShaderVar("shadowSize", &shadowSize, "mesh");
    RegisterShaderVar("shadowBlur", &shadowBlur, "mesh"); // 0x00BE0840
  }

  MeshShaderVarSet& GetMeshShaderVars()
  {
    static MeshShaderVarSet shaderVars{};
    return shaderVars;
  }

  // ---------------------------------------------------------------------------
  // Per-material mesh-texture shader-vars.
  //
  // Distinct from the 23-entry MeshShaderVarSet above, the binary holds these
  // six texture sampler shader-vars as standalone process-wide `ShaderVar`
  // globals, each installed by its own CRT init thunk (byte-verified from
  // bin/2025.7.1/ForgedAlliance.exe): register thunks at 0x00BE0520
  // (environmentTexture, global 0x010BEDC0), 0x00BE0860 (albedoTexture, global
  // 0x010BE670), 0x00BE0880 (normalsTexture, global 0x010BEAA8), 0x00BE08A0
  // (specularTexture, global 0x010BEC10), 0x00BE08C0 (lookupTexture, global
  // 0x010BE820) and 0x00BE08E0 (secondaryTexture, global 0x010BE8F8). Every
  // thunk calls `RegisterShaderVar(<name>, &global, "mesh")` (0x00438000), so
  // all six register against the "mesh" effect. The HLSL name strings are the
  // exact null-terminated `.rdata` literals passed to those calls (VAs
  // 0x00E3F580 / 0x00E3F6E0 / 0x00E3F6F0 / 0x00E3F700 / 0x00E3F710 /
  // 0x00E3F720). MeshRenderer::Render binds all six per LOD material; the
  // recovered model groups them into one set exposed through
  // GetMeshTextureShaderVars(), mirroring MeshShaderVarSet.
  // ---------------------------------------------------------------------------
  namespace
  {
    struct MeshTextureShaderVarSet
    {
      ShaderVar environmentTexture; // "environmentTexture" &0x010BEDC0
      ShaderVar albedoTexture;      // "albedoTexture"      &0x010BE670
      ShaderVar specularTexture;    // "specularTexture"    &0x010BEC10
      ShaderVar lookupTexture;      // "lookupTexture"      &0x010BE820
      ShaderVar secondaryTexture;   // "secondaryTexture"   &0x010BE8F8
      ShaderVar normalsTexture;     // "normalsTexture"     &0x010BEAA8

      MeshTextureShaderVarSet()
      {
        RegisterShaderVar("environmentTexture", &environmentTexture, "mesh"); // 0x00BE0520
        RegisterShaderVar("albedoTexture", &albedoTexture, "mesh");           // 0x00BE0860
        RegisterShaderVar("specularTexture", &specularTexture, "mesh");       // 0x00BE08A0
        RegisterShaderVar("lookupTexture", &lookupTexture, "mesh");           // 0x00BE08C0
        RegisterShaderVar("secondaryTexture", &secondaryTexture, "mesh");     // 0x00BE08E0
        RegisterShaderVar("normalsTexture", &normalsTexture, "mesh");         // 0x00BE0880
      }
    };

    MeshTextureShaderVarSet& GetMeshTextureShaderVars()
    {
      static MeshTextureShaderVarSet textureVars{};
      return textureVars;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // GPU mesh skinning-palette shader-vars (translation + rotation palettes).
  //
  // These are two process-wide `MeshShaderPaletteVar` globals the binary holds
  // separately from the 23-entry `MeshShaderVarSet` above (distinct CRT init
  // thunks at 0x00BE0900 / 0x00BE0920, distinct global addresses 0x010BEEF8 /
  // 0x010BEE50). Each is a `ShaderVar` extended with an inline palette buffer
  // reserved to 80 (`kPaletteCapacity`) 16-byte entries at registration time.
  // ---------------------------------------------------------------------------

  // AppendDefaultPaletteEntries removed: MeshShaderPaletteBuffer is
  // msvc8::vector<SkinPaletteEntry> (see Mesh.h), so its 0x007E9280 body is
  // this template's own insert(pos,count,value) member for the 16-byte
  // element -- see the Address: citations added there.

  /**
   * Address: 0x007E96A0 (FUN_007E96A0, sub_7E96A0)
   *
   * What it does:
   * Uninitialized-move relocation for palette entries: copies each 16-byte
   * `SkinPaletteEntry` in `[first, last)` into `dest`, four floats at a time, and
   * returns the one-past-end destination pointer.
   */
  SkinPaletteEntry* RelocatePaletteEntries(
    SkinPaletteEntry* dest,
    SkinPaletteEntry* first,
    SkinPaletteEntry* const last
  )
  {
    while (first != last) {
      dest->x = first->x;
      dest->y = first->y;
      dest->z = first->z;
      dest->w = first->w;
      ++first;
      ++dest;
    }
    return dest;
  }

  void MeshShaderPaletteBuffer::ReserveToPaletteCapacity()
  {
    const std::size_t count = size();
    if (count < kPaletteCapacity) {
      insert(end(), kPaletteCapacity - count, SkinPaletteEntry{});
    } else if (count > kPaletteCapacity) {
      erase(begin() + kPaletteCapacity, end());
    }
  }

  /**
   * Address: 0x007E9050 (FUN_007E9050, register_MeshShaderVar)
   *
   * IDA signature:
   * struct_MeshShaderVar* __thiscall register_MeshShaderVar(
   *     const char* name, struct_MeshShaderVar* a2);
   *
   * What it does:
   * Registers one mesh skinning-palette shader-var against the `"mesh"` effect
   * file (via `RegisterShaderVar`), clears its embedded palette buffer triplet,
   * and reserves the palette to `kPaletteCapacity` (80) entries.
   */
  MeshShaderPaletteVar* register_MeshShaderVar(const char* const name, MeshShaderPaletteVar* const paletteVar)
  {
    RegisterShaderVar(name, paletteVar, "mesh");

    // No explicit triplet reset needed: mPalette is a real
    // msvc8::vector<SkinPaletteEntry> here, already empty from
    // MeshShaderPaletteVar's own (implicit) default construction.
    paletteVar->mPalette.ReserveToPaletteCapacity();
    return paletteVar;
  }

  // The two palette globals are defined ahead of the bootstrap object below:
  // C++ constructs a translation unit's namespace-scope objects in definition
  // order, so each one is default-constructed before its registrar runs
  // `register_MeshShaderVar` on it. No other translation unit reads them
  // during static initialization.

  /**
   * Address: 0x00C03E40 (FUN_00C03E40, dynamic atexit destructor for `meshShaderVarTransPalette`)
   *
   * What it does:
   * Translation skinning-palette shader-var (binary global 0x010BEEF8).
   */
  MeshShaderPaletteVar meshShaderVarTransPalette;

  /**
   * Address: 0x00C03E80 (FUN_00C03E80, dynamic atexit destructor for `meshShaderVarRotPalette`)
   *
   * What it does:
   * Rotation skinning-palette shader-var (binary global 0x010BEE50).
   */
  MeshShaderPaletteVar meshShaderVarRotPalette;

  namespace
  {
    /**
     * CRT static-init bootstrap mirroring the two `__xc_a` entries at
     * 0x00BE0900 / 0x00BE0920: registering both palette shader-vars at process
     * startup. This is the source-level invocation site for the palette cluster
     * (FRAMEWORK_DISPATCH via static init).
     */
    struct MeshPaletteShaderVarBootstrap
    {
      MeshPaletteShaderVarBootstrap()
      {
        moho::register_MeshShaderVarTransPalette();
        moho::register_MeshShaderVarRotPalette();
      }
    };

    [[maybe_unused]] MeshPaletteShaderVarBootstrap gMeshPaletteShaderVarBootstrap;
  } // namespace

  /**
   * Address: 0x00BE0900 (FUN_00BE0900, register_MeshShaderVarTransPalette)
   *
   * What it does:
   * CRT static-init registration thunk: registers `meshShaderVarTransPalette`
   * under the byte-verified HLSL name `"transPalette"`.
   */
  void register_MeshShaderVarTransPalette()
  {
    register_MeshShaderVar("transPalette", &meshShaderVarTransPalette);
  }

  /**
   * Address: 0x00BE0920 (FUN_00BE0920, register_MeshShaderVarRotPalette)
   *
   * What it does:
   * CRT static-init registration thunk: registers `meshShaderVarRotPalette`
   * under the byte-verified HLSL name `"rotPalette"`.
   */
  void register_MeshShaderVarRotPalette()
  {
    register_MeshShaderVar("rotPalette", &meshShaderVarRotPalette);
  }

  /**
   * Address: 0x007E1720 (FUN_007E1720, Moho::MeshRenderer::LoadGlobalTextures)
   * Mangled: ?LoadGlobalTextures@MeshRenderer@Moho@@AAEXXZ
   *
   * IDA signature:
   * private: void __thiscall Moho::MeshRenderer::LoadGlobalTextures(void);
   *
   * What it does:
   * Lazily resolves the renderer's four global texture resources from the
   * active D3D device resources and stores each retained
   * `boost::shared_ptr<RD3DTextureResource>` into its lane. Each lane is only
   * (re)loaded when still empty, matching the binary's `if (!lane.obj)` guards,
   * so repeated calls after the first successful load are no-ops per lane. The
   * mesh-environment cube map path comes from the renderer's
   * `MeshEnvironment::mCubeMapPath`; the other three are fixed engine texture
   * paths transcribed verbatim from the binary. `allowCreate=0, allowFallback=1`
   * for every lookup.
   */
  void MeshRenderer::LoadGlobalTextures()
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    if (!dissolveTex) {
      resources->GetTexture(dissolveTex, "/textures/environment/dissolve.dds", 0, true);
    }
    if (!meshEnvironmentTex) {
      resources->GetTexture(meshEnvironmentTex, meshEnvironment.mCubeMapPath.c_str(), 0, true);
      { ID3DTextureSheet::TextureHandle h{}; if (meshEnvironmentTex) { meshEnvironmentTex->GetTexture(h); } gpg::Warnf("[ENVDIAG] cube path='%s' res=%p tex=%p native1=%p native3=%p", meshEnvironment.mCubeMapPath.c_str(), static_cast<void*>(meshEnvironmentTex.get()), static_cast<void*>(h.get()), h ? ProbeNativeTexture1(h.get()) : nullptr, h ? ProbeNativeTexture3(h.get()) : nullptr); } // TEMPORARY PROBE (do not commit)
    }
    if (!anisotropiclookupTex) {
      resources->GetTexture(anisotropiclookupTex, "/textures/engine/anisotropiclookup.dds", 0, true);
    }
    if (!insectlookupTex) {
      resources->GetTexture(insectlookupTex, "/textures/engine/insectlookup.dds", 0, true);
    }
  }

  /**
   * Address: 0x007E19D0 (FUN_007E19D0, Moho::MeshRenderer::ConfigureShader)
   * Mangled: ?ConfigureShader@MeshRenderer@Moho@@AAEXABVGeomCamera3@2@PAVShadow@2@_N@Z
   *
   * IDA signature:
   * private: void __thiscall Moho::MeshRenderer::ConfigureShader(
   *     const GeomCamera3& camera, Shadow* shadow, bool mirrored);
   *
   * What it does:
   * Binds the whole mesh-render shader-constant lane for one render pass. Reads
   * the active water surface elevation (falling back to -1000/-10000 when no
   * terrain/water is present), loads the global lookup textures, binds the
   * anisotropic/insect/dissolve textures, uploads the frame time, mirror flag,
   * (optionally mirror-flipped) view matrix and projection matrix, then either
   * the active terrain's terrain-scale/sun/shadow/water lighting lanes or the
   * renderer's fallback mesh-environment lighting lanes, and finally the
   * optional shadow-map lane. All float constants and HLSL names are byte-
   * verified from bin/2025.7.1/ForgedAlliance.exe.
   */
  void MeshRenderer::ConfigureShader(const GeomCamera3& camera, Shadow* const shadow, const bool mirrored)
  {
    MeshShaderVarSet& sv = GetMeshShaderVars();

    // Select the active terrain resource (nullptr when there is no world map or
    // no terrain). The binary reads the `sWldMap` global directly; the recovered
    // `REN_GetTerrainRes` folds in both the map and terrain null checks and
    // returns `sWldMap->mTerrainRes` (mirrors 0x007E1A0B..0x007E1A25).
    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();

    // Surface (water) elevation lane: current water elevation when water is
    // enabled on the active map, else -10000; -1000 when there is no terrain.
    float surfaceElevation;
    if (terrainRes != nullptr) {
      const STIMap* const map = terrainRes->mMap;
      surfaceElevation = (map->mWaterEnabled != 0) ? map->mWaterElevation : -10000.0f;
    } else {
      surfaceElevation = -1000.0f;
    }

    // Global lookup textures + the three per-frame texture binds.
    LoadGlobalTextures();
    BindTextureShaderVar(sv.anisotropicTexture, boost::static_pointer_cast<ID3DTextureSheet>(anisotropiclookupTex));
    BindTextureShaderVar(sv.insectTexture, boost::static_pointer_cast<ID3DTextureSheet>(insectlookupTex));

    // Frame time: fold the frame counter into a float (with the unsigned int
    // fixup the binary applies to negative counters), add the accumulated delta
    // frame, then wrap into the shader time window (fmod by 36000).
    const auto frameCounter = static_cast<std::int32_t>(instanceListSize);
    double frameSeconds = static_cast<double>(frameCounter);
    if (frameCounter < 0) {
      frameSeconds += 4294967296.0; // 2^32 unsigned fixup (dbl_E4F710)
    }
    frameSeconds += deltaFrame;
    const float shaderTime = static_cast<float>(std::fmod(frameSeconds, 36000.0)); // flt_F57F08
    if (sv.time.Exists()) {
      sv.time.SetFloat(shaderTime);
    }

    if (sv.mirrored.Exists()) {
      const int mirroredFlag = mirrored ? 1 : 0;
      SetShaderVarPtr(sv.mirrored, &mirroredFlag, 4);
    }

    // Copy the camera view matrix; when mirrored, reflect it about the water
    // plane (translate row along the up axis by 2*surfaceElevation and negate
    // the up-axis row). Row layout: r[row].{x,y,z,w}.
    VMatrix4 viewMatrixCopy;
    std::memcpy(&viewMatrixCopy, &camera.view, sizeof(viewMatrixCopy));
    if (mirrored) {
      const float translate = surfaceElevation * 2.0f; // flt_DFEB0C = 2.0
      viewMatrixCopy.r[3].x += (viewMatrixCopy.r[2].x + viewMatrixCopy.r[0].x) * 0.0f + viewMatrixCopy.r[1].x * translate;
      viewMatrixCopy.r[3].y += (viewMatrixCopy.r[2].y + viewMatrixCopy.r[0].y) * 0.0f + viewMatrixCopy.r[1].y * translate;
      viewMatrixCopy.r[3].z += (viewMatrixCopy.r[2].z + viewMatrixCopy.r[0].z) * 0.0f + viewMatrixCopy.r[1].z * translate;
      viewMatrixCopy.r[3].w += (viewMatrixCopy.r[2].w + viewMatrixCopy.r[0].w) * 0.0f + viewMatrixCopy.r[1].w * translate;
      viewMatrixCopy.r[1].x *= -1.0f; // flt_E4F6E8 = -1.0
      viewMatrixCopy.r[1].y *= -1.0f;
      viewMatrixCopy.r[1].z *= -1.0f;
      viewMatrixCopy.r[1].w *= -1.0f;
    }

    // LOD basis = viewport matrix row 1 (camera.viewport.r[1], 4 floats).
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&viewMatrixCopy);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    BindTextureShaderVar(sv.dissolveTexture, boost::static_pointer_cast<ID3DTextureSheet>(dissolveTex));

    if (terrainRes != nullptr) {
      const STIMap* const map = terrainRes->mMap;
      const CHeightField* const heightField = map->mHeightField.get();

      // Terrain scale = {1/(width-1), 0, 1/(height-1), 1}.
      const float terrainScaleValues[4] = {
        1.0f / static_cast<float>(heightField->width - 1),
        0.0f,
        1.0f / static_cast<float>(heightField->height - 1),
        1.0f
      };
      if (sv.terrainScale.Exists()) {
        SetShaderVarMem(sv.terrainScale, 4, terrainScaleValues);
      }

      const float lightingMultiplier = terrainRes->GetLightingMultiplier();
      if (sv.lightMultiplier.Exists()) {
        sv.lightMultiplier.SetFloat(lightingMultiplier);
      }

      // Sun direction: negated when mirrored (reflected across the water plane).
      Wm3::Vector3f sunDirection = terrainRes->GetSunDirection();
      if (mirrored) {
        sunDirection.x = -0.0f - sunDirection.x; // dword_E4F748 = -0.0
        sunDirection.y = -0.0f - sunDirection.y;
        sunDirection.z = -0.0f - sunDirection.z;
      }
      if (sv.sunDirection.Exists()) {
        SetShaderVarMem(sv.sunDirection, 3, &sunDirection.x);
      }

      const Wm3::Vector3f sunColor = terrainRes->GetSunColor();
      if (sv.sunDiffuse.Exists()) {
        SetShaderVarMem(sv.sunDiffuse, 3, &sunColor.x);
      }
      const Wm3::Vector3f sunAmbience = terrainRes->GetSunAmbience();
      if (sv.sunAmbient.Exists()) {
        SetShaderVarMem(sv.sunAmbient, 3, &sunAmbience.x);
      }
      const Wm3::Vector3f shadowFillColor = terrainRes->GetShadowFillColor();
      if (sv.shadowFill.Exists()) {
        SetShaderVarMem(sv.shadowFill, 3, &shadowFillColor.x);
      }
      // TEMPORARY PROBE -- black-unit lighting triage, delete when resolved.
      {
        static int sLightCount = 0;
        static int sSeenMirrored[2] = {0, 0};
        ++sLightCount;
        if (sSeenMirrored[mirrored ? 1 : 0]++ < 2 || (sLightCount % 997) == 0) {
          gpg::Warnf("[LIGHTDIAG] mesh exists: mult=%d dir=%d diff=%d amb=%d fill=%d | mult=%.2f dir=(%.2f,%.2f,%.2f) diff=(%.2f,%.2f,%.2f) amb=(%.2f,%.2f,%.2f) fill=(%.2f,%.2f,%.2f) mirrored=%d n=%d",
                     sv.lightMultiplier.Exists() ? 1 : 0, sv.sunDirection.Exists() ? 1 : 0, sv.sunDiffuse.Exists() ? 1 : 0,
                     sv.sunAmbient.Exists() ? 1 : 0, sv.shadowFill.Exists() ? 1 : 0, lightingMultiplier, sunDirection.x, sunDirection.y,
                     sunDirection.z, sunColor.x, sunColor.y, sunColor.z, sunAmbience.x, sunAmbience.y, sunAmbience.z, shadowFillColor.x,
                     shadowFillColor.y, shadowFillColor.z, mirrored ? 1 : 0, sLightCount);
        }
      }

      CWaterShaderProperties* const waterProperties = terrainRes->GetWaterShaderProperties();
      if (sv.surfaceElevation.Exists()) {
        sv.surfaceElevation.SetFloat(surfaceElevation);
      }

      const float abyssElevation = (map->mWaterEnabled != 0) ? map->mWaterElevationAbyss : -10000.0f;
      if (sv.abyssElevation.Exists()) {
        sv.abyssElevation.SetFloat(abyssElevation);
      }

      BindTextureShaderVar(sv.waterRamp, waterProperties->GetWaterRamp());
    } else {
      // Fallback (no terrain): use the renderer's mesh-environment lighting.
      if (sv.lightMultiplier.Exists()) {
        sv.lightMultiplier.SetFloat(meshEnvironment.mFallbackLightMultiplier);
      }
      if (sv.sunDirection.Exists()) {
        SetShaderVarMem(sv.sunDirection, 3, &meshEnvironment.mFallbackSunDirection.x);
      }
      if (sv.sunDiffuse.Exists()) {
        SetShaderVarMem(sv.sunDiffuse, 3, &meshEnvironment.mFallbackSunDiffuseColor.x);
      }
      if (sv.sunAmbient.Exists()) {
        SetShaderVarMem(sv.sunAmbient, 3, &meshEnvironment.mFallbackSunAmbientColor.x);
      }
      if (sv.shadowFill.Exists()) {
        SetShaderVarMem(sv.shadowFill, 3, &meshEnvironment.mFallbackShadowFillColor.x);
      }
      if (sv.surfaceElevation.Exists()) {
        sv.surfaceElevation.SetFloat(surfaceElevation);
      }
      if (sv.abyssElevation.Exists()) {
        sv.abyssElevation.SetFloat(-1000.0f); // dword_E4F8D8
      }

      // No terrain water-ramp resource: resolve the fixed engine water ramp.
      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      ID3DDeviceResources::TextureResourceHandle waterRampResource;
      resources->GetTexture(waterRampResource, "/textures/engine/waterramp.dds", 0, true);
      BindTextureShaderVar(sv.waterRamp, boost::static_pointer_cast<ID3DTextureSheet>(waterRampResource));
    }

    // Shadow-map lane: only when a shadow object with fidelity > 1 is supplied.
    if (shadow != nullptr && shadow->mShadowFidelity > 1) {
      const int shadowsEnabledFlag = 1;
      if (sv.shadowsEnabled.Exists()) {
        SetShaderVarPtr(sv.shadowsEnabled, &shadowsEnabledFlag, 4);
      }
      if (sv.shadowMatrix.Exists()) {
        sv.shadowMatrix.SetMatrix4x4(&shadow->mCamera.viewProjection);
      }

      // Bind the shadow map for sampling. The binary reaches it through
      // Shadow::GetShadowMap (sub_7DB350), which takes a *strong* reference -
      // it increments the control block's use_count_ at +0x04 - and hands the
      // retained render target to the render-target binder (0x00491280), which
      // pulls the GAL surface off the target's own vtable. The retained copy is
      // released when it leaves scope, matching the binary's trailing
      // shared_ptr teardown.
      boost::shared_ptr<CD3DRenderTarget> shadowMap{};
      shadow->GetShadowMap(shadowMap);
      sv.shadowTexture.SetRenderTargetTexture(shadowMap);

      const float shadowBias = ren_ShadowBias; // 0.005
      if (sv.shadowBias.Exists()) {
        sv.shadowBias.SetFloat(shadowBias);
      }
      const int shadowSize = shadow->mShadowSize;
      if (sv.shadowSize.Exists()) {
        sv.shadowSize.SetFloat(static_cast<float>(shadowSize));
      }
      const int shadowBlurFlag = (shadow->mShadowBlurEnabled && shadow->mShadowFidelity == 3) ? 1 : 0;
      if (sv.shadowBlur.Exists()) {
        SetShaderVarPtr(sv.shadowBlur, &shadowBlurFlag, 4);
      }
    } else {
      const int shadowsEnabledFlag = 0;
      if (sv.shadowsEnabled.Exists()) {
        SetShaderVarPtr(sv.shadowsEnabled, &shadowsEnabledFlag, 4);
      }
    }
  }

  namespace
  {
    /**
     * Resolves the MeshLOD associated with one batch bucket.
     *
     * The batch key's `mLod` lane (`MeshBatchKey` +0x08) stores the owning
     * `MeshLOD*` directly (the binary reads `key.lod` at 0x007DFCDC).
     */
    [[nodiscard]] MeshLOD* MeshBatchEntryLod(const MeshBatchBucket& bucket) noexcept
    {
      return bucket.first.mLod;
    }

    /**
     * True when a batch bucket holds skinned (static-pose) instances.
     *
     * The batch key's `mIsStaticPose` byte (`MeshBatchKey` +0x04) selects the
     * skinned batch path when non-zero (the binary reads `*(node + 0x10)`,
     * i.e. the key byte inside the node payload at +0x0C).
     */
    [[nodiscard]] bool MeshBatchEntryIsSkinned(const MeshBatchBucket& bucket) noexcept
    {
      return bucket.first.mIsStaticPose != 0;
    }

    /**
     * FAF divergence from the shipped binary - not a recovered function.
     *
     * What it does:
     * Empties every bucket's instance list for the next `MeshRenderer::Batch`
     * while keeping the buckets themselves, and periodically drops the ones
     * that went unused.
     *
     * The binary starts every Batch with `meshes.clear()`, and Batch runs two or
     * three times a frame (main view, shadow camera, cartographic). That frees
     * every map node and every instance vector, and the same buckets are then
     * reallocated as they refill - thousands of allocations a frame in a busy
     * scene. Clearing a vector keeps its capacity, so a bucket that is visible
     * frame after frame stops allocating at all.
     *
     * Buckets left empty since the previous Batch are erased every
     * `kPruneEveryNthBatch` calls, so the map follows the recently visible set
     * instead of growing. Pruning only occasionally matters: main view and
     * shadow camera alternate over the same map, so a bucket one of them sees
     * is always momentarily empty from the other's point of view.
     *
     * An empty bucket's key may name a MeshLOD the mesh cache has since
     * released. The key compare only reads that pointer's value, and every
     * consumer of the map skips empty buckets before touching the LOD.
     */
    void RecycleBatchBuckets(MeshBatchBucketTree& buckets)
    {
      constexpr unsigned kPruneEveryNthBatch = 64u;
      static unsigned sBatchesSincePrune = 0u;

      const bool prune = (++sBatchesSincePrune >= kPruneEveryNthBatch);
      if (prune) {
        sBatchesSincePrune = 0u;
      }

      for (auto it = buckets.begin(); it != buckets.end();) {
        if (prune && it->second.empty()) {
          it = buckets.erase(it);
          continue;
        }
        it->second.clear();
        ++it;
      }
    }

    /**
     * Resolves a material's cached render-stage index, resolving it from the
     * effect's `renderStage` integer annotation on first use and caching the
     * result back into `mShaderIndex` (binary: the `mMat.mVal < 0` block).
     */
    [[nodiscard]] std::int32_t ResolveMaterialRenderStage(CD3DEffect* const effect, MeshMaterial& material)
    {
      if (material.mShaderIndex < 0) {
        material.mShaderIndex =
          effect->GetIntegerAnnotation(material.mShaderAnnotation, msvc8::string("renderStage"), 0);
      }
      return material.mShaderIndex;
    }
  } // namespace

  /**
   * Address: 0x007DFF30 (FUN_007DFF30, ?RenderCartographic@MeshRenderer@Moho@@QAEXMMMABVGeomCamera3@2@AAV?$map@...@Z)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::RenderCartographic(
   *   MeshRenderer* this, std::map<MeshBatchKey, vector<MeshInstance*>>* map,
   *   float surfaceElevation, float minimumElevation, float maximumElevation,
   *   const GeomCamera3& camera);
   *
   * What it does:
   * Draws one mesh batch tree in cartographic (minimap) mode. Binds the seven
   * cartographic mesh shader-vars for this pass (time / lodBasis / the three
   * elevation floats / view / proj), then walks the batch-bucket RB-tree in key
   * order. Unlike Render it does NOT call ConfigureShader and does NOT select an
   * effect — the caller has already made a cartographic effect the device's
   * current effect, so it reads `device->GetCurEffect()` to resolve the per-
   * material cartographic technique. There is no renderStage gate: each material
   * lazily resolves + caches its "cartographicTechnique" string annotation
   * (`MeshMaterial::mCartographicTechnique`, guarded by `mCartographicTechniqueResolved`) and is drawn only when
   * that technique is non-empty. Per material it binds the albedo/specular/
   * normals samplers (this bind order), then draws the bucket's instances through
   * the LOD's lazily-built skinned/static hardware batch, always un-mirrored
   * (binary pushes 0 as the last Render arg, 0x007E030C).
   *
   * The three float params are the elevation lane: the binary binds
   * `shaderVarMeshSurfaceElevation = a3`, `shaderVarMeshMinimumElevation = a4`,
   * `shaderVarMeshMaximumElevation = a5` (0x007E0000..0x007E006C), which is why
   * they are named surface/minimum/maximum here rather than the decompiler's
   * mislabelled projection-scale trio.
   */
  void MeshRenderer::RenderCartographic(
    const float surfaceElevation,
    const float minimumElevation,
    const float maximumElevation,
    const GeomCamera3& camera,
    MeshBatchBucketTree& meshMap
  )
  {
    // Nothing to draw when the batch tree is empty (binary: `if (*(arg4+8))`).
    if (meshMap.empty()) {
      return;
    }

    // The current effect is whatever cartographic effect the caller selected;
    // GetResources() is still pinged at the head of the pass exactly as the
    // binary does (D3D_GetDevice()->GetResources(), 0x007DFF69..0x007DFF79).
    MeshShaderVarSet& sv = GetMeshShaderVars();

    CD3DDevice* const device = D3D_GetDevice();
    device->GetResources();

    // Frame time: fold the frame counter into a float (with the unsigned int
    // fixup the binary applies to negative counters), add the accumulated delta
    // frame, then wrap into the shader time window (fmod by 36000). Identical to
    // RenderDepth's / ConfigureShader's shaderTime lane.
    const auto frameCounter = static_cast<std::int32_t>(instanceListSize);
    double frameSeconds = static_cast<double>(frameCounter);
    if (frameCounter < 0) {
      frameSeconds += 4294967296.0; // 2^32 unsigned fixup (dbl_E4F710)
    }
    frameSeconds += deltaFrame;
    const float shaderTime = static_cast<float>(std::fmod(frameSeconds, 36000.0)); // flt_F57F08
    if (sv.time.Exists()) {
      sv.time.SetFloat(shaderTime);
    }

    // Bind the cartographic shader-constant lane in binary order: LOD basis
    // (viewport matrix row 1, camera.viewport.r[1], 4 floats = arg5+660), then
    // the three elevation floats, then the view/projection matrices (arg5+92 /
    // arg5+28). (Transcribed from FUN_007DFF30 @0x007DFFD6..0x007E00A8.)
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    if (sv.minimumElevation.Exists()) {
      sv.minimumElevation.SetFloat(minimumElevation);
    }
    if (sv.maximumElevation.Exists()) {
      sv.maximumElevation.SetFloat(maximumElevation);
    }
    if (sv.surfaceElevation.Exists()) {
      sv.surfaceElevation.SetFloat(surfaceElevation);
    }
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    // Cartographic mode does NOT select an effect: it consumes the effect the
    // caller already made current (binary: `effect = device->GetCurEffect()`,
    // vtbl+0x58 @0x007E00AA..0x007E00B3). This effect resolves each material's
    // cartographic technique string annotation.
    CD3DEffect* const effect = device->GetCurEffect();

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // Walk the batch-bucket map in key order. The binary's `begin()` is
    // `head->left` and its `end()` is the header itself, stepped by `_Inc`
    // (0x007E42F0) - which is what `msvc8::map`'s iterator does.
    for (const MeshBatchBucket& bucket : meshMap) {
      // A recycled bucket can sit empty over a released mesh; see
      // RecycleBatchBuckets. Skip it before touching its LOD.
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = MeshBatchEntryLod(bucket);
      MeshMaterial& material = lod->mat;

      // Lazily resolve + cache this material's cartographic technique the first
      // time the cartographic pass reaches it (binary: `if (!mMat.byte8C) {
      // mMat.byte8C = 1; mMat.mStr2 = GetStringAnnotation(mAnnot,
      // "cartographicTechnique", ""); }`). Unlike Render/RenderDepth there is no
      // renderStage gate — the only per-material gate is a non-empty technique.
      if (!material.mCartographicTechniqueResolved) {
        material.mCartographicTechniqueResolved = true;
        const msvc8::string cartographicTechnique =
          effect->GetStringAnnotation(material.mShaderAnnotation, msvc8::string("cartographicTechnique"), msvc8::string(""));
        material.mCartographicTechnique.assign_owned(cartographicTechnique.view());
      }

      // Only draw when a cartographic technique is defined for the material
      // (binary: `if (mMat.mStr2._Mysize)`).
      if (material.mCartographicTechnique.size() != 0) {
        device->SelectTechnique(material.mCartographicTechnique.c_str());

        // Cartographic pass binds three samplers, in binary bind order:
        // albedo, specular, normals (0x007E01FD / 0x007E020B / 0x007E0219).
        tv.albedoTexture.GetTexture(material.mAlbedoSheet);
        tv.specularTexture.GetTexture(material.mSpecularSheet);
        tv.normalsTexture.GetTexture(material.mNormalsSheet);

        // Draw the bucket's instances through the LOD's lazily-built hardware
        // mesh batch (skinned for static-pose buckets, static otherwise). The
        // shared_ptr handle keeps the batch retained for the draw call; the
        // cartographic pass always draws un-mirrored (binary pushes 0,
        // 0x007E030C).
        boost::shared_ptr<MeshBatch> batchHandle;
        if (MeshBatchEntryIsSkinned(bucket)) {
          lod->GetSkinnedBatch(batchHandle);
        } else {
          lod->GetStaticBatch(batchHandle);
        }
        if (batchHandle) {
          batchHandle->Render(bucket.second, false);
        }
      }
    }
  }

  /**
   * Address: 0x007E0830 (FUN_007E0830, ?RenderSilhouette@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::RenderSilhouette(
   *     Moho::MeshRenderer *this, const struct Moho::GeomCamera3 *a2);
   *
   * What it does:
   * Draws the silhouette overlay in two passes over the same batch tree: the
   * `Occlude` technique writes the occluders that hide silhouettes, then the
   * `Silhouette` technique draws the outlines themselves. Each pass has its
   * own per-LOD opt-in flag and binds only the albedo sampler.
   *
   * Note IDA prints `this` and `a2` swapped here, as it does in
   * Silhouette::Render: the body reads camera fields off `this`
   * (`(int)this + 660` is GeomCamera3::viewport.r[1] at 0x294) and the batch
   * tree off `a2`.
   */
  void MeshRenderer::RenderSilhouette(const GeomCamera3& camera)
  {
    CD3DDevice* const device = D3D_GetDevice();

    // Same pass head as RenderCartographic/RenderDepth, minus the time and
    // elevation lanes: LOD basis from the viewport matrix row 1, then the two
    // camera matrices.
    MeshShaderVarSet& sv = GetMeshShaderVars();
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    device->SelectFxFile("mesh");

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // The two passes walk the same tree but gate on different per-LOD bytes
    // (0x007E0913 reads MeshLOD+0xAD, 0x007E0A93 reads +0xAE), so a mesh can
    // occlude without being outlined and vice versa.
    const auto drawPass =
      [&](const char* const technique, std::uint8_t MeshLOD::* const gate) {
        device->SelectTechnique(technique);
        for (const MeshBatchBucket& bucket : meshes) {
          // See RecycleBatchBuckets: an empty bucket's LOD may be released.
          if (bucket.second.empty()) {
            continue;
          }
          MeshLOD* const lod = MeshBatchEntryLod(bucket);
          if (!(lod->*gate)) {
            continue;
          }

          tv.albedoTexture.GetTexture(lod->mat.mAlbedoSheet);

          boost::shared_ptr<MeshBatch> batchHandle;
          if (MeshBatchEntryIsSkinned(bucket)) {
            lod->GetSkinnedBatch(batchHandle);
          } else {
            lod->GetStaticBatch(batchHandle);
          }
          if (batchHandle) {
            batchHandle->Render(bucket.second, false);
          }
        }
      };

    drawPass("Occlude", &MeshLOD::occlude);
    drawPass("Silhouette", &MeshLOD::silhouette);
  }

  /**
   * Address: 0x007E03B0 (FUN_007E03B0, ?RenderDepth@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@AAV?$map@...@Z)
   *
   * What it does:
   * Draws one mesh batch tree into the active depth surface. Structurally this
   * is the same RB-tree walk as Render but: the pass head binds only the
   * time / lodBasis / view / proj mesh shader-vars (no ConfigureShader,
   * textures or lighting); the per-node gate is the depth stage bit
   * (`mShaderIndex & 1`); the material technique is a lazily-cached
   * `depthTechnique` string annotation; only the albedo sampler is bound; and
   * the batch is always drawn un-mirrored.
   *
   * The depth-technique string is `MeshMaterial::mDepthTechnique` (a msvc8::string at
   * mMat+0x70). The binary's reads at mMat+0x74 / +0x84 / +0x88 (`_Bx`,
   * `_Mysize`, `_Myres`) are that same string's internal members at
   * string+0x04 / +0x14 / +0x18 — normal msvc8::string access, not a separate
   * field. Cross-checked from FUN_007E03B0.asm via mAlbedoSheet at esi+0x2C =
   * mMat+0x20, mShaderIndex at esi+0x5C = mMat+0x50, mDepthTechniqueResolved at esi+0x99
   * = mMat+0x8D.
   */
  void MeshRenderer::RenderDepth(const GeomCamera3& camera, MeshBatchBucketTree& meshMap)
  {
    // Nothing to draw when the batch tree is empty (binary: `if (*(arg4+8))`).
    if (meshMap.empty()) {
      return;
    }

    // Bind only the depth-pass shader-constant lane: frame time, LOD basis, and
    // the view/projection matrices. RenderDepth does NOT call ConfigureShader
    // and never mirrors (no water-plane reflection of the view matrix).
    // (Transcribed from FUN_007E03B0 @0x007E03D0..0x007E04B0.)
    MeshShaderVarSet& sv = GetMeshShaderVars();

    CD3DDevice* const device = D3D_GetDevice();

    // Frame time: fold the frame counter into a float (with the unsigned int
    // fixup the binary applies to negative counters), add the accumulated delta
    // frame, then wrap into the shader time window (fmod by 36000). Identical to
    // ConfigureShader's shaderTime lane.
    const auto frameCounter = static_cast<std::int32_t>(instanceListSize);
    double frameSeconds = static_cast<double>(frameCounter);
    if (frameCounter < 0) {
      frameSeconds += 4294967296.0; // 2^32 unsigned fixup
    }
    frameSeconds += deltaFrame;
    const float shaderTime = static_cast<float>(std::fmod(frameSeconds, 36000.0)); // flt_F57F08
    if (sv.time.Exists()) {
      sv.time.SetFloat(shaderTime);
    }

    // LOD basis = viewport matrix row 1 (camera.viewport.r[1], 4 floats; the
    // binary's arg0+660).
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    // View / projection matrices bound directly (un-mirrored). arg0+92 / arg0+28.
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    // Select the "mesh" effect as the device's current effect.
    CD3DEffect* const meshEffect = device->GetResources()->FindEffect("mesh");
    device->SetCurEffect(meshEffect);

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // Walk the batch-bucket map in key order (binary: begin = head->left,
    // end = header, stepped by `_Inc` at 0x007E42F0).
    for (const MeshBatchBucket& bucket : meshMap) {
      // A recycled bucket can sit empty over a released mesh; see
      // RecycleBatchBuckets. Skip it before touching its LOD.
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = MeshBatchEntryLod(bucket);
      MeshMaterial& material = lod->mat;

      // Resolve + cache the material render stage on first use.
      const std::int32_t renderStage = ResolveMaterialRenderStage(meshEffect, material);

      // Depth gate: only draw materials whose render stage participates in the
      // depth pass (binary: `if (mMat.mVal & 1)`).
      if ((renderStage & 1) == 0) {
        continue;
      }

      // Lazily resolve + cache this material's depth technique the first time
      // the depth pass reaches it (binary: `if (!mMat.byte8D) { mMat.byte8D=1;
      // mMat.mStr3 = GetStringAnnotation(mAnnot,"depthTechnique",""); }`).
      if (!material.mDepthTechniqueResolved) {
        material.mDepthTechniqueResolved = true;
        const msvc8::string depthTechnique =
          meshEffect->GetStringAnnotation(material.mShaderAnnotation, msvc8::string("depthTechnique"), msvc8::string(""));
        material.mDepthTechnique.assign_owned(depthTechnique.view());
      }

      // Only draw when a depth technique is defined for the material
      // (binary: `if (mMat.mStr3._Mysize)`).
      if (material.mDepthTechnique.size() != 0) {
        device->SelectTechnique(material.mDepthTechnique.c_str());

        // Depth pass binds only the albedo sampler.
        tv.albedoTexture.GetTexture(material.mAlbedoSheet);

        // Draw the bucket's instances through the LOD's lazily-built hardware
        // mesh batch (skinned for static-pose buckets, static otherwise). The
        // shared_ptr handle keeps the batch retained for the draw call; the
        // depth pass always draws un-mirrored (binary passes 0).
        boost::shared_ptr<MeshBatch> batchHandle;
        if (MeshBatchEntryIsSkinned(bucket)) {
          lod->GetSkinnedBatch(batchHandle);
        } else {
          lod->GetStaticBatch(batchHandle);
        }
        if (batchHandle) {
          batchHandle->Render(bucket.second, false);
        }
      }
    }
  }

  /**
   * Address: 0x007E0C30 (FUN_007E0C30, Moho::MeshRenderer::Render)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::Render(
   *   std::map<MeshBatchKey, vector<MeshInstance*>>* map, MeshRenderer* this,
   *   int meshFlags, Moho::GeomCamera3* camera, Moho::Shadow* shadow);
   *
   * What it does:
   * Draws one mesh batch tree with optional shadow state. Selects the "mesh"
   * effect, binds the whole per-pass shader-constant lane (ConfigureShader),
   * then walks the batch-bucket RB-tree in key order. For each bucket it
   * resolves the material render stage, applies the pass stage filter, selects
   * the material technique, lazily resolves the environment texture sheet,
   * binds the six per-material texture samplers, then draws the bucket's
   * instance vector through the LOD's lazily-built skinned/static hardware mesh
   * batch. `mirrored` (the batch draw flag) is `meshFlags == 2`.
   *
   * The recovered entry is invoked by name from the main render lane at
   * `src/sdk/moho/app/WxRuntimeTypes.cpp`
   * (`renderer->Render(meshFlags, *cam, shadowRenderer, instance->meshes)`).
   */
  void MeshRenderer::Render(
    const std::int32_t meshFlags,
    const GeomCamera3& camera,
    Shadow* const shadow,
    MeshBatchBucketTree& meshMap
  )
  {
    // Nothing to draw when the batch tree is empty (binary: `if (map->_Mysize)`).
    // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
    {
      static int sRenderCount = 0;
      if ((sRenderCount++ % 61) == 0 || FafProbeFrameDiag() > 0) {
        int skinned = 0;
        int total = 0;
        for (const MeshBatchBucket& bucket : meshMap) {
          ++total;
          skinned += MeshBatchEntryIsSkinned(bucket) ? 1 : 0;
        }
        gpg::Warnf("[SKINDIAG] f=%d Render flags=%d buckets=%d skinned=%d n=%d", FafProbeFrameSeq(), meshFlags, total, skinned, sRenderCount);
      }
    }
    if (meshMap.empty()) {
      return;
    }

    // Active render-time terrain resource (nullptr when no map/terrain). Read at
    // the head of the pass exactly like the binary's `sWldMap ? mTerrainRes : 0`.
    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();

    // Select the mesh effect as the device's current effect, then bind the whole
    // mesh shader-constant lane for this pass. `mirrored` is `meshFlags == 2`.
    // (Transcribed from FUN_007E0C30 @0x007E0C64..0x007E0CD7.)
    CD3DDevice* const device = D3D_GetDevice();
    CD3DEffect* const meshEffect = device->GetResources()->FindEffect("mesh");
    device->SetCurEffect(meshEffect);
    const bool mirrored = (meshFlags == 2);
    ConfigureShader(camera, shadow, mirrored);

    // Per-pass stage filter selectors (binary: v44 = a3 & 0x30, v42 = a3 & 0xC).
    const std::int32_t stageMaskHigh = meshFlags & 0x30;
    const std::int32_t stageMaskLow = meshFlags & 0x0C;

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // Walk the batch-bucket map in key order (binary: begin = head->left,
    // end = header, stepped by `_Inc` at 0x007E42F0).
    for (const MeshBatchBucket& bucket : meshMap) {
      // A recycled bucket can sit empty over a released mesh; see
      // RecycleBatchBuckets. Skip it before touching its LOD.
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = MeshBatchEntryLod(bucket);
      MeshMaterial& material = lod->mat;

      // Resolve + cache the material render stage on first use.
      const std::int32_t renderStage = ResolveMaterialRenderStage(meshEffect, material);

      // Pass stage filter (binary: `!v13 || v13==2 ||
      // ((val & (a3&0x30)) && (val & (a3&0xC)))`).
      const bool passesStageFilter =
        meshFlags == 0 || meshFlags == 2 ||
        (((renderStage & stageMaskHigh) != 0) && ((renderStage & stageMaskLow) != 0));
      if (!passesStageFilter) {
        continue;
      }

      // Select this material's technique for the pass.
      // TEMPORARY PROBE (do not commit): "<FAF_TOGGLE_DIR>\albedopreview.on" /
      // "normalspreview.on" / "lightingpreview.on" swap the unit techniques for the
      // mesh.fx debug previews so albedo/UV, normals and lighting can be judged apart.
      {
        static int sPreviewMode = 0;
        static unsigned sPreviewToggleCalls = 0;
        if ((sPreviewToggleCalls++ % 200u) == 0u) {
          sPreviewMode = 0;
          char dir[512] = {};
          std::size_t length = 0;
          if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u) {
            char path[600];
            (void)std::snprintf(path, sizeof(path), "%s\\albedopreview.on", dir);
            if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sPreviewMode = 1;
            (void)std::snprintf(path, sizeof(path), "%s\\normalspreview.on", dir);
            if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sPreviewMode = 2;
            (void)std::snprintf(path, sizeof(path), "%s\\lightingpreview.on", dir);
            if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sPreviewMode = 3;
          }
        }
        if (sPreviewMode != 0 && meshFlags != 2 && material.mShaderAnnotation.view().find("Unit") != std::string_view::npos) {
          device->SelectTechnique(sPreviewMode == 1 ? "AlbedoPreview" : sPreviewMode == 2 ? "NormalsPreview" : "LightingPreview");
        } else {
          device->SelectTechnique(material.mShaderAnnotation.c_str());
        }
      }

      // Lazily resolve the environment texture sheet the first time this
      // material is drawn. When a terrain resource is present the sheet is the
      // terrain's per-environment lookup (keyed by the material's "environment"
      // string annotation); otherwise it is the renderer's shared mesh
      // environment texture. Both are ID3DTextureSheet-rooted, which is why the
      // lane is held at that base -- no cast is needed in either direction, and
      // the stored word is the one the binary stores.
      if (!material.mEnvironmentSheet) {
        if (terrainRes != nullptr) {
          const msvc8::string environmentKey =
            meshEffect->GetStringAnnotation(material.mShaderAnnotation, msvc8::string("environment"), msvc8::string("<default>"));
          material.mEnvironmentSheet = terrainRes->GetEnvLookup(environmentKey);
        } else {
          material.mEnvironmentSheet = meshEnvironmentTex;
        }
      }

      // TEMPORARY PROBE (do not commit): dark-unit triage - do the texture vars resolve?
      {
        static int sTexVarBudget = 0;
        if (sTexVarBudget < 12) {
          ++sTexVarBudget;
          const auto dimsOf = [](const boost::shared_ptr<ID3DTextureSheet>& sheet) {
            Wm3::Vector2i dims{0, 0};
            if (sheet) {
              (void)sheet->GetOriginalDimensions(&dims);
            }
            return dims;
          };
          const Wm3::Vector2i albedoDims = dimsOf(material.mAlbedoSheet);
          const Wm3::Vector2i specDims = dimsOf(material.mSpecularSheet);
          const Wm3::Vector2i normalsDims = dimsOf(material.mNormalsSheet);
          { // TEMPORARY PROBE (do not commit): pool/usage of a unit albedo for comparison with decals
            static int sDescBudget = 0;
            if (sDescBudget < 2 && material.mAlbedoSheet) {
              ++sDescBudget;
              ID3DTextureSheet::TextureHandle h{};
              material.mAlbedoSheet->GetTexture(h);
              ProbeLogTextureDesc("unit-albedo", h ? ProbeNativeTexture1(h.get()) : nullptr);
            }
          }
          gpg::Warnf("[TEXVARDIAG] exists env=%d albedo=%d spec=%d lookup=%d secondary=%d normals=%d | albedo=%p %dx%d spec=%p %dx%d normals=%p %dx%d tech=%s",
                     tv.environmentTexture.Exists() ? 1 : 0, tv.albedoTexture.Exists() ? 1 : 0,
                     tv.specularTexture.Exists() ? 1 : 0, tv.lookupTexture.Exists() ? 1 : 0,
                     tv.secondaryTexture.Exists() ? 1 : 0, tv.normalsTexture.Exists() ? 1 : 0,
                     static_cast<const void*>(material.mAlbedoSheet.get()), albedoDims.X(), albedoDims.Y(),
                     static_cast<const void*>(material.mSpecularSheet.get()), specDims.X(), specDims.Y(),
                     static_cast<const void*>(material.mNormalsSheet.get()), normalsDims.X(), normalsDims.Y(),
                     material.mShaderAnnotation.c_str());
        }
      }
      // Bind the six per-material texture samplers, in binary bind order.
      tv.environmentTexture.GetTexture(material.mEnvironmentSheet);
      tv.albedoTexture.GetTexture(material.mAlbedoSheet);
      tv.specularTexture.GetTexture(material.mSpecularSheet);
      tv.lookupTexture.GetTexture(material.mLookupSheet);
      tv.secondaryTexture.GetTexture(material.mSecondarySheet);
      tv.normalsTexture.GetTexture(material.mNormalsSheet);

      // Draw the bucket's instances through the LOD's lazily-built hardware mesh
      // batch (skinned for static-pose buckets, static otherwise). The
      // shared_ptr handle keeps the batch retained for the draw call.
      boost::shared_ptr<MeshBatch> batchHandle;
      if (MeshBatchEntryIsSkinned(bucket)) {
        lod->GetSkinnedBatch(batchHandle);
      } else {
        lod->GetStaticBatch(batchHandle);
      }
      // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
      {
        static int sBucketCount = 0;
        if ((sBucketCount++ % 61) == 0) {
          auto handleOf = [](const boost::shared_ptr<ID3DTextureSheet>& sheet) -> const void* {
            if (!sheet) {
              return nullptr;
            }
            ID3DTextureSheet::TextureHandle h{};
            sheet->GetTexture(h);
            return static_cast<const void*>(h.get());
          };
          gpg::Warnf("[SKINDIAG] bucket skinned=%d handle=%p verts=%d idx=%d instances=%d stage=%d flags=%d technique=%s albedo=%p/%p normals=%p/%p spec=%p/%p lookup=%p/%p env=%p n=%d",
                     MeshBatchEntryIsSkinned(bucket) ? 1 : 0, static_cast<const void*>(batchHandle.get()), batchHandle ? batchHandle->mVertexCount : -1, batchHandle ? batchHandle->mIndexCount : -1, static_cast<int>(bucket.second.size()), renderStage,
                     meshFlags, material.mShaderAnnotation.c_str(),
                     static_cast<const void*>(material.mAlbedoSheet.get()), handleOf(material.mAlbedoSheet),
                     static_cast<const void*>(material.mNormalsSheet.get()), handleOf(material.mNormalsSheet),
                     static_cast<const void*>(material.mSpecularSheet.get()), handleOf(material.mSpecularSheet),
                     static_cast<const void*>(material.mLookupSheet.get()), handleOf(material.mLookupSheet),
                     static_cast<const void*>(material.mEnvironmentSheet.get()), sBucketCount);
        }
      }
      if (batchHandle) {
        batchHandle->Render(bucket.second, mirrored);
      }
    }
  }

  /**
   * Address: 0x007DFDB0 (FUN_007DFDB0, Moho::MeshRenderer::RenderSkeletons)
   *
   * What it does:
   * Draws skeleton-debug overlays for visible mesh instances.
   */
  void MeshRenderer::RenderSkeletons(
    CD3DPrimBatcher* const debugBatcher,
    CDebugCanvas* const debugCanvas,
    const GeomCamera3& camera,
    const bool showBoneNames
  )
  {
    (void)debugBatcher;
    (void)debugCanvas;
    (void)camera;
    (void)showBoneNames;
  }

  /**
   * Address: 0x007E2290 (FUN_007E2290, Moho::MeshRenderer::RenderSkeleton)
   *
   * What it does:
   * Draws one mesh instance skeleton-debug overlay. The recovered entry
   * calls `MeshInstance::ComputeDebugPose` at the head of the function
   * (address 0x007DE7A0) to refresh the interpolated pose used for the
   * bone-debug pass; remaining CD3D-prim-batcher draw-call mechanics are
   * still under recovery, so this TU keeps the typed pose-refresh step
   * and drops the draw-call emission until its typed dependencies are
   * wired.
   */
  void MeshRenderer::RenderSkeleton(
    CD3DPrimBatcher* const debugBatcher,
    CDebugCanvas* const debugCanvas,
    MeshInstance* const meshInstance,
    const bool showBoneNames
  )
  {
    (void)debugBatcher;
    (void)debugCanvas;
    (void)showBoneNames;

    if (meshInstance == nullptr) {
      return;
    }

    const boost::shared_ptr<CAniPose> activePose = meshInstance->ComputeDebugPose();
    if (!activePose) {
      return;
    }

    // Draw-call emission (CD3DPrimBatcher bind + bone-line quad batch)
    // stays blocked on typed CD3DPrimBatcher surface recovery; the pose
    // refresh above produces the same observable side effect as the
    // binary's skeleton-overlay entry before it enters draw-call code.
  }

  /**
   * Address: 0x007E0380 (FUN_007E0380, ?RenderCartographic@MeshRenderer@Moho@@QAEXMMMABVGeomCamera3@2@@Z)
   *
   * What it does:
   * Forwards cartographic rendering to the batch-map overload using this
   * renderer's persistent `meshes` tree.
   */
  void MeshRenderer::RenderCartographic(
    const float surfaceElevation,
    const float minimumElevation,
    const float maximumElevation,
    const GeomCamera3& camera
  )
  {
    RenderCartographic(surfaceElevation, minimumElevation, maximumElevation, camera, meshes);
  }

  /**
   * Address: 0x007E0820 (FUN_007E0820, ?RenderDepth@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@@Z)
   *
   * What it does:
   * Forwards depth rendering to the batch-map overload using this renderer's
   * persistent `meshes` tree.
   */
  void MeshRenderer::RenderDepth(const GeomCamera3& camera)
  {
    RenderDepth(camera, meshes);
  }

  /**
   * Address: 0x007E11A0 (FUN_007E11A0, ?Render@MeshRenderer@Moho@@QAEXIABVGeomCamera3@2@PAVShadow@2@@Z)
   *
   * What it does:
   * Forwards one standard render call to the batch-map overload using this
   * renderer's persistent `meshes` tree.
   */
  void MeshRenderer::Render(const std::int32_t meshFlags, const GeomCamera3& camera, Shadow* const shadow)
  {
    Render(meshFlags, camera, shadow, meshes);
  }

  /**
   * Address: 0x007E11C0 (FUN_007E11C0,
   * ?RenderThumbnail@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@PAVMeshInstance@2@PAVID3DRenderTarget@2@PAVID3DDepthStencil@2@@Z)
   *
   * What it does:
   * Renders one mesh instance with one thumbnail camera into the caller-provided
   * color/depth targets. Binds the caller's render/depth targets with a full
   * clear, selects the mesh effect + top-LOD technique, binds the three material
   * texture sheets (albedo/normals/specular), then draws the single instance
   * through the LOD's static hardware batch (un-mirrored).
   */
  void MeshRenderer::RenderThumbnail(
    const GeomCamera3& camera,
    MeshInstance* const meshInstance,
    ID3DRenderTarget* const renderTarget,
    ID3DDepthStencil* const depthStencil
  )
  {
    if (!meshInstance || !renderTarget || !depthStencil) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();

    // Retain the instance's mesh for the whole pass and select its top LOD. The
    // binary reads `*mesh->lods._Myfirst` (the first LOD) after taking a live
    // shared_ptr copy via GetMesh(); the handle keeps the mesh alive across the
    // draw. (FUN_007E11C0 @0x007E11EA..0x007E11FE.)
    const boost::shared_ptr<Mesh> mesh = meshInstance->GetMesh();
    MeshLOD* const lod = mesh->lods.front();

    // Bind the caller's color + depth targets with a full clear (color
    // 0xFF000000, z=1.0, stencil=0). The decompiler mislabels the two pointer
    // args, but the frame slots resolve to renderTarget (arg_C, first SetRender-
    // Target1 param) then depthStencil (arg_10, second) — matching the caller
    // MeshThumbnailRenderer::RenderThumbnail which passes (mColorTarget,
    // mDepthStencil). (FUN_007E11C0 @0x007E11FF..0x007E1220.)
    device->SetRenderTarget1(renderTarget, depthStencil, true, 0xFF000000, 1.0f, 0);

    // Select the mesh effect file, then bind the mesh shader-constant lane for
    // this thumbnail pass (no shadow, not mirrored).
    device->SelectFxFile("mesh");
    ConfigureShader(camera, nullptr, false);

    // Select the top LOD material's technique, then bind its three texture
    // sheets in binary bind order: albedo, normals, specular. These are the same
    // shared shader-var handles the batch-map render path binds
    // (GetMeshTextureShaderVars()). (FUN_007E11C0 @0x007E124E..0x007E127D.)
    MeshMaterial& material = lod->mat;
    device->SelectTechnique(material.mShaderAnnotation.c_str());

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();
    tv.albedoTexture.GetTexture(material.mAlbedoSheet);
    tv.normalsTexture.GetTexture(material.mNormalsSheet);
    tv.specularTexture.GetTexture(material.mSpecularSheet);

    // Draw the single instance through the LOD's lazily-built static hardware
    // batch (thumbnails are never skinned, so GetStaticBatch only). The batch is
    // fed a one-element instance vector and drawn un-mirrored; the shared_ptr
    // handle retains the batch for the draw and the vector releases after.
    // (FUN_007E11C0 @0x007E1282..0x007E12DB.)
    boost::shared_ptr<MeshBatch> batchHandle;
    lod->GetStaticBatch(batchHandle);
    if (batchHandle) {
      msvc8::vector<MeshInstance*> singleInstance;
      singleInstance.push_back(meshInstance);
      batchHandle->Render(singleInstance, false);
    }
  }

  /**
   * Address: 0x007DFA00 (FUN_007DFA00, ?Batch@MeshRenderer@Moho@@QAEXHMABVGeomCamera3@2@ABVVector4f@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::Batch(
   *   MeshRenderer* this, int gameTick, float deltaFrame,
   *   const GeomCamera3& camera, const Vector4f& fadePlane);
   *
   * What it does:
   * Rebuilds this renderer's per-key render-batch map (`meshes`) for one frame.
   * Clears the bucket tree, snapshots the frame tick/delta, collects every mesh
   * instance intersecting the camera frustum from the mesh spatial DB, then for
   * each visible instance: selects a LOD by view-depth distance, applies the
   * dissolve fade, frustum-culls the instance sphere, and appends it into the
   * bucket keyed by `(isStaticPose, blueprint sort order)`.
   */
  void MeshRenderer::Batch(
    const std::int32_t gameTick,
    const float deltaFrameArg,
    const GeomCamera3& camera,
    const Vector4f& fadePlane
  )
  {
    // Clear last frame's buckets and reset the renderer frame lanes.
    gPropSeen = 0; gPropLod = 0; gPropFrustum = 0; gPropPushed = 0; // TEMPORARY PROBE (do not commit)
    RecycleBatchBuckets(meshes);
    // Binary stores `gameTick` (param0) into +0x94 and clears the batched-count
    // lane at +0x9C; both are reused by this pass as frame-scoped scratch.
    instanceListSize = gameTick;
    instanceListStateFlags = 0u;
    deltaFrame = deltaFrameArg;

    // Camera forward direction = negated third row of the inverse-view matrix.
    // Used as the spatial-DB support/selector axis for the collect volume.
    const Wm3::Vec3f cameraForward(
      -camera.inverseView.r[2].x,
      -camera.inverseView.r[2].y,
      -camera.inverseView.r[2].z
    );

    // Collect every renderable instance whose bounds intersect the camera
    // frustum solid. SpatialDB<MeshInstance> yields its own payload type, so
    // these slots no longer have to be laundered through UserEntity*.
    gpg::fastvector<MeshInstance*> collected;
    meshSpatialDb.CollectAllInVolume(
      collected, &const_cast<GeomCamera3&>(camera).solid2, cameraForward, fadePlane
    );

    // TEMPORARY PROBE (do not commit) -- transport-flight bad_alloc triage.
    // The failing allocation is a bucket vector's growth a few lines below, so
    // the question is whether `collected` came back implausibly large (a
    // spatial-DB tree that is cyclic or accumulating duplicates) or stayed
    // normal (in which case the allocator/address space is the problem, not
    // this pass). Unthrottled and unconditional, but only past a bound no sane
    // frame reaches, so it costs one compare per frame until it matters.
    {
      constexpr std::size_t kImplausibleCollectCount = 100000u;
      static bool sReportedImplausible = false;
      if (collected.size() > kImplausibleCollectCount && !sReportedImplausible) {
        sReportedImplausible = true;
        char probe[160];
        sprintf_s(probe, sizeof(probe), "[COLLECTDIAG] collected=%Iu tick=%d -- spatial DB is returning too much\n",
                  collected.size(), gameTick);
        ::OutputDebugStringA(probe);
      }
    }

    // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
    {
      static int sCollectCount = 0;
      if ((sCollectCount++ % 61) == 0) {
        int skinnedCollected = 0;
        for (MeshInstance* const e : collected) {
          skinnedCollected += e->isStaticPose != 0u ? 1 : 0;
        }
        gpg::Warnf("[SKINDIAG] Batch collected=%d skinned=%d tick=%d n=%d", static_cast<int>(collected.size()),
                   skinnedCollected, gameTick, sCollectCount);
      }
    }
    for (MeshInstance* const instance : collected) {

      // Skinned/static inclusion gates plus the hidden flag.
      const bool isStatic = instance->isStaticPose != 0u;
      // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
      if (isStatic) {
        static int sSkinTop = 0;
        if ((sSkinTop++ % 31) == 0) {
          gpg::Warnf("[SKINDIAG] skinned inst=%p hidden=%u tickFilter=%d tick=%d renSkinned=%d n=%d",
                     static_cast<const void*>(instance), static_cast<unsigned>(instance->isHidden), instance->unk24, gameTick,
                     ren_MeshSkinned ? 1 : 0, sSkinTop);
        }
      }
      if ((!ren_MeshSkinned && isStatic) || (!ren_MeshStatic && !isStatic) || instance->isHidden != 0u) {
        continue;
      }

      // Per-instance tick filter (+0x24). It is 0 for every constructed mesh
      // instance today, so the `filter == 0` short-circuit always accepts and
      // the game tick is only compared when a future stamp is present. The
      // binary loads this compare operand from a stale register lane that IDA
      // splits across the arg0/deltaFrame stack slots; both are dead while the
      // filter is 0, so we transcribe the intent (compare against the frame
      // tick) faithfully.
      const std::int32_t renderTickFilter = instance->unk24;
      if (renderTickFilter != 0 && renderTickFilter != gameTick) {
        continue;
      }

      instance->UpdateInterpolatedFields();

      // View-depth distance: the binary treats the first sixteen bytes of the
      // camera transform as a plane (a,b,c,d) and dots the interpolated world
      // position against it -- 0x007DFB7F..0x007DFBB9 reads [cam+8]*pos.z +
      // [cam+4]*pos.y + [cam+0]*pos.x + [cam+0Ch], with `orient_` at +0x00.
      // Those are MEMORY LANES 0..3 of the quaternion, which in Wm3's storage
      // are (w,x,y,z). The previous body spelled them as the named fields
      // (.x,.y,.z,.w) -- correct only while lane 0 was called .x; the
      // scalar-first conversion moved lane 0 to .w, and this site was not
      // converted with it, so every mesh got a garbage depth and was culled by
      // ComputeLOD. Index the storage directly so the lane order can no
      // longer drift with the naming.
      const Wm3::Vec3f& worldPos = instance->interpolatedPosition;
      const Wm3::Quatf& plane = camera.tranform.orient_;
      const float distance =
        worldPos.z * plane.m_afTuple[2]
        + worldPos.y * plane.m_afTuple[1]
        + plane.m_afTuple[0] * worldPos.x
        + plane.m_afTuple[3];

      const boost::shared_ptr<Mesh> mesh = instance->GetMesh();
      const MeshLOD* const lod = mesh->ComputeLOD(distance);
      if (instance->isStaticPose == 0u) { ++gPropSeen; if (lod != nullptr) { ++gPropLod; } if (camera.solid2.Intersects(instance->sphere)) { ++gPropFrustum; } } // TEMPORARY PROBE (do not commit)

      // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
      {
        static int sLodBudget = 0;
        if (sLodBudget < 16 && instance->isStaticPose != 0u) {
          ++sLodBudget;
          char probe[320];
          (void)std::snprintf(
            probe, sizeof(probe),
            "[LODDIAG] inst=%p pos=(%.1f,%.1f,%.1f) camq=(%.3f,%.3f,%.3f,%.3f) campos=(%.1f,%.1f,%.1f) "
            "dist=%.1f lod=%p cutoff=%.1f dissolve=%.1f hidden=%u\n",
            static_cast<const void*>(instance), worldPos.x, worldPos.y, worldPos.z,
            plane.m_afTuple[0], plane.m_afTuple[1], plane.m_afTuple[2], plane.m_afTuple[3],
            camera.tranform.pos_.x, camera.tranform.pos_.y, camera.tranform.pos_.z,
            distance, static_cast<const void*>(lod), mesh->GetMaxCutoff(), ren_MeshDissolve,
            static_cast<unsigned>(instance->isHidden));
          ::OutputDebugStringA(probe);
        }
      }
      // TEMPORARY PROBE -- invisible-commander triage, delete when resolved.
      if (instance->isStaticPose != 0u) {
        static int sSkinCount = 0;
        if ((sSkinCount++ % 31) == 0 || FafProbeFrameDiag() > 0) {
          gpg::Warnf("[SKINDIAG] f=%d Batch inst=%p pos=(%.1f,%.1f,%.1f) dist=%.1f lod=%p maxCutoff=%.1f frustum=%d sphere=(%.1f,%.1f,%.1f r=%.1f) n=%d q=(%.3f,%.3f,%.3f,%.3f)",
                     FafProbeFrameSeq(), static_cast<const void*>(instance), worldPos.x, worldPos.y, worldPos.z, distance,
                     static_cast<const void*>(lod), mesh->GetMaxCutoff(),
                     camera.solid2.Intersects(instance->sphere) ? 1 : 0, instance->sphere.Center.X(), instance->sphere.Center.Y(),
                     instance->sphere.Center.Z(), instance->sphere.Radius, sSkinCount, instance->endTransform.orient_.w, instance->endTransform.orient_.x, instance->endTransform.orient_.y, instance->endTransform.orient_.z);
        }
      }
      if (lod == nullptr || distance > (mesh->GetMaxCutoff() + ren_MeshDissolve)) {
        continue;
      }

      // Dissolve fade for LODs that fade out past their cutoff.
      if (lod->useDissolve != 0u && lod->cutoff > 0.0f && distance > lod->cutoff) {
        instance->SetDissolve(1.0f - ((distance - lod->cutoff) / ren_MeshDissolve));
      } else {
        instance->dissolve = 1.0f;
      }

      // Fully dissolved instances are skipped entirely.
      if (instance->dissolve < ren_MeshDissolveCutoff) {
        continue;
      }

      instance->UpdateInterpolatedFields();

      // Second frustum cull against the camera solid using the refreshed
      // bounding sphere. The binary reads this camera pointer from the arg0
      // stack slot, which the demangled `int` parameter cannot address; the
      // only live view camera in this pass is `camera`, so both the collect
      // volume and this cull share it.
      if (!camera.solid2.Intersects(instance->sphere)) {
        continue;
      }

      // Append into the bucket keyed by (isStaticPose, selected LOD, sort
      // order). The LOD lane carries the `ComputeLOD` result: the binary
      // stores it at 0x007DFBED and the key load at 0x007DFCDC reads that same
      // slot back (see `MeshBatchKey::mLod` for why IDA splits the one slot
      // into `var_1D0`/`var_1D4`). Keying on it is what keeps one bucket to one
      // LOD, so each bucket draws with its own material and hardware batch.
      MeshBatchKey key;
      key.mIsStaticPose = instance->isStaticPose;
      key.mLod = const_cast<MeshLOD*>(lod);
      key.mSortKey = mesh->GetSortOrder();

      MeshBatchInstanceVector* const bucket = MeshBatchBucketTreeFindOrCreateInstances(key, meshes);
      if (bucket != nullptr) {
        // `std::vector<MeshInstance*>::push_back` (0x007D9FC0, growing through
        // `_Insert_n` at 0x007DA270) - the container's own append.
        bucket->push_back(instance);
        ++instanceListStateFlags;
      }
    }
    { static int sF = 0; if ((sF++ % 20) == 0) { gpg::Warnf("[PROPFUNNEL] seen=%d lod=%d frustum=%d cam=(%.1f,%.1f,%.1f)", gPropSeen, gPropLod, gPropFrustum, camera.tranform.pos_.x, camera.tranform.pos_.y, camera.tranform.pos_.z); } } // TEMPORARY PROBE (do not commit)

    // FAF: the bones of this map's skinned instances, written once for every
    // pass that is about to draw it.
    PrepareBonePalettes();
  }

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Writes the bones of every posed instance of every skinned bucket in
   * `meshes` into the bone palette texture and uploads it, when the mesh
   * effect reads its skinning palette from there. Each Batch call starts the
   * texture over: the draws of the previous map have all been issued by then.
   */
  void MeshRenderer::PrepareBonePalettes()
  {
    if (!HardwareMeshBatch::UsesBoneTexture()) {
      return;
    }

    HardwareMeshBatch::BeginBonePalettes();
    for (const MeshBatchBucket& bucket : meshes) {
      // See RecycleBatchBuckets: an empty bucket's LOD may be released.
      if (bucket.second.empty() || !MeshBatchEntryIsSkinned(bucket)) {
        continue;
      }

      // Every LOD batch is a HardwareMeshBatch (BuildHardwareMeshBatchForLod).
      boost::shared_ptr<MeshBatch> batchHandle;
      MeshBatchEntryLod(bucket)->GetSkinnedBatch(batchHandle);
      if (batchHandle) {
        static_cast<HardwareMeshBatch*>(batchHandle.get())->PrepareBonePalettes(bucket.second);
      }
    }
    HardwareMeshBatch::UploadBonePalettes();
  }

  namespace
  {
    /**
     * The distance fog parameters of a mesh effect compiled with
     * FAF_BONE_TEXTURE (see MeshRenderer::SetDistanceFog).
     */
    struct DistanceFogShaderVars
    {
      ShaderVar params{};
      ShaderVar color{};

      DistanceFogShaderVars()
      {
        RegisterShaderVar("fogParams", &params, "mesh");
        RegisterShaderVar("fogColor", &color, "mesh");
      }
    };

    [[nodiscard]] DistanceFogShaderVars& GetDistanceFogShaderVars()
    {
      // Never destroyed: the effect unlinks its shader-vars when it goes,
      // which may happen after static destruction would have run.
      static DistanceFogShaderVars* const vars = new DistanceFogShaderVars();
      return *vars;
    }
  } // namespace

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Sets the mesh effect's fog parameters to what the fixed-function linear
   * table fog computes per pixel from the same values: the fraction of the
   * pixel's own colour kept is saturate((end - d) / (end - start)), stored
   * as `end / (end - start)` and `1 / (end - start)` so the shader does one
   * multiply-add. d is the eye distance when the projection is w-based
   * (Direct3D's "w-friendly" check, a non-zero _34) and the depth otherwise.
   * With fog off the parameters keep every pixel's colour.
   */
  void MeshRenderer::SetDistanceFog(
    const bool enabled,
    const gpg::gal::Matrix* const projection,
    const float fogStart,
    const float fogEnd,
    const std::uint32_t fogColor
  )
  {
    DistanceFogShaderVars& vars = GetDistanceFogShaderVars();
    if (!vars.params.Exists()) {
      return;
    }

    float params[4] = {1.0f, 0.0f, 1.0f, 0.0f};
    if (enabled) {
      // A start at or past the end would divide by zero; this turns it into
      // the step the fog would converge on.
      constexpr float kMinimumFogRange = 1.0e-4f;
      const float range = std::max(fogEnd - fogStart, kMinimumFogRange);
      params[0] = fogEnd / range;
      params[1] = 1.0f / range;
      params[2] = (projection == nullptr || projection->r[2].w != 0.0f) ? 1.0f : 0.0f;
    }
    SetShaderVarMem(vars.params, 4u, params);

    constexpr float kChannelScale = 1.0f / 255.0f;
    const float color[3] = {
      static_cast<float>((fogColor >> 16u) & 0xFFu) * kChannelScale,
      static_cast<float>((fogColor >> 8u) & 0xFFu) * kChannelScale,
      static_cast<float>(fogColor & 0xFFu) * kChannelScale,
    };
    SetShaderVarMem(vars.color, 3u, color);
  }

  namespace
  {
    /**
     * `Moho::RefCountedCache<MeshKey,Mesh>::Deleter` (address block on
     * `ConstructSharedMeshWithCacheEvictingDeleter`, Mesh.h). Erases the
     * mesh's cache-tree entry the moment its last strong reference drops,
     * then destroys the mesh itself through its own virtual destructor --
     * matching `dispose()`'s real two-step body (`sub_7E69E0`): `erase_node`
     * on the tree, then `Mesh`'s own scalar deleting destructor.
     */
    struct MeshCacheEvictingDeleter
    {
      MeshRendererMeshCacheTree* tree;
      MeshKey key;

      void operator()(Mesh* const mesh) const
      {
        if (tree != nullptr) {
          tree->erase(key);
        }
        delete mesh;
      }
    };
  } // namespace

  void ConstructSharedMeshWithCacheEvictingDeleter(
    boost::shared_ptr<Mesh>& out,
    Mesh* const raw,
    MeshRendererMeshCacheTree& tree,
    const MeshKey& key)
  {
    out.reset(raw, MeshCacheEvictingDeleter{&tree, key});
  }

  // MSVC emits one out-of-line body per (template, element type), and this
  // binary carries exactly two of each: the renderer's SpatialDB<MeshInstance>
  // and the world session's SpatialDB<UserEntity>. /OPT:ICF then folded the
  // identical, pointer-only-differing pairs onto one address apiece, which is
  // why the export names only one of them.
  class WaveGenerator;
  class ShoreCell;
  class CWldTerrainDecal;

  template struct SpatialDB<MeshInstance>;
  template struct SpatialDB<UserEntity>;
  template struct SpatialDB<WaveGenerator>;
  template struct SpatialDB<ShoreCell>;
  template struct SpatialDB<CWldTerrainDecal>;
  template struct SpatialDBEntry<MeshInstance>;
  template struct SpatialDBEntry<UserEntity>;
  template struct SpatialDBEntry<WaveGenerator>;
  template struct SpatialDBEntry<ShoreCell>;
  template struct SpatialDBEntry<CWldTerrainDecal>;
} // namespace moho
