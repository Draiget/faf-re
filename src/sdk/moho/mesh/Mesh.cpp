#include "Mesh.h"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector4f.h"
#include "moho/mesh/MeshBatch.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/Logging.h"

namespace moho
{
  [[nodiscard]] float REN_GetSimDeltaSeconds();
}

namespace moho
{
  float ren_MeshDissolve = 0.0f;
  float ren_MeshDissolveCutoff = 0.0f;

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
   * Address: 0x00832060 (FUN_00832060, boost::shared_ptr_MeshInstance::shared_ptr_MeshInstance)
   *
   * What it does:
   * Constructs one `shared_ptr<MeshInstance>` from one raw mesh-instance
   * pointer lane.
   */
  boost::shared_ptr<MeshInstance>* ConstructSharedMeshInstanceFromRaw(
    boost::shared_ptr<MeshInstance>* const outMeshInstance,
    MeshInstance* const meshInstance
  )
  {
    return ::new (outMeshInstance) boost::shared_ptr<MeshInstance>(meshInstance);
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

  struct MeshInstanceOwnerRuntimeView
  {
    std::uint8_t reserved00_33[0x34];
    MeshInstance* meshInstance; // +0x34
  };
  static_assert(
    offsetof(MeshInstanceOwnerRuntimeView, meshInstance) == 0x34,
    "MeshInstanceOwnerRuntimeView::meshInstance offset must be 0x34"
  );

  struct MeshInstanceSphereRuntimeView
  {
    float centerX; // +0x00
    float centerY; // +0x04
    float centerZ; // +0x08
    float radius;  // +0x0C
  };
  static_assert(sizeof(MeshInstanceSphereRuntimeView) == 0x10, "MeshInstanceSphereRuntimeView size must be 0x10");

  struct MeshInstanceBoundsRuntimeView
  {
    float minX; // +0x00
    float minY; // +0x04
    float minZ; // +0x08
    float maxX; // +0x0C
    float maxY; // +0x10
    float maxZ; // +0x14
  };
  static_assert(sizeof(MeshInstanceBoundsRuntimeView) == 0x18, "MeshInstanceBoundsRuntimeView size must be 0x18");

  /**
   * Address: 0x004FE260 (FUN_004FE260)
   *
   * What it does:
   * Expands one sphere `(center.xyz,radius)` into axis-aligned bounds
   * `(min.xyz,max.xyz)` and writes the result into caller output storage.
   */
  [[maybe_unused]] MeshInstanceBoundsRuntimeView* ExpandMeshInstanceSphereToBounds(
    MeshInstanceBoundsRuntimeView* const outBounds,
    const MeshInstanceSphereRuntimeView* const sphere
  ) noexcept
  {
    const float radius = sphere->radius;
    outBounds->minX = sphere->centerX - radius;
    outBounds->minY = sphere->centerY - radius;
    outBounds->minZ = sphere->centerZ - radius;
    outBounds->maxX = sphere->centerX + radius;
    outBounds->maxY = sphere->centerY + radius;
    outBounds->maxZ = sphere->centerZ + radius;
    return outBounds;
  }

  /**
   * Address: 0x0086AF80 (FUN_0086AF80)
   *
   * What it does:
   * Refreshes interpolation on the owner mesh-instance lane and copies current
   * world-space sphere `(center.xyz, radius)` into caller output storage.
   */
  [[maybe_unused]] MeshInstanceSphereRuntimeView* CopyOwnerMeshInstanceSphere(
    const MeshInstanceOwnerRuntimeView* const owner,
    MeshInstanceSphereRuntimeView* const outSphere
  )
  {
    if (outSphere == nullptr) {
      return nullptr;
    }

    MeshInstance* const meshInstance = owner != nullptr ? owner->meshInstance : nullptr;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      outSphere->centerX = meshInstance->sphere.Center.x;
      outSphere->centerY = meshInstance->sphere.Center.y;
      outSphere->centerZ = meshInstance->sphere.Center.z;
      outSphere->radius = meshInstance->sphere.Radius;
    }

    return outSphere;
  }

  /**
   * Address: 0x0086AFC0 (FUN_0086AFC0)
   *
   * What it does:
   * Refreshes interpolation on the owner mesh-instance lane and copies current
   * world-space axis-aligned bounds `(min.xyz,max.xyz)` into output storage.
   */
  [[maybe_unused]] MeshInstanceBoundsRuntimeView* CopyOwnerMeshInstanceBounds(
    const MeshInstanceOwnerRuntimeView* const owner,
    MeshInstanceBoundsRuntimeView* const outBounds
  )
  {
    if (outBounds == nullptr) {
      return nullptr;
    }

    MeshInstance* const meshInstance = owner != nullptr ? owner->meshInstance : nullptr;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      outBounds->minX = meshInstance->xMin;
      outBounds->minY = meshInstance->yMin;
      outBounds->minZ = meshInstance->zMin;
      outBounds->maxX = meshInstance->xMax;
      outBounds->maxY = meshInstance->yMax;
      outBounds->maxZ = meshInstance->zMax;
    }

    return outBounds;
  }

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

  struct SpatialShardData;

  template <class T>
  struct SpatialShardArray
  {
    void* mDebugProxy; // +0x00
    T** mBegin;        // +0x04
    T** mEnd;          // +0x08
    T** mCapacity;     // +0x0C
  };

  static_assert(sizeof(SpatialShardArray<void>) == 0x10, "SpatialShardArray size must be 0x10");

  struct SpatialShard
  {
    SpatialShard* mParent;                     // +0x00
    gpg::Rect2i mAreaRect;                     // +0x04
    std::int32_t mLevel;                       // +0x14
    std::int32_t mUnitCount;                   // +0x18
    std::int32_t mProjectileCount;             // +0x1C
    std::int32_t mPropCount;                   // +0x20
    std::int32_t mEntityCount;                 // +0x24
    Wm3::AxisAlignedBox3f mBounds;             // +0x28
    SpatialShardArray<SpatialShard> mShards;   // +0x40
    SpatialShardArray<SpatialShardData> mData; // +0x50

    /**
     * Address: 0x005011A0 (FUN_005011A0, Moho::SpatialShard::SpatialShard)
     *
     * What it does:
     * Builds one shard node (or one leaf-data lane set) for the recursive 4x4
     * spatial partition tree.
     */
    SpatialShard(std::int32_t level, SpatialShard* parent, const gpg::Rect2i& areaRect);

    /**
     * Address: 0x00501370 (FUN_00501370, Moho::SpatialShard::~SpatialShard)
     *
     * What it does:
     * Releases recursively-owned child shards or leaf-data lanes and clears
     * shard pointer arrays.
     */
    ~SpatialShard();

    /**
     * Address: 0x00501490 (FUN_00501490, Moho::SpatialShard::CountType)
     *
     * What it does:
     * Returns true when this shard has no entities for the requested type mask.
     */
    [[nodiscard]] bool CountType(EEntityType type) const;

    /**
     * Address: 0x00501710 (FUN_00501710, Moho::SpatialShard::DecrementCount)
     *
     * What it does:
     * Decrements one requested entity-lane counter on this shard and all
     * ancestors.
     */
    static void DecrementCount(SpatialShard* shard, EEntityType type);

    /**
     * Address: 0x00501500 (FUN_00501500, Moho::SpatialShard::RecalculateBounds)
     *
     * What it does:
     * Rebuilds this shard bounds from the 16 child lanes and propagates
     * recalculation up the parent chain.
     */
    void RecalculateBounds();
  };

  static_assert(sizeof(SpatialShard) == 0x60, "SpatialShard size must be 0x60");
  static_assert(offsetof(SpatialShard, mLevel) == 0x14, "SpatialShard::mLevel offset must be 0x14");
  static_assert(offsetof(SpatialShard, mBounds) == 0x28, "SpatialShard::mBounds offset must be 0x28");
  static_assert(offsetof(SpatialShard, mShards) == 0x40, "SpatialShard::mShards offset must be 0x40");
  static_assert(offsetof(SpatialShard, mData) == 0x50, "SpatialShard::mData offset must be 0x50");

  struct SpatialMapNode
  {
    SpatialMapNode* mLeft;      // +0x00
    SpatialMapNode* mParent;    // +0x04
    SpatialMapNode* mRight;     // +0x08
    Wm3::AxisAlignedBox3f mBox; // +0x0C
    std::uint32_t mEntityType;     // +0x24
    SpatialShardData* mShardData;  // +0x28
    float mFadeOut;                // +0x2C
    void* mOwner;                  // +0x30
    std::uint8_t mColor;           // +0x34
    std::uint8_t mIsNil;           // +0x35
    std::uint8_t mPad_36_37[0x02];
  };

  static_assert(sizeof(SpatialMapNode) == 0x38, "SpatialMapNode size must be 0x38");
  static_assert(offsetof(SpatialMapNode, mBox) == 0x0C, "SpatialMapNode::mBox offset must be 0x0C");
  static_assert(offsetof(SpatialMapNode, mEntityType) == 0x24, "SpatialMapNode::mEntityType offset must be 0x24");
  static_assert(offsetof(SpatialMapNode, mShardData) == 0x28, "SpatialMapNode::mShardData offset must be 0x28");
  static_assert(offsetof(SpatialMapNode, mFadeOut) == 0x2C, "SpatialMapNode::mFadeOut offset must be 0x2C");
  static_assert(offsetof(SpatialMapNode, mOwner) == 0x30, "SpatialMapNode::mOwner offset must be 0x30");
  static_assert(offsetof(SpatialMapNode, mIsNil) == 0x35, "SpatialMapNode::mIsNil offset must be 0x35");

  struct SpatialMapTree
  {
    void* mAllocatorCookie; // +0x00
    SpatialMapNode* mHead;  // +0x04
    std::int32_t mSize;     // +0x08
  };

  static_assert(sizeof(SpatialMapTree) == 0x0C, "SpatialMapTree size must be 0x0C");

  struct SpatialShardData
  {
    SpatialShard* mShard;       // +0x00
    std::uint8_t mPad_04_13[0x10];
    std::int32_t mTimeSinceRecalc; // +0x14
    Wm3::AxisAlignedBox3f mBounds; // +0x18
    SpatialMapTree mMapUnits;      // +0x30
    SpatialMapTree mMapProjectiles; // +0x3C
    SpatialMapTree mMapProps;      // +0x48
    SpatialMapTree mMapEntities;   // +0x54

    /**
     * Address: 0x00500F60 (FUN_00500F60, Moho::SpatialShardData::SpatialShardData)
     *
     * What it does:
     * Initializes one leaf-data lane container and allocates sentinel map
     * heads for unit/projectile/prop/entity trees.
     */
    explicit SpatialShardData(SpatialShard* ownerShard);

    /**
     * Address: 0x005017E0 (FUN_005017E0, Moho::SpatialShardData::~SpatialShardData)
     *
     * What it does:
     * Destroys all map nodes in unit/projectile/prop/entity trees and releases
     * their sentinel heads.
     */
    ~SpatialShardData();

    /**
     * Address: 0x00502780 (FUN_00502780, Moho::SpatialShardData::CollectFromData)
     *
     * What it does:
     * Appends all entity pointers from selected leaf maps to destination.
     */
    static void CollectFromData(EEntityType type, gpg::fastvector<UserEntity*>& destination, SpatialShardData* data);

    /**
     * Address: 0x00501070 (FUN_00501070, Moho::SpatialShardData::HasType)
     *
     * What it does:
     * Returns true when this leaf-data lane has no entities for the requested
     * type mask.
     */
    [[nodiscard]] static bool HasType(const SpatialShardData* data, EEntityType type);

    /**
     * Address: 0x005023B0 (FUN_005023B0, Moho::SpatialShardData::RecalculateBounds)
     *
     * What it does:
     * Rebuilds leaf-map aggregate bounds and updates owner shard bounds.
     */
    void RecalculateBounds();

    /**
     * Address: 0x00503BB0 (FUN_00503BB0, Moho::SpatialShardData::Collect)
     *
     * What it does:
     * Recursively collects selected entities from every shard/data lane.
     */
    static void Collect(SpatialShard* shard, EEntityType type, gpg::fastvector<UserEntity*>& destination);

    /**
     * Address: 0x00503C00 (FUN_00503C00, Moho::SpatialShardData::CollectInBox)
     *
     * What it does:
     * Recursively collects selected entities that intersect one AABB query.
     */
    static void CollectInBox(
      SpatialShard* shard,
      EEntityType type,
      const Wm3::AxisAlignedBox3f& bounds,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00502950 (FUN_00502950, Moho::SpatialShardData::CollectInBoxFromData)
     *
     * What it does:
     * Collects selected leaf-map entities intersecting one AABB query.
     */
    void CollectInBoxFromData(
      const Wm3::AxisAlignedBox3f& bounds,
      EEntityType type,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00503DB0 (FUN_00503DB0, Moho::SpatialShardData::CollectInVolume)
     *
     * What it does:
     * Recursively collects selected entities that intersect one convex volume.
     */
    static void CollectInVolume(
      SpatialShard* shard,
      EEntityType type,
      CGeomSolid3* volume,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00503490 (FUN_00503490, Moho::SpatialShardData::CollectInVolumeFromData)
     *
     * What it does:
     * Collects selected leaf-map entities intersecting one convex volume.
     */
    void CollectInVolumeFromData(gpg::fastvector<UserEntity*>& destination, EEntityType type, CGeomSolid3* volume);

    /**
     * Address: 0x00502340 (FUN_00502340, Moho::SpatialShardData::RemoveNode)
     *
     * What it does:
     * Removes one map node from the matching type lane and decrements shard
     * counters up the parent chain.
     */
    void RemoveNode(SpatialMapNode* node);

    /**
     * Address: 0x00503730 (FUN_00503730, Moho::SpatialShardData::FindInVolumeFromData)
     *
     * What it does:
     * Collects leaf-lane entities intersecting one volume with fade-threshold
     * early-out driven by support selector and viewport plane lanes.
     */
    static void FindInVolumeFromData(
      const Vector4f& fadePlane,
      const Wm3::Vector3f& supportSelector,
      SpatialShardData* data,
      EEntityType type,
      CGeomSolid3* volume,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00503E30 (FUN_00503E30, Moho::SpatialShardData::FindInVolume)
     *
     * What it does:
     * Recursively collects entities intersecting one volume using view/fade
     * cull inputs for leaf-lane filtering.
     */
    static void FindInVolume(
      SpatialShard* shard,
      EEntityType type,
      CGeomSolid3* volume,
      const Wm3::Vector3f& supportSelector,
      const Vector4f& fadePlane,
      gpg::fastvector<UserEntity*>& destination
    );
  };

  static_assert(sizeof(SpatialShardData) == 0x60, "SpatialShardData size must be 0x60");
  static_assert(offsetof(SpatialShardData, mTimeSinceRecalc) == 0x14, "SpatialShardData::mTimeSinceRecalc offset must be 0x14");
  static_assert(offsetof(SpatialShardData, mBounds) == 0x18, "SpatialShardData::mBounds offset must be 0x18");
  static_assert(offsetof(SpatialShardData, mMapUnits) == 0x30, "SpatialShardData::mMapUnits offset must be 0x30");
  static_assert(offsetof(SpatialShardData, mMapProjectiles) == 0x3C, "SpatialShardData::mMapProjectiles offset must be 0x3C");
  static_assert(offsetof(SpatialShardData, mMapProps) == 0x48, "SpatialShardData::mMapProps offset must be 0x48");
  static_assert(offsetof(SpatialShardData, mMapEntities) == 0x54, "SpatialShardData::mMapEntities offset must be 0x54");
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

  [[nodiscard]] bool Finite(const float value) noexcept
  {
    return std::isfinite(value);
  }

  [[nodiscard]] bool HasFiniteWorldBounds(const moho::MeshInstance& instance) noexcept
  {
    return Finite(instance.xMin) && Finite(instance.yMin) && Finite(instance.zMin) && Finite(instance.xMax) &&
      Finite(instance.yMax) && Finite(instance.zMax);
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
  constexpr std::size_t kSpatialMapMaxNodeCount = 0x06666665u;
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

  [[nodiscard]] bool SpatialShardHasNoRequestedType(const moho::SpatialShard& shard, const moho::EEntityType type) noexcept
  {
    return shard.CountType(type);
  }

  [[nodiscard]] bool SpatialShardDataHasNoRequestedType(
    const moho::SpatialShardData& data,
    const moho::EEntityType type
  ) noexcept
  {
    return moho::SpatialShardData::HasType(&data, type);
  }

  [[nodiscard]] bool AxisAlignedBoxesIntersect(const Wm3::AxisAlignedBox3f& lhs, const Wm3::AxisAlignedBox3f& rhs) noexcept
  {
    return lhs.Min.x <= rhs.Max.x && rhs.Min.x <= lhs.Max.x && lhs.Min.y <= rhs.Max.y && rhs.Min.y <= lhs.Max.y &&
      lhs.Min.z <= rhs.Max.z && rhs.Min.z <= lhs.Max.z;
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

  struct SphereBoundsProbe
  {
    Wm3::Vector3f center;
    float radius;
  };

  struct SegmentEndpointPair
  {
    Wm3::Vector3f begin;
    Wm3::Vector3f end;
  };

  static_assert(sizeof(SphereBoundsProbe) == 0x10, "SphereBoundsProbe size must be 0x10");
  static_assert(sizeof(SegmentEndpointPair) == 0x18, "SegmentEndpointPair size must be 0x18");

  /**
   * Address: 0x00500D00 (FUN_00500D00)
   *
   * What it does:
   * Returns true only when both segment endpoints lie within the sphere
   * defined by `probe.center` and `probe.radius`.
   */
  [[maybe_unused]] [[nodiscard]] bool AreSegmentEndpointsWithinSphereBounds(
    const SphereBoundsProbe& probe,
    const SegmentEndpointPair& endpoints
  ) noexcept
  {
    const auto distanceSquaredTo = [&probe](const Wm3::Vector3f& point) noexcept {
      const float dx = point.x - probe.center.x;
      const float dy = point.y - probe.center.y;
      const float dz = point.z - probe.center.z;
      return (dx * dx) + (dy * dy) + (dz * dz);
    };

    const float radiusSquared = probe.radius * probe.radius;
    return distanceSquaredTo(endpoints.begin) <= radiusSquared && distanceSquaredTo(endpoints.end) <= radiusSquared;
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

  [[nodiscard]] const moho::SpatialMapNode* TreeNext(const moho::SpatialMapNode* node) noexcept
  {
    if (node == nullptr || node->mIsNil != 0u) {
      return node;
    }

    const moho::SpatialMapNode* right = node->mRight;
    if (right != nullptr && right->mIsNil == 0u) {
      const moho::SpatialMapNode* next = right;
      while (next->mLeft != nullptr && next->mLeft->mIsNil == 0u) {
        next = next->mLeft;
      }
      return next;
    }

    const moho::SpatialMapNode* child = node;
    const moho::SpatialMapNode* parent = node->mParent;
    while (parent != nullptr && parent->mIsNil == 0u && child == parent->mRight) {
      child = parent;
      parent = parent->mParent;
    }
    return parent;
  }

  [[nodiscard]] bool IsSpatialMapSentinel(const moho::SpatialMapNode* const node) noexcept
  {
    return node == nullptr || node->mIsNil != 0u;
  }

  [[nodiscard]] moho::SpatialMapNode* SpatialMapNextNode(
    moho::SpatialMapNode* node,
    const moho::SpatialMapNode* const head
  ) noexcept
  {
    if (node == nullptr || head == nullptr) {
      return nullptr;
    }

    if (!IsSpatialMapSentinel(node->mRight)) {
      node = node->mRight;
      while (!IsSpatialMapSentinel(node->mLeft)) {
        node = node->mLeft;
      }
      return node;
    }

    moho::SpatialMapNode* parent = node->mParent;
    while (!IsSpatialMapSentinel(parent) && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }

    return parent;
  }

  [[nodiscard]] moho::SpatialMapNode* SpatialMapMinimumNode(moho::SpatialMapNode* node) noexcept
  {
    while (!IsSpatialMapSentinel(node->mLeft)) {
      node = node->mLeft;
    }
    return node;
  }

  [[nodiscard]] moho::SpatialMapNode* SpatialMapMaximumNode(moho::SpatialMapNode* node) noexcept
  {
    while (!IsSpatialMapSentinel(node->mRight)) {
      node = node->mRight;
    }
    return node;
  }

  /**
   * Address: 0x00504C10 (FUN_00504C10, sub_504C10)
   *
   * What it does:
   * Performs one left rotation around `pivot` in the spatial map RB tree.
   */
  void SpatialMapRotateLeft(moho::SpatialMapTree& tree, moho::SpatialMapNode* const pivot) noexcept
  {
    if (IsSpatialMapSentinel(pivot) || IsSpatialMapSentinel(pivot->mRight)) {
      return;
    }

    moho::SpatialMapNode* const head = tree.mHead;
    moho::SpatialMapNode* const right = pivot->mRight;

    pivot->mRight = right->mLeft;
    if (!IsSpatialMapSentinel(right->mLeft)) {
      right->mLeft->mParent = pivot;
    }

    right->mParent = pivot->mParent;
    if (IsSpatialMapSentinel(pivot->mParent)) {
      head->mParent = right;
    } else if (pivot == pivot->mParent->mLeft) {
      pivot->mParent->mLeft = right;
    } else {
      pivot->mParent->mRight = right;
    }

    right->mLeft = pivot;
    pivot->mParent = right;
  }

  /**
   * Address: 0x00504CC0 (FUN_00504CC0, sub_504CC0)
   *
   * What it does:
   * Performs one right rotation around `pivot` in the spatial map RB tree.
   */
  void SpatialMapRotateRight(moho::SpatialMapTree& tree, moho::SpatialMapNode* const pivot) noexcept
  {
    if (IsSpatialMapSentinel(pivot) || IsSpatialMapSentinel(pivot->mLeft)) {
      return;
    }

    moho::SpatialMapNode* const head = tree.mHead;
    moho::SpatialMapNode* const left = pivot->mLeft;

    pivot->mLeft = left->mRight;
    if (!IsSpatialMapSentinel(left->mRight)) {
      left->mRight->mParent = pivot;
    }

    left->mParent = pivot->mParent;
    if (IsSpatialMapSentinel(pivot->mParent)) {
      head->mParent = left;
    } else if (pivot == pivot->mParent->mRight) {
      pivot->mParent->mRight = left;
    } else {
      pivot->mParent->mLeft = left;
    }

    left->mRight = pivot;
    pivot->mParent = left;
  }

  [[nodiscard]] bool IsSpatialMapNodeBlack(const moho::SpatialMapNode* const node) noexcept
  {
    return IsSpatialMapSentinel(node) || node->mColor == 1u;
  }

  void SpatialMapEraseFixup(
    moho::SpatialMapTree& tree,
    moho::SpatialMapNode* node,
    moho::SpatialMapNode* parent
  ) noexcept
  {
    moho::SpatialMapNode* const head = tree.mHead;

    while (node != head->mParent && IsSpatialMapNodeBlack(node)) {
      if (node == parent->mLeft) {
        moho::SpatialMapNode* sibling = parent->mRight;

        if (!IsSpatialMapSentinel(sibling) && sibling->mColor == 0u) {
          sibling->mColor = 1u;
          parent->mColor = 0u;
          SpatialMapRotateLeft(tree, parent);
          sibling = parent->mRight;
        }

        if (IsSpatialMapSentinel(sibling)) {
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsSpatialMapNodeBlack(sibling->mLeft) && IsSpatialMapNodeBlack(sibling->mRight)) {
          sibling->mColor = 0u;
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsSpatialMapNodeBlack(sibling->mRight)) {
          if (!IsSpatialMapSentinel(sibling->mLeft)) {
            sibling->mLeft->mColor = 1u;
          }
          sibling->mColor = 0u;
          SpatialMapRotateRight(tree, sibling);
          sibling = parent->mRight;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = 1u;
        if (!IsSpatialMapSentinel(sibling->mRight)) {
          sibling->mRight->mColor = 1u;
        }
        SpatialMapRotateLeft(tree, parent);
      } else {
        moho::SpatialMapNode* sibling = parent->mLeft;

        if (!IsSpatialMapSentinel(sibling) && sibling->mColor == 0u) {
          sibling->mColor = 1u;
          parent->mColor = 0u;
          SpatialMapRotateRight(tree, parent);
          sibling = parent->mLeft;
        }

        if (IsSpatialMapSentinel(sibling)) {
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsSpatialMapNodeBlack(sibling->mRight) && IsSpatialMapNodeBlack(sibling->mLeft)) {
          sibling->mColor = 0u;
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsSpatialMapNodeBlack(sibling->mLeft)) {
          if (!IsSpatialMapSentinel(sibling->mRight)) {
            sibling->mRight->mColor = 1u;
          }
          sibling->mColor = 0u;
          SpatialMapRotateLeft(tree, sibling);
          sibling = parent->mLeft;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = 1u;
        if (!IsSpatialMapSentinel(sibling->mLeft)) {
          sibling->mLeft->mColor = 1u;
        }
        SpatialMapRotateRight(tree, parent);
      }

      break;
    }

    if (!IsSpatialMapSentinel(node)) {
      node->mColor = 1u;
    }
  }

  void SpatialMapEraseNode(moho::SpatialMapTree& tree, moho::SpatialMapNode* const eraseTarget) noexcept
  {
    moho::SpatialMapNode* const head = tree.mHead;
    if (IsSpatialMapSentinel(eraseTarget) || IsSpatialMapSentinel(head)) {
      return;
    }

    moho::SpatialMapNode* const next = SpatialMapNextNode(eraseTarget, head);
    moho::SpatialMapNode* fixupNode = nullptr;
    moho::SpatialMapNode* fixupParent = nullptr;

    if (IsSpatialMapSentinel(eraseTarget->mLeft)) {
      fixupNode = eraseTarget->mRight;
      fixupParent = eraseTarget->mParent;
      if (!IsSpatialMapSentinel(fixupNode)) {
        fixupNode->mParent = fixupParent;
      }

      if (head->mParent == eraseTarget) {
        head->mParent = fixupNode;
      } else if (fixupParent->mLeft == eraseTarget) {
        fixupParent->mLeft = fixupNode;
      } else {
        fixupParent->mRight = fixupNode;
      }

      if (head->mLeft == eraseTarget) {
        head->mLeft = IsSpatialMapSentinel(fixupNode) ? fixupParent : SpatialMapMinimumNode(fixupNode);
      }
      if (head->mRight == eraseTarget) {
        head->mRight = IsSpatialMapSentinel(fixupNode) ? fixupParent : SpatialMapMaximumNode(fixupNode);
      }
    } else if (IsSpatialMapSentinel(eraseTarget->mRight)) {
      fixupNode = eraseTarget->mLeft;
      fixupParent = eraseTarget->mParent;
      if (!IsSpatialMapSentinel(fixupNode)) {
        fixupNode->mParent = fixupParent;
      }

      if (head->mParent == eraseTarget) {
        head->mParent = fixupNode;
      } else if (fixupParent->mLeft == eraseTarget) {
        fixupParent->mLeft = fixupNode;
      } else {
        fixupParent->mRight = fixupNode;
      }

      if (head->mLeft == eraseTarget) {
        head->mLeft = IsSpatialMapSentinel(fixupNode) ? fixupParent : SpatialMapMinimumNode(fixupNode);
      }
      if (head->mRight == eraseTarget) {
        head->mRight = IsSpatialMapSentinel(fixupNode) ? fixupParent : SpatialMapMaximumNode(fixupNode);
      }
    } else {
      moho::SpatialMapNode* const successor = next;
      fixupNode = successor->mRight;

      if (successor == eraseTarget->mRight) {
        fixupParent = successor;
      } else {
        fixupParent = successor->mParent;
        if (!IsSpatialMapSentinel(fixupNode)) {
          fixupNode->mParent = fixupParent;
        }
        fixupParent->mLeft = fixupNode;

        successor->mRight = eraseTarget->mRight;
        successor->mRight->mParent = successor;
      }

      if (head->mParent == eraseTarget) {
        head->mParent = successor;
      } else if (eraseTarget->mParent->mLeft == eraseTarget) {
        eraseTarget->mParent->mLeft = successor;
      } else {
        eraseTarget->mParent->mRight = successor;
      }

      successor->mParent = eraseTarget->mParent;
      successor->mLeft = eraseTarget->mLeft;
      successor->mLeft->mParent = successor;
      std::swap(successor->mColor, eraseTarget->mColor);
    }

    if (eraseTarget->mColor == 1u) {
      SpatialMapEraseFixup(tree, fixupNode, fixupParent);
    }

    delete eraseTarget;
    if (tree.mSize > 0) {
      --tree.mSize;
    }
  }

  /**
   * Address: 0x00505D20 (FUN_00505D20, sub_505D20)
   *
   * What it does:
   * Allocates one map node header and seeds default red/black color lanes used
   * by subsequent map-sentinel initialization.
   */
  [[nodiscard]] moho::SpatialMapNode* AllocateSpatialMapNodeHeader()
  {
    moho::SpatialMapNode* const node = new (std::nothrow) moho::SpatialMapNode{};
    if (node == nullptr) {
      return nullptr;
    }

    node->mLeft = nullptr;
    node->mParent = nullptr;
    node->mRight = nullptr;
    node->mColor = 1u;
    node->mIsNil = 0u;
    return node;
  }

  /**
   * Address: 0x00505200 (FUN_00505200, sub_505200)
   *
   * What it does:
   * Erases one node range from a map tree and returns the post-erase iterator.
   */
  [[nodiscard]] moho::SpatialMapNode*
  EraseSpatialMapRange(moho::SpatialMapTree& tree, moho::SpatialMapNode* first, moho::SpatialMapNode* last)
  {
    moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    if (first == head->mLeft && last == head) {
      for (moho::SpatialMapNode* node = head->mLeft; !IsSpatialMapSentinel(node) && node != head;) {
        moho::SpatialMapNode* const next = SpatialMapNextNode(node, head);
        delete node;
        node = next;
      }

      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      tree.mSize = 0;
      return head->mLeft;
    }

    moho::SpatialMapNode* cursor = first;
    while (cursor != last) {
      if (IsSpatialMapSentinel(cursor)) {
        cursor = last;
        break;
      }

      moho::SpatialMapNode* const eraseNode = cursor;
      cursor = SpatialMapNextNode(cursor, head);
      SpatialMapEraseNode(tree, eraseNode);
    }

    return cursor;
  }

  void InitializeSpatialMapTree(moho::SpatialMapTree& tree)
  {
    tree.mAllocatorCookie = nullptr;
    moho::SpatialMapNode* const head = AllocateSpatialMapNodeHeader();
    if (head == nullptr) {
      tree.mHead = nullptr;
      tree.mSize = 0;
      return;
    }

    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mBox = {};
    head->mEntityType = 0u;
    head->mShardData = nullptr;
    head->mFadeOut = 0.0f;
    head->mOwner = nullptr;
    head->mColor = 1u;
    head->mIsNil = 1u;
    head->mPad_36_37[0] = 0u;
    head->mPad_36_37[1] = 0u;
    tree.mHead = head;
    tree.mSize = 0;
  }

  /**
   * Address: 0x00501760 (FUN_00501760, sub_501760)
   *
   * What it does:
   * Clears one spatial-map tree node range, frees the sentinel node, and
   * resets head/size lanes to null/zero.
   */
  void DestroySpatialMapTree(moho::SpatialMapTree& tree)
  {
    moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      tree.mSize = 0;
      return;
    }

    EraseSpatialMapRange(tree, head->mLeft, head);

    delete head;
    tree.mHead = nullptr;
    tree.mSize = 0;
  }

  template <class T>
  void AllocateSpatialShardArray(moho::SpatialShardArray<T>& array, const std::size_t count)
  {
    array.mDebugProxy = nullptr;
    array.mBegin = nullptr;
    array.mEnd = nullptr;
    array.mCapacity = nullptr;

    if (count == 0u) {
      return;
    }

    T** const entries = new (std::nothrow) T*[count];
    if (entries == nullptr) {
      return;
    }
    std::fill_n(entries, count, nullptr);
    array.mBegin = entries;
    array.mEnd = entries + count;
    array.mCapacity = entries + count;
  }

  template <class T>
  void ResetSpatialShardArray(moho::SpatialShardArray<T>& array)
  {
    delete[] array.mBegin;
    array.mDebugProxy = nullptr;
    array.mBegin = nullptr;
    array.mEnd = nullptr;
    array.mCapacity = nullptr;
  }

  /**
   * Address: 0x00504D70 (FUN_00504D70, sub_504D70)
   *
   * What it does:
   * Ensures one shard-pointer array has exactly 16 active lanes.
   */
  [[nodiscard]] std::size_t EnsureSpatialShardSlots16(moho::SpatialShardArray<moho::SpatialShard>& shards)
  {
    moho::SpatialShard** const begin = shards.mBegin;
    std::size_t size = 0u;
    if (begin != nullptr && shards.mEnd != nullptr && shards.mEnd >= begin) {
      size = static_cast<std::size_t>(shards.mEnd - begin);
    }

    if (begin == nullptr) {
      AllocateSpatialShardArray(shards, kSpatialShardSlotCount);
      return shards.mBegin == nullptr ? 0u : static_cast<std::size_t>(kSpatialShardSlotCount);
    }

    if (size < static_cast<std::size_t>(kSpatialShardSlotCount)) {
      std::size_t capacity = 0u;
      if (shards.mCapacity != nullptr && shards.mCapacity >= begin) {
        capacity = static_cast<std::size_t>(shards.mCapacity - begin);
      }

      if (capacity >= static_cast<std::size_t>(kSpatialShardSlotCount)) {
        std::fill(begin + size, begin + kSpatialShardSlotCount, nullptr);
        shards.mEnd = begin + kSpatialShardSlotCount;
        return static_cast<std::size_t>(kSpatialShardSlotCount);
      }

      moho::SpatialShard** const expanded = new (std::nothrow) moho::SpatialShard*[kSpatialShardSlotCount];
      if (expanded == nullptr) {
        return size;
      }
      std::fill_n(expanded, kSpatialShardSlotCount, nullptr);
      if (size > 0u) {
        std::copy_n(begin, size, expanded);
      }

      delete[] begin;
      shards.mBegin = expanded;
      shards.mEnd = expanded + kSpatialShardSlotCount;
      shards.mCapacity = expanded + kSpatialShardSlotCount;
      return static_cast<std::size_t>(kSpatialShardSlotCount);
    }

    if (size > static_cast<std::size_t>(kSpatialShardSlotCount)) {
      shards.mEnd = begin + kSpatialShardSlotCount;
      return static_cast<std::size_t>(kSpatialShardSlotCount);
    }

    return size;
  }

  [[nodiscard]] std::int32_t FloorSpatialCellCoordinate(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value * 0.0625f));
  }

  struct SpatialMapValuePayload
  {
    Wm3::AxisAlignedBox3f mBox;    // +0x00
    std::uint32_t mEntityType;     // +0x18
    moho::SpatialShardData* mData; // +0x1C
    float mFadeOut;                // +0x20
    void* mOwner;                  // +0x24
  };

  static_assert(sizeof(SpatialMapValuePayload) == 0x28, "SpatialMapValuePayload size must be 0x28");
  static_assert(offsetof(SpatialMapValuePayload, mBox) == 0x00, "SpatialMapValuePayload::mBox offset must be 0x00");
  static_assert(
    offsetof(SpatialMapValuePayload, mEntityType) == 0x18,
    "SpatialMapValuePayload::mEntityType offset must be 0x18"
  );
  static_assert(offsetof(SpatialMapValuePayload, mData) == 0x1C, "SpatialMapValuePayload::mData offset must be 0x1C");
  static_assert(
    offsetof(SpatialMapValuePayload, mFadeOut) == 0x20,
    "SpatialMapValuePayload::mFadeOut offset must be 0x20"
  );
  static_assert(offsetof(SpatialMapValuePayload, mOwner) == 0x24, "SpatialMapValuePayload::mOwner offset must be 0x24");

  [[nodiscard]] moho::SpatialMapNode* EntryNodeFromHandle(const std::int32_t entryHandle) noexcept
  {
    if (entryHandle == 0) {
      return nullptr;
    }

    return reinterpret_cast<moho::SpatialMapNode*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(entryHandle)));
  }

  [[nodiscard]] std::int32_t EntryHandleFromNode(const moho::SpatialMapNode* const node) noexcept
  {
    if (node == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(node)));
  }

  [[nodiscard]] SpatialMapValuePayload MakePayloadFromNode(const moho::SpatialMapNode& node) noexcept
  {
    SpatialMapValuePayload payload{};
    payload.mBox = node.mBox;
    payload.mEntityType = node.mEntityType;
    payload.mData = node.mShardData;
    payload.mFadeOut = node.mFadeOut;
    payload.mOwner = node.mOwner;
    return payload;
  }

  void ApplyPayloadToNode(moho::SpatialMapNode& node, const SpatialMapValuePayload& payload) noexcept
  {
    node.mBox = payload.mBox;
    node.mEntityType = payload.mEntityType;
    node.mShardData = payload.mData;
    node.mFadeOut = payload.mFadeOut;
    node.mOwner = payload.mOwner;
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
  void PropagateBoundsToShardChain(moho::SpatialShard* shard, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    for (moho::SpatialShard* current = shard; current != nullptr; current = current->mParent) {
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
  void IncrementShardTypeCountChain(moho::SpatialShard* shard, const std::uint32_t typeBits) noexcept
  {
    for (moho::SpatialShard* current = shard; current != nullptr; current = current->mParent) {
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

  [[nodiscard]] bool SpatialFadeInsertsLeft(const float candidateFade, const float currentFade) noexcept
  {
    if (candidateFade > 0.0f) {
      if (currentFade <= 0.0f) {
        return false;
      }

      return candidateFade > currentFade;
    }

    if (currentFade > 0.0f) {
      return true;
    }

    return candidateFade < currentFade;
  }

  [[nodiscard]] bool SpatialFadeLessOrEqual(const float lhs, const float rhs) noexcept
  {
    if (lhs > 0.0f) {
      if (rhs <= 0.0f) {
        return false;
      }
      return lhs >= rhs;
    }

    if (rhs > 0.0f) {
      return true;
    }

    return lhs <= rhs;
  }

  void SpatialMapInsertFixup(moho::SpatialMapTree& tree, moho::SpatialMapNode* node) noexcept
  {
    moho::SpatialMapNode* const head = tree.mHead;
    while (!IsSpatialMapSentinel(node) && node != head->mParent && node->mParent->mColor == 0u) {
      moho::SpatialMapNode* const parent = node->mParent;
      moho::SpatialMapNode* const grand = parent->mParent;
      if (parent == grand->mLeft) {
        moho::SpatialMapNode* uncle = grand->mRight;
        if (!IsSpatialMapSentinel(uncle) && uncle->mColor == 0u) {
          parent->mColor = 1u;
          uncle->mColor = 1u;
          grand->mColor = 0u;
          node = grand;
          continue;
        }

        if (node == parent->mRight) {
          node = parent;
          SpatialMapRotateLeft(tree, node);
        }

        node->mParent->mColor = 1u;
        grand->mColor = 0u;
        SpatialMapRotateRight(tree, grand);
      } else {
        moho::SpatialMapNode* uncle = grand->mLeft;
        if (!IsSpatialMapSentinel(uncle) && uncle->mColor == 0u) {
          parent->mColor = 1u;
          uncle->mColor = 1u;
          grand->mColor = 0u;
          node = grand;
          continue;
        }

        if (node == parent->mLeft) {
          node = parent;
          SpatialMapRotateRight(tree, node);
        }

        node->mParent->mColor = 1u;
        grand->mColor = 0u;
        SpatialMapRotateLeft(tree, grand);
      }
    }

    if (!IsSpatialMapSentinel(head->mParent)) {
      head->mParent->mColor = 1u;
    }
  }

  /**
   * Address: 0x00505D60 (FUN_00505D60, sub_505D60)
   *
   * What it does:
   * Allocates one value node for the spatial map tree and seeds link/color lanes.
   */
  [[nodiscard]] moho::SpatialMapNode* AllocateSpatialMapValueNode(
    moho::SpatialMapNode* const left,
    moho::SpatialMapNode* const parent,
    moho::SpatialMapNode* const right,
    const SpatialMapValuePayload& payload
  )
  {
    moho::SpatialMapNode* const node = new moho::SpatialMapNode{};
    node->mLeft = left;
    node->mParent = parent;
    node->mRight = right;
    ApplyPayloadToNode(*node, payload);
    node->mColor = 0u;
    node->mIsNil = 0u;
    return node;
  }

  /**
   * Address: 0x00505F20 (FUN_00505F20)
   *
   * What it does:
   * Allocates raw storage for one `SpatialMapNode` lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::SpatialMapNode* AllocateSingleSpatialMapNodeLane()
  {
    return static_cast<moho::SpatialMapNode*>(::operator new(sizeof(moho::SpatialMapNode)));
  }

  /**
   * Address: 0x00505F40 (FUN_00505F40, sub_505F40)
   *
   * What it does:
   * Returns in-order predecessor for one map node (or rightmost when input is head sentinel).
   */
  [[nodiscard]] moho::SpatialMapNode* SpatialMapPrevNode(
    moho::SpatialMapNode* node,
    const moho::SpatialMapNode* const head
  ) noexcept
  {
    if (IsSpatialMapSentinel(node)) {
      return node->mRight;
    }

    if (!IsSpatialMapSentinel(node->mLeft)) {
      node = node->mLeft;
      while (!IsSpatialMapSentinel(node->mRight)) {
        node = node->mRight;
      }
      return node;
    }

    moho::SpatialMapNode* parent = node->mParent;
    while (!IsSpatialMapSentinel(parent) && node == parent->mLeft) {
      node = parent;
      parent = parent->mParent;
    }

    return parent;
  }

  /**
   * Address: 0x005052F0 (FUN_005052F0, sub_5052F0)
   *
   * What it does:
   * Inserts one payload node at an explicit parent/side position, then applies RB-tree fixup.
   */
  [[nodiscard]] moho::SpatialMapNode* InsertSpatialPayloadAtLink(
    moho::SpatialMapTree& tree,
    moho::SpatialMapNode* const parent,
    const bool insertLeft,
    const SpatialMapValuePayload& payload
  )
  {
    moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    if (tree.mSize >= kSpatialMapMaxNodeCount) {
      throw std::length_error("map/set<T> too long");
    }

    moho::SpatialMapNode* const inserted = AllocateSpatialMapValueNode(head, parent, head, payload);
    ++tree.mSize;

    if (parent == head) {
      head->mParent = inserted;
      head->mLeft = inserted;
      head->mRight = inserted;
    } else if (insertLeft) {
      parent->mLeft = inserted;
      if (parent == head->mLeft) {
        head->mLeft = inserted;
      }
    } else {
      parent->mRight = inserted;
      if (parent == head->mRight) {
        head->mRight = inserted;
      }
    }

    SpatialMapInsertFixup(tree, inserted);
    if (!IsSpatialMapSentinel(head->mParent)) {
      head->mLeft = SpatialMapMinimumNode(head->mParent);
      head->mRight = SpatialMapMaximumNode(head->mParent);
    }
    return inserted;
  }

  /**
   * Address: 0x00504990 (FUN_00504990, sub_504990)
   *
   * What it does:
   * Inserts one payload into a tree lane ordered by fade bucket sign/magnitude.
   */
  [[nodiscard]] moho::SpatialMapNode*
  InsertSpatialPayloadByFade(moho::SpatialMapTree& tree, const SpatialMapValuePayload& payload)
  {
    moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    moho::SpatialMapNode* parent = head;
    moho::SpatialMapNode* cursor = head->mParent;
    bool insertLeft = true;
    while (!IsSpatialMapSentinel(cursor)) {
      parent = cursor;
      insertLeft = SpatialFadeInsertsLeft(payload.mFadeOut, cursor->mFadeOut);
      cursor = insertLeft ? cursor->mLeft : cursor->mRight;
    }

    return InsertSpatialPayloadAtLink(tree, parent, insertLeft, payload);
  }

  /**
   * Address: 0x00504A10 (FUN_00504A10, sub_504A10)
   *
   * What it does:
   * Performs hint-aware insertion for one payload; falls back to full tree walk when hint ordering misses.
   */
  [[nodiscard]] moho::SpatialMapNode* InsertSpatialPayloadWithHint(
    moho::SpatialMapTree& tree,
    const SpatialMapValuePayload& payload,
    moho::SpatialMapNode* hint
  )
  {
    moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    if (tree.mSize == 0) {
      return InsertSpatialPayloadAtLink(tree, head, true, payload);
    }

    if (hint == head->mLeft) {
      if (SpatialFadeLessOrEqual(payload.mFadeOut, hint->mFadeOut)) {
        return InsertSpatialPayloadAtLink(tree, hint, true, payload);
      }
      return InsertSpatialPayloadByFade(tree, payload);
    }

    if (hint == head) {
      moho::SpatialMapNode* const rightmost = head->mRight;
      if (SpatialFadeLessOrEqual(rightmost->mFadeOut, payload.mFadeOut)) {
        return InsertSpatialPayloadAtLink(tree, rightmost, false, payload);
      }
      return InsertSpatialPayloadByFade(tree, payload);
    }

    if (SpatialFadeLessOrEqual(payload.mFadeOut, hint->mFadeOut)) {
      moho::SpatialMapNode* const prev = SpatialMapPrevNode(hint, head);
      if (SpatialFadeLessOrEqual(prev->mFadeOut, payload.mFadeOut)) {
        if (IsSpatialMapSentinel(prev->mRight)) {
          return InsertSpatialPayloadAtLink(tree, prev, false, payload);
        }
        return InsertSpatialPayloadAtLink(tree, hint, true, payload);
      }
      return InsertSpatialPayloadByFade(tree, payload);
    }

    if (SpatialFadeLessOrEqual(hint->mFadeOut, payload.mFadeOut)) {
      moho::SpatialMapNode* const next = SpatialMapNextNode(hint, head);
      if (next == head || SpatialFadeLessOrEqual(payload.mFadeOut, next->mFadeOut)) {
        if (IsSpatialMapSentinel(hint->mRight)) {
          return InsertSpatialPayloadAtLink(tree, hint, false, payload);
        }
        return InsertSpatialPayloadAtLink(tree, next, true, payload);
      }
    }

    return InsertSpatialPayloadByFade(tree, payload);
  }

  /**
   * Address: 0x00504330 (FUN_00504330)
   *
   * What it does:
   * Register-lane adapter that performs hint-aware payload insertion and
   * returns the caller-provided node-slot lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::SpatialMapNode** InsertSpatialPayloadWithHintSlotAdapter(
    moho::SpatialMapNode** const outNodeSlot,
    moho::SpatialMapTree& tree,
    moho::SpatialMapNode* const hint,
    const SpatialMapValuePayload& payload
  )
  {
    (void)InsertSpatialPayloadWithHint(tree, payload, hint);
    return outNodeSlot;
  }

  struct PointerToPointerSlot04RuntimeView
  {
    std::uint8_t reserved00_03[4]{};
    std::uintptr_t* slot04 = nullptr; // +0x04
  };
  static_assert(
    offsetof(PointerToPointerSlot04RuntimeView, slot04) == 0x04,
    "PointerToPointerSlot04RuntimeView::slot04 offset must be 0x04"
  );

  struct PointerSlot04RuntimeView
  {
    std::uint8_t reserved00_03[4]{};
    std::uintptr_t slot04 = 0u; // +0x04
  };
  static_assert(offsetof(PointerSlot04RuntimeView, slot04) == 0x04, "PointerSlot04RuntimeView::slot04 offset must be 0x04");

  struct PointerSlot08RuntimeView
  {
    std::uint8_t reserved00_07[8]{};
    std::uintptr_t slot08 = 0u; // +0x08
  };
  static_assert(offsetof(PointerSlot08RuntimeView, slot08) == 0x08, "PointerSlot08RuntimeView::slot08 offset must be 0x08");

  [[nodiscard]] std::uintptr_t* StorePointerLaneValue(
    std::uintptr_t* const outLane,
    const std::uintptr_t value
  ) noexcept
  {
    *outLane = value;
    return outLane;
  }

  /**
   * Address: 0x00504380 (FUN_00504380)
   *
   * What it does:
   * Stores one pointer value loaded from the indirection lane at `+0x04`.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StoreDereferencedPointerSlot04Lane(
    std::uintptr_t* const outLane,
    const PointerToPointerSlot04RuntimeView* const runtime
  ) noexcept
  {
    return StorePointerLaneValue(outLane, *runtime->slot04);
  }

  /**
   * Address: 0x00504390 (FUN_00504390)
   *
   * What it does:
   * Stores one direct pointer lane from `+0x04`.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StorePointerSlot04LaneA(
    std::uintptr_t* const outLane,
    const PointerSlot04RuntimeView* const runtime
  ) noexcept
  {
    return StorePointerLaneValue(outLane, runtime->slot04);
  }

  /**
   * Address: 0x005046C0 (FUN_005046C0)
   *
   * What it does:
   * Alias lane that stores one direct pointer from `+0x04`.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StorePointerSlot04LaneB(
    std::uintptr_t* const outLane,
    const PointerSlot04RuntimeView* const runtime
  ) noexcept
  {
    return StorePointerSlot04LaneA(outLane, runtime);
  }

  /**
   * Address: 0x005046D0 (FUN_005046D0)
   *
   * What it does:
   * Alias lane that stores one direct pointer from `+0x04`.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StorePointerSlot04LaneC(
    std::uintptr_t* const outLane,
    const PointerSlot04RuntimeView* const runtime
  ) noexcept
  {
    return StorePointerSlot04LaneA(outLane, runtime);
  }

  /**
   * Address: 0x005046E0 (FUN_005046E0)
   *
   * What it does:
   * Stores one direct pointer lane from `+0x08`.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StorePointerSlot08LaneA(
    std::uintptr_t* const outLane,
    const PointerSlot08RuntimeView* const runtime
  ) noexcept
  {
    return StorePointerLaneValue(outLane, runtime->slot08);
  }

  /**
   * Address: 0x005046F0 (FUN_005046F0)
   *
   * What it does:
   * Alias lane that stores one direct pointer from `+0x08`.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StorePointerSlot08LaneB(
    std::uintptr_t* const outLane,
    const PointerSlot08RuntimeView* const runtime
  ) noexcept
  {
    return StorePointerSlot08LaneA(outLane, runtime);
  }

  /**
   * Address: 0x00504310 (FUN_00504310, sub_504310)
   *
   * What it does:
   * Inserts one payload into the entity tree lane using the shared fade-order
   * insertion helper.
   */
  [[nodiscard]] moho::SpatialMapNode*
  InsertSpatialEntityPayload(moho::SpatialMapTree& entityTree, const SpatialMapValuePayload& payload)
  {
    return InsertSpatialPayloadByFade(entityTree, payload);
  }

  /**
   * Address: 0x00502200 (FUN_00502200, sub_502200)
   *
   * What it does:
   * Inserts one payload into the matching shard-data map lane, updates
   * aggregate bounds/time counters, and links node owner data.
   */
  [[nodiscard]] moho::SpatialMapNode*
  InsertSpatialPayloadIntoShardData(moho::SpatialShardData& data, const SpatialMapValuePayload& payload)
  {
    moho::SpatialMapTree* targetTree = &data.mMapEntities;
    const std::uint32_t typeBits = payload.mEntityType;
    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      targetTree = &data.mMapUnits;
    } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      targetTree = &data.mMapProjectiles;
    } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      targetTree = &data.mMapProps;
    }

    moho::SpatialMapNode* inserted = nullptr;
    if (targetTree == &data.mMapEntities) {
      inserted = InsertSpatialEntityPayload(*targetTree, payload);
    } else {
      inserted = InsertSpatialPayloadByFade(*targetTree, payload);
    }

    data.mBounds.Min.x = std::min(data.mBounds.Min.x, payload.mBox.Min.x);
    data.mBounds.Min.y = std::min(data.mBounds.Min.y, payload.mBox.Min.y);
    data.mBounds.Min.z = std::min(data.mBounds.Min.z, payload.mBox.Min.z);
    data.mBounds.Max.x = std::max(data.mBounds.Max.x, payload.mBox.Max.x);
    data.mBounds.Max.y = std::max(data.mBounds.Max.y, payload.mBox.Max.y);
    data.mBounds.Max.z = std::max(data.mBounds.Max.z, payload.mBox.Max.z);
    ++data.mTimeSinceRecalc;

    if (inserted != nullptr) {
      inserted->mShardData = &data;
    }

    if (data.mShard != nullptr) {
      PropagateBoundsToShardChain(data.mShard, data.mBounds);
      IncrementShardTypeCountChain(data.mShard, payload.mEntityType);
    }

    return inserted;
  }

  /**
   * Address: 0x00506080 (FUN_00506080)
   *
   * What it does:
   * Copies one contiguous dword lane range `[sourceBegin, sourceEnd)` into
   * `destinationBegin` and returns one-past-last written destination slot.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordLaneRangeAndReturnEnd(
    std::uint32_t* const destinationBegin,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    const std::ptrdiff_t dwordCount = sourceEnd - sourceBegin;
    std::uint32_t* const destinationEnd = destinationBegin + dwordCount;
    if (dwordCount > 0) {
      const std::size_t byteCount = static_cast<std::size_t>(dwordCount) * sizeof(std::uint32_t);
      (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x005060B0 (FUN_005060B0)
   *
   * What it does:
   * Duplicate adapter lane of `CopyDwordLaneRangeAndReturnEnd`.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordLaneRangeAndReturnEndAlias(
    std::uint32_t* const destinationBegin,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return CopyDwordLaneRangeAndReturnEnd(destinationBegin, sourceBegin, sourceEnd);
  }

  template <class TPredicate>
  void CollectTreeNodes(
    const moho::SpatialMapTree& tree,
    gpg::fastvector<moho::UserEntity*>& destination,
    const TPredicate& predicate
  )
  {
    const moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      return;
    }

    for (const moho::SpatialMapNode* node = head->mLeft; node != head; node = TreeNext(node)) {
      if (predicate(node->mBox)) {
        destination.push_back(static_cast<moho::UserEntity*>(node->mOwner));
      }
    }
  }

  /**
   * Address: 0x00502C60 (FUN_00502C60, Spatial shard AABB leaf collect helper)
   *
   * What it does:
   * Scans one leaf `SpatialShardData` lane and appends all entity owners whose
   * node AABBs intersect the query `bounds` for requested type masks.
   */
  void CollectInBoxFromLeafData(
    const Wm3::AxisAlignedBox3f& bounds,
    moho::SpatialShardData& data,
    const moho::EEntityType type,
    gpg::fastvector<moho::UserEntity*>& destination
  )
  {
    if (SpatialShardDataHasNoRequestedType(data, type) || !AxisAlignedBoxesIntersect(bounds, data.mBounds)) {
      return;
    }

    if (data.mTimeSinceRecalc > 500) {
      data.RecalculateBounds();
    }

    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto intersectsQuery = [&bounds](const Wm3::AxisAlignedBox3f& nodeBox) {
      return AxisAlignedBoxesIntersect(nodeBox, bounds);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectTreeNodes(data.mMapUnits, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectTreeNodes(data.mMapProjectiles, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectTreeNodes(data.mMapProps, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectTreeNodes(data.mMapEntities, destination, intersectsQuery);
    }
  }

  void CollectInVolumeFromLeafData(
    gpg::fastvector<moho::UserEntity*>& destination,
    moho::SpatialShardData& data,
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
      CollectTreeNodes(data.mMapUnits, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectTreeNodes(data.mMapProjectiles, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectTreeNodes(data.mMapProps, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectTreeNodes(data.mMapEntities, destination, intersectsOrContained);
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
  void CollectInViewFromLeafData(
    gpg::fastvector<moho::UserEntity*>& destination,
    moho::SpatialShardData* const data,
    moho::GeomCamera3* const camera,
    const moho::EEntityType type
  )
  {
    const Wm3::Vector3f supportSelector = BuildViewSupportSelector(*camera);
    moho::SpatialShardData::FindInVolumeFromData(
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
  void CollectInViewFromShard(
    moho::GeomCamera3* const camera,
    gpg::fastvector<moho::UserEntity*>& destination,
    moho::SpatialShard* const shard,
    const moho::EEntityType type
  )
  {
    const Wm3::Vector3f supportSelector = BuildViewSupportSelector(*camera);
    moho::SpatialShardData::FindInVolume(shard, type, &camera->solid2, supportSelector, camera->viewport.r[1], destination);
  }

  void CollectVolumeCandidatesWithFade(
    const moho::SpatialMapTree& tree,
    const moho::CGeomSolid3& volume,
    const bool dataBoundsContained,
    const float fadeThreshold,
    gpg::fastvector<moho::UserEntity*>& destination
  )
  {
    const moho::SpatialMapNode* const head = tree.mHead;
    if (head == nullptr) {
      return;
    }

    for (const moho::SpatialMapNode* node = head->mLeft; node != head; node = TreeNext(node)) {
      if (node->mFadeOut > 0.0f && fadeThreshold >= node->mFadeOut) {
        break;
      }

      if (dataBoundsContained || volume.Intersects(node->mBox)) {
        destination.push_back(static_cast<moho::UserEntity*>(node->mOwner));
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

  void UpdateFallbackWorldBounds(moho::MeshInstance& instance) noexcept
  {
    float maxScale = std::max(instance.scale.x, std::max(instance.scale.y, instance.scale.z));
    if (!(maxScale > 0.0f)) {
      maxScale = 1.0f;
    }

    const float halfExtent = maxScale * 0.5f;
    instance.sphere.Center = instance.interpolatedPosition;
    instance.sphere.Radius = halfExtent;

    instance.xMin = instance.interpolatedPosition.x - halfExtent;
    instance.yMin = instance.interpolatedPosition.y - halfExtent;
    instance.zMin = instance.interpolatedPosition.z - halfExtent;
    instance.xMax = instance.interpolatedPosition.x + halfExtent;
    instance.yMax = instance.interpolatedPosition.y + halfExtent;
    instance.zMax = instance.interpolatedPosition.z + halfExtent;

    instance.renderMinX = instance.xMin;
    instance.renderMinY = instance.yMin;
    instance.renderMinZ = instance.zMin;
    instance.renderMaxX = instance.xMax;
    instance.renderMaxY = instance.yMax;
    instance.renderMaxZ = instance.zMax;

    instance.box.Center[0] = instance.interpolatedPosition.x;
    instance.box.Center[1] = instance.interpolatedPosition.y;
    instance.box.Center[2] = instance.interpolatedPosition.z;
    instance.box.Axis[0][0] = 1.0f;
    instance.box.Axis[0][1] = 0.0f;
    instance.box.Axis[0][2] = 0.0f;
    instance.box.Axis[1][0] = 0.0f;
    instance.box.Axis[1][1] = 1.0f;
    instance.box.Axis[1][2] = 0.0f;
    instance.box.Axis[2][0] = 0.0f;
    instance.box.Axis[2][1] = 0.0f;
    instance.box.Axis[2][2] = 1.0f;
    instance.box.Extent[0] = halfExtent;
    instance.box.Extent[1] = halfExtent;
    instance.box.Extent[2] = halfExtent;
    instance.boundsValid = 1;
  }

  [[nodiscard]] std::uintptr_t PointerOrderKey(const void* const ptr) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(ptr);
  }

  constexpr std::int32_t kMeshSpatialDbRoutingMask = 0x800;

  struct SpatialDbMeshCollectView
  {
    void* shardProxy;                   // +0x00
    moho::SpatialShard** shardBegin;    // +0x04
    moho::SpatialShard** shardEnd;      // +0x08
    moho::SpatialShard** shardCapacity; // +0x0C
    moho::SpatialShardData shardData;   // +0x10
    std::int32_t mapWidth;              // +0x70
    std::int32_t mapHeight;             // +0x74
    std::int32_t shardWidth;            // +0x78
    std::int32_t shardHeight;           // +0x7C
    std::int32_t shardLevel;            // +0x80
    moho::SpatialMapTree mapTree;       // +0x84
  };

  static_assert(offsetof(SpatialDbMeshCollectView, shardProxy) == 0x00, "SpatialDbMeshCollectView::shardProxy offset must be 0x00");
  static_assert(offsetof(SpatialDbMeshCollectView, shardBegin) == 0x04, "SpatialDbMeshCollectView::shardBegin offset must be 0x04");
  static_assert(offsetof(SpatialDbMeshCollectView, shardEnd) == 0x08, "SpatialDbMeshCollectView::shardEnd offset must be 0x08");
  static_assert(offsetof(SpatialDbMeshCollectView, shardCapacity) == 0x0C, "SpatialDbMeshCollectView::shardCapacity offset must be 0x0C");
  static_assert(offsetof(SpatialDbMeshCollectView, shardData) == 0x10, "SpatialDbMeshCollectView::shardData offset must be 0x10");
  static_assert(offsetof(SpatialDbMeshCollectView, mapWidth) == 0x70, "SpatialDbMeshCollectView::mapWidth offset must be 0x70");
  static_assert(offsetof(SpatialDbMeshCollectView, mapHeight) == 0x74, "SpatialDbMeshCollectView::mapHeight offset must be 0x74");
  static_assert(offsetof(SpatialDbMeshCollectView, shardWidth) == 0x78, "SpatialDbMeshCollectView::shardWidth offset must be 0x78");
  static_assert(offsetof(SpatialDbMeshCollectView, shardHeight) == 0x7C, "SpatialDbMeshCollectView::shardHeight offset must be 0x7C");
  static_assert(offsetof(SpatialDbMeshCollectView, shardLevel) == 0x80, "SpatialDbMeshCollectView::shardLevel offset must be 0x80");
  static_assert(offsetof(SpatialDbMeshCollectView, mapTree) == 0x84, "SpatialDbMeshCollectView::mapTree offset must be 0x84");
  static_assert(sizeof(SpatialDbMeshCollectView) == 0x90, "SpatialDbMeshCollectView size must be 0x90");

  [[nodiscard]] SpatialDbMeshCollectView& AsSpatialDbMeshCollectView(moho::SpatialDB_MeshInstance& storage) noexcept
  {
    return *reinterpret_cast<SpatialDbMeshCollectView*>(&storage);
  }

  [[nodiscard]] moho::SpatialShardArray<moho::SpatialShard>&
  AsSpatialDbShardArray(SpatialDbMeshCollectView& storage) noexcept
  {
    return *reinterpret_cast<moho::SpatialShardArray<moho::SpatialShard>*>(&storage.shardProxy);
  }

  /**
    * Alias of FUN_00501D80 (non-canonical helper lane).
   *
   * What it does:
   * Initializes one spatial-db mesh storage view: resets shard vector lanes,
   * constructs inline shard-data state, and seeds an empty map sentinel tree.
   */
  void InitializeSpatialDbMeshStorage(SpatialDbMeshCollectView& storage)
  {
    storage.shardProxy = nullptr;
    storage.shardBegin = nullptr;
    storage.shardEnd = nullptr;
    storage.shardCapacity = nullptr;
    new (&storage.shardData) moho::SpatialShardData(nullptr);

    storage.mapWidth = 0;
    storage.mapHeight = 0;
    storage.shardWidth = 0;
    storage.shardHeight = 0;
    storage.shardLevel = 0;
    InitializeSpatialMapTree(storage.mapTree);

    if (storage.shardBegin != storage.shardEnd) {
      storage.shardEnd = storage.shardBegin;
    }
  }

  /**
    * Alias of FUN_00501E50 (non-canonical helper lane).
   *
   * What it does:
   * Releases shard allocations, destroys map/sentinel storage, tears down
   * inline shard-data state, and resets shard vector lanes.
   */
  void DestroySpatialDbMeshStorage(SpatialDbMeshCollectView& storage)
  {
    if (storage.shardBegin != nullptr && storage.shardEnd != nullptr && storage.shardEnd > storage.shardBegin) {
      const std::ptrdiff_t shardCount = storage.shardEnd - storage.shardBegin;
      for (std::ptrdiff_t index = 0; index < shardCount; ++index) {
        delete storage.shardBegin[index];
        storage.shardBegin[index] = nullptr;
      }
    }
    storage.shardEnd = storage.shardBegin;

    DestroySpatialMapTree(storage.mapTree);
    storage.shardData.~SpatialShardData();

    delete[] storage.shardBegin;
    storage.shardProxy = nullptr;
    storage.shardBegin = nullptr;
    storage.shardEnd = nullptr;
    storage.shardCapacity = nullptr;
  }

  /**
   * Address: 0x00501F50 (FUN_00501F50, Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance)
   *
   * What it does:
   * Rebuilds top-level shard lanes for one map size update.
   */
  void UpdateSpatialDbMeshStorageMapSize(SpatialDbMeshCollectView& storage, const std::int32_t width, const std::int32_t height)
  {
    if (width == storage.mapWidth && height == storage.mapHeight) {
      return;
    }

    storage.mapWidth = width;
    storage.shardWidth = width / kSpatialShardSlotCount;
    storage.shardHeight = height / kSpatialShardSlotCount;
    storage.mapHeight = height;

    moho::SpatialShardArray<moho::SpatialShard>& shardArray = AsSpatialDbShardArray(storage);
    if (shardArray.mBegin != nullptr && shardArray.mEnd != nullptr && shardArray.mEnd > shardArray.mBegin) {
      const std::ptrdiff_t shardCount = shardArray.mEnd - shardArray.mBegin;
      for (std::ptrdiff_t index = 0; index < shardCount; ++index) {
        delete shardArray.mBegin[index];
        shardArray.mBegin[index] = nullptr;
      }
    }

    if (shardArray.mBegin != shardArray.mEnd) {
      shardArray.mEnd = shardArray.mBegin;
    }

    if (storage.mapWidth <= 0 || storage.mapHeight <= 0) {
      return;
    }

    const std::int32_t dominantExtent = std::max(storage.mapWidth, storage.mapHeight);
    if (dominantExtent <= kSpatialShardLevelSmallThreshold) {
      storage.shardLevel = kSpatialShardLevelSmall;
    } else if (dominantExtent <= kSpatialShardLevelMediumThreshold) {
      storage.shardLevel = kSpatialShardLevelMedium;
    } else {
      storage.shardLevel = kSpatialShardLevelLarge;
    }

    const std::int32_t shardSize = kSpatialShardCellSizeByLevel[storage.shardLevel];
    if (EnsureSpatialShardSlots16(shardArray) < static_cast<std::size_t>(kSpatialShardSlotCount)) {
      return;
    }

    for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
      const std::int32_t col = index % kSpatialShardGridDimension;
      const std::int32_t row = index / kSpatialShardGridDimension;

      gpg::Rect2i cellRect{};
      cellRect.x0 = shardSize * col;
      cellRect.z0 = shardSize * row;
      cellRect.x1 = shardSize * (col + 1);
      cellRect.z1 = shardSize * (row + 1);

      if (cellRect.x1 <= storage.mapWidth && cellRect.z1 <= storage.mapHeight) {
        shardArray.mBegin[index] = new (std::nothrow) moho::SpatialShard(storage.shardLevel - 1, nullptr, cellRect);
      } else {
        shardArray.mBegin[index] = nullptr;
      }
    }
  }

  /**
   * Address: 0x00503B10 (FUN_00503B10, sub_503B10)
   *
   * What it does:
   * Walks shard children by x/z cell index until it reaches one leaf-data lane.
   */
  [[nodiscard]] moho::SpatialShardData*
  ResolveSpatialLeafDataForPoint(moho::SpatialShard* shard, const float worldZ, const float worldX)
  {
    moho::SpatialShard* current = shard;
    while (current != nullptr) {
      const std::int32_t level = current->mLevel;
      const float cellSize = static_cast<float>(kSpatialShardCellSizeByLevel[level]);
      const std::int32_t laneX = static_cast<std::int32_t>((worldX - static_cast<float>(current->mAreaRect.x0)) / cellSize);
      const std::int32_t laneZ = static_cast<std::int32_t>((worldZ - static_cast<float>(current->mAreaRect.z0)) / cellSize);
      const std::int32_t laneIndex = laneX + kSpatialShardGridDimension * laneZ;

      if (level <= 0) {
        return current->mData.mBegin[laneIndex];
      }

      current = current->mShards.mBegin[laneIndex];
    }

    return nullptr;
  }

  /**
   * Address: 0x00502120 (FUN_00502120, sub_502120)
   *
   * What it does:
   * Resolves one world position to leaf shard-data lane; falls back to inline
   * root shard-data lane when position is outside shard-grid coverage.
   */
  [[nodiscard]] moho::SpatialShardData*
  ResolveSpatialLeafDataFromStoragePoint(const Wm3::Vec3f& point, SpatialDbMeshCollectView& storage)
  {
    const std::int32_t coarseX = static_cast<std::int32_t>(std::floor(point.x * 0.0625f));
    const std::int32_t coarseZ = static_cast<std::int32_t>(std::floor(point.z * 0.0625f));
    if (
      coarseX < 0 || coarseZ < 0 || coarseX >= storage.shardWidth || coarseZ >= storage.shardHeight ||
      storage.shardBegin == nullptr
    ) {
      return &storage.shardData;
    }

    const float shardCellSize = static_cast<float>(kSpatialShardCellSizeByLevel[storage.shardLevel]);
    const std::int32_t shardX = static_cast<std::int32_t>(point.x / shardCellSize);
    const std::int32_t shardZ = static_cast<std::int32_t>(point.z / shardCellSize);
    const std::int32_t topIndex = shardX + kSpatialShardGridDimension * shardZ;

    moho::SpatialShard* const rootShard = storage.shardBegin[topIndex];
    if (rootShard == nullptr) {
      return &storage.shardData;
    }

    moho::SpatialShardData* const leaf = ResolveSpatialLeafDataForPoint(rootShard, point.z, point.x);
    return leaf != nullptr ? leaf : &storage.shardData;
  }

  struct SpatialDbStorageRootView
  {
    std::uint8_t pad_00_83[0x84];
    void* orderedEntryRoot;     // +0x84
    void* orderedEntrySentinel; // +0x88
  };

  static_assert(
    offsetof(SpatialDbStorageRootView, orderedEntryRoot) == 0x84,
    "SpatialDbStorageRootView::orderedEntryRoot offset must be 0x84"
  );
  static_assert(
    offsetof(SpatialDbStorageRootView, orderedEntrySentinel) == 0x88,
    "SpatialDbStorageRootView::orderedEntrySentinel offset must be 0x88"
  );
  static_assert(sizeof(SpatialDbStorageRootView) == 0x8C, "SpatialDbStorageRootView size must be 0x8C");

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

  [[nodiscard]] boost::shared_ptr<moho::RScmResource>
  ResolveMeshResourceForLod(const msvc8::string& meshPath, moho::CResourceWatcher* const ownerWatcher)
  {
    // Address chain: 0x007DCED0 -> 0x00539BA0 -> 0x004ABEE0 -> 0x004AA220.
    // Full resource-manager lifting is pending; keep the API seam typed.
    (void)meshPath;
    (void)ownerWatcher;
    return {};
  }

  struct ShaderDictionaryEntry
  {
    msvc8::string remappedShaderName;
    std::int32_t sourceGeneration;
  };

  class ShaderDictionaryRuntime
  {
  public:
    /**
     * Address: 0x007DB3A0 (FUN_007DB3A0, ??0ShaderDictionary@Moho@@QAE@@Z)
     *
     * What it does:
     * Seeds the runtime shader remap dictionary with legacy-to-modern
     * annotation aliases used by mesh material creation.
     */
    ShaderDictionaryRuntime();

    [[nodiscard]] static ShaderDictionaryRuntime& Instance() noexcept
    {
      static ShaderDictionaryRuntime runtime{};
      return runtime;
    }

    [[nodiscard]] std::int32_t CurrentGeneration() const noexcept
    {
      return mCurrentGeneration;
    }

    [[nodiscard]] const ShaderDictionaryEntry* Lookup(const msvc8::string& requestedShaderName) const
    {
      const auto it = mEntries.find(NormalizeKey(requestedShaderName));
      if (it == mEntries.end()) {
        return nullptr;
      }

      return &it->second;
    }

    /**
     * Address: 0x007DBE90 (FUN_007DBE90, sub_7DBE90)
     *
     * What it does:
     * Writes one remap entry for one legacy shader annotation key.
     */
    void AssignRemap(const msvc8::string& legacyShaderName, const msvc8::string& remappedShaderName);

  private:
    template <class TString>
    [[nodiscard]] static std::string NormalizeKey(const TString& value)
    {
      const std::string_view view = value.view();
      return std::string(view.begin(), view.end());
    }

    std::int32_t mCurrentGeneration = 0;
    std::unordered_map<std::string, ShaderDictionaryEntry> mEntries{};
  };

  /**
   * Address: 0x007DBE90 (FUN_007DBE90, sub_7DBE90)
   *
   * What it does:
   * Stores one legacy shader key -> remapped shader name pair in the runtime
   * dictionary and tags the entry with the current dictionary generation.
   */
  void ShaderDictionaryRuntime::AssignRemap(
    const msvc8::string& legacyShaderName,
    const msvc8::string& remappedShaderName
  )
  {
    ShaderDictionaryEntry& entry = mEntries[NormalizeKey(legacyShaderName)];
    entry.remappedShaderName = remappedShaderName;
    entry.sourceGeneration = mCurrentGeneration;
  }

  /**
   * Address: 0x007DB3A0 (FUN_007DB3A0, ??0ShaderDictionary@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes the shader remap dictionary with all built-in annotation
   * aliases used by legacy mesh assets.
   */
  ShaderDictionaryRuntime::ShaderDictionaryRuntime()
  {
    AssignRemap("TMeshNoLighting", "Flat");
    AssignRemap("TMeshNoNormals", "VertexNormal");
    AssignRemap("TMeshAlpha", "NormalMappedAlpha");
    AssignRemap("TMeshGlow", "NormalMappedGlow");
    AssignRemap("TMeshTerrain", "NormalMappedTerrain");
    AssignRemap("Simple", "Unit");
    AssignRemap("Team", "Unit");
    AssignRemap("TMeshAlphaGlowFade", "UnitBuild");
    AssignRemap("TMeshMetalBuild", "AeonBuild");
    AssignRemap("TMeshShield", "Shield");
    AssignRemap("TMeshZFill", "ShieldFill");
    AssignRemap("TMeshAdd", "Effect");
    AssignRemap("TMeshExplosion", "Explosion");
    AssignRemap("TMeshCloud", "Cloud");
    AssignRemap("TMeshOuterCloud", "OuterCloud");
    AssignRemap("TMeshEMPNuke", "NukeEMP");
    AssignRemap("TMeshQuantumNuke", "NukeQuantum");
    AssignRemap("TMeshTemporalBubble", "TemporalBubble");
  }

  /**
   * Address: 0x007DBDB0 (FUN_007DBDB0, sub_7DBDB0)
   *
   * What it does:
   * Resolves one shader annotation through runtime shader remap dictionary
   * and falls back to caller text (or "Unit" for empty names).
   */
  [[nodiscard]] msvc8::string ResolveShaderAnnotationName(const msvc8::string& shaderName)
  {
    const ShaderDictionaryRuntime& dictionary = ShaderDictionaryRuntime::Instance();
    const ShaderDictionaryEntry* const dictionaryEntry = dictionary.Lookup(shaderName);
    if (!dictionaryEntry) {
      if (shaderName.empty()) {
        return msvc8::string("Unit");
      }

      return msvc8::string(shaderName.view());
    }

    if (dictionaryEntry->sourceGeneration != dictionary.CurrentGeneration()) {
      gpg::Warnf("Use of 'old' shader: %s", shaderName.raw_data_unsafe());
    }

    return msvc8::string(dictionaryEntry->remappedShaderName.view());
  }

  [[nodiscard]] boost::shared_ptr<moho::CD3DDynamicTextureSheet>
  ResolveMaterialTextureSheet(const msvc8::string& textureName, moho::CResourceWatcher* const resourceWatcher)
  {
    // Address chain: 0x007DC1B0 -> D3D_GetDevice/GetResources -> resource lookup vfunc.
    // Device/resource interfaces are still being reconstructed; keep this seam typed.
    (void)textureName;
    (void)resourceWatcher;
    return {};
  }

  void AssignMaterialTextureSheet(
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>& destination,
    const msvc8::string& textureName,
    moho::CResourceWatcher* const resourceWatcher
  )
  {
    if (textureName.empty()) {
      return;
    }

    destination = ResolveMaterialTextureSheet(textureName, resourceWatcher);
  }

  void MaybeRunExtraSoundWork()
  {
    // Address chain: 0x007DC1B0 -> gpg::time::Timer::ElapsedMilliseconds -> SND_Frame.
    // Sound-system globals are not yet reconstructed in this pass.
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

  constexpr std::uint8_t kRbNodeRed = 0;
  constexpr std::uint8_t kRbNodeBlack = 1;
  constexpr std::uint8_t kRbNodeSentinel = 1;

  [[nodiscard]] moho::MeshInstance::ListLink* MeshInstanceLink(moho::MeshInstance* const instance) noexcept
  {
    if (!instance) {
      return nullptr;
    }

    return reinterpret_cast<moho::MeshInstance::ListLink*>(&instance->linkPrev);
  }

  [[nodiscard]] moho::MeshInstance* MeshInstanceFromLink(moho::MeshInstance::ListLink* const link) noexcept
  {
    if (!link) {
      return nullptr;
    }

    return reinterpret_cast<moho::MeshInstance*>(
      reinterpret_cast<std::uint8_t*>(link) - offsetof(moho::MeshInstance, linkPrev)
    );
  }

  /**
   * Address: 0x007DF2B0 (FUN_007DF2B0)
   *
   * What it does:
   * Unlinks one mesh-instance intrusive link node from its current ring and
   * restores self-linked singleton lanes.
   */
  [[maybe_unused]] moho::MeshInstance::ListLink* UnlinkMeshInstanceListLink(
    moho::MeshInstance::ListLink* const link
  ) noexcept
  {
    link->mPrev->mNext = link->mNext;
    link->mNext->mPrev = link->mPrev;
    link->mPrev = link;
    link->mNext = link;
    return link;
  }

  void RemoveLinkFromList(moho::MeshInstance::ListLink* const link) noexcept
  {
    if (!link || !link->mPrev || !link->mNext) {
      return;
    }

    link->ListUnlink();
  }

  void InsertLinkBefore(moho::MeshInstance::ListLink* const position, moho::MeshInstance::ListLink* const link) noexcept
  {
    if (!position || !link || !position->mPrev) {
      return;
    }

    link->mPrev = position->mPrev;
    link->mNext = position;
    position->mPrev->mNext = link;
    position->mPrev = link;
  }

  [[nodiscard]] bool IsMeshCacheSentinelNode(const moho::MeshRendererMeshCacheNode* const node) noexcept
  {
    return node == nullptr || node->isSentinel == kRbNodeSentinel;
  }

  [[nodiscard]] bool IsMeshBatchSentinelNode(const moho::MeshBatchBucketNode* const node) noexcept
  {
    return node == nullptr || node->isSentinel == kRbNodeSentinel;
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode* CreateMeshCacheNode(
    const moho::MeshKey& key,
    const boost::shared_ptr<moho::Mesh>& mesh,
    moho::MeshRendererMeshCacheNode* const left,
    moho::MeshRendererMeshCacheNode* const parent,
    moho::MeshRendererMeshCacheNode* const right,
    const std::uint8_t color,
    const std::uint8_t isSentinel
  )
  {
    void* const raw = ::operator new(sizeof(moho::MeshRendererMeshCacheNode));
    auto* const node = static_cast<moho::MeshRendererMeshCacheNode*>(raw);

    node->left = left;
    node->parent = parent;
    node->right = right;
    new (&node->entry.key) moho::MeshKey(key);
    new (&node->entry.mesh) boost::shared_ptr<moho::Mesh>(mesh);
    node->color = color;
    node->isSentinel = isSentinel;
    node->pad_26_27[0] = 0;
    node->pad_26_27[1] = 0;
    return node;
  }

  void DestroyMeshCacheNode(moho::MeshRendererMeshCacheNode* const node) noexcept
  {
    if (!node) {
      return;
    }

    node->entry.mesh.~shared_ptr<moho::Mesh>();
    node->entry.key.~MeshKey();
    ::operator delete(node);
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode* CreateMeshCacheTreeSentinel()
  {
    const boost::shared_ptr<moho::MeshMaterial> emptyMaterial;
    const boost::shared_ptr<moho::Mesh> emptyMesh;
    moho::MeshKey sentinelKey(nullptr, emptyMaterial);
    moho::MeshRendererMeshCacheNode* const head =
      CreateMeshCacheNode(sentinelKey, emptyMesh, nullptr, nullptr, nullptr, kRbNodeBlack, kRbNodeSentinel);
    head->left = head;
    head->parent = head;
    head->right = head;
    return head;
  }

  /**
   * Address: 0x007E2B50 (FUN_007E2B50)
   *
   * What it does:
   * Initializes one mesh-cache RB-tree storage lane with a fresh self-linked
   * sentinel head and zero size.
   */
  [[maybe_unused]] moho::MeshRendererMeshCacheTree* InitializeMeshCacheTreeStorageAdapter(
    moho::MeshRendererMeshCacheTree* const tree
  )
  {
    tree->head = CreateMeshCacheTreeSentinel();
    tree->size = 0u;
    return tree;
  }

  void MeshCacheRotateLeft(moho::MeshRendererMeshCacheNode* const node, moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    moho::MeshRendererMeshCacheNode* const pivot = node->right;
    node->right = pivot->left;
    if (!IsMeshCacheSentinelNode(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (node == head->parent) {
      head->parent = pivot;
    } else {
      moho::MeshRendererMeshCacheNode* const parent = node->parent;
      if (node == parent->left) {
        parent->left = pivot;
      } else {
        parent->right = pivot;
      }
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void MeshCacheRotateRight(moho::MeshRendererMeshCacheNode* const node, moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    moho::MeshRendererMeshCacheNode* const pivot = node->left;
    node->left = pivot->right;
    if (!IsMeshCacheSentinelNode(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (node == head->parent) {
      head->parent = pivot;
    } else {
      moho::MeshRendererMeshCacheNode* const parent = node->parent;
      if (node == parent->right) {
        parent->right = pivot;
      } else {
        parent->left = pivot;
      }
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void
  RebalanceMeshCacheAfterInsert(moho::MeshRendererMeshCacheTree& tree, moho::MeshRendererMeshCacheNode* node) noexcept
  {
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    while (!IsMeshCacheSentinelNode(node->parent) && node->parent->color == kRbNodeRed) {
      moho::MeshRendererMeshCacheNode* const parent = node->parent;
      moho::MeshRendererMeshCacheNode* const grandParent = parent->parent;
      if (parent == grandParent->left) {
        moho::MeshRendererMeshCacheNode* const uncle = grandParent->right;
        if (!IsMeshCacheSentinelNode(uncle) && uncle->color == kRbNodeRed) {
          parent->color = kRbNodeBlack;
          uncle->color = kRbNodeBlack;
          grandParent->color = kRbNodeRed;
          node = grandParent;
        } else {
          if (node == parent->right) {
            node = parent;
            MeshCacheRotateLeft(node, tree);
          }
          node->parent->color = kRbNodeBlack;
          node->parent->parent->color = kRbNodeRed;
          MeshCacheRotateRight(node->parent->parent, tree);
        }
      } else {
        moho::MeshRendererMeshCacheNode* const uncle = grandParent->left;
        if (!IsMeshCacheSentinelNode(uncle) && uncle->color == kRbNodeRed) {
          parent->color = kRbNodeBlack;
          uncle->color = kRbNodeBlack;
          grandParent->color = kRbNodeRed;
          node = grandParent;
        } else {
          if (node == parent->left) {
            node = parent;
            MeshCacheRotateRight(node, tree);
          }
          node->parent->color = kRbNodeBlack;
          node->parent->parent->color = kRbNodeRed;
          MeshCacheRotateLeft(node->parent->parent, tree);
        }
      }
    }

    if (!IsMeshCacheSentinelNode(head->parent)) {
      head->parent->color = kRbNodeBlack;
    }
  }

  /**
   * Address: 0x007E6050 (FUN_007E6050)
   *
   * What it does:
   * Returns one lower-bound node in the mesh-cache tree for `key`, or the head
   * sentinel when no key >= probe exists.
   */
  [[nodiscard]] moho::MeshRendererMeshCacheNode*
  MeshCacheTreeLowerBound(const moho::MeshRendererMeshCacheTree& tree, const moho::MeshKey& key) noexcept
  {
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (!head) {
      return nullptr;
    }

    moho::MeshRendererMeshCacheNode* candidate = head;
    for (moho::MeshRendererMeshCacheNode* node = head->parent; !IsMeshCacheSentinelNode(node);) {
      if (node->entry.key.LessThan(key)) {
        node = node->right;
      } else {
        candidate = node;
        node = node->left;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x007E5C00 (FUN_007E5C00)
   *
   * What it does:
   * Finds one exact mesh-cache key and stores either that node or the tree head
   * sentinel (miss) into `outNode`.
   */
  moho::MeshRendererMeshCacheNode** FindMeshCacheNodeExactOrHead(
    moho::MeshRendererMeshCacheNode** const outNode,
    const moho::MeshRendererMeshCacheTree& tree,
    const moho::MeshKey& key
  ) noexcept
  {
    if (outNode == nullptr || tree.head == nullptr) {
      return outNode;
    }

    moho::MeshRendererMeshCacheNode* const candidate = MeshCacheTreeLowerBound(tree, key);
    if (candidate == tree.head || key.LessThan(candidate->entry.key)) {
      *outNode = tree.head;
    } else {
      *outNode = candidate;
    }
    return outNode;
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode*
  MeshCacheTreeFind(const moho::MeshRendererMeshCacheTree& tree, const moho::MeshKey& key) noexcept
  {
    moho::MeshRendererMeshCacheNode* candidate = tree.head;
    (void)FindMeshCacheNodeExactOrHead(&candidate, tree, key);
    if (!candidate || candidate == tree.head) {
      return nullptr;
    }

    return candidate;
  }

  [[nodiscard]] moho::MeshRendererMeshCacheNode* MeshCacheTreeInsertUnique(
    moho::MeshRendererMeshCacheTree& tree,
    const moho::MeshKey& key,
    const boost::shared_ptr<moho::Mesh>& mesh,
    bool& inserted
  )
  {
    inserted = false;
    moho::MeshRendererMeshCacheNode* const head = tree.head;
    if (!head) {
      return nullptr;
    }

    moho::MeshRendererMeshCacheNode* parent = head;
    moho::MeshRendererMeshCacheNode* node = head->parent;
    bool insertLeft = true;
    while (!IsMeshCacheSentinelNode(node)) {
      parent = node;
      if (key.LessThan(node->entry.key)) {
        insertLeft = true;
        node = node->left;
        continue;
      }

      if (node->entry.key.LessThan(key)) {
        insertLeft = false;
        node = node->right;
        continue;
      }

      return node;
    }

    moho::MeshRendererMeshCacheNode* const insertedNode =
      CreateMeshCacheNode(key, mesh, head, parent, head, kRbNodeRed, 0);
    if (parent == head) {
      head->parent = insertedNode;
      head->left = insertedNode;
      head->right = insertedNode;
    } else if (insertLeft) {
      parent->left = insertedNode;
      if (parent == head->left) {
        head->left = insertedNode;
      }
    } else {
      parent->right = insertedNode;
      if (parent == head->right) {
        head->right = insertedNode;
      }
    }

    ++tree.size;
    RebalanceMeshCacheAfterInsert(tree, insertedNode);
    inserted = true;
    return insertedNode;
  }

  void ClearMeshCacheTreeNodes(
    moho::MeshRendererMeshCacheNode* const node, moho::MeshRendererMeshCacheNode* const head
  ) noexcept
  {
    if (!node || node == head || IsMeshCacheSentinelNode(node)) {
      return;
    }

    ClearMeshCacheTreeNodes(node->left, head);
    ClearMeshCacheTreeNodes(node->right, head);
    DestroyMeshCacheNode(node);
  }

  void ResetMeshCacheTree(moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    if (!tree.head) {
      tree.size = 0;
      return;
    }

    ClearMeshCacheTreeNodes(tree.head->parent, tree.head);
    tree.head->parent = tree.head;
    tree.head->left = tree.head;
    tree.head->right = tree.head;
    tree.size = 0;
  }

  /**
   * Address: 0x007DF2D0 (FUN_007DF2D0, sub_7DF2D0)
   *
   * What it does:
   * Releases one mesh-cache RB-tree storage lane by erasing all entries,
   * deleting the head sentinel, and zeroing `{head,size}`.
   */
  std::int32_t ReleaseMeshCacheTreeStorage(moho::MeshRendererMeshCacheTree* const tree) noexcept
  {
    if (tree == nullptr) {
      return 0;
    }

    if (tree->head != nullptr) {
      ResetMeshCacheTree(*tree);
      DestroyMeshCacheNode(tree->head);
    }

    tree->head = nullptr;
    tree->size = 0u;
    return 0;
  }

  void DestroyMeshCacheTree(moho::MeshRendererMeshCacheTree& tree) noexcept
  {
    (void)ReleaseMeshCacheTreeStorage(&tree);
    tree.proxy = nullptr;
  }

  [[nodiscard]] moho::MeshBatchBucketNode* CreateMeshBatchTreeSentinel()
  {
    auto* const head = new moho::MeshBatchBucketNode{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = kRbNodeBlack;
    head->isSentinel = kRbNodeSentinel;
    head->bucket.instances.proxy = nullptr;
    head->bucket.instances.first = nullptr;
    head->bucket.instances.last = nullptr;
    head->bucket.instances.end = nullptr;
    return head;
  }

  /**
   * Address: 0x007E2C30 (FUN_007E2C30)
   *
   * What it does:
   * Initializes one mesh-batch RB-tree storage lane with a fresh self-linked
   * sentinel head and zero size.
   */
  [[maybe_unused]] moho::MeshBatchBucketTree* InitializeMeshBatchTreeStorageAdapter(
    moho::MeshBatchBucketTree* const tree
  )
  {
    tree->head = CreateMeshBatchTreeSentinel();
    tree->size = 0u;
    return tree;
  }

  void ReleaseMeshBatchInstanceVector(moho::MeshBatchInstanceVector& vector) noexcept
  {
    if (vector.first) {
      ::operator delete(vector.first);
    }

    vector.proxy = nullptr;
    vector.first = nullptr;
    vector.last = nullptr;
    vector.end = nullptr;
  }

  void ClearMeshBatchTreeNodes(moho::MeshBatchBucketNode* const node, moho::MeshBatchBucketNode* const head) noexcept
  {
    if (!node || node == head || IsMeshBatchSentinelNode(node)) {
      return;
    }

    ClearMeshBatchTreeNodes(node->left, head);
    ClearMeshBatchTreeNodes(node->right, head);
    ReleaseMeshBatchInstanceVector(node->bucket.instances);
    delete node;
  }

  void ResetMeshBatchTree(moho::MeshBatchBucketTree& tree) noexcept
  {
    if (!tree.head) {
      tree.size = 0;
      return;
    }

    ClearMeshBatchTreeNodes(tree.head->parent, tree.head);
    tree.head->parent = tree.head;
    tree.head->left = tree.head;
    tree.head->right = tree.head;
    tree.size = 0;
  }

  /**
   * Address: 0x007E2D90 (FUN_007E2D90)
   *
   * What it does:
   * Clears one mesh-batch RB-tree payload lane and restores empty sentinel
   * head-links; returns the tree head lane.
   */
  [[maybe_unused]] moho::MeshBatchBucketNode* ResetMeshBatchTreeAndReturnHead(
    moho::MeshBatchBucketTree* const tree
  ) noexcept
  {
    if (tree == nullptr || tree->head == nullptr) {
      return nullptr;
    }

    ResetMeshBatchTree(*tree);
    return tree->head;
  }

  /**
   * Address: 0x007E2B20 (FUN_007E2B20, sub_7E2B20)
   *
   * What it does:
   * Releases one mesh-batch RB-tree storage lane by erasing all entries,
   * deleting the head sentinel, and zeroing `{head,size}`.
   */
  std::int32_t ReleaseMeshBatchTreeStorage(moho::MeshBatchBucketTree* const tree) noexcept
  {
    if (tree == nullptr) {
      return 0;
    }

    if (tree->head != nullptr) {
      ResetMeshBatchTree(*tree);
      delete tree->head;
    }

    tree->head = nullptr;
    tree->size = 0u;
    return 0;
  }

  void DestroyMeshBatchTree(moho::MeshBatchBucketTree& tree) noexcept
  {
    (void)ReleaseMeshBatchTreeStorage(&tree);
    tree.proxy = nullptr;
  }

  void ResetLodBatchesForInstanceLinkList(moho::MeshInstance::ListLink& head) noexcept
  {
    for (moho::MeshInstance::ListLink* link = head.mNext; link && link != &head; link = link->mNext) {
      moho::MeshInstance* const instance = MeshInstanceFromLink(link);
      if (!instance || !instance->mesh) {
        continue;
      }

      for (moho::MeshLOD** lod = instance->mesh->lods.begin(); lod && lod != instance->mesh->lods.end(); ++lod) {
        if (*lod) {
          (*lod)->ResetBatches();
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
  SpatialShard::SpatialShard(const std::int32_t level, SpatialShard* const parent, const gpg::Rect2i& areaRect)
    : mParent(parent)
    , mAreaRect(areaRect)
    , mLevel(level)
    , mUnitCount(0)
    , mProjectileCount(0)
    , mPropCount(0)
    , mEntityCount(0)
    , mBounds{}
    , mShards{}
    , mData{}
  {
    mBounds.Min.x = FLT_MAX;
    mBounds.Min.y = FLT_MAX;
    mBounds.Min.z = FLT_MAX;
    mBounds.Max.x = -FLT_MAX;
    mBounds.Max.y = -FLT_MAX;
    mBounds.Max.z = -FLT_MAX;

    mShards.mDebugProxy = nullptr;
    mShards.mBegin = nullptr;
    mShards.mEnd = nullptr;
    mShards.mCapacity = nullptr;

    mData.mDebugProxy = nullptr;
    mData.mBegin = nullptr;
    mData.mEnd = nullptr;
    mData.mCapacity = nullptr;

    if (mLevel <= 0) {
      AllocateSpatialShardArray(mData, 16);
      if (mData.mBegin == nullptr) {
        return;
      }

      for (std::int32_t index = 0; index < 16; ++index) {
        SpatialShardData* const lane = new (std::nothrow) SpatialShardData(this);
        mData.mBegin[index] = lane;
      }
      return;
    }

    const std::int32_t dx = (mAreaRect.x1 - mAreaRect.x0) / 4;
    const std::int32_t dz = (mAreaRect.z1 - mAreaRect.z0) / 4;

    EnsureSpatialShardSlots16(mShards);
    if (mShards.mBegin == nullptr) {
      return;
    }

    for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
      const std::int32_t col = index % kSpatialShardGridDimension;
      const std::int32_t row = index / kSpatialShardGridDimension;

      gpg::Rect2i childRect{};
      childRect.x0 = mAreaRect.x0 + dx * col;
      childRect.z0 = mAreaRect.z0 + dz * row;
      childRect.x1 = mAreaRect.x0 + dx * (col + 1);
      childRect.z1 = mAreaRect.z0 + dz * (row + 1);

      SpatialShard* const child = new (std::nothrow) SpatialShard(mLevel - 1, this, childRect);
      mShards.mBegin[index] = child;
    }
  }

  /**
   * Address: 0x00501370 (FUN_00501370, Moho::SpatialShard::~SpatialShard)
   *
   * What it does:
   * Releases recursively-owned child shards or leaf-data lanes and frees shard
   * pointer arrays.
   */
  SpatialShard::~SpatialShard()
  {
    if (mLevel <= 0) {
      if (mData.mBegin != nullptr) {
        for (std::int32_t index = 0; index < 16; ++index) {
          delete mData.mBegin[index];
          mData.mBegin[index] = nullptr;
        }
      }
      mData.mEnd = mData.mBegin;
    } else {
      if (mShards.mBegin != nullptr) {
        for (std::int32_t index = 0; index < 16; ++index) {
          delete mShards.mBegin[index];
          mShards.mBegin[index] = nullptr;
        }
      }
      mShards.mEnd = mShards.mBegin;
    }

    ResetSpatialShardArray(mData);
    ResetSpatialShardArray(mShards);
  }

  /**
   * Address: 0x00501490 (FUN_00501490, Moho::SpatialShard::CountType)
   *
   * What it does:
   * Returns true when the shard has no entries for requested type lanes.
   */
  bool SpatialShard::CountType(const EEntityType type) const
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
  void SpatialShard::DecrementCount(SpatialShard* shard, const EEntityType type)
  {
    for (SpatialShard* current = shard; current != nullptr; current = current->mParent) {
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
  void SpatialShard::RecalculateBounds()
  {
    for (SpatialShard* shard = this; shard != nullptr; shard = shard->mParent) {
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
          sourceBounds = &shard->mData.mBegin[index]->mBounds;
        } else {
          sourceBounds = &shard->mShards.mBegin[index]->mBounds;
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
  bool SpatialShardData::HasType(const SpatialShardData* const data, const EEntityType type)
  {
    const std::uint32_t typeBits = EntityTypeBits(type);
    if (typeBits != 0u) {
      return ((typeBits & kSpatialEntityTypeUnit) == 0u || data->mMapUnits.mSize == 0)
        && ((typeBits & kSpatialEntityTypeProjectile) == 0u || data->mMapProjectiles.mSize == 0)
        && ((typeBits & kSpatialEntityTypeProp) == 0u || data->mMapProps.mSize == 0)
        && ((typeBits & kSpatialEntityTypeEntity) == 0u || data->mMapEntities.mSize == 0);
    }

    return data->mMapUnits.mSize == 0 && data->mMapProjectiles.mSize == 0 && data->mMapProps.mSize == 0 &&
      data->mMapEntities.mSize == 0;
  }

  /**
   * Address: 0x00500F60 (FUN_00500F60, Moho::SpatialShardData::SpatialShardData)
   *
   * What it does:
   * Initializes one shard-data lane and allocates sentinel heads for all
   * entity-type trees.
   */
  SpatialShardData::SpatialShardData(SpatialShard* const ownerShard)
    : mShard(ownerShard)
    , mPad_04_13{}
    , mTimeSinceRecalc(0)
    , mBounds{}
    , mMapUnits{}
    , mMapProjectiles{}
    , mMapProps{}
    , mMapEntities{}
  {
    mBounds.Min.x = FLT_MAX;
    mBounds.Min.y = FLT_MAX;
    mBounds.Min.z = FLT_MAX;
    mBounds.Max.x = -FLT_MAX;
    mBounds.Max.y = -FLT_MAX;
    mBounds.Max.z = -FLT_MAX;

    InitializeSpatialMapTree(mMapUnits);
    InitializeSpatialMapTree(mMapProjectiles);
    InitializeSpatialMapTree(mMapProps);
    InitializeSpatialMapTree(mMapEntities);
  }

  /**
   * Address: 0x005017E0 (FUN_005017E0, Moho::SpatialShardData::~SpatialShardData)
   *
   * What it does:
   * Releases all map nodes and sentinel heads for unit/projectile/prop/entity
   * trees.
   */
  SpatialShardData::~SpatialShardData()
  {
    DestroySpatialMapTree(mMapEntities);
    DestroySpatialMapTree(mMapProps);
    DestroySpatialMapTree(mMapProjectiles);
    DestroySpatialMapTree(mMapUnits);
  }

  /**
   * Address: 0x005023B0 (FUN_005023B0, Moho::SpatialShardData::RecalculateBounds)
   *
   * What it does:
   * Rebuilds aggregate bounds from all leaf-map lanes, then propagates shard
   * bounds through the owning shard chain.
   */
  void SpatialShardData::RecalculateBounds()
  {
    Wm3::AxisAlignedBox3f mergedBounds{};
    mergedBounds.Min.x = FLT_MAX;
    mergedBounds.Min.y = FLT_MAX;
    mergedBounds.Min.z = FLT_MAX;
    mergedBounds.Max.x = -FLT_MAX;
    mergedBounds.Max.y = -FLT_MAX;
    mergedBounds.Max.z = -FLT_MAX;

    const auto accumulateTreeBounds = [&mergedBounds](const SpatialMapTree& tree) {
      const SpatialMapNode* const head = tree.mHead;
      if (head == nullptr) {
        return;
      }

      for (const SpatialMapNode* node = head->mLeft; node != head; node = TreeNext(node)) {
        const Wm3::AxisAlignedBox3f& nodeBox = node->mBox;
        mergedBounds.Min.x = std::min(mergedBounds.Min.x, nodeBox.Min.x);
        mergedBounds.Min.y = std::min(mergedBounds.Min.y, nodeBox.Min.y);
        mergedBounds.Min.z = std::min(mergedBounds.Min.z, nodeBox.Min.z);
        mergedBounds.Max.x = std::max(mergedBounds.Max.x, nodeBox.Max.x);
        mergedBounds.Max.y = std::max(mergedBounds.Max.y, nodeBox.Max.y);
        mergedBounds.Max.z = std::max(mergedBounds.Max.z, nodeBox.Max.z);
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
   * Removes one node from the matching entity-type tree and updates shard
   * counts up the owner chain.
   */
  void SpatialShardData::RemoveNode(SpatialMapNode* const node)
  {
    if (node == nullptr) {
      return;
    }

    ++mTimeSinceRecalc;
    const EEntityType type = static_cast<EEntityType>(node->mEntityType);

    SpatialMapTree* targetTree = &mMapEntities;
    const std::uint32_t typeBits = EntityTypeBits(type);
    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      targetTree = &mMapUnits;
    } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      targetTree = &mMapProjectiles;
    } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      targetTree = &mMapProps;
    }

    SpatialMapEraseNode(*targetTree, node);
    if (mShard != nullptr) {
      SpatialShard::DecrementCount(mShard, type);
    }
  }

  /**
   * Address: 0x00502780 (FUN_00502780, Moho::SpatialShardData::CollectFromData)
   *
   * What it does:
   * Appends all entity pointers from selected leaf maps to destination.
   */
  void SpatialShardData::CollectFromData(const EEntityType type, gpg::fastvector<UserEntity*>& destination, SpatialShardData* const data)
  {
    if (SpatialShardDataHasNoRequestedType(*data, type)) {
      return;
    }

    const std::uint32_t typeBits = EntityTypeBits(type);
    const auto collectAll = [&destination](const SpatialMapTree& tree) {
      CollectTreeNodes(tree, destination, [](const Wm3::AxisAlignedBox3f&) { return true; });
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
  void SpatialShardData::Collect(
    SpatialShard* const shard,
    const EEntityType type,
    gpg::fastvector<UserEntity*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        CollectFromData(type, destination, shard->mData.mBegin[index]);
      } else {
        Collect(shard->mShards.mBegin[index], type, destination);
      }
    }
  }

  /**
   * Address: 0x00503C00 (FUN_00503C00, Moho::SpatialShardData::CollectInBox)
   *
   * What it does:
   * Recursively collects selected entities that intersect one AABB query.
   */
  void SpatialShardData::CollectInBox(
    SpatialShard* const shard,
    const EEntityType type,
    const Wm3::AxisAlignedBox3f& bounds,
    gpg::fastvector<UserEntity*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !AxisAlignedBoxesIntersect(shard->mBounds, bounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        shard->mData.mBegin[index]->CollectInBoxFromData(bounds, type, destination);
      } else {
        CollectInBox(shard->mShards.mBegin[index], type, bounds, destination);
      }
    }
  }

  /**
   * Address: 0x00502950 (FUN_00502950, Moho::SpatialShardData::CollectInBoxFromData)
   *
   * What it does:
   * Collects entities from this leaf-data lane that intersect one AABB query.
   */
  void SpatialShardData::CollectInBoxFromData(
    const Wm3::AxisAlignedBox3f& bounds,
    const EEntityType type,
    gpg::fastvector<UserEntity*>& destination
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
  void SpatialShardData::CollectInVolume(
    SpatialShard* const shard,
    const EEntityType type,
    CGeomSolid3* const volume,
    gpg::fastvector<UserEntity*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume->Intersects(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        shard->mData.mBegin[index]->CollectInVolumeFromData(destination, type, volume);
      } else {
        CollectInVolume(shard->mShards.mBegin[index], type, volume, destination);
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
  void SpatialShardData::CollectInVolumeFromData(
    gpg::fastvector<UserEntity*>& destination,
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
   * Address: 0x00503730 (FUN_00503730, Moho::SpatialShardData::FindInVolumeFromData)
   *
   * What it does:
   * Collects matching entities from one leaf shard-data lane using view-volume
   * culling plus per-node fade threshold early-out.
   */
  void SpatialShardData::FindInVolumeFromData(
    const Vector4f& fadePlane,
    const Wm3::Vector3f& supportSelector,
    SpatialShardData* const data,
    const EEntityType type,
    CGeomSolid3* const volume,
    gpg::fastvector<UserEntity*>& destination
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
  void SpatialShardData::FindInVolume(
    SpatialShard* const shard,
    const EEntityType type,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane,
    gpg::fastvector<UserEntity*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume->Intersects(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        FindInVolumeFromData(fadePlane, supportSelector, shard->mData.mBegin[index], type, volume, destination);
      } else {
        FindInVolume(shard->mShards.mBegin[index], type, volume, supportSelector, fadePlane, destination);
      }
    }
  }

  /**
   * Address: 0x00501D80 (FUN_00501D80, Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance)
   *
   * What it does:
   * Initializes one embedded spatial-db mesh-storage view in-place.
   */
  void SpatialDB_MeshInstance::InitializeStorage()
  {
    auto& storage = AsSpatialDbMeshCollectView(*this);
    InitializeSpatialDbMeshStorage(storage);
  }

  /**
   * Address: 0x007E2AA0 (FUN_007E2AA0)
   *
   * What it does:
   * Register-shape adapter that placement-constructs one
   * `SpatialDB_MeshInstance` object in caller-provided storage.
   */
  [[maybe_unused]] SpatialDB_MeshInstance* ConstructSpatialDbMeshInstanceAdapter(
    SpatialDB_MeshInstance* const storage
  )
  {
    return ::new (storage) SpatialDB_MeshInstance();
  }

  /**
   * Address: 0x007E2AC0 (FUN_007E2AC0)
   *
   * What it does:
   * Register-shape adapter that forwards one collect-all-in-volume request to
   * `SpatialDB_MeshInstance::CollectAllInVolume`.
   */
  [[maybe_unused]] std::int32_t CollectAllInVolumeAdapter(
    SpatialDB_MeshInstance* const instance,
    gpg::fastvector<UserEntity*>& destination,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane
  )
  {
    return instance->CollectAllInVolume(destination, volume, supportSelector, fadePlane);
  }

  /**
   * Address: 0x007E2AD0 (FUN_007E2AD0)
   *
   * What it does:
   * Register-shape adapter that registers one spatial-db entry with fixed
   * routing mask `0x800`.
   */
  [[maybe_unused]] SpatialDB_MeshInstance* RegisterSpatialDbEntryMask800Adapter(
    SpatialDB_MeshInstance* const entry,
    void* const spatialDbStorage,
    void* const owner
  )
  {
    entry->Register(spatialDbStorage, owner, 0x800);
    return entry;
  }

  /**
     * Alias of FUN_00501F50 (non-canonical helper lane).
   *
   * What it does:
   * Rebuilds embedded top-level shard lanes for one map-size update.
   */
  void SpatialDB_MeshInstance::ResizeStorageForMap(const std::int32_t width, const std::int32_t height)
  {
    auto& storage = AsSpatialDbMeshCollectView(*this);
    UpdateSpatialDbMeshStorageMapSize(storage, width, height);
  }

  /**
   * Address: 0x00501E50 (FUN_00501E50, Moho::SpatialDB_MeshInstance::~SpatialDB_MeshInstance)
   *
   * What it does:
   * Tears down one embedded spatial-db mesh-storage view in-place.
   */
  void SpatialDB_MeshInstance::DestroyStorage()
  {
    auto& storage = AsSpatialDbMeshCollectView(*this);
    DestroySpatialDbMeshStorage(storage);
  }

  struct SpatialDbEntryPairRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
  };
  static_assert(sizeof(SpatialDbEntryPairRuntimeView) == 0x08, "SpatialDbEntryPairRuntimeView size must be 0x08");

  /**
   * Address: 0x00501A70 (FUN_00501A70)
   *
   * What it does:
   * Zero-initializes one two-dword spatial-db entry pair lane.
   */
  [[maybe_unused]] SpatialDbEntryPairRuntimeView* InitializeSpatialDbEntryPairZero(
    SpatialDbEntryPairRuntimeView* const entryPair
  ) noexcept
  {
    entryPair->lane00 = 0u;
    entryPair->lane04 = 0u;
    return entryPair;
  }

  /**
   * Address: 0x00501A80 (FUN_00501A80, sub_501A80)
   *
   * What it does:
   * Registers one mesh-instance owner in the spatial-db storage and seeds entry state.
   */
  void SpatialDB_MeshInstance::Register(void* const spatialDbStorage, void* const owner, const std::int32_t routingMask)
  {
    if (db) {
      ClearRegistration();
    }

    db = spatialDbStorage;
    entry = 0;
    if (!db) {
      return;
    }

    auto* const storage = reinterpret_cast<SpatialDbMeshCollectView*>(db);
    SpatialMapValuePayload payload{};
    payload.mBox = {};
    payload.mEntityType = static_cast<std::uint32_t>(routingMask);
    payload.mData = nullptr;
    payload.mFadeOut = 0.0f;
    payload.mOwner = owner;

    moho::SpatialMapNode* const inserted = InsertSpatialPayloadWithHint(storage->mapTree, payload, storage->mapTree.mHead);
    entry = EntryHandleFromNode(inserted);
  }

  /**
   * Address: 0x00501B00 (FUN_00501B00, sub_501B00)
   *
   * What it does:
   * Updates dissolve-cutoff payload in the current spatial-db entry.
   */
  void SpatialDB_MeshInstance::UpdateDissolveCutoff(const float cutoff)
  {
    if (!db || entry == 0) {
      return;
    }

    auto* const storage = reinterpret_cast<SpatialDbMeshCollectView*>(db);
    moho::SpatialMapNode* const currentNode = EntryNodeFromHandle(entry);
    if (currentNode == nullptr || storage == nullptr) {
      return;
    }

    SpatialMapValuePayload payload = MakePayloadFromNode(*currentNode);
    payload.mFadeOut = cutoff;

    moho::SpatialMapNode* insertedNode = nullptr;
    if (currentNode->mShardData != nullptr) {
      moho::SpatialShardData* const data = currentNode->mShardData;
      data->RemoveNode(currentNode);
      insertedNode = InsertSpatialPayloadIntoShardData(*data, payload);
    } else {
      SpatialMapEraseNode(storage->mapTree, currentNode);
      insertedNode = InsertSpatialPayloadWithHint(storage->mapTree, payload, storage->mapTree.mHead);
    }

    entry = EntryHandleFromNode(insertedNode);
  }

  /**
   * Address: 0x00501C10 (FUN_00501C10, sub_501C10)
   *
   * What it does:
   * Copies one updated world AABB into this spatial-db entry payload lane.
   */
  void SpatialDB_MeshInstance::UpdateBounds(const Wm3::AxisAlignedBox3f& bounds)
  {
    if (!db || entry == 0) {
      return;
    }

    auto* const storage = reinterpret_cast<SpatialDbMeshCollectView*>(db);
    moho::SpatialMapNode* const currentNode = EntryNodeFromHandle(entry);
    if (currentNode == nullptr || storage == nullptr) {
      return;
    }

    const bool requiresRelink = (currentNode->mShardData != nullptr)
      ? HasSpatialCellChanged(currentNode->mBox, bounds)
      : true;
    currentNode->mBox = bounds;

    if (requiresRelink) {
      SpatialMapValuePayload payload = MakePayloadFromNode(*currentNode);
      if (currentNode->mShardData != nullptr) {
        currentNode->mShardData->RemoveNode(currentNode);
      } else {
        SpatialMapEraseNode(storage->mapTree, currentNode);
      }

      const Wm3::Vec3f queryPoint{bounds.Min.x, 0.0f, bounds.Min.z};
      moho::SpatialShardData* const targetData = ResolveSpatialLeafDataFromStoragePoint(queryPoint, *storage);
      moho::SpatialMapNode* const insertedNode = InsertSpatialPayloadIntoShardData(*targetData, payload);
      entry = EntryHandleFromNode(insertedNode);
      return;
    }

    moho::SpatialShardData* const data = currentNode->mShardData;
    if (data == nullptr) {
      return;
    }

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

  void SpatialDB_MeshInstance::ClearRegistration() noexcept
  {
    if (!db) {
      entry = 0;
      return;
    }

    auto* const storage = reinterpret_cast<SpatialDbMeshCollectView*>(db);
    moho::SpatialMapNode* const currentNode = EntryNodeFromHandle(entry);
    if (currentNode != nullptr) {
      if (currentNode->mShardData != nullptr) {
        currentNode->mShardData->RemoveNode(currentNode);
      } else if (storage != nullptr) {
        SpatialMapEraseNode(storage->mapTree, currentNode);
      }
    }

    db = nullptr;
    entry = 0;
  }

  /**
   * Address: 0x00501BC0 (FUN_00501BC0, ??1SpatialDB_MeshInstance@Moho@@QAE@XZ)
   *
   * What it does:
   * Clears mesh-instance spatial-db registration state.
   */
  SpatialDB_MeshInstance::~SpatialDB_MeshInstance()
  {
    ClearRegistration();
  }

  /**
   * Address: 0x00504090 (FUN_00504090)
   *
   * What it does:
   * Walks all shard lanes in one mesh-instance view, collects node owners whose
   * AABBs intersect `bounds`, then appends matches from inline root shard data.
   */
  [[maybe_unused]] std::int32_t CollectShardsInBoxIntoDestination(
    const Wm3::AxisAlignedBox3f& bounds,
    gpg::fastvector<UserEntity*>& destination,
    SpatialDbMeshCollectView& spatialView,
    const EEntityType type
  )
  {
    for (SpatialShard** shard = spatialView.shardBegin; shard != spatialView.shardEnd; ++shard) {
      if (*shard != nullptr) {
        SpatialShardData::CollectInBox(*shard, type, bounds, destination);
      }
    }

    spatialView.shardData.CollectInBoxFromData(bounds, type, destination);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x005040E0 (FUN_005040E0)
   *
   * What it does:
   * Walks all shard lanes in one mesh-instance view, collects node owners that
   * intersect `volume`, then appends matches from inline root shard data.
   */
  [[maybe_unused]] std::int32_t CollectShardsInVolumeIntoDestination(
    CGeomSolid3* const volume,
    gpg::fastvector<UserEntity*>& destination,
    SpatialDbMeshCollectView& spatialView,
    const EEntityType type
  )
  {
    for (SpatialShard** shard = spatialView.shardBegin; shard != spatialView.shardEnd; ++shard) {
      if (*shard != nullptr) {
        SpatialShardData::CollectInVolume(*shard, type, volume, destination);
      }
    }

    spatialView.shardData.CollectInVolumeFromData(destination, type, volume);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x00503F80 (FUN_00503F80, Moho::SpatialDB_MeshInstance::Collect)
   *
   * What it does:
   * Collects requested entity lanes from shard hierarchy, inline root
   * shard-data lane, and map-backed overflow lane.
   */
  std::int32_t SpatialDB_MeshInstance::Collect(
    gpg::fastvector<UserEntity*>& destination,
    const EEntityType type
  )
  {
    SpatialDbMeshCollectView& spatialView = AsSpatialDbMeshCollectView(*this);

    for (SpatialShard** shard = spatialView.shardBegin; shard != spatialView.shardEnd; ++shard) {
      if (*shard != nullptr) {
        SpatialShardData::Collect(*shard, type, destination);
      }
    }

    SpatialShardData::CollectFromData(type, destination, &spatialView.shardData);
    CollectTreeNodes(spatialView.mapTree, destination, [](const Wm3::AxisAlignedBox3f&) { return true; });
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x0082BA50 (FUN_0082BA50)
   *
   * What it does:
   * Register-order bridge that forwards one mesh-instance spatial collect lane
   * into `SpatialDB_MeshInstance::Collect`.
   */
  [[maybe_unused]] std::int32_t CollectMeshInstanceRegisterAdapter(
    SpatialDB_MeshInstance* const instance,
    const EEntityType type,
    gpg::fastvector<UserEntity*>& destination
  )
  {
    return instance->Collect(destination, type);
  }

  /**
   * Address: 0x008C5A90 (FUN_008C5A90)
   *
   * What it does:
   * Source-first adapter that forwards one mesh-instance box query into
   * `SpatialDB_MeshInstance::CollectInBox`.
   */
  [[maybe_unused]] std::int32_t CollectMeshInstanceInBoxSourceFirstAdapter(
    SpatialDB_MeshInstance* const instance,
    gpg::fastvector<UserEntity*>* const destination,
    const Wm3::AxisAlignedBox3f* const bounds
  )
  {
    return instance->CollectInBox(*destination, *bounds);
  }

  /**
   * Address: 0x00504040 (FUN_00504040, Moho::SpatialDB_MeshInstance::CollectInBox)
   *
   * What it does:
   * Walks all child shard pointers, collects unit entities intersecting
   * `bounds`, then collects from the inline root shard-data lane.
   */
  std::int32_t SpatialDB_MeshInstance::CollectInBox(
    gpg::fastvector<UserEntity*>& destination,
    const Wm3::AxisAlignedBox3f& bounds
  )
  {
    SpatialDbMeshCollectView& spatialView = AsSpatialDbMeshCollectView(*this);
    constexpr EEntityType kUnitType = static_cast<EEntityType>(kSpatialEntityTypeUnit);
    return CollectShardsInBoxIntoDestination(bounds, destination, spatialView, kUnitType);
  }

  /**
   * Address: 0x00504130 (FUN_00504130, Moho::SpatialDB_MeshInstance::CollectInVolume)
   *
   * What it does:
   * Walks all child shard pointers, collects matching entities intersecting
   * `volume`, then collects from the inline root shard-data lane.
   */
  std::int32_t SpatialDB_MeshInstance::CollectInVolume(
    gpg::fastvector<UserEntity*>& destination,
    const EEntityType type,
    CGeomSolid3* const volume
  )
  {
    SpatialDbMeshCollectView& spatialView = AsSpatialDbMeshCollectView(*this);
    return CollectShardsInVolumeIntoDestination(volume, destination, spatialView, type);
  }

  /**
   * Address: 0x00504180 (FUN_00504180, Moho::SpatialDB_MeshInstance::CollectAllInVolume)
   *
   * What it does:
   * Collects all render-relevant entity lanes (unit/prop/projectile/entity)
   * intersecting `volume` with fade-threshold cull inputs.
   */
  std::int32_t SpatialDB_MeshInstance::CollectAllInVolume(
    gpg::fastvector<UserEntity*>& destination,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane
  )
  {
    SpatialDbMeshCollectView& spatialView = AsSpatialDbMeshCollectView(*this);
    constexpr EEntityType kAllRenderableTypes = static_cast<EEntityType>(
      kSpatialEntityTypeUnit | kSpatialEntityTypeProjectile | kSpatialEntityTypeProp | kSpatialEntityTypeEntity
    );

    for (SpatialShard** shard = spatialView.shardBegin; shard != spatialView.shardEnd; ++shard) {
      if (*shard != nullptr) {
        SpatialShardData::FindInVolume(*shard, kAllRenderableTypes, volume, supportSelector, fadePlane, destination);
      }
    }

    SpatialShardData::FindInVolumeFromData(
      fadePlane,
      supportSelector,
      &spatialView.shardData,
      kAllRenderableTypes,
      volume,
      destination
    );
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x005041E0 (FUN_005041E0, Moho::SpatialDB_MeshInstance::CollectInView)
   *
   * What it does:
   * Collects entities intersecting camera view/fade lanes from child shards
   * and inline root shard-data lane.
   */
  std::int32_t SpatialDB_MeshInstance::CollectInView(
    GeomCamera3* const camera,
    gpg::fastvector<UserEntity*>& destination,
    const EEntityType type
  )
  {
    SpatialDbMeshCollectView& spatialView = AsSpatialDbMeshCollectView(*this);

    for (SpatialShard** shard = spatialView.shardBegin; shard != spatialView.shardEnd; ++shard) {
      if (*shard != nullptr) {
        CollectInViewFromShard(camera, destination, *shard, type);
      }
    }

    CollectInViewFromLeafData(destination, &spatialView.shardData, camera, type);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x007AE170 (FUN_007AE170)
   *
   * What it does:
   * Register-order adapter that forwards one mesh-instance view collection lane
   * through `SpatialDB_MeshInstance::CollectInView`.
   */
  [[maybe_unused]] std::int32_t CollectMeshInstanceInViewRegisterAdapter(
    SpatialDB_MeshInstance* const instance,
    const EEntityType type,
    gpg::fastvector<UserEntity*>& destination,
    GeomCamera3* const camera
  )
  {
    return instance->CollectInView(camera, destination, type);
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
    , mAuxTag0()
    , mAuxTag1()
    , mRuntimeFlag0(0)
    , mRuntimeFlag1(0)
    , mPad8E_8F{}
  {}

  /**
   * Address: 0x007DBFC0 (FUN_007DBFC0, ??1MeshMaterial@Moho@@UAE@XZ)
   * Deleting thunk: 0x007DBFA0 (FUN_007DBFA0)
   */
  MeshMaterial::~MeshMaterial()
  {
    mAuxTag1.tidy(true, 0U);
    mAuxTag0.tidy(true, 0U);
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
    mAuxTag0.assign_owned(rhs.mAuxTag0.view());
    mAuxTag1.assign_owned(rhs.mAuxTag1.view());
    mRuntimeFlag0 = rhs.mRuntimeFlag0;
    mRuntimeFlag1 = rhs.mRuntimeFlag1;
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
    MaybeRunExtraSoundWork();
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
    res = ResolveMeshResourceForLod(blueprintLod.mMeshName, ownerWatcher);
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
   * Address: 0x007E5B20 (FUN_007E5B20)
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
  void MeshInstance::SetCurrentInterpolant()
  {
    ++sFrameCounter;
    sCurrentInterpolant = REN_GetSimDeltaSeconds();
  }

  /**
   * Address: 0x007DE060 (FUN_007DE060,
   * ??0MeshInstance@Moho@@QAE@PAV?$SpatialDB@VMeshInstance@Moho@@@1@HIV?$shared_ptr@VMesh@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_N@Z)
   */
  MeshInstance::MeshInstance(
    const Wm3::Vec3f& scaleArg,
    void* const spatialDbStorage,
    const std::int32_t gameTickArg,
    const std::int32_t colorArg,
    const bool isStaticPoseArg,
    const boost::shared_ptr<Mesh> meshArg
  )
    : linkPrev(nullptr)
    , linkNext(nullptr)
    , db{nullptr, 0}
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
    , frameCounter(-1)
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
    MeshInstance::ListLink* const selfLink = MeshInstanceLink(this);
    linkPrev = selfLink;
    linkNext = selfLink;

    const boost::shared_ptr<const CAniSkel> skeleton = ResolveInitialPoseSkeleton(meshArg, isStaticPoseArg);
    curPose.reset(new CAniPose(skeleton, 1.0f));

    db.Register(spatialDbStorage, this, kMeshSpatialDbRoutingMask);
    const float dissolveCutoff = ComputeSpatialDissolveCutoff(meshArg);
    db.UpdateDissolveCutoff(dissolveCutoff);
  }

  /**
   * Address: 0x007DE550 (FUN_007DE550, ??1MeshInstance@Moho@@QAE@XZ)
   */
  MeshInstance::~MeshInstance()
  {
    curPose.reset();
    endPose.reset();
    startPose.reset();
    mesh.reset();
    db.ClearRegistration();
    RemoveLinkFromList(MeshInstanceLink(this));
  }

  /**
   * Address: 0x007DE510 (FUN_007DE510, deleting thunk)
   *
   * What it does:
   * Runs destructor and conditionally frees memory when low flag bit is set.
   */
  void MeshInstance::Release(const std::int32_t destroyNow)
  {
    if ((destroyNow & 0x01) != 0) {
      delete this;
      return;
    }

    this->~MeshInstance();
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
    frameCounter = static_cast<std::int8_t>(sFrameCounter);
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
    frameCounter = static_cast<std::int8_t>(sFrameCounter);
    currInterpolant = -1.0f;
    boundsValid = 1;
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

    frameCounter = static_cast<std::int8_t>(sFrameCounter);
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

    frameCounter = static_cast<std::int8_t>(sFrameCounter);
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

    // Keep interpolated pose-derived bounds coherent for immediate users.
    UpdateInterpolatedFields();
  }

  /**
   * Address: 0x007DEC80 (FUN_007DEC80, ?UpdateInterpolatedFields@MeshInstance@Moho@@ABEXXZ)
   *
   * What it does:
   * Recomputes interpolated transform fields for the current global
   * interpolant and refreshes fallback runtime bounds.
   */
  void MeshInstance::UpdateInterpolatedFields()
  {
    if (sCurrentInterpolant == currInterpolant) {
      return;
    }

    float interpolation = uniformScale * sCurrentInterpolant;
    interpolation = Clamp01(interpolation);
    currInterpolant = sCurrentInterpolant;
    interpolationStateFresh = 1;

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

    if (!HasFiniteWorldBounds(*this)) {
      UpdateFallbackWorldBounds(*this);
      return;
    }

    // When existing bounds are valid, keep size and recenter around the current
    // interpolated position. This mirrors the binary intent (bounds follow stance)
    // without requiring unrecovered mesh-resource box helpers.
    const float halfX = std::max(0.0f, (xMax - xMin) * 0.5f);
    const float halfY = std::max(0.0f, (yMax - yMin) * 0.5f);
    const float halfZ = std::max(0.0f, (zMax - zMin) * 0.5f);
    xMin = interpolatedPosition.x - halfX;
    xMax = interpolatedPosition.x + halfX;
    yMin = interpolatedPosition.y - halfY;
    yMax = interpolatedPosition.y + halfY;
    zMin = interpolatedPosition.z - halfZ;
    zMax = interpolatedPosition.z + halfZ;
    renderMinX = xMin;
    renderMinY = yMin;
    renderMinZ = zMin;
    renderMaxX = xMax;
    renderMaxY = yMax;
    renderMaxZ = zMax;

    const float radius = std::sqrt(halfX * halfX + halfY * halfY + halfZ * halfZ);
    sphere.Center = interpolatedPosition;
    sphere.Radius = radius;
    boundsValid = 1;

    // Refresh oriented `box` lane from the interpolated stance so renderer
    // and culling consumers always see a current OBB. Mirrors the binary
    // call into FUN_00472CF0 from UpdateInterpolatedFields/GetSweptAlignedBox.
    BuildOrientedBoxFromLocalAabb(
      curOrientation, interpolatedPosition, xMin, yMin, zMin, xMax, yMax, zMax, box
    );
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
    return static_cast<std::int32_t>(resource->mFile->mBoneCount);
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
    , meshCacheTree{nullptr, nullptr, 0}
    , dissolveTex()
    , meshEnvironmentTex()
    , anisotropiclookupTex()
    , insectlookupTex()
    , instanceListHead()
    , instanceListSize(0)
    , deltaFrame(0.0f)
    , instanceListStateFlags(0)
    , meshes{nullptr, nullptr, 0}
    , meshSpatialDb{nullptr, 0}
  {
    meshCacheTree.head = CreateMeshCacheTreeSentinel();
    meshes.head = CreateMeshBatchTreeSentinel();
    (void)UnlinkMeshInstanceListLink(&instanceListHead);
    gMeshRendererInstance = this;
  }

  /**
   * Address: 0x007DF330 (FUN_007DF330, ??1MeshRenderer@Moho@@QAE@XZ)
   */
  MeshRenderer::~MeshRenderer()
  {
    Reset();
    meshSpatialDb.ClearRegistration();
    DestroyMeshBatchTree(meshes);
    (void)UnlinkMeshInstanceListLink(&instanceListHead);
    DestroyMeshCacheTree(meshCacheTree);
    if (gMeshRendererInstance == this) {
      gMeshRendererInstance = nullptr;
    }
  }

  /**
   * Address: 0x007DF260 (FUN_007DF260, Moho::MeshRenderer::operator delete)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for mesh-renderer runtime lanes.
   */
  MeshRenderer* MeshRenderer::DeleteWithFlag(
    MeshRenderer* const object,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    if (object == nullptr) {
      return nullptr;
    }

    object->~MeshRenderer();
    if ((deleteFlags & 1u) != 0u) {
      operator delete(object);
    }

    return object;
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
    ResetLodBatchesForInstanceLinkList(instanceListHead);
    ResetMeshBatchTree(meshes);
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
    ResetLodBatchesForInstanceLinkList(instanceListHead);
    RemoveLinkFromList(&instanceListHead);
    ResetMeshBatchTree(meshes);
  }

  /**
   * Address: 0x007DF510 (FUN_007DF510, ?UpdateMapSize@MeshRenderer@Moho@@QAEXHH@Z)
   *
   * What it does:
   * Resizes renderer-owned mesh spatial-db storage for current map dimensions.
   */
  void MeshRenderer::UpdateMapSize(const std::int32_t width, const std::int32_t height)
  {
    meshSpatialDb.ResizeStorageForMap(width, height);
  }

  boost::shared_ptr<Mesh> MeshRenderer::FindOrCreateMesh(
    const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    MeshKey key(blueprint, materialArg);
    MeshRendererMeshCacheNode* const foundNode = MeshCacheTreeFind(meshCacheTree, key);
    if (foundNode) {
      return foundNode->entry.mesh;
    }

    boost::shared_ptr<Mesh> mesh(new Mesh(blueprint, materialArg));
    bool inserted = false;
    MeshRendererMeshCacheNode* const insertedNode = MeshCacheTreeInsertUnique(meshCacheTree, key, mesh, inserted);
    if (!insertedNode) {
      return {};
    }

    if (inserted || !insertedNode->entry.mesh) {
      insertedNode->entry.mesh = mesh;
    }

    return insertedNode->entry.mesh;
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

    if (lodBegin->mMeshName.empty()) {
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
    MeshInstance::ListLink* const instanceLink = MeshInstanceLink(instance);
    RemoveLinkFromList(instanceLink);
    InsertLinkBefore(&instanceListHead, instanceLink);
    return instance;
  }

  /**
   * Address: 0x007DFF30 (FUN_007DFF30, ?RenderCartographic@MeshRenderer@Moho@@QAEXMMMABVGeomCamera3@2@AAV?$map@...@Z)
   *
   * What it does:
   * Draws one mesh batch tree in cartographic mode.
   */
  void MeshRenderer::RenderCartographic(
    const float projectionScaleX,
    const float projectionScaleY,
    const float projectionScaleZ,
    const GeomCamera3& camera,
    MeshBatchBucketTree& meshMap
  )
  {
    (void)projectionScaleX;
    (void)projectionScaleY;
    (void)projectionScaleZ;
    (void)camera;
    (void)meshMap;
  }

  /**
   * Address: 0x007E03B0 (FUN_007E03B0, ?RenderDepth@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@AAV?$map@...@Z)
   *
   * What it does:
   * Draws one mesh batch tree into the active depth surface.
   */
  void MeshRenderer::RenderDepth(const GeomCamera3& camera, MeshBatchBucketTree& meshMap)
  {
    (void)camera;
    (void)meshMap;
  }

  /**
   * Address: 0x007E0C30 (FUN_007E0C30, Moho::MeshRenderer::Render)
   *
   * What it does:
   * Draws one mesh batch tree with optional shadow state.
   */
  void MeshRenderer::Render(
    const std::int32_t meshFlags,
    const GeomCamera3& camera,
    Shadow* const shadow,
    MeshBatchBucketTree& meshMap
  )
  {
    (void)meshFlags;
    (void)camera;
    (void)shadow;
    (void)meshMap;
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
   * Draws one mesh instance skeleton-debug overlay.
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
    (void)meshInstance;
    (void)showBoneNames;
  }

  /**
   * Address: 0x007E0380 (FUN_007E0380, ?RenderCartographic@MeshRenderer@Moho@@QAEXMMMABVGeomCamera3@2@@Z)
   *
   * What it does:
   * Forwards cartographic rendering to the batch-map overload using this
   * renderer's persistent `meshes` tree.
   */
  void MeshRenderer::RenderCartographic(
    const float projectionScaleX,
    const float projectionScaleY,
    const float projectionScaleZ,
    const GeomCamera3& camera
  )
  {
    RenderCartographic(projectionScaleX, projectionScaleY, projectionScaleZ, camera, meshes);
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
   * Renders one mesh instance with one thumbnail camera into caller-provided
   * color/depth targets.
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

    // Full draw-call/material state chain is still under active recovery.
    // Keep this typed seam so thumbnail paths can call the proper owner API.
    (void)camera;
    (void)meshInstance->GetMesh();
  }
} // namespace moho
