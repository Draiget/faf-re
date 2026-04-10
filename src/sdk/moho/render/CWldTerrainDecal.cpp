#include "moho/render/CWldTerrainDecal.h"

#include <algorithm>
#include <cmath>
#include <cstddef>

#include "moho/animation/CAnimTexture.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace
{
  constexpr float kHeightWordScale = 0.0078125f;

  struct PlaneEquation
  {
    Wm3::Vec3f mNormal;
    float mDistance;
  };

  [[nodiscard]] const moho::CHeightField&
  GetTerrainHeightField(const moho::IWldTerrainRes& terrainRes) noexcept
  {
    const auto* const map = reinterpret_cast<const moho::STIMap*>(terrainRes.mPlayableRectSource);
    return *map->GetHeightField();
  }

  [[nodiscard]] int ClampHeightSampleIndex(const int coordinate, const int extent) noexcept
  {
    int clamped = extent - 1;
    if (coordinate < clamped) {
      clamped = coordinate;
    }
    if (clamped < 0) {
      clamped = 0;
    }
    return clamped;
  }

  [[nodiscard]] float SampleTerrainHeightWordScaled(const moho::CHeightField& field, const int x, const int z) noexcept
  {
    const int clampedX = ClampHeightSampleIndex(x, field.width);
    const int clampedZ = ClampHeightSampleIndex(z, field.height);
    return static_cast<float>(field.data[clampedX + clampedZ * field.width]) * kHeightWordScale;
  }

  [[nodiscard]] PlaneEquation BuildPlaneFromAnchor(
    const Wm3::Vec3f& anchor,
    const Wm3::Vec3f& edgePointA,
    const Wm3::Vec3f& edgePointB
  ) noexcept
  {
    const Wm3::Vec3f edgeA = Wm3::Vec3f::Sub(edgePointA, anchor);
    const Wm3::Vec3f edgeB = Wm3::Vec3f::Sub(edgePointB, anchor);

    Wm3::Vec3f normal = Wm3::Vec3f::Cross(edgeA, edgeB);
    (void)Wm3::Vec3f::Normalize(normal);

    return {normal, Wm3::Vec3f::Dot(normal, anchor)};
  }

  [[nodiscard]] float SignedPlaneDistance(
    const PlaneEquation& plane,
    const float x,
    const float y,
    const float z
  ) noexcept
  {
    return plane.mNormal.x * x + plane.mNormal.y * y + plane.mNormal.z * z - plane.mDistance;
  }

  void ReleaseTrackedCountedObjectPtr(moho::CountedPtr<moho::CountedObject>& ptr) noexcept
  {
    if (ptr.tex != nullptr) {
      ptr.tex->ReleaseReference();
      ptr.tex = nullptr;
    }
  }

  void SetTrackedCountedObjectPtr(
    moho::CountedPtr<moho::CountedObject>& slot,
    moho::CountedObject* const object
  ) noexcept
  {
    if (slot.tex == object) {
      return;
    }

    ReleaseTrackedCountedObjectPtr(slot);
    slot.tex = object;
    if (slot.tex != nullptr) {
      slot.tex->AddReference();
    }
  }

  [[nodiscard]] moho::VMatrix4 RotationAxisX(const float angle) noexcept
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);

    moho::VMatrix4 out = moho::VMatrix4::Identity();
    out.r[1].y = c;
    out.r[1].z = s;
    out.r[2].y = -s;
    out.r[2].z = c;
    return out;
  }

  [[nodiscard]] moho::VMatrix4 RotationAxisY(const float angle) noexcept
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);

    moho::VMatrix4 out = moho::VMatrix4::Identity();
    out.r[0].x = c;
    out.r[0].z = s;
    out.r[2].x = -s;
    out.r[2].z = c;
    return out;
  }

  [[nodiscard]] moho::VMatrix4 RotationAxisZ(const float angle) noexcept
  {
    const float c = std::cos(angle);
    const float s = std::sin(angle);

    moho::VMatrix4 out = moho::VMatrix4::Identity();
    out.r[0].x = c;
    out.r[0].y = s;
    out.r[1].x = -s;
    out.r[1].y = c;
    return out;
  }

  void ProjectDecalBoundsXZ(
    const Wm3::Vec3f& position,
    const Wm3::Vec3f& scale,
    const Wm3::Vec3f& orientation,
    float& outMaxX,
    float& outMaxZ,
    float& outMinX,
    float& outMinZ
  ) noexcept
  {
    const float c = std::cos(orientation.y);
    const float s = std::sin(orientation.y);

    const float xAxisX = scale.x * c;
    const float xAxisZ = scale.x * s;
    const float zAxisX = -(scale.z * s);
    const float zAxisZ = scale.z * c;

    const float minXOffset = std::min({0.0f, xAxisX, zAxisX, xAxisX + zAxisX});
    const float minZOffset = std::min({0.0f, xAxisZ, zAxisZ, xAxisZ + zAxisZ});
    const float maxXOffset = std::max({0.0f, xAxisX, zAxisX, xAxisX + zAxisX});
    const float maxZOffset = std::max({0.0f, xAxisZ, zAxisZ, xAxisZ + zAxisZ});

    outMinX = position.x + minXOffset;
    outMinZ = position.z + minZOffset;
    outMaxX = position.x + maxXOffset;
    outMaxZ = position.z + maxZOffset;
  }

  void ApplyInverseScaleToTextureMatrix(moho::VMatrix4& matrix, const Wm3::Vec3f& scale) noexcept
  {
    const float inverseScaleX = 1.0f / scale.x;
    const float inverseScaleY = 1.0f / scale.y;
    const float inverseScaleZ = 1.0f / scale.z;

    matrix.r[0].x *= inverseScaleX;
    matrix.r[0].y *= inverseScaleY;
    matrix.r[0].z *= inverseScaleZ;
    matrix.r[1].x *= inverseScaleX;
    matrix.r[1].y *= inverseScaleY;
    matrix.r[1].z *= inverseScaleZ;
    matrix.r[2].x *= inverseScaleX;
    matrix.r[2].y *= inverseScaleY;
    matrix.r[2].z *= inverseScaleZ;
    matrix.r[3].x *= inverseScaleX;
    matrix.r[3].y *= inverseScaleY;
    matrix.r[3].z *= inverseScaleZ;
  }
} // namespace

namespace moho
{
  extern float ren_DecalAlbedoLodCutoff;
  extern float ren_DecalNormalLodCutoff;
  extern float ren_DecalFlatTol;

  /**
   * Address: 0x0089CA60 (FUN_0089CA60, Moho::CWldTerrainDecal::CWldTerrainDecal)
   *
   * What it does:
   * Seeds the terrain-decal defaults, registers the decal into the spatial
   * database, and initializes the default scale/position/orientation lanes.
   */
  CWldTerrainDecal::CWldTerrainDecal(SpatialDB_MeshInstance* const spatialDbOwner, IWldTerrainRes* const terrainRes)
    : mLinkHead(nullptr)
    , mTerrainRes(terrainRes)
    , mEntry{}
    , mVecIndex(0)
    , mIndex(0)
    , mType(WldTerrainDecalType_Undefined)
    , mRuntimeActive(1)
    , mPad21_23{0, 0, 0}
    , mNames{}
    , mScale{8.0f, 8.0f, 8.0f}
    , mPosition{}
    , mOrientation{}
    , mCutoffLOD(0.0f)
    , mNearCutoff(0.0f)
    , mRemoveTick(0)
    , mCurrentAlpha(1.0f)
    , mFadeDistance(5.0f)
    , mUnknown94(0.0f)
    , mRuntimeHandle(0)
    , mUnknown9C(-1)
    , mUnknownA0(0)
    , mPadA1_A3{0, 0, 0}
    , mResourceRefs{}
    , mTexMatrix{}
    , mTangentMatrix{}
    , mBoundsMinX(0.0f)
    , mBoundsMinZ(0.0f)
    , mBoundsMaxX(0.0f)
    , mBoundsMaxZ(0.0f)
    , mFlatOptimizationEnabled(1)
    , mFlatnessCacheValid(0)
    , mCachedFlatResult(0)
    , mPad13F(0)
    , mCachedFlatQuad{}
  {
    mEntry.Register(spatialDbOwner, this, 0x800);
  }

  /**
   * Address: 0x0089CBB0 (FUN_0089CBB0, Moho::CWldTerrainDecal::dtr)
   * Address: 0x0089CBF0 (FUN_0089CBF0, Moho::CWldTerrainDecal::~CWldTerrainDecal body)
   *
   * What it does:
   * Releases the counted runtime reference lanes and clears spatial-db
   * registration before object teardown.
   */
  CWldTerrainDecal::~CWldTerrainDecal()
  {
    for (std::size_t index = 2; index > 0; --index) {
      ReleaseTrackedCountedObjectPtr(mResourceRefs[index - 1]);
    }

    mEntry.ClearRegistration();

    while (mLinkHead != nullptr) {
      CWldTerrainDecalLink* const nextLink = mLinkHead->mNext;
      mLinkHead->mPrev = nullptr;
      mLinkHead->mNext = nullptr;
      mLinkHead = nextLink;
    }
  }

  /**
   * Address: 0x0089C890 (FUN_0089C890, Moho::CWldTerrainDecal::EnableFlatOptimization)
   *
   * What it does:
   * Stores one per-decal flat-optimization enable flag at +0x13C.
   */
  void CWldTerrainDecal::EnableFlatOptimization(const bool enabled)
  {
    mFlatOptimizationEnabled = static_cast<std::uint8_t>(enabled ? 1u : 0u);
  }

  /**
   * Address: 0x0089D1F0 (FUN_0089D1F0, Moho::CWldTerrainDecal::SetName)
   *
   * What it does:
   * Writes one name lane and refreshes the matching counted texture reference.
   */
  void CWldTerrainDecal::SetName(const msvc8::string& name, const int slot)
  {
    mNames[slot] = name;

    if (!mNames[slot].empty()) {
      CAnimTexture* const texture = CAnimTexture::FindOrCreate(mNames[slot].c_str());
      SetTrackedCountedObjectPtr(mResourceRefs[slot], texture);
      if (texture != nullptr) {
        texture->ReleaseReference();
      }
      return;
    }

    ReleaseTrackedCountedObjectPtr(mResourceRefs[slot]);
  }

  /**
   * Address: 0x0089D9C0 (FUN_0089D9C0, Moho::CWldTerrainDecal::ComputeCorner)
   *
   * What it does:
   * Projects one local corner into XZ world space using current yaw/scale.
   */
  Wm3::Vec2f CWldTerrainDecal::ComputeCorner(const Wm3::Vec2f& corner) const
  {
    const float angle = mOrientation.y;
    const float cosAngle = static_cast<float>(std::cos(angle));
    const float sinAngle = static_cast<float>(std::sin(angle));

    Wm3::Vec2f out{};
    out.x =
      (mPosition.x + (corner.y * (-mScale.z * sinAngle)))
      + (corner.x * (mScale.x * cosAngle));
    out.y =
      (mPosition.z + (corner.y * (mScale.z * cosAngle)))
      + (corner.x * (mScale.x * sinAngle));
    return out;
  }

  /**
   * Address: 0x0089D560 (FUN_0089D560, Moho::CWldTerrainDecal::ComputeFlatness)
   *
   * What it does:
   * Reuses or rebuilds one cached terrain-sampled corner quad and tests all
   * covered heightfield samples against the fitted plane tolerance.
   */
  bool CWldTerrainDecal::ComputeFlatness(Quad& quad)
  {
    if (mFlatOptimizationEnabled == 0) {
      return false;
    }

    quad = mCachedFlatQuad;

    if (mFlatnessCacheValid == 0 && mTerrainRes != nullptr) {
      const CHeightField& field = GetTerrainHeightField(*mTerrainRes);
      const float flatToleranceSquared = ren_DecalFlatTol * ren_DecalFlatTol;

      const int minX = static_cast<int>(std::floor(mBoundsMinX));
      const int minZ = static_cast<int>(std::floor(mBoundsMinZ));
      const int maxX = static_cast<int>(std::ceil(mBoundsMaxX));
      const int maxZ = static_cast<int>(std::ceil(mBoundsMaxZ));

      mCachedFlatQuad.mCorner0 = {
        static_cast<float>(minX),
        SampleTerrainHeightWordScaled(field, minX, maxZ),
        static_cast<float>(maxZ)
      };
      mCachedFlatQuad.mCorner1 = {
        static_cast<float>(minX),
        SampleTerrainHeightWordScaled(field, minX, minZ),
        static_cast<float>(minZ)
      };
      mCachedFlatQuad.mCorner2 = {
        static_cast<float>(maxX),
        SampleTerrainHeightWordScaled(field, maxX, maxZ),
        static_cast<float>(maxZ)
      };
      mCachedFlatQuad.mCorner3 = {
        static_cast<float>(maxX),
        SampleTerrainHeightWordScaled(field, maxX, minZ),
        static_cast<float>(minZ)
      };

      const PlaneEquation plane = BuildPlaneFromAnchor(
        mCachedFlatQuad.mCorner0,
        mCachedFlatQuad.mCorner2,
        mCachedFlatQuad.mCorner1
      );

      const auto isInsideTolerance = [&](const float x, const float y, const float z) noexcept -> bool {
        const float signedDistance = SignedPlaneDistance(plane, x, y, z);
        return flatToleranceSquared > (signedDistance * signedDistance);
      };

      bool isFlat = isInsideTolerance(
        mCachedFlatQuad.mCorner3.x,
        mCachedFlatQuad.mCorner3.y,
        mCachedFlatQuad.mCorner3.z
      );

      for (int sampleX = minX; isFlat && sampleX <= maxX; ++sampleX) {
        for (int sampleZ = minZ; isFlat && sampleZ <= maxZ; ++sampleZ) {
          const float sampleHeight = SampleTerrainHeightWordScaled(field, sampleX, sampleZ);
          isFlat = isInsideTolerance(static_cast<float>(sampleX), sampleHeight, static_cast<float>(sampleZ));
        }
      }

      mCachedFlatResult = static_cast<std::uint8_t>(isFlat ? 1u : 0u);

      mCachedFlatQuad.mCorner0.y += ren_DecalFlatTol;
      mCachedFlatQuad.mCorner1.y += ren_DecalFlatTol;
      mCachedFlatQuad.mCorner2.y += ren_DecalFlatTol;
      mCachedFlatQuad.mCorner3.y += ren_DecalFlatTol;

      quad = mCachedFlatQuad;
      mFlatnessCacheValid = 1;
    }

    return mCachedFlatResult != 0;
  }

  /**
   * Address: 0x0089DA80 (FUN_0089DA80, Moho::CWldTerrainDecal::ComputeCutoffLOD)
   *
   * What it does:
   * Returns one distance-scaled cutoff metric using decal extents and type lane.
   */
  float CWldTerrainDecal::ComputeCutoffLOD(const float distance) const
  {
    const float extentX = mBoundsMaxX - mBoundsMinX;
    const float extentY = mBoundsMaxZ - mBoundsMinZ;
    const float diagonal = static_cast<float>(std::sqrt((extentX * extentX) + (extentY * extentY)));

    if (distance > 0.0f) {
      return diagonal * distance;
    }

    if (
      mType == WldTerrainDecalType_Albedo
      || mType == WldTerrainDecalType_WaterAlbedo
      || mType == WldTerrainDecalType_GlowMask
    ) {
      return diagonal * ren_DecalAlbedoLodCutoff;
    }

    return diagonal * ren_DecalNormalLodCutoff;
  }

  /**
   * Address: 0x0089D3C0 (FUN_0089D3C0, Moho::CWldTerrainDecal::SetCutoffLOD)
   *
   * What it does:
   * Stores one explicit cutoff-lod scalar and updates spatial-db dissolve sort key.
   */
  void CWldTerrainDecal::SetCutoffLOD(const float cutoffLod)
  {
    mCutoffLOD = cutoffLod;
    mEntry.UpdateDissolveCutoff(cutoffLod);
  }

  /**
   * Address: 0x0089DC70 (FUN_0089DC70, Moho::CWldTerrainDecal::Update)
   *
   * What it does:
   * Recomputes texture/tangent transforms, refreshes projected world bounds, and
   * updates spatial-db dissolve/bounds lanes for this decal frame.
   */
  void CWldTerrainDecal::Update()
  {
    ProjectDecalBoundsXZ(
      mPosition,
      mScale,
      mOrientation,
      mBoundsMaxX,
      mBoundsMaxZ,
      mBoundsMinX,
      mBoundsMinZ
    );

    mTexMatrix = VMatrix4::Identity();
    mTexMatrix.r[3].x = -mPosition.x;
    mTexMatrix.r[3].y = -mPosition.y;
    mTexMatrix.r[3].z = -mPosition.z;

    mTexMatrix = VMatrix4::Multiply(mTexMatrix, RotationAxisY(mOrientation.y));
    mTexMatrix = VMatrix4::Multiply(mTexMatrix, RotationAxisX(mOrientation.x));
    mTexMatrix = VMatrix4::Multiply(mTexMatrix, RotationAxisZ(mOrientation.z));

    ApplyInverseScaleToTextureMatrix(mTexMatrix, mScale);

    mTangentMatrix = RotationAxisY(mOrientation.y);

    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = mBoundsMinX;
    bounds.Max.x = mBoundsMaxX;
    bounds.Min.y = 0.0f;
    bounds.Max.y = 128.0f;
    bounds.Min.z = mBoundsMinZ;
    bounds.Max.z = mBoundsMaxZ;

    mEntry.UpdateDissolveCutoff(mCutoffLOD);
    mEntry.UpdateBounds(bounds);

    mFlatnessCacheValid = 0;
    mCachedFlatResult = 0;
  }
} // namespace moho
