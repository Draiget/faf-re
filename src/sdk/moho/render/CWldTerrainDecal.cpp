#include "moho/render/CWldTerrainDecal.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>

#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/utils/Logging.h"
#include "moho/animation/CAnimTexture.h"
#include "moho/resource/IResources.h"
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

  /**
   * Address: 0x0089D970 (FUN_0089D970, sub_89D970)
   *
   * What it does:
   * Copies one 12-float terrain-decal quad lane (`4 x Vec3`) into the
   * destination slot and returns the destination pointer.
   */
  [[nodiscard]] moho::CWldTerrainDecal::Quad* CopyTerrainDecalQuad(
    moho::CWldTerrainDecal::Quad& destination, const moho::CWldTerrainDecal::Quad& source
  ) noexcept
  {
    destination.mCorner0 = source.mCorner0;
    destination.mCorner1 = source.mCorner1;
    destination.mCorner2 = source.mCorner2;
    destination.mCorner3 = source.mCorner3;
    return &destination;
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

  /**
   * Address: 0x0089C770 (FUN_0089C770)
   *
   * What it does:
   * Multiplies each XYZ axis lane in a 4x4 texture matrix by the provided
   * axis-scale vector.
   */
  void ApplyAxisScaleToTextureMatrix(moho::VMatrix4& matrix, const Wm3::Vec3f& axisScale) noexcept
  {
    matrix.r[0].x *= axisScale.x;
    matrix.r[0].y *= axisScale.y;
    matrix.r[0].z *= axisScale.z;
    matrix.r[1].x *= axisScale.x;
    matrix.r[1].y *= axisScale.y;
    matrix.r[1].z *= axisScale.z;
    matrix.r[2].x *= axisScale.x;
    matrix.r[2].y *= axisScale.y;
    matrix.r[2].z *= axisScale.z;
    matrix.r[3].x *= axisScale.x;
    matrix.r[3].y *= axisScale.y;
    matrix.r[3].z *= axisScale.z;
  }

  void ApplyInverseScaleToTextureMatrix(moho::VMatrix4& matrix, const Wm3::Vec3f& scale) noexcept
  {
    Wm3::Vec3f inverseScale{};
    inverseScale.x = 1.0f / scale.x;
    inverseScale.y = 1.0f / scale.y;
    inverseScale.z = 1.0f / scale.z;
    ApplyAxisScaleToTextureMatrix(matrix, inverseScale);
  }
} // namespace

namespace moho
{
  extern float ren_DecalAlbedoLodCutoff;
  extern float ren_DecalNormalLodCutoff;
  extern float ren_DecalFlatTol;
  extern float ren_DecalFadeFraction;

  msvc8::string CWldTerrainDecal::sTypeDesc[10] = {
    "Undefined",
    "Albedo",
    "Normals",
    "Water Mask",
    "Water Albedo",
    "Water Normals",
    "Glow",
    "Alpha Normals",
    "Glow Mask",
    "AlbedoXP",
  };

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
   * Address: 0x0089CF30 (FUN_0089CF30, ?DecalSave@CWldTerrainDecal@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
   * Mangled: ?DecalSave@CWldTerrainDecal@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
   *
   * What it does:
   * Writes decal persistence payload in binary order:
   * index, type, name-slot count + per-slot `(byteLen, bytes)`, then
   * scale/position/orientation, cutoff lanes, and terminal runtime token.
   */
  void CWldTerrainDecal::DecalSave(gpg::BinaryWriter& writer)
  {
    writer.Write(mIndex);

    const std::int32_t decalType = static_cast<std::int32_t>(mType);
    writer.Write(decalType);

    constexpr std::int32_t kNameSlotCount = 2;
    writer.Write(kNameSlotCount);

    for (std::int32_t slot = 0; slot < kNameSlotCount; ++slot) {
      const msvc8::string& name = mNames[slot];
      const std::int32_t nameByteLength = static_cast<std::int32_t>(name.size());
      writer.Write(nameByteLength);
      writer.Write(name.raw_data_unsafe(), static_cast<std::size_t>(nameByteLength));
    }

    writer.Write(reinterpret_cast<const char*>(&mScale), sizeof(mScale));
    writer.Write(reinterpret_cast<const char*>(&mPosition), sizeof(mPosition));
    writer.Write(reinterpret_cast<const char*>(&mOrientation), sizeof(mOrientation));
    writer.Write(mCutoffLOD);
    writer.Write(mNearCutoff);
    writer.Write(mUnknown9C);
  }

  /**
   * Address: 0x0089D190 (FUN_0089D190, ?LookupDecalType@CWldTerrainDecal@Moho@@SA?AW4TYPE@12@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   * Mangled: ?LookupDecalType@CWldTerrainDecal@Moho@@SA?AW4TYPE@12@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
   *
   * What it does:
   * Resolves one decal type enum from static descriptor text and warns when
   * caller input does not match any known descriptor lane.
   */
  EWldTerrainDecalType CWldTerrainDecal::LookupDecalType(const msvc8::string& typeDescription)
  {
    msvc8::string* const begin = &sTypeDesc[0];
    msvc8::string* const end = begin + 10;
    msvc8::string* const found = SearchStringArrayFor(begin, end, &typeDescription);
    if (found != end) {
      return static_cast<EWldTerrainDecalType>(found - begin);
    }

    gpg::Warnf("unknown decal type: %s", typeDescription.c_str());
    return WldTerrainDecalType_Undefined;
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
   * Address: 0x0089D310 (FUN_0089D310, ?SetHandle@CWldTerrainDecal@Moho@@QAEXH@Z)
   * Mangled: ?SetHandle@CWldTerrainDecal@Moho@@QAEXH@Z
   *
   * What it does:
   * Stores one runtime handle lane used by decal registration systems.
   */
  void CWldTerrainDecal::SetHandle(const int handle)
  {
    mRuntimeHandle = handle;
  }

  /**
   * Address: 0x0089D320 (FUN_0089D320, ?SetScale@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
   * Mangled: ?SetScale@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Stores scale lanes and tail-calls `Update` via the vtable slot.
   */
  void CWldTerrainDecal::SetScale(const Wm3::Vec3f& scale)
  {
    mScale = scale;
    Update();
  }

  /**
   * Address: 0x0089D340 (FUN_0089D340, ?SetPosition@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
   * Mangled: ?SetPosition@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Stores world-position lanes and tail-calls `Update` via the vtable slot.
   */
  void CWldTerrainDecal::SetPosition(const Wm3::Vec3f& position)
  {
    mPosition = position;
    Update();
  }

  /**
   * Address: 0x0089D360 (FUN_0089D360, ?SetOrientation@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
   * Mangled: ?SetOrientation@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Stores orientation lanes and tail-calls `Update` via the vtable slot.
   */
  void CWldTerrainDecal::SetOrientation(const Wm3::Vec3f& orientation)
  {
    mOrientation = orientation;
    Update();
  }

  /**
   * Address: 0x0089D380 (FUN_0089D380, ?SetParameters@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@00@Z)
   * Mangled: ?SetParameters@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@00@Z
   *
   * What it does:
   * Stores all transform lanes (scale/position/orientation) and tail-calls `Update`.
   */
  void CWldTerrainDecal::SetParameters(
    const Wm3::Vec3f& orientation,
    const Wm3::Vec3f& position,
    const Wm3::Vec3f& scale
  )
  {
    mScale = scale;
    mPosition = position;
    mOrientation = orientation;
    Update();
  }

  /**
   * Address: 0x0089D3E0 (FUN_0089D3E0, ?SetNearCutoffLOD@CWldTerrainDecal@Moho@@QAEXM@Z)
   * Mangled: ?SetNearCutoffLOD@CWldTerrainDecal@Moho@@QAEXM@Z
   *
   * What it does:
   * Clears near-cutoff fade to zero (argument is ignored by binary behavior).
   */
  void CWldTerrainDecal::SetNearCutoffLOD(const float nearCutoffLod)
  {
    (void)nearCutoffLod;
    mNearCutoff = 0.0f;
  }

  /**
   * Address: 0x0089D3F0 (FUN_0089D3F0, ?SetRemoveTick@CWldTerrainDecal@Moho@@QAEXH@Z)
   * Mangled: ?SetRemoveTick@CWldTerrainDecal@Moho@@QAEXH@Z
   *
   * What it does:
   * Stores one absolute remove-tick lane for lifetime scheduling.
   */
  void CWldTerrainDecal::SetRemoveTick(const int removeTick)
  {
    mRemoveTick = removeTick;
  }

  /**
   * Address: 0x0089DB50 (FUN_0089DB50, Moho::CWldTerrainDecal::GetTexture)
   *
   * What it does:
   * Samples one animated decal texture for `slot` using binary-equivalent frame
   * phase math and returns one retained texture-sheet handle.
   */
  boost::shared_ptr<ID3DTextureSheet>
  CWldTerrainDecal::GetTexture(const int slot, const float phaseOffset, const int frameSeed) const
  {
    CountedObject* const resource = mResourceRefs[slot].tex;
    if (resource == nullptr) {
      return {};
    }

    CAnimTexture::FrameRef frame{};
    const float framePhase = ((static_cast<float>(frameSeed) + phaseOffset) * mFadeDistance * 0.1f) + mUnknown94;
    static_cast<const CAnimTexture*>(resource)->GetFrameAt(frame, framePhase);
    return boost::SharedPtrFromRawRetained(frame);
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
   * Address: 0x0089D490 (FUN_0089D490, ?IsInside@CWldTerrainDecal@Moho@@QBE_NABV?$Vector2@M@Wm3@@@Z)
   * Mangled: ?IsInside@CWldTerrainDecal@Moho@@QBE_NABV?$Vector2@M@Wm3@@@Z
   *
   * What it does:
   * Applies inverse decal translation + yaw rotation + scale to a world-space
   * XZ point and returns true when the mapped UV lies in `[0, 1)` on both axes.
   */
  bool CWldTerrainDecal::IsInside(const Wm3::Vec2f& worldXZ) const
  {
    const float inverseYaw = -mOrientation.y;
    const float cosine = static_cast<float>(std::cos(inverseYaw));
    const float sine = static_cast<float>(std::sin(inverseYaw));

    const float normalizedX = (worldXZ.x - mPosition.x) * (1.0f / mScale.x);
    const float normalizedZ = (worldXZ.y - mPosition.z) * (1.0f / mScale.z);

    const float transformedV = (normalizedZ * cosine) + (normalizedX * sine);
    const float transformedU = (normalizedX * cosine) - (normalizedZ * sine);

    return transformedU >= 0.0f && transformedU < 1.0f && transformedV >= 0.0f && transformedV < 1.0f;
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

    (void)CopyTerrainDecalQuad(quad, mCachedFlatQuad);

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

      (void)CopyTerrainDecalQuad(quad, mCachedFlatQuad);
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
   * Address: 0x0089D400 (FUN_0089D400, Moho::CWldTerrainDecal::GetLODAlpha)
   *
   * What it does:
   * Computes one normalized alpha in `[0,1]` from either near-cutoff or
   * far-cutoff fade lanes.
   */
  float CWldTerrainDecal::GetLODAlpha(const float distance) const
  {
    if (mNearCutoff > 0.0f) {
      const float fadeBegin = mNearCutoff * ren_DecalFadeFraction;
      const float clampedDistance = std::clamp(distance, fadeBegin, mNearCutoff);
      return (clampedDistance - fadeBegin) / (mNearCutoff - fadeBegin);
    }

    const float fadeBegin = mCutoffLOD * ren_DecalFadeFraction;
    const float clampedDistance = std::clamp(distance, fadeBegin, mCutoffLOD);
    return 1.0f - ((clampedDistance - fadeBegin) / (mCutoffLOD - fadeBegin));
  }

  /**
   * Address: 0x0089DBB0 (FUN_0089DBB0, ?GetTextureMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z)
   * Mangled: ?GetTextureMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z
   *
   * What it does:
   * Returns the cached texture projection matrix.
   */
  VMatrix4 CWldTerrainDecal::GetTextureMatrix(const int slot, const float lod) const
  {
    (void)slot;
    (void)lod;
    return mTexMatrix;
  }

  /**
   * Address: 0x0089DBD0 (FUN_0089DBD0, ?GetTangentMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z)
   * Mangled: ?GetTangentMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z
   *
   * What it does:
   * Returns the cached tangent matrix.
   */
  VMatrix4 CWldTerrainDecal::GetTangentMatrix(const int slot, const float lod) const
  {
    (void)slot;
    (void)lod;
    return mTangentMatrix;
  }

  /**
   * Address: 0x0089DBF0 (FUN_0089DBF0, ?GetExtents@CWldTerrainDecal@Moho@@QBEXHMPAV?$Vector2@M@Wm3@@0@Z)
   * Mangled: ?GetExtents@CWldTerrainDecal@Moho@@QBEXHMPAV?$Vector2@M@Wm3@@0@Z
   *
   * What it does:
   * Writes current projected min/max extents in XZ space.
   */
  void CWldTerrainDecal::GetExtents(
    const int slot,
    const float lod,
    Wm3::Vec2f* const minOut,
    Wm3::Vec2f* const maxOut
  ) const
  {
    (void)slot;
    (void)lod;
    minOut->x = mBoundsMinX;
    minOut->y = mBoundsMinZ;
    maxOut->x = mBoundsMaxX;
    maxOut->y = mBoundsMaxZ;
  }

  /**
   * Address: 0x0089DC20 (FUN_0089DC20, ?GetCurrentAlpha@CWldTerrainDecal@Moho@@QBEMHM@Z)
   * Mangled: ?GetCurrentAlpha@CWldTerrainDecal@Moho@@QBEMHM@Z
   *
   * What it does:
   * Returns the current alpha lane.
   */
  float CWldTerrainDecal::GetCurrentAlpha(const int slot, const float lod) const
  {
    (void)slot;
    (void)lod;
    return mCurrentAlpha;
  }

  /**
   * Address: 0x0089DC30 (FUN_0089DC30, ?AdjustAlpha@CWldTerrainDecal@Moho@@QAEMMM@Z)
   * Mangled: ?AdjustAlpha@CWldTerrainDecal@Moho@@QAEMMM@Z
   *
   * What it does:
   * Adds/subtracts one delta from current alpha and clamps to the binary branch outcome.
   */
  float CWldTerrainDecal::AdjustAlpha(const float delta, const float lod)
  {
    (void)lod;

    const float originalAlpha = mCurrentAlpha;
    float upperCandidate = originalAlpha + delta;
    const float lowerCandidate = originalAlpha - delta;

    if (upperCandidate > 0.0f) {
      upperCandidate = 0.0f;
    }
    if (lowerCandidate > upperCandidate) {
      upperCandidate = lowerCandidate;
    }

    mCurrentAlpha = upperCandidate;
    return upperCandidate;
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

