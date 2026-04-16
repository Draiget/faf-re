#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/math/VMatrix4.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/CountedObject.h"
#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  class ID3DTextureSheet;
  class IWldTerrainRes;
}

namespace gpg
{
  class BinaryWriter;
}

namespace moho
{

  struct CWldTerrainDecalLink
  {
    CWldTerrainDecalLink* mPrev; // +0x00
    CWldTerrainDecalLink* mNext; // +0x04
  };
  static_assert(sizeof(CWldTerrainDecalLink) == 0x08, "CWldTerrainDecalLink size must be 0x08");

  /**
   * Terrain-decal base object recovered from the Moho render runtime.
   */
  class CWldTerrainDecal
  {
  public:
    /**
     * Address: 0x0089D190 (FUN_0089D190, ?LookupDecalType@CWldTerrainDecal@Moho@@SA?AW4TYPE@12@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     * Mangled: ?LookupDecalType@CWldTerrainDecal@Moho@@SA?AW4TYPE@12@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
     *
     * What it does:
     * Resolves one decal type enum from the static decal-type descriptor table
     * and warns when the descriptor text is unknown.
     */
    [[nodiscard]] static EWldTerrainDecalType LookupDecalType(const msvc8::string& typeDescription);

    struct Quad
    {
      Wm3::Vec3f mCorner0; // +0x00
      Wm3::Vec3f mCorner1; // +0x0C
      Wm3::Vec3f mCorner2; // +0x18
      Wm3::Vec3f mCorner3; // +0x24
    };

    /**
     * Address: 0x0089CA60 (FUN_0089CA60, Moho::CWldTerrainDecal::CWldTerrainDecal)
     *
     * What it does:
     * Seeds the terrain-decal defaults, registers the decal into the spatial
     * database, and initializes the default scale/position/orientation lanes.
     */
    CWldTerrainDecal(SpatialDB_MeshInstance* spatialDbOwner, IWldTerrainRes* terrainRes);

    /**
     * Address: 0x0089CBB0 (FUN_0089CBB0, Moho::CWldTerrainDecal::dtr)
     * Address: 0x0089CBF0 (FUN_0089CBF0, Moho::CWldTerrainDecal::~CWldTerrainDecal body)
     *
     * What it does:
     * Releases the counted runtime reference lanes and clears spatial-db
     * registration before object teardown.
     */
    virtual ~CWldTerrainDecal();

    /**
     * Address: 0x0089CF30 (FUN_0089CF30, ?DecalSave@CWldTerrainDecal@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     * Mangled: ?DecalSave@CWldTerrainDecal@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
     *
     * What it does:
     * Serializes decal runtime payload to the binary writer in engine save
     * order (index/type/name slots/transforms/lod lanes).
     */
    void DecalSave(gpg::BinaryWriter& writer);

    /**
     * Address: 0x0089D1F0 (Moho::CWldTerrainDecal::SetName)
     *
     * What it does:
     * Updates the decal's named texture lanes and per-slot name metadata.
     */
    virtual void SetName(const msvc8::string& name, int slot);

    /**
     * Address: 0x0089D310 (FUN_0089D310, ?SetHandle@CWldTerrainDecal@Moho@@QAEXH@Z)
     * Mangled: ?SetHandle@CWldTerrainDecal@Moho@@QAEXH@Z
     *
     * What it does:
     * Stores one runtime handle lane used by decal registration systems.
     */
    void SetHandle(int handle);

    /**
     * Address: 0x0089D320 (FUN_0089D320, ?SetScale@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     * Mangled: ?SetScale@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
     *
     * What it does:
     * Updates world scale and immediately refreshes derived bounds/transforms.
     */
    void SetScale(const Wm3::Vec3f& scale);

    /**
     * Address: 0x0089D340 (FUN_0089D340, ?SetPosition@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     * Mangled: ?SetPosition@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
     *
     * What it does:
     * Updates world position and immediately refreshes derived bounds/transforms.
     */
    void SetPosition(const Wm3::Vec3f& position);

    /**
     * Address: 0x0089D360 (FUN_0089D360, ?SetOrientation@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     * Mangled: ?SetOrientation@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
     *
     * What it does:
     * Updates orientation euler lanes and immediately refreshes derived transforms.
     */
    void SetOrientation(const Wm3::Vec3f& orientation);

    /**
     * Address: 0x0089D380 (FUN_0089D380, ?SetParameters@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@00@Z)
     * Mangled: ?SetParameters@CWldTerrainDecal@Moho@@QAEXABV?$Vector3@M@Wm3@@00@Z
     *
     * What it does:
     * Stores orientation/position/scale lanes in one pass, then refreshes decal state.
     */
    void SetParameters(
      const Wm3::Vec3f& orientation,
      const Wm3::Vec3f& position,
      const Wm3::Vec3f& scale
    );

    /**
     * Address: 0x0089D3E0 (FUN_0089D3E0, ?SetNearCutoffLOD@CWldTerrainDecal@Moho@@QAEXM@Z)
     * Mangled: ?SetNearCutoffLOD@CWldTerrainDecal@Moho@@QAEXM@Z
     *
     * What it does:
     * Clears near-cutoff fade to zero (input argument is ignored by binary logic).
     */
    void SetNearCutoffLOD(float nearCutoffLod);

    /**
     * Address: 0x0089D3F0 (FUN_0089D3F0, ?SetRemoveTick@CWldTerrainDecal@Moho@@QAEXH@Z)
     * Mangled: ?SetRemoveTick@CWldTerrainDecal@Moho@@QAEXH@Z
     *
     * What it does:
     * Stores one absolute remove-tick lane used by lifetime scheduling.
     */
    void SetRemoveTick(int removeTick);

    /**
     * Address: 0x0089DB50 (FUN_0089DB50, Moho::CWldTerrainDecal::GetTexture)
     *
     * What it does:
     * Resolves one animated decal texture lane by slot using frame phase
     * `(frameSeed + phaseOffset) * mFadeDistance * 0.1 + mUnknown94`, and
     * returns one retained texture-sheet handle.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet>
      GetTexture(int slot, float phaseOffset, int frameSeed) const;

    /**
     * Address: 0x0089D9C0 (Moho::CWldTerrainDecal::ComputeCorner)
     *
     * What it does:
     * Projects one decal corner in world space.
     */
    virtual Wm3::Vec2f ComputeCorner(const Wm3::Vec2f& corner) const;

    /**
     * Address: 0x0089D490 (FUN_0089D490, ?IsInside@CWldTerrainDecal@Moho@@QBE_NABV?$Vector2@M@Wm3@@@Z)
     * Mangled: ?IsInside@CWldTerrainDecal@Moho@@QBE_NABV?$Vector2@M@Wm3@@@Z
     *
     * What it does:
     * Tests whether one world-space XZ point falls inside this decal's unit
     * local `[0, 1)` footprint.
     */
    [[nodiscard]] bool IsInside(const Wm3::Vec2f& worldXZ) const;

    /**
     * Address: 0x0089C890 (Moho::CWldTerrainDecal::EnableFlatOptimization)
     *
     * What it does:
     * Toggles flatness optimization for this decal lane.
     */
    virtual void EnableFlatOptimization(bool enabled);

    /**
     * Address: 0x0089D560 (Moho::CWldTerrainDecal::ComputeFlatness)
     *
     * What it does:
     * Evaluates whether one quad is flat enough to keep the current LOD.
     */
    virtual bool ComputeFlatness(Quad& quad);

    /**
     * Address: 0x0089DA80 (Moho::CWldTerrainDecal::ComputeCutoffLOD)
     *
     * What it does:
     * Computes the distance-based cutoff LOD for the decal.
     */
    virtual float ComputeCutoffLOD(float distance) const;
    /**
     * Address: 0x0089D400 (FUN_0089D400, Moho::CWldTerrainDecal::GetLODAlpha)
     *
     * What it does:
     * Computes distance-fade alpha against either near-cutoff or far-cutoff
     * lanes using `ren_DecalFadeFraction`.
     */
    [[nodiscard]] float GetLODAlpha(float distance) const;

    /**
     * Address: 0x0089DBB0 (FUN_0089DBB0, ?GetTextureMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z)
     * Mangled: ?GetTextureMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z
     *
     * What it does:
     * Returns the current texture matrix snapshot.
     */
    [[nodiscard]] VMatrix4 GetTextureMatrix(int slot, float lod) const;

    /**
     * Address: 0x0089DBD0 (FUN_0089DBD0, ?GetTangentMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z)
     * Mangled: ?GetTangentMatrix@CWldTerrainDecal@Moho@@QBE?AUVMatrix4@2@HM@Z
     *
     * What it does:
     * Returns the current tangent matrix snapshot.
     */
    [[nodiscard]] VMatrix4 GetTangentMatrix(int slot, float lod) const;

    /**
     * Address: 0x0089DBF0 (FUN_0089DBF0, ?GetExtents@CWldTerrainDecal@Moho@@QBEXHMPAV?$Vector2@M@Wm3@@0@Z)
     * Mangled: ?GetExtents@CWldTerrainDecal@Moho@@QBEXHMPAV?$Vector2@M@Wm3@@0@Z
     *
     * What it does:
     * Writes current projected XZ min/max extents to output vectors.
     */
    void GetExtents(int slot, float lod, Wm3::Vec2f* minOut, Wm3::Vec2f* maxOut) const;

    /**
     * Address: 0x0089DC20 (FUN_0089DC20, ?GetCurrentAlpha@CWldTerrainDecal@Moho@@QBEMHM@Z)
     * Mangled: ?GetCurrentAlpha@CWldTerrainDecal@Moho@@QBEMHM@Z
     *
     * What it does:
     * Returns the current decal alpha lane.
     */
    [[nodiscard]] float GetCurrentAlpha(int slot, float lod) const;

    /**
     * Address: 0x0089DC30 (FUN_0089DC30, ?AdjustAlpha@CWldTerrainDecal@Moho@@QAEMMM@Z)
     * Mangled: ?AdjustAlpha@CWldTerrainDecal@Moho@@QAEMMM@Z
     *
     * What it does:
     * Adjusts alpha by one signed delta and clamps against `[mCurrentAlpha-delta, 0]`.
     */
    float AdjustAlpha(float delta, float lod);

    /**
     * Address: 0x0089D3C0 (FUN_0089D3C0, Moho::CWldTerrainDecal::SetCutoffLOD)
     *
     * What it does:
     * Stores one explicit cutoff-lod scalar and updates spatial-db dissolve sort key.
     */
    void SetCutoffLOD(float cutoffLod);

    /**
     * Address: 0x0089DC70 (Moho::CWldTerrainDecal::Update)
     *
     * What it does:
     * Advances runtime decal state for the current frame.
     */
    virtual void Update();

    static msvc8::string sTypeDesc[10];

  public:
    CWldTerrainDecalLink* mLinkHead;           // +0x04
    IWldTerrainRes* mTerrainRes;               // +0x08
    SpatialDB_MeshInstance mEntry;             // +0x0C
    std::uint32_t mVecIndex;                   // +0x14
    std::int32_t mIndex;                       // +0x18
    EWldTerrainDecalType mType;                // +0x1C
    std::uint8_t mRuntimeActive;               // +0x20
    std::uint8_t mPad21_23[0x03];              // +0x21
    msvc8::string mNames[2];                   // +0x24
    Wm3::Vec3f mScale;                         // +0x5C
    Wm3::Vec3f mPosition;                      // +0x68
    Wm3::Vec3f mOrientation;                   // +0x74
    float mCutoffLOD;                          // +0x80
    float mNearCutoff;                         // +0x84
    std::int32_t mRemoveTick;                  // +0x88
    float mCurrentAlpha;                       // +0x8C
    float mFadeDistance;                       // +0x90
    float mUnknown94;                          // +0x94
    std::int32_t mRuntimeHandle;               // +0x98
    std::int32_t mUnknown9C;                   // +0x9C
    std::uint8_t mUnknownA0;                   // +0xA0
    std::uint8_t mPadA1_A3[0x03];              // +0xA1
    CountedPtr<CountedObject> mResourceRefs[2]; // +0xA4
    VMatrix4 mTexMatrix;                       // +0xAC
    VMatrix4 mTangentMatrix;                   // +0xEC
    float mBoundsMinX;                         // +0x12C
    float mBoundsMinZ;                         // +0x130
    float mBoundsMaxX;                         // +0x134
    float mBoundsMaxZ;                         // +0x138
    std::uint8_t mFlatOptimizationEnabled;     // +0x13C
    std::uint8_t mFlatnessCacheValid;          // +0x13D
    std::uint8_t mCachedFlatResult;            // +0x13E
    std::uint8_t mPad13F;                      // +0x13F
    Quad mCachedFlatQuad;                      // +0x140
  };

  static_assert(offsetof(CWldTerrainDecal, mLinkHead) == 0x04, "CWldTerrainDecal::mLinkHead offset must be 0x04");
  static_assert(offsetof(CWldTerrainDecal, mTerrainRes) == 0x08, "CWldTerrainDecal::mTerrainRes offset must be 0x08");
  static_assert(offsetof(CWldTerrainDecal, mEntry) == 0x0C, "CWldTerrainDecal::mEntry offset must be 0x0C");
  static_assert(offsetof(CWldTerrainDecal, mVecIndex) == 0x14, "CWldTerrainDecal::mVecIndex offset must be 0x14");
  static_assert(offsetof(CWldTerrainDecal, mIndex) == 0x18, "CWldTerrainDecal::mIndex offset must be 0x18");
  static_assert(offsetof(CWldTerrainDecal, mType) == 0x1C, "CWldTerrainDecal::mType offset must be 0x1C");
  static_assert(offsetof(CWldTerrainDecal, mRuntimeActive) == 0x20, "CWldTerrainDecal::mRuntimeActive offset must be 0x20");
  static_assert(offsetof(CWldTerrainDecal, mNames) == 0x24, "CWldTerrainDecal::mNames offset must be 0x24");
  static_assert(offsetof(CWldTerrainDecal, mScale) == 0x5C, "CWldTerrainDecal::mScale offset must be 0x5C");
  static_assert(offsetof(CWldTerrainDecal, mPosition) == 0x68, "CWldTerrainDecal::mPosition offset must be 0x68");
  static_assert(offsetof(CWldTerrainDecal, mOrientation) == 0x74, "CWldTerrainDecal::mOrientation offset must be 0x74");
  static_assert(offsetof(CWldTerrainDecal, mCutoffLOD) == 0x80, "CWldTerrainDecal::mCutoffLOD offset must be 0x80");
  static_assert(offsetof(CWldTerrainDecal, mNearCutoff) == 0x84, "CWldTerrainDecal::mNearCutoff offset must be 0x84");
  static_assert(offsetof(CWldTerrainDecal, mRemoveTick) == 0x88, "CWldTerrainDecal::mRemoveTick offset must be 0x88");
  static_assert(
    offsetof(CWldTerrainDecal, mCurrentAlpha) == 0x8C, "CWldTerrainDecal::mCurrentAlpha offset must be 0x8C"
  );
  static_assert(offsetof(CWldTerrainDecal, mFadeDistance) == 0x90, "CWldTerrainDecal::mFadeDistance offset must be 0x90");
  static_assert(offsetof(CWldTerrainDecal, mUnknown94) == 0x94, "CWldTerrainDecal::mUnknown94 offset must be 0x94");
  static_assert(offsetof(CWldTerrainDecal, mRuntimeHandle) == 0x98, "CWldTerrainDecal::mRuntimeHandle offset must be 0x98");
  static_assert(offsetof(CWldTerrainDecal, mUnknown9C) == 0x9C, "CWldTerrainDecal::mUnknown9C offset must be 0x9C");
  static_assert(offsetof(CWldTerrainDecal, mUnknownA0) == 0xA0, "CWldTerrainDecal::mUnknownA0 offset must be 0xA0");
  static_assert(offsetof(CWldTerrainDecal, mResourceRefs) == 0xA4, "CWldTerrainDecal::mResourceRefs offset must be 0xA4");
  static_assert(offsetof(CWldTerrainDecal, mTexMatrix) == 0xAC, "CWldTerrainDecal::mTexMatrix offset must be 0xAC");
  static_assert(
    offsetof(CWldTerrainDecal, mTangentMatrix) == 0xEC, "CWldTerrainDecal::mTangentMatrix offset must be 0xEC"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mBoundsMinX) == 0x12C,
    "CWldTerrainDecal::mBoundsMinX offset must be 0x12C"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mBoundsMinZ) == 0x130,
    "CWldTerrainDecal::mBoundsMinZ offset must be 0x130"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mBoundsMaxX) == 0x134,
    "CWldTerrainDecal::mBoundsMaxX offset must be 0x134"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mBoundsMaxZ) == 0x138,
    "CWldTerrainDecal::mBoundsMaxZ offset must be 0x138"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mFlatOptimizationEnabled) == 0x13C,
    "CWldTerrainDecal::mFlatOptimizationEnabled offset must be 0x13C"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mFlatnessCacheValid) == 0x13D,
    "CWldTerrainDecal::mFlatnessCacheValid offset must be 0x13D"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mCachedFlatResult) == 0x13E,
    "CWldTerrainDecal::mCachedFlatResult offset must be 0x13E"
  );
  static_assert(
    offsetof(CWldTerrainDecal, mCachedFlatQuad) == 0x140,
    "CWldTerrainDecal::mCachedFlatQuad offset must be 0x140"
  );

  static_assert(sizeof(CWldTerrainDecal::Quad) == 0x30, "CWldTerrainDecal::Quad size must be 0x30");
  static_assert(sizeof(CountedPtr<CountedObject>) == 0x04, "CountedPtr<CountedObject> size must be 0x04");
  static_assert(sizeof(CWldTerrainDecal) == 0x170, "CWldTerrainDecal size must be 0x170");
} // namespace moho

