#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/CountedObject.h"
#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
  class IWldTerrainRes;

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
    struct Quad;

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
     * Address: 0x0089D1F0 (Moho::CWldTerrainDecal::SetName)
     *
     * What it does:
     * Updates the decal's named texture lanes and per-slot name metadata.
     */
    virtual void SetName(const msvc8::string& name, int slot) = 0;

    /**
     * Address: 0x0089D9C0 (Moho::CWldTerrainDecal::ComputeCorner)
     *
     * What it does:
     * Projects one decal corner in world space.
     */
    virtual Wm3::Vec2f ComputeCorner(const Wm3::Vec2f& corner) const = 0;

    /**
     * Address: 0x0089C890 (Moho::CWldTerrainDecal::EnableFlatOptimization)
     *
     * What it does:
     * Toggles flatness optimization for this decal lane.
     */
    virtual void EnableFlatOptimization(bool enabled) = 0;

    /**
     * Address: 0x0089D560 (Moho::CWldTerrainDecal::ComputeFlatness)
     *
     * What it does:
     * Evaluates whether one quad is flat enough to keep the current LOD.
     */
    virtual bool ComputeFlatness(Quad& quad) = 0;

    /**
     * Address: 0x0089DA80 (Moho::CWldTerrainDecal::ComputeCutoffLOD)
     *
     * What it does:
     * Computes the distance-based cutoff LOD for the decal.
     */
    virtual float ComputeCutoffLOD(float distance) const = 0;

    /**
     * Address: 0x0089DC70 (Moho::CWldTerrainDecal::Update)
     *
     * What it does:
     * Advances runtime decal state for the current frame.
     */
    virtual void Update() = 0;

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
    float mUnknown80;                          // +0x80
    float mUnknown84;                          // +0x84
    float mUnknown88;                          // +0x88
    float mUnknown8C;                          // +0x8C
    float mUnknown90;                          // +0x90
    float mUnknown94;                          // +0x94
    std::int32_t mUnknown98;                   // +0x98
    std::int32_t mUnknown9C;                   // +0x9C
    std::uint8_t mUnknownA0;                   // +0xA0
    std::uint8_t mPadA1_A3[0x03];              // +0xA1
    CountedPtr<CountedObject> mResourceRefs[2]; // +0xA4
    std::uint8_t mPadAC_13B[0x90];             // +0xAC
    std::uint8_t mFlag13C;                     // +0x13C
    std::uint8_t mFlag13D;                     // +0x13D
    std::uint8_t mFlag13E;                     // +0x13E
    std::uint8_t mPad13F;                      // +0x13F
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
  static_assert(offsetof(CWldTerrainDecal, mUnknown80) == 0x80, "CWldTerrainDecal::mUnknown80 offset must be 0x80");
  static_assert(offsetof(CWldTerrainDecal, mUnknown84) == 0x84, "CWldTerrainDecal::mUnknown84 offset must be 0x84");
  static_assert(offsetof(CWldTerrainDecal, mUnknown88) == 0x88, "CWldTerrainDecal::mUnknown88 offset must be 0x88");
  static_assert(offsetof(CWldTerrainDecal, mUnknown8C) == 0x8C, "CWldTerrainDecal::mUnknown8C offset must be 0x8C");
  static_assert(offsetof(CWldTerrainDecal, mUnknown90) == 0x90, "CWldTerrainDecal::mUnknown90 offset must be 0x90");
  static_assert(offsetof(CWldTerrainDecal, mUnknown94) == 0x94, "CWldTerrainDecal::mUnknown94 offset must be 0x94");
  static_assert(offsetof(CWldTerrainDecal, mUnknown98) == 0x98, "CWldTerrainDecal::mUnknown98 offset must be 0x98");
  static_assert(offsetof(CWldTerrainDecal, mUnknown9C) == 0x9C, "CWldTerrainDecal::mUnknown9C offset must be 0x9C");
  static_assert(offsetof(CWldTerrainDecal, mUnknownA0) == 0xA0, "CWldTerrainDecal::mUnknownA0 offset must be 0xA0");
  static_assert(offsetof(CWldTerrainDecal, mResourceRefs) == 0xA4, "CWldTerrainDecal::mResourceRefs offset must be 0xA4");
  static_assert(offsetof(CWldTerrainDecal, mFlag13C) == 0x13C, "CWldTerrainDecal::mFlag13C offset must be 0x13C");
  static_assert(offsetof(CWldTerrainDecal, mFlag13D) == 0x13D, "CWldTerrainDecal::mFlag13D offset must be 0x13D");
  static_assert(offsetof(CWldTerrainDecal, mFlag13E) == 0x13E, "CWldTerrainDecal::mFlag13E offset must be 0x13E");

  static_assert(sizeof(CountedPtr<CountedObject>) == 0x04, "CountedPtr<CountedObject> size must be 0x04");
  static_assert(sizeof(CWldTerrainDecal) == 0x140, "CWldTerrainDecal size must be 0x140");
} // namespace moho
