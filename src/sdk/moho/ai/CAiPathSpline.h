#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  class Unit;

  /**
   * Collision reaction category stored in steering collision state.
   */
  enum ECollisionType : std::int32_t
  {
    COLLISIONTYPE_None = 0,
    COLLISIONTYPE_1 = 1,
    COLLISIONTYPE_2 = 2,
    COLLISIONTYPE_3 = 3,
    COLLISIONTYPE_4 = 4,
    COLLISIONTYPE_5 = 5,
  };

  /**
   * Path spline generation mode.
   */
  enum EPathSplineType : std::int32_t
  {
    PT_0 = 0,
    PT_1 = 1,
    PT_2 = 2,
    PT_3 = 3,
    PT_4 = 4,
  };

  /**
   * Path point steering-state tag used by spline generation/update logic.
   */
  enum EPathPointState : std::int32_t
  {
    PPS_0 = 0,
    PPS_1 = 1,
    PPS_2 = 2,
    PPS_3 = 3,
    PPS_4 = 4,
    PPS_5 = 5,
    PPS_6 = 6,
    PPS_7 = 7,
    PPS_8 = 8,
  };

  /**
   * Address: 0x0062F6B0 (FUN_0062F6B0, CPathPointTypeInfo::Init size evidence)
   */
  struct CPathPoint
  {
    Wm3::Vector3f mPosition;  // +0x00
    Wm3::Vector3f mDirection; // +0x0C
    EPathPointState mState;   // +0x18
  };

  static_assert(sizeof(CPathPoint) == 0x1C, "CPathPoint size must be 0x1C");
  static_assert(offsetof(CPathPoint, mPosition) == 0x00, "CPathPoint::mPosition offset must be 0x00");
  static_assert(offsetof(CPathPoint, mDirection) == 0x0C, "CPathPoint::mDirection offset must be 0x0C");
  static_assert(offsetof(CPathPoint, mState) == 0x18, "CPathPoint::mState offset must be 0x18");

  /**
   * Intrusive collision-link header paired with steering collision state.
   */
  struct SCollisionLink
  {
    void* mUnitIntrusiveSlot; // +0x00 (stores Unit+0x04 style intrusive slot, not Unit*)
    void* mNextInUnitChain;   // +0x04

    [[nodiscard]]
    Unit* ResolveUnitFromIntrusiveSlot() const noexcept;

    [[nodiscard]]
    void** GetIntrusiveSlotAddress() const noexcept;

    [[nodiscard]]
    bool HasLinkedUnit() const noexcept;

    void AssignUnit(Unit* unit) noexcept;

    void ClearLink() noexcept;
  };

  static_assert(sizeof(SCollisionLink) == 0x08, "SCollisionLink size must be 0x08");
  static_assert(
    offsetof(SCollisionLink, mUnitIntrusiveSlot) == 0x00, "SCollisionLink::mUnitIntrusiveSlot offset must be 0x00"
  );
  static_assert(
    offsetof(SCollisionLink, mNextInUnitChain) == 0x04, "SCollisionLink::mNextInUnitChain offset must be 0x04"
  );

  /**
   * Address: 0x00596790 (FUN_00596790, SCollisionInfoTypeInfo::Init size evidence)
   */
  struct SCollisionInfo
  {
    SCollisionLink mUnit;   // +0x00
    Wm3::Vector3f mPos;     // +0x08
    ECollisionType mCollisionType; // +0x14
    std::int32_t mTickGate;        // +0x18 (used as sim-tick gate when mCollisionType == COLLISIONTYPE_1)
  };

  static_assert(sizeof(SCollisionInfo) == 0x1C, "SCollisionInfo size must be 0x1C");
  static_assert(offsetof(SCollisionInfo, mUnit) == 0x00, "SCollisionInfo::mUnit offset must be 0x00");
  static_assert(offsetof(SCollisionInfo, mPos) == 0x08, "SCollisionInfo::mPos offset must be 0x08");
  static_assert(
    offsetof(SCollisionInfo, mCollisionType) == 0x14, "SCollisionInfo::mCollisionType offset must be 0x14"
  );
  static_assert(offsetof(SCollisionInfo, mTickGate) == 0x18, "SCollisionInfo::mTickGate offset must be 0x18");

  /**
   * Address: 0x00596560 (FUN_00596560, sub_596560)
   *
   * What it does:
   * Clears collision link/position/state values for steering collision info.
   */
  void ResetCollisionInfo(SCollisionInfo& info);

  /**
   * Continuation state for subsequent spline regeneration.
   */
  struct SPathSplineContinuationInfo
  {
    Wm3::Vector3f mPreviousPosition; // +0x00
    Wm3::Vector3f mPreviousDirection; // +0x0C
    Wm3::Vector3f mPreviousVelocity; // +0x18
    EPathPointState mContinuationState; // +0x24
  };

  static_assert(sizeof(SPathSplineContinuationInfo) == 0x28, "SPathSplineContinuationInfo size must be 0x28");
  static_assert(
    offsetof(SPathSplineContinuationInfo, mPreviousPosition) == 0x00,
    "SPathSplineContinuationInfo::mPreviousPosition offset must be 0x00"
  );
  static_assert(
    offsetof(SPathSplineContinuationInfo, mPreviousDirection) == 0x0C,
    "SPathSplineContinuationInfo::mPreviousDirection offset must be 0x0C"
  );
  static_assert(
    offsetof(SPathSplineContinuationInfo, mPreviousVelocity) == 0x18,
    "SPathSplineContinuationInfo::mPreviousVelocity offset must be 0x18"
  );
  static_assert(
    offsetof(SPathSplineContinuationInfo, mContinuationState) == 0x24,
    "SPathSplineContinuationInfo::mContinuationState offset must be 0x24"
  );

  class CAiPathSpline
  {
  public:
    /**
     * Address: 0x005B2550 (FUN_005B2550, ??0CAiPathSpline@Moho@@QAE@@Z)
     */
    CAiPathSpline();

    /**
     * Address: 0x005D45D0 (FUN_005D45D0, ??1CAiPathSpline@Moho@@QAE@@Z)
     */
    ~CAiPathSpline();

    /**
     * Address: 0x005B26C0 (FUN_005B26C0, Moho::CAiPathSpline::Update)
     *
     * What it does:
     * Rebuilds/extends local steering path nodes from the current unit state.
     */
    int Update(Unit* unit, int updateMode);

    /**
     * Address: 0x005B2FF0 (FUN_005B2FF0, Moho::CAiPathSpline::Generate)
     *
     * What it does:
     * Generates a path spline toward a target destination vector.
     */
    void Generate(Unit* unit, const Wm3::Vector3f& destination, int pathType, bool allowContinuation);

    /**
     * Address: 0x005B2550 (FUN_005B2550)
     *
     * What it does:
     * Releases heap-backed node storage and restores inline buffer ownership.
     */
    void ResetNodesToInline();

    /**
     * Address: 0x005965E0 (FUN_005965E0, sub_5965E0)
     *
     * What it does:
     * Returns node pointer for an index if it is within `mNodeCount`; otherwise null.
     */
    [[nodiscard]]
    CPathPoint* TryGetNode(std::uint32_t index);

    /**
     * Address: 0x005965E0 (FUN_005965E0, sub_5965E0)
     */
    [[nodiscard]]
    const CPathPoint* TryGetNode(std::uint32_t index) const;

  public:
    static gpg::RType* sType;

    // 0x00..0x23F
    gpg::core::FastVectorN<CPathPoint, 20> nodes;
    std::uint32_t mCurrentNodeIndex;      // +0x240
    std::uint32_t mNodeCount;             // +0x244
    EPathSplineType mPathType;            // +0x248
    SPathSplineContinuationInfo mContinuation; // +0x24C
    std::uint32_t mTailWord;              // +0x274 (semantic unresolved)
  };

  static_assert(sizeof(gpg::core::FastVectorN<CPathPoint, 20>) == 0x240, "FastVectorN<CPathPoint,20> size must be 0x240");
  static_assert(sizeof(CAiPathSpline) == 0x278, "CAiPathSpline size must be 0x278");
  static_assert(
    offsetof(CAiPathSpline, mCurrentNodeIndex) == 0x240, "CAiPathSpline::mCurrentNodeIndex offset must be 0x240"
  );
  static_assert(offsetof(CAiPathSpline, mNodeCount) == 0x244, "CAiPathSpline::mNodeCount offset must be 0x244");
  static_assert(offsetof(CAiPathSpline, mPathType) == 0x248, "CAiPathSpline::mPathType offset must be 0x248");
  static_assert(
    offsetof(CAiPathSpline, mContinuation) == 0x24C, "CAiPathSpline::mContinuation offset must be 0x24C"
  );
  static_assert(offsetof(CAiPathSpline, mTailWord) == 0x274, "CAiPathSpline::mTailWord offset must be 0x274");

  class SCollisionInfoTypeInfo : public gpg::RType
  {
  public:
    ~SCollisionInfoTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00596790 (FUN_00596790, SCollisionInfoTypeInfo::Init)
     */
    void Init() override;
  };

  class CPathPointTypeInfo : public gpg::RType
  {
  public:
    ~CPathPointTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0062F6B0 (FUN_0062F6B0, CPathPointTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SCollisionInfoTypeInfo) == 0x64, "SCollisionInfoTypeInfo size must be 0x64");
  static_assert(sizeof(CPathPointTypeInfo) == 0x64, "CPathPointTypeInfo size must be 0x64");
} // namespace moho
