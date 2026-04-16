#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/math/Vector2f.h"
#include "moho/math/Vector3f.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;
  class VTransform;

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
  enum EPathType : std::int32_t
  {
    PT_0 = 0,
    PT_1 = 1,
    PT_2 = 2,
    PT_3 = 3,
    PT_4 = 4,
  };

  using EPathSplineType = EPathType;

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
    /**
     * Address: 0x0062F9F0 (FUN_0062F9F0, Moho::CPathPoint::MemberDeserialize)
     *
     * What it does:
     * Loads path-point position/direction vectors and state enum lanes from a
     * read archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    Wm3::Vector3f mPosition;  // +0x00
    Wm3::Vector3f mDirection; // +0x0C
    EPathPointState mState;   // +0x18
  };

  static_assert(sizeof(CPathPoint) == 0x1C, "CPathPoint size must be 0x1C");
  static_assert(offsetof(CPathPoint, mPosition) == 0x00, "CPathPoint::mPosition offset must be 0x00");
  static_assert(offsetof(CPathPoint, mDirection) == 0x0C, "CPathPoint::mDirection offset must be 0x0C");
  static_assert(offsetof(CPathPoint, mState) == 0x18, "CPathPoint::mState offset must be 0x18");

  struct SteeringParams
  {
    /**
     * Address: 0x006990E0 (FUN_006990E0, ??0struct_SteeringParams@@QAE@@Z)
     *
     * What it does:
     * Builds steering scalar/vector lanes from unit physics + attributes and a
     * source/destination/forward snapshot.
     */
    SteeringParams(
      Unit* unit,
      const Wm3::Vector3f& sourcePosition,
      const Wm3::Vector3f& destinationPosition,
      const Wm3::Vector3f& forwardVector,
      float speedLimit,
      bool skipDynamicLimits
    ) noexcept;

    float mMaxSpeed;                 // +0x00
    float mMaxReverseSpeed;          // +0x04
    float mMaxAcceleration;          // +0x08
    float mMaxBrake;                 // +0x0C
    float mMaxSteer;                 // +0x10
    float mInvTurnRadius;            // +0x14
    float mTurnRate;                 // +0x18
    float mTurnFacingRate;           // +0x1C
    float mDeltaX;                   // +0x20
    float mDeltaZ;                   // +0x24
    Wm3::Vector2f mForwardXZ;        // +0x28
    float mDistance;                 // +0x30
    float mDistanceSq;               // +0x34
    std::uint8_t mRotateOnSpot;      // +0x38
    std::uint8_t pad_39_3B[0x03]{};  // +0x39
    float mRotateOnSpotThreshold;    // +0x3C
  };

  static_assert(offsetof(SteeringParams, mMaxSpeed) == 0x00, "SteeringParams::mMaxSpeed offset must be 0x00");
  static_assert(
    offsetof(SteeringParams, mMaxReverseSpeed) == 0x04, "SteeringParams::mMaxReverseSpeed offset must be 0x04"
  );
  static_assert(
    offsetof(SteeringParams, mMaxAcceleration) == 0x08, "SteeringParams::mMaxAcceleration offset must be 0x08"
  );
  static_assert(offsetof(SteeringParams, mMaxBrake) == 0x0C, "SteeringParams::mMaxBrake offset must be 0x0C");
  static_assert(offsetof(SteeringParams, mMaxSteer) == 0x10, "SteeringParams::mMaxSteer offset must be 0x10");
  static_assert(
    offsetof(SteeringParams, mInvTurnRadius) == 0x14, "SteeringParams::mInvTurnRadius offset must be 0x14"
  );
  static_assert(offsetof(SteeringParams, mTurnRate) == 0x18, "SteeringParams::mTurnRate offset must be 0x18");
  static_assert(
    offsetof(SteeringParams, mTurnFacingRate) == 0x1C, "SteeringParams::mTurnFacingRate offset must be 0x1C"
  );
  static_assert(offsetof(SteeringParams, mDeltaX) == 0x20, "SteeringParams::mDeltaX offset must be 0x20");
  static_assert(offsetof(SteeringParams, mDeltaZ) == 0x24, "SteeringParams::mDeltaZ offset must be 0x24");
  static_assert(offsetof(SteeringParams, mForwardXZ) == 0x28, "SteeringParams::mForwardXZ offset must be 0x28");
  static_assert(offsetof(SteeringParams, mDistance) == 0x30, "SteeringParams::mDistance offset must be 0x30");
  static_assert(offsetof(SteeringParams, mDistanceSq) == 0x34, "SteeringParams::mDistanceSq offset must be 0x34");
  static_assert(
    offsetof(SteeringParams, mRotateOnSpot) == 0x38, "SteeringParams::mRotateOnSpot offset must be 0x38"
  );
  static_assert(
    offsetof(SteeringParams, mRotateOnSpotThreshold) == 0x3C,
    "SteeringParams::mRotateOnSpotThreshold offset must be 0x3C"
  );
  static_assert(sizeof(SteeringParams) == 0x40, "SteeringParams size must be 0x40");

  /**
   * Address: 0x00698FF0 (FUN_00698FF0)
   *
   * What it does:
   * Builds one temporary `SteeringParams` snapshot from a transform origin,
   * destination vector, and transform-derived XZ forward lane.
   */
  [[nodiscard]]
  SteeringParams
  BuildSteeringParamsFromTransform(Unit* unit, const VTransform& transform, const Wm3::Vector3f& destination) noexcept;

  /**
   * Address: 0x006992C0 (FUN_006992C0)
   *
   * What it does:
   * Rotates one XZ direction toward a target direction by at most the supplied
   * max turn angle, preserving source length semantics.
   */
  Wm3::Vector2f* RotateDirectionTowardTargetLimited(
    Wm3::Vector2f* outDirection,
    float maxTurnRadians,
    float sourceX,
    float sourceZ,
    float targetX,
    float targetZ
  ) noexcept;

  /**
   * Address: 0x00699940 (FUN_00699940)
   *
   * What it does:
   * Converts one XZ direction lane into a yaw-only quaternion orientation.
   */
  Wm3::Quaternionf*
  BuildHeadingQuaternionFromDirection2D(const Wm3::Vector2f* direction, Wm3::Quaternionf* outOrientation) noexcept;

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

    /**
     * Address: 0x005984E0 (FUN_005984E0, Moho::SCollisionInfo::MemberDeserialize)
     *
     * What it does:
     * Loads weak-unit link, collision position/type, and tick-gate state.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005985A0 (FUN_005985A0, Moho::SCollisionInfo::MemberSerialize)
     *
     * What it does:
     * Saves weak-unit link, collision position/type, and tick-gate state.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
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
  struct SContinueInfo
  {
    static gpg::RType* sType;

    Wm3::Vector3f mOldPosition; // +0x00
    Wm3::Vector3f mOldDirection; // +0x0C
    Wm3::Vector3f mOldVelocity; // +0x18
    EPathPointState mState; // +0x24

    /**
     * Address: 0x005B5530 (FUN_005B5530, Moho::SContinueInfo::MemberDeserialize)
     *
     * What it does:
     * Loads continuation vectors/state from archive lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005B5610 (FUN_005B5610, Moho::SContinueInfo::MemberSerialize)
     *
     * What it does:
     * Saves continuation vectors/state into archive lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  using SPathSplineContinuationInfo = SContinueInfo;

  static_assert(sizeof(SContinueInfo) == 0x28, "SContinueInfo size must be 0x28");
  static_assert(
    offsetof(SContinueInfo, mOldPosition) == 0x00,
    "SContinueInfo::mOldPosition offset must be 0x00"
  );
  static_assert(
    offsetof(SContinueInfo, mOldDirection) == 0x0C,
    "SContinueInfo::mOldDirection offset must be 0x0C"
  );
  static_assert(
    offsetof(SContinueInfo, mOldVelocity) == 0x18,
    "SContinueInfo::mOldVelocity offset must be 0x18"
  );
  static_assert(
    offsetof(SContinueInfo, mState) == 0x24,
    "SContinueInfo::mState offset must be 0x24"
  );

  class CAiPathSpline
  {
  public:
    /**
       * Address: 0x005B2550 (FUN_005B2550)
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
     * Address: 0x005B5FB0 (FUN_005B5FB0, Moho::CAiPathSpline::MemberDeserialize)
     *
     * What it does:
     * Loads path-spline node/state payload, tracks prebuilt node pointers, and
     * restores continuation lanes from archive data.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005B60E0 (FUN_005B60E0, Moho::CAiPathSpline::MemberSerialize)
     *
     * What it does:
     * Saves path-spline node/state payload and pre-created node pointers into
     * the write archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
      * Alias of FUN_005B2550 (non-canonical helper lane).
     *
     * What it does:
     * Releases heap-backed node storage and restores inline buffer ownership.
     */
    void ResetNodesToInline();

    /**
      * Alias of FUN_005965E0 (non-canonical helper lane).
     *
     * What it does:
     * Returns node pointer for an index if it is within `mNodeCount`; otherwise null.
     */
    [[nodiscard]]
    CPathPoint* TryGetNode(std::uint32_t index);

    /**
      * Alias of FUN_005965E0 (non-canonical helper lane).
     */
    [[nodiscard]]
    const CPathPoint* TryGetNode(std::uint32_t index) const;

  public:
    static gpg::RType* sType;

    // 0x00..0x23F
    gpg::core::FastVectorN<CPathPoint, 20> nodes;
    std::uint32_t mCurrentNodeIndex;      // +0x240
    std::uint32_t mNodeCount;             // +0x244
    EPathType mPathType;                  // +0x248
    SContinueInfo mContinuation;          // +0x24C
    std::uint32_t mTailWord;              // +0x274 (semantic unresolved)
  };

  static_assert(sizeof(gpg::core::FastVectorN<CPathPoint, 20>) == 0x240, "FastVectorN<CPathPoint,20> size must be 0x240");
  static_assert(sizeof(CAiPathSpline) == 0x278, "CAiPathSpline size must be 0x278");
  static_assert(offsetof(CAiPathSpline, nodes) == 0x00, "CAiPathSpline::nodes offset must be 0x00");
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
    /**
     * Address: 0x00596730 (FUN_00596730, ctor)
     *
     * What it does:
     * Preregisters `SCollisionInfo` RTTI so lookup resolves to this type helper.
     */
    SCollisionInfoTypeInfo();

    ~SCollisionInfoTypeInfo() override;

    /**
     * Address: 0x005967B0 (FUN_005967B0, Moho::SCollisionInfoTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00596790 (FUN_00596790, SCollisionInfoTypeInfo::Init)
     */
    void Init() override;
  };

  class ECollisionTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00596600 (FUN_00596600, ctor)
     *
     * What it does:
     * Preregisters `ECollisionType` RTTI so lookup resolves to this enum helper.
     */
    ECollisionTypeTypeInfo();

    /**
     * Address: 0x00BF6510 (FUN_00BF6510, dtr)
     */
    ~ECollisionTypeTypeInfo() override;

    /**
     * Address: 0x00596680 (FUN_00596680, Moho::ECollisionTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00596660 (FUN_00596660, Moho::ECollisionTypeTypeInfo::Init)
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

  /**
   * Address: 0x0062F520 (FUN_0062F520, EPathPointStateTypeInfo prereg lane)
   *
   * What it does:
   * Owns the reflected enum descriptor for `EPathPointState`.
   */
  class EPathPointStateTypeInfo final : public gpg::REnumType
  {
  public:
    ~EPathPointStateTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;
    void Init() override;
  };

  /**
   * Address: 0x00BD20E0 (FUN_00BD20E0, register_EPathPointStatePrimitiveSerializer)
   *
   * What it does:
   * Binds primitive enum load/save callbacks onto reflected `EPathPointState`.
   */
  class EPathPointStatePrimitiveSerializer
  {
  public:
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EPathPointStatePrimitiveSerializer, mHelperNext) == 0x04,
    "EPathPointStatePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EPathPointStatePrimitiveSerializer, mHelperPrev) == 0x08,
    "EPathPointStatePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EPathPointStatePrimitiveSerializer, mDeserialize) == 0x0C,
    "EPathPointStatePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EPathPointStatePrimitiveSerializer, mSerialize) == 0x10,
    "EPathPointStatePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(EPathPointStatePrimitiveSerializer) == 0x14,
    "EPathPointStatePrimitiveSerializer size must be 0x14"
  );

  class SCollisionInfoSerializer
  {
  public:
    /**
     * Address: 0x00596870 (FUN_00596870, Moho::SCollisionInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SCollisionInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00596880 (FUN_00596880, Moho::SCollisionInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SCollisionInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00598390 (FUN_00598390, gpg::SerSaveLoadHelper<Moho::SCollisionInfo>::Init)
     *
     * What it does:
     * Binds `SCollisionInfo` load/save callbacks onto reflected type metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SCollisionInfoSerializer, mHelperNext) == 0x04,
    "SCollisionInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SCollisionInfoSerializer, mHelperPrev) == 0x08,
    "SCollisionInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SCollisionInfoSerializer, mDeserialize) == 0x0C,
    "SCollisionInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SCollisionInfoSerializer, mSerialize) == 0x10,
    "SCollisionInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SCollisionInfoSerializer) == 0x14, "SCollisionInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BD2140 (FUN_00BD2140, register_CPathPointSerializer)
   *
   * What it does:
   * Serializer helper that binds `CPathPoint` load/save callbacks.
   */
  class CPathPointSerializer
  {
  public:
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(CPathPointSerializer, mHelperNext) == 0x04, "CPathPointSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CPathPointSerializer, mHelperPrev) == 0x08, "CPathPointSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(CPathPointSerializer, mDeserialize) == 0x0C,
    "CPathPointSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(offsetof(CPathPointSerializer, mSerialize) == 0x10, "CPathPointSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CPathPointSerializer) == 0x14, "CPathPointSerializer size must be 0x14");

  /**
   * Address: 0x00BD20C0 (FUN_00BD20C0, register_EPathPointStateTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `EPathPointState` type-info, then schedules
   * teardown.
   */
  int register_EPathPointStateTypeInfo();

  /**
   * Address: 0x00BD20E0 (FUN_00BD20E0, register_EPathPointStatePrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `EPathPointState` and
   * schedules helper-node teardown.
   */
  int register_EPathPointStatePrimitiveSerializer();

  /**
   * Address: 0x00BCBDB0 (FUN_00BCBDB0, register_SCollisionInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `SCollisionInfo` type-info and installs teardown.
   */
  int register_SCollisionInfoTypeInfo();

  /**
   * Address: 0x00BCBD50 (FUN_00BCBD50, register_ECollisionTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ECollisionType` enum type-info and installs teardown.
   */
  void register_ECollisionTypeTypeInfo();

  /**
   * Address: 0x00BCBD70 (FUN_00BCBD70, register_PrimitiveSerHelper_ECollisionType_int)
   *
   * What it does:
   * Initializes primitive enum serializer callbacks for `ECollisionType`.
   */
  void register_PrimitiveSerHelper_ECollisionType_int();

  /**
   * Address: 0x00BCBDD0 (FUN_00BCBDD0, register_SCollisionInfoSerializer)
   *
   * What it does:
   * Initializes `SCollisionInfo` serializer callbacks and installs teardown.
   */
  void register_SCollisionInfoSerializer();

  /**
   * Address: 0x00BD2120 (FUN_00BD2120, register_CPathPointTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `CPathPoint` type-info, then schedules teardown.
   */
  int register_CPathPointTypeInfo();

  /**
   * Address: 0x00BD2140 (FUN_00BD2140, register_CPathPointSerializer)
   *
   * What it does:
   * Initializes `CPathPoint` serializer callbacks and schedules helper-node
   * teardown.
   */
  void register_CPathPointSerializer();

  /**
   * Address: 0x00BCD390 (FUN_00BCD390, register_FastVectorCPathPointTypeAtexit)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for
   * `gpg::fastvector<CPathPoint>` and installs process-exit teardown.
   */
  int register_FastVectorCPathPointTypeAtexit();

  /**
   * Address: 0x00BCD3B0 (FUN_00BCD3B0, register_CAiPathSplineStartupStatsCleanup)
   *
   * What it does:
   * Installs process-exit cleanup for one startup-owned AI path-spline stats
   * slot.
   */
  int register_CAiPathSplineStartupStatsCleanup();

  static_assert(sizeof(SCollisionInfoTypeInfo) == 0x64, "SCollisionInfoTypeInfo size must be 0x64");
  static_assert(sizeof(ECollisionTypeTypeInfo) == 0x78, "ECollisionTypeTypeInfo size must be 0x78");
  static_assert(sizeof(CPathPointTypeInfo) == 0x64, "CPathPointTypeInfo size must be 0x64");
  static_assert(sizeof(EPathPointStateTypeInfo) == 0x78, "EPathPointStateTypeInfo size must be 0x78");
} // namespace moho
