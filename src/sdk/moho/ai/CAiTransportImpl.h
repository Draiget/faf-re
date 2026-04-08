#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/ArmyUnitSet.h"
#include "wm3/Quaternion.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class RUnitBlueprint;
  class SCoordsVec2;
  class SOCellPos;

  enum class ETransportClass : std::int32_t
  {
    TRANSPORTCLASS_1 = 1,
    TRANSPORTCLASS_2 = 2,
    TRANSPORTCLASS_3 = 3,
    TRANSPORTCLASS_4 = 4,
    TRANSPORTCLASS_SPECIAL = 5,
  };

  /**
   * Attach-point record used by transport slot assignment.
   *
   * Evidence:
   * - Transport assign/space checks iterate by 0x14-byte stride.
   * - 0x005E4D40 reads `index` and writes squared distance at +0x10.
   */
  struct SAttachPoint
  {
    std::uint32_t index; // +0x00
    Wm3::Vec3f localPos; // +0x04
    float distSq;        // +0x10
  };
  static_assert(sizeof(SAttachPoint) == 0x14, "SAttachPoint size must be 0x14");
  static_assert(offsetof(SAttachPoint, index) == 0x00, "SAttachPoint::index offset must be 0x00");
  static_assert(offsetof(SAttachPoint, localPos) == 0x04, "SAttachPoint::localPos offset must be 0x04");
  static_assert(offsetof(SAttachPoint, distSq) == 0x10, "SAttachPoint::distSq offset must be 0x10");

  struct STransportPickUpInfo
  {
    /**
     * Address: 0x005E43A0 (FUN_005E43A0, Moho::STransportPickUpInfo::STransportPickUpInfo)
     *
     * What it does:
     * Initializes fallback position/orientation lanes and resets pickup-unit
     * set storage to an empty inline-backed state.
     */
    STransportPickUpInfo();

    [[nodiscard]] bool HasUnit(const Unit* unit) const noexcept;
    void RemoveUnit(Unit* unit) noexcept;

    SCoordsVec2 mFallbackPos;        // +0x00
    Wm3::Quatf mOri;                 // +0x08
    Wm3::Vec3f mPos;                 // +0x18
    std::uint32_t mReserved24;       // +0x24
    SEntitySetTemplateUnit mUnits;   // +0x28
    std::uint8_t mHasSpace;          // +0x50
    std::uint8_t mUnknown51[0x07];   // +0x51
  };
  static_assert(sizeof(STransportPickUpInfo) == 0x58, "STransportPickUpInfo size must be 0x58");
  static_assert(
    offsetof(STransportPickUpInfo, mFallbackPos) == 0x00,
    "STransportPickUpInfo::mFallbackPos offset must be 0x00"
  );
  static_assert(offsetof(STransportPickUpInfo, mOri) == 0x08, "STransportPickUpInfo::mOri offset must be 0x08");
  static_assert(offsetof(STransportPickUpInfo, mPos) == 0x18, "STransportPickUpInfo::mPos offset must be 0x18");
  static_assert(offsetof(STransportPickUpInfo, mUnits) == 0x28, "STransportPickUpInfo::mUnits offset must be 0x28");
  static_assert(
    offsetof(STransportPickUpInfo, mHasSpace) == 0x50,
    "STransportPickUpInfo::mHasSpace offset must be 0x50"
  );

  /**
   * VFTABLE: 0x00E1F3CC
   * COL:  0x00E7664C
   */
  class CAiTransportImpl : public IAiTransport
  {
  public:
    /**
     * Address: 0x005E5300 (FUN_005E5300, Moho::CAiTransportImpl::CAiTransportImpl)
     * Address: 0x005E5670 (FUN_005E5670, Moho::CAiTransportImpl::CAiTransportImpl)
     * Mangled: ??0CAiTransportImpl@Moho@@AAE@XZ
     * Mangled: ??0CAiTransportImpl@Moho@@QAE@PAVUnit@1@@Z
     *
     * What it does:
     * Initializes transport runtime lanes, and when `unit` is provided also
     * derives category flags, attach-point buckets, and entity-set registry links.
     */
    explicit CAiTransportImpl(Unit* unit = nullptr);

    /**
     * Address: 0x005E8500 (FUN_005E8500, Moho::CAiTransportImpl::MemberConstruct)
     *
     * What it does:
     * Allocates one `CAiTransportImpl` instance and publishes it via
     * `SerConstructResult::SetUnowned`.
     */
    static void MemberConstruct(gpg::SerConstructResult* result);

    /**
     * Address: 0x005EEE30 (FUN_005EEE30, Moho::CAiTransportImpl::MemberDeserialize)
     *
     * What it does:
     * Loads runtime transport state lanes from the read archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005EF1F0 (FUN_005EF1F0, Moho::CAiTransportImpl::MemberSerialize)
     *
     * What it does:
     * Saves runtime transport state lanes into the write archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005E8280 (FUN_005E8280, scalar deleting thunk)
     * Address: 0x005E5C10 (FUN_005E5C10, core dtor)
     *
     * What it does:
     * Clears transport waiting-formation state and destroys live stored units
     * before regular member/base teardown.
     *
     * VFTable SLOT: 0
     */
    ~CAiTransportImpl() override;

    /**
     * Address: 0x005E60F0 (FUN_005E60F0)
     *
     * VFTable SLOT: 1
     */
    bool TransportIsAirStagingPlatform() const override;

    /**
     * Address: 0x005E6100 (FUN_005E6100)
     *
     * VFTable SLOT: 2
     */
    bool TransportIsTeleporter() const override;

    /**
     * Address: 0x005E6110 (FUN_005E6110)
     *
     * VFTable SLOT: 3
     */
    EntitySetTemplate<Unit> TransportGetLoadedUnits(bool) const override;

    /**
     * Address: 0x005E6260 (FUN_005E6260)
     *
     * VFTable SLOT: 4
     */
    void TransportAddPickupUnits(const EntitySetTemplate<Unit>&, SCoordsVec2) override;

    /**
     * Address: 0x005E64A0 (FUN_005E64A0)
     *
     * VFTable SLOT: 5
     */
    void TransportRemovePickupUnit(Unit*, bool) override;

    /**
     * Address: 0x005E64D0 (FUN_005E64D0)
     *
     * VFTable SLOT: 6
     */
    void TransportRemoveUnitReservation(Unit*) override;

    /**
     * Address: 0x005E65A0 (FUN_005E65A0)
     *
     * VFTable SLOT: 7
     */
    unsigned int TransportGetPickupUnitCount() const override;

    /**
     * Address: 0x005E65F0 (FUN_005E65F0)
     *
     * VFTable SLOT: 8
     */
    EntitySetTemplate<Unit> TransportGetPickupUnits() override;

    /**
     * Address: 0x005E6870 (FUN_005E6870)
     *
     * VFTable SLOT: 9
     */
    bool TransportCanCarryUnit(Unit*) const override;

    /**
     * Address: 0x005E6C70 (FUN_005E6C70)
     *
     * VFTable SLOT: 10
     */
    bool TransportHasSpaceFor(const RUnitBlueprint*) override;

    /**
     * Address: 0x005E6E30 (FUN_005E6E30)
     *
     * VFTable SLOT: 11
     */
    bool TransportAssignSlot(Unit*, int) override;

    /**
     * Address: 0x005E7100 (FUN_005E7100)
     *
     * VFTable SLOT: 12
     */
    bool TransportAttachUnit(Unit*) override;

    /**
     * Address: 0x005E7170 (FUN_005E7170)
     *
     * VFTable SLOT: 13
     */
    bool TransportDetachUnit(Unit*) override;

    /**
     * Address: 0x005E73E0 (FUN_005E73E0)
     *
     * VFTable SLOT: 14
     */
    EntitySetTemplate<Unit> TransportDetachAllUnits(bool) override;

    /**
     * Address: 0x005E6690 (FUN_005E6690)
     *
     * VFTable SLOT: 15
     */
    bool TransportIsUnitAssignedForPickup(Unit*) const override;

    /**
     * Address: 0x005E66B0 (FUN_005E66B0)
     *
     * VFTable SLOT: 16
     */
    SOCellPos TransportGetPickupUnitPos(Unit*) const override;

    /**
     * Address: 0x005E77B0 (FUN_005E77B0)
     *
     * VFTable SLOT: 17
     */
    void TransportAtPickupPosition() override;

    /**
     * Address: 0x005E77C0 (FUN_005E77C0)
     *
     * VFTable SLOT: 18
     */
    bool TransportIsReadyForUnit(Unit*) const override;

    /**
     * Address: 0x005E7930 (FUN_005E7930)
     *
     * VFTable SLOT: 19
     */
    int TransportGetAttachBone(Unit*) const override;

    /**
     * Address: 0x005E77F0 (FUN_005E77F0)
     *
     * VFTable SLOT: 20
     */
    SOCellPos TransportGetAttachPosition(Unit*) const override;

    /**
     * Address: 0x005E7950 (FUN_005E7950)
     *
     * VFTable SLOT: 21
     */
    Wm3::Vec3f TransportGetAttachBonePosition(Unit*) const override;

    /**
     * Address: 0x005E7A60 (FUN_005E7A60)
     *
     * VFTable SLOT: 22
     */
    VTransform TransportGetAttachBoneTransform(Unit*) const override;

    /**
     * Address: 0x005E7AD0 (FUN_005E7AD0)
     *
     * VFTable SLOT: 23
     */
    Wm3::Vec3f TransportGetAttachFacing(Unit*) const override;

    /**
     * Address: 0x005E7BB0 (FUN_005E7BB0)
     *
     * VFTable SLOT: 24
     */
    Wm3::Vec3f TransportGetPickupFacing() const override;

    /**
     * Address: 0x005E7BE0 (FUN_005E7BE0)
     *
     * VFTable SLOT: 25
     */
    void TransportAddToStorage(Unit*) override;

    /**
     * Address: 0x005E7CF0 (FUN_005E7CF0)
     *
     * VFTable SLOT: 26
     */
    void TransportRemoveFromStorage(Unit*, VTransform&) override;

    /**
     * Address: 0x005E7E60 (FUN_005E7E60)
     *
     * VFTable SLOT: 27
     */
    EntitySetTemplate<Unit> TransportGetStoredUnits() const override;

    /**
     * Address: 0x005E8050 (FUN_005E8050)
     *
     * VFTable SLOT: 28
     */
    bool TransportIsStoredUnit(Unit*) const override;

    /**
     * Address: 0x005E7E80 (FUN_005E7E80)
     *
     * VFTable SLOT: 29
     */
    bool TransportHasAvailableStorage() const override;

    /**
     * Address: 0x005E7EC0 (FUN_005E7EC0)
     *
     * VFTable SLOT: 30
     */
    int TransportReserveStorage(Unit*, Wm3::Vec3f&, Wm3::Vec3f&, float&) override;

    /**
     * Address: 0x005E8020 (FUN_005E8020)
     *
     * VFTable SLOT: 31
     */
    void TransportClearReservation(Unit*) override;

    /**
     * Address: 0x005E8040 (FUN_005E8040)
     *
     * VFTable SLOT: 32
     */
    void TransportResetReservation() override;

    /**
     * Address: 0x005E6530 (FUN_005E6530)
     *
     * VFTable SLOT: 33
     */
    void TransportUnreserveUnattachedSpots() override;

    /**
     * Address: 0x005E5F10 (FUN_005E5F10)
     *
     * VFTable SLOT: 34
     */
    void TransportRemoveFromWaitingList(Unit*) override;

    /**
     * Address: 0x005E5EF0 (FUN_005E5EF0)
     *
     * VFTable SLOT: 35
     */
    EntitySetTemplate<Unit> TransportGetUnitsWaitingForPickup() const override;

    /**
     * Address: 0x005E5F30 (FUN_005E5F30)
     *
     * VFTable SLOT: 36
     */
    IFormationInstance* TransportGetWaitingFormation() const override;

    /**
     * Address: 0x005E5F40 (FUN_005E5F40)
     *
     * VFTable SLOT: 37
     */
    void TransportGenerateWaitingFormationForUnits(const EntitySetTemplate<Unit>&) override;

    /**
     * Address: 0x005E60A0 (FUN_005E60A0)
     *
     * VFTable SLOT: 38
     */
    void TransportClearWaitingFormation() override;

    /**
     * Address: 0x005E8080 (FUN_005E8080)
     *
     * VFTable SLOT: 39
     */
    void TranspotSetTeleportDest(Unit*) override;

    /**
     * Address: 0x005E8120 (FUN_005E8120)
     *
     * VFTable SLOT: 40
     */
    Wm3::Vec3f TransportGetTeleportDest() const override;

    /**
     * Address: 0x005E81C0 (FUN_005E81C0)
     *
     * VFTable SLOT: 41
     */
    Unit* TransportGetTeleportBeacon() const override;

    /**
     * Address: 0x005E81D0 (FUN_005E81D0)
     *
     * VFTable SLOT: 42
     */
    bool TransportIsTeleportBeaconReady() const override;

  private:
    /**
     * Address: 0x005E4930 (FUN_005E4930, Moho::CAiTransportImpl::SetUpAttachPoints)
     *
     * What it does:
     * Scans transport skeleton bones and buckets attach indices by bone-name
     * tag into launch/class/generic attach vectors.
     */
    void SetUpAttachPoints();

    /**
     * Address: 0x005E5120 (FUN_005E5120)
     */
    const SAiReservedTransportBone* GetReservedBone(Unit*) const;

    /**
     * Address: 0x005E50A0 (FUN_005E50A0)
     */
    unsigned int GetBestAttachPoint(Unit*) const;

    /**
     * Address: 0x005E5150 (FUN_005E5150)
     */
    void AttachUnitToBone(Unit* unit, unsigned int transportBoneIndex, unsigned int attachBoneIndex);

    /**
     * Address: 0x005E6AC0 (FUN_005E6AC0)
     */
    bool TransportValidateType(const RUnitBlueprint*) const;

    /**
     * Address: 0x005E6B30 (FUN_005E6B30)
     */
    void TransportFindAttachList(
      int unitClass,
      msvc8::vector<SAttachPoint>& attachPoints,
      msvc8::vector<SAttachPoint>& outAttachPoints,
      int& outAttachSize
    );

    /**
     * Address: 0x005E4D40 (FUN_005E4D40)
     */
    msvc8::vector<int> GetClosestAttachPointsTo(msvc8::vector<SAttachPoint> attachPoints, int hookIndex, int attachSize);

    /**
     * Address: 0x005E4F00 (FUN_005E4F00)
     */
    bool IsBoneReserved(msvc8::vector<int> boneIndices);

    /**
     * Address: 0x005E4FA0 (FUN_005E4FA0)
     */
    void ReserveBone(unsigned int bestAttachBoneIndex, Unit* unit, unsigned int transportBoneIndex, msvc8::vector<int> boneIndices);

  public:
    static gpg::RType* sType;

    Unit* mUnit; // +0x0C
    WeakPtr<Unit> mTeleportBeacon; // +0x10
    std::uint8_t mStagingPlatform; // +0x18
    std::uint8_t mTeleportation; // +0x19
    std::uint8_t mUnknown1A[0x02]; // +0x1A
    std::int32_t mAttachpoints; // +0x1C
    std::int32_t mNextGeneric; // +0x20
    std::int32_t mLaunchAttachIndex; // +0x24
    std::int32_t mGenericOverflow; // +0x28
    std::uint8_t mUnknown2C[0x04]; // +0x2C
    SEntitySetTemplateUnit mUnitSet30; // +0x30
    SEntitySetTemplateUnit mStoredUnits; // +0x58
    SEntitySetTemplateUnit mUnitSet80; // +0x80
    msvc8::vector<SAiReservedTransportBone> mReservedBones; // +0xA8
    STransportPickUpInfo mPickupInfo; // +0xB8
    IFormationInstance* mWaitingFormation; // +0x110
    Wm3::Vec3f mPickupFacing; // +0x114
    msvc8::vector<SAttachPoint> mGenericAttachPoints; // +0x120
    msvc8::vector<SAttachPoint> mClass1AttachPoints; // +0x130
    msvc8::vector<SAttachPoint> mClass2AttachPoints; // +0x140
    msvc8::vector<SAttachPoint> mClass3AttachPoints; // +0x150
    msvc8::vector<SAttachPoint> mClass4AttachPoints; // +0x160
    msvc8::vector<SAttachPoint> mClassSAttachPoints; // +0x170
    msvc8::vector<SAttachPoint> mLaunchAttachPoints; // +0x180
  };

  static_assert(sizeof(CAiTransportImpl) == 0x190, "CAiTransportImpl size must be 0x190");
  static_assert(offsetof(CAiTransportImpl, mUnit) == 0x0C, "CAiTransportImpl::mUnit offset must be 0x0C");
  static_assert(
    offsetof(CAiTransportImpl, mTeleportBeacon) == 0x10,
    "CAiTransportImpl::mTeleportBeacon offset must be 0x10"
  );
  static_assert(
    offsetof(CAiTransportImpl, mStagingPlatform) == 0x18,
    "CAiTransportImpl::mStagingPlatform offset must be 0x18"
  );
  static_assert(offsetof(CAiTransportImpl, mTeleportation) == 0x19, "CAiTransportImpl::mTeleportation offset must be 0x19");
  static_assert(offsetof(CAiTransportImpl, mAttachpoints) == 0x1C, "CAiTransportImpl::mAttachpoints offset must be 0x1C");
  static_assert(offsetof(CAiTransportImpl, mNextGeneric) == 0x20, "CAiTransportImpl::mNextGeneric offset must be 0x20");
  static_assert(
    offsetof(CAiTransportImpl, mLaunchAttachIndex) == 0x24,
    "CAiTransportImpl::mLaunchAttachIndex offset must be 0x24"
  );
  static_assert(
    offsetof(CAiTransportImpl, mGenericOverflow) == 0x28,
    "CAiTransportImpl::mGenericOverflow offset must be 0x28"
  );
  static_assert(offsetof(CAiTransportImpl, mStoredUnits) == 0x58, "CAiTransportImpl::mStoredUnits offset must be 0x58");
  static_assert(offsetof(CAiTransportImpl, mReservedBones) == 0xA8, "CAiTransportImpl::mReservedBones offset must be 0xA8");
  static_assert(
    offsetof(CAiTransportImpl, mPickupInfo) == 0xB8,
    "CAiTransportImpl::mPickupInfo offset must be 0xB8"
  );
  static_assert(
    offsetof(CAiTransportImpl, mWaitingFormation) == 0x110,
    "CAiTransportImpl::mWaitingFormation offset must be 0x110"
  );
  static_assert(
    offsetof(CAiTransportImpl, mPickupFacing) == 0x114,
    "CAiTransportImpl::mPickupFacing offset must be 0x114"
  );
  static_assert(
    offsetof(CAiTransportImpl, mGenericAttachPoints) == 0x120,
    "CAiTransportImpl::mGenericAttachPoints offset must be 0x120"
  );
  static_assert(
    offsetof(CAiTransportImpl, mLaunchAttachPoints) == 0x180,
    "CAiTransportImpl::mLaunchAttachPoints offset must be 0x180"
  );
} // namespace moho
