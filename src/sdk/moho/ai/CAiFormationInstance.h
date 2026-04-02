#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/ai/IFormationInstance.h"
#include "legacy/containers/String.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/containers/TDatList.h"
#include "wm3/Quaternion.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  class RRuleGameRules;
  class Sim;
  class Unit;

  struct SFormationLinkedUnitRef
  {
    std::uint32_t* ownerChainHead; // +0x00
    std::uint32_t nextChainLink;   // +0x04

    [[nodiscard]] static std::uint32_t* NextChainLinkSlot(std::uint32_t linkWord) noexcept;
  };
  static_assert(sizeof(SFormationLinkedUnitRef) == 0x08, "SFormationLinkedUnitRef size must be 0x08");

  struct SFormationLaneUnitNode
  {
    SFormationLaneUnitNode* left;   // +0x00
    SFormationLaneUnitNode* parent; // +0x04
    SFormationLaneUnitNode* right;  // +0x08
    std::uint32_t unitEntityId;     // +0x0C
    std::uint8_t unknown10[0x0C];   // +0x10
    float formationOffsetX;         // +0x1C
    float formationOffsetZ;         // +0x20
    std::uint8_t unknown24[0x10];   // +0x24
    float speedBandLow;             // +0x34
    float speedBandMid;             // +0x38
    float speedBandHigh;            // +0x3C
    std::uint8_t color;             // +0x40
    std::uint8_t isNil;             // +0x41
    std::uint8_t pad42[2];          // +0x42
  };
  static_assert(sizeof(SFormationLaneUnitNode) == 0x44, "SFormationLaneUnitNode size must be 0x44");
  static_assert(
    offsetof(SFormationLaneUnitNode, formationOffsetX) == 0x1C,
    "SFormationLaneUnitNode::formationOffsetX offset must be 0x1C"
  );
  static_assert(
    offsetof(SFormationLaneUnitNode, speedBandHigh) == 0x3C, "SFormationLaneUnitNode::speedBandHigh offset must be 0x3C"
  );
  static_assert(offsetof(SFormationLaneUnitNode, isNil) == 0x41, "SFormationLaneUnitNode::isNil offset must be 0x41");

  struct SFormationLaneUnitMap
  {
    std::uint32_t allocatorCookie;  // +0x00
    SFormationLaneUnitNode* head;   // +0x04
    std::uint32_t size;             // +0x08
  };
  static_assert(sizeof(SFormationLaneUnitMap) == 0x0C, "SFormationLaneUnitMap size must be 0x0C");
  static_assert(
    offsetof(SFormationLaneUnitMap, head) == 0x04, "SFormationLaneUnitMap::head offset must be 0x04"
  );
  static_assert(
    offsetof(SFormationLaneUnitMap, size) == 0x08, "SFormationLaneUnitMap::size offset must be 0x08"
  );

  struct SFormationLaneEntry
  {
    SFormationLaneUnitMap unitMap;            // +0x00
    std::uint8_t unknown0C[0x1C];             // +0x0C
    float dynamicOffsetX;                     // +0x28
    float dynamicOffsetZ;                     // +0x2C
    std::uint8_t unknown30[0x08];             // +0x30
    std::uint8_t applyDynamicOffset;          // +0x38
    std::uint8_t slotAvailable;               // +0x39
    std::uint8_t pad3A[2];                    // +0x3A
    float preferredSpeed;                     // +0x3C
    float speedAnchor;                        // +0x40
    std::uint32_t linkedUnitBackLinkHeadWord; // +0x44
    std::uint32_t linkedUnitBackLinkNextWord; // +0x48
  };
  static_assert(sizeof(SFormationLaneEntry) == 0x4C, "SFormationLaneEntry size must be 0x4C");
  static_assert(
    offsetof(SFormationLaneEntry, dynamicOffsetX) == 0x28, "SFormationLaneEntry::dynamicOffsetX offset must be 0x28"
  );
  static_assert(
    offsetof(SFormationLaneEntry, slotAvailable) == 0x39, "SFormationLaneEntry::slotAvailable offset must be 0x39"
  );
  static_assert(
    offsetof(SFormationLaneEntry, preferredSpeed) == 0x3C, "SFormationLaneEntry::preferredSpeed offset must be 0x3C"
  );
  static_assert(
    offsetof(SFormationLaneEntry, linkedUnitBackLinkHeadWord) == 0x44,
    "SFormationLaneEntry::linkedUnitBackLinkHeadWord offset must be 0x44"
  );

  struct SFormationOccupiedSlot
  {
    SCoordsVec2 position;      // +0x00
    std::int32_t footprintSize; // +0x08
    std::int32_t laneToken;     // +0x0C
  };
  static_assert(sizeof(SFormationOccupiedSlot) == 0x10, "SFormationOccupiedSlot size must be 0x10");
  static_assert(
    offsetof(SFormationOccupiedSlot, footprintSize) == 0x08, "SFormationOccupiedSlot::footprintSize offset must be 0x08"
  );
  static_assert(offsetof(SFormationOccupiedSlot, laneToken) == 0x0C, "SFormationOccupiedSlot::laneToken offset must be 0x0C");

  struct SFormationCoordCacheNode
  {
    SFormationCoordCacheNode* left;   // +0x00
    SFormationCoordCacheNode* parent; // +0x04
    SFormationCoordCacheNode* right;  // +0x08
    std::uint32_t unitEntityId;       // +0x0C
    SCoordsVec2 position;             // +0x10
    std::uint8_t color;               // +0x18
    std::uint8_t isNil;               // +0x19
    std::uint8_t pad1A[2];            // +0x1A
  };
  static_assert(sizeof(SFormationCoordCacheNode) == 0x1C, "SFormationCoordCacheNode size must be 0x1C");
  static_assert(
    offsetof(SFormationCoordCacheNode, unitEntityId) == 0x0C, "SFormationCoordCacheNode::unitEntityId offset must be 0x0C"
  );
  static_assert(
    offsetof(SFormationCoordCacheNode, position) == 0x10, "SFormationCoordCacheNode::position offset must be 0x10"
  );
  static_assert(
    offsetof(SFormationCoordCacheNode, isNil) == 0x19, "SFormationCoordCacheNode::isNil offset must be 0x19"
  );

  struct SFormationCoordCacheMap
  {
    std::uint32_t allocatorCookie;   // +0x00
    SFormationCoordCacheNode* head;  // +0x04
    std::uint32_t size;              // +0x08
  };
  static_assert(sizeof(SFormationCoordCacheMap) == 0x0C, "SFormationCoordCacheMap size must be 0x0C");
  static_assert(
    offsetof(SFormationCoordCacheMap, head) == 0x04, "SFormationCoordCacheMap::head offset must be 0x04"
  );
  static_assert(
    offsetof(SFormationCoordCacheMap, size) == 0x08, "SFormationCoordCacheMap::size offset must be 0x08"
  );

  using SFormationLinkedUnitRefVec = gpg::fastvector_n<SFormationLinkedUnitRef, 4>;
  using SFormationLaneVec = gpg::fastvector_n<SFormationLaneEntry, 2>;
  using SFormationOccupiedSlotVec = gpg::fastvector_n<SFormationOccupiedSlot, 16>;
  static_assert(sizeof(SFormationLinkedUnitRefVec) == 0x30, "SFormationLinkedUnitRefVec size must be 0x30");
  static_assert(sizeof(SFormationLaneVec) == 0xA8, "SFormationLaneVec size must be 0xA8");
  static_assert(sizeof(SFormationOccupiedSlotVec) == 0x110, "SFormationOccupiedSlotVec size must be 0x110");

  /**
   * VFTABLE: 0x00E1B47C
   * COL:  0x00E70B80
   */
  class CAiFormationInstance : public IFormationInstance
  {
  public:
    /**
     * Address: 0x0059BD60 (FUN_0059BD60, ??3CAiFormationInstance@Moho@@QAE@@Z)
     *
     * What it does:
     * Runs `CAiFormationInstance` teardown and frees storage when bit0 in
     * `deleteFlags` is set.
     *
     * Slot: 0
     */
    void operator_delete(std::int32_t deleteFlags) override;

    /**
     * Address: 0x0059E950 (FUN_0059E950, Moho::CAiFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Reads serialized formation-instance members from archive lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0059E9B0 (FUN_0059E9B0, Moho::CAiFormationInstance::MemberSerialize)
     *
     * What it does:
     * Writes serialized formation-instance members to archive lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00569A10
     * Slot: 1
     * Demangled: Moho::CFormationInstance::Func2 (GetCenter)
     */
    virtual SCoordsVec2* Func2(SCoordsVec2* outCenter) const;

    /**
     * Address: 0x00569A30
     * Slot: 2
     * Demangled: Moho::CFormationInstance::Func3 (SetCenter)
     */
    virtual void Func3(const SCoordsVec2& center);

    /**
     * Address: 0x0056A210
     * Slot: 3
     * Demangled: Moho::CFormationInstance::UnitCount
     */
    virtual int UnitCount() const;

    /**
     * Address: 0x00569BD0
     * Slot: 4
     * Demangled: Moho::CFormationInstance::Func5
     */
    virtual bool Func5(Unit* unit) const;

    /**
     * Address: 0x005669A0
     * Slot: 5
     * Demangled: Moho::CFormationInstance::Func6
     */
    virtual void Func6() = 0;

    /**
     * Address: 0x00569CB0
     * Slot: 6
     * Demangled: Moho::CFormationInstance::GetFormationPosition
     */
    virtual void GetFormationPosition() = 0;

    /**
     * Address: 0x00569EA0
     * Slot: 7
     * Demangled: Moho::CFormationInstance::GetAdjustedFormationPosition
     */
    virtual void GetAdjustedFormationPosition() = 0;

    /**
     * Address: 0x00569F70
     * Slot: 8
     * Demangled: Moho::CFormationInstance::Func9
     */
    virtual void Func9() = 0;

    /**
     * Address: 0x0056A150
     * Slot: 9
     * Demangled: Moho::CFormationInstance::Func10
     */
    virtual void Func10() = 0;

    /**
     * Address: 0x0059A790
     * Slot: 10
     * Demangled: Moho::CAiFormationInstance::Func11
     */
    virtual void Func11() = 0;

    /**
     * Address: 0x0059A7D0
     * Slot: 11
     * Demangled: Moho::CAiFormationInstance::Func12
     */
    virtual void Func12() = 0;

    /**
     * Address: 0x0059A620
     * Slot: 12
     * Demangled: Moho::CAiFormationInstance::CalcFormationSpeed
     */
    virtual void CalcFormationSpeed() = 0;

    /**
     * Address: 0x0059A870
     * Slot: 13
     * Demangled: Moho::CAiFormationInstance::Func14
     */
    virtual void Func14() = 0;

    /**
     * Address: 0x0056A220
     * Slot: 14
     * Demangled: Moho::CFormationInstance::AddUnit
     */
    virtual void AddUnit(Unit* unit) = 0;

    /**
     * Address: 0x0056A300
     * Slot: 15
     * Demangled: Moho::CFormationInstance::RemoveUnit
     */
    virtual void RemoveUnit(Unit* unit) = 0;

    /**
     * Address: 0x0056A440
     * Slot: 16
     * Demangled: Moho::CFormationInstance::Func17
     */
    virtual void Func17() = 0;

    /**
     * Address: 0x0059AE80
     * Slot: 17
     * Demangled: Moho::CAiFormationInstance::Update
     */
    virtual void Update() = 0;

    /**
     * Address: 0x00569B60
     * Slot: 18
     * Demangled: Moho::CFormationInstance::Func19
     */
    virtual void Func19() = 0;

    /**
     * Address: 0x00569BF0
     * Slot: 19
     * Demangled: Moho::CFormationInstance::CommandIsForm
     */
    virtual bool CommandIsForm() const;

    /**
     * Address: 0x00569C20
     * Slot: 20
     * Demangled: Moho::CFormationInstance::Func21
     */
    virtual void Func21() = 0;

    /**
     * Address: 0x0056A4F0
     * Slot: 21
     * Demangled: Moho::CFormationInstance::Func22
     */
    virtual void Func22(float scale);

    /**
     * Address: 0x0056A520
     * Slot: 22
     * Demangled: Moho::CFormationInstance::SetOrientation
     */
    virtual void SetOrientation(const Wm3::Quatf& orientation);

    /**
     * Address: 0x0056A680
     * Slot: 23
     * Demangled: Moho::CFormationInstance::GetOrientation
     */
    virtual Wm3::Quatf* GetOrientation(Wm3::Quatf* outOrientation) const;

    /**
     * Address: 0x00569A00
     * Slot: 24
     * Demangled: Moho::CFormationInstance::GetCommandType
     */
    virtual EUnitCommandType GetCommandType() const;

    /**
     * Address: 0x0059AA20
     * Slot: 25
     * Demangled: Moho::CAiFormationInstance::FindSlotFor
     */
    virtual void FindSlotFor() = 0;

    /**
     * Address: 0x0059A570
     * Slot: 26
     * Demangled: Moho::CAiFormationInstance::Func27
     */
    virtual bool Func27(const SCoordsVec2& position, std::int32_t footprintSize, std::int32_t laneToken) const;

  public:
    std::int32_t mUnitCount;                      // +0x04
    TDatListItem<void, void> mUnitLinkListHead;   // +0x08
    LuaPlus::LuaState* mLuaState;                 // +0x10
    RRuleGameRules* mGameRules;                   // +0x14
    EUnitCommandType mCommandType;                // +0x18
    std::uint32_t mUnknown_0x01C;                 // +0x1C
    SFormationLinkedUnitRefVec mUnits;            // +0x20
    SFormationLaneVec mLanes[2];                  // +0x50
    SFormationOccupiedSlotVec mOccupiedSlots;     // +0x1A0
    SFormationCoordCacheMap mCoordCachePrimary;   // +0x2B0
    SFormationCoordCacheMap mCoordCacheSecondary; // +0x2BC
    Wm3::Vec3f mForwardVector;                    // +0x2C8
    Wm3::Quatf mOrientation;                      // +0x2D4
    Wm3::Quatf mOrientationBaseline;              // +0x2E4
    msvc8::string mScriptName;                    // +0x2F4
    SCoordsVec2 mFormationCenter;                 // +0x310
    float mFormationUpdateScale;                  // +0x318
    std::uint8_t mPlanUpdateRequested;            // +0x31C
    std::uint8_t mPad_0x31D[3];                   // +0x31D
    std::int32_t mMaxUnitSlotCount;               // +0x320
    float mFormationUnitSpacingMultiplier;        // +0x324
    Sim* mSim;                                    // +0x328
    std::uint32_t mUnknown_0x32C;                 // +0x32C
  };

  static_assert(offsetof(CAiFormationInstance, mUnitCount) == 0x04, "CAiFormationInstance::mUnitCount offset must be 0x04");
  static_assert(
    offsetof(CAiFormationInstance, mUnitLinkListHead) == 0x08, "CAiFormationInstance::mUnitLinkListHead offset must be 0x08"
  );
  static_assert(offsetof(CAiFormationInstance, mLuaState) == 0x10, "CAiFormationInstance::mLuaState offset must be 0x10");
  static_assert(
    offsetof(CAiFormationInstance, mCommandType) == 0x18, "CAiFormationInstance::mCommandType offset must be 0x18"
  );
  static_assert(offsetof(CAiFormationInstance, mUnits) == 0x20, "CAiFormationInstance::mUnits offset must be 0x20");
  static_assert(offsetof(CAiFormationInstance, mLanes) == 0x50, "CAiFormationInstance::mLanes offset must be 0x50");
  static_assert(
    offsetof(CAiFormationInstance, mOccupiedSlots) == 0x1A0, "CAiFormationInstance::mOccupiedSlots offset must be 0x1A0"
  );
  static_assert(
    offsetof(CAiFormationInstance, mCoordCachePrimary) == 0x2B0,
    "CAiFormationInstance::mCoordCachePrimary offset must be 0x2B0"
  );
  static_assert(
    offsetof(CAiFormationInstance, mCoordCacheSecondary) == 0x2BC,
    "CAiFormationInstance::mCoordCacheSecondary offset must be 0x2BC"
  );
  static_assert(
    offsetof(CAiFormationInstance, mForwardVector) == 0x2C8, "CAiFormationInstance::mForwardVector offset must be 0x2C8"
  );
  static_assert(
    offsetof(CAiFormationInstance, mOrientation) == 0x2D4, "CAiFormationInstance::mOrientation offset must be 0x2D4"
  );
  static_assert(
    offsetof(CAiFormationInstance, mOrientationBaseline) == 0x2E4,
    "CAiFormationInstance::mOrientationBaseline offset must be 0x2E4"
  );
  static_assert(
    offsetof(CAiFormationInstance, mScriptName) == 0x2F4, "CAiFormationInstance::mScriptName offset must be 0x2F4"
  );
  static_assert(
    offsetof(CAiFormationInstance, mFormationCenter) == 0x310, "CAiFormationInstance::mFormationCenter offset must be 0x310"
  );
  static_assert(
    offsetof(CAiFormationInstance, mFormationUpdateScale) == 0x318,
    "CAiFormationInstance::mFormationUpdateScale offset must be 0x318"
  );
  static_assert(
    offsetof(CAiFormationInstance, mMaxUnitSlotCount) == 0x320,
    "CAiFormationInstance::mMaxUnitSlotCount offset must be 0x320"
  );
  static_assert(
    offsetof(CAiFormationInstance, mFormationUnitSpacingMultiplier) == 0x324,
    "CAiFormationInstance::mFormationUnitSpacingMultiplier offset must be 0x324"
  );
  static_assert(offsetof(CAiFormationInstance, mSim) == 0x328, "CAiFormationInstance::mSim offset must be 0x328");
  static_assert(sizeof(CAiFormationInstance) == 0x330, "CAiFormationInstance size must be 0x330");
} // namespace moho
