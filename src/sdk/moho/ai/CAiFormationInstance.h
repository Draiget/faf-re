#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/ai/IFormationInstance.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/String.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/WeakPtr.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class WriteArchive;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  class IUnit;
  class RRuleGameRules;
  class RRuleGameRulesImpl;
  class Sim;
  struct SOCellPos;
  struct SWeakRefSlot;
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
    std::uint32_t linkedUnitOwnerWord; // +0x10
    std::uint32_t linkedUnitNextWord;  // +0x14
    std::int32_t leaderPriority;       // +0x18
    float formationOffsetX;         // +0x1C
    float formationOffsetZ;         // +0x20
    Wm3::Vec3f formationVector;     // +0x24
    float formationWeight;          // +0x30
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

  struct SUnitOffsetInfo
  {
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x005707B0 (FUN_005707B0, Moho::SUnitOffsetInfo::MemberDeserialize)
     *
     * What it does:
     * Loads unit weak-link lane plus formation offset/vector/speed metadata
     * lanes from archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005708A0 (FUN_005708A0, Moho::SUnitOffsetInfo::MemberSerialize)
     *
     * What it does:
     * Saves unit weak-link lane plus formation offset/vector/speed metadata
     * lanes into archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    WeakPtr<IUnit> mUnit;         // +0x00
    std::int32_t mLeaderPriority; // +0x08
    SCoordsVec2 mOffset;          // +0x0C
    Wm3::Vec3f mDirection;        // +0x14
    float mWeight;                // +0x20
    float mSpeedBandLow;          // +0x24
    float mSpeedBandMid;          // +0x28
    float mSpeedBandHigh;         // +0x2C
  };
  static_assert(sizeof(SUnitOffsetInfo) == 0x30, "SUnitOffsetInfo size must be 0x30");
  static_assert(
    offsetof(SUnitOffsetInfo, mLeaderPriority) == 0x08,
    "SUnitOffsetInfo::mLeaderPriority offset must be 0x08"
  );
  static_assert(offsetof(SUnitOffsetInfo, mOffset) == 0x0C, "SUnitOffsetInfo::mOffset offset must be 0x0C");
  static_assert(offsetof(SUnitOffsetInfo, mDirection) == 0x14, "SUnitOffsetInfo::mDirection offset must be 0x14");
  static_assert(offsetof(SUnitOffsetInfo, mWeight) == 0x20, "SUnitOffsetInfo::mWeight offset must be 0x20");
  static_assert(
    offsetof(SUnitOffsetInfo, mSpeedBandLow) == 0x24, "SUnitOffsetInfo::mSpeedBandLow offset must be 0x24"
  );
  static_assert(
    offsetof(SUnitOffsetInfo, mSpeedBandMid) == 0x28, "SUnitOffsetInfo::mSpeedBandMid offset must be 0x28"
  );
  static_assert(
    offsetof(SUnitOffsetInfo, mSpeedBandHigh) == 0x2C, "SUnitOffsetInfo::mSpeedBandHigh offset must be 0x2C"
  );

  /**
   * RTTI: `.?AUSOffsetInfo@Moho@@` (dumps/rtti_dump_all.hpp).
   *
   * The formation lane entry. This one 0x4C object was modelled twice in this
   * header until now -- once as `SOffsetInfo` (named from the binary's own RTTI
   * type descriptor, with the +0x0C position and the +0x44 weak-link lane
   * resolved) and once as `SFormationLaneEntry` (an invented name, but with the
   * +0x18..+0x40 span resolved to real behaviour from
   * `CAiFormationInstance::RunScript`). Neither name is a placeholder for the
   * other: they are the same bytes.
   *
   * `SOffsetInfo` owns the definition because it is the name the shipped binary
   * carries in RTTI; `SFormationLaneEntry` remains as a thin alias below. The
   * field set is the union of what both models had proven:
   *
   *   - `unitMap` @ +0x00 keeps the intrusive `SFormationLaneUnitMap` typing the
   *     lane-map helpers in CAiFormationInstance.cpp operate on. It is the same
   *     0x0C MSVC8 tree the reflected `map<EntId,SUnitOffsetInfo>` serializer
   *     writes, which is why `MemberSerialize` hands it `this` rather than a
   *     member address.
   *   - `mPos` @ +0x0C resolves what `SFormationLaneEntry` carried as an opaque
   *     `unknown0C[0xC]` span.
   *   - +0x18..+0x40 keep the behaviour-derived names, retyped as `SCoordsVec2`
   *     pairs so the reflected coordinate serializer can address them directly.
   *   - +0x44 keeps the raw intrusive weak-link word pair the lane-relink
   *     helpers manipulate; that 8-byte lane is the binary's `WeakPtr<IUnit>`,
   *     and the serializer reads/writes it through the reflected
   *     `WeakPtr<IUnit>` descriptor at `&linkedUnitBackLinkHeadWord`.
   */
  struct SOffsetInfo
  {
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x00570B60 (FUN_00570B60, Moho::SOffsetInfo::MemberSerialize)
     *
     * What it does:
     * Writes one offset-info payload: the whole unit-offset map, formation
     * position, four 2D coordinate lanes, two flags, two scalars, and the
     * owning unit weak-link.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005709A0 (FUN_005709A0, Moho::SOffsetInfo::MemberDeserialize)
     *
     * What it does:
     * Read mirror of `MemberSerialize`: reads the whole unit-offset map,
     * formation position, four 2D coordinate lanes, two flags, two scalars,
     * and the owning unit weak-link, each through its reflected RTTI serializer.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    SFormationLaneUnitMap unitMap;            // +0x00
    Wm3::Vec3f mPos;                          // +0x0C
    /// Mean XZ of the formation-script slot table, written by
    /// `CAiFormationInstance::RunScript` (0x00567300, phase 5, the
    /// `var_C08.m_next`/`m_state` sums divided by slot count at
    /// 0x0056795C-0x005679D4).
    SCoordsVec2 meanSlotOffset;               // +0x18
    SCoordsVec2 overlapRadius;                // +0x20
    SCoordsVec2 dynamicOffset;                // +0x28
    SCoordsVec2 overlapAnchor;                // +0x30
    std::uint8_t applyDynamicOffset;          // +0x38
    std::uint8_t slotAvailable;               // +0x39
    std::uint8_t pad3A[2];                    // +0x3A
    float preferredSpeed;                     // +0x3C
    float speedAnchor;                        // +0x40
    std::uint32_t linkedUnitBackLinkHeadWord; // +0x44
    std::uint32_t linkedUnitBackLinkNextWord; // +0x48
  };
  static_assert(sizeof(SOffsetInfo) == 0x4C, "SOffsetInfo size must be 0x4C");
  static_assert(offsetof(SOffsetInfo, mPos) == 0x0C, "SOffsetInfo::mPos offset must be 0x0C");
  static_assert(
    offsetof(SOffsetInfo, meanSlotOffset) == 0x18, "SOffsetInfo::meanSlotOffset offset must be 0x18"
  );
  static_assert(offsetof(SOffsetInfo, overlapRadius) == 0x20, "SOffsetInfo::overlapRadius offset must be 0x20");
  static_assert(offsetof(SOffsetInfo, dynamicOffset) == 0x28, "SOffsetInfo::dynamicOffset offset must be 0x28");
  static_assert(offsetof(SOffsetInfo, overlapAnchor) == 0x30, "SOffsetInfo::overlapAnchor offset must be 0x30");
  static_assert(
    offsetof(SOffsetInfo, applyDynamicOffset) == 0x38, "SOffsetInfo::applyDynamicOffset offset must be 0x38"
  );
  static_assert(offsetof(SOffsetInfo, slotAvailable) == 0x39, "SOffsetInfo::slotAvailable offset must be 0x39");
  static_assert(offsetof(SOffsetInfo, preferredSpeed) == 0x3C, "SOffsetInfo::preferredSpeed offset must be 0x3C");
  static_assert(offsetof(SOffsetInfo, speedAnchor) == 0x40, "SOffsetInfo::speedAnchor offset must be 0x40");
  static_assert(
    offsetof(SOffsetInfo, linkedUnitBackLinkHeadWord) == 0x44,
    "SOffsetInfo::linkedUnitBackLinkHeadWord offset must be 0x44"
  );

  /**
   * Thin alias for the single owning `SOffsetInfo` definition above. Kept
   * because the recovered lane-map / relink helpers and the
   * `fastvector<SOffsetInfo>` reflection lane were all written against this
   * name; the binary knows the object only as `Moho::SOffsetInfo`.
   */
  using SFormationLaneEntry = SOffsetInfo;

  /**
   * Static reflection serializer callback for `SOffsetInfo`.
   */
  struct SOffsetInfoSerializer
  {
    /**
     * Address: 0x00566510 (FUN_00566510, Moho::SOffsetInfoSerializer::Serialize)
     *
     * What it does:
     * Reflection save-callback facade for `SOffsetInfo`. Forwards the
     * reflected object pointer to `SOffsetInfo::MemberSerialize`; `version`
     * and the owner-ref lane are unused by the member (mirrors the binary
     * tail call). Signature matches `gpg::RType::save_func_t` since this is
     * stored directly into the reflected serializer helper's callback slot.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00566500 (FUN_00566500, Moho::SOffsetInfoSerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade for `SOffsetInfo`. Forwards the
     * reflected object pointer to `SOffsetInfo::MemberDeserialize`; `version`
     * and the owner-ref lane are unused by the member (mirrors the binary
     * tail call). Signature matches `gpg::RType::load_func_t` since this is
     * stored directly into the reflected serializer helper's callback slot.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  struct SAssignedLocInfo
  {
    /// Element-type reflection cache. The binary keeps this as the
    /// `Moho::SAssignedLocInfo::sType` global that
    /// `RFastVectorType<SAssignedLocInfo>::SerLoad` (0x0056E000) fills on first
    /// use. Static storage, so it does not affect the 0x10 layout below.
    inline static gpg::RType* sType = nullptr;

    SCoordsVec2 position;      // +0x00
    std::int32_t footprintSize; // +0x08
    std::int32_t laneToken;     // +0x0C

    SAssignedLocInfo() = default;

    /**
     * Address: 0x0059A3F0 (FUN_0059A3F0)
     *
     * What it does:
     * Initializes one occupied-slot payload from `(position, footprintSize,
     * laneToken)`.
     */
    SAssignedLocInfo(const SCoordsVec2& slotPosition, std::int32_t footprintSizeValue, std::int32_t laneTokenValue) noexcept;

    /**
     * Address: 0x00570E20 (FUN_00570E20, Moho::SAssignedLocInfo::MemberDeserialize)
     *
     * What it does:
     * Loads one occupied-slot lane: assigned 2D position, footprint size, and
     * lane token.
     */
    static void MemberDeserialize(SAssignedLocInfo* slot, gpg::ReadArchive* archive);

    /**
     * Address: 0x00570E80 (FUN_00570E80, Moho::SAssignedLocInfo::MemberSerialize)
     *
     * What it does:
     * Stores one occupied-slot lane: assigned 2D position, footprint size, and
     * lane token.
     */
    static void MemberSerialize(const SAssignedLocInfo* slot, gpg::WriteArchive* archive);
  };
  static_assert(sizeof(SAssignedLocInfo) == 0x10, "SAssignedLocInfo size must be 0x10");

  /**
   * Address: 0x0056DEC0 (FUN_0056DEC0, gpg::RFastVectorType_SOffsetInfo::SerLoad)
   *
   * What it does:
   * `RIndexed`-owning `SerLoad` callback body for `gpg::fastvector<SOffsetInfo>`
   * reflection. Exposed (not file-local) because
   * `gpg::RFastVectorType<Moho::SOffsetInfo>::Init` (FastVectorUIntReflection.cpp)
   * stores this address into `serLoadFunc_`; the lane-entry default-prototype
   * and resize helpers it needs are file-local to CAiFormationInstance.cpp.
   */
  void LoadFastVectorSOffsetInfo(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  /**
   * Address: 0x0056DF80 (FUN_0056DF80, gpg::RFastVectorType_SOffsetInfo::SerSave)
   *
   * What it does:
   * `RIndexed`-owning `SerSave` callback body for `gpg::fastvector<SOffsetInfo>`
   * reflection. Exposed for the same reason as `LoadFastVectorSOffsetInfo`.
   */
  void SaveFastVectorSOffsetInfo(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  /**
   * Address: 0x0056C1A0 (FUN_0056C1A0, gpg::RFastVectorType_SOffsetInfo::SetCount)
   *
   * What it does:
   * `RIndexed::SetCount` slot body for `gpg::fastvector<SOffsetInfo>`
   * reflection. Exposed for the same reason as `LoadFastVectorSOffsetInfo`.
   */
  void SetFastVectorSOffsetInfoCount(void* laneVector, int count);

  /**
   * Address: 0x0056E000 (FUN_0056E000, gpg::RFastVectorType_SAssignedLocInfo::SerLoad)
   *
   * What it does:
   * `RIndexed`-owning `SerLoad` callback body for
   * `gpg::fastvector<SAssignedLocInfo>` reflection. Exposed so
   * `gpg::RFastVectorType<Moho::SAssignedLocInfo>::Init`
   * (FastVectorUIntReflection.cpp) can store this address into `serLoadFunc_`.
   */
  void LoadFastVectorSAssignedLocInfo(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  /**
   * Address: 0x0056E0A0 (FUN_0056E0A0, gpg::RFastVectorType_SAssignedLocInfo::SerSave)
   *
   * What it does:
   * `RIndexed`-owning `SerSave` callback body for
   * `gpg::fastvector<SAssignedLocInfo>` reflection. Exposed for the same
   * reason as `LoadFastVectorSAssignedLocInfo`.
   */
  void SaveFastVectorSAssignedLocInfo(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  /**
   * Address: 0x0056C3B0 (FUN_0056C3B0, gpg::RFastVectorType_SAssignedLocInfo::SetCount)
   *
   * What it does:
   * `RIndexed::SetCount` slot body for `gpg::fastvector<SAssignedLocInfo>`
   * reflection. Exposed for the same reason as `LoadFastVectorSAssignedLocInfo`.
   */
  void SetFastVectorSAssignedLocInfoCount(void* slotVector, int count);

  /**
   * Thin alias for the single owning `SAssignedLocInfo` definition above.
   * `SAssignedLocInfo` is the name the shipped binary carries in RTTI
   * (`.?AUSAssignedLocInfo@Moho@@`) and the name `Reflection.h` forward-
   * declares for `RRef_SAssignedLocInfo`, which previously left it an
   * incomplete type with no definition anywhere in the tree.
   */
  using SFormationOccupiedSlot = SAssignedLocInfo;
  static_assert(
    offsetof(SAssignedLocInfo, footprintSize) == 0x08, "SAssignedLocInfo::footprintSize offset must be 0x08"
  );
  static_assert(offsetof(SAssignedLocInfo, laneToken) == 0x0C, "SAssignedLocInfo::laneToken offset must be 0x0C");

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
  using SAssignedLocInfoVec = gpg::fastvector_n<SAssignedLocInfo, 16>;
  static_assert(sizeof(SFormationLinkedUnitRefVec) == 0x30, "SFormationLinkedUnitRefVec size must be 0x30");
  static_assert(sizeof(SFormationLaneVec) == 0xA8, "SFormationLaneVec size must be 0xA8");
  static_assert(sizeof(SAssignedLocInfoVec) == 0x110, "SAssignedLocInfoVec size must be 0x110");

  /// Thin alias kept alongside `SFormationOccupiedSlot` for the same reason.
  using SFormationOccupiedSlotVec = SAssignedLocInfoVec;

  /**
   * The transient "candidate unit set" `PreRunScript`/`Setup`/`RunScript`/
   * `UpdateFormation` build and drain (IDA's own local type library names
   * it `gpg::fastvector_n4_WeakPtr_IUnit`). The element is `SWeakRefSlot`
   * (moho/unit/core/Unit.h) rather than `WeakPtr<IUnit>` itself: a slot is
   * bound/queried through `SWeakRefSlot::AsWeakPtr<IUnit>()`, which is the
   * exact same intrusive weak-link relink logic, but keeps the container's
   * own element type POD/trivially-destructible. `WeakPtr<IUnit>` carries a
   * real (non-trivial) unlink destructor; letting the compiler auto-invoke
   * that on an abandoned inline slot after a heap grow (the growth path
   * leaves stale, non-null link bytes in the old inline array, which stays
   * a live C++ subobject) would re-walk an already-spliced chain and can
   * run off its end. Every unlink in this family is therefore the explicit
   * call the binary itself makes.
   */
  using SFormationLayerUnitSet = gpg::fastvector_n<SWeakRefSlot, 4>;

  /**
   * Binds one freshly-linked weak slot to `unit` and appends it to
   * `destination`, matching the binary's inline construct-then-push dance
   * used by every `SFormationLayerUnitSet` builder in the engine: `UpdateFormation`
   * (0x00567F1D..0x00567F94), `PreRunScript`/`Setup` (CAiFormationInstance.cpp),
   * and `CFormation::Finalize` (0x0083836D..0x008383B6, CFormation.cpp) all
   * inline this exact sequence -- construct a temporary bound to `unit`
   * (linking it at the unit's real weak-chain head), push_back it (the
   * relink-aware push steals the link for the new slot), then unlink the
   * temporary, since the container's copy now owns the link going forward.
   * Moved to external linkage (was file-local in CAiFormationInstance.cpp's
   * anonymous namespace) so `CFormation::Finalize` can reuse it instead of
   * duplicating the same intrusive-weak-guard dance.
   */
  void AppendLinkedUnitWeakSlot(SFormationLayerUnitSet& destination, Unit* unit);

  /**
   * Binds one freshly-linked `SFormationLinkedUnitRef` to `target` and appends
   * it to `destination`, matching the same construct-then-push-then-unlink
   * dance as `AppendLinkedUnitWeakSlot` above, but for the `mUnits` lane's own
   * element type: link a temporary into `target`'s owner-chain head
   * (`target + 0x04`, the `IUnit`/`WeakObject` chain head every `IUnit`
   * sub-object carries, regardless of which concrete class it belongs to),
   * push_back it (the copy steals the link), then unlink the now-redundant
   * temporary. `CFormation::Finalize` (0x0083836D..0x008383B6, CFormation.cpp)
   * inlines exactly this sequence to collect its participant set into the
   * `SFormationLinkedUnitRefVec` it hands to `CFormationInstance::Create`.
   */
  void AppendLinkedUnitRef(SFormationLinkedUnitRefVec& destination, IUnit* target);

  /**
   * Unlinks every slot in `container` from its target's real weak chain and
   * resets storage to inline. Matches FUN_0056D3C0 (`sub_56D3C0`) followed by
   * the conditional `operator delete[]`, which every one of
   * `PreRunScript`/`Setup`/`UpdateFormation` inlines at its own scope exit --
   * and which `CFormation::Finalize` (0x00838464..0x008384A3) inlines too, to
   * release the transient participant collection it builds each call. Moved
   * to external linkage for the same reason as `AppendLinkedUnitWeakSlot`
   * above.
   */
  void ClearLinkedUnitWeakSlots(SFormationLayerUnitSet& container);

  /**
   * `SFormationLinkedUnitRefVec` counterpart of `ClearLinkedUnitWeakSlots`
   * above: unlinks every slot in `container` from its unit's real owner-chain
   * (mirroring `AppendLinkedUnitRef`'s own link mechanics) and resets storage
   * to inline. `CFormation::Finalize` calls this on its transient participant
   * collection after handing it to `CFormationInstance::Create` (whose ctor
   * copy-constructs its own `mUnits` from the same elements, re-linking each
   * one into the unit's chain independently).
   */
  void ClearLinkedUnitRefs(SFormationLinkedUnitRefVec& container);

  /**
   * The formation-instance state the binary keeps on `CFormationInstance`,
   * which `CAiFormationInstance` derives from and
   * `CAiFormationInstanceTypeInfo::Init` registers as its base.
   *
   * Sizes pin the split exactly: `CFormationInstanceTypeInfo::Init`
   * (0x0056A780) sets 808 = 0x328, and `CAiFormationInstanceTypeInfo::Init`
   * (0x0059BDE0) sets 816 = 0x330 - the 8-byte delta is `mSim` plus the
   * trailing word, which stay on the derived class.
   *
   * `CFormationInstance::MemberSerialize` (0x005744E0) and
   * `MemberDeserialize` (0x005741D0) are methods on this class and touch
   * only the fields below.
   */
  class CFormationInstance : public IFormationInstance
  {
  public:
    /// Cached reflection descriptor, mirroring the binary's
    /// `Moho::CFormationInstance::sType` global. The serializer helper and
    /// the base registration both read it.
    inline static gpg::RType* sType = nullptr;

    /**
     * No standalone binary address: purely a base-subobject default-init
     * step. `CAiFormationInstance::CAiFormationInstance()` already
     * re-assigns every one of these base fields itself right after the
     * base subobject exists, so this default constructor's own
     * member-default-initialization is always immediately overwritten
     * there -- it exists only so the derived class's no-arg constructor
     * has a base to default-construct.
     */
    CFormationInstance() = default;

    /**
     * Address: 0x005694B0 (FUN_005694B0, Moho::CFormationInstance::CFormationInstance)
     *
     * IDA signature:
     * Moho::CAiFormationInstance *__fastcall Moho::CFormationInstance::CFormationInstance(
     *     Moho::RRuleGameRulesImpl *rules, int commandType, Moho::CFormationInstance *this,
     *     LuaPlus::LuaState *state, gpg::fastvector_n<SFormationLinkedUnitRef, 4> *units,
     *     const char *name, Moho::SCoordsVec2 *coords, Wm3::Quaternionf orientation);
     *
     * What it does:
     * Self-links the intrusive unit-link list node, stamps the Lua state,
     * game rules, and command type, copies the caller's initial unit-ref set
     * into `mUnits`, default-constructs both lane vectors and the
     * occupied-slot vector (implicit, matching the binary's inline
     * `eh vector constructor iterator` + inline-buffer setup), eagerly
     * builds both coord-cache head sentinels, sets the script name and
     * formation center, and -- only when `coords` yields a valid flat
     * ground-plane point -- derives the initial forward vector from
     * `orientation` (same formula as `SetOrientation`), clears the occupied
     * slots and both coord caches back to empty, and runs one
     * `UpdateFormation` pass.
     */
    CFormationInstance(
      RRuleGameRulesImpl* rules,
      EUnitCommandType commandType,
      LuaPlus::LuaState* state,
      const SFormationLinkedUnitRefVec& units,
      const char* name,
      const SCoordsVec2& coords,
      const Wm3::Quatf& orientation
    );

    /**
     * Address: 0x0056A920 (FUN_0056A920, ??2CFormationInstance@Moho@@QAE@@Z,
     * Moho::CFormationInstance::operator new)
     *
     * IDA signature:
     * Moho::CAiFormationInstance *__cdecl Moho::CAiFormationInstance::operator new(
     *     LuaPlus::LuaState *state, Moho::RRuleGameRulesImpl *rules,
     *     Wm3::Vector3f *units, const char *name, Moho::SCoordsVec2 *coords,
     *     float a6, float arg18, float a8, float a9);
     *
     * What it does:
     * Despite the mangled `operator new` name, this is a plain static factory,
     * not a real allocator overload: it calls `::operator new(0x328)` for the
     * base `CFormationInstance` footprint, explicitly invokes the base ctor
     * (0x005694B0) on the fresh storage with `commandType` hardcoded to
     * `UNITCOMMAND_None` (matching the binary's literal `push 0`), and returns
     * the constructed pointer (or `nullptr` if the allocation itself failed).
     * The decompiler's `Wm3::Vector3f *units` parameter typing is a type-
     * confusion artifact (the same one documented on `CFormation::mParticipants`
     * elsewhere in this tree) -- the binary's only caller, `CFormation::Finalize`
     * (0x0083843B), actually passes the address of a transient
     * `gpg::fastvector_n4_WeakPtr_IUnit`-shaped collector, matching
     * `SFormationLinkedUnitRefVec`'s copy-constructing consumer in the base
     * ctor above. The four trailing floats are the caller's `mDirection`
     * quaternion, spread across contiguous stack slots by the by-value ABI;
     * reconstructed here as a single `Wm3::Quatf` parameter for clarity, since
     * both sides of the only real call site pass/consume it as one unit.
     */
    [[nodiscard]] static CFormationInstance* Create(
      RRuleGameRulesImpl* rules,
      LuaPlus::LuaState* state,
      const SFormationLinkedUnitRefVec& units,
      const char* name,
      const SCoordsVec2& coords,
      const Wm3::Quatf& orientation
    );

    /**
     * Address: 0x005741D0 (FUN_005741D0, Moho::CFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Reads the eighteen reflected lanes back in the order MemberSerialize
     * wrote them. The Lua state and game-rules lanes come back through typed
     * pointer readers rather than a raw form.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005744E0 (FUN_005744E0, Moho::CFormationInstance::MemberSerialize)
     *
     * What it does:
     * Writes the reflected base payload, the two owning pointers as unowned
     * tracked references, then every formation lane. mSim and the trailing
     * word are runtime-only and deliberately not written.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00569430 (FUN_00569430, Moho::CFormationInstance::operator delete)
     * Slot: 0
     *
     * IDA signature:
     * Moho::CFormationInstance *__thiscall Moho::CFormationInstance::operator delete(
     *     Moho::CFormationInstance *this, char deleteFlags);
     *
     * What it does:
     * Runs the destructor, then frees storage when bit0 of `deleteFlags` is
     * set -- the real, distinct vtable slot-0 implementation for this class
     * (not inherited from `CAiFormationInstance`'s own slot-0 override,
     * `0x0059BD60`; `CFormationInstance`'s own vtable, `??_7CFormationInstance@Moho@@6B@`
     * at 0xE18E0C, carries its own copy of this slot). This is what makes
     * `CFormationInstance` a concrete, instantiable class in the binary --
     * `CFormationInstance::Create` (0x0056A920) allocates exactly
     * `sizeof(CFormationInstance)` (0x328) and placement-constructs a bare
     * `CFormationInstance`, not a `CAiFormationInstance`.
     */
    void operator_delete(std::int32_t deleteFlags) override;

    std::int32_t mUnitCount;                      // +0x04
    TDatListItem<void, void> mUnitLinkListHead;   // +0x08
    LuaPlus::LuaState* mLuaState;                 // +0x10
    RRuleGameRules* mGameRules;                   // +0x14
    EUnitCommandType mCommandType;                // +0x18
    std::uint32_t mUnknown_0x01C;                 // +0x1C
    SFormationLinkedUnitRefVec mUnits;            // +0x20
    SFormationLaneVec mLanes[2];                  // +0x50
    SAssignedLocInfoVec mOccupiedSlots;     // +0x1A0
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

  public:
    /**
     * Address: 0x00568AC0 (FUN_00568AC0, Moho::CFormationInstance::CleanupFormation)
     *
     * IDA signature:
     * void __usercall Moho::CFormationInstance::CleanupFormation@<eax>(
     *     Moho::CFormationInstance *this@<eax>);
     *
     * What it does:
     * Resets transient formation-plan state: clears the occupied-slot vector to
     * its inline buffer, resets both coord-cache RB-trees in place (keeping the
     * head sentinel), zeroes the orientation-baseline quaternion, and tears down
     * each of the two lane vectors (destroying every lane entry's unit map and
     * unlinking its weak back-link words) before resetting them to inline.
     */
    void CleanupFormation();

    /**
     * Address: 0x0056A6B0 (FUN_0056A6B0, Moho::CFormationInstance::Update)
     * Slot: 17
     *
     * What it does:
     * When a plan update is pending, clears the pending flag and runs one
     * cleanup+rebuild pass: drops dead unit links, resets transient formation
     * state, and rebuilds the formation plan. `CAiFormationInstance` overrides
     * this slot with its own, much larger update pass (`FUN_0059AE80`); this
     * base implementation is the one every other `CFormationInstance`-rooted
     * override falls back to.
     */
    virtual void Update();

    /**
     * Address: 0x00569880 (FUN_00569880, Moho::CFormationInstance::~CFormationInstance)
     *
     * What it does:
     * Resets the transient formation plan, then lets the members and the
     * IFormationInstance base tear themselves down.
     */
    ~CFormationInstance();
  };

  static_assert(sizeof(CFormationInstance) == 0x328, "CFormationInstance size must be 0x328");

  /**
   * VFTABLE: 0x00E1B47C
   * COL:  0x00E70B80
   */
  class CAiFormationInstance : public CFormationInstance
  {
  public:
    /**
     * Mangled: ??0CAiFormationInstance@Moho@@QAE@@Z
     *
     * A standalone out-of-line body exists at 0x0059A470 but is unreferenced
     * (zero code/data/vtable xrefs); see the .cpp definition for the full
     * evidence note. The recovered behavior is proven from the identical
     * sequence inlined into `operator new` (0x0059D0F0).
     *
     * What it does:
     * Runs the base `CFormationInstance` constructor (0x005692D0: formation
     * intrusive links, lane vectors, coord-cache map heads, and default
     * scalar state), then publishes the `CAiFormationInstance` vtable and
     * clears the owning-`Sim` back-reference.
     */
    CAiFormationInstance();

    /**
     * Address: 0x0059A500 (FUN_0059A500, ??1CAiFormationInstance@Moho@@QAE@@Z)
     * Mangled: ??1CAiFormationInstance@Moho@@QAE@@Z
     *
     * What it does:
     * Tears down transient formation caches/lane state, unregisters this
     * instance from the owning formation DB, then tears down unit-link lanes.
     */
    ~CAiFormationInstance();

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
     * Address: 0x00569A10 (FUN_00569A10)
     * Slot: 1
     * Demangled: Moho::CFormationInstance::Func2 (GetCenter)
     */
    virtual SCoordsVec2* Func2(SCoordsVec2* outCenter) const;

    /**
     * Address: 0x00569A30 (FUN_00569A30)
     * Slot: 2
     * Demangled: Moho::CFormationInstance::Func3 (SetCenter)
     */
    virtual void Func3(const SCoordsVec2& center);

    /**
     * Address: 0x0056A210 (FUN_0056A210)
     * Slot: 3
     * Demangled: Moho::CFormationInstance::UnitCount
     */
    virtual int UnitCount() const;

    /**
     * Address: 0x00569BD0 (FUN_00569BD0)
     *
     * IDA signature:
     * int __stdcall Moho::CFormationInstance::GetLayer(Moho::Unit *unit);
     *
     * What it does:
     * Returns the formation layer this unit belongs to: `1` for air-motion
     * blueprints, `0` for everything else. The result indexes `mLanes`.
     * `PreRunScript` (0x00566B10) dispatches this through slot 4 and compares
     * the result against the layer being built, which is where the name comes
     * from.
     *
     * Slot: 4
     * Demangled: Moho::CFormationInstance::GetLayer
     */
    virtual std::int32_t GetLayer(Unit* unit) const;

    /**
     * Address: 0x005669A0 (FUN_005669A0)
     * Slot: 5
     * Demangled: Moho::CFormationInstance::Func6
     */
    virtual SFormationLaneEntry* Func6(Unit* unit);

    /**
     * Address: 0x00569CB0 (FUN_00569CB0)
     * Slot: 6
     * Demangled: Moho::CFormationInstance::GetFormationPosition
     */
    virtual SCoordsVec2* GetFormationPosition(SCoordsVec2* dest, Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x00569EA0 (FUN_00569EA0)
     * Slot: 7
     * Demangled: Moho::CFormationInstance::GetAdjustedFormationPosition
     */
    virtual SOCellPos* GetAdjustedFormationPosition(SOCellPos* dest, Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x00569F70 (FUN_00569F70)
     * Slot: 8
     * Demangled: Moho::CFormationInstance::Func9
     */
    virtual SCoordsVec2* Func9(SCoordsVec2* dest, Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x0056A150 (FUN_0056A150)
     * Slot: 9
     * Demangled: Moho::CFormationInstance::Func10
     */
    virtual Wm3::Vec3f* Func10(Wm3::Vec3f* out, Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x0059A790 (FUN_0059A790)
     * Slot: 10
     * Demangled: Moho::CAiFormationInstance::Func11
     */
    virtual float Func11(Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x0059A7D0 (FUN_0059A7D0)
     * Slot: 11
     * Demangled: Moho::CAiFormationInstance::Func12
     */
    virtual std::int32_t Func12(Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x0059A620 (FUN_0059A620)
     * Slot: 12
     * Demangled: Moho::CAiFormationInstance::CalcFormationSpeed
     */
    virtual float CalcFormationSpeed(Unit* unit, float* speedScaleOut, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x0059A870 (FUN_0059A870)
     * Slot: 13
     * Demangled: Moho::CAiFormationInstance::Func14
     */
    virtual Unit* Func14(Unit* unit, SFormationLaneEntry* laneEntry);

    /**
     * Address: 0x0056A220 (FUN_0056A220)
     * Slot: 14
     * Demangled: Moho::CFormationInstance::AddUnit
     */
    virtual void AddUnit(Unit* unit);

    /**
     * Address: 0x0056A300 (FUN_0056A300)
     * Slot: 15
     * Demangled: Moho::CFormationInstance::RemoveUnit
     */
    virtual void RemoveUnit(Unit* unit);

    /**
     * Address: 0x0056A440 (FUN_0056A440)
     * Slot: 16
     * Demangled: Moho::CFormationInstance::Func17
     */
    virtual bool Func17(Unit* unit, bool checkAll) const;

    /**
     * Address: 0x0059AE80 (FUN_0059AE80, Moho::CAiFormationInstance::Update)
     *
     * What it does:
     * Advances the active formation lanes, refreshes lane leaders, and
     * dispatches the formation update event when the lane state becomes
     * actionable.
     * Slot: 17
     * Demangled: Moho::CAiFormationInstance::Update
     */
    virtual void Update();

    /**
     * Address: 0x00569B60 (FUN_00569B60)
     * Slot: 18
     * Demangled: Moho::CFormationInstance::Func19
     */
    virtual Wm3::Vec3f* Func19(Wm3::Vec3f* out, Unit* unit) const;

    /**
     * Address: 0x00569BF0 (FUN_00569BF0)
     * Slot: 19
     * Demangled: Moho::CFormationInstance::CommandIsForm
     */
    virtual bool CommandIsForm() const;

    /**
     * Address: 0x00569C20 (FUN_00569C20)
     * Slot: 20
     * Demangled: Moho::CFormationInstance::Func21
     */
    virtual bool Func21(Unit* unit) const;

    /**
     * Address: 0x0056A4F0 (FUN_0056A4F0)
     * Slot: 21
     * Demangled: Moho::CFormationInstance::Func22
     */
    virtual void Func22(float scale);

    /**
     * Address: 0x0056A520 (FUN_0056A520)
     * Slot: 22
     * Demangled: Moho::CFormationInstance::SetOrientation
     */
    virtual void SetOrientation(const Wm3::Quatf& orientation);

    /**
     * Address: 0x0056A680 (FUN_0056A680)
     * Slot: 23
     * Demangled: Moho::CFormationInstance::GetOrientation
     */
    virtual Wm3::Quatf* GetOrientation(Wm3::Quatf* outOrientation) const;

    /**
     * Address: 0x00569A00 (FUN_00569A00)
     * Slot: 24
     * Demangled: Moho::CFormationInstance::GetCommandType
     */
    virtual EUnitCommandType GetCommandType() const;

    /**
     * Address: 0x0059AA20 (FUN_0059AA20)
     * Slot: 25
     * Demangled: Moho::CAiFormationInstance::FindSlotFor
     *
     * What it does:
     * Resolves one free formation slot near `pos`, records the chosen occupied
     * slot, and falls back to current unit position when no free slot can be
     * found.
     */
    virtual SCoordsVec2* FindSlotFor(SCoordsVec2* dest, const SCoordsVec2* pos, Unit* unit);

    /**
     * Address: 0x0059A570 (FUN_0059A570)
     * Slot: 26
     * Demangled: Moho::CAiFormationInstance::Func27
     */
    virtual bool Func27(const SCoordsVec2& position, std::int32_t footprintSize, std::int32_t laneToken) const;

    /**
     * Address: 0x005691E0 (FUN_005691E0, Moho::CAiFormationInstance::RemoveDeadUnits)
     *
     * What it does:
     * Removes null/dead/destroy-queued units from linked formation unit refs
     * and reports whether `checkForUnit` remains live in the set.
     */
    bool RemoveDeadUnits(Unit* checkForUnit);

    /**
     * Address: 0x00566A30 (FUN_00566A30, Moho::CAiFormationInstance::ComputeRunScriptOffset)
     *
     * What it does:
     * Scales one script-local formation offset, optionally rotates it by the
     * current formation orientation, then multiplies by slot-span scale.
     */
    SCoordsVec2* ComputeRunScriptOffset(const SCoordsVec2* sourceOffset, SCoordsVec2* dest) const;

    /**
     * Address: 0x00566B10 (FUN_00566B10, Moho::CAiFormationInstance::PreRunScript)
     *
     * IDA signature:
     * void __userpurge Moho::CAiFormationInstance::PreRunScript(
     *     gpg::fastvector_n4_WeakPtr_IUnit *layerUnitsOut@<ebx>,
     *     Moho::CAiFormationInstance *this,
     *     gpg::fastvector_n4_WeakPtr_IUnit *candidateUnits, int layerIndex);
     *
     * What it does:
     * Partitions the shared candidate-unit list by `GetLayer()`: every unit
     * whose layer matches `layerIndex` is moved out of `candidateUnits` into
     * `layerUnitsOut` (erased from the shared list so a later layer's pass
     * never sees it again); units belonging to a different layer are left
     * in place.
     */
    void PreRunScript(SFormationLayerUnitSet& layerUnitsOut, SFormationLayerUnitSet& candidateUnits, std::int32_t layerIndex);

    /**
     * Address: 0x00568820 (FUN_00568820, Moho::CAiFormationInstance::Setup)
     *
     * IDA signature:
     * void __userpurge Moho::CAiFormationInstance::Setup(
     *     int layerIndex@<edi>, Moho::CAiFormationInstance *this,
     *     gpg::fastvector_n4_WeakPtr_IUnit *candidateUnits);
     *
     * What it does:
     * Claims this layer's units out of the shared candidate list via
     * `PreRunScript`, runs the formation script over them via `RunScript`
     * when any were claimed, then releases the per-layer scratch list.
     */
    void Setup(SFormationLayerUnitSet& candidateUnits, std::int32_t layerIndex);

    /**
     * Address: 0x00567300 (FUN_00567300, Moho::CAiFormationInstance::RunScript)
     *
     * ASM-only recovery (no `.c` decompile); see
     * `decomp/recovery/escalations/FUN_00567300.md` for the stack-frame
     * decode key, EH funclet table, and the seven-phase behavior this
     * follows. 1010 instructions.
     *
     * IDA signature:
     * void __stdcall Moho::CAiFormationInstance::RunScript(
     *     gpg::fastvector_n4_WeakPtr_IUnit *units, std::int32_t layerIndex);
     *
     * What it does:
     * Builds a Lua unit table from `units` and calls `Moho::FORMATION_RunScript`;
     * early-exits if it produced no slots. Computes the mean unit position,
     * builds one relative-position descriptor per unit (optionally rotated by
     * `mOrientationBaseline`) while folding the lane's `preferredSpeed`,
     * computes slot-table span/mean statistics, builds one scored candidate
     * per (slot, unit) pair whose category matches and sorts them by squared
     * distance, then greedily assigns each candidate's nearest still-free
     * unit into the new lane entry's `unitMap` (warning on duplicate
     * assignment), calls `RemoveUnit` for anything left unassigned, and
     * appends the finished lane entry to `mLanes[layerIndex]`.
     */
    void RunScript(SFormationLayerUnitSet& units, std::int32_t layerIndex);

    /**
     * Address: 0x00568CA0 (FUN_00568CA0, Moho::CAiFormationInstance::UpdateFormation)
     *
     * What it does:
     * Snapshots every live, mobile, non-building, non-destroy-queued linked
     * unit into a weak-slot scratch list, accumulates the formation's mean
     * facing and each unit's max footprint size, refreshes
     * `mOrientationChng` when the facing changed enough, then rebuilds each
     * formation layer in turn: releases the previous lane entries for that
     * layer and calls `Setup` to claim and script this layer's units. After
     * both layers rebuild, merges overlapping lane bands for `Form*`
     * commands and broadcasts `FORMATIONSTATUS_FormationUpdated`.
     */
    void UpdateFormation();

  public:
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

  /**
   * Address: 0x005661C0 (FUN_005661C0, preregister_SUnitOffsetInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SUnitOffsetInfo`.
   */
  [[nodiscard]] gpg::RType* preregister_SUnitOffsetInfoTypeInfo();

  /**
   * Address: 0x005665B0 (FUN_005665B0, preregister_IFormationInstanceTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `IFormationInstance`.
   */
  [[nodiscard]] gpg::RType* preregister_IFormationInstanceTypeInfo();

  /**
   * Address: 0x00571A70 (FUN_00571A70, preregister_RMapType_EntId_SUnitOffsetInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `std::map<EntId,SUnitOffsetInfo>`.
   */
  [[nodiscard]] gpg::RType* preregister_RMapType_EntId_SUnitOffsetInfo();

  /**
   * Address: 0x00571AD0 (FUN_00571AD0, preregister_RBroadcasterRType_EFormationdStatus)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `Broadcaster<EFormationdStatus>`.
   */
  [[nodiscard]] gpg::RType* preregister_RBroadcasterRType_EFormationdStatus();

  /**
   * Address: 0x00571B30 (FUN_00571B30, preregister_RListenerRType_EFormationdStatus)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `Listener<EFormationdStatus>`.
   */
  [[nodiscard]] gpg::RType* preregister_RListenerRType_EFormationdStatus();

  /**
   * Address: 0x00571CE0 (FUN_00571CE0, preregister_RMapType_EntId_SCoordsVec2)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `std::map<EntId,SCoordsVec2>`.
   */
  [[nodiscard]] gpg::RType* preregister_RMapType_EntId_SCoordsVec2();

  /**
   * Address: 0x00569CA0 (FUN_00569CA0, Moho::CFormationInstance::CalcFormationSpeed)
   *
   * What it does:
   * Represents the base-formation default speed stub lane used by
   * `CFormationInstance` vftables; returns `0.0f`.
   */
  float CFormationInstanceCalcFormationSpeedFallback(Unit* unit, float* speedScaleOut, SFormationLaneEntry* laneEntry);
} // namespace moho
