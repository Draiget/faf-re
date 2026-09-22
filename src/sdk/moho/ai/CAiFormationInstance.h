#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/String.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/Broadcaster.h"
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
  class Sim;
  struct SOCellPos;
  class Unit;

  /// `Moho::EntId` is the 32-bit entity id `Entity.h` defines; restated here so
  /// the map keys below do not drag the whole entity header into every
  /// formation consumer.
  typedef std::int32_t EntId;

  /**
   * RTTI: `.?AUSUnitOffsetInfo@Moho@@` (dumps/rtti_dump_all.hpp).
   *
   * One unit's slot inside a formation group: the mapped value of
   * `SOffsetInfo::mUnitOffsets`, keyed by the unit's entity id. `RunScript`
   * (0x00567300, 0x00567EED-0x00567FA3) fills one on the stack per assigned
   * candidate -- `mUnit` bound to the unit, `mLeaderPriority` from the running
   * assignment counter, `mOffset` from the scored slot, `mTargetPos` zero,
   * `mHeadingAngle` +inf, both distances zero, `mWeight` from the script slot
   * -- and stores it with `mUnitOffsets[entityId] = info`. `Update`
   * (0x0059AE80) then rewrites `mTargetPos`, `mHeadingAngle` and both
   * distances every tick.
   *
   * The compiler-generated special members are all real binary functions:
   *   - Address: 0x005683F0 (FUN_005683F0) copy constructor -- splices the
   *     copy's `mUnit` into the source unit's weak chain, then copies the ten
   *     remaining words;
   *   - Address: 0x00568490 (FUN_00568490) copy assignment -- `mUnit`'s
   *     relinking `operator=` followed by the same ten-word copy;
   *   - Address: 0x00568450 (the `loc_568450` EH funclet target in
   *     `RunScript`) destructor -- `~WeakPtr<IUnit>` unlinking `mUnit`.
   * None of them has a source line of its own; `WeakPtr<IUnit>`'s members
   * produce them.
   */
  struct SUnitOffsetInfo
  {
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x005707B0 (FUN_005707B0, Moho::SUnitOffsetInfo::MemberDeserialize)
     *
     * What it does:
     * Loads the unit weak-link, leader priority, offset, target position and
     * the four trailing floats from archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005708A0 (FUN_005708A0, Moho::SUnitOffsetInfo::MemberSerialize)
     *
     * What it does:
     * Saves the unit weak-link, leader priority, offset, target position and
     * the four trailing floats into archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /// The unit this slot belongs to.
    WeakPtr<IUnit> mUnit;         // +0x00
    /// Assignment rank handed out by `RunScript`; `SOffsetInfo::GetLeader`
    /// picks the live unit with the highest one.
    std::int32_t mLeaderPriority; // +0x08
    /// Slot offset from the formation centre (`RunScript` phase 7), already
    /// scaled and rotated by `ComputeRunScriptOffset`.
    SCoordsVec2 mOffset;          // +0x0C
    /// Smoothed world-space position the unit is steering for
    /// (`Update`, 0x0059AE90 onward); zero until the first update, which
    /// is why `GetTargetPosition` falls back to the unit's own position.
    Wm3::Vec3f mTargetPos;        // +0x14
    /// Smoothed heading correction (radians) applied to the slot offset when
    /// the leader is off its own slot; +inf until first computed.
    float mHeadingAngle;          // +0x20
    /// Distance from the unit to `mTargetPos` this tick; `CalcFormationSpeed`
    /// compares it against `SOffsetInfo::mAvgDistToTarget` to speed
    /// stragglers up and slow the leaders down.
    float mDistToTarget;          // +0x24
    /// Distance from this unit's slot position to the leader's;
    /// `GetDistFromLeader` hands it to `Unit::UpdateInfoCache` as the unit's
    /// formation ordering metric.
    float mDistFromLeader;        // +0x28
    /// The formation script's weight for the slot (`SFormationScriptSlot::
    /// mWeight`); `GetPriority` turns it into the unit's integer priority.
    float mWeight;                // +0x2C
  };
  static_assert(sizeof(SUnitOffsetInfo) == 0x30, "SUnitOffsetInfo size must be 0x30");
  static_assert(offsetof(SUnitOffsetInfo, mLeaderPriority) == 0x08, "SUnitOffsetInfo::mLeaderPriority offset must be 0x08");
  static_assert(offsetof(SUnitOffsetInfo, mOffset) == 0x0C, "SUnitOffsetInfo::mOffset offset must be 0x0C");
  static_assert(offsetof(SUnitOffsetInfo, mTargetPos) == 0x14, "SUnitOffsetInfo::mTargetPos offset must be 0x14");
  static_assert(offsetof(SUnitOffsetInfo, mHeadingAngle) == 0x20, "SUnitOffsetInfo::mHeadingAngle offset must be 0x20");
  static_assert(offsetof(SUnitOffsetInfo, mDistToTarget) == 0x24, "SUnitOffsetInfo::mDistToTarget offset must be 0x24");
  static_assert(offsetof(SUnitOffsetInfo, mDistFromLeader) == 0x28, "SUnitOffsetInfo::mDistFromLeader offset must be 0x28");
  static_assert(offsetof(SUnitOffsetInfo, mWeight) == 0x2C, "SUnitOffsetInfo::mWeight offset must be 0x2C");

  /**
   * RTTI: `.?AUSOffsetInfo@Moho@@` (dumps/rtti_dump_all.hpp).
   *
   * One formation group: every unit of one layer that a single
   * `FORMATION_RunScript` pass placed, plus the group's bounding box, speed
   * and cached leader. `CFormationInstance::mOffsetInfo[layer]` holds one
   * vector of these per layer.
   *
   * `mUnitOffsets` is the `std::map<EntId,SUnitOffsetInfo>` the binary's own
   * reflection names (`preregister_RMapType_EntId_SUnitOffsetInfo`,
   * 0x00571A70); its node is 0x44 bytes with the colour/nil pair at +0x40/+0x41,
   * exactly `msvc8::detail::rb_node<std::pair<const EntId, SUnitOffsetInfo>>`.
   *
   * The compiler-generated special members are all real binary functions and
   * fall straight out of the member types:
   *   - Address: 0x0056CAA0 (FUN_0056CAA0) copy constructor -- stands a fresh
   *     map head up and clones the source tree (`0x0056CC50`, the
   *     `_Tree(const _Tree&)` emission cited on `msvc8::detail::rb_tree`),
   *     copies the scalar fields, then splices `mLeader` into the source
   *     leader's weak chain;
   *   - Address: 0x00573270 (FUN_00573270) copy assignment -- the map's
   *     clear-and-clone `operator=`, the scalar copies, then `mLeader`'s
   *     relinking `operator=`;
   *   - Address: 0x00568360 (FUN_00568360) destructor -- unlinks `mLeader`,
   *     erases the map's whole range and frees its head.
   * Only the default constructor below has a body of its own.
   */
  struct SOffsetInfo
  {
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x00565AB0 (FUN_00565AB0, Moho::SOffsetInfo::SOffsetInfo)
     *
     * What it does:
     * Default state for a fresh group: empty unit map, zero position,
     * centre and offsets, a 2x2 minimum extent, both flags clear, an
     * unbounded speed (+inf, the identity for the min-reduction `RunScript`
     * performs), zero average distance and no leader.
     */
    SOffsetInfo();

    /**
     * Address: 0x00570B60 (FUN_00570B60, Moho::SOffsetInfo::MemberSerialize)
     *
     * What it does:
     * Writes one group: the whole unit map, position, the four coordinate
     * pairs, both flags, both scalars and the leader weak-link, each through
     * its reflected RTTI serializer.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005709A0 (FUN_005709A0, Moho::SOffsetInfo::MemberDeserialize)
     *
     * What it does:
     * Read mirror of `MemberSerialize`.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005688C0 (FUN_005688C0, sub_5688C0)
     *
     * What it does:
     * True when this group's bounding box (`mCenter` +/- `mExtent`) overlaps
     * `other`'s on both axes.
     */
    [[nodiscard]] bool Overlaps(const SOffsetInfo& other) const noexcept;

    /**
     * Address: 0x0059A300 (FUN_0059A300, sub_59A300)
     *
     * IDA signature:
     * _DWORD *__thiscall sub_59A300(_DWORD *this);
     *
     * What it does:
     * Returns the group's leader. When no leader is cached yet, walks the
     * unit map for the live unit with the highest `mLeaderPriority`, binds
     * `mLeader` to it and returns it.
     */
    [[nodiscard]] Unit* GetLeader();

    /// The placed units of this group, keyed by entity id.
    msvc8::map<EntId, SUnitOffsetInfo> mUnitOffsets; // +0x00
    /// Zeroed by the constructor and copied by the special members; nothing
    /// else in the binary writes it.
    Wm3::Vec3f mPos;                                 // +0x0C
    /// Mean of the script's slot offsets (`RunScript` phase 5).
    SCoordsVec2 mSlotCenter;                         // +0x18
    /// Mean unit position when the script ran; the centre of the overlap box.
    SCoordsVec2 mCenter;                             // +0x20
    /// Added to every slot offset while `mUseDynamicOffset` is set
    /// (`GetFormationPosition`, `GetOffsetPosition`). No writer in the binary
    /// beyond the constructor and the copy members, so it stays zero in the
    /// shipped game.
    SCoordsVec2 mDynamicOffset;                      // +0x28
    /// Half-size of the overlap box: `max(2, slot span)` from `RunScript`,
    /// raised to at least 10 when overlapping groups are merged.
    SCoordsVec2 mExtent;                             // +0x30
    bool mUseDynamicOffset;                          // +0x38
    /// Set by `CAiFormationInstance::Update` once every unit is close enough
    /// to its slot; `IsInFormation` reports it to the units.
    bool mInFormation;                               // +0x39
    /// Formation speed: the slowest unit's max speed times 0.85, reduced
    /// further when overlapping groups are merged. `CalcFormationSpeed`
    /// returns it.
    float mSpeed;                                    // +0x3C
    /// Midpoint of the smallest and largest `SUnitOffsetInfo::mDistToTarget`
    /// this tick; the reference `CalcFormationSpeed` scales each unit's speed
    /// against.
    float mAvgDistToTarget;                          // +0x40
    /// Cached leader, resolved lazily by `GetLeader`.
    WeakPtr<IUnit> mLeader;                          // +0x44
  };
  static_assert(sizeof(SOffsetInfo) == 0x4C, "SOffsetInfo size must be 0x4C");
  static_assert(offsetof(SOffsetInfo, mPos) == 0x0C, "SOffsetInfo::mPos offset must be 0x0C");
  static_assert(offsetof(SOffsetInfo, mSlotCenter) == 0x18, "SOffsetInfo::mSlotCenter offset must be 0x18");
  static_assert(offsetof(SOffsetInfo, mCenter) == 0x20, "SOffsetInfo::mCenter offset must be 0x20");
  static_assert(offsetof(SOffsetInfo, mDynamicOffset) == 0x28, "SOffsetInfo::mDynamicOffset offset must be 0x28");
  static_assert(offsetof(SOffsetInfo, mExtent) == 0x30, "SOffsetInfo::mExtent offset must be 0x30");
  static_assert(offsetof(SOffsetInfo, mUseDynamicOffset) == 0x38, "SOffsetInfo::mUseDynamicOffset offset must be 0x38");
  static_assert(offsetof(SOffsetInfo, mInFormation) == 0x39, "SOffsetInfo::mInFormation offset must be 0x39");
  static_assert(offsetof(SOffsetInfo, mSpeed) == 0x3C, "SOffsetInfo::mSpeed offset must be 0x3C");
  static_assert(offsetof(SOffsetInfo, mAvgDistToTarget) == 0x40, "SOffsetInfo::mAvgDistToTarget offset must be 0x40");
  static_assert(offsetof(SOffsetInfo, mLeader) == 0x44, "SOffsetInfo::mLeader offset must be 0x44");

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
     * and the owner-ref are unused by the member (mirrors the binary tail
     * call). Signature matches `gpg::RType::save_func_t` since this is
     * stored directly into the reflected serializer helper's callback slot.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00566500 (FUN_00566500, Moho::SOffsetInfoSerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade for `SOffsetInfo`. Forwards the
     * reflected object pointer to `SOffsetInfo::MemberDeserialize`; `version`
     * and the owner-ref are unused by the member (mirrors the binary tail
     * call). Signature matches `gpg::RType::load_func_t` since this is
     * stored directly into the reflected serializer helper's callback slot.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  /**
   * RTTI: `.?AUSAssignedLocInfo@Moho@@`.
   *
   * One slot `FindSlotFor` has already handed out this plan: the position,
   * the footprint size it was reserved for and the layer it belongs to.
   * `PosIsFree` scans them so two units of one layer never get overlapping
   * slots.
   */
  struct SAssignedLocInfo
  {
    /// Element-type reflection cache. The binary keeps this as the
    /// `Moho::SAssignedLocInfo::sType` global. It is filled once, at static
    /// initialization, by `preregister_SAssignedLocInfoTypeInfo` (0x005667A0,
    /// `.CRT$XCL`-phase, run from `sub_BCABC0`/`__xc_a`) rather than lazily by
    /// `RFastVectorType<SAssignedLocInfo>::SerLoad` (0x0056E000): that
    /// consumer calls `gpg::LookupRType`, which throws if the type was not
    /// already preregistered, so the real binary always publishes this
    /// descriptor before any `SerLoad`/`SerSave` call can run. Static
    /// storage, so it does not affect the 0x10 layout below.
    inline static gpg::RType* sType = nullptr;

    SCoordsVec2 mPos;     // +0x00
    /// Address: 0x0059C790 (FUN_0059C790) -- the compiler's out-of-line
    /// `int* <- mSize` accessor emission for this field. It has no caller in
    /// the shipped binary (`PosIsFree` reads the field inline; the emission
    /// is an ICF twin of a dozen identical field readers), so it anchors on
    /// the field rather than on a function.
    std::int32_t mSize;   // +0x08
    /// Address: 0x0059C7A0 (FUN_0059C7A0) -- the same caller-less accessor
    /// emission for this field.
    std::int32_t mLayer;  // +0x0C

    SAssignedLocInfo() = default;

    /**
     * Address: 0x0059A3F0 (FUN_0059A3F0)
     *
     * What it does:
     * Initializes one assigned slot from `(position, size, layer)`.
     */
    SAssignedLocInfo(const SCoordsVec2& position, std::int32_t size, std::int32_t layer) noexcept;

    /**
     * Address: 0x00570E20 (FUN_00570E20, Moho::SAssignedLocInfo::MemberDeserialize)
     *
     * What it does:
     * Loads one assigned slot: position, footprint size and layer.
     */
    static void MemberDeserialize(SAssignedLocInfo* slot, gpg::ReadArchive* archive);

    /**
     * Address: 0x00570E80 (FUN_00570E80, Moho::SAssignedLocInfo::MemberSerialize)
     *
     * What it does:
     * Stores one assigned slot: position, footprint size and layer.
     */
    static void MemberSerialize(const SAssignedLocInfo* slot, gpg::WriteArchive* archive);
  };
  static_assert(sizeof(SAssignedLocInfo) == 0x10, "SAssignedLocInfo size must be 0x10");
  static_assert(offsetof(SAssignedLocInfo, mSize) == 0x08, "SAssignedLocInfo::mSize offset must be 0x08");
  static_assert(offsetof(SAssignedLocInfo, mLayer) == 0x0C, "SAssignedLocInfo::mLayer offset must be 0x0C");

  static_assert(sizeof(gpg::fastvector_n<WeakPtr<IUnit>, 4>) == 0x30, "fastvector_n<WeakPtr<IUnit>,4> size must be 0x30");
  static_assert(sizeof(gpg::fastvector_n<SOffsetInfo, 2>) == 0xA8, "fastvector_n<SOffsetInfo,2> size must be 0xA8");
  static_assert(sizeof(gpg::fastvector_n<SAssignedLocInfo, 16>) == 0x110, "fastvector_n<SAssignedLocInfo,16> size must be 0x110");
  static_assert(sizeof(msvc8::map<EntId, SUnitOffsetInfo>) == 0x0C, "map<EntId,SUnitOffsetInfo> size must be 0x0C");
  static_assert(sizeof(msvc8::map<EntId, SCoordsVec2>) == 0x0C, "map<EntId,SCoordsVec2> size must be 0x0C");

  /**
   * Address: 0x0056DEC0 (FUN_0056DEC0, gpg::RFastVectorType_SOffsetInfo::SerLoad)
   *
   * What it does:
   * `RIndexed`-owning `SerLoad` callback body for `gpg::fastvector<SOffsetInfo>`
   * reflection. Exposed (not file-local) because
   * `gpg::RFastVectorType<Moho::SOffsetInfo>::Init` (FastVectorUIntReflection.cpp)
   * stores this address into `serLoadFunc_`.
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
  void SetFastVectorSOffsetInfoCount(void* vector, int count);

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
  void SetFastVectorSAssignedLocInfoCount(void* vector, int count);

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
   * RTTI (`.?AVCFormationInstance@Moho@@`) lists the bases as
   * `IFormationInstance` (mdisp 0), `Moho::CountedObject` (mdisp 0) and
   * `Broadcaster<EFormationdStatus>` (mdisp 8): the two words right after the
   * vtable are the counted-object reference count and the status-listener
   * ring, and both belong to `IFormationInstance`'s own two bases. This class
   * therefore starts at +0x10, which is exactly what
   * `offsetof(.., mState) == 0x10` below re-checks from the far side.
   *
   * Member names follow the shipped symbol set the FAF IDB carries for this
   * class (`mState`, `mGamerules`, `mUnits`, `mOffsetInfo`,
   * `mSlots`, `mOrientation`, `mPlanUpdate`, `mMaxSize`); the caches, the
   * forward vector and the scale carry names taken from their proven
   * readers and writers instead of the IDB's `mMap1`/`mPos1`/`mVal2`
   * placeholders.
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
     * Address: 0x005692D0 (FUN_005692D0, Moho::CFormationInstance::CFormationInstance)
     *
     * What it does:
     * The default state a reflection-constructed instance starts from:
     * reference count zero, self-linked listener ring, no Lua state, rules
     * or command, every container empty on its inline storage, both
     * position caches with a fresh head, an empty script name, a NaN centre,
     * no pending plan, zero max footprint and zero scale. The orientation
     * lanes are left untouched, exactly as the binary leaves them.
     */
    CFormationInstance();

    /**
     * Address: 0x005694B0 (FUN_005694B0, Moho::CFormationInstance::CFormationInstance)
     *
     * IDA signature:
     * Moho::CAiFormationInstance *__fastcall Moho::CFormationInstance::CFormationInstance(
     *     Moho::RRuleGameRulesImpl *rules, int commandType, Moho::CFormationInstance *this,
     *     LuaPlus::LuaState *state, gpg::fastvector_n<WeakPtr<IUnit>, 4> *units,
     *     const char *name, Moho::SCoordsVec2 *coords, Wm3::Quaternionf orientation);
     *
     * What it does:
     * Stamps the Lua state, game rules and command type, copies the caller's
     * initial unit set into `mUnits` (the copy links every element into its
     * unit's weak chain), default-constructs both group vectors, the assigned
     * slot vector and both position caches, sets the script name and centre,
     * and -- only when `coords` yields a valid flat ground-plane point --
     * derives the initial forward vector from `orientation` (same formula as
     * `SetOrientation`), clears the slot caches and runs one
     * `UpdateFormation` pass.
     */
    CFormationInstance(
      RRuleGameRules* rules,
      EUnitCommandType commandType,
      LuaPlus::LuaState* state,
      const gpg::fastvector_n<WeakPtr<IUnit>, 4>& units,
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
     * confusion artifact -- the binary's only caller, `CFormation::Finalize`
     * (0x0083843B), actually passes the address of a transient
     * `gpg::fastvector_n4_WeakPtr_IUnit` collector. The four trailing floats
     * are the caller's `mDirection` quaternion, spread across contiguous
     * stack slots by the by-value ABI; reconstructed here as a single
     * `Wm3::Quatf` parameter for clarity, since both sides of the only real
     * call site pass/consume it as one unit.
     */
    [[nodiscard]] static CFormationInstance* Create(
      RRuleGameRules* rules,
      LuaPlus::LuaState* state,
      const gpg::fastvector_n<WeakPtr<IUnit>, 4>& units,
      const char* name,
      const SCoordsVec2& coords,
      const Wm3::Quatf& orientation
    );

    /**
     * Address: 0x005741D0 (FUN_005741D0, Moho::CFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Reads the eighteen reflected fields back in the order MemberSerialize
     * wrote them. The Lua state and game-rules fields come back through typed
     * pointer readers rather than a raw form.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005744E0 (FUN_005744E0, Moho::CFormationInstance::MemberSerialize)
     *
     * What it does:
     * Writes the reflected base payload, the two owning pointers as unowned
     * tracked references, then every formation field. mSim and the trailing
     * word are runtime-only and deliberately not written.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    LuaPlus::LuaState* mState;                                // +0x10
    RRuleGameRules* mGamerules;                               // +0x14
    EUnitCommandType mCommandType;                            // +0x18
    /// Never written by any constructor or method in the binary.
    std::uint32_t mUnknown_0x01C;                             // +0x1C
    /// Every unit in the formation (IDA: `gpg::fastvector_n4_WeakPtr_IUnit`).
    gpg::fastvector_n<WeakPtr<IUnit>, 4> mUnits;              // +0x20
    /// The formation groups, one vector per layer (`GetLayer`: 0 ground, 1 air).
    gpg::fastvector_n<SOffsetInfo, 2> mOffsetInfo[2];         // +0x50
    /// Slots `FindSlotFor` has handed out for the current plan.
    gpg::fastvector_n<SAssignedLocInfo, 16> mSlots;           // +0x1A0
    /// `GetFormationPosition` results by entity id, valid until the centre
    /// moves or the plan is rebuilt.
    msvc8::map<EntId, SCoordsVec2> mFormationPosCache;        // +0x2B0
    /// `GetOffsetPosition` results by entity id, same lifetime as
    /// `mFormationPosCache`.
    msvc8::map<EntId, SCoordsVec2> mOffsetPosCache;           // +0x2BC
    Wm3::Vec3f mForwardVector;                                // +0x2C8
    Wm3::Quatf mOrientation;                                  // +0x2D4
    /// Rotation from the units' mean heading to the formation heading
    /// (`UpdateFormation`); `RunScript` pre-rotates each unit's relative
    /// position by it before matching slots.
    Wm3::Quatf mOrientationChange;                            // +0x2E4
    msvc8::string mScriptName;                                // +0x2F4
    /// The formation centre (`GetCoords`/`SetCoords`).
    SCoordsVec2 mCoords;                                      // +0x310
    /// Multiplies every script offset (`ComputeRunScriptOffset`); `SetScale`.
    float mScale;                                             // +0x318
    /// Set whenever the plan must be rebuilt before it is next read.
    std::uint8_t mPlanUpdate;                                 // +0x31C
    std::uint8_t mPad_0x31D[3];                               // +0x31D
    /// Largest footprint dimension among the formation's mobile units.
    std::int32_t mMaxSize;                                    // +0x320
    /// Never written by any constructor or method in the binary; no formation
    /// code reads it either.
    std::uint32_t mUnknown_0x324;                             // +0x324

  public:
    /**
     * Address: 0x00569A10 (FUN_00569A10)
     * Slot: 1
     *
     * What it does:
     * Copies the formation centre into `outCoords`.
     */
    SCoordsVec2* GetCoords(SCoordsVec2* outCoords) const override;

    /**
     * Address: 0x00569A30 (FUN_00569A30, Moho::CFormationInstance::SetCoords)
     * Slot: 2
     *
     * What it does:
     * Moves the formation centre when the new one differs and is not NaN,
     * dropping every assigned slot and both position caches.
     */
    void SetCoords(const SCoordsVec2& coords) override;

    /**
     * Address: 0x0056A210 (FUN_0056A210)
     * Slot: 3
     * Demangled: Moho::CFormationInstance::UnitCount
     */
    int UnitCount() const override;

    /**
     * Address: 0x00569BD0 (FUN_00569BD0)
     *
     * IDA signature:
     * int __stdcall Moho::CFormationInstance::GetLayer(Moho::Unit *unit);
     *
     * What it does:
     * Returns the formation layer this unit belongs to: `1` for air-motion
     * blueprints, `0` for everything else. The result indexes `mOffsetInfo`.
     * `PreRunScript` (0x00566B10) dispatches this through slot 4 and compares
     * the result against the layer being built, which is where the name comes
     * from.
     *
     * Slot: 4
     * Demangled: Moho::CFormationInstance::GetLayer
     */
    std::int32_t GetLayer(Unit* unit) const override;

    /**
     * Address: 0x005669A0 (FUN_005669A0)
     * Slot: 5
     *
     * What it does:
     * The group `unit` was placed in: the first group of the unit's layer
     * whose unit map holds its entity id. Warns and returns null when the
     * unit is in no group.
     */
    SOffsetInfo* GetOffsetInfo(Unit* unit) override;

    /**
     * Address: 0x00569CB0 (FUN_00569CB0)
     * Slot: 6
     * Demangled: Moho::CFormationInstance::GetFormationPosition
     */
    SCoordsVec2* GetFormationPosition(SCoordsVec2* dest, Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x00569EA0 (FUN_00569EA0)
     * Slot: 7
     * Demangled: Moho::CFormationInstance::GetAdjustedFormationPosition
     */
    SOCellPos* GetAdjustedFormationPosition(SOCellPos* dest, Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x00569F70 (FUN_00569F70)
     * Slot: 8
     *
     * What it does:
     * The unit's raw slot position (`mCoords + mOffset`, no free-slot
     * search), cached in `mOffsetPosCache`.
     */
    SCoordsVec2* GetOffsetPosition(SCoordsVec2* dest, Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x0056A150 (FUN_0056A150)
     * Slot: 9
     *
     * What it does:
     * The unit's smoothed `SUnitOffsetInfo::mTargetPos`, or its own position
     * before the first update has produced one.
     */
    Wm3::Vec3f* GetTargetPosition(Wm3::Vec3f* out, Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x00566070 (FUN_00566070)
     * Slot: 10
     *
     * What it does:
     * Base implementation: no leader distance, always zero.
     */
    float GetDistFromLeader(Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x00566080 (FUN_00566080)
     * Slot: 11
     *
     * What it does:
     * Base implementation: every unit has priority 1.
     */
    std::int32_t GetPriority(Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x00569CA0 (FUN_00569CA0, Moho::CFormationInstance::CalcFormationSpeed)
     * Slot: 12
     */
    float CalcFormationSpeed(Unit* unit, float* speedScaleOut, SOffsetInfo* info) override;

    /**
     * Address: 0x0056A6E0 (FUN_0056A6E0)
     * Slot: 13
     *
     * What it does:
     * Base implementation: no leader, always null.
     */
    Unit* GetLeader(Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x0056A220 (FUN_0056A220)
     * Slot: 14
     * Demangled: Moho::CFormationInstance::AddUnit
     */
    void AddUnit(Unit* unit) override;

    /**
     * Address: 0x0056A300 (FUN_0056A300)
     * Slot: 15
     * Demangled: Moho::CFormationInstance::RemoveUnit
     */
    void RemoveUnit(Unit* unit) override;

    /**
     * Address: 0x0056A440 (FUN_0056A440, Moho::CFormationInstance::Contains)
     * Slot: 16
     *
     * What it does:
     * Membership test: placed in a group of the unit's layer, or (with
     * `checkAll`) merely listed in `mUnits`.
     */
    bool Contains(Unit* unit, bool checkAll) const override;

    /**
     * Address: 0x00568AC0 (FUN_00568AC0, Moho::CFormationInstance::CleanupFormation)
     *
     * IDA signature:
     * void __usercall Moho::CFormationInstance::CleanupFormation@<eax>(
     *     Moho::CFormationInstance *this@<eax>);
     *
     * What it does:
     * Resets transient formation-plan state: clears the assigned slots, both
     * position caches (keeping their head sentinels) and the orientation
     * change, then destroys every group of both layers -- each group's
     * destructor unlinks its leader and frees its unit map -- and returns the
     * group vectors to inline storage.
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
    void Update() override;

    /**
     * Address: 0x00569B60 (FUN_00569B60)
     * Slot: 18
     *
     * What it does:
     * The formation forward vector for a placed unit, zero otherwise.
     */
    Wm3::Vec3f* GetForwardVector(Wm3::Vec3f* out, Unit* unit) const override;

    /**
     * Address: 0x00569BF0 (FUN_00569BF0)
     * Slot: 19
     * Demangled: Moho::CFormationInstance::CommandIsForm
     */
    bool CommandIsForm() const override;

    /**
     * Address: 0x00569C20 (FUN_00569C20)
     * Slot: 20
     *
     * What it does:
     * The unit's group `mInFormation` flag, or every group's when no valid
     * unit is given.
     */
    bool IsInFormation(Unit* unit) const override;

    /**
     * Address: 0x0056A4F0 (FUN_0056A4F0)
     * Slot: 21
     *
     * What it does:
     * Stores a changed script-offset scale and requests a plan rebuild.
     */
    void SetScale(float scale) override;

    /**
     * Address: 0x0056A520 (FUN_0056A520)
     * Slot: 22
     * Demangled: Moho::CFormationInstance::SetOrientation
     */
    void SetOrientation(const Wm3::Quatf& orientation) override;

    /**
     * Address: 0x0056A680 (FUN_0056A680)
     * Slot: 23
     * Demangled: Moho::CFormationInstance::GetOrientation
     */
    Wm3::Quatf* GetOrientation(Wm3::Quatf* outOrientation) const override;

    /**
     * Address: 0x00569A00 (FUN_00569A00)
     * Slot: 24
     * Demangled: Moho::CFormationInstance::GetCommandType
     */
    EUnitCommandType GetCommandType() const override;

    /**
     * Address: 0x0056A700 (FUN_0056A700, Moho::CFormationInstance::FindSlotFor)
     * Slot: 25
     *
     * What it does:
     * Base implementation: hands `pos` straight back through `dest`. It never
     * consults the assigned-slot table; `CAiFormationInstance` overrides it
     * with the real slot search.
     */
    virtual SCoordsVec2* FindSlotFor(SCoordsVec2* dest, const SCoordsVec2* pos, Unit* unit);

    /**
     * Address: 0x005691E0 (FUN_005691E0, Moho::CFormationInstance::RemoveDeadUnits)
     *
     * What it does:
     * Erases every null, dead or destroy-queued unit from `mUnits` and
     * reports whether `checkForUnit` is still in the set.
     */
    bool RemoveDeadUnits(Unit* checkForUnit);

    /**
     * Address: 0x00566A30 (FUN_00566A30, Moho::CFormationInstance::ComputeRunScriptOffset)
     *
     * What it does:
     * Scales one script-local formation offset, optionally rotates it by the
     * current formation orientation, then multiplies by slot-span scale.
     */
    SCoordsVec2* ComputeRunScriptOffset(const SCoordsVec2* sourceOffset, SCoordsVec2* dest) const;

    /**
     * Address: 0x00566B10 (FUN_00566B10, Moho::CFormationInstance::PreRunScript)
     *
     * IDA signature:
     * void __userpurge Moho::CFormationInstance::PreRunScript(
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
    void PreRunScript(
      gpg::fastvector_n<WeakPtr<IUnit>, 4>& layerUnitsOut,
      gpg::fastvector_n<WeakPtr<IUnit>, 4>& candidateUnits,
      std::int32_t layerIndex
    );

    /**
     * Address: 0x00568820 (FUN_00568820, Moho::CFormationInstance::Setup)
     *
     * IDA signature:
     * void __userpurge Moho::CFormationInstance::Setup(
     *     int layerIndex@<edi>, Moho::CAiFormationInstance *this,
     *     gpg::fastvector_n4_WeakPtr_IUnit *candidateUnits);
     *
     * What it does:
     * Claims this layer's units out of the shared candidate list via
     * `PreRunScript`, runs the formation script over them via `RunScript`
     * when any were claimed, then releases the per-layer scratch list.
     */
    void Setup(gpg::fastvector_n<WeakPtr<IUnit>, 4>& candidateUnits, std::int32_t layerIndex);

    /**
     * Address: 0x00567300 (FUN_00567300, Moho::CFormationInstance::RunScript)
     *
     * ASM-only recovery (no `.c` decompile); see
     * `decomp/recovery/escalations/FUN_00567300.md` for the stack-frame
     * decode key, EH funclet table, and the seven-phase behavior this
     * follows. 1010 instructions.
     *
     * IDA signature:
     * void __stdcall Moho::CFormationInstance::RunScript(
     *     gpg::fastvector_n4_WeakPtr_IUnit *units, std::int32_t layerIndex);
     *
     * What it does:
     * Builds a Lua unit table from `units` and calls `Moho::FORMATION_RunScript`;
     * early-exits if it produced no slots. Computes the mean unit position,
     * builds one relative-position descriptor per unit (optionally rotated by
     * `mOrientationChange`) while folding the group's speed, computes
     * slot-table span/mean statistics, builds one scored candidate per
     * (slot, unit) pair whose category matches and sorts them by squared
     * distance, then greedily assigns each candidate's nearest still-free
     * unit into the new group's `mUnitOffsets` (warning on duplicate
     * assignment), calls `RemoveUnit` for anything left unassigned, and
     * appends the finished group to `mOffsetInfo[layerIndex]`.
     */
    void RunScript(gpg::fastvector_n<WeakPtr<IUnit>, 4>& units, std::int32_t layerIndex);

    /**
     * Address: 0x00568CA0 (FUN_00568CA0, Moho::CFormationInstance::UpdateFormation)
     *
     * What it does:
     * Snapshots every live, mobile, non-building, non-destroy-queued linked
     * unit into a scratch unit set, accumulates the formation's mean
     * facing and each unit's max footprint size, refreshes
     * `mOrientationChange` when the facing changed enough, then rebuilds each
     * formation layer in turn: destroys the previous groups for that layer
     * and calls `Setup` to claim and script this layer's units. After both
     * layers rebuild, merges overlapping groups for `Form*` commands and
     * broadcasts `FORMATIONSTATUS_FormationUpdated`.
     */
    void UpdateFormation();

    /**
     * Address: 0x00569880 (FUN_00569880, Moho::CFormationInstance::~CFormationInstance)
     * Address: 0x00569430 (FUN_00569430, `??_GCFormationInstance@Moho@@UAEPAXI@Z`
     *   -- the scalar deleting destructor MSVC parks in slot 0 of this class's
     *   own vtable, `??_7CFormationInstance@Moho@@6B@` at 0xE18E0C: `call
     *   0x569880` then the conditional `::operator delete`. `CFormationInstance`
     *   is a concrete, instantiable class in the binary, so it carries its own
     *   copy of the slot rather than inheriting `CAiFormationInstance`'s
     *   (0x0059BD60) -- `CFormationInstance::Create` (0x0056A920) allocates
     *   exactly `sizeof(CFormationInstance)` (0x328) and placement-constructs a
     *   bare `CFormationInstance`.)
     *
     * VFTable SLOT: 0
     *
     * What it does:
     * Resets the transient formation plan, then lets the members and the
     * IFormationInstance base tear themselves down.
     */
    ~CFormationInstance() override;

  private:
    /**
     * No standalone binary address: the three-step slot reset the binary
     * inlines at 0x00569A30 (`SetCoords`), 0x005694B0 (the constructor tail)
     * and 0x00568AC0 (the head of `CleanupFormation`).
     *
     * What it does:
     * Drops every assigned slot back to inline storage and empties both
     * position caches, keeping their head sentinels.
     */
    void ClearSlotCaches();
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
     * Runs the base `CFormationInstance` constructor (0x005692D0: reference
     * count, listener ring, empty containers, position-cache heads and
     * default scalar state), then publishes the `CAiFormationInstance`
     * vtable and clears the owning-`Sim` back-reference.
     */
    CAiFormationInstance();

    /**
     * No standalone binary address: inlined into
     * `CAiFormationDBImpl::NewFormation` (0x0059C120, 0x0059C1F6-0x0059C22B),
     * the only place the binary builds a formation from live units --
     * `::operator new(0x330)`, the base constructor with the sim's rules and
     * Lua state, the `CAiFormationInstance` vtable, then `mSim`.
     *
     * What it does:
     * Builds a formation for `sim` over `units` (see the base constructor)
     * and binds the owning sim.
     */
    CAiFormationInstance(
      Sim* sim,
      RRuleGameRules* rules,
      EUnitCommandType commandType,
      LuaPlus::LuaState* state,
      const gpg::fastvector_n<WeakPtr<IUnit>, 4>& units,
      const char* name,
      const SCoordsVec2& coords,
      const Wm3::Quatf& orientation
    );

    /**
     * Address: 0x0059A500 (FUN_0059A500, ??1CAiFormationInstance@Moho@@QAE@@Z)
     * Mangled: ??1CAiFormationInstance@Moho@@QAE@@Z
     *
     * What it does:
     * Resets the transient plan, unregisters this instance from the owning
     * formation DB, then lets `~CFormationInstance` tear the members down.
     *
     * Address: 0x0059BD60 (FUN_0059BD60, `??_GCAiFormationInstance@Moho@@UAEPAXI@Z`
     *   -- the scalar deleting destructor in slot 0 of 0xE1B47C: `call
     *   0x59A500` then the conditional `::operator delete`)
     *
     * VFTable SLOT: 0
     */
    ~CAiFormationInstance() override;

    /**
     * Address: 0x0059E950 (FUN_0059E950, Moho::CAiFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Reads serialized formation-instance members from the archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0059E9B0 (FUN_0059E9B0, Moho::CAiFormationInstance::MemberSerialize)
     *
     * What it does:
     * Writes serialized formation-instance members to the archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0059A790 (FUN_0059A790)
     * Slot: 10
     *
     * What it does:
     * The unit's `SUnitOffsetInfo::mDistFromLeader`, zero when it has no
     * slot in `info`.
     */
    float GetDistFromLeader(Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x0059A7D0 (FUN_0059A7D0)
     * Slot: 11
     *
     * What it does:
     * The unit's priority order: `10 * (int)SUnitOffsetInfo::mWeight`,
     * floored at 1; always 1 for guarding units and units without a slot.
     */
    std::int32_t GetPriority(Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x0059A620 (FUN_0059A620)
     * Slot: 12
     * Demangled: Moho::CAiFormationInstance::CalcFormationSpeed
     */
    float CalcFormationSpeed(Unit* unit, float* speedScaleOut, SOffsetInfo* info) override;

    /**
     * Address: 0x0059A870 (FUN_0059A870)
     * Slot: 13
     *
     * What it does:
     * The leader the unit follows: the guarded unit for guard commands, else
     * its group's leader (air groups follow the first overlapping ground
     * group's leader instead).
     */
    Unit* GetLeader(Unit* unit, SOffsetInfo* info) override;

    /**
     * Address: 0x0059AE80 (FUN_0059AE80, Moho::CAiFormationInstance::Update)
     *
     * What it does:
     * Advances every group of both layers: resolves the leader, refreshes
     * each unit's target position and distances, and raises
     * `mInFormation` (broadcasting `FORMATIONSTATUS_FormationAtGoal`) once
     * every unit is close to its slot.
     * Slot: 17
     * Demangled: Moho::CAiFormationInstance::Update
     */
    void Update() override;

    /**
     * Address: 0x0059AA20 (FUN_0059AA20)
     * Slot: 25
     * Demangled: Moho::CAiFormationInstance::FindSlotFor
     *
     * What it does:
     * Resolves one free formation slot near `pos`, records it in `mSlots`,
     * and falls back to the current unit position when no free slot can be
     * found.
     */
    SCoordsVec2* FindSlotFor(SCoordsVec2* dest, const SCoordsVec2* pos, Unit* unit) override;

    /**
     * Address: 0x0059A570 (FUN_0059A570, Moho::CAiFormationInstance::PosIsFree)
     * Slot: 26
     *
     * What it does:
     * True when no assigned slot of `layer` overlaps `position` by `size`.
     */
    virtual bool PosIsFree(const SCoordsVec2& position, std::int32_t size, std::int32_t layer) const;

  public:
    Sim* mSim;                                    // +0x328
    std::uint32_t mUnknown_0x32C;                 // +0x32C
  };

  // The reference count at +0x04 and the listener ring at +0x08 are
  // `IFormationInstance`'s two base subobjects now, so `offsetof` cannot name
  // them here; `sizeof(IFormationInstance) == 0x10` guards them instead, and
  // this first own-member assert re-checks the far edge.
  static_assert(offsetof(CAiFormationInstance, mState) == 0x10, "CAiFormationInstance::mState offset must be 0x10");
  static_assert(offsetof(CAiFormationInstance, mGamerules) == 0x14, "CAiFormationInstance::mGamerules offset must be 0x14");
  static_assert(
    offsetof(CAiFormationInstance, mCommandType) == 0x18, "CAiFormationInstance::mCommandType offset must be 0x18"
  );
  static_assert(offsetof(CAiFormationInstance, mUnits) == 0x20, "CAiFormationInstance::mUnits offset must be 0x20");
  static_assert(offsetof(CAiFormationInstance, mOffsetInfo) == 0x50, "CAiFormationInstance::mOffsetInfo offset must be 0x50");
  static_assert(offsetof(CAiFormationInstance, mSlots) == 0x1A0, "CAiFormationInstance::mSlots offset must be 0x1A0");
  static_assert(
    offsetof(CAiFormationInstance, mFormationPosCache) == 0x2B0,
    "CAiFormationInstance::mFormationPosCache offset must be 0x2B0"
  );
  static_assert(
    offsetof(CAiFormationInstance, mOffsetPosCache) == 0x2BC, "CAiFormationInstance::mOffsetPosCache offset must be 0x2BC"
  );
  static_assert(
    offsetof(CAiFormationInstance, mForwardVector) == 0x2C8, "CAiFormationInstance::mForwardVector offset must be 0x2C8"
  );
  static_assert(
    offsetof(CAiFormationInstance, mOrientation) == 0x2D4, "CAiFormationInstance::mOrientation offset must be 0x2D4"
  );
  static_assert(
    offsetof(CAiFormationInstance, mOrientationChange) == 0x2E4,
    "CAiFormationInstance::mOrientationChange offset must be 0x2E4"
  );
  static_assert(
    offsetof(CAiFormationInstance, mScriptName) == 0x2F4, "CAiFormationInstance::mScriptName offset must be 0x2F4"
  );
  static_assert(offsetof(CAiFormationInstance, mCoords) == 0x310, "CAiFormationInstance::mCoords offset must be 0x310");
  static_assert(offsetof(CAiFormationInstance, mScale) == 0x318, "CAiFormationInstance::mScale offset must be 0x318");
  static_assert(offsetof(CAiFormationInstance, mPlanUpdate) == 0x31C, "CAiFormationInstance::mPlanUpdate offset must be 0x31C");
  static_assert(offsetof(CAiFormationInstance, mMaxSize) == 0x320, "CAiFormationInstance::mMaxSize offset must be 0x320");
  static_assert(
    offsetof(CAiFormationInstance, mUnknown_0x324) == 0x324, "CAiFormationInstance::mUnknown_0x324 offset must be 0x324"
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
   * Address: 0x005667A0 (FUN_005667A0, preregister_SAssignedLocInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SAssignedLocInfo`. Reached
   * from `sub_BCABC0` (`.CRT$XCL`/`__xc_a` static-init table), matching the
   * `preregister_SUnitOffsetInfoTypeInfo` reachability shape above.
   */
  [[nodiscard]] gpg::RType* preregister_SAssignedLocInfoTypeInfo();

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
} // namespace moho
