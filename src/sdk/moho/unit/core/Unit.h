// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <string>
#include <string_view>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/String.h"
#include "IUnit.h"
#include "UnitAttributes.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/containers/TDatList.h"
#include "moho/entity/Entity.h"
#include "moho/misc/WeakPtr.h"
#include "wm3/Vector3.h"

namespace moho
{
  enum EUnitState : std::int32_t;
  struct CEconRequest;
  class CIntel;
  struct RUnitBlueprint;
  class ReconBlip;
  class StatItem;
  class UserUnit;
  class VTransform;
  struct SExtraUnitData;
  template <class T>
  class Stats;
} // namespace moho
namespace moho
{
  class CUnitCommand;
  class CUnitCommandQueue;
  class CUnitMotion;
  class CAniActor;
  class CFormationInstance;
  class IAiBuilder;
  class IAiNavigator;
  class IAiSteering;
  class IAiTransport;
} // namespace moho

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RRef;
  class RType;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  struct SBeatResourceAccumulators
  {
    float maintenanceEnergy;
    float maintenanceMass;
    float resourcesSpentEnergy;
    float resourcesSpentMass;

    void Clear() noexcept;
  };

  struct SWeakRefSlot
  {
    void* valueWithTag;
    void* backlink;

    template <class TObject>
    [[nodiscard]] WeakPtr<TObject>& AsWeakPtr() noexcept
    {
      static_assert(sizeof(SWeakRefSlot) == sizeof(WeakPtr<void>), "SWeakRefSlot/WeakPtr layout mismatch");
      static_assert(
        offsetof(SWeakRefSlot, valueWithTag) == offsetof(WeakPtr<void>, ownerLinkSlot),
        "SWeakRefSlot owner slot mismatch"
      );
      static_assert(
        offsetof(SWeakRefSlot, backlink) == offsetof(WeakPtr<void>, nextInOwner), "SWeakRefSlot next slot mismatch"
      );
      return reinterpret_cast<WeakPtr<TObject>&>(*this);
    }

    template <class TObject>
    [[nodiscard]] const WeakPtr<TObject>& AsWeakPtr() const noexcept
    {
      static_assert(sizeof(SWeakRefSlot) == sizeof(WeakPtr<void>), "SWeakRefSlot/WeakPtr layout mismatch");
      static_assert(
        offsetof(SWeakRefSlot, valueWithTag) == offsetof(WeakPtr<void>, ownerLinkSlot),
        "SWeakRefSlot owner slot mismatch"
      );
      static_assert(
        offsetof(SWeakRefSlot, backlink) == offsetof(WeakPtr<void>, nextInOwner), "SWeakRefSlot next slot mismatch"
      );
      return reinterpret_cast<const WeakPtr<TObject>&>(*this);
    }

    template <class TObject>
    [[nodiscard]] TObject* ResolveObjectPtr() const noexcept
    {
      return AsWeakPtr<TObject>().GetObjectPtr();
    }

    template <class TObject>
    void ResetObjectPtr(TObject* object) noexcept
    {
      AsWeakPtr<TObject>().ResetFromObject(object);
    }
  };
  static_assert(sizeof(SWeakRefSlot) == 0x08, "SWeakRefSlot size must be 0x08");
  static_assert(offsetof(SWeakRefSlot, valueWithTag) == 0x00, "SWeakRefSlot::valueWithTag offset must be 0x00");
  static_assert(offsetof(SWeakRefSlot, backlink) == 0x04, "SWeakRefSlot::backlink offset must be 0x04");

  /**
   * Encoded weak-owner slot lane used by Unit guarded-by lists.
   *
   * Evidence:
   * - `cfunc_UnitGetGuardsL` (0x006CD4E0) iterates dword slots and decodes
   *   each non-null value as `(slot - 0x8)` before calling `Entity::GetLuaObject`.
   */
  struct SGuardedByWeakOwnerSlot
  {
    void* ownerLinkSlot; // encoded weak owner-link slot pointer
  };
  static_assert(sizeof(SGuardedByWeakOwnerSlot) == 0x04, "SGuardedByWeakOwnerSlot size must be 0x04");
  static_assert(
    offsetof(SGuardedByWeakOwnerSlot, ownerLinkSlot) == 0x00,
    "SGuardedByWeakOwnerSlot::ownerLinkSlot offset must be 0x00"
  );

  /**
   * Runtime guarded-by list lane stored in `Unit` at +0x4F8.
   *
   * Layout evidence:
   * - `cfunc_UnitGetGuardsL` copies from `unit+0x500` into a local
   *   fastvector runtime view after seeding a preceding 8-byte intrusive node.
   */
  struct SGuardedByRuntimeList
  {
    TDatListItem<void, void> mOwnerNode;                  // +0x00
    gpg::fastvector_runtime_view<SGuardedByWeakOwnerSlot> mSlots; // +0x08
  };
  static_assert(sizeof(SGuardedByRuntimeList) == 0x18, "SGuardedByRuntimeList size must be 0x18");
  static_assert(
    offsetof(SGuardedByRuntimeList, mOwnerNode) == 0x00, "SGuardedByRuntimeList::mOwnerNode offset must be 0x00"
  );
  static_assert(
    offsetof(SGuardedByRuntimeList, mSlots) == 0x08, "SGuardedByRuntimeList::mSlots offset must be 0x08"
  );

  /**
   * Packed pair emitted by Unit::GetExtraData during sync-filter serialization.
   *
   * Evidence:
   * - Unit::GetExtraData (0x006ACB20) appends 8-byte records and writes two dwords.
   */
  struct SExtraUnitDataPair
  {
    std::int32_t key;   // weapon/slot discriminator
    std::int32_t value; // payload id / marker
  };
  static_assert(sizeof(SExtraUnitDataPair) == 0x08, "SExtraUnitDataPair size must be 0x08");

  /**
   * Sync-filter extra data record owned by Sim::AdvanceBeat scratch vector.
   *
   * Size evidence:
   * - Sim::AdvanceBeat (0x00749F40) appends 0x20-byte elements in this stage.
   * - Unit::GetExtraData writes output owner id at +0x18 (a1[6]).
   */
  struct SExtraUnitData
  {
    SExtraUnitDataPair* pairsBegin;       // +0x00
    SExtraUnitDataPair* pairsEnd;         // +0x04
    SExtraUnitDataPair* pairsCapacityEnd; // +0x08
    SExtraUnitDataPair* pairsInlineBegin; // +0x0C (inline storage anchor used by reset/copy helpers)
    SExtraUnitDataPair inlinePair;        // +0x10 (single inline pair storage)
    EntId unitEntityId;                   // +0x18
    std::int32_t syncAuxWord1C;           // +0x1C (seen zero-initialized in Sim::AdvanceBeat; semantic use unresolved)
  };
  static_assert(sizeof(SExtraUnitData) == 0x20, "SExtraUnitData size must be 0x20");
  static_assert(
    offsetof(SExtraUnitData, pairsInlineBegin) == 0x0C, "SExtraUnitData::pairsInlineBegin offset must be 0x0C"
  );
  static_assert(offsetof(SExtraUnitData, inlinePair) == 0x10, "SExtraUnitData::inlinePair offset must be 0x10");
  static_assert(offsetof(SExtraUnitData, unitEntityId) == 0x18, "SExtraUnitData::unitEntityId offset must be 0x18");

  /**
   * Reflection type in RTTI: Moho::SInfoCache
   * Size evidence:
   * - SInfoCacheTypeInfo::Init (0x006A4EC0) writes sizeof(type)=0x28.
   * - Unit::GetInfoCache returns this+0x0580 in FA.
   *
   * Recovered field evidence:
   * - `Unit::IsHigherPriorityThan` (0x006A8D80) uses:
   *   - +0x00 as formation-layer pointer (`CFormationInstance*`)
   *   - +0x04 as intrusive weak owner-link slot (`Unit* + 0x04`)
   *   - +0x08 as weak chain next pointer
   *   - +0x0C as formation ordering word
   *   - +0x10 bool lane serialized by SInfoCacheSerializer::Serialize
   *   - +0x14/+0x18 float lanes serialized by SInfoCacheSerializer::Serialize
   *   - +0x1C as cached vector lane serialized by SInfoCacheSerializer::Serialize
   */
  struct SInfoCache
  {
    CFormationInstance* mFormationLayer;   // +0x00
    SWeakRefSlot mFormationLeadRef;        // +0x04
    std::int32_t mFormationPriorityOrder;  // +0x0C
    bool mHasFormationSpeedData;           // +0x10
    std::uint8_t mPad11[0x03];             // +0x11
    float mFormationTopSpeed;              // +0x14
    float mFormationDistanceMetric;        // +0x18
    Wm3::Vector3f mFormationHeadingHint;   // +0x1C
  };
  static_assert(offsetof(SInfoCache, mFormationLayer) == 0x00, "SInfoCache::mFormationLayer offset must be 0x00");
  static_assert(offsetof(SInfoCache, mFormationLeadRef) == 0x04, "SInfoCache::mFormationLeadRef offset must be 0x04");
  static_assert(
    offsetof(SInfoCache, mFormationPriorityOrder) == 0x0C, "SInfoCache::mFormationPriorityOrder offset must be 0x0C"
  );
  static_assert(
    offsetof(SInfoCache, mHasFormationSpeedData) == 0x10, "SInfoCache::mHasFormationSpeedData offset must be 0x10"
  );
  static_assert(
    offsetof(SInfoCache, mFormationTopSpeed) == 0x14, "SInfoCache::mFormationTopSpeed offset must be 0x14"
  );
  static_assert(
    offsetof(SInfoCache, mFormationDistanceMetric) == 0x18, "SInfoCache::mFormationDistanceMetric offset must be 0x18"
  );
  static_assert(
    offsetof(SInfoCache, mFormationHeadingHint) == 0x1C, "SInfoCache::mFormationHeadingHint offset must be 0x1C"
  );
  static_assert(sizeof(SInfoCache) == 0x28, "SInfoCache size must be 0x28");

  /**
   * Runtime RB-tree node payload used by unit armor-multiplier map lanes.
   *
   * Evidence:
   * - func_hasArmorType (0x006ADD30) reads key lane via node+0x10 and value at
   *   node+0x28.
   * - sub_6B0200 (0x006B0200) initializes RB-tree color/isNil bytes at
   *   node+0x2C/node+0x2D.
   */
  struct SArmorMultiplierMapNode
  {
    SArmorMultiplierMapNode* left; // +0x00
    SArmorMultiplierMapNode* parent; // +0x04
    SArmorMultiplierMapNode* right; // +0x08
    msvc8::string damageTypeName; // +0x0C
    float armorMultiplier; // +0x28
    std::uint8_t color; // +0x2C (0=red, 1=black)
    std::uint8_t isNil; // +0x2D (1 for sentinel/head)
    std::uint16_t reserved; // +0x2E
  };
  static_assert(offsetof(SArmorMultiplierMapNode, left) == 0x00, "SArmorMultiplierMapNode::left offset must be 0x00");
  static_assert(
    offsetof(SArmorMultiplierMapNode, parent) == 0x04, "SArmorMultiplierMapNode::parent offset must be 0x04"
  );
  static_assert(
    offsetof(SArmorMultiplierMapNode, right) == 0x08, "SArmorMultiplierMapNode::right offset must be 0x08"
  );
  static_assert(
    offsetof(SArmorMultiplierMapNode, damageTypeName) == 0x0C,
    "SArmorMultiplierMapNode::damageTypeName offset must be 0x0C"
  );
  static_assert(
    offsetof(SArmorMultiplierMapNode, armorMultiplier) == 0x28,
    "SArmorMultiplierMapNode::armorMultiplier offset must be 0x28"
  );
  static_assert(offsetof(SArmorMultiplierMapNode, color) == 0x2C, "SArmorMultiplierMapNode::color offset must be 0x2C");
  static_assert(offsetof(SArmorMultiplierMapNode, isNil) == 0x2D, "SArmorMultiplierMapNode::isNil offset must be 0x2D");
  static_assert(sizeof(SArmorMultiplierMapNode) == 0x30, "SArmorMultiplierMapNode size must be 0x30");

  /**
   * Runtime map lane (`std::map<std::string,float>`) embedded in `Unit`.
   *
   * Evidence:
   * - cfunc_UnitGetArmorMultL (0x006C4200) passes `this+0x568` as map lane.
   * - func_hasArmorType (0x006ADD30) reads sentinel head from map+0x04.
   */
  struct SArmorMultiplierMap
  {
    void* treeMeta;                // +0x00 (allocator/comparator payload lane)
    SArmorMultiplierMapNode* head; // +0x04 (sentinel/end node)
    std::uint32_t size;            // +0x08
  };
  static_assert(sizeof(SArmorMultiplierMap) == 0x0C, "SArmorMultiplierMap size must be 0x0C");
  static_assert(offsetof(SArmorMultiplierMap, head) == 0x04, "SArmorMultiplierMap::head offset must be 0x04");
  static_assert(offsetof(SArmorMultiplierMap, size) == 0x08, "SArmorMultiplierMap::size offset must be 0x08");

  /**
   * Reflection type in RTTI: Moho::SSTIUnitConstantData
   * Size evidence:
   * - SSTIUnitConstantDataTypeInfo::Init (0x0055C470) sets sizeof(type)=16.
   * - Unit ctor (0x006A53F0) initializes this block at +0x278 via sub_5BD720.
   */
  struct SSTIUnitConstantData
  {
    /**
     * Address: 0x005BD720 (FUN_005BD720, ??0SSTIUnitConstantData@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one unit constant-data payload and seeds a default
     * `Stats<StatItem>` shared root.
     */
    SSTIUnitConstantData();

    /**
     * Address: 0x0055DF40 (FUN_0055DF40, Moho::SSTIUnitConstantData::MemberDeserialize)
     *
     * What it does:
     * Loads build-state tag, stats root shared-pointer lane, and fake flag from
     * archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive, int version);

    /**
     * Address: 0x0055DFB0 (FUN_0055DFB0, Moho::SSTIUnitConstantData::MemberSerialize)
     *
     * What it does:
     * Saves build-state tag, stats root shared-pointer lane, and fake flag to
     * archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive, int version) const;

    static gpg::RType* sType;

    std::uint8_t mBuildStateTag;    // +0x00
    std::uint8_t pad_01[3];         // +0x01
    boost::shared_ptr<Stats<StatItem>> mStatsRoot; // +0x04
    std::uint8_t mFake;             // +0x0C
    std::uint8_t pad_0D[3];         // +0x0D
  };
  static_assert(sizeof(SSTIUnitConstantData) == 0x10, "SSTIUnitConstantData size must be 0x10");
  static_assert(
    offsetof(SSTIUnitConstantData, mStatsRoot) == 0x04,
    "SSTIUnitConstantData::mStatsRoot offset must be 0x04"
  );
  static_assert(offsetof(SSTIUnitConstantData, mFake) == 0x0C, "SSTIUnitConstantData::mFake offset must be 0x0C");

  struct SSTIUnitEconomyPair
  {
    float ENERGY; // +0x00
    float MASS;   // +0x04
  };
  static_assert(sizeof(SSTIUnitEconomyPair) == 0x08, "SSTIUnitEconomyPair size must be 0x08");

  struct SSTIUnitWeaponInfoSnapshot
  {
    std::uint8_t storage[0x98];
  };
  static_assert(sizeof(SSTIUnitWeaponInfoSnapshot) == 0x98, "SSTIUnitWeaponInfoSnapshot size must be 0x98");

  using SSTIUnitWeaponInfoVector = gpg::fastvector_n<SSTIUnitWeaponInfoSnapshot, 1>;
  static_assert(sizeof(SSTIUnitWeaponInfoVector) == 0xA8, "SSTIUnitWeaponInfoVector size must be 0xA8");

  /**
   * Reflection type in RTTI: Moho::SSTIUnitVariableData
   * Size evidence:
   * - SSTIUnitVariableDataTypeInfo::Init (0x0055C680) sets sizeof(type)=552 (0x228).
   * - Unit ctor (0x006A53F0) initializes this block starting at +0x288.
   */
  struct SSTIUnitVariableData
  {
    /**
     * Address: 0x005BD7A0 (FUN_005BD7A0, ??0SSTIUnitVariableData@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one unit variable-data payload to default sim-sync values.
     */
    SSTIUnitVariableData();

    /**
     * Address: 0x00560500 (FUN_00560500, ??1SSTIUnitVariableData@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases dynamic sync lanes (string/shared refs/inline vectors) and
     * resets inline storage ownership.
     */
    ~SSTIUnitVariableData();

    SSTIUnitVariableData(const SSTIUnitVariableData& other);
    SSTIUnitVariableData& operator=(const SSTIUnitVariableData& other);

    /**
     * Address: 0x005BF1E0 (FUN_005BF1E0, Moho::SSTIUnitVariableData::Assign)
     *
     * What it does:
     * Copies one unit variable-data payload, including intrusive/shared
     * ownership lanes and command/build queue snapshots.
     */
    SSTIUnitVariableData& AssignFrom(const SSTIUnitVariableData& other);

    EntId mCreator;                // +0x000
    std::int32_t mCreationTick;    // +0x004
    bool mAutoMode;                // +0x008
    bool mAutoSurfaceMode;         // +0x009
    bool mIsBusy;                  // +0x00A
    std::uint8_t mPad00B;          // +0x00B
    float mFuelRatio;              // +0x00C
    float mShieldRatio;            // +0x010
    std::int32_t mStunTicks;       // +0x014
    bool mIsPaused;                // +0x018
    bool mIsValidTarget;           // +0x019
    bool mRepeatQueue;             // +0x01A
    std::uint8_t mPad01B;          // +0x01B
    std::int32_t mJobType;         // +0x01C (EJobType storage lane)
    std::int32_t mFireState;       // +0x020 (EFireState storage lane)
    float mWorkProgress;           // +0x024
    std::int32_t mTacticalSiloBuildCount;      // +0x028
    std::int32_t mNukeSiloBuildCount;          // +0x02C
    std::int32_t mTacticalSiloStorageCount;    // +0x030
    std::int32_t mNukeSiloStorageCount;        // +0x034
    std::int32_t mTacticalSiloMaxStorageCount; // +0x038
    std::int32_t mNukeSiloMaxStorageCount;     // +0x03C
    EntId mUnknown40;             // +0x040
    msvc8::string mCustomName;    // +0x044
    SSTIUnitEconomyPair mProduced;         // +0x060
    SSTIUnitEconomyPair mResourcesSpent;   // +0x068
    SSTIUnitEconomyPair mMaintainenceCost; // +0x070
    EntId mFocusUnit;             // +0x078
    EntId mGuardedUnit;           // +0x07C
    EntId mTargetBlip;            // +0x080
    boost::shared_ptr<CAniPose> mPriorSharedPose; // +0x084
    boost::shared_ptr<CAniPose> mSharedPose;      // +0x08C
    std::uint8_t mPad094_097[0x04];               // +0x094
    gpg::fastvector_n<WeakPtr<CUnitCommand>, 4> mCommands;   // +0x098
    gpg::fastvector_n<WeakPtr<CUnitCommand>, 4> mBuildQueue; // +0x0C8
    SSTIUnitWeaponInfoVector mWeaponInfo; // +0x0F8
    UnitAttributes mAttributes;           // +0x1A0
    std::uint32_t mScriptbits;            // +0x210
    std::uint64_t mUnitStates;            // +0x218
    bool mDidRefresh;                     // +0x220
    bool mOverchargePaused;               // +0x221
    std::uint8_t mPad222_227[0x06];       // +0x222
  };
  static_assert(sizeof(SSTIUnitVariableData) == 0x228, "SSTIUnitVariableData size must be 0x228");
  static_assert(offsetof(SSTIUnitVariableData, mCustomName) == 0x044, "SSTIUnitVariableData::mCustomName offset");
  static_assert(offsetof(SSTIUnitVariableData, mCommands) == 0x098, "SSTIUnitVariableData::mCommands offset");
  static_assert(offsetof(SSTIUnitVariableData, mBuildQueue) == 0x0C8, "SSTIUnitVariableData::mBuildQueue offset");
  static_assert(offsetof(SSTIUnitVariableData, mWeaponInfo) == 0x0F8, "SSTIUnitVariableData::mWeaponInfo offset");
  static_assert(offsetof(SSTIUnitVariableData, mAttributes) == 0x1A0, "SSTIUnitVariableData::mAttributes offset");
  static_assert(offsetof(SSTIUnitVariableData, mScriptbits) == 0x210, "SSTIUnitVariableData::mScriptbits offset");
  static_assert(offsetof(SSTIUnitVariableData, mUnitStates) == 0x218, "SSTIUnitVariableData::mUnitStates offset");
  static_assert(offsetof(SSTIUnitVariableData, mDidRefresh) == 0x220, "SSTIUnitVariableData::mDidRefresh offset");
  static_assert(
    offsetof(SSTIUnitVariableData, mOverchargePaused) == 0x221, "SSTIUnitVariableData::mOverchargePaused offset"
  );
  static_assert(sizeof(gpg::core::FastVectorN<SWeakRefSlot, 20>) == 0xB0, "FastVectorN<SWeakRefSlot,20> must be 0xB0");
  static_assert(sizeof(gpg::core::FastVectorN<ReconBlip*, 2>) == 0x18, "FastVectorN<ReconBlip*,2> must be 0x18");

  /**
   * VFTABLE: 0x00E2A574
   * COL:  0x00E83CA4
   */
  class Unit : public IUnit, public Entity
  {
  public:
    /**
     * Address: 0x006AD3C0 (FUN_006AD3C0, Moho::Unit::MemberConstruct)
     *
     * What it does:
     * Deserializes construct-time owner lanes and returns a newly constructed
     * `Unit` via `SerConstructResult`.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerConstructResult& result
    );

    /**
     * Address: 0x006B2B50 (FUN_006B2B50, Moho::Unit::MemberDeserialize)
     *
     * What it does:
     * Deserializes runtime `Unit` state lanes for the given archive version.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, Unit* unit, int version);

    /**
     * Address: 0x006B33A0 (FUN_006B33A0, Moho::Unit::MemberSerialize)
     *
     * What it does:
     * Serializes runtime `Unit` state lanes for the given archive version.
     */
    static void MemberSerialize(gpg::WriteArchive* archive, Unit* unit, int version);

    /**
     * Address: 0x006A4BC0 (FUN_006A4BC0)
     *
     * What it does:
     * Returns this unit pointer through the const RTTI/downcast lane.
     */
    virtual Unit const* IsUnit() const;

    /**
     * Address: 0x006A4BB0 (FUN_006A4BB0)
     *
     * What it does:
     * Returns this unit pointer through the mutable RTTI/downcast lane.
     */
    virtual Unit* IsUnit();

    /**
     * Address: 0x006A48E0
     * Slot: 2
     * Demangled: public: virtual class moho::UserUnit const near * __thiscall moho::IUnit::IsUserUnit(void)const
     */
    virtual UserUnit const* IsUserUnit() const;

    /**
     * Address: 0x006A48D0
     * Slot: 3
     * Demangled: public: virtual class moho::UserUnit near * __thiscall moho::IUnit::IsUserUnit(void)
     */
    virtual UserUnit* IsUserUnit();

    /**
     * Address: 0x006A49A0
     * Slot: 4
     * Demangled: public: virtual class moho::EntId __thiscall moho::Unit::GetEntityId(void)const
     */
    virtual EntId GetEntityId() const;

    /**
     * Address: 0x006A49B0
     * Slot: 5
     * Demangled: public: virtual class Wm3::Vec3f const near & __thiscall moho::Unit::GetPosition(void)const
     */
    virtual Wm3::Vec3f const& GetPosition() const;

    /**
     * Address: 0x006A49C0
     * Slot: 6
     * Demangled: public: virtual class moho::VTransform const near & __thiscall moho::Unit::GetTransform(void)const
     */
    virtual VTransform const& GetTransform() const;

    /**
     * Address: 0x006A8B20
     * Slot: 7
     * Demangled: public: virtual class moho::RUnitBlueprint const near * __thiscall moho::Unit::GetBlueprint(void)const
     */
    virtual RUnitBlueprint const* GetBlueprint() const;

    /**
     * Address: 0x006A49D0
     * Slot: 8
     * Demangled: public: virtual class LuaPlus::LuaObject __thiscall moho::Unit::GetLuaObject(void)
     */
    virtual LuaPlus::LuaObject GetLuaObject();

    /**
     * Address: 0x006A8B30
     * Slot: 9
     * Demangled: public: virtual float __thiscall moho::Unit::CalcTransportLoadFactor(void)const
     */
    virtual float CalcTransportLoadFactor() const;

    /**
     * Address: 0x006A49F0
     * Slot: 10
     * Demangled: public: virtual bool __thiscall moho::Unit::IsDead(void)const
     */
    virtual bool IsDead() const;

    /**
     * Address: 0x006A4A00
     * Slot: 11
     * Demangled: public: virtual bool __thiscall moho::Unit::DestroyQueued(void)const
     */
    virtual bool DestroyQueued() const;

    /**
     * Address: 0x006A4A10
     * Slot: 12
     * Demangled: public: virtual bool __thiscall moho::Unit::IsMobile(void)const
     */
    virtual bool IsMobile() const;

    /**
     * Address: 0x006A4A20
     * Slot: 13
     * Demangled: public: virtual bool __thiscall moho::Unit::IsBeingBuilt(void)const
     */
    virtual bool IsBeingBuilt() const;

    /**
     * Address: 0x0062CD40 (FUN_0062CD40, Moho::Unit::PredictAheadBomb)
     *
     * What it does:
     * Predicts short-horizon XZ movement by iteratively rotating current
     * velocity with impulse-derived roll and integrating over `precision*10`.
     */
    Wm3::Vec3f* PredictAheadBomb(Wm3::Vec3f* out, float precision) const;

    /**
     * Address: 0x006A7B90 (FUN_006A7B90, ?InitializeArmor@Unit@Moho@@AAEXXZ)
     *
     * What it does:
     * Loads armor-type multipliers from Lua armor definitions and seeds
     * `ArmorMultipliers` with parsed `<damageType multiplier>` lanes.
     */
    void InitializeArmor();

    /**
     * Address: 0x006A7DC0
     * Slot: 14
     * Demangled: public: virtual bool __thiscall moho::Unit::IsNavigatorIdle(void)const
     */
    virtual bool IsNavigatorIdle() const;

    /**
     * Address: 0x006A7D10 (FUN_006A7D10, Moho::Unit::IsBusy)
     *
     * What it does:
     * Returns true when either movement navigation is active or builder state
     * reports busy.
     */
    [[nodiscard]] bool IsBusy() const;

    /**
     * Address: 0x006AC940 (FUN_006AC940, ?UpdateSpeedThroughStatus@Unit@Moho@@QAEXXZ)
     *
     * What it does:
     * Recomputes navigator "speed-through-goal" mode from current command
     * queue state, formation-lead ownership, and escort-specific air rules.
     */
    void UpdateSpeedThroughStatus();

    /**
     * Address: 0x006AA310 (FUN_006AA310, ?Warp@Unit@Moho@@UAEXVVTransform@2@@Z)
     *
     * What it does:
     * Warps unit movement transform, updates layer/elevation lanes, and refreshes
     * post-warp terrain type classification.
     */
    void Warp(const VTransform& transform) override;

    /**
     * Address: 0x006AC2C0 (FUN_006AC2C0, ?CreateInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
     *
     * What it does:
     * Queues one `SCreateUnitParams` packet into `SSyncData::mNewUnits` and marks
     * this entity interface as created.
     */
    void CreateInterface(SSyncData* syncData) override;

    /**
     * Address: 0x006A4AF0
     * Slot: 15
     * Demangled: public: virtual bool __thiscall moho::Unit::IsUnitState(enum moho::EUnitState)const
     */
    virtual bool IsUnitState(EUnitState) const;

    /**
     * Address: 0x006A4990
     * Slot: 16
     * Demangled: public: virtual struct moho::UnitAttributes near & __thiscall moho::Unit::GetAttributes(void)
     */
    virtual UnitAttributes& GetAttributes();

    /**
     * Address: 0x006A4980
     * Slot: 17
     * Demangled: public: virtual struct moho::UnitAttributes const near & __thiscall
     * moho::Unit::GetAttributes(void)const
     */
    virtual UnitAttributes const& GetAttributes() const;

    /**
     * Address: 0x006A4B90
     * Slot: 18
     * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg,class
     * std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>> const near &)
     */
    virtual StatItem*
    GetStat(gpg::StrArg, std::basic_string<char, std::char_traits<char>, std::allocator<char>> const&);

    /**
     * Address: 0x006A4B70
     * Slot: 19
     * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg,float
     * const near &)
     */
    virtual StatItem* GetStat(gpg::StrArg, float const&);

    /**
     * Address: 0x006A4B50
     * Slot: 20
     * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg,int const
     * near &)
     */
    virtual StatItem* GetStat(gpg::StrArg, int const&);

    /**
     * Address: 0x006A4B30
     * Slot: 21
     * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg)
     */
    virtual StatItem* GetStat(gpg::StrArg);

    /**
     * Address: 0x006A73A0 (FUN_006A73A0)
     *
     * What it does:
     * Stores the auto-mode flag and dispatches the matching script callback.
     */
    virtual void SetAutoMode(bool);

    /**
     * Address: 0x006A73E0 (FUN_006A73E0)
     *
     * What it does:
     * Stores the auto-surface-mode flag.
     */
    virtual void SetAutoSurfaceMode(bool);

    /**
     * Address: 0x006A4A30 (FUN_006A4A30)
     *
     * What it does:
     * Returns the current auto-mode flag.
     */
    virtual bool IsAutoMode() const;

    /**
     * Address: 0x006A4A40 (FUN_006A4A40)
     *
     * What it does:
     * Returns the current auto-surface-mode flag.
     */
    virtual bool IsAutoSurfaceMode() const;

    /**
     * Address: 0x006A4A50 (FUN_006A4A50)
     *
     * What it does:
     * Copies a caller-provided name into the unit custom-name lane.
     */
    virtual void SetCustomName(std::basic_string<char, std::char_traits<char>, std::allocator<char>>);

    /**
     * Address: 0x006A4AB0 (FUN_006A4AB0)
     *
     * What it does:
     * Returns the current custom name string from unit runtime variable data.
     */
    virtual std::basic_string<char, std::char_traits<char>, std::allocator<char>> GetCustomName() const;

  public:
    /**
     * Address: 0x006A8790 (FUN_006A8790)
     *
     * What it does:
     * Releases AI/command sidecar objects and clears the kill-cleanup latch.
     */
    void KillCleanup();

    /**
     * Address: 0x006ACB20 (FUN_006ACB20)
     *
     * What it does:
     * Appends unit-side sync extra-data records into the provided output buffer.
     */
    void GetExtraData(SExtraUnitData* out) const;

    /**
     * Address: 0x006A73F0 (FUN_006A73F0)
     *
     * What it does:
     * Updates paused state when pause toggling is allowed by command/toggle
     * caps, emits OnPaused/OnUnpaused callbacks, and marks sync game-data dirty.
     */
    void SetPaused(bool paused);

    /**
     * Address: 0x006A7450 (FUN_006A7450)
     *
     * What it does:
     * Sets repeat-queue mode, marks the dirty-sync lane, and emits
     * OnStartRepeatQueue/OnStopRepeatQueue callbacks.
     */
    void SetRepeatQueue(bool enabled);

    /**
     * Address: 0x006A7600 (FUN_006A7600)
     * Mangled: ?GetSkirtRect@Unit@Moho@@QBE?AV?$Rect2@M@gpg@@XZ
     *
     * What it does:
     * Projects this unit position to XZ and resolves world-space skirt bounds
     * through the owning unit blueprint.
     */
    [[nodiscard]] gpg::Rect2f GetSkirtRect() const;

    /**
     * Address: 0x006AA900 (FUN_006AA900, ?SetConsumptionActive@Unit@Moho@@QAEX_N@Z)
     *
     * What it does:
     * Rebuilds unit upkeep request lanes for active/inactive economy
     * consumption and dispatches matching Lua script callbacks.
     */
    void SetConsumptionActive(bool isActive);

    /**
     * Address: 0x006A9370 (FUN_006A9370, ?RenderAIDebugInfo@Unit@Moho@@AAEXXZ)
     *
     * What it does:
     * Emits per-unit AI debug stat counters under `AIDebug_<UniqueName>`,
     * including platoon metadata, idle marker, and active unit-state markers.
     */
    void RenderAIDebugInfo();

    /**
     * Address: 0x006AC530 (FUN_006AC530, ?ShowAIDebugInfo@Unit@Moho@@QAEX_N@Z)
     *
     * What it does:
     * Resolves this unit's `AIDebug_<UniqueName>` stat path and clears it from
     * owning army stats.
     */
    void ShowAIDebugInfo(bool isEnabled);

    /**
     * Address: 0x006AC600 (FUN_006AC600, ?DebugShowRaisedPlatforms@Unit@Moho@@QAEXXZ)
     *
     * What it does:
     * When `ShowRaisedPlatforms` sim-convar is enabled, draws one debug quad
     * for each raised-platform blueprint polygon relative to unit position.
     */
    void DebugShowRaisedPlatforms();

    /**
     * Address: 0x0062AF70 (FUN_0062AF70, Moho::Unit::DistanceToOccupiedRect)
     *
     * What it does:
     * Evaluates raised-platform quad height at `samplePoint` and returns one
     * additional local occupancy offset used by motion ground-snap paths.
     */
    [[nodiscard]] float DistanceToOccupiedRect(const Wm3::Vector3f* samplePoint);

    /**
     * Address: 0x006A7490 (FUN_006A7490)
     *
     * What it does:
     * Toggles a script bit and dispatches OnScriptBitSet/OnScriptBitClear.
     */
    void ToggleScriptBit(int bitIndex);

    /**
     * Address: 0x006A97C0 (FUN_006A97C0)
     *
     * What it does:
     * Updates fire-state storage and marks the dirty-sync lane for replication.
     */
    void SetFireState(std::int32_t fireState);

    /**
     * Address: 0x006AAF50 (?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
     *
     * What it does:
     * Picks a random index in `Blueprint->AI.TargetBones`; writes `-1` when
     * the list is empty. Returns true on all paths.
     */
    bool PickTargetPoint(std::int32_t& outTargetPoint) const;

    /**
     * Address: 0x006AAFB0 (FUN_006AAFB0, ?PickTargetPointAboveWater@Unit@Moho@@QBE_NAAH@Z)
     *
     * What it does:
     * Picks one target-bone index above current water elevation, or falls back
     * to unit centerline elevation when no target-bone lanes are present.
     */
    bool PickTargetPointAboveWater(std::int32_t& outTargetPoint) const;

    /**
     * Address: 0x006AB190 (FUN_006AB190, ?PickTargetPointBelowWater@Unit@Moho@@QBE_NAAH@Z)
     *
     * What it does:
     * Picks one target-bone index below current water elevation, or falls back
     * to unit centerline elevation when no target-bone lanes are present.
     */
    bool PickTargetPointBelowWater(std::int32_t& outTargetPoint) const;

    /**
     * Address: 0x006AB340 (FUN_006AB340, Moho::Unit::GetTargetPoint)
     *
     * What it does:
     * Resolves one target-bone index to world position, clamping index lanes
     * to blueprint target-bone bounds and falling back to root bone when the
     * requested lane is negative.
     */
    [[nodiscard]] Wm3::Vec3f GetTargetPoint(std::int32_t targetPoint) const;

    /**
     * Address: 0x006A9E50 (FUN_006A9E50, ?CanBuild@Unit@Moho@@QBE_NPBVRUnitBlueprint@2@@Z)
     *
     * What it does:
     * Tests whether `blueprint` is present in this unit's effective build
     * category set after army and per-unit build restrictions are applied.
     */
    [[nodiscard]]
    bool CanBuild(const RUnitBlueprint* blueprint) const;

    /**
     * Address: 0x0059A430 (FUN_0059A430, ?GetGuardedUnit@Unit@Moho@@QBEPAV12@XZ)
     *
     * What it does:
     * Resolves `GuardedUnitRef` intrusive weak-link slot to a `Unit*`.
     */
    [[nodiscard]]
    Unit* GetGuardedUnit() const;

    /**
     * Address: 0x00585B10 (FUN_00585B10, Moho::Unit::GetFocusEntity)
     *
     * What it does:
     * Resolves `FocusEntityRef` intrusive weak-link slot to an `Entity*`.
     */
    [[nodiscard]]
    Entity* GetFocusEntity() const;

    /**
     * Address: 0x0062EE00 (FUN_0062EE00, Moho::Unit::GetStagingPlatform)
     *
     * What it does:
     * Resolves `TransportedByRef` and returns the parent transport unit when
     * it is alive and flagged as an air-staging platform.
     */
    [[nodiscard]]
    Unit* GetStagingPlatform() const;

    /**
     * Address: 0x005E3C30 (FUN_005E3C30, Moho::Unit::GetTransportedBy)
     *
     * What it does:
     * Resolves `TransportedByRef` intrusive weak-link slot to a `Unit*`.
     */
    [[nodiscard]]
    Unit* GetTransportedBy() const;

    /**
     * Address: 0x005F5540 (FUN_005F5540, Moho::Unit::GetCreator)
     *
     * What it does:
     * Resolves `CreatorRef` intrusive weak-link slot to a `Unit*`.
     */
    [[nodiscard]]
    Unit* GetCreator() const;

    /**
     * Address: 0x006A8D40 (FUN_006A8D40, Moho::Unit::IsSameFormationLayerWith)
     *
     * What it does:
     * Returns true when both units are not attacking and share the same
     * non-null formation-layer pointer in `SInfoCache`.
     */
    [[nodiscard]]
    bool IsSameFormationLayerWith(const Unit* other) const;

    /**
     * Address: 0x006A8D80 (FUN_006A8D80, ?IsHigherPriorityThan@Unit@Moho@@QBE_NPBV12@@Z)
     *
     * What it does:
     * Compares steering/collision priority against `other` using unit state,
     * formation metadata, footprint size, and forward-alignment tie-breakers.
     */
    [[nodiscard]]
    bool IsHigherPriorityThan(const Unit* other) const;

    /**
     * Address: 0x006AB6F0 (FUN_006AB6F0, ?ReserveOgridRect@Unit@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Frees previous unit occupancy reservation, stores `ogridRect`, and marks
     * the O-grid occupation bit-array region as occupied.
     */
    void ReserveOgridRect(const gpg::Rect2i& ogridRect);

    /**
     * Address: 0x006AB760 (FUN_006AB760, ?FreeOgridRect@Unit@Moho@@QAEXXZ)
     *
     * What it does:
     * Clears this unit's current O-grid occupation reservation rectangle and
     * unmarks the occupied bit-array region when a non-empty reservation exists.
     */
    void FreeOgridRect();

    /**
     * Address: 0x006AB810 (FUN_006AB810, ?CanReserveOgridRect@Unit@Moho@@QAE_NABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Temporarily clears this unit's own reservation marks, tests whether
     * `ogridRect` intersects occupied cells, then restores prior reservation.
     */
    [[nodiscard]]
    bool CanReserveOgridRect(const gpg::Rect2i& ogridRect);

    /**
     * Address: 0x006A7770 (FUN_006A7770, ?ExecuteOccupyGround@Unit@Moho@@QAEXXZ)
     *
     * What it does:
     * Applies blueprint occupy-rect lanes (or footprint fallback rect) into
     * O-grid terrain/water occupancy masks and dirties path clusters.
     */
    void ExecuteOccupyGround();

  public:
    [[nodiscard]] bool NeedsKillCleanup() const noexcept;
    void ClearBeatResourceAccumulators() noexcept;
    [[nodiscard]] CIntel* GetIntelManager() noexcept;
    [[nodiscard]] CIntel const* GetIntelManager() const noexcept;
    [[nodiscard]] SSTIUnitVariableData& VarDat() noexcept;
    [[nodiscard]] SSTIUnitVariableData const& VarDat() const noexcept;

  public:
    SSTIUnitConstantData mConstDat; // 0x0278
    // Leading bytes of SSTIUnitVariableData (starts at 0x0288).
    std::uint8_t mVarDatHead[8]; // 0x0288
    bool AutoMode;               // 0x0290
    bool AutoSurfaceMode;        // 0x0291
    char pad_0292[2];            // 0x0292
    float FuelRatio;             // 0x0294
    float ShieldRatio;           // 0x0298
    std::int32_t StunnedState;   // 0x029C
    bool IsPaused;               // 0x02A0
    bool IsValidTarget;          // 0x02A1
    bool RepeatQueueEnabled;     // 0x02A2
    char pad_02A3[5];            // 0x02A3
    std::int32_t FireState;      // 0x02A8
    float WorkProgress;          // 0x02AC
    char pad_02B0[24];           // 0x02B0
    EntId UpgradedToEntityId;    // 0x02C8
    msvc8::string CustomName;    // 0x02CC
    // 0x02E8..0x02F4 reset in Sim::AdvanceBeat for living units.
    SBeatResourceAccumulators mBeatResourceAccumulators; // 0x02E8
    // Shared runtime slot used by multiple economy lanes (event requests and
    // maintenance consumption) at different points in the beat/update flow.
    float SharedEconomyRateEnergy; // 0x02F8
    float SharedEconomyRateMass;   // 0x02FC
    char pad_0300[16];                                   // 0x0300
    class CAniPose* AnimationPose;                       // 0x0310
    char pad_0314[0x114];                                // 0x0314
    UnitAttributes Attributes;                           // 0x0428
    std::uint32_t ScriptBitMask;                         // 0x0498: toggled by ToggleScriptBit
    std::uint32_t pad_049C;                              // 0x049C
    std::uint64_t UnitStateMask;                         // 0x04A0
    std::uint8_t mUnknown04A8;                           // 0x04A8
    bool OverchargePaused;                               // 0x04A9
    std::uint8_t mUnknown04AA[6];                        // 0x04AA
    CUnitMotion* UnitMotion;                             // 0x04B0
    CUnitCommandQueue* CommandQueue;                     // 0x04B4
    SWeakRefSlot CreatorRef;                             // 0x04B8
    SWeakRefSlot TransportedByRef;                       // 0x04C0
    SWeakRefSlot AssignedTransportRef;                   // 0x04C8
    SWeakRefSlot FocusEntityRef;                         // 0x04D0
    SWeakRefSlot TargetBlipEntityRef;                    // 0x04D8
    SWeakRefSlot GuardedUnitRef;                         // 0x04E0
    Wm3::Vector3f GuardedPos;                            // 0x04E8
    char pad_04F4[4];                                    // 0x04F4
    SGuardedByRuntimeList GuardedByList;                 // 0x04F8
    void* OccupyGroundToken;                             // 0x0510
    char pad_0514[16];                                   // 0x0514
    bool mNeedsKillCleanup;            // 0x0524: tested in Sim::AdvanceBeat, cleared by Unit::KillCleanup (0x006A8790)
    char pad_0525[0x0B];               // 0x0525
    std::int32_t PriorityBoost;        // 0x0530
    CEconRequest* mConsumptionData;    // 0x0534
    bool ConsumptionActive;            // 0x0538
    bool ProductionActive;             // 0x0539
    char pad_053A[2];                  // 0x053A
    float ResourceConsumed;            // 0x053C
    CAniActor* AniActor;               // 0x0540
    class CAiAttackerImpl* AiAttacker; // 0x0544
    class IAiCommandDispatchImpl* AiCommandDispatch; // 0x0548
    IAiNavigator* AiNavigator;                       // 0x054C
    IAiSteering* AiSteering;                         // 0x0550
    IAiBuilder* AiBuilder;                           // 0x0554
    CAiSiloBuildImpl* AiSiloBuild;                   // 0x0558
    IAiTransport* AiTransport;                       // 0x055C
    bool FootprintDown;                              // 0x0560
    char pad_0561[0x07];                             // 0x0561
    SArmorMultiplierMap ArmorMultipliers;            // 0x0568
    TDatListItem<void, void> mEconomyEventListHead;  // 0x0574
    std::uint8_t CurrentTerrainType;                 // 0x057C
    bool mDebugAIStates;                             // 0x057D
    char pad_057E[2];                                // 0x057E
    SInfoCache mInfoCache;                           // 0x0580
    std::int32_t ReservedOgridRectMinX;              // 0x05A8
    std::int32_t ReservedOgridRectMinZ;              // 0x05AC
    std::int32_t ReservedOgridRectMaxX;              // 0x05B0
    std::int32_t ReservedOgridRectMaxZ;              // 0x05B4
    // Built by FUN_006ADE50: fastvector_n with 8-byte elements and inline capacity 20.
    gpg::core::FastVectorN<SWeakRefSlot, 20> mBlipsInRange; // 0x05B8
    // External findings name; xrefs in current export set are still limited.
    std::int32_t mBlipLastUpdateTick; // 0x0668
    std::int32_t mUnknown066C;        // 0x066C
    // Unit::GetReconBlipList returns this+0x0670 (FA).
    gpg::core::FastVectorN<ReconBlip*, 2> mReconBlips; // 0x0670
    bool mIsNotPod;                                    // 0x0688 ("POD"/"STATIONASSISTPOD" category checks in ctor)
    bool mIsEngineer;                                  // 0x0689 ("ENGINEER" category check in ctor)
    bool mIsNaval;                                     // 0x068A ("NAVAL" category check in ctor)
    bool mIsAir;                                       // 0x068B ("AIR" category check in ctor)
    bool mUsesGridBasedMotion;                         // 0x068C ("GRIDBASEDMOTION" category check in ctor)
    bool mIsMelee;                                     // 0x068D ("MELEE" category check in ctor)
    bool NeedSyncGameData;                             // 0x068E
    char pad_068F[1];                                  // 0x068F
    std::int32_t CaptorCount;                          // 0x0690
    char pad_0694[0x14];                               // 0x0694
  };

  static_assert(offsetof(Unit, GuardedByList) == 0x04F8, "Unit::GuardedByList offset must be 0x04F8");
  static_assert(offsetof(Unit, PriorityBoost) == 0x0530, "Unit::PriorityBoost offset must be 0x0530");
  static_assert(offsetof(Unit, mConsumptionData) == 0x0534, "Unit::mConsumptionData offset must be 0x0534");
  static_assert(
    offsetof(Unit, SharedEconomyRateEnergy) == 0x02F8, "Unit::SharedEconomyRateEnergy offset must be 0x02F8"
  );
  static_assert(offsetof(Unit, SharedEconomyRateMass) == 0x02FC, "Unit::SharedEconomyRateMass offset must be 0x02FC");
  static_assert(offsetof(Unit, mDebugAIStates) == 0x057D, "Unit::mDebugAIStates offset must be 0x057D");
  static_assert(
    offsetof(Unit, ReservedOgridRectMinX) == 0x05A8, "Unit::ReservedOgridRectMinX offset must be 0x05A8"
  );
  static_assert(
    offsetof(Unit, ReservedOgridRectMinZ) == 0x05AC, "Unit::ReservedOgridRectMinZ offset must be 0x05AC"
  );
  static_assert(
    offsetof(Unit, ReservedOgridRectMaxX) == 0x05B0, "Unit::ReservedOgridRectMaxX offset must be 0x05B0"
  );
  static_assert(
    offsetof(Unit, ReservedOgridRectMaxZ) == 0x05B4, "Unit::ReservedOgridRectMaxZ offset must be 0x05B4"
  );
  static_assert(offsetof(Unit, ArmorMultipliers) == 0x0568, "Unit::ArmorMultipliers offset must be 0x0568");
  static_assert(offsetof(Unit, mEconomyEventListHead) == 0x0574, "Unit::mEconomyEventListHead offset must be 0x0574");
  static_assert(offsetof(Unit, mReconBlips) == 0x0670, "Unit::mReconBlips offset must be 0x0670");
  static_assert(offsetof(Unit, OverchargePaused) == 0x04A9, "Unit::OverchargePaused offset must be 0x04A9");
  static_assert(offsetof(Unit, NeedSyncGameData) == 0x068E, "Unit::NeedSyncGameData offset must be 0x068E");
  static_assert(offsetof(Unit, CaptorCount) == 0x0690, "Unit::CaptorCount offset must be 0x0690");
  static_assert(sizeof(Unit) == 0x6A8, "Unit size must be 0x6A8");

  /**
   * VFTABLE: 0x00E1F4CC
   * COL:  0x00E76454
   */
  using UnitTransportDetachAllUnits_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3A8
   * COL:  0x00E86EC8
   */
  using UnitGetUnitId_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3B0
   * COL:  0x00E86E78
   */
  using UnitSetCreator_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3B8
   * COL:  0x00E86E28
   */
  using UnitGetCargo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3C0
   * COL:  0x00E86DD8
   */
  using UnitAlterArmor_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3C8
   * COL:  0x00E86D88
   */
  using UnitGetArmorMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3D0
   * COL:  0x00E86D38
   */
  using UnitClearFocusEntity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3D8
   * COL:  0x00E86CE8
   */
  using UnitSetFocusEntity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3E0
   * COL:  0x00E86C98
   */
  using UnitGetFocusUnit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3E8
   * COL:  0x00E86C48
   */
  using UnitGetWeapon_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x00564660 (FUN_00564660, ?ARMOR_GetArmorDefinations@Moho@@YA?AV?$list@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Loads `/lua/armordefinition.lua`, resolves the row that matches
   * `armorTypeName`, and returns all `<damageType multiplier>` string lanes.
   */
  [[nodiscard]] msvc8::list<msvc8::string> ARMOR_GetArmorDefinations(LuaPlus::LuaState* state, gpg::StrArg armorTypeName);

  /**
   * Address: 0x006C3AB0 (FUN_006C3AB0, cfunc_UnitGetUnitId)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetUnitIdL`.
   */
  int cfunc_UnitGetUnitId(lua_State* luaContext);

  /**
   * Address: 0x006C3AD0 (FUN_006C3AD0, func_UnitGetUnitId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetUnitId()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetUnitId_LuaFuncDef();

  /**
   * Address: 0x006C3B30 (FUN_006C3B30, cfunc_UnitGetUnitIdL)
   *
   * What it does:
   * Returns this unit's blueprint-id token string.
   */
  int cfunc_UnitGetUnitIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C3C00 (FUN_006C3C00, cfunc_UnitSetCreator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCreatorL`.
   */
  int cfunc_UnitSetCreator(lua_State* luaContext);

  /**
   * Address: 0x006C3C20 (FUN_006C3C20, func_UnitSetCreator_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetCreator(creator)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetCreator_LuaFuncDef();

  /**
   * Address: 0x006C3C80 (FUN_006C3C80, cfunc_UnitSetCreatorL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit creator weak lane and marks sync dirty.
   */
  int cfunc_UnitSetCreatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C3F80 (FUN_006C3F80, cfunc_UnitAlterArmor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitAlterArmorL`.
   */
  int cfunc_UnitAlterArmor(lua_State* luaContext);

  /**
   * Address: 0x006C3FA0 (FUN_006C3FA0, func_UnitAlterArmor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:AlterArmor(damageTypeName, multiplier)` Lua binder
   * definition.
   */
  CScrLuaInitForm* func_UnitAlterArmor_LuaFuncDef();

  /**
   * Address: 0x006C4000 (FUN_006C4000, cfunc_UnitAlterArmorL)
   *
   * What it does:
   * Writes or creates one damage-type armor multiplier entry in this unit's
   * runtime armor map.
   */
  int cfunc_UnitAlterArmorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C4180 (FUN_006C4180, cfunc_UnitGetArmorMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetArmorMultL`.
   */
  int cfunc_UnitGetArmorMult(lua_State* luaContext);

  /**
   * Address: 0x006C41A0 (FUN_006C41A0, func_UnitGetArmorMult_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetArmorMult(damageTypeName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetArmorMult_LuaFuncDef();

  /**
   * Address: 0x006C4200 (FUN_006C4200, cfunc_UnitGetArmorMultL)
   *
   * What it does:
   * Returns this unit's damage-type armor multiplier, defaulting to `1.0` when
   * the armor map has no matching entry.
   */
  int cfunc_UnitGetArmorMultL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C4370 (FUN_006C4370, cfunc_UnitClearFocusEntity)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitClearFocusEntityL`.
   */
  int cfunc_UnitClearFocusEntity(lua_State* luaContext);

  /**
   * Address: 0x006C4390 (FUN_006C4390, func_UnitClearFocusEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:ClearFocusEntity(self)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitClearFocusEntity_LuaFuncDef();

  /**
   * Address: 0x006C43F0 (FUN_006C43F0, cfunc_UnitClearFocusEntityL)
   *
   * What it does:
   * Clears the focused-entity weak lane and marks focus state as assigned for
   * script-side follow-up.
   */
  int cfunc_UnitClearFocusEntityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C44E0 (FUN_006C44E0, cfunc_UnitSetFocusEntity)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetFocusEntityL`.
   */
  int cfunc_UnitSetFocusEntity(lua_State* luaContext);

  /**
   * Address: 0x006C4500 (FUN_006C4500, func_UnitSetFocusEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetFocusEntity(self, focus)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetFocusEntity_LuaFuncDef();

  /**
   * Address: 0x006C4560 (FUN_006C4560, cfunc_UnitSetFocusEntityL)
   *
   * What it does:
   * Resolves optional focus entity from Lua arg #2, writes it into unit focus
   * weak lane, dispatches `OnAssignedFocusEntity`, and marks focus assigned.
   */
  int cfunc_UnitSetFocusEntityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C4670 (FUN_006C4670, cfunc_UnitGetFocusUnit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetFocusUnitL`.
   */
  int cfunc_UnitGetFocusUnit(lua_State* luaContext);

  /**
   * Address: 0x006C4690 (FUN_006C4690, func_UnitGetFocusUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetFocusUnit(self)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetFocusUnit_LuaFuncDef();

  /**
   * Address: 0x006C46F0 (FUN_006C46F0, cfunc_UnitGetFocusUnitL)
   *
   * What it does:
   * Returns focused unit Lua object when the current focused entity resolves to
   * one unit; otherwise returns `nil`.
   */
  int cfunc_UnitGetFocusUnitL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D3F0
   * COL:  0x00E86BF8
   */
  using UnitGetWeaponCount_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C4800 (FUN_006C4800, cfunc_UnitGetWeapon)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWeaponL`.
   */
  int cfunc_UnitGetWeapon(lua_State* luaContext);

  /**
   * Address: 0x006C4820 (FUN_006C4820, func_UnitGetWeapon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetWeapon(self,index)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetWeapon_LuaFuncDef();

  /**
   * Address: 0x006C4880 (FUN_006C4880, cfunc_UnitGetWeaponL)
   *
   * What it does:
   * Returns one unit weapon Lua object for arg #2 index (1-based), or nil
   * when no weapon object is available at that lane.
   */
  int cfunc_UnitGetWeaponL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C49F0 (FUN_006C49F0, cfunc_UnitGetWeaponCount)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWeaponCountL`.
   */
  int cfunc_UnitGetWeaponCount(lua_State* luaContext);

  /**
   * Address: 0x006C4A10 (FUN_006C4A10, func_UnitGetWeaponCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetWeaponCount(self)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetWeaponCount_LuaFuncDef();

  /**
   * Address: 0x006C4A70 (FUN_006C4A70, cfunc_UnitGetWeaponCountL)
   *
   * What it does:
   * Returns the attacker-side runtime weapon count for this unit.
   */
  int cfunc_UnitGetWeaponCountL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D3F8
   * COL:  0x00E86BA8
   */
  using UnitGetTargetEntity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C4B40 (FUN_006C4B40, cfunc_UnitGetTargetEntity)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetTargetEntityL`.
   */
  int cfunc_UnitGetTargetEntity(lua_State* luaContext);

  /**
   * Address: 0x006C4B60 (FUN_006C4B60, func_UnitGetTargetEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetTargetEntity(self)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetTargetEntity_LuaFuncDef();

  /**
   * Address: 0x006C4BC0 (FUN_006C4BC0, cfunc_UnitGetTargetEntityL)
   *
   * What it does:
   * Returns the current desired target entity Lua object from the unit attacker
   * manager, or `nil` when no desired target is available.
   */
  int cfunc_UnitGetTargetEntityL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D400
   * COL:  0x00E86B58
   */
  using UnitGetHealth_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C4CA0 (FUN_006C4CA0, cfunc_UnitGetHealth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetHealthL`.
   */
  int cfunc_UnitGetHealth(lua_State* luaContext);

  /**
   * Address: 0x006C4CC0 (FUN_006C4CC0, func_UnitGetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetHealth(self)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetHealth_LuaFuncDef();

  /**
   * Address: 0x006C4D20 (FUN_006C4D20, cfunc_UnitGetHealthL)
   *
   * What it does:
   * Returns this unit's current health scalar.
   */
  int cfunc_UnitGetHealthL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D408
   * COL:  0x00E86B08
   */
  using UnitGetAttacker_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C4E10 (FUN_006C4E10, cfunc_UnitGetAttacker)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetAttackerL`.
   */
  int cfunc_UnitGetAttacker(lua_State* luaContext);

  /**
   * Address: 0x006C4E30 (FUN_006C4E30, func_UnitGetAttacker_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetAttacker()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetAttacker_LuaFuncDef();

  /**
   * Address: 0x006C4E90 (FUN_006C4E90, cfunc_UnitGetAttackerL)
   *
   * What it does:
   * Returns this unit's tactical attacker manager object, or nil when absent.
   */
  int cfunc_UnitGetAttackerL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D410
   * COL:  0x00E86AB8
   */
  using UnitEnableManipulators_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D418
   * COL:  0x00E86A68
   */
  using UnitKillManipulator_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D420
   * COL:  0x00E86A18
   */
  using UnitKillManipulators_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5170 (FUN_006C5170, cfunc_UnitKillManipulator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitKillManipulatorL`.
   */
  int cfunc_UnitKillManipulator(lua_State* luaContext);

  /**
   * Address: 0x006C5190 (FUN_006C5190, func_UnitKillManipulator_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:KillManipulator(manipulator)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitKillManipulator_LuaFuncDef();

  /**
   * Address: 0x006C51F0 (FUN_006C51F0, cfunc_UnitKillManipulatorL)
   *
   * What it does:
   * Resolves `(unit, manipulator)` from Lua and destroys that exact
   * manipulator when linked on the unit actor.
   */
  int cfunc_UnitKillManipulatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C52E0 (FUN_006C52E0, cfunc_UnitKillManipulators)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitKillManipulatorsL`.
   */
  int cfunc_UnitKillManipulators(lua_State* luaContext);

  /**
   * Address: 0x006C5300 (FUN_006C5300, func_UnitKillManipulators_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:KillManipulators([boneName|boneIndex])` Lua binder
   * definition.
   */
  CScrLuaInitForm* func_UnitKillManipulators_LuaFuncDef();

  /**
   * Address: 0x006C5360 (FUN_006C5360, cfunc_UnitKillManipulatorsL)
   *
   * What it does:
   * Kills each unit manipulator that matches arg #2 by bone index (`number`) or
   * bone name wildcard (`string`).
   */
  int cfunc_UnitKillManipulatorsL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D428
   * COL:  0x00E869C8
   */
  using UnitScaleGetBuiltEmitter_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C54B0 (FUN_006C54B0, cfunc_UnitScaleGetBuiltEmitter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitScaleGetBuiltEmitterL`.
   */
  int cfunc_UnitScaleGetBuiltEmitter(lua_State* luaContext);

  /**
   * Address: 0x006C54D0 (FUN_006C54D0, func_UnitScaleGetBuiltEmitter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:ScaleGetBuiltEmitter(self, emitter)` Lua binder
   * definition.
   */
  CScrLuaInitForm* func_UnitScaleGetBuiltEmitter_LuaFuncDef();

  /**
   * Address: 0x006C5530 (FUN_006C5530, cfunc_UnitScaleGetBuiltEmitterL)
   *
   * What it does:
   * Reads one unit footprint and writes scale curves into emitter lanes
   * `(10, 4, 3)`.
   */
  int cfunc_UnitScaleGetBuiltEmitterL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D430
   * COL:  0x00E86978
   */
  using UnitSetStrategicUnderlay_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5780 (FUN_006C5780, cfunc_UnitSetStrategicUnderlay)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetStrategicUnderlayL`.
   */
  int cfunc_UnitSetStrategicUnderlay(lua_State* luaContext);

  /**
   * Address: 0x006C57A0 (FUN_006C57A0, func_UnitSetStrategicUnderlay_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetStrategicUnderlay(icon)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetStrategicUnderlay_LuaFuncDef();

  /**
   * Address: 0x006C5800 (FUN_006C5800, cfunc_UnitSetStrategicUnderlayL)
   *
   * What it does:
   * Resolves `(self, icon)` and applies one strategic underlay icon id on the
   * unit entity.
   */
  int cfunc_UnitSetStrategicUnderlayL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D438
   * COL:  0x00E86928
   */
  using UnitIsUnitState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5900 (FUN_006C5900, cfunc_UnitIsUnitState)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsUnitStateL`.
   */
  int cfunc_UnitIsUnitState(lua_State* luaContext);

  /**
   * Address: 0x006C5920 (FUN_006C5920, func_UnitIsUnitState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:IsUnitState(unit, stateName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsUnitState_LuaFuncDef();

  /**
   * Address: 0x006C5980 (FUN_006C5980, cfunc_UnitIsUnitStateL)
   *
   * What it does:
   * Resolves `(unit, stateName)` and returns whether that runtime unit-state
   * bit is currently set.
   */
  int cfunc_UnitIsUnitStateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D440
   * COL:  0x00E868D8
   */
  using UnitIsIdleState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5AA0 (FUN_006C5AA0, cfunc_UnitIsIdleState)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsIdleStateL`.
   */
  int cfunc_UnitIsIdleState(lua_State* luaContext);

  /**
   * Address: 0x006C5AC0 (FUN_006C5AC0, func_UnitIsIdleState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:IsIdleState(unit)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsIdleState_LuaFuncDef();

  /**
   * Address: 0x006C5B20 (FUN_006C5B20, cfunc_UnitIsIdleStateL)
   *
   * What it does:
   * Returns whether a unit has no live front command in its current queue.
   */
  int cfunc_UnitIsIdleStateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D448
   * COL:  0x00E86888
   */
  using UnitIsStunned_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5C10 (FUN_006C5C10, cfunc_UnitIsStunned)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsStunnedL`.
   */
  int cfunc_UnitIsStunned(lua_State* luaContext);

  /**
   * Address: 0x006C5C30 (FUN_006C5C30, func_UnitIsStunned_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:IsStunned(unit)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsStunned_LuaFuncDef();

  /**
   * Address: 0x006C5C90 (FUN_006C5C90, cfunc_UnitIsStunnedL)
   *
   * What it does:
   * Returns true when arg#1 does not resolve to a unit or the unit has active
   * stun ticks.
   */
  int cfunc_UnitIsStunnedL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D450
   * COL:  0x00E86838
   */
  using UnitIsBeingBuilt_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5D60 (FUN_006C5D60, cfunc_UnitIsBeingBuilt)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsBeingBuiltL`.
   */
  int cfunc_UnitIsBeingBuilt(lua_State* luaContext);

  /**
   * Address: 0x006C5D80 (FUN_006C5D80, func_UnitIsBeingBuilt_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:IsBeingBuilt()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsBeingBuilt_LuaFuncDef();

  /**
   * Address: 0x006C5DE0 (FUN_006C5DE0, cfunc_UnitIsBeingBuiltL)
   *
   * What it does:
   * Returns true when arg#1 resolves to a unit currently in being-built state.
   */
  int cfunc_UnitIsBeingBuiltL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D458
   * COL:  0x00E867E8
   */
  using UnitIsPaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C5EB0 (FUN_006C5EB0, cfunc_UnitIsPaused)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsPausedL`.
   */
  int cfunc_UnitIsPaused(lua_State* luaContext);

  /**
   * Address: 0x006C5ED0 (FUN_006C5ED0, func_UnitIsPaused_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:IsPaused()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsPaused_LuaFuncDef();

  /**
   * Address: 0x006C5F30 (FUN_006C5F30, cfunc_UnitIsPausedL)
   *
   * What it does:
   * Returns true when arg#1 resolves to a currently paused unit.
   */
  int cfunc_UnitIsPausedL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D460
   * COL:  0x00E86798
   */
  using UnitSetPaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6000 (FUN_006C6000, cfunc_UnitSetPaused)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetPausedL`.
   */
  int cfunc_UnitSetPaused(lua_State* luaContext);

  /**
   * Address: 0x006C6020 (FUN_006C6020, func_UnitSetPaused_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetPaused()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetPaused_LuaFuncDef();

  /**
   * Address: 0x006C6080 (FUN_006C6080, cfunc_UnitSetPausedL)
   *
   * What it does:
   * Applies paused state from arg#2 to the unit resolved from arg#1.
   */
  int cfunc_UnitSetPausedL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D468
   * COL:  0x00E86748
   */
  using UnitSetConsumptionActive_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6140 (FUN_006C6140, cfunc_UnitSetConsumptionActive)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetConsumptionActiveL`.
   */
  int cfunc_UnitSetConsumptionActive(lua_State* luaContext);

  /**
   * Address: 0x006C6160 (FUN_006C6160, func_UnitSetConsumptionActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetConsumptionActive(flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetConsumptionActive_LuaFuncDef();

  /**
   * Address: 0x006C61C0 (FUN_006C61C0, cfunc_UnitSetConsumptionActiveL)
   *
   * What it does:
   * Applies consumption-active flag from arg#2 to the unit resolved from arg#1.
   */
  int cfunc_UnitSetConsumptionActiveL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C9DA0 (FUN_006C9DA0, cfunc_UnitSetConsumptionPerSecondEnergy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetConsumptionPerSecondEnergyL`.
   */
  int cfunc_UnitSetConsumptionPerSecondEnergy(lua_State* luaContext);

  /**
   * Address: 0x006C9DC0 (FUN_006C9DC0, func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetConsumptionPerSecondEnergy(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x006C9E20 (FUN_006C9E20, cfunc_UnitSetConsumptionPerSecondEnergyL)
   *
   * What it does:
   * Writes a clamped non-negative energy consumption-per-second value from arg#2
   * into the unit attributes resolved from arg#1.
   */
  int cfunc_UnitSetConsumptionPerSecondEnergyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006C9F40 (FUN_006C9F40, cfunc_UnitSetConsumptionPerSecondMass)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetConsumptionPerSecondMassL`.
   */
  int cfunc_UnitSetConsumptionPerSecondMass(lua_State* luaContext);

  /**
   * Address: 0x006C9F60 (FUN_006C9F60, func_UnitSetConsumptionPerSecondMass_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetConsumptionPerSecondMass(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetConsumptionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x006C9FC0 (FUN_006C9FC0, cfunc_UnitSetConsumptionPerSecondMassL)
   *
   * What it does:
   * Writes a clamped non-negative mass consumption-per-second value from arg#2
   * into the unit attributes resolved from arg#1.
   */
  int cfunc_UnitSetConsumptionPerSecondMassL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D470
   * COL:  0x00E866F8
   */
  using UnitSetProductionActive_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6290 (FUN_006C6290, cfunc_UnitSetProductionActive)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetProductionActiveL`.
   */
  int cfunc_UnitSetProductionActive(lua_State* luaContext);

  /**
   * Address: 0x006C62B0 (FUN_006C62B0, func_UnitSetProductionActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetProductionActive(flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetProductionActive_LuaFuncDef();

  /**
   * Address: 0x006C6310 (FUN_006C6310, cfunc_UnitSetProductionActiveL)
   *
   * What it does:
   * Writes `Unit::ProductionActive` from arg #2 and dispatches
   * `OnProductionActive` / `OnProductionInActive` script callbacks.
   */
  int cfunc_UnitSetProductionActiveL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D478
   * COL:  0x00E866A8
   */
  using UnitSetBusy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C63F0 (FUN_006C63F0, cfunc_UnitSetBusy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetBusyL`.
   */
  int cfunc_UnitSetBusy(lua_State* luaContext);

  /**
   * Address: 0x006C6410 (FUN_006C6410, func_UnitSetBusy_LuaFuncDef)
   *
   * What it does:
   * Publishes `SetBusy(unit, flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetBusy_LuaFuncDef();

  /**
   * Address: 0x006C6470 (FUN_006C6470, cfunc_UnitSetBusyL)
   *
   * What it does:
   * Sets or clears `UNITSTATE_Busy` bit from arg#2 on unit arg#1.
   */
  int cfunc_UnitSetBusyL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D480
   * COL:  0x00E86658
   */
  using UnitSetBlockCommandQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6570 (FUN_006C6570, cfunc_UnitSetBlockCommandQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetBlockCommandQueueL`.
   */
  int cfunc_UnitSetBlockCommandQueue(lua_State* luaContext);

  /**
   * Address: 0x006C6590 (FUN_006C6590, func_UnitSetBlockCommandQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `SetBlockCommandQueue(unit, flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetBlockCommandQueue_LuaFuncDef();

  /**
   * Address: 0x006C65F0 (FUN_006C65F0, cfunc_UnitSetBlockCommandQueueL)
   *
   * What it does:
   * Sets or clears `UNITSTATE_BlockCommandQueue` bit from arg#2 on unit arg#1.
   */
  int cfunc_UnitSetBlockCommandQueueL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D488
   * COL:  0x00E86608
   */
  using UnitSetImmobile_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C66F0 (FUN_006C66F0, cfunc_UnitSetImmobile)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetImmobileL`.
   */
  int cfunc_UnitSetImmobile(lua_State* luaContext);

  /**
   * Address: 0x006C6710 (FUN_006C6710, func_UnitSetImmobile_LuaFuncDef)
   *
   * What it does:
   * Publishes the `SetImmobile(unit, flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetImmobile_LuaFuncDef();

  /**
   * Address: 0x006C6770 (FUN_006C6770, cfunc_UnitSetImmobileL)
   *
   * What it does:
   * Sets or clears `UNITSTATE_Immobile` bit from arg#2 on unit arg#1.
   */
  int cfunc_UnitSetImmobileL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D490
   * COL:  0x00E865B8
   */
  using UnitSetStunned_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6860 (FUN_006C6860, cfunc_UnitSetStunned)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetStunnedL`.
   */
  int cfunc_UnitSetStunned(lua_State* luaContext);

  /**
   * Address: 0x006C6880 (FUN_006C6880, func_UnitSetStunned_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetStunned(unit, time)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetStunned_LuaFuncDef();

  /**
   * Address: 0x006C68E0 (FUN_006C68E0, cfunc_UnitSetStunnedL)
   *
   * What it does:
   * Sets stunned ticks from `time` seconds (arg #2) using a `*10` simulation
   * tick scale.
   */
  int cfunc_UnitSetStunnedL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D498
   * COL:  0x00E86568
   */
  using UnitSetUnSelectable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C69D0 (FUN_006C69D0, cfunc_UnitSetUnSelectable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetUnSelectableL`.
   */
  int cfunc_UnitSetUnSelectable(lua_State* luaContext);

  /**
   * Address: 0x006C69F0 (FUN_006C69F0, func_UnitSetUnSelectable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `SetUnSelectable(unit, flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetUnSelectable_LuaFuncDef();

  /**
   * Address: 0x006C6A50 (FUN_006C6A50, cfunc_UnitSetUnSelectableL)
   *
   * What it does:
   * Sets or clears `UNITSTATE_UnSelectable` bit from arg#2 on unit arg#1.
   */
  int cfunc_UnitSetUnSelectableL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4A0
   * COL:  0x00E86518
   */
  using UnitSetDoNotTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6B40 (FUN_006C6B40, cfunc_UnitSetDoNotTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetDoNotTargetL`.
   */
  int cfunc_UnitSetDoNotTarget(lua_State* luaContext);

  /**
   * Address: 0x006C6B60 (FUN_006C6B60, func_UnitSetDoNotTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `SetDoNotTarget(unit, flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetDoNotTarget_LuaFuncDef();

  /**
   * Address: 0x006C6BC0 (FUN_006C6BC0, cfunc_UnitSetDoNotTargetL)
   *
   * What it does:
   * Sets or clears `UNITSTATE_DoNotTarget` bit from arg#2 on unit arg#1.
   */
  int cfunc_UnitSetDoNotTargetL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4A8
   * COL:  0x00E864C8
   */
  using UnitSetUnitState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6CB0 (FUN_006C6CB0, cfunc_UnitSetUnitState)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetUnitStateL`.
   */
  int cfunc_UnitSetUnitState(lua_State* luaContext);

  /**
   * Address: 0x006C6CD0 (FUN_006C6CD0, func_UnitSetUnitState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `SetUnitState(name, bool)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetUnitState_LuaFuncDef();

  /**
   * Address: 0x006C6D30 (FUN_006C6D30, cfunc_UnitSetUnitStateL)
   *
   * What it does:
   * Resolves `(unit, stateName, enabled)` and sets/clears the corresponding
   * state bit in `Unit::UnitStateMask` when lexical enum parsing succeeds.
   */
  int cfunc_UnitSetUnitStateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4B0
   * COL:  0x00E86478
   */
  using UnitStopSiloBuild_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6E80 (FUN_006C6E80, cfunc_UnitStopSiloBuild)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitStopSiloBuildL`.
   */
  int cfunc_UnitStopSiloBuild(lua_State* luaContext);

  /**
   * Address: 0x006C6EA0 (FUN_006C6EA0, func_UnitStopSiloBuild_LuaFuncDef)
   *
   * What it does:
   * Publishes the `StopSiloBuild(unit)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitStopSiloBuild_LuaFuncDef();

  /**
   * Address: 0x006C6F00 (FUN_006C6F00, cfunc_UnitStopSiloBuildL)
   *
   * What it does:
   * Stops active silo build on the unit when a silo-build AI lane exists.
   */
  int cfunc_UnitStopSiloBuildL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4B8
   * COL:  0x00E86428
   */
  using UnitSetIsValidTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C6FB0 (FUN_006C6FB0, cfunc_UnitSetIsValidTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetIsValidTargetL`.
   */
  int cfunc_UnitSetIsValidTarget(lua_State* luaContext);

  /**
   * Address: 0x006C6FD0 (FUN_006C6FD0, func_UnitSetIsValidTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `SetIsValidTarget(self,bool)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetIsValidTarget_LuaFuncDef();

  /**
   * Address: 0x006C7030 (FUN_006C7030, cfunc_UnitSetIsValidTargetL)
   *
   * What it does:
   * Writes one boolean into `Unit::IsValidTarget`.
   */
  int cfunc_UnitSetIsValidTargetL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4C0
   * COL:  0x00E863D8
   */
  using UnitIsValidTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C70F0 (FUN_006C70F0, cfunc_UnitIsValidTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsValidTargetL`.
   */
  int cfunc_UnitIsValidTarget(lua_State* luaContext);

  /**
   * Address: 0x006C7110 (FUN_006C7110, func_UnitIsValidTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `bool = IsValidTarget(self)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsValidTarget_LuaFuncDef();

  /**
   * Address: 0x006C7170 (FUN_006C7170, cfunc_UnitIsValidTargetL)
   *
   * What it does:
   * Returns the current `Unit::IsValidTarget` lane.
   */
  int cfunc_UnitIsValidTargetL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4C8
   * COL:  0x00E86388
   */
  using UnitGetNumBuildOrders_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7230 (FUN_006C7230, cfunc_UnitGetNumBuildOrders)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetNumBuildOrdersL`.
   */
  int cfunc_UnitGetNumBuildOrders(lua_State* luaContext);

  /**
   * Address: 0x006C7250 (FUN_006C7250, func_UnitGetNumBuildOrders_LuaFuncDef)
   *
   * What it does:
   * Publishes the `GetNumBuildOrders(self, category)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetNumBuildOrders_LuaFuncDef();

  /**
   * Address: 0x006C72B0 (FUN_006C72B0, cfunc_UnitGetNumBuildOrdersL)
   *
   * What it does:
   * Counts queued build orders for one builder unit that match a category.
   */
  int cfunc_UnitGetNumBuildOrdersL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4D0
   * COL:  0x00E86338
   */
  using UnitCalculateWorldPositionFromRelative_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7470 (FUN_006C7470, cfunc_UnitCalculateWorldPositionFromRelative)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitCalculateWorldPositionFromRelativeL`.
   */
  int cfunc_UnitCalculateWorldPositionFromRelative(lua_State* luaContext);

  /**
   * Address: 0x006C7490 (FUN_006C7490, func_UnitCalculateWorldPositionFromRelative_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CalculateWorldPositionFromRelative(self, relPos)` binder.
   */
  CScrLuaInitForm* func_UnitCalculateWorldPositionFromRelative_LuaFuncDef();

  /**
   * Address: 0x006C74F0 (FUN_006C74F0, cfunc_UnitCalculateWorldPositionFromRelativeL)
   *
   * What it does:
   * Rotates one relative vector by unit orientation and offsets it by the
   * unit world position.
   */
  int cfunc_UnitCalculateWorldPositionFromRelativeL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4D8
   * COL:  0x00E862E8
   */
  using UnitGetScriptBit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7690 (FUN_006C7690, cfunc_UnitGetScriptBit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetScriptBitL`.
   */
  int cfunc_UnitGetScriptBit(lua_State* luaContext);

  /**
   * Address: 0x006C76B0 (FUN_006C76B0, func_UnitGetScriptBit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetScriptBit(toggleName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetScriptBit_LuaFuncDef();

  /**
   * Address: 0x006C7710 (FUN_006C7710, cfunc_UnitGetScriptBitL)
   *
   * What it does:
   * Resolves one toggle-cap lexical name and returns whether the matching
   * script bit is currently set.
   */
  int cfunc_UnitGetScriptBitL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4E0
   * COL:  0x00E86298
   */
  using UnitSetScriptBit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7870 (FUN_006C7870, cfunc_UnitSetScriptBit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetScriptBitL`.
   */
  int cfunc_UnitSetScriptBit(lua_State* luaContext);

  /**
   * Address: 0x006C7890 (FUN_006C7890, func_UnitSetScriptBit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetScriptBit(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetScriptBit_LuaFuncDef();

  /**
   * Address: 0x006C78F0 (FUN_006C78F0, cfunc_UnitSetScriptBitL)
   *
   * What it does:
   * Resolves `(unit, toggleCapName, enabled)` and toggles the matching script
   * bit lane through `Unit::ToggleScriptBit` when desired/current states
   * differ.
   */
  int cfunc_UnitSetScriptBitL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4E8
   * COL:  0x00E86248
   */
  using UnitToggleScriptBit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7A30 (FUN_006C7A30, cfunc_UnitToggleScriptBit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitToggleScriptBitL`.
   */
  int cfunc_UnitToggleScriptBit(lua_State* luaContext);

  /**
   * Address: 0x006C7A50 (FUN_006C7A50, func_UnitToggleScriptBit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:ToggleScriptBit(toggleName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitToggleScriptBit_LuaFuncDef();

  /**
   * Address: 0x006C7AB0 (FUN_006C7AB0, cfunc_UnitToggleScriptBitL)
   *
   * What it does:
   * Resolves one toggle-cap lexical name and toggles the matching script bit.
   */
  int cfunc_UnitToggleScriptBitL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4F0
   * COL:  0x00E861F8
   */
  using UnitToggleFireState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7BD0 (FUN_006C7BD0, cfunc_UnitToggleFireState)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitToggleFireStateL`.
   */
  int cfunc_UnitToggleFireState(lua_State* luaContext);

  /**
   * Address: 0x006C7BF0 (FUN_006C7BF0, func_UnitToggleFireState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:ToggleFireState()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitToggleFireState_LuaFuncDef();

  /**
   * Address: 0x006C7C50 (FUN_006C7C50, cfunc_UnitToggleFireStateL)
   *
   * What it does:
   * Rotates one unit fire-state lane through `[0, 1, 2]`.
   */
  int cfunc_UnitToggleFireStateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D4F8
   * COL:  0x00E861A8
   */
  using UnitSetFireState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7D10 (FUN_006C7D10, cfunc_UnitSetFireState)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFireStateL`.
   */
  int cfunc_UnitSetFireState(lua_State* luaContext);

  /**
   * Address: 0x006C7D30 (FUN_006C7D30, func_UnitSetFireState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetFireState(stateName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetFireState_LuaFuncDef();

  /**
   * Address: 0x006C7D90 (FUN_006C7D90, cfunc_UnitSetFireStateL)
   *
   * What it does:
   * Parses arg #2 lexical fire-state and applies it to one unit when changed.
   */
  int cfunc_UnitSetFireStateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D500
   * COL:  0x00E86158
   */
  using UnitGetFireState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7EA0 (FUN_006C7EA0, cfunc_UnitGetFireState)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFireStateL`.
   */
  int cfunc_UnitGetFireState(lua_State* luaContext);

  /**
   * Address: 0x006C7EC0 (FUN_006C7EC0, func_UnitGetFireState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetFireState()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetFireState_LuaFuncDef();

  /**
   * Address: 0x006C7F20 (FUN_006C7F20, cfunc_UnitGetFireStateL)
   *
   * What it does:
   * Pushes one unit fire-state value as Lua number.
   */
  int cfunc_UnitGetFireStateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D508
   * COL:  0x00E86108
   */
  using UnitSetAutoMode_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C7FE0 (FUN_006C7FE0, cfunc_UnitSetAutoMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetAutoModeL`.
   */
  int cfunc_UnitSetAutoMode(lua_State* luaContext);

  /**
   * Address: 0x006C8000 (FUN_006C8000, func_UnitSetAutoMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetAutoMode(enabled)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetAutoMode_LuaFuncDef();

  /**
   * Address: 0x006C8060 (FUN_006C8060, cfunc_UnitSetAutoModeL)
   *
   * What it does:
   * Resolves `(unit, enabled)` and dispatches to `Unit::SetAutoMode`.
   */
  int cfunc_UnitSetAutoModeL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D510
   * COL:  0x00E860B8
   */
  using UnitAddBuildRestriction_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8120 (FUN_006C8120, cfunc_UnitAddBuildRestriction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitAddBuildRestrictionL`.
   */
  int cfunc_UnitAddBuildRestriction(lua_State* luaContext);

  /**
   * Address: 0x006C8140 (FUN_006C8140, func_UnitAddBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:AddBuildRestriction(categorySet)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitAddBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x006C81A0 (FUN_006C81A0, cfunc_UnitAddBuildRestrictionL)
   *
   * What it does:
   * Adds category bits from Lua category object into unit build restrictions.
   */
  int cfunc_UnitAddBuildRestrictionL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D518
   * COL:  0x00E86068
   */
  using UnitRemoveBuildRestriction_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8290 (FUN_006C8290, cfunc_UnitRemoveBuildRestriction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitRemoveBuildRestrictionL`.
   */
  int cfunc_UnitRemoveBuildRestriction(lua_State* luaContext);

  /**
   * Address: 0x006C82B0 (FUN_006C82B0, func_UnitRemoveBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RemoveBuildRestriction(categorySet)` Lua binder
   * definition.
   */
  CScrLuaInitForm* func_UnitRemoveBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x006C8310 (FUN_006C8310, cfunc_UnitRemoveBuildRestrictionL)
   *
   * What it does:
   * Removes category bits from unit build restrictions.
   */
  int cfunc_UnitRemoveBuildRestrictionL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D520
   * COL:  0x00E86018
   */
  using UnitRestoreBuildRestrictions_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8400 (FUN_006C8400, cfunc_UnitRestoreBuildRestrictions)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitRestoreBuildRestrictionsL`.
   */
  int cfunc_UnitRestoreBuildRestrictions(lua_State* luaContext);

  /**
   * Address: 0x006C8420 (FUN_006C8420, func_UnitRestoreBuildRestrictions_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RestoreBuildRestrictions()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRestoreBuildRestrictions_LuaFuncDef();

  /**
   * Address: 0x006C8480 (FUN_006C8480, cfunc_UnitRestoreBuildRestrictionsL)
   *
   * What it does:
   * Clears per-unit build restriction category bits.
   */
  int cfunc_UnitRestoreBuildRestrictionsL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D528
   * COL:  0x00E85FC8
   */
  using UnitAddCommandCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8560 (FUN_006C8560, cfunc_UnitAddCommandCap)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddCommandCapL`.
   */
  int cfunc_UnitAddCommandCap(lua_State* luaContext);

  /**
   * Address: 0x006C8580 (FUN_006C8580, func_UnitAddCommandCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:AddCommandCap(capName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitAddCommandCap_LuaFuncDef();

  /**
   * Address: 0x006C85E0 (FUN_006C85E0, cfunc_UnitAddCommandCapL)
   *
   * What it does:
   * Resolves command-cap lexical arg and ORs it into unit command-cap mask.
   */
  int cfunc_UnitAddCommandCapL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D530
   * COL:  0x00E85F78
   */
  using UnitRemoveCommandCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8700 (FUN_006C8700, cfunc_UnitRemoveCommandCap)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitRemoveCommandCapL`.
   */
  int cfunc_UnitRemoveCommandCap(lua_State* luaContext);

  /**
   * Address: 0x006C8720 (FUN_006C8720, func_UnitRemoveCommandCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RemoveCommandCap(capName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRemoveCommandCap_LuaFuncDef();

  /**
   * Address: 0x006C8780 (FUN_006C8780, cfunc_UnitRemoveCommandCapL)
   *
   * What it does:
   * Resolves command-cap lexical arg and clears it from unit command-cap mask.
   */
  int cfunc_UnitRemoveCommandCapL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D538
   * COL:  0x00E85F28
   */
  using UnitRestoreCommandCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C88A0 (FUN_006C88A0, cfunc_UnitRestoreCommandCaps)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitRestoreCommandCapsL`.
   */
  int cfunc_UnitRestoreCommandCaps(lua_State* luaContext);

  /**
   * Address: 0x006C88C0 (FUN_006C88C0, func_UnitRestoreCommandCaps_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RestoreCommandCaps()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRestoreCommandCaps_LuaFuncDef();

  /**
   * Address: 0x006C8920 (FUN_006C8920, cfunc_UnitRestoreCommandCapsL)
   *
   * What it does:
   * Restores the runtime command-cap mask from the owning unit blueprint.
   */
  int cfunc_UnitRestoreCommandCapsL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D540
   * COL:  0x00E85ED8
   */
  using UnitTestCommandCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C89E0 (FUN_006C89E0, cfunc_UnitTestCommandCaps)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitTestCommandCapsL`.
   */
  int cfunc_UnitTestCommandCaps(lua_State* luaContext);

  /**
   * Address: 0x006C8A00 (FUN_006C8A00, func_UnitTestCommandCaps_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:TestCommandCaps(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitTestCommandCaps_LuaFuncDef();

  /**
   * Address: 0x006C8A60 (FUN_006C8A60, cfunc_UnitTestCommandCapsL)
   *
   * What it does:
   * Resolves `(unit, commandCapName)` and returns whether the corresponding
   * blueprint capability bit is present.
   */
  int cfunc_UnitTestCommandCapsL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D548
   * COL:  0x00E85E88
   */
  using UnitAddToggleCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8B80 (FUN_006C8B80, cfunc_UnitAddToggleCap)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddToggleCapL`.
   */
  int cfunc_UnitAddToggleCap(lua_State* luaContext);

  /**
   * Address: 0x006C8BA0 (FUN_006C8BA0, func_UnitAddToggleCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:AddToggleCap(capName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitAddToggleCap_LuaFuncDef();

  /**
   * Address: 0x006C8C00 (FUN_006C8C00, cfunc_UnitAddToggleCapL)
   *
   * What it does:
   * Resolves toggle-cap lexical arg and ORs it into unit toggle-cap mask.
   */
  int cfunc_UnitAddToggleCapL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D550
   * COL:  0x00E85E38
   */
  using UnitRemoveToggleCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8D20 (FUN_006C8D20, cfunc_UnitRemoveToggleCap)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitRemoveToggleCapL`.
   */
  int cfunc_UnitRemoveToggleCap(lua_State* luaContext);

  /**
   * Address: 0x006C8D40 (FUN_006C8D40, func_UnitRemoveToggleCap_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RemoveToggleCap(capName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRemoveToggleCap_LuaFuncDef();

  /**
   * Address: 0x006C8DA0 (FUN_006C8DA0, cfunc_UnitRemoveToggleCapL)
   *
   * What it does:
   * Resolves toggle-cap lexical arg and clears it from unit toggle-cap mask.
   */
  int cfunc_UnitRemoveToggleCapL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D558
   * COL:  0x00E85DE8
   */
  using UnitRestoreToggleCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C8EC0 (FUN_006C8EC0, cfunc_UnitRestoreToggleCaps)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitRestoreToggleCapsL`.
   */
  int cfunc_UnitRestoreToggleCaps(lua_State* luaContext);

  /**
   * Address: 0x006C8EE0 (FUN_006C8EE0, func_UnitRestoreToggleCaps_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RestoreToggleCaps()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRestoreToggleCaps_LuaFuncDef();

  /**
   * Address: 0x006C8F40 (FUN_006C8F40, cfunc_UnitRestoreToggleCapsL)
   *
   * What it does:
   * Restores the runtime toggle-cap mask from the owning unit blueprint.
   */
  int cfunc_UnitRestoreToggleCapsL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D560
   * COL:  0x00E85D98
   */
  using UnitTestToggleCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C9000 (FUN_006C9000, cfunc_UnitTestToggleCaps)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitTestToggleCapsL`.
   */
  int cfunc_UnitTestToggleCaps(lua_State* luaContext);

  /**
   * Address: 0x006C9020 (FUN_006C9020, func_UnitTestToggleCaps_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:TestToggleCaps(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitTestToggleCaps_LuaFuncDef();

  /**
   * Address: 0x006C9080 (FUN_006C9080, cfunc_UnitTestToggleCapsL)
   *
   * What it does:
   * Resolves `(unit, toggleCapName)` and returns whether that toggle capability
   * bit is present in the owning blueprint.
   */
  int cfunc_UnitTestToggleCapsL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D568
   * COL:  0x00E85D48
   */
  using UnitSetRegenRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C91A0 (FUN_006C91A0, cfunc_UnitSetRegenRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetRegenRateL`.
   */
  int cfunc_UnitSetRegenRate(lua_State* luaContext);

  /**
   * Address: 0x006C91C0 (FUN_006C91C0, func_UnitSetRegenRate_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetRegenRate(rate)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetRegenRate_LuaFuncDef();

  /**
   * Address: 0x006C9220 (FUN_006C9220, cfunc_UnitSetRegenRateL)
   *
   * What it does:
   * Writes a clamped non-negative regen rate from arg #2 into arg #1 unit
   * attributes.
   */
  int cfunc_UnitSetRegenRateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D570
   * COL:  0x00E85CF8
   */
  using UnitRevertRegenRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C9330 (FUN_006C9330, cfunc_UnitRevertRegenRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitRevertRegenRateL`.
   */
  int cfunc_UnitRevertRegenRate(lua_State* luaContext);

  /**
   * Address: 0x006C9350 (FUN_006C9350, func_UnitRevertRegenRate_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:RevertRegenRate()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRevertRegenRate_LuaFuncDef();

  /**
   * Address: 0x006C93B0 (FUN_006C93B0, cfunc_UnitRevertRegenRateL)
   *
   * What it does:
   * Restores `UnitAttributes::regenRate` from blueprint defense regen data.
   */
  int cfunc_UnitRevertRegenRateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D578
   * COL:  0x00E85CA8
   */
  using UnitSetReclaimable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D580
   * COL:  0x00E85C58
   */
  using UnitSetCapturable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D588
   * COL:  0x00E85C08
   */
  using UnitIsCapturable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D590
   * COL:  0x00E85BB8
   */
  using UnitSetOverchargePaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D598
   * COL:  0x00E85B68
   */
  using UnitIsOverchargePaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5A0
   * COL:  0x00E85B18
   */
  using UnitSetBuildRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C9AC0 (FUN_006C9AC0, cfunc_UnitSetBuildRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetBuildRateL`.
   */
  int cfunc_UnitSetBuildRate(lua_State* luaContext);

  /**
   * Address: 0x006C9AE0 (FUN_006C9AE0, func_UnitSetBuildRate_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetBuildRate(frac)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetBuildRate_LuaFuncDef();

  /**
   * Address: 0x006C9B40 (FUN_006C9B40, cfunc_UnitSetBuildRateL)
   *
   * What it does:
   * Writes a clamped non-negative build-rate scalar from arg #2 into arg #1
   * unit attributes.
   */
  int cfunc_UnitSetBuildRateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5A8
   * COL:  0x00E85AC8
   */
  using UnitGetBuildRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006C9C50 (FUN_006C9C50, cfunc_UnitGetBuildRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetBuildRateL`.
   */
  int cfunc_UnitGetBuildRate(lua_State* luaContext);

  /**
   * Address: 0x006C9C70 (FUN_006C9C70, func_UnitGetBuildRate_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetBuildRate()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetBuildRate_LuaFuncDef();

  /**
   * Address: 0x006C9CD0 (FUN_006C9CD0, cfunc_UnitGetBuildRateL)
   *
   * What it does:
   * Returns `UnitAttributes::buildRate` for arg #1.
   */
  int cfunc_UnitGetBuildRateL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5B0
   * COL:  0x00E85A78
   */
  using UnitSetConsumptionPerSecondEnergy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5B8
   * COL:  0x00E85A28
   */
  using UnitSetConsumptionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5C0
   * COL:  0x00E859D8
   */
  using UnitSetProductionPerSecondEnergy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA0E0 (FUN_006CA0E0, cfunc_UnitSetProductionPerSecondEnergy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetProductionPerSecondEnergyL`.
   */
  int cfunc_UnitSetProductionPerSecondEnergy(lua_State* luaContext);

  /**
   * Address: 0x006CA100 (FUN_006CA100, func_UnitSetProductionPerSecondEnergy_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetProductionPerSecondEnergy(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetProductionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x006CA160 (FUN_006CA160, cfunc_UnitSetProductionPerSecondEnergyL)
   *
   * What it does:
   * Writes a clamped non-negative energy production-per-second scalar from
   * arg #2 into arg #1 unit attributes.
   */
  int cfunc_UnitSetProductionPerSecondEnergyL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5C8
   * COL:  0x00E85988
   */
  using UnitSetProductionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA270 (FUN_006CA270, cfunc_UnitSetProductionPerSecondMass)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetProductionPerSecondMassL`.
   */
  int cfunc_UnitSetProductionPerSecondMass(lua_State* luaContext);

  /**
   * Address: 0x006CA290 (FUN_006CA290, func_UnitSetProductionPerSecondMass_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetProductionPerSecondMass(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetProductionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x006CA2F0 (FUN_006CA2F0, cfunc_UnitSetProductionPerSecondMassL)
   *
   * What it does:
   * Writes a clamped non-negative mass production-per-second scalar from arg #2
   * into arg #1 unit attributes.
   */
  int cfunc_UnitSetProductionPerSecondMassL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5D0
   * COL:  0x00E85938
   */
  using UnitGetConsumptionPerSecondEnergy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA400 (FUN_006CA400, cfunc_UnitGetConsumptionPerSecondEnergy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetConsumptionPerSecondEnergyL`.
   */
  int cfunc_UnitGetConsumptionPerSecondEnergy(lua_State* luaContext);

  /**
   * Address: 0x006CA420 (FUN_006CA420, func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetConsumptionPerSecondEnergy()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x006CA480 (FUN_006CA480, cfunc_UnitGetConsumptionPerSecondEnergyL)
   *
   * What it does:
   * Returns `UnitAttributes::consumptionPerSecondEnergy` for arg #1.
   */
  int cfunc_UnitGetConsumptionPerSecondEnergyL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5D8
   * COL:  0x00E858E8
   */
  using UnitGetConsumptionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA550 (FUN_006CA550, cfunc_UnitGetConsumptionPerSecondMass)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetConsumptionPerSecondMassL`.
   */
  int cfunc_UnitGetConsumptionPerSecondMass(lua_State* luaContext);

  /**
   * Address: 0x006CA570 (FUN_006CA570, func_UnitGetConsumptionPerSecondMass_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetConsumptionPerSecondMass()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetConsumptionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x006CA5D0 (FUN_006CA5D0, cfunc_UnitGetConsumptionPerSecondMassL)
   *
   * What it does:
   * Returns `UnitAttributes::consumptionPerSecondMass` for arg #1.
   */
  int cfunc_UnitGetConsumptionPerSecondMassL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5E0
   * COL:  0x00E85898
   */
  using UnitGetProductionPerSecondEnergy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA6A0 (FUN_006CA6A0, cfunc_UnitGetProductionPerSecondEnergy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetProductionPerSecondEnergyL`.
   */
  int cfunc_UnitGetProductionPerSecondEnergy(lua_State* luaContext);

  /**
   * Address: 0x006CA6C0 (FUN_006CA6C0, func_UnitGetProductionPerSecondEnergy_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetProductionPerSecondEnergy()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetProductionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x006CA720 (FUN_006CA720, cfunc_UnitGetProductionPerSecondEnergyL)
   *
   * What it does:
   * Returns `UnitAttributes::productionPerSecondEnergy` for arg #1.
   */
  int cfunc_UnitGetProductionPerSecondEnergyL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5E8
   * COL:  0x00E85848
   */
  using UnitGetProductionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA7F0 (FUN_006CA7F0, cfunc_UnitGetProductionPerSecondMass)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitGetProductionPerSecondMassL`.
   */
  int cfunc_UnitGetProductionPerSecondMass(lua_State* luaContext);

  /**
   * Address: 0x006CA810 (FUN_006CA810, func_UnitGetProductionPerSecondMass_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetProductionPerSecondMass()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetProductionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x006CA870 (FUN_006CA870, cfunc_UnitGetProductionPerSecondMassL)
   *
   * What it does:
   * Returns `UnitAttributes::productionPerSecondMass` for arg #1.
   */
  int cfunc_UnitGetProductionPerSecondMassL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5F0
   * COL:  0x00E857F8
   */
  using UnitGetResourceConsumed_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CA940 (FUN_006CA940, cfunc_UnitGetResourceConsumed)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetResourceConsumedL`.
   */
  int cfunc_UnitGetResourceConsumed(lua_State* luaContext);

  /**
   * Address: 0x006CA960 (FUN_006CA960, func_UnitGetResourceConsumed_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetResourceConsumed()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetResourceConsumed_LuaFuncDef();

  /**
   * Address: 0x006CA9C0 (FUN_006CA9C0, cfunc_UnitGetResourceConsumedL)
   *
   * What it does:
   * Returns `Unit::ResourceConsumed` for arg #1.
   */
  int cfunc_UnitGetResourceConsumedL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D5F8
   * COL:  0x00E857A8
   */
  using UnitSetElevation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CAA80 (FUN_006CAA80, cfunc_UnitSetElevation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetElevationL`.
   */
  int cfunc_UnitSetElevation(lua_State* luaContext);

  /**
   * Address: 0x006CAAA0 (FUN_006CAAA0, func_UnitSetElevation_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetElevation(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetElevation_LuaFuncDef();

  /**
   * Address: 0x006CAB00 (FUN_006CAB00, cfunc_UnitSetElevationL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit elevation offset attribute.
   */
  int cfunc_UnitSetElevationL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D600
   * COL:  0x00E85758
   */
  using UnitRevertElevation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CABF0 (FUN_006CABF0, cfunc_UnitRevertElevation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitRevertElevationL`.
   */
  int cfunc_UnitRevertElevation(lua_State* luaContext);

  /**
   * Address: 0x006CAC10 (FUN_006CAC10, func_UnitRevertElevation_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:RevertElevation()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRevertElevation_LuaFuncDef();

  /**
   * Address: 0x006CAC70 (FUN_006CAC70, cfunc_UnitRevertElevationL)
   *
   * What it does:
   * Restores `UnitAttributes::spawnElevationOffset` from blueprint physics
   * elevation data.
   */
  int cfunc_UnitRevertElevationL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D608
   * COL:  0x00E85708
   */
  using UnitSetSpeedMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CAD20 (FUN_006CAD20, cfunc_UnitSetSpeedMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetSpeedMultL`.
   */
  int cfunc_UnitSetSpeedMult(lua_State* luaContext);

  /**
   * Address: 0x006CAD40 (FUN_006CAD40, func_UnitSetSpeedMult_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetSpeedMult(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetSpeedMult_LuaFuncDef();

  /**
   * Address: 0x006CADA0 (FUN_006CADA0, cfunc_UnitSetSpeedMultL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit speed-multiplier attribute.
   */
  int cfunc_UnitSetSpeedMultL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D610
   * COL:  0x00E856B8
   */
  using UnitSetAccMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CAE90 (FUN_006CAE90, cfunc_UnitSetAccMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetAccMultL`.
   */
  int cfunc_UnitSetAccMult(lua_State* luaContext);

  /**
   * Address: 0x006CAEB0 (FUN_006CAEB0, func_UnitSetAccMult_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetAccMult(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetAccMult_LuaFuncDef();

  /**
   * Address: 0x006CAF10 (FUN_006CAF10, cfunc_UnitSetAccMultL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit acceleration-multiplier attribute.
   */
  int cfunc_UnitSetAccMultL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D618
   * COL:  0x00E85668
   */
  using UnitSetTurnMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CB000 (FUN_006CB000, cfunc_UnitSetTurnMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetTurnMultL`.
   */
  int cfunc_UnitSetTurnMult(lua_State* luaContext);

  /**
   * Address: 0x006CB020 (FUN_006CB020, func_UnitSetTurnMult_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetTurnMult(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetTurnMult_LuaFuncDef();

  /**
   * Address: 0x006CB080 (FUN_006CB080, cfunc_UnitSetTurnMultL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit turn-multiplier attribute.
   */
  int cfunc_UnitSetTurnMultL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D620
   * COL:  0x00E85618
   */
  using UnitSetBreakOffTriggerMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CB170 (FUN_006CB170, cfunc_UnitSetBreakOffTriggerMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetBreakOffTriggerMultL`.
   */
  int cfunc_UnitSetBreakOffTriggerMult(lua_State* luaContext);

  /**
   * Address: 0x006CB190 (FUN_006CB190, func_UnitSetBreakOffTriggerMult_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetBreakOffTriggerMult(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetBreakOffTriggerMult_LuaFuncDef();

  /**
   * Address: 0x006CB1F0 (FUN_006CB1F0, cfunc_UnitSetBreakOffTriggerMultL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit break-off-trigger multiplier attribute.
   */
  int cfunc_UnitSetBreakOffTriggerMultL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D628
   * COL:  0x00E855C8
   */
  using UnitSetBreakOffDistanceMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CB2E0 (FUN_006CB2E0, cfunc_UnitSetBreakOffDistanceMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitSetBreakOffDistanceMultL`.
   */
  int cfunc_UnitSetBreakOffDistanceMult(lua_State* luaContext);

  /**
   * Address: 0x006CB300 (FUN_006CB300, func_UnitSetBreakOffDistanceMult_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetBreakOffDistanceMult(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetBreakOffDistanceMult_LuaFuncDef();

  /**
   * Address: 0x006CB360 (FUN_006CB360, cfunc_UnitSetBreakOffDistanceMultL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit break-off-distance multiplier attribute.
   */
  int cfunc_UnitSetBreakOffDistanceMultL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D630
   * COL:  0x00E85578
   */
  using UnitRevertCollisionShape_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D638
   * COL:  0x00E85528
   */
  using UnitRecoilImpulse_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D640
   * COL:  0x00E854D8
   */
  using UnitGetCurrentLayer_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D648
   * COL:  0x00E85488
   */
  using UnitCanPathTo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D650
   * COL:  0x00E85438
   */
  using UnitCanPathToRect_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D658
   * COL:  0x00E853E8
   */
  using UnitIsMobile_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D660
   * COL:  0x00E85398
   */
  using UnitIsMoving_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D668
   * COL:  0x00E85348
   */
  using UnitGetNavigator_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D670
   * COL:  0x00E852F8
   */
  using UnitGetVelocity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D678
   * COL:  0x00E852A8
   */
  using UnitGetStat_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D680
   * COL:  0x00E85258
   */
  using UnitSetStat_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D688
   * COL:  0x00E85208
   */
  using UnitSetWorkProgress_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CCB40 (FUN_006CCB40, cfunc_UnitSetWorkProgress)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetWorkProgressL`.
   */
  int cfunc_UnitSetWorkProgress(lua_State* luaContext);

  /**
   * Address: 0x006CCB60 (FUN_006CCB60, func_UnitSetWorkProgress_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetWorkProgress(progress)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetWorkProgress_LuaFuncDef();

  /**
   * Address: 0x006CCBC0 (FUN_006CCBC0, cfunc_UnitSetWorkProgressL)
   *
   * What it does:
   * Writes arg #2 into arg #1 unit work-progress runtime lane.
   */
  int cfunc_UnitSetWorkProgressL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D690
   * COL:  0x00E851B8
   */
  using UnitGetWorkProgress_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6A0
   * COL:  0x00E85118
   */
  using UnitGetGuardedUnit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6A8
   * COL:  0x00E850C8
   */
  using UnitGetGuards_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6B0
   * COL:  0x00E85078
   */
  using UnitGetTransportFerryBeacon_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6B8
   * COL:  0x00E85028
   */
  using UnitHasValidTeleportDest_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6C0
   * COL:  0x00E84FD8
   */
  using UnitAddUnitToStorage_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6C8
   * COL:  0x00E84F88
   */
  using UnitSetCustomName_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006CDB00 (FUN_006CDB00, cfunc_UnitSetCustomName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCustomNameL`.
   */
  int cfunc_UnitSetCustomName(lua_State* luaContext);

  /**
   * Address: 0x006CDB20 (FUN_006CDB20, func_UnitSetCustomName_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetCustomName(name)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetCustomName_LuaFuncDef();

  /**
   * Address: 0x006CDB80 (FUN_006CDB80, cfunc_UnitSetCustomNameL)
   *
   * What it does:
   * Resolves `(self, name)` and dispatches `Unit::SetCustomName`.
   */
  int cfunc_UnitSetCustomNameL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D6D0
   * COL:  0x00E84F38
   */
  using UnitHasMeleeSpaceAroundTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6D8
   * COL:  0x00E84EE8
   */
  using UnitMeleeWarpAdjacentToTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6E0
   * COL:  0x00E84E98
   */
  using UnitGetCommandQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6E8
   * COL:  0x00E84E48
   */
  using UnitPrintCommandQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6F0
   * COL:  0x00E84DF8
   */
  using UnitGetCurrentMoveLocation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D6F8
   * COL:  0x00E84DA8
   */
  using UnitGiveNukeSiloAmmo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D700
   * COL:  0x00E84D58
   */
  using UnitRemoveNukeSiloAmmo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D708
   * COL:  0x00E84D08
   */
  using UnitGetNukeSiloAmmoCount_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D710
   * COL:  0x00E84CB8
   */
  using UnitGiveTacticalSiloAmmo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D718
   * COL:  0x00E84C68
   */
  using UnitRemoveTacticalSiloAmmo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D720
   * COL:  0x00E84C18
   */
  using UnitGetTacticalSiloAmmoCount_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D740
   * COL:  0x00E84AD8
   */
  using UnitCanBuild_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D748
   * COL:  0x00E84A88
   */
  using UnitGetRallyPoint_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D750
   * COL:  0x00E84A38
   */
  using UnitGetFuelUseTime_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D758
   * COL:  0x00E849E8
   */
  using UnitSetFuelUseTime_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D760
   * COL:  0x00E84998
   */
  using UnitGetFuelRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D768
   * COL:  0x00E84948
   */
  using UnitSetFuelRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D770
   * COL:  0x00E848F8
   */
  using UnitSetShieldRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x006D0400 (FUN_006D0400, func_UnitCanBuild_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:CanBuild(blueprint)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitCanBuild_LuaFuncDef();

  /**
   * Address: 0x006D08F0 (FUN_006D08F0, func_UnitSetFuelUseTime_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetFuelUseTime(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetFuelUseTime_LuaFuncDef();

  /**
   * Address: 0x006D0BD0 (FUN_006D0BD0, func_UnitSetFuelRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetFuelRatio(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetFuelRatio_LuaFuncDef();

  /**
   * Address: 0x006D0D30 (FUN_006D0D30, cfunc_UnitSetShieldRatio)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetShieldRatioL`.
   */
  int cfunc_UnitSetShieldRatio(lua_State* luaContext);

  /**
   * Address: 0x006D0D50 (FUN_006D0D50, func_UnitSetShieldRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetShieldRatio(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x006D0DB0 (FUN_006D0DB0, cfunc_UnitSetShieldRatioL)
   *
   * What it does:
   * Resolves `(self, value)` and writes `Unit::ShieldRatio`.
   */
  int cfunc_UnitSetShieldRatioL(LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E2D778
   * COL:  0x00E848A8
   */
  using UnitGetShieldRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D780
   * COL:  0x00E84858
   */
  using UnitGetBlip_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D788
   * COL:  0x00E84808
   */
  using UnitTransportHasSpaceFor_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D790
   * COL:  0x00E847B8
   */
  using UnitTransportHasAvailableStorage_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D798
   * COL:  0x00E84768
   */
  using UnitShowBone_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D7A0
   * COL:  0x00E84718
   */
  using UnitHideBone_LuaFuncDef = ::moho::CScrLuaBinder;

} // namespace moho
