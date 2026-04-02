// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/lua/CScrLuaBinderFwd.h"

#include <cstddef>
#include <cstdint>
#include <string>

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
  class RUnitBlueprint;
  class ReconBlip;
  class StatItem;
  class UserUnit;
  class VTransform;
  struct SExtraUnitData;
} // namespace moho
namespace moho
{
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
   * Reflection type in RTTI: Moho::SSTIUnitConstantData
   * Size evidence:
   * - SSTIUnitConstantDataTypeInfo::Init (0x0055C470) sets sizeof(type)=16.
   * - Unit ctor (0x006A53F0) initializes this block at +0x278 via sub_5BD720.
   */
  struct SSTIUnitConstantData
  {
    std::uint8_t mByte0;    // +0x00
    std::uint8_t pad_01[3]; // +0x01
    void* mStatsRoot;       // +0x04 (Unit::GetStat virtuals pass this+0x27C to Stats<StatItem> resolvers)
    void* mRefObject;       // +0x08
    std::uint8_t mByteC;    // +0x0C
    std::uint8_t pad_0D[3]; // +0x0D
  };
  static_assert(sizeof(SSTIUnitConstantData) == 0x10, "SSTIUnitConstantData size must be 0x10");

  /**
   * Reflection type in RTTI: Moho::SSTIUnitVariableData
   * Size evidence:
   * - SSTIUnitVariableDataTypeInfo::Init (0x0055C680) sets sizeof(type)=552 (0x228).
   * - Unit ctor (0x006A53F0) initializes this block starting at +0x288.
   */
  struct SSTIUnitVariableData
  {
    std::uint8_t storage[0x228];
  };
  static_assert(sizeof(SSTIUnitVariableData) == 0x228, "SSTIUnitVariableData size must be 0x228");
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
     * Address: 0x006A4BC0
     * Slot: 0
     * Demangled: public: virtual class moho::Unit const near * __thiscall moho::Unit::IsUnit(void)const
     */
    virtual Unit const* IsUnit() const;

    /**
     * Address: 0x006A4BB0
     * Slot: 1
     * Demangled: public: virtual class moho::Unit near * __thiscall moho::Unit::IsUnit(void)
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
     * Address: 0x006A7DC0
     * Slot: 14
     * Demangled: public: virtual bool __thiscall moho::Unit::IsNavigatorIdle(void)const
     */
    virtual bool IsNavigatorIdle() const;

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
     * Address: 0x006A73A0
     * Slot: 22
     * Demangled: public: virtual void __thiscall moho::Unit::SetAutoMode(bool)
     */
    virtual void SetAutoMode(bool);

    /**
     * Address: 0x006A73E0
     * Slot: 23
     * Demangled: public: virtual void __thiscall moho::Unit::SetAutoSurfaceMode(bool)
     */
    virtual void SetAutoSurfaceMode(bool);

    /**
     * Address: 0x006A4A30
     * Slot: 24
     * Demangled: public: virtual bool __thiscall moho::Unit::IsAutoMode(void)const
     */
    virtual bool IsAutoMode() const;

    /**
     * Address: 0x006A4A40
     * Slot: 25
     * Demangled: public: virtual bool __thiscall moho::Unit::IsAutoSurfaceMode(void)const
     */
    virtual bool IsAutoSurfaceMode() const;

    /**
     * Address: 0x006A4A50
     * Slot: 26
     * Demangled: public: virtual void __thiscall moho::Unit::SetCustomName(class std::basic_string<char,struct
     * std::char_traits<char>,class std::allocator<char>>)
     */
    virtual void SetCustomName(std::basic_string<char, std::char_traits<char>, std::allocator<char>>);

    /**
     * Address: 0x006A4AB0
     * Slot: 27
     * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>
     * __thiscall moho::Unit::GetCustomName(void)const
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
     * Sets the paused state and emits OnPaused/OnUnpaused callbacks.
     */
    void SetPaused(bool paused);

    /**
     * Address: 0x006A7450 (FUN_006A7450)
     *
     * What it does:
     * Sets repeat-queue mode and emits OnStartRepeatQueue/OnStopRepeatQueue callbacks.
     */
    void SetRepeatQueue(bool enabled);

    /**
     * Address: 0x006AA900 (FUN_006AA900, ?SetConsumptionActive@Unit@Moho@@QAEX_N@Z)
     *
     * What it does:
     * Rebuilds unit upkeep request lanes for active/inactive economy
     * consumption and dispatches matching Lua script callbacks.
     */
    void SetConsumptionActive(bool isActive);

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
     * Updates fire-state storage used by UI/sync replication.
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
     * Address: 0x0062EE00 (FUN_0062EE00, Moho::Unit::GetStagingPlatform)
     *
     * What it does:
     * Resolves `TransportedByRef` and returns the parent transport unit when
     * it is alive and flagged as an air-staging platform.
     */
    [[nodiscard]]
    Unit* GetStagingPlatform() const;

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
    union
    {
      struct
      {
        float EconomyEventRequestedEnergyRate; // 0x02F8
        float EconomyEventRequestedMassRate;   // 0x02FC
      };
      struct
      {
        float MaintainenceCostEnergy; // 0x02F8
        float MaintainenceCostMass;   // 0x02FC
      };
    };
    char pad_0300[16];                                   // 0x0300
    class CAniPose* AnimationPose;                       // 0x0310
    char pad_0314[0x114];                                // 0x0314
    UnitAttributes Attributes;                           // 0x0428
    std::uint32_t ScriptBitMask;                         // 0x0498: toggled by ToggleScriptBit
    std::uint32_t pad_049C;                              // 0x049C
    std::uint64_t UnitStateMask;                         // 0x04A0
    char pad_04A8[8];                                    // 0x04A8
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
    char GuardedByListStorage[24];                       // 0x04F8
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
    char pad_0561[0x13];                             // 0x0561
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

  static_assert(offsetof(Unit, GuardedByListStorage) == 0x04F8, "Unit::GuardedByListStorage offset must be 0x04F8");
  static_assert(offsetof(Unit, PriorityBoost) == 0x0530, "Unit::PriorityBoost offset must be 0x0530");
  static_assert(offsetof(Unit, mConsumptionData) == 0x0534, "Unit::mConsumptionData offset must be 0x0534");
  static_assert(
    offsetof(Unit, MaintainenceCostEnergy) == 0x02F8, "Unit::MaintainenceCostEnergy offset must be 0x02F8"
  );
  static_assert(
    offsetof(Unit, MaintainenceCostMass) == 0x02FC, "Unit::MaintainenceCostMass offset must be 0x02FC"
  );
  static_assert(
    offsetof(Unit, EconomyEventRequestedEnergyRate) == 0x02F8,
    "Unit::EconomyEventRequestedEnergyRate offset must be 0x02F8"
  );
  static_assert(
    offsetof(Unit, EconomyEventRequestedMassRate) == 0x02FC,
    "Unit::EconomyEventRequestedMassRate offset must be 0x02FC"
  );
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
  static_assert(offsetof(Unit, mEconomyEventListHead) == 0x0574, "Unit::mEconomyEventListHead offset must be 0x0574");
  static_assert(offsetof(Unit, mReconBlips) == 0x0670, "Unit::mReconBlips offset must be 0x0670");
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
   * VFTABLE: 0x00E2D3F0
   * COL:  0x00E86BF8
   */
  using UnitGetWeaponCount_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D3F8
   * COL:  0x00E86BA8
   */
  using UnitGetTargetEntity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D400
   * COL:  0x00E86B58
   */
  using UnitGetHealth_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D408
   * COL:  0x00E86B08
   */
  using UnitGetAttacker_LuaFuncDef = ::moho::CScrLuaBinder;

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
   * VFTABLE: 0x00E2D430
   * COL:  0x00E86978
   */
  using UnitSetStrategicUnderlay_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D438
   * COL:  0x00E86928
   */
  using UnitIsUnitState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D440
   * COL:  0x00E868D8
   */
  using UnitIsIdleState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D448
   * COL:  0x00E86888
   */
  using UnitIsStunned_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D450
   * COL:  0x00E86838
   */
  using UnitIsBeingBuilt_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D458
   * COL:  0x00E867E8
   */
  using UnitIsPaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D460
   * COL:  0x00E86798
   */
  using UnitSetPaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D468
   * COL:  0x00E86748
   */
  using UnitSetConsumptionActive_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D470
   * COL:  0x00E866F8
   */
  using UnitSetProductionActive_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D478
   * COL:  0x00E866A8
   */
  using UnitSetBusy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D480
   * COL:  0x00E86658
   */
  using UnitSetBlockCommandQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D488
   * COL:  0x00E86608
   */
  using UnitSetImmobile_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D490
   * COL:  0x00E865B8
   */
  using UnitSetStunned_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D498
   * COL:  0x00E86568
   */
  using UnitSetUnSelectable_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4A0
   * COL:  0x00E86518
   */
  using UnitSetDoNotTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4A8
   * COL:  0x00E864C8
   */
  using UnitSetUnitState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4B0
   * COL:  0x00E86478
   */
  using UnitStopSiloBuild_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4B8
   * COL:  0x00E86428
   */
  using UnitSetIsValidTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4C0
   * COL:  0x00E863D8
   */
  using UnitIsValidTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4C8
   * COL:  0x00E86388
   */
  using UnitGetNumBuildOrders_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4D0
   * COL:  0x00E86338
   */
  using UnitCalculateWorldPositionFromRelative_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4D8
   * COL:  0x00E862E8
   */
  using UnitGetScriptBit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4E0
   * COL:  0x00E86298
   */
  using UnitSetScriptBit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4E8
   * COL:  0x00E86248
   */
  using UnitToggleScriptBit_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4F0
   * COL:  0x00E861F8
   */
  using UnitToggleFireState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D4F8
   * COL:  0x00E861A8
   */
  using UnitSetFireState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D500
   * COL:  0x00E86158
   */
  using UnitGetFireState_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D508
   * COL:  0x00E86108
   */
  using UnitSetAutoMode_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D510
   * COL:  0x00E860B8
   */
  using UnitAddBuildRestriction_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D518
   * COL:  0x00E86068
   */
  using UnitRemoveBuildRestriction_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D520
   * COL:  0x00E86018
   */
  using UnitRestoreBuildRestrictions_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D528
   * COL:  0x00E85FC8
   */
  using UnitAddCommandCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D530
   * COL:  0x00E85F78
   */
  using UnitRemoveCommandCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D538
   * COL:  0x00E85F28
   */
  using UnitRestoreCommandCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D540
   * COL:  0x00E85ED8
   */
  using UnitTestCommandCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D548
   * COL:  0x00E85E88
   */
  using UnitAddToggleCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D550
   * COL:  0x00E85E38
   */
  using UnitRemoveToggleCap_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D558
   * COL:  0x00E85DE8
   */
  using UnitRestoreToggleCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D560
   * COL:  0x00E85D98
   */
  using UnitTestToggleCaps_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D568
   * COL:  0x00E85D48
   */
  using UnitSetRegenRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D570
   * COL:  0x00E85CF8
   */
  using UnitRevertRegenRate_LuaFuncDef = ::moho::CScrLuaBinder;

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
   * VFTABLE: 0x00E2D5A8
   * COL:  0x00E85AC8
   */
  using UnitGetBuildRate_LuaFuncDef = ::moho::CScrLuaBinder;

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
   * VFTABLE: 0x00E2D5C8
   * COL:  0x00E85988
   */
  using UnitSetProductionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5D0
   * COL:  0x00E85938
   */
  using UnitGetConsumptionPerSecondEnergy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5D8
   * COL:  0x00E858E8
   */
  using UnitGetConsumptionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5E0
   * COL:  0x00E85898
   */
  using UnitGetProductionPerSecondEnergy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5E8
   * COL:  0x00E85848
   */
  using UnitGetProductionPerSecondMass_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5F0
   * COL:  0x00E857F8
   */
  using UnitGetResourceConsumed_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D5F8
   * COL:  0x00E857A8
   */
  using UnitSetElevation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D600
   * COL:  0x00E85758
   */
  using UnitRevertElevation_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D608
   * COL:  0x00E85708
   */
  using UnitSetSpeedMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D610
   * COL:  0x00E856B8
   */
  using UnitSetAccMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D618
   * COL:  0x00E85668
   */
  using UnitSetTurnMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D620
   * COL:  0x00E85618
   */
  using UnitSetBreakOffTriggerMult_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E2D628
   * COL:  0x00E855C8
   */
  using UnitSetBreakOffDistanceMult_LuaFuncDef = ::moho::CScrLuaBinder;

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
