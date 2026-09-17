#pragma once

#include <cstddef>
#include <cstdint>

#include "../../gpg/core/containers/FastVector.h"
#include "../../gpg/core/containers/Set.h"
#include "../../legacy/containers/String.h"
#include "../../legacy/containers/Vector.h"
#include "../entity/EntityCategoryReflection.h"
#include "ESquadClass.h"
#include "SimArmy.h"
#include "STIMap.h"
#include "Wm3Vector2.h"

namespace LuaPlus
{
  class LuaObject;
}

namespace moho
{
  class Entity;
  class Sim;
  class CInfluenceMap;
  class CAiBrain;
  class CAiReconDBImpl;
  class CArmyStats;
  class CPlatoon;
  class CSimArmyEconomyInfo;
  class CIntelGrid;
  class UserArmy;
  class Unit;
  struct ArmyLaunchInfo;

  struct ArmyPool
  {
    // +0x00..+0x2F: fastvector_n header + inline platoon pointer storage
    // (start_, end_, capacity_, originalVec_, inlineVec_[8]). This is the
    // whole struct -- what was previously modeled as a trailing `unknown30`
    // scalar at ArmyPool+0x30 is not part of ArmyPool at all: it is the
    // `myProxy_` (debug-iterator) lane of the adjacent, separate
    // `CArmyImpl::UnitCategorySets` real `msvc8::vector<SEntitySetTemplateUnit>`
    // member that starts immediately after this struct (CArmyImpl+0x258).
    // Evidence: `CArmyImpl::CArmyImpl` (0x006FE690) builds the category-set
    // count/value arguments and calls `sub_702450` (`resize`) at 0x006FF2E1
    // with `edx = lea [ebp+258h]` -- i.e. the vector object's own address,
    // one dword *before* `UnitCategorySetsBegin` (formerly modeled at
    // CArmyImpl+0x25C). `sub_702450`/`sub_7030C0` (`_Insert_n`) only ever
    // read/write `*(obj+4)`/`*(obj+8)`/`*(obj+0xC)` (first_/last_/end_),
    // never `*(obj+0)` -- exactly the `msvc8::vector<T>` shape (leading
    // unused proxy slot). Independently confirmed by
    // `gpg::RVectorType<SEntitySetTemplateUnit>::Init()`
    // (ArmyUnitSetVectorReflection.cpp), which sets
    // `size_ = sizeof(msvc8::vector<SEntitySetTemplateUnit>)` == 0x10 (16
    // bytes) for the exact same reflected field.
    gpg::fastvector_n<CPlatoon*, 8> platoons;
  };

  static_assert(sizeof(gpg::fastvector_n<CPlatoon*, 8>) == 0x30, "gpg::fastvector_n<CPlatoon*,8> size must be 0x30");
  static_assert(sizeof(ArmyPool) == 0x30, "ArmyPool size must be 0x30");
  static_assert(offsetof(ArmyPool, platoons) == 0x00, "ArmyPool::platoons offset must be 0x00");
  static_assert(offsetof(ArmyPool, platoons.start_) == 0x00, "ArmyPool::platoons.start_ offset must be 0x00");
  static_assert(offsetof(ArmyPool, platoons.end_) == 0x04, "ArmyPool::platoons.end_ offset must be 0x04");
  static_assert(offsetof(ArmyPool, platoons.capacity_) == 0x08, "ArmyPool::platoons.capacity_ offset must be 0x08");
  static_assert(
    offsetof(ArmyPool, platoons.originalVec_) == 0x0C, "ArmyPool::platoons.originalVec_ offset must be 0x0C"
  );
  static_assert(offsetof(ArmyPool, platoons.inlineVec_) == 0x10, "ArmyPool::platoons.inlineVec_ offset must be 0x10");

  class CArmyImpl : public SimArmy
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006FE5B0 (FUN_006FE5B0, ??0CArmyImpl@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Initializes CArmyImpl-owned runtime pointer lanes and inline platoon
     * pool header storage.
     */
    CArmyImpl();

    /**
     * Address: 0x006FE690 (FUN_006FE690, Moho::CArmyImpl::CArmyImpl)
     *
     * What it does:
     * Builds one scenario-launched army from Lua setup data, command-source
     * launch state, and scenario options, then creates the per-army runtime
     * economy, brain, recon, influence-map, platoon-pool, and path queue lanes.
     */
    CArmyImpl(
      Sim* sim,
      std::int32_t armyIndex,
      const ArmyLaunchInfo& launchInfo,
      const LuaPlus::LuaObject& armySetup,
      const LuaPlus::LuaObject& scenarioInfoOptions,
      bool isFocusArmy
    );

    /**
     * Address: 0x006FE670 (FUN_006FE670)
     *
     * What it does:
     * Destroys CArmyImpl runtime state and releases owned per-army systems.
     */
    ~CArmyImpl() override;

    /** Address: 0x006FDC10 (FUN_006FDC10, Moho::CArmyImpl::GetSim) */
    Sim* GetSim() override;
    /** Address: 0x006FFC90 (FUN_006FFC90, Moho::CArmyImpl::IsHuman) */
    bool IsHuman() override;
    /** Address: 0x006FDC20 (FUN_006FDC20, Moho::CArmyImpl::GetArmyType) */
    const char* GetArmyType() override;
    /** Address: 0x006FDC40 (FUN_006FDC40, Moho::CArmyImpl::SetArmyPlans) */
    void SetArmyPlans(const msvc8::string& armyPlans) override;
    /** Address: 0x006FDC60 (FUN_006FDC60, Moho::CArmyImpl::GetArmyPlans) */
    const char* GetArmyPlans() override;
    /** Address: 0x006FDC80 (FUN_006FDC80, Moho::CArmyImpl::GetIGrid) */
    CInfluenceMap* GetIGrid() override;
    /** Address: 0x006FDC90 (FUN_006FDC90, Moho::CArmyImpl::GetArmyBrain) */
    CAiBrain* GetArmyBrain() override;
    /** Address: 0x006FDCA0 (FUN_006FDCA0, Moho::CArmyImpl::GetReconDB) */
    CAiReconDBImpl* GetReconDB() override;
    /** Address: 0x006FDCB0 (FUN_006FDCB0, Moho::CArmyImpl::GetEconomy) */
    CSimArmyEconomyInfo* GetEconomy() override;
    /** Address: 0x006FFCB0 (FUN_006FFCB0, Moho::CArmyImpl::GenerateArmyStart) */
    void GenerateArmyStart() override;
    /** Address: 0x006FDCC0 (FUN_006FDCC0, Moho::CArmyImpl::SetArmyStart) */
    void SetArmyStart(const Wm3::Vector2f& startPosition) override;
    /** Address: 0x006FDCE0 (FUN_006FDCE0, Moho::CArmyImpl::GetArmyStartPos) */
    void GetArmyStartPos(Wm3::Vector2f& outStartPosition) override;
    /** Address: 0x006FDF30 (FUN_006FDF30, Moho::CArmyImpl::SetAlliance) */
    void SetAlliance(std::uint32_t armyId, int relationIndex) override;

    /**
     * Address: 0x006FDEE0 (FUN_006FDEE0, Moho::CArmyImpl::SetCanSee)
     *
     * What it does:
     * Updates ally-visibility flag from current focused-army sync filter.
     */
    void SetCanSee(std::int32_t focusArmyIndex);

    /**
     * Address: 0x006FFF70 (FUN_006FFF70, Moho::CArmyImpl::RenderDebugPlayableRect)
     *
     * What it does:
     * Emits playable-rect debug contour lines when debug convar is enabled.
     */
    void RenderDebugPlayableRect();

    /**
     * Address: 0x00700820 (FUN_00700820, Moho::CArmyImpl::CleanUpPlatoons)
     *
     * What it does:
     * Removes idle/empty platoons and dispatches platoon destroy script hooks.
     */
    void CleanUpPlatoons();

    /** Address: 0x00700FC0 (FUN_00700FC0, Moho::CArmyImpl::OnCommandSourceTerminated) */
    void OnCommandSourceTerminated(std::uint32_t sourceId) override;

    /**
     * Address: 0x006FFD70 (FUN_006FFD70, Moho::CArmyImpl::OnTick)
     *
     * What it does:
     * Executes this army's per-tick update path (visibility, AI tasks, and
     * debug/stat refresh lanes).
     */
    void OnTick() override;
    /** Address: 0x00700080 (FUN_00700080, Moho::CArmyImpl::GetConstDat) */
    SSTIArmyConstantData* CopyArmyConstantData(SSTIArmyConstantData* outBuffer) override;
    /** Address: 0x00700240 (FUN_00700240, Moho::CArmyImpl::CopyArmyVariableData) */
    SSTIArmyVariableData* CopyArmyVariableData(SSTIArmyVariableData* outBuffer) override;
    /** Address: 0x006FDD50 (FUN_006FDD50, Moho::CArmyImpl::GetArmyStats) */
    CArmyStats* GetArmyStats() override;
    /** Address: 0x006FDD60 (FUN_006FDD60, Moho::CArmyImpl::GetArmyUnitCostTotal) */
    float GetArmyUnitCostTotal() override;
    /** Address: 0x006FDDE0 (FUN_006FDDE0, Moho::CArmyImpl::GetPathFinder) */
    void* GetPathFinder() override;
    /** Address: 0x006FDDF0 (FUN_006FDDF0, Moho::CArmyImpl::SetUnknownSharedRef) */
    boost::SharedPtrRaw<void>* SetUnknownSharedRef(boost::SharedPtrRaw<void>* value) override;
    /** Address: 0x006FDE40 (FUN_006FDE40, Moho::CArmyImpl::GetUnknownSharedRef) */
    boost::SharedPtrRaw<void>* GetUnknownSharedRef(boost::SharedPtrRaw<void>* outValue) override;
    /** Address: 0x006FDE70 (FUN_006FDE70, Moho::CArmyImpl::SetUnknownVectorWithMeta) */
    std::uint32_t SetUnknownVectorWithMeta(const SArmyVectorWithMeta* value) override;
    /** Address: 0x006FDE90 (FUN_006FDE90, Moho::CArmyImpl::GetPlatoonsList) */
    void GetPlatoonsList(ArmyPool& outPool) override;
    /** Address: 0x00700410 (FUN_00700410, Moho::CArmyImpl::MakePlatoon) */
    virtual CPlatoon* MakePlatoon(const char* platoonName, const char* aiPlan) override;
    /** Address: 0x00700470 (FUN_00700470, Moho::CArmyImpl::GetPlatoonByName) */
    CPlatoon* GetPlatoonByName(const char* platoonName) override;
    /** Address: 0x007004E0 (FUN_007004E0, Moho::CArmyImpl::GetPlatoonFor) */
    CPlatoon* GetPlatoonFor(int queryArg, ESquadClass* outSquadClass) override;
    /**
     * Address: 0x007005F0 (FUN_007005F0, Moho::CArmyImpl::DisbandPlatoonUniquelyNamed)
     *
     * What it does:
     * Removes one uniquely-named platoon from this army and destroys it.
     */
    void DisbandPlatoonUniquelyNamed(const char* platoonName) override;

    /**
     * Address: 0x00700540 (FUN_00700540, Moho::CArmyImpl::DisbandPlatoon)
     *
     * What it does:
     * Removes one platoon pointer from this army and destroys it.
     */
    void DisbandPlatoon(CPlatoon* platoon) override;
    /**
     * Address: 0x007006C0 (FUN_007006C0, Moho::CArmyImpl::AssignUnitsToPlatoon)
     *
     * What it does:
     * Removes all provided units from their current platoons, then appends
     * that unit set into the unassigned squad of the named platoon.
     */
    void AssignUnitsToPlatoon(const SEntitySetTemplateUnit* units, const char* platoonName) override;
    /** Address: 0x00700700 (FUN_00700700, Moho::CArmyImpl::RemoveFromPlatoon) */
    void RemoveFromPlatoon(Unit* unit) override;
    /** Address: 0x00700730 (FUN_00700730, Moho::CArmyImpl::RemoveUnitsFromPlatoons) */
    void RemoveUnitsFromPlatoons(const SEntitySetTemplateUnit* units) override;
    /** Address: 0x00700770 (FUN_00700770, Moho::CArmyImpl::GetNumPlatoonsTemplateNamed) */
    int GetNumPlatoonsTemplateNamed(const char* templateName) override;
    /** Address: 0x007007C0 (FUN_007007C0, Moho::CArmyImpl::GetNumPlatoonWithPlan) */
    int GetNumPlatoonWithPlan(const char* planName) override;
    /** Address: 0x00700A00 (FUN_00700A00, Moho::CArmyImpl::CountUnitsInBoundsXZ) */
    int CountUnitsInBoundsXZ(
      const Wm3::Vector3f& minBounds, const Wm3::Vector3f& maxBounds, const SEntitySetTemplateUnit& unitSet
    ) override;
    /** Address: 0x00700A70 (FUN_00700A70, Moho::CArmyImpl::UpdateAIDebugPlatoonStats) */
    void UpdateAIDebugPlatoonStats(Unit* unit) override;
    /** Address: 0x00700E20 (FUN_00700E20, Moho::CArmyImpl::AddUnitToCategorySet) */
    void AddUnitToCategorySet(Unit* unit) override;
    /** Address: 0x00700E70 (FUN_00700E70, Moho::CArmyImpl::ConsumeUnitFromCategorySet) */
    bool ConsumeUnitFromCategorySet(Unit* unit) override;
    /** Address: 0x00700EB0 (FUN_00700EB0, Moho::CArmyImpl::GetUnits) */
    void* GetUnits(void* outUnits, void* filterBuckets) override;
    /** Address: 0x006FE090 (FUN_006FE090, Moho::CArmyImpl::GetAlliedArmies) */
    msvc8::vector<CArmyImpl*>* GetAlliedArmies(msvc8::vector<CArmyImpl*>* outArmyList) override;
    /** Address: 0x006FDD00 (FUN_006FDD00, Moho::CArmyImpl::GetUnitCap) */
    float GetUnitCap() override;
    /** Address: 0x006FDD10 (FUN_006FDD10, Moho::CArmyImpl::SetUnitCap) */
    void SetUnitCap(float unitCap) override;
    /** Address: 0x006FDD30 (FUN_006FDD30, Moho::CArmyImpl::IgnoreUnitCap) */
    bool IgnoreUnitCap() override;
    /** Address: 0x006FDD40 (FUN_006FDD40, Moho::CArmyImpl::SetUseUnitCap) */
    void SetUseUnitCap(bool useUnitCap) override;
    /** Address: 0x006FDEC0 (FUN_006FDEC0, Moho::CArmyImpl::SetIgnorePlayableRect) */
    void SetIgnorePlayableRect(bool ignorePlayableRect) override;
    /** Address: 0x006FDED0 (FUN_006FDED0, Moho::CArmyImpl::UseWholeMap) */
    bool UseWholeMap() override;
    /** Address: 0x006FE1B0 (FUN_006FE1B0, Moho::CArmyImpl::AddBuildRestriction) */
    void AddBuildRestriction(void* restriction) override;
    /** Address: 0x006FE220 (FUN_006FE220, Moho::CArmyImpl::RemoveBuildRestriction) */
    void RemoveBuildRestriction(void* restriction) override;
    /** Address: 0x006FE290 (FUN_006FE290, Moho::CArmyImpl::SetNoRushTimer) */
    void SetNoRushTimer(float seconds) override;
    /** Address: 0x006FE2B0 (FUN_006FE2B0, Moho::CArmyImpl::SetNoRushRadius) */
    void SetNoRushRadius(float radius) override;
    /** Address: 0x006FE2D0 (FUN_006FE2D0, Moho::CArmyImpl::SetNoRushOffset) */
    void SetNoRushOffset(float offsetX, float offsetY) override;
    /** Address: 0x006FE2F0 (FUN_006FE2F0, Moho::CArmyImpl::GetPathcapLand) */
    std::int32_t GetPathcapLand() override;
    /** Address: 0x006FE300 (FUN_006FE300, Moho::CArmyImpl::GetPathcapSea) */
    std::int32_t GetPathcapSea() override;
    /** Address: 0x006FE310 (FUN_006FE310, Moho::CArmyImpl::GetPathcapBoth) */
    std::int32_t GetPathcapBoth() override;

    /**
     * Address: 0x00705BE0 (FUN_00705BE0, Moho::CArmyImpl::MemberDeserialize)
     *
     * What it does:
     * Deserializes CArmyImpl-owned runtime fields and dependent owned pointers.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00705E40 (FUN_00705E40, Moho::CArmyImpl::MemberSerialize)
     *
     * What it does:
     * Serializes CArmyImpl-owned runtime fields and dependent owned pointers.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x007010B0 (FUN_007010B0, Moho::CArmyImpl::DeserializePlatoons)
     *
     * What it does:
     * Reads owned platoon pointers until null terminator and appends them into
     * the platoon pool.
     */
    void DeserializePlatoons(gpg::ReadArchive* archive);

    /**
     * Address: 0x00701130 (FUN_00701130, Moho::CArmyImpl::SerializePlatoons)
     *
     * What it does:
     * Writes owned platoon pointers from the platoon pool and emits a null
     * pointer terminator.
     */
    void SerializePlatoons(gpg::WriteArchive* archive) const;

  public:
    // +0x00 vfptr (SimArmy), +0x04 alignment padding, +0x08..+0x1E8 the
    // replicated IArmy payload (mConstDat / mVarDat, see IArmy.h). This class's
    // own state starts here.
    Sim* Simulation;                                     // 0x01E8
    CAiBrain* AiBrain;                                   // 0x01EC
    CAiReconDBImpl* AiReconDb;                           // 0x01F0
    CSimArmyEconomyInfo* EconomyInfo;                    // 0x01F4
    msvc8::string ArmyPlans;                             // 0x01F8
    CArmyStats* Stats;                                   // 0x0214
    CInfluenceMap* InfluenceMap;                         // 0x0218 (FUN_006FDC80 / mIMmap)
    void* PathFinder;                                    // 0x021C
    boost::SharedPtrRaw<void> UnknownShared220;          // 0x0220
    ArmyPool PlatoonPool;                                // 0x0228
    /**
     * Real `msvc8::vector<SEntitySetTemplateUnit>` (0x258: myProxy_,
     * 0x25C: first_/begin, 0x260: last_/end, 0x264: end_/capacityEnd),
     * one per-category-bit-index cached unit set. Built by
     * `InitializeArmyUnitCategorySets` (FUN_006FE690 tail via
     * `sub_702450`/`sub_7030C0`, i.e. `resize(count)`) and consumed by
     * `ResolveCategorySetForUnit`, `~CArmyImpl` (via `TeardownEntitySetRange`),
     * and the `MemberSerialize`/`MemberDeserialize` reflection lanes.
     */
    msvc8::vector<SEntitySetTemplateUnit> UnitCategorySets; // 0x0258
    std::uint32_t UnitCategoryBaseIndex;                 // 0x0268
    std::uint32_t UnitCategoryMaxIndex;                  // 0x026C
    float UnitCapacity;                                  // 0x0270
    std::uint8_t IgnoreUnitCapFlag;                      // 0x0274
    char pad_0275[3];                                    // 0x0275
    std::int32_t PathCapacityLand;                       // 0x0278
    std::int32_t PathCapacitySea;                        // 0x027C
    std::int32_t PathCapacityBoth;                       // 0x0280
    char pad_0284[4];                                    // 0x0284
  };

  // The IArmy payload ends at +0x1E8 (vfptr + padding + 0x1E0); this pins the
  // base at +0x08 from the derived side. GenerateArmyStart (0x006FFCB0) stores
  // mVarDat.mArmyStart at 0x006FFD5B / 0x006FFD61 as `fstp [esi+1C4h]` /
  // `[esi+1C8h]`: 0x08 + 0x80 + 0x13C.
  static_assert(offsetof(CArmyImpl, Simulation) == 0x1E8, "CArmyImpl::Simulation offset must be 0x1E8");
  static_assert(offsetof(CArmyImpl, ArmyPlans) == 0x1F8, "CArmyImpl::ArmyPlans offset must be 0x1F8");
  static_assert(offsetof(CArmyImpl, InfluenceMap) == 0x218, "CArmyImpl::InfluenceMap offset must be 0x218");
  static_assert(offsetof(CArmyImpl, PathFinder) == 0x21C, "CArmyImpl::PathFinder offset must be 0x21C");
  static_assert(offsetof(CArmyImpl, UnknownShared220) == 0x220, "CArmyImpl::UnknownShared220 offset must be 0x220");
  static_assert(offsetof(CArmyImpl, PlatoonPool) == 0x228, "CArmyImpl::PlatoonPool offset must be 0x228");
  static_assert(offsetof(CArmyImpl, UnitCategorySets) == 0x258, "CArmyImpl::UnitCategorySets offset must be 0x258");
  static_assert(
    offsetof(CArmyImpl, UnitCategoryBaseIndex) == 0x268, "CArmyImpl::UnitCategoryBaseIndex offset must be 0x268"
  );
  static_assert(
    offsetof(CArmyImpl, UnitCategoryMaxIndex) == 0x26C, "CArmyImpl::UnitCategoryMaxIndex offset must be 0x26C"
  );
  static_assert(offsetof(CArmyImpl, IgnoreUnitCapFlag) == 0x274, "CArmyImpl::IgnoreUnitCapFlag offset must be 0x274");
  static_assert(sizeof(CArmyImpl) == 0x288, "CArmyImpl size must be 0x288");

  /**
   * Address: 0x006FE530 (FUN_006FE530, func_SimArmyAlloc)
   *
   * What it does:
   * Allocates one scenario army object and forwards the typed launch, Lua army
   * setup, and scenario option payloads into the full CArmyImpl constructor.
   */
  [[nodiscard]] CArmyImpl* AllocateScenarioArmy(
    Sim* sim,
    std::int32_t armyIndex,
    const ArmyLaunchInfo& launchInfo,
    const LuaPlus::LuaObject& armySetup,
    const LuaPlus::LuaObject& scenarioInfoOptions,
    bool isFocusArmy
  );

  /**
   * Address: 0x005A2C20 (FUN_005A2C20, Moho::AI_Tick)
   *
   * What it does:
   * Advances one AI brain tick for an army across its three task-thread stages.
   */
  void AI_Tick(CArmyImpl* army);
} // namespace moho
