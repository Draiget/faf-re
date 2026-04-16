#pragma once

#include <cstddef>
#include <cstdint>

#include "../../gpg/core/containers/FastVector.h"
#include "../../gpg/core/containers/Set.h"
#include "../../legacy/containers/String.h"
#include "../../legacy/containers/Vector.h"
#include "ESquadClass.h"
#include "SimArmy.h"
#include "STIMap.h"
#include "Wm3Vector2.h"

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

  struct ArmyPool
  {
    // +0x00..+0x2F: fastvector_n header + inline platoon pointer storage
    // (start_, end_, capacity_, originalVec_, inlineVec_[8])
    gpg::fastvector_n<CPlatoon*, 8> platoons;
    // +0x30: unknown scalar (layout-owned, currently unresolved)
    std::uint32_t unknown30;
  };

  static_assert(sizeof(gpg::fastvector_n<CPlatoon*, 8>) == 0x30, "gpg::fastvector_n<CPlatoon*,8> size must be 0x30");
  static_assert(sizeof(ArmyPool) == 0x34, "ArmyPool size must be 0x34");
  static_assert(offsetof(ArmyPool, platoons) == 0x00, "ArmyPool::platoons offset must be 0x00");
  static_assert(offsetof(ArmyPool, platoons.start_) == 0x00, "ArmyPool::platoons.start_ offset must be 0x00");
  static_assert(offsetof(ArmyPool, platoons.end_) == 0x04, "ArmyPool::platoons.end_ offset must be 0x04");
  static_assert(offsetof(ArmyPool, platoons.capacity_) == 0x08, "ArmyPool::platoons.capacity_ offset must be 0x08");
  static_assert(
    offsetof(ArmyPool, platoons.originalVec_) == 0x0C, "ArmyPool::platoons.originalVec_ offset must be 0x0C"
  );
  static_assert(offsetof(ArmyPool, platoons.inlineVec_) == 0x10, "ArmyPool::platoons.inlineVec_ offset must be 0x10");
  static_assert(offsetof(ArmyPool, unknown30) == 0x30, "ArmyPool::unknown30 offset must be 0x30");

  struct SArmyWordVector
  {
    std::int32_t baseWordIndex;           // +0x00
    std::int32_t meta;                    // +0x04
    gpg::fastvector<std::uint32_t> words; // +0x08
  };

  static_assert(sizeof(SArmyWordVector) == 0x14, "SArmyWordVector size must be 0x14");
  static_assert(offsetof(SArmyWordVector, words) == 0x08, "SArmyWordVector::words offset must be 0x08");

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
    /** Address: 0x00700080 (FUN_00700080, Moho::CArmyImpl::CopyConstantDataToUserArmy) */
    UserArmy* CopyConstantDataToUserArmy(UserArmy* outUserArmy) override;
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
    void* N000006B2;                                     // 0x0004
    std::int32_t ArmyId;                                 // 0x0008
    msvc8::string ArmyName;                              // 0x000C
    msvc8::string PlayerName;                            // 0x0028
    std::uint8_t IsCivilian;                             // 0x0044
    char pad_0045[3];                                    // 0x0045
    boost::shared_ptr<CIntelGrid> ExploredReconGrid;     // 0x0048
    boost::shared_ptr<CIntelGrid> FogReconGrid;          // 0x0050
    boost::shared_ptr<CIntelGrid> WaterReconGrid;        // 0x0058
    boost::shared_ptr<CIntelGrid> RadarReconGrid;        // 0x0060
    boost::shared_ptr<CIntelGrid> SonarReconGrid;        // 0x0068
    boost::shared_ptr<CIntelGrid> OmniReconGrid;         // 0x0070
    boost::shared_ptr<CIntelGrid> RciReconGrid;          // 0x0078
    boost::shared_ptr<CIntelGrid> SciReconGrid;          // 0x0080
    float EnergyCurrent;                                 // 0x0088
    float MassCurrent;                                   // 0x008C
    float IncomeEnergy10x;                               // 0x0090
    float IncomeMass10x;                                 // 0x0094
    float ReclaimedEnergy10x;                            // 0x0098
    float ReclaimedMass10x;                              // 0x009C
    float RequestedEnergy10x;                            // 0x00A0
    float RequestedMass10x;                              // 0x00A4
    float ExpenseEnergy10x;                              // 0x00A8
    float ExpenseMass10x;                                // 0x00AC
    std::uint32_t EnergyCapacity;                        // 0x00B0
    char pad_00B4[4];                                    // 0x00B4
    std::uint32_t MassCapacity;                          // 0x00B8
    char pad_00BC[4];                                    // 0x00BC
    std::uint8_t IsResourceSharingEnabled;               // 0x00C0
    char pad_00C1[7];                                    // 0x00C1
    Set Neutrals;                                        // 0x00C8
    Set Allies;                                          // 0x00E8
    Set Enemies;                                         // 0x0108
    std::uint8_t IsAlly;                                 // 0x0128 (FUN_006FDEE0 / SetCanSee)
    char pad_0129[7];                                    // 0x0129
    Set MohoSetValidCommandSources;                      // 0x0130
    std::uint32_t PlayerColorBgra;                       // 0x0150
    std::uint32_t ArmyColorBgra;                         // 0x0154
    msvc8::string ArmyTypeText;                          // 0x0158
    std::int32_t FactionIndex;                           // 0x0174
    std::uint8_t UseWholeMapFlag;                        // 0x0178 (FUN_006FDEC0/FUN_006FDED0)
    char pad_0179[3];                                    // 0x0179
    SArmyVectorWithMeta RuntimeWordVectorWithMeta;       // 0x017C (FUN_006FDE70, FUN_00700280)
    std::uint32_t UnknownVar98;                          // 0x0190 (FUN_00700280 / mVarDat.v98)
    std::uint8_t ShowScoreFlag;                          // 0x0194 (FUN_00700280 / mVarDat.mShowScore)
    char pad_0195[3];                                    // 0x0195
    SArmyWordVector AllUnitsWordSet;                     // 0x0198 (FUN_006FE690, FUN_00700280 / mVarDat.v101-v105)
    char pad_01AC[0x0C];                                 // 0x01AC
    void* OutOfGameContext;                              // 0x01B8
    char pad_01BC[4];                                    // 0x01BC
    std::uint8_t IsOutOfGame;                            // 0x01C0
    char pad_01C1[3];                                    // 0x01C1
    Wm3::Vector2f StartPosition;                         // 0x01C4
    std::int32_t NoRushTicks;                            // 0x01CC
    float NoRushRadius;                                  // 0x01D0
    float NoRushOffsetX;                                 // 0x01D4
    float NoRushOffsetY;                                 // 0x01D8
    float HasHandicap;                                   // 0x01DC
    float Handicap;                                      // 0x01E0
    char pad_01E4[4];                                    // 0x01E4
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
    SEntitySetTemplateUnit* UnitCategorySetsBegin;       // 0x025C
    SEntitySetTemplateUnit* UnitCategorySetsEnd;         // 0x0260
    SEntitySetTemplateUnit* UnitCategorySetsCapacityEnd; // 0x0264
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

  static_assert(offsetof(CArmyImpl, UseWholeMapFlag) == 0x178, "CArmyImpl::UseWholeMapFlag offset must be 0x178");
  static_assert(offsetof(CArmyImpl, ArmyId) == 0x08, "CArmyImpl::ArmyId offset must be 0x08");
  static_assert(offsetof(CArmyImpl, EnergyCurrent) == 0x88, "CArmyImpl::EnergyCurrent offset must be 0x88");
  static_assert(offsetof(CArmyImpl, IsAlly) == 0x128, "CArmyImpl::IsAlly offset must be 0x128");
  static_assert(
    offsetof(CArmyImpl, RuntimeWordVectorWithMeta) == 0x17C, "CArmyImpl::RuntimeWordVectorWithMeta offset must be 0x17C"
  );
  static_assert(offsetof(CArmyImpl, UnknownVar98) == 0x190, "CArmyImpl::UnknownVar98 offset must be 0x190");
  static_assert(offsetof(CArmyImpl, ShowScoreFlag) == 0x194, "CArmyImpl::ShowScoreFlag offset must be 0x194");
  static_assert(offsetof(CArmyImpl, AllUnitsWordSet) == 0x198, "CArmyImpl::AllUnitsWordSet offset must be 0x198");
  static_assert(offsetof(CArmyImpl, NoRushTicks) == 0x1CC, "CArmyImpl::NoRushTicks offset must be 0x1CC");
  static_assert(offsetof(CArmyImpl, HasHandicap) == 0x1DC, "CArmyImpl::HasHandicap offset must be 0x1DC");
  static_assert(offsetof(CArmyImpl, ArmyPlans) == 0x1F8, "CArmyImpl::ArmyPlans offset must be 0x1F8");
  static_assert(offsetof(CArmyImpl, InfluenceMap) == 0x218, "CArmyImpl::InfluenceMap offset must be 0x218");
  static_assert(offsetof(CArmyImpl, PathFinder) == 0x21C, "CArmyImpl::PathFinder offset must be 0x21C");
  static_assert(offsetof(CArmyImpl, UnknownShared220) == 0x220, "CArmyImpl::UnknownShared220 offset must be 0x220");
  static_assert(offsetof(CArmyImpl, PlatoonPool) == 0x228, "CArmyImpl::PlatoonPool offset must be 0x228");
  static_assert(
    offsetof(CArmyImpl, UnitCategorySetsBegin) == 0x25C, "CArmyImpl::UnitCategorySetsBegin offset must be 0x25C"
  );
  static_assert(
    offsetof(CArmyImpl, UnitCategorySetsEnd) == 0x260, "CArmyImpl::UnitCategorySetsEnd offset must be 0x260"
  );
  static_assert(
    offsetof(CArmyImpl, UnitCategorySetsCapacityEnd) == 0x264,
    "CArmyImpl::UnitCategorySetsCapacityEnd offset must be 0x264"
  );
  static_assert(
    offsetof(CArmyImpl, UnitCategoryBaseIndex) == 0x268, "CArmyImpl::UnitCategoryBaseIndex offset must be 0x268"
  );
  static_assert(
    offsetof(CArmyImpl, UnitCategoryMaxIndex) == 0x26C, "CArmyImpl::UnitCategoryMaxIndex offset must be 0x26C"
  );
  static_assert(offsetof(CArmyImpl, IgnoreUnitCapFlag) == 0x274, "CArmyImpl::IgnoreUnitCapFlag offset must be 0x274");
  static_assert(sizeof(CArmyImpl) == 0x288, "CArmyImpl size must be 0x288");

  /**
   * Address: 0x005A2C20 (FUN_005A2C20, Moho::AI_Tick)
   *
   * What it does:
   * Advances one AI brain tick for an army across its three task-thread stages.
   */
  void AI_Tick(CArmyImpl* army);
} // namespace moho
