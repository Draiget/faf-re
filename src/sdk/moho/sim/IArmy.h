#pragma once

#include <cstdint>

#include "../../gpg/core/utils/BoostWrappers.h"
#include "../../legacy/containers/String.h"
#include "../../legacy/containers/Vector.h"
#include "ArmyUnitSet.h"
#include "ESquadClass.h"
#include "SSTIArmyVariableData.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class Sim;
  class CInfluenceMap;
  class CAiBrain;
  class CAiReconDBImpl;
  class CSimArmyEconomyInfo;
  class CArmyStats;
  class CPlatoon;
  class CArmyImpl;
  class UserArmy;
  class Unit;
  enum EAlliance : std::int32_t;
  struct ArmyPool;

  class IArmy
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x005517A0 (FUN_005517A0, Moho::IArmy::MemberDeserialize)
     *
     * What it does:
     * Deserializes the fixed `SSTIArmyConstantData` (+0x00) and
     * `SSTIArmyVariableData` (+0x80) lanes of the IArmy payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00551820 (FUN_00551820, Moho::IArmy::MemberSerialize)
     *
     * What it does:
     * Serializes the fixed `SSTIArmyConstantData` (+0x00) and
     * `SSTIArmyVariableData` (+0x80) lanes of the IArmy payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00579430 (FUN_00579430, Moho::IArmy::GetAllianceWith)
     *
     * What it does:
     * Resolves alliance relation against `other` using the neutral/ally/enemy
     * relation bitsets, defaulting to neutral.
     */
    [[nodiscard]] EAlliance GetAllianceWith(const IArmy* other) const;

    /**
     * Address: 0x005D5540 (FUN_005D5540, Moho::IArmy::IsEnemy)
     *
     * What it does:
     * Returns whether `armyIndex` is present in the enemy relation bitset.
     */
    [[nodiscard]] bool IsEnemy(std::uint32_t armyIndex) const;

    /**
     * Binary evidence summary:
     * - Address: 0x00550B20 (FUN_00550B20): IArmy typeinfo size is 0x1E0.
     * - Address: 0x00703E40 (FUN_00703E40): SimArmy registers IArmy as base at offset +0x08.
     * - SimArmy's own vtable is abstract in RTTI/emit output (all `_purecall` slots except dtor).
     *
     * The slot addresses below are concrete FA binary bodies observed when this interface is
     * implemented by the concrete army class vtable.
     */
    virtual ~IArmy() = 0;

    // Address: 0x006FDC10 (FUN_006FDC10)
    virtual Sim* GetSim() = 0;
    // Address: 0x006FFC90 (FUN_006FFC90)
    virtual bool IsHuman() = 0;
    // Address: 0x006FDC20 (FUN_006FDC20)
    virtual const char* GetArmyType() = 0;
    // Address: 0x006FDC40 (FUN_006FDC40)
    virtual void SetArmyPlans(const msvc8::string& armyPlans) = 0;
    // Address: 0x006FDC60 (FUN_006FDC60)
    virtual const char* GetArmyPlans() = 0;
    // Address: 0x006FDC80 (FUN_006FDC80)
    virtual CInfluenceMap* GetIGrid() = 0;
    // Address: 0x006FDC90 (FUN_006FDC90)
    virtual CAiBrain* GetArmyBrain() = 0;
    // Address: 0x006FDCA0 (FUN_006FDCA0)
    virtual CAiReconDBImpl* GetReconDB() = 0;
    // Address: 0x006FDCB0 (FUN_006FDCB0)
    virtual CSimArmyEconomyInfo* GetEconomy() = 0;
    // Address: 0x006FFCB0 (FUN_006FFCB0)
    virtual void GenerateArmyStart() = 0;
    // Address: 0x006FDCC0 (FUN_006FDCC0)
    virtual void SetArmyStart(const Wm3::Vector2f& startPosition) = 0;
    // Address: 0x006FDCE0 (FUN_006FDCE0)
    virtual void GetArmyStartPos(Wm3::Vector2f& outStartPosition) = 0;
    // Address: 0x006FDF30 (FUN_006FDF30)
    virtual void SetAlliance(std::uint32_t armyId, int relationIndex) = 0;
    // Address: 0x00700FC0 (FUN_00700FC0)
    virtual void OnCommandSourceTerminated(std::uint32_t sourceId) = 0;
    // Address: 0x006FFD70 (FUN_006FFD70)
    virtual void OnTick() = 0;
    // Address: 0x00700080 (FUN_00700080)
    virtual UserArmy* CopyConstantDataToUserArmy(UserArmy* outUserArmy) = 0;
    // Address: 0x00700240 (FUN_00700240)
    virtual SSTIArmyVariableData* CopyArmyVariableData(SSTIArmyVariableData* outBuffer) = 0;
    // Address: 0x006FDD50 (FUN_006FDD50)
    virtual CArmyStats* GetArmyStats() = 0;
    // Address: 0x006FDD60 (FUN_006FDD60)
    virtual float GetArmyUnitCostTotal() = 0;
    // Address: 0x006FDDE0 (FUN_006FDDE0)
    virtual void* GetPathFinder() = 0;
    // Address: 0x006FDDF0 (FUN_006FDDF0)
    virtual boost::SharedPtrRaw<void>* SetUnknownSharedRef(boost::SharedPtrRaw<void>* value) = 0;
    // Address: 0x006FDE40 (FUN_006FDE40)
    virtual boost::SharedPtrRaw<void>* GetUnknownSharedRef(boost::SharedPtrRaw<void>* outValue) = 0;
    // Address: 0x006FDE70 (FUN_006FDE70)
    virtual std::uint32_t SetUnknownVectorWithMeta(const SArmyVectorWithMeta* value) = 0;
    // Address: 0x006FDE90 (FUN_006FDE90)
    virtual void GetPlatoonsList(ArmyPool& outPool) = 0;
    // Address: 0x00700410 (FUN_00700410)
    virtual CPlatoon* MakePlatoon(const char* platoonName, const char* aiPlan) = 0;
    // Address: 0x00700470 (FUN_00700470)
    virtual CPlatoon* GetPlatoonByName(const char* platoonName) = 0;
    // Address: 0x007004E0 (FUN_007004E0)
    virtual CPlatoon* GetPlatoonFor(int queryArg, ESquadClass* outSquadClass) = 0;
    // Address: 0x007005F0 (FUN_007005F0)
    virtual void DisbandPlatoonUniquelyNamed(const char* platoonName) = 0;
    // Address: 0x00700540 (FUN_00700540)
    virtual void DisbandPlatoon(CPlatoon* platoon) = 0;
    /**
     * Address: 0x007006C0 (FUN_007006C0)
     *
     * What it does:
     * Clears the incoming unit set out of any current platoons, then assigns
     * those units into the named platoon's unassigned squad lane.
     */
    virtual void AssignUnitsToPlatoon(const SEntitySetTemplateUnit* units, const char* platoonName) = 0;
    // Address: 0x00700700 (FUN_00700700)
    virtual void RemoveFromPlatoon(Unit* unit) = 0;
    // Address: 0x00700730 (FUN_00700730)
    virtual void RemoveUnitsFromPlatoons(const SEntitySetTemplateUnit* units) = 0;
    // Address: 0x00700770 (FUN_00700770)
    virtual int GetNumPlatoonsTemplateNamed(const char* templateName) = 0;
    // Address: 0x007007C0 (FUN_007007C0)
    virtual int GetNumPlatoonWithPlan(const char* planName) = 0;
    // Address: 0x00700A00 (FUN_00700A00)
    virtual int CountUnitsInBoundsXZ(
      const Wm3::Vector3f& minBounds, const Wm3::Vector3f& maxBounds, const SEntitySetTemplateUnit& unitSet
    ) = 0;
    // Address: 0x00700A70 (FUN_00700A70)
    virtual void UpdateAIDebugPlatoonStats(Unit* unit) = 0;
    // Address: 0x00700E20 (FUN_00700E20)
    virtual void AddUnitToCategorySet(Unit* unit) = 0;
    // Address: 0x00700E70 (FUN_00700E70)
    virtual bool ConsumeUnitFromCategorySet(Unit* unit) = 0;
    // Address: 0x00700EB0 (FUN_00700EB0)
    virtual void* GetUnits(void* outUnits, void* filterBuckets) = 0;
    // Address: 0x006FE090 (FUN_006FE090)
    virtual msvc8::vector<CArmyImpl*>* GetAlliedArmies(msvc8::vector<CArmyImpl*>* outArmyList) = 0;
    // Address: 0x006FDD00 (FUN_006FDD00)
    virtual float GetUnitCap() = 0;
    // Address: 0x006FDD10 (FUN_006FDD10)
    virtual void SetUnitCap(float unitCap) = 0;
    // Address: 0x006FDD30 (FUN_006FDD30)
    virtual bool IgnoreUnitCap() = 0;
    // Address: 0x006FDD40 (FUN_006FDD40)
    virtual void SetUseUnitCap(bool useUnitCap) = 0;
    // Address: 0x006FDEC0 (FUN_006FDEC0)
    virtual void SetIgnorePlayableRect(bool ignorePlayableRect) = 0;
    // Address: 0x006FDED0 (FUN_006FDED0)
    virtual bool UseWholeMap() = 0;
    // Address: 0x006FE1B0 (FUN_006FE1B0)
    virtual void AddBuildRestriction(void* restriction) = 0;
    // Address: 0x006FE220 (FUN_006FE220)
    virtual void RemoveBuildRestriction(void* restriction) = 0;
    // Address: 0x006FE290 (FUN_006FE290)
    virtual void SetNoRushTimer(float seconds) = 0;
    // Address: 0x006FE2B0 (FUN_006FE2B0)
    virtual void SetNoRushRadius(float radius) = 0;
    // Address: 0x006FE2D0 (FUN_006FE2D0)
    virtual void SetNoRushOffset(float offsetX, float offsetY) = 0;
    // Address: 0x006FE2F0 (FUN_006FE2F0)
    virtual std::int32_t GetPathcapLand() = 0;
    // Address: 0x006FE300 (FUN_006FE300)
    virtual std::int32_t GetPathcapSea() = 0;
    // Address: 0x006FE310 (FUN_006FE310)
    virtual std::int32_t GetPathcapBoth() = 0;
  };

} // namespace moho
