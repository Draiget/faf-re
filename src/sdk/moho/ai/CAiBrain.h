#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/script/CScriptObject.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CArmyImpl;
  class CAiPersonality;
  class CScrLuaInitForm;
  class CTaskStage;
  struct SEntitySetTemplateUnit;
  class Sim;
  class Unit;

  struct SBuildResourceInfoLink
  {
    SBuildResourceInfoLink** mOwnerSlot; // +0x00
    SBuildResourceInfoLink* mNext;       // +0x04
  };
  static_assert(sizeof(SBuildResourceInfoLink) == 0x08, "SBuildResourceInfoLink size must be 0x08");

  struct SBuildResourceInfo
  {
    SBuildResourceInfoLink mPlacementLink;  // +0x00
    SBuildResourceInfoLink mResourceLink;   // +0x08
  };
  static_assert(sizeof(SBuildResourceInfo) == 0x10, "SBuildResourceInfo size must be 0x10");

  struct SBuildStructurePositionNode
  {
    SBuildStructurePositionNode* left;      // +0x00
    SBuildStructurePositionNode* parent;    // +0x04
    SBuildStructurePositionNode* right;     // +0x08
    Wm3::Vector2i mGridPosition;            // +0x0C
    SBuildResourceInfo mBuildInfo;          // +0x14
    std::uint8_t mColor;                    // +0x24
    std::uint8_t mIsNil;                    // +0x25
    std::uint8_t mPad26[2];                 // +0x26
  };
  static_assert(sizeof(SBuildStructurePositionNode) == 0x28, "SBuildStructurePositionNode size must be 0x28");
  static_assert(
    offsetof(SBuildStructurePositionNode, mGridPosition) == 0x0C,
    "SBuildStructurePositionNode::mGridPosition offset must be 0x0C"
  );
  static_assert(
    offsetof(SBuildStructurePositionNode, mBuildInfo) == 0x14,
    "SBuildStructurePositionNode::mBuildInfo offset must be 0x14"
  );
  static_assert(offsetof(SBuildStructurePositionNode, mColor) == 0x24, "SBuildStructurePositionNode::mColor");
  static_assert(offsetof(SBuildStructurePositionNode, mIsNil) == 0x25, "SBuildStructurePositionNode::mIsNil");

  struct SBuildStructurePositionMap
  {
    std::uint32_t mMeta00;                   // +0x00
    SBuildStructurePositionNode* mHead;      // +0x04
    std::uint32_t mSize;                     // +0x08
  };
  static_assert(sizeof(SBuildStructurePositionMap) == 0x0C, "SBuildStructurePositionMap size must be 0x0C");
  static_assert(
    offsetof(SBuildStructurePositionMap, mHead) == 0x04, "SBuildStructurePositionMap::mHead offset must be 0x04"
  );
  static_assert(
    offsetof(SBuildStructurePositionMap, mSize) == 0x08, "SBuildStructurePositionMap::mSize offset must be 0x08"
  );

  struct SAiAttackVectorDebug
  {
    Wm3::Vector3f mOrigin;     // +0x00
    Wm3::Vector3f mDirection;  // +0x0C
  };
  static_assert(sizeof(SAiAttackVectorDebug) == 0x18, "SAiAttackVectorDebug size must be 0x18");
  static_assert(offsetof(SAiAttackVectorDebug, mOrigin) == 0x00, "SAiAttackVectorDebug::mOrigin offset must be 0x00");
  static_assert(
    offsetof(SAiAttackVectorDebug, mDirection) == 0x0C, "SAiAttackVectorDebug::mDirection offset must be 0x0C"
  );

  /**
   * VFTABLE: 0x00E19900
   * COL:  0x00E6EA10
   */
  class CAiBrain : public CScriptObject
  {
  public:
    /**
     * Address: 0x00579E40 (FUN_00579E40, default ctor)
     */
    CAiBrain();

    /**
     * Address: 0x00579F80 (FUN_00579F80, army ctor)
     */
    explicit CAiBrain(CArmyImpl* army);

    /**
     * Address: 0x0057A440 (FUN_0057A440, Moho::CAiBrain::Initialize)
     *
     * What it does:
     * Resolves this army's plan string (or `"None"`), then dispatches either
     * `OnCreateHuman` or `OnCreateAI` on the brain script object.
     */
    void Initialize();

    /**
     * Address: 0x00579590 (FUN_00579590, ?GetClass@CAiBrain@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x005795B0 (FUN_005795B0, ?GetDerivedObjectRef@CAiBrain@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00583CB0 (FUN_00583CB0, Moho::CAiBrain::MemberDeserialize)
     *
     * What it does:
     * Loads CAiBrain runtime lanes from archive storage, replacing owned
     * personality/task-stage pointers with freshly deserialized instances.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00583ED0 (FUN_00583ED0, Moho::CAiBrain::MemberSerialize)
     *
     * What it does:
     * Saves CAiBrain runtime lanes to archive storage, preserving original
     * tracked-pointer ownership states for each pointer field.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00579F30 (FUN_00579F30, scalar deleting thunk)
     * Address: 0x0057A1E0 (FUN_0057A1E0, core destructor)
     *
     * VFTable SLOT: 2
     */
    ~CAiBrain() override;

    /**
     * Address: 0x0057A6D0 (FUN_0057A6D0, Moho::CAiBrain::CanBuildUnit)
     *
     * What it does:
     * Resolves a unit blueprint id through active sim rules and tests whether
     * `builder` can construct that blueprint under current build restrictions.
     */
    static bool CanBuildUnit(const char* blueprintId, CAiBrain* brain, Unit* builder);

    /**
     * Address: 0x0057B1E0 (FUN_0057B1E0, Moho::CAiBrain::BuildUnit)
     *
     * What it does:
     * Resolves one buildable blueprint id and issues `UNITCOMMAND_BuildFactory`
     * commands for `builder` `count` times.
     */
    static bool BuildUnit(const char* blueprintId, CAiBrain* brain, Unit* builder, int count);

    /**
     * Address: 0x0057BAA0 (FUN_0057BAA0, Moho::CAiBrain::DrawDebug)
     *
     * What it does:
     * Draws AI debug grid lines and per-attack-vector direction markers.
     */
    static CAiBrain* DrawDebug(CAiBrain* brain);

    /**
     * Address: 0x0057A510 (FUN_0057A510, Moho::CAiBrain::CenterOfArmy)
     *
     * What it does:
     * Computes the average position of all live, non-destroying mobile units
     * (`MOBILE - STRUCTURE` category) belonging to this brain's army and writes
     * the result into `outPosition`. When the army has no qualifying units,
     * `outPosition` is left at the zero vector.
     */
    Wm3::Vec3f* CenterOfArmy(Wm3::Vec3f* outPosition);

    /**
     * Address: 0x0057BDB0 (FUN_0057BDB0, Moho::CAiBrain::ProcessAttackVectors)
     *
     * What it does:
     * Rebuilds debug attack-vector lanes from current enemy unit positions.
     */
    void ProcessAttackVectors();

    /**
     * Address: 0x0057AEC0 (FUN_0057AEC0, Moho::CAiBrain::GetAvailableFactories)
     *
     * What it does:
     * Scans this brain's non-mobile factory units and appends currently
     * available entries to `outSet`, optionally filtering by XZ range.
     */
    SEntitySetTemplateUnit* GetAvailableFactories(
      SEntitySetTemplateUnit* outSet,
      const Wm3::Vector3f* referencePosition,
      float maxDistance
    );

  public:
    static gpg::RType* sType;

    CArmyImpl* mArmy;                              // +0x34
    CArmyImpl* mCurrentEnemy;                      // +0x38
    CAiPersonality* mPersonality;                  // +0x3C
    msvc8::string mCurrentPlan;                    // +0x40
    msvc8::vector<SAiAttackVectorDebug> mAttackVectors; // +0x5C
    std::uint32_t mAttackVectorMeta6C;             // +0x6C (unknown; written/used outside recovered scope)
    CategoryWordRangeView mBuildCategoryRange;     // +0x70
    SBuildStructurePositionMap mBuildStructureMap; // +0x98
    Sim* mSim;                                     // +0xA4
    CTaskStage* mAiThreadStage;                    // +0xA8
    CTaskStage* mAttackerThreadStage;              // +0xAC
    CTaskStage* mReservedThreadStage;              // +0xB0
    std::uint32_t mTailWord;                       // +0xB4
  };

  static_assert(sizeof(CAiBrain) == 0xB8, "CAiBrain size must be 0xB8");
  static_assert(offsetof(CAiBrain, mArmy) == 0x34, "CAiBrain::mArmy offset must be 0x34");
  static_assert(offsetof(CAiBrain, mCurrentEnemy) == 0x38, "CAiBrain::mCurrentEnemy offset must be 0x38");
  static_assert(offsetof(CAiBrain, mPersonality) == 0x3C, "CAiBrain::mPersonality offset must be 0x3C");
  static_assert(offsetof(CAiBrain, mCurrentPlan) == 0x40, "CAiBrain::mCurrentPlan offset must be 0x40");
  static_assert(offsetof(CAiBrain, mAttackVectors) == 0x5C, "CAiBrain::mAttackVectors offset must be 0x5C");
  static_assert(offsetof(CAiBrain, mAttackVectorMeta6C) == 0x6C, "CAiBrain::mAttackVectorMeta6C offset must be 0x6C");
  static_assert(
    offsetof(CAiBrain, mBuildCategoryRange) == 0x70, "CAiBrain::mBuildCategoryRange offset must be 0x70"
  );
  static_assert(offsetof(CAiBrain, mBuildStructureMap) == 0x98, "CAiBrain::mBuildStructureMap offset must be 0x98");
  static_assert(offsetof(CAiBrain, mSim) == 0xA4, "CAiBrain::mSim offset must be 0xA4");
  static_assert(offsetof(CAiBrain, mAiThreadStage) == 0xA8, "CAiBrain::mAiThreadStage offset must be 0xA8");
  static_assert(
    offsetof(CAiBrain, mAttackerThreadStage) == 0xAC, "CAiBrain::mAttackerThreadStage offset must be 0xAC"
  );
  static_assert(
    offsetof(CAiBrain, mReservedThreadStage) == 0xB0, "CAiBrain::mReservedThreadStage offset must be 0xB0"
  );
  static_assert(offsetof(CAiBrain, mTailWord) == 0xB4, "CAiBrain::mTailWord offset must be 0xB4");

  /**
   * Address: 0x00BCB4B0 (FUN_00BCB4B0, sub_BCB4B0)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index for the CAiBrain startup lane.
   */
  int register_CScrLuaMetatableFactory_CAiBrain_Index();
} // namespace moho

/**
 * VFTABLE: 0x00E1AF5C
 * COL:  0x00E6FFD8
 */
using CAiBrainIsOpponentAIRunning_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF64
 * COL:  0x00E6FF88
 */
using CAiBrainGetArmyIndex_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF6C
 * COL:  0x00E6FF38
 */
using CAiBrainGetFactionIndex_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF74
 * COL:  0x00E6FEE8
 */
using CAiBrainSetCurrentPlan_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF7C
 * COL:  0x00E6FE98
 */
using CAiBrainGetPersonality_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF84
 * COL:  0x00E6FE48
 */
using CAiBrainSetCurrentEnemy_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF8C
 * COL:  0x00E6FDF8
 */
using CAiBrainGetCurrentEnemy_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF94
 * COL:  0x00E6FDA8
 */
using CAiBrainGetUnitBlueprint_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AF9C
 * COL:  0x00E6FD58
 */
using CAiBrainGetArmyStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFA4
 * COL:  0x00E6FD08
 */
using CAiBrainSetArmyStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFAC
 * COL:  0x00E6FCB8
 */
using CAiBrainAddArmyStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFB4
 * COL:  0x00E6FC68
 */
using CAiBrainSetGreaterOf_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFBC
 * COL:  0x00E6FC18
 */
using CAiBrainGetBlueprintStat_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFC4
 * COL:  0x00E6FBC8
 */
using CAiBrainGetCurrentUnits_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFCC
 * COL:  0x00E6FB78
 */
using CAiBrainGetListOfUnits_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFD4
 * COL:  0x00E6FB28
 */
using CAiBrainSetArmyStatsTrigger_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFDC
 * COL:  0x00E6FAD8
 */
using CAiBrainRemoveArmyStatsTrigger_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFE4
 * COL:  0x00E6FA88
 */
using CAiBrainGiveResource_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFEC
 * COL:  0x00E6FA38
 */
using CAiBrainGiveStorage_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFF4
 * COL:  0x00E6F9E8
 */
using CAiBrainTakeResource_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1AFFC
 * COL:  0x00E6F998
 */
using CAiBrainSetResourceSharing_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B004
 * COL:  0x00E6F948
 */
using CAiBrainFindUnit_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B00C
 * COL:  0x00E6F8F8
 */
using CAiBrainFindUpgradeBP_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B014
 * COL:  0x00E6F8A8
 */
using CAiBrainFindUnitToUpgrade_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B01C
 * COL:  0x00E6F858
 */
using CAiBrainDecideWhatToBuild_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B024
 * COL:  0x00E6F808
 */
using CAiBrainGetArmyStartPos_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B02C
 * COL:  0x00E6F7B8
 */
using CAiBrainCreateUnitNearSpot_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B034
 * COL:  0x00E6F768
 */
using CAiBrainCreateResourceBuildingNearest_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B03C
 * COL:  0x00E6F718
 */
using CAiBrainFindPlaceToBuild_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B044
 * COL:  0x00E6F6C8
 */
using CAiBrainCanBuildStructureAt_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B04C
 * COL:  0x00E6F678
 */
using CAiBrainBuildStructure_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B054
 * COL:  0x00E6F628
 */
using CAiBrainNumCurrentlyBuilding_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B05C
 * COL:  0x00E6F5D8
 */
using CAiBrainGetAvailableFactories_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B064
 * COL:  0x00E6F588
 */
using CAiBrainCanBuildPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B06C
 * COL:  0x00E6F538
 */
using CAiBrainBuildPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B074
 * COL:  0x00E6F4E8
 */
using CAiBrainBuildUnit_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B07C
 * COL:  0x00E6F498
 */
using CAiBrainIsAnyEngineerBuilding_LuaFuncDef = ::moho::CScrLuaBinder;

namespace moho
{
  /**
   * Address: 0x00585EF0 (FUN_00585EF0, cfunc_CAiBrainIsOpponentAIRunning)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainIsOpponentAIRunningL`.
   */
  int cfunc_CAiBrainIsOpponentAIRunning(lua_State* luaContext);

  /**
   * Address: 0x00585F10 (FUN_00585F10, func_CAiBrainIsOpponentAIRunning_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:IsOpponentAIRunning()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainIsOpponentAIRunning_LuaFuncDef();

  /**
   * Address: 0x00585F70 (FUN_00585F70, cfunc_CAiBrainIsOpponentAIRunningL)
   *
   * What it does:
   * Returns whether opponent AI should run for one brain, honoring `/noai`
   * override and sim-convar state.
   */
  int cfunc_CAiBrainIsOpponentAIRunningL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00586070 (FUN_00586070, cfunc_CAiBrainGetArmyIndex)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetArmyIndexL`.
   */
  int cfunc_CAiBrainGetArmyIndex(lua_State* luaContext);

  /**
   * Address: 0x00586090 (FUN_00586090, func_CAiBrainGetArmyIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetArmyIndex()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetArmyIndex_LuaFuncDef();

  /**
   * Address: 0x005860F0 (FUN_005860F0, cfunc_CAiBrainGetArmyIndexL)
   *
   * What it does:
   * Returns one-based army index for the brain's owning army.
   */
  int cfunc_CAiBrainGetArmyIndexL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005861C0 (FUN_005861C0, cfunc_CAiBrainGetFactionIndex)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetFactionIndexL`.
   */
  int cfunc_CAiBrainGetFactionIndex(lua_State* luaContext);

  /**
   * Address: 0x005861E0 (FUN_005861E0, func_CAiBrainGetFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetFactionIndex()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetFactionIndex_LuaFuncDef();

  /**
   * Address: 0x00586240 (FUN_00586240, cfunc_CAiBrainGetFactionIndexL)
   *
   * What it does:
   * Returns one-based faction index for the brain's owning army.
   */
  int cfunc_CAiBrainGetFactionIndexL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00586310 (FUN_00586310, cfunc_CAiBrainSetCurrentPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetCurrentPlanL`.
   */
  int cfunc_CAiBrainSetCurrentPlan(lua_State* luaContext);

  /**
   * Address: 0x00586330 (FUN_00586330, func_CAiBrainSetCurrentPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetCurrentPlan(planName)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetCurrentPlan_LuaFuncDef();

  /**
   * Address: 0x00586390 (FUN_00586390, cfunc_CAiBrainSetCurrentPlanL)
   *
   * What it does:
   * Updates the brain current-plan string from Lua arg #2 when it is a string.
   */
  int cfunc_CAiBrainSetCurrentPlanL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005864A0 (FUN_005864A0, cfunc_CAiBrainGetPersonality)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetPersonalityL`.
   */
  int cfunc_CAiBrainGetPersonality(lua_State* luaContext);

  /**
   * Address: 0x005864C0 (FUN_005864C0, func_CAiBrainGetPersonality_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetPersonality()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetPersonality_LuaFuncDef();

  /**
   * Address: 0x00586520 (FUN_00586520, cfunc_CAiBrainGetPersonalityL)
   *
   * What it does:
   * Returns personality Lua object for this brain, or `nil` when unavailable.
   */
  int cfunc_CAiBrainGetPersonalityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005865F0 (FUN_005865F0, cfunc_CAiBrainSetCurrentEnemy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetCurrentEnemyL`.
   */
  int cfunc_CAiBrainSetCurrentEnemy(lua_State* luaContext);

  /**
   * Address: 0x00586610 (FUN_00586610, func_CAiBrainSetCurrentEnemy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetCurrentEnemy(enemyBrain)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetCurrentEnemy_LuaFuncDef();

  /**
   * Address: 0x00586670 (FUN_00586670, cfunc_CAiBrainSetCurrentEnemyL)
   *
   * What it does:
   * Stores enemy army pointer from Lua arg #2 brain (or clears it on nil/invalid).
   */
  int cfunc_CAiBrainSetCurrentEnemyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00586770 (FUN_00586770, cfunc_CAiBrainGetCurrentEnemy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetCurrentEnemyL`.
   */
  int cfunc_CAiBrainGetCurrentEnemy(lua_State* luaContext);

  /**
   * Address: 0x00586790 (FUN_00586790, func_CAiBrainGetCurrentEnemy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetCurrentEnemy()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetCurrentEnemy_LuaFuncDef();

  /**
   * Address: 0x005867F0 (FUN_005867F0, cfunc_CAiBrainGetCurrentEnemyL)
   *
   * What it does:
   * Returns current enemy brain Lua object for this brain, or `nil` when none.
   */
  int cfunc_CAiBrainGetCurrentEnemyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005868D0 (FUN_005868D0, cfunc_CAiBrainGetUnitBlueprint)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetUnitBlueprintL`.
   */
  int cfunc_CAiBrainGetUnitBlueprint(lua_State* luaContext);

  /**
   * Address: 0x005868F0 (FUN_005868F0, func_CAiBrainGetUnitBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetUnitBlueprint(bpName)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetUnitBlueprint_LuaFuncDef();

  /**
   * Address: 0x00586950 (FUN_00586950, cfunc_CAiBrainGetUnitBlueprintL)
   *
   * What it does:
   * Resolves one unit blueprint id string for the given AI brain and returns
   * the corresponding Lua blueprint table/object, or `nil` when missing.
   */
  int cfunc_CAiBrainGetUnitBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00586AD0 (FUN_00586AD0, cfunc_CAiBrainGetArmyStat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetArmyStatL`.
   */
  int cfunc_CAiBrainGetArmyStat(lua_State* luaContext);

  /**
   * Address: 0x00586AF0 (FUN_00586AF0, func_CAiBrainGetArmyStat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetArmyStat(statName, defaultValue)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetArmyStat_LuaFuncDef();

  /**
   * Address: 0x00586B50 (FUN_00586B50, cfunc_CAiBrainGetArmyStatL)
   *
   * What it does:
   * Resolves one army stat by path and returns its Lua table representation.
   */
  int cfunc_CAiBrainGetArmyStatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00586DA0 (FUN_00586DA0, cfunc_CAiBrainSetArmyStat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetArmyStatL`.
   */
  int cfunc_CAiBrainSetArmyStat(lua_State* luaContext);

  /**
   * Address: 0x00586DC0 (FUN_00586DC0, func_CAiBrainSetArmyStat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetArmyStat(statName, value)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetArmyStat_LuaFuncDef();

  /**
   * Address: 0x00586E20 (FUN_00586E20, cfunc_CAiBrainSetArmyStatL)
   *
   * What it does:
   * Writes one army stat lane from Lua number input.
   */
  int cfunc_CAiBrainSetArmyStatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00587020 (FUN_00587020, cfunc_CAiBrainAddArmyStat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainAddArmyStatL`.
   */
  int cfunc_CAiBrainAddArmyStat(lua_State* luaContext);

  /**
   * Address: 0x00587040 (FUN_00587040, func_CAiBrainAddArmyStat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:AddArmyStat(statName, value)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainAddArmyStat_LuaFuncDef();

  /**
   * Address: 0x005870A0 (FUN_005870A0, cfunc_CAiBrainAddArmyStatL)
   *
   * What it does:
   * Adds one Lua numeric delta into one army stat lane.
   */
  int cfunc_CAiBrainAddArmyStatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005872A0 (FUN_005872A0, cfunc_CAiBrainSetGreaterOf)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetGreaterOfL`.
   */
  int cfunc_CAiBrainSetGreaterOf(lua_State* luaContext);

  /**
   * Address: 0x005872C0 (FUN_005872C0, func_CAiBrainSetGreaterOf_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetGreaterOf(statName, value)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetGreaterOf_LuaFuncDef();

  /**
   * Address: 0x00587320 (FUN_00587320, cfunc_CAiBrainSetGreaterOfL)
   *
   * What it does:
   * Updates one army stat only when the incoming value is greater than the
   * stored stat lane.
   */
  int cfunc_CAiBrainSetGreaterOfL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00587520 (FUN_00587520, cfunc_CAiBrainGetBlueprintStat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetBlueprintStatL`.
   */
  int cfunc_CAiBrainGetBlueprintStat(lua_State* luaContext);

  /**
   * Address: 0x00587540 (FUN_00587540, func_CAiBrainGetBlueprintStat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetBlueprintStat(statName, category)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetBlueprintStat_LuaFuncDef();

  /**
   * Address: 0x005875A0 (FUN_005875A0, cfunc_CAiBrainGetBlueprintStatL)
   *
   * What it does:
   * Returns one blueprint-filtered aggregate value for the selected stat path.
   */
  int cfunc_CAiBrainGetBlueprintStatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005876E0 (FUN_005876E0, cfunc_CAiBrainGetCurrentUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetCurrentUnitsL`.
   */
  int cfunc_CAiBrainGetCurrentUnits(lua_State* luaContext);

  /**
   * Address: 0x00587700 (FUN_00587700, func_CAiBrainGetCurrentUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetCurrentUnits(category)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetCurrentUnits_LuaFuncDef();

  /**
   * Address: 0x00587760 (FUN_00587760, cfunc_CAiBrainGetCurrentUnitsL)
   *
   * What it does:
   * Returns the active-unit count for one category set, truncated to integer.
   */
  int cfunc_CAiBrainGetCurrentUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00587B80 (FUN_00587B80, cfunc_CAiBrainSetArmyStatsTrigger)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainSetArmyStatsTriggerL`.
   */
  int cfunc_CAiBrainSetArmyStatsTrigger(lua_State* luaContext);

  /**
   * Address: 0x00587BA0 (FUN_00587BA0, func_CAiBrainSetArmyStatsTrigger_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetArmyStatsTrigger(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetArmyStatsTrigger_LuaFuncDef();

  /**
   * Address: 0x00587C00 (FUN_00587C00, cfunc_CAiBrainSetArmyStatsTriggerL)
   *
   * What it does:
   * Adds one army-stat trigger condition with optional category filtering.
   */
  int cfunc_CAiBrainSetArmyStatsTriggerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00587FA0 (FUN_00587FA0, cfunc_CAiBrainRemoveArmyStatsTrigger)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainRemoveArmyStatsTriggerL`.
   */
  int cfunc_CAiBrainRemoveArmyStatsTrigger(lua_State* luaContext);

  /**
   * Address: 0x00587FC0 (FUN_00587FC0, func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:RemoveArmyStatsTrigger(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef();

  /**
   * Address: 0x00588020 (FUN_00588020, cfunc_CAiBrainRemoveArmyStatsTriggerL)
   *
   * What it does:
   * Removes one named trigger from the owning army stats trigger list.
   */
  int cfunc_CAiBrainRemoveArmyStatsTriggerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00587870 (FUN_00587870, cfunc_CAiBrainGetListOfUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetListOfUnitsL`.
   */
  int cfunc_CAiBrainGetListOfUnits(lua_State* luaContext);

  /**
   * Address: 0x00587890 (FUN_00587890, func_CAiBrainGetListOfUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetListOfUnits(entityCategory, needToBeIdle, requireBuilt)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetListOfUnits_LuaFuncDef();

  /**
   * Address: 0x005878F0 (FUN_005878F0, cfunc_CAiBrainGetListOfUnitsL)
   *
   * What it does:
   * Builds and returns a Lua array of army units matching category + optional
   * idle/build filters.
   */
  int cfunc_CAiBrainGetListOfUnitsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00588850 (FUN_00588850, cfunc_CAiBrainSetResourceSharing)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainSetResourceSharingL`.
   */
  int cfunc_CAiBrainSetResourceSharing(lua_State* luaContext);

  /**
   * Address: 0x00588870 (FUN_00588870, func_CAiBrainSetResourceSharing_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetResourceSharing(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetResourceSharing_LuaFuncDef();

  /**
   * Address: 0x005888D0 (FUN_005888D0, cfunc_CAiBrainSetResourceSharingL)
   *
   * What it does:
   * Sets per-army economy resource-sharing enable flag from Lua arg #2.
   */
  int cfunc_CAiBrainSetResourceSharingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00589720 (FUN_00589720, cfunc_CAiBrainGetArmyStartPos)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetArmyStartPosL`.
   */
  int cfunc_CAiBrainGetArmyStartPos(lua_State* luaContext);

  /**
   * Address: 0x00589740 (FUN_00589740, func_CAiBrainGetArmyStartPos_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetArmyStartPos()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetArmyStartPos_LuaFuncDef();

  /**
   * Address: 0x005897A0 (FUN_005897A0, cfunc_CAiBrainGetArmyStartPosL)
   *
   * What it does:
   * Returns army start position as two Lua numbers: `x`, `y`.
   */
  int cfunc_CAiBrainGetArmyStartPosL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005898B0 (FUN_005898B0, func_CAiBrainCreateUnitNearSpot_LuaFuncDef)
   *
   * What it does:
   * Publishes the `brain:CreateUnitNearSpot(unitName, posX, posY)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainCreateUnitNearSpot_LuaFuncDef();

  /**
   * Address: 0x00589DD0 (FUN_00589DD0, func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef)
   *
   * What it does:
   * Publishes the `brain:CreateResourceBuildingNearest(structureName, posX, posY)` Lua binder.
   */
  void func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef();

  /**
   * Address: 0x0058A460 (FUN_0058A460, func_CAiBrainFindPlaceToBuild_LuaFuncDef)
   *
   * What it does:
   * Publishes the `brain:FindPlaceToBuild(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainFindPlaceToBuild_LuaFuncDef();

  /**
   * Address: 0x0058ED60 (FUN_0058ED60, cfunc_CAiBrainGetAttackVectors)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetAttackVectorsL`.
   */
  int cfunc_CAiBrainGetAttackVectors(lua_State* luaContext);

  /**
   * Address: 0x0058ED80 (FUN_0058ED80, func_CAiBrainGetAttackVectors_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetAttackVectors()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetAttackVectors_LuaFuncDef();

  /**
   * Address: 0x0058EDE0 (FUN_0058EDE0, cfunc_CAiBrainGetAttackVectorsL)
   *
   * What it does:
   * Returns the brain's current attack vectors as a Lua table of
   * `SPointVector` objects, or `nil` when none are available.
   */
  int cfunc_CAiBrainGetAttackVectorsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058F390 (FUN_0058F390, func_CAiBrainGetEconomyStored_LuaFuncDef)
   * Alias export: 0x0058F3A0 (FUN_0058F3A0)
   *
   * What it does:
   * Publishes the `CAiBrain:GetEconomyStored()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetEconomyStored_LuaFuncDef();

  /**
   * Address: 0x0058F370 (FUN_0058F370, cfunc_CAiBrainGetEconomyStored)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyStoredL`.
   */
  int cfunc_CAiBrainGetEconomyStored(lua_State* luaContext);

  /**
   * Address: 0x0058F3F0 (FUN_0058F3F0, cfunc_CAiBrainGetEconomyStoredL)
   *
   * What it does:
   * Returns stored economy amount for one requested resource lane.
   */
  int cfunc_CAiBrainGetEconomyStoredL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058F750 (FUN_0058F750, func_CAiBrainGetEconomyIncome_LuaFuncDef)
   * Alias export: 0x0058F760 (FUN_0058F760)
   *
   * What it does:
   * Publishes the `CAiBrain:GetEconomyIncome()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetEconomyIncome_LuaFuncDef();

  /**
   * Address: 0x0058F730 (FUN_0058F730, cfunc_CAiBrainGetEconomyIncome)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyIncomeL`.
   */
  int cfunc_CAiBrainGetEconomyIncome(lua_State* luaContext);

  /**
   * Address: 0x0058F7B0 (FUN_0058F7B0, cfunc_CAiBrainGetEconomyIncomeL)
   *
   * What it does:
   * Returns economy income amount for one requested resource lane.
   */
  int cfunc_CAiBrainGetEconomyIncomeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058F910 (FUN_0058F910, func_CAiBrainGetEconomyUsage_LuaFuncDef)
   * Alias export: 0x0058F920 (FUN_0058F920)
   *
   * What it does:
   * Publishes the `CAiBrain:GetEconomyUsage()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetEconomyUsage_LuaFuncDef();

  /**
   * Address: 0x0058F8F0 (FUN_0058F8F0, cfunc_CAiBrainGetEconomyUsage)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyUsageL`.
   */
  int cfunc_CAiBrainGetEconomyUsage(lua_State* luaContext);

  /**
   * Address: 0x0058F970 (FUN_0058F970, cfunc_CAiBrainGetEconomyUsageL)
   *
   * What it does:
   * Returns last-actual usage amount for one requested resource lane.
   */
  int cfunc_CAiBrainGetEconomyUsageL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058FAD0 (FUN_0058FAD0, func_CAiBrainGetEconomyRequested_LuaFuncDef)
   * Alias export: 0x0058FAE0 (FUN_0058FAE0)
   *
   * What it does:
   * Publishes the `CAiBrain:GetEconomyRequested()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetEconomyRequested_LuaFuncDef();

  /**
   * Address: 0x0058FAB0 (FUN_0058FAB0, cfunc_CAiBrainGetEconomyRequested)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyRequestedL`.
   */
  int cfunc_CAiBrainGetEconomyRequested(lua_State* luaContext);

  /**
   * Address: 0x0058FB30 (FUN_0058FB30, cfunc_CAiBrainGetEconomyRequestedL)
   *
   * What it does:
   * Returns last-requested amount for one requested resource lane.
   */
  int cfunc_CAiBrainGetEconomyRequestedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058FC90 (FUN_0058FC90, func_CAiBrainGetEconomyTrend_LuaFuncDef)
   * Alias export: 0x0058FCA0 (FUN_0058FCA0)
   *
   * What it does:
   * Publishes the `CAiBrain:GetEconomyTrend()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetEconomyTrend_LuaFuncDef();

  /**
   * Address: 0x0058FC70 (FUN_0058FC70, cfunc_CAiBrainGetEconomyTrend)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyTrendL`.
   */
  int cfunc_CAiBrainGetEconomyTrend(lua_State* luaContext);

  /**
   * Address: 0x0058FCF0 (FUN_0058FCF0, cfunc_CAiBrainGetEconomyTrendL)
   *
   * What it does:
   * Returns `(income - lastActualUse)` for one requested resource lane.
   */
  int cfunc_CAiBrainGetEconomyTrendL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058F530 (FUN_0058F530, cfunc_CAiBrainGetEconomyStoredRatio)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetEconomyStoredRatioL`.
  */
  int cfunc_CAiBrainGetEconomyStoredRatio(lua_State* luaContext);

  /**
   * Address: 0x0058F550 (FUN_0058F550, func_CAiBrainGetEconomyStoredRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetEconomyStoredRatio(resourceType)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetEconomyStoredRatio_LuaFuncDef();

  /**
   * Address: 0x0058F5B0 (FUN_0058F5B0, cfunc_CAiBrainGetEconomyStoredRatioL)
   *
   * What it does:
   * Returns stored-to-capacity ratio for the requested economy resource lane.
   */
  int cfunc_CAiBrainGetEconomyStoredRatioL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058FE30 (FUN_0058FE30, cfunc_CAiBrainGetMapWaterRatio)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetMapWaterRatioL`.
   */
  int cfunc_CAiBrainGetMapWaterRatio(lua_State* luaContext);

  /**
   * Address: 0x0058FE50 (FUN_0058FE50, func_CAiBrainGetMapWaterRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetMapWaterRatio()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetMapWaterRatio_LuaFuncDef();

  /**
   * Address: 0x0058FEB0 (FUN_0058FEB0, cfunc_CAiBrainGetMapWaterRatioL)
   *
   * What it does:
   * Samples the owning sim-map terrain and returns the map water-coverage ratio.
   */
  int cfunc_CAiBrainGetMapWaterRatioL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005881F0 (FUN_005881F0, cfunc_CAiBrainGiveResource)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGiveResourceL`.
   */
  int cfunc_CAiBrainGiveResource(lua_State* luaContext);

  /**
   * Address: 0x00588210 (FUN_00588210, func_CAiBrainGiveResource_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GiveResource(type,amount)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGiveResource_LuaFuncDef();

  /**
   * Address: 0x00588270 (FUN_00588270, cfunc_CAiBrainGiveResourceL)
   *
   * What it does:
   * Adds `amount` to one stored economy-resource lane selected by `type`
   * after decoding `(brain, type, amount)` from Lua.
   */
  int cfunc_CAiBrainGiveResourceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005883E0 (FUN_005883E0, cfunc_CAiBrainGiveStorage)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGiveStorageL`.
   */
  int cfunc_CAiBrainGiveStorage(lua_State* luaContext);

  /**
   * Address: 0x00588400 (FUN_00588400, func_CAiBrainGiveStorage_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GiveStorage(type,amount)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGiveStorage_LuaFuncDef();

  /**
   * Address: 0x00588460 (FUN_00588460, cfunc_CAiBrainGiveStorageL)
   *
   * What it does:
   * Replaces one economy extra-storage lane (`ENERGY` or `MASS`) with `amount`
   * after decoding `(brain, resourceType, amount)` from Lua.
   */
  int cfunc_CAiBrainGiveStorageL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005885E0 (FUN_005885E0, cfunc_CAiBrainTakeResource)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainTakeResourceL`.
   */
  int cfunc_CAiBrainTakeResource(lua_State* luaContext);

  /**
   * Address: 0x00588600 (FUN_00588600, func_CAiBrainTakeResource_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:TakeResource(type,amount)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainTakeResource_LuaFuncDef();

  /**
   * Address: 0x00588660 (FUN_00588660, cfunc_CAiBrainTakeResourceL)
   *
   * What it does:
   * Removes up to `amount` from the selected stored economy resource and
   * returns the actually removed value.
   */
  int cfunc_CAiBrainTakeResourceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005889A0 (FUN_005889A0, cfunc_CAiBrainFindUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainFindUnitL`.
   */
  int cfunc_CAiBrainFindUnit(lua_State* luaContext);

  /**
   * Address: 0x00588A20 (FUN_00588A20, cfunc_CAiBrainFindUnitL)
   *
   * What it does:
   * Returns the first live army unit matching category arg #2, optionally
   * requiring idle-state when arg #3 is true.
   */
  int cfunc_CAiBrainFindUnitL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005889C0 (FUN_005889C0, func_CAiBrainFindUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:FindUnit(unitCategory, needToBeIdle)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainFindUnit_LuaFuncDef();

  /**
   * Address: 0x00588C10 (FUN_00588C10, cfunc_CAiBrainFindUpgradeBP)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainFindUpgradeBPL`.
   */
  int cfunc_CAiBrainFindUpgradeBP(lua_State* luaContext);

  /**
   * Address: 0x00588C30 (FUN_00588C30, func_CAiBrainFindUpgradeBP_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:FindUpgradeBP(unitName, upgradeList)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainFindUpgradeBP_LuaFuncDef();

  /**
   * Address: 0x00588C90 (FUN_00588C90, cfunc_CAiBrainFindUpgradeBPL)
   *
   * What it does:
   * Finds one matching `unitName` entry in `upgradeList` and returns its
   * upgrade blueprint id string, or `nil` when no match exists.
   */
  int cfunc_CAiBrainFindUpgradeBPL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00588EB0 (FUN_00588EB0, cfunc_CAiBrainFindUnitToUpgrade)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainFindUnitToUpgradeL`.
   */
  int cfunc_CAiBrainFindUnitToUpgrade(lua_State* luaContext);

  /**
   * Address: 0x00588F30 (FUN_00588F30, cfunc_CAiBrainFindUnitToUpgradeL)
   *
   * What it does:
   * Scans one `(fromBlueprintId, toBlueprintId)` candidate list and returns the
   * first eligible unit Lua object plus the upgrade blueprint id.
   */
  int cfunc_CAiBrainFindUnitToUpgradeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00588ED0 (FUN_00588ED0, func_CAiBrainFindUnitToUpgrade_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:FindUnitToUpgrade(upgradeList)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainFindUnitToUpgrade_LuaFuncDef();

  /**
   * Address: 0x00589380 (FUN_00589380, cfunc_CAiBrainDecideWhatToBuild)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainDecideWhatToBuildL`.
   */
  int cfunc_CAiBrainDecideWhatToBuild(lua_State* luaContext);

  /**
   * Address: 0x00589400 (FUN_00589400, cfunc_CAiBrainDecideWhatToBuildL)
   *
   * What it does:
   * Selects and returns the first buildable blueprint id from a typed
   * candidate table (`buildingTypes`) for the requested builder/type pair.
   */
  int cfunc_CAiBrainDecideWhatToBuildL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005893A0 (FUN_005893A0, func_CAiBrainDecideWhatToBuild_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:DecideWhatToBuild(builder, type, buildingTypes)`
   * Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainDecideWhatToBuild_LuaFuncDef();

  /**
   * Address: 0x0058B610 (FUN_0058B610, cfunc_CAiBrainBuildStructure)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainBuildStructureL`.
   */
  int cfunc_CAiBrainBuildStructure(lua_State* luaContext);

  /**
   * Address: 0x0058B690 (FUN_0058B690, cfunc_CAiBrainBuildStructureL)
   *
   * What it does:
   * Orders one structure build from `(brain, builder, blueprintId, locationInfo,
   * [relativeToArmyStart])` and schedules build-structure bookkeeping.
   */
  int cfunc_CAiBrainBuildStructureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058B630 (FUN_0058B630, func_CAiBrainBuildStructure_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:BuildStructure(builder, structureName, locationInfo)`
   * Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainBuildStructure_LuaFuncDef();

  /**
   * Address: 0x0058BCB0 (FUN_0058BCB0, cfunc_CAiBrainGetAvailableFactories)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetAvailableFactoriesL`.
   */
  int cfunc_CAiBrainGetAvailableFactories(lua_State* luaContext);

  /**
   * Address: 0x0058BD30 (FUN_0058BD30, cfunc_CAiBrainGetAvailableFactoriesL)
   *
   * What it does:
   * Reads `(brain[, referencePosition, maxDistance])` from the Lua stack,
   * collects this brain's available factory units (filtered by XZ
   * distance when supplied), and returns them as a Lua table.
   */
  int cfunc_CAiBrainGetAvailableFactoriesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058BCD0 (FUN_0058BCD0, func_CAiBrainGetAvailableFactories_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetAvailableFactories([referencePosition[, maxDistance]])`
   * Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetAvailableFactories_LuaFuncDef();

  /**
   * Address: 0x00590280 (FUN_00590280, cfunc_CAiBrainGetThreatAtPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetThreatAtPositionL`.
   */
  int cfunc_CAiBrainGetThreatAtPosition(lua_State* luaContext);

  /**
   * Address: 0x005902E0 (FUN_005902E0, cfunc_CAiBrainGetThreatAtPositionL)
   *
   * What it does:
   * Reads `(brain, position, ringRadius, restrictToOnMap[, threatType,
   * armyIndex])` from the Lua stack, samples the army influence map
   * around `position`, and pushes the aggregated threat value back on
   * the stack.
   */
  int cfunc_CAiBrainGetThreatAtPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00590300 (FUN_00590300, func_CAiBrainGetThreatAtPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetThreatAtPosition(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetThreatAtPosition_LuaFuncDef();

  /**
   * Address: 0x005905D0 (FUN_005905D0, cfunc_CAiBrainGetThreatBetweenPositions)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetThreatBetweenPositionsL`.
   */
  int cfunc_CAiBrainGetThreatBetweenPositions(lua_State* luaContext);

  /**
   * Address: 0x00590630 (FUN_00590630, cfunc_CAiBrainGetThreatBetweenPositionsL)
   *
   * What it does:
   * Reads `(brain, positionA, positionB, useRingMode[, threatType,
   * armyIndex])` from the Lua stack and returns the aggregated threat
   * along the grid-aligned path between the two positions.
   */
  int cfunc_CAiBrainGetThreatBetweenPositionsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005905F0 (FUN_005905F0, func_CAiBrainGetThreatBetweenPositions_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetThreatBetweenPositions(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetThreatBetweenPositions_LuaFuncDef();

  /**
   * Address: 0x0058FFA0 (FUN_0058FFA0, cfunc_CAiBrainAssignThreatAtPosition)
   */
  int cfunc_CAiBrainAssignThreatAtPosition(lua_State* luaContext);

  /**
   * Address: 0x00590000 (FUN_00590000, cfunc_CAiBrainAssignThreatAtPositionL)
   *
   * What it does:
   * Reads `(brain, position, threatValue[, decayRate, threatType])`
   * from the Lua stack and assigns the resulting threat through
   * `CInfluenceMap::AssignThreatAtPosition`.
   */
  int cfunc_CAiBrainAssignThreatAtPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058FFC0 (FUN_0058FFC0, func_CAiBrainAssignThreatAtPosition_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiBrainAssignThreatAtPosition_LuaFuncDef();

  /**
   * Address: 0x005908F0 (FUN_005908F0, cfunc_CAiBrainGetHighestThreatPosition)
   */
  int cfunc_CAiBrainGetHighestThreatPosition(lua_State* luaContext);

  /**
   * Address: 0x00590950 (FUN_00590950, cfunc_CAiBrainGetHighestThreatPositionL)
   *
   * What it does:
   * Reads `(brain, radius, restrictToOnMap[, threatType, armyIndex])`,
   * scans the influence map for the highest-threat cell, and pushes
   * `(position, threatValue)` back onto the Lua stack.
   */
  int cfunc_CAiBrainGetHighestThreatPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00590910 (FUN_00590910, func_CAiBrainGetHighestThreatPosition_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiBrainGetHighestThreatPosition_LuaFuncDef();

  /**
   * Address: 0x0058BA40 (FUN_0058BA40, cfunc_CAiBrainNumCurrentlyBuilding)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainNumCurrentlyBuildingL`.
   */
  int cfunc_CAiBrainNumCurrentlyBuilding(lua_State* luaContext);

  /**
   * Address: 0x0058BA60 (FUN_0058BA60, func_CAiBrainNumCurrentlyBuilding_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:NumCurrentlyBuilding(entityCategoryOfBuildee,entityCategoryOfBuilder)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainNumCurrentlyBuilding_LuaFuncDef();

  /**
   * Address: 0x0058BAC0 (FUN_0058BAC0, cfunc_CAiBrainNumCurrentlyBuildingL)
   *
   * What it does:
   * Counts live non-destroy-queued builder-category units in `Building`/`Upgrading`
   * state whose focused build target blueprint matches the requested buildee category.
   */
  int cfunc_CAiBrainNumCurrentlyBuildingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058C840 (FUN_0058C840, cfunc_CAiBrainBuildUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainBuildUnitL`.
   */
  int cfunc_CAiBrainBuildUnit(lua_State* luaContext);

  /**
   * Address: 0x0058C860 (FUN_0058C860, func_CAiBrainBuildUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:BuildUnit()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainBuildUnit_LuaFuncDef();

  /**
   * Address: 0x0058C8C0 (FUN_0058C8C0, cfunc_CAiBrainBuildUnitL)
   *
   * What it does:
   * Reads `(brain, builder, blueprintId, count)` from Lua and dispatches
   * `CAiBrain::BuildUnit` when arg #3 is a string.
   */
  int cfunc_CAiBrainBuildUnitL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058CA40 (FUN_0058CA40, cfunc_CAiBrainIsAnyEngineerBuilding)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainIsAnyEngineerBuildingL`.
   */
  int cfunc_CAiBrainIsAnyEngineerBuilding(lua_State* luaContext);

  /**
   * Address: 0x0058CAC0 (FUN_0058CAC0, cfunc_CAiBrainIsAnyEngineerBuildingL)
   *
   * What it does:
   * Returns whether any engineer currently in a build state has a blueprint
   * that matches the requested category set.
   */
  int cfunc_CAiBrainIsAnyEngineerBuildingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058CA60 (FUN_0058CA60, func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:IsAnyEngineerBuilding(category)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef();

  /**
   * Address: 0x0058CCA0 (FUN_0058CCA0, cfunc_CAiBrainGetNumPlatoonsWithAI)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetNumPlatoonsWithAIL`.
   */
  int cfunc_CAiBrainGetNumPlatoonsWithAI(lua_State* luaContext);

  /**
   * Address: 0x0058CCC0 (FUN_0058CCC0, func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetNumPlatoonsWithAI(planName)` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef();

  /**
   * Address: 0x0058CD10 (FUN_0058CD10, cfunc_CAiBrainGetNumPlatoonsWithAIL)
   *
   * What it does:
   * Resolves `(brain, planName)` and returns matching platoon count.
   */
  int cfunc_CAiBrainGetNumPlatoonsWithAIL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058CE30 (FUN_0058CE30, cfunc_CAiBrainGetNumPlatoonsTemplateNamed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetNumPlatoonsTemplateNamedL`.
   */
  int cfunc_CAiBrainGetNumPlatoonsTemplateNamed(lua_State* luaContext);

  /**
   * Address: 0x0058CE50 (FUN_0058CE50, func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetNumPlatoonsTemplateNamed(templateName)`
   * Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef();

  /**
   * Address: 0x0058CEA0 (FUN_0058CEA0, cfunc_CAiBrainGetNumPlatoonsTemplateNamedL)
   *
   * What it does:
   * Resolves `(brain, templateName)` and returns matching platoon count.
   */
  int cfunc_CAiBrainGetNumPlatoonsTemplateNamedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058CFC0 (FUN_0058CFC0, cfunc_CAiBrainPlatoonExists)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainPlatoonExistsL`.
   */
  int cfunc_CAiBrainPlatoonExists(lua_State* luaContext);

  /**
   * Address: 0x0058CFE0 (FUN_0058CFE0, func_CAiBrainPlatoonExists_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:PlatoonExists()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainPlatoonExists_LuaFuncDef();

  /**
   * Address: 0x0058D040 (FUN_0058D040, cfunc_CAiBrainPlatoonExistsL)
   *
   * What it does:
   * Returns whether arg #2 resolves to a live platoon object.
   */
  int cfunc_CAiBrainPlatoonExistsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058D140 (FUN_0058D140, cfunc_CAiBrainGetPlatoonsList)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetPlatoonsListL`.
   */
  int cfunc_CAiBrainGetPlatoonsList(lua_State* luaContext);

  /**
   * Address: 0x0058D160 (FUN_0058D160, func_CAiBrainGetPlatoonsList_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetPlatoonsList()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetPlatoonsList_LuaFuncDef();

  /**
   * Address: 0x0058D1C0 (FUN_0058D1C0, cfunc_CAiBrainGetPlatoonsListL)
   *
   * What it does:
   * Returns a Lua array of non-empty platoons, excluding `ArmyPool`.
   */
  int cfunc_CAiBrainGetPlatoonsListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058D360 (FUN_0058D360, cfunc_CAiBrainDisbandPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainDisbandPlatoonL`.
   */
  int cfunc_CAiBrainDisbandPlatoon(lua_State* luaContext);

  /**
   * Address: 0x0058D380 (FUN_0058D380, func_CAiBrainDisbandPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:DisbandPlatoon()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainDisbandPlatoon_LuaFuncDef();

  /**
   * Address: 0x0058D3E0 (FUN_0058D3E0, cfunc_CAiBrainDisbandPlatoonL)
   *
   * What it does:
   * Resolves `(brain, platoon)` from Lua and disbands the platoon via army
   * ownership.
   */
  int cfunc_CAiBrainDisbandPlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058D4D0 (FUN_0058D4D0, cfunc_CAiBrainDisbandPlatoonUniquelyNamed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainDisbandPlatoonUniquelyNamedL`.
   */
  int cfunc_CAiBrainDisbandPlatoonUniquelyNamed(lua_State* luaContext);

  /**
   * Address: 0x0058D4F0 (FUN_0058D4F0, func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:DisbandPlatoonUniquelyNamed()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef();

  /**
   * Address: 0x0058D550 (FUN_0058D550, cfunc_CAiBrainDisbandPlatoonUniquelyNamedL)
   *
   * What it does:
   * Resolves `(brain, uniqueName)` and disbands one uniquely named platoon.
   */
  int cfunc_CAiBrainDisbandPlatoonUniquelyNamedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058DFA0 (FUN_0058DFA0, cfunc_CAiBrainGetPlatoonUniquelyNamed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainGetPlatoonUniquelyNamedL`.
   */
  int cfunc_CAiBrainGetPlatoonUniquelyNamed(lua_State* luaContext);

  /**
   * Address: 0x0058DFC0 (FUN_0058DFC0, func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetPlatoonUniquelyNamed()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef();

  /**
   * Address: 0x0058E020 (FUN_0058E020, cfunc_CAiBrainGetPlatoonUniquelyNamedL)
   *
   * What it does:
   * Resolves `(brain, platoonName)` and returns the matching platoon Lua object
   * or `nil` when no matching platoon exists.
   */
  int cfunc_CAiBrainGetPlatoonUniquelyNamedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x005917F0 (FUN_005917F0, cfunc_CAiBrainGetNoRushTicks)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetNoRushTicksL`.
   */
  int cfunc_CAiBrainGetNoRushTicks(lua_State* luaContext);

  /**
   * Address: 0x00591810 (FUN_00591810, func_CAiBrainGetNoRushTicks_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:GetNoRushTicks()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainGetNoRushTicks_LuaFuncDef();

  /**
   * Address: 0x00591870 (FUN_00591870, cfunc_CAiBrainGetNoRushTicksL)
   *
   * What it does:
   * Returns current no-rush timer ticks for the brain owning army.
   */
  int cfunc_CAiBrainGetNoRushTicksL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058EB40 (FUN_0058EB40, cfunc_CAiBrainSetUpAttackVectorsToArmy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainSetUpAttackVectorsToArmyL`.
   */
  int cfunc_CAiBrainSetUpAttackVectorsToArmy(lua_State* luaContext);

  /**
   * Address: 0x0058EB60 (FUN_0058EB60, func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:SetUpAttackVectorsToArmy()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef();

  /**
   * Address: 0x0058EBC0 (FUN_0058EBC0, cfunc_CAiBrainSetUpAttackVectorsToArmyL)
   *
   * What it does:
   * Sets the brain's attack-vector category filter (defaulting to
   * `MOBILE - STRUCTURE`) and rebuilds attack vectors.
   */
  int cfunc_CAiBrainSetUpAttackVectorsToArmyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058E830 (FUN_0058E830, cfunc_CAiBrainFindClosestArmyWithBase)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainFindClosestArmyWithBaseL`.
   */
  int cfunc_CAiBrainFindClosestArmyWithBase(lua_State* luaContext);

  /**
   * Address: 0x0058E850 (FUN_0058E850, func_CAiBrainFindClosestArmyWithBase_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:FindClosestArmyWithBase()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainFindClosestArmyWithBase_LuaFuncDef();

  /**
   * Address: 0x0058E8B0 (FUN_0058E8B0, cfunc_CAiBrainFindClosestArmyWithBaseL)
   *
   * What it does:
   * Returns the brain of the closest enemy/allied/neutral army that owns at
   * least one structure, or nil when no such army exists.
   */
  int cfunc_CAiBrainFindClosestArmyWithBaseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058C490 (FUN_0058C490, cfunc_CAiBrainBuildPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CAiBrainBuildPlatoonL`.
   */
  int cfunc_CAiBrainBuildPlatoon(lua_State* luaContext);

  /**
   * Address: 0x0058C4B0 (FUN_0058C4B0, func_CAiBrainBuildPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:BuildPlatoon()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainBuildPlatoon_LuaFuncDef();

  /**
   * Address: 0x0058C510 (FUN_0058C510, cfunc_CAiBrainBuildPlatoonL)
   *
   * What it does:
   * Issues `BuildUnit` for each row in the build-plan table, scaling the
   * row's base count by the supplied multiplier and rotating across the
   * builder table.
   */
  int cfunc_CAiBrainBuildPlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058DC60 (FUN_0058DC60, cfunc_CAiBrainAssignUnitsToPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CAiBrainAssignUnitsToPlatoonL`.
   */
  int cfunc_CAiBrainAssignUnitsToPlatoon(lua_State* luaContext);

  /**
   * Address: 0x0058DC80 (FUN_0058DC80, func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAiBrain:AssignUnitsToPlatoon()` Lua binder.
   */
  CScrLuaInitForm* func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef();

  /**
   * Address: 0x0058DCE0 (FUN_0058DCE0, cfunc_CAiBrainAssignUnitsToPlatoonL)
   *
   * What it does:
   * Moves units from a Lua list into a platoon's named squad, removing them
   * from any prior platoon assignment, then dispatches `OnUnitsAddedToPlatoon`.
   */
  int cfunc_CAiBrainAssignUnitsToPlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058D650 (FUN_0058D650, cfunc_CAiBrainMakePlatoon)
   */
  int cfunc_CAiBrainMakePlatoon(lua_State* luaContext);

  /**
   * Address: 0x0058D670 (FUN_0058D670, func_CAiBrainMakePlatoon_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiBrainMakePlatoon_LuaFuncDef();

  /**
   * Address: 0x0058D6D0 (FUN_0058D6D0, cfunc_CAiBrainMakePlatoonL)
   *
   * What it does:
   * Two-mode `(brain, name|configTable, plan?)` platoon constructor: string
   * form passes through to `IArmy::MakePlatoon`; table form additionally
   * pulls live units out of the army-pool's unassigned squad to seed each
   * configured squad on the new platoon.
   */
  int cfunc_CAiBrainMakePlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0058BF80 (FUN_0058BF80, cfunc_CAiBrainCanBuildPlatoon)
   */
  int cfunc_CAiBrainCanBuildPlatoon(lua_State* luaContext);

  /**
   * Address: 0x0058BFA0 (FUN_0058BFA0, func_CAiBrainCanBuildPlatoon_LuaFuncDef)
   */
  CScrLuaInitForm* func_CAiBrainCanBuildPlatoon_LuaFuncDef();

  /**
   * Address: 0x0058C000 (FUN_0058C000, cfunc_CAiBrainCanBuildPlatoonL)
   *
   * What it does:
   * Returns either a Lua array of factory units or nil, answering "can this
   * brain's army currently build every row of a platoon template".
   */
  int cfunc_CAiBrainCanBuildPlatoonL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0057AC30 (FUN_0057AC30, Moho::FindAvailableFactory)
   *
   * What it does:
   * Returns the first builder in `candidateList` (or, when that list is
   * empty, any of the brain's army static factories) that is live, idle,
   * fully built, and capable of building the blueprint identified by
   * `blueprintId`. Returns null when no candidate matches or the blueprint
   * id is unknown.
   */
  [[nodiscard]] Unit* FindAvailableFactory(
    gpg::core::FastVector<Unit*>& candidateList, const char* blueprintId, CAiBrain* brain
  );
} // namespace moho

/**
 * VFTABLE: 0x00E1B084
 * COL:  0x00E6F448
 */
using CAiBrainGetNumPlatoonsWithAI_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B08C
 * COL:  0x00E6F3F8
 */
using CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B094
 * COL:  0x00E6F3A8
 */
using CAiBrainPlatoonExists_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B09C
 * COL:  0x00E6F358
 */
using CAiBrainGetPlatoonsList_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0A4
 * COL:  0x00E6F308
 */
using CAiBrainDisbandPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0AC
 * COL:  0x00E6F2B8
 */
using CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0B4
 * COL:  0x00E6F268
 */
using CAiBrainMakePlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0BC
 * COL:  0x00E6F218
 */
using CAiBrainAssignUnitsToPlatoon_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0C4
 * COL:  0x00E6F1C8
 */
using CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0CC
 * COL:  0x00E6F178
 */
using CAiBrainGetNumUnitsAroundPoint_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0D4
 * COL:  0x00E6F128
 */
using CAiBrainGetUnitsAroundPoint_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0DC
 * COL:  0x00E6F0D8
 */
using CAiBrainFindClosestArmyWithBase_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0E4
 * COL:  0x00E6F088
 */
using CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0EC
 * COL:  0x00E6F038
 */
using CAiBrainGetAttackVectors_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0F4
 * COL:  0x00E6EFE8
 */
using CAiBrainPickBestAttackVector_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B0FC
 * COL:  0x00E6EF98
 */
using CAiBrainGetEconomyStored_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B104
 * COL:  0x00E6EF48
 */
using CAiBrainGetEconomyStoredRatio_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B10C
 * COL:  0x00E6EEF8
 */
using CAiBrainGetEconomyIncome_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B114
 * COL:  0x00E6EEA8
 */
using CAiBrainGetEconomyUsage_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B11C
 * COL:  0x00E6EE58
 */
using CAiBrainGetEconomyRequested_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B124
 * COL:  0x00E6EE08
 */
using CAiBrainGetEconomyTrend_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B12C
 * COL:  0x00E6EDB8
 */
using CAiBrainGetMapWaterRatio_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B134
 * COL:  0x00E6ED68
 */
using CAiBrainAssignThreatAtPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B13C
 * COL:  0x00E6ED18
 */
using CAiBrainGetThreatAtPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B144
 * COL:  0x00E6ECC8
 */
using CAiBrainGetThreatBetweenPositions_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B14C
 * COL:  0x00E6EC78
 */
using CAiBrainGetHighestThreatPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B154
 * COL:  0x00E6EC28
 */
using CAiBrainGetThreatsAroundPosition_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B15C
 * COL:  0x00E6EBD8
 */
using CAiBrainCheckBlockingTerrain_LuaFuncDef = ::moho::CScrLuaBinder;

/**
 * VFTABLE: 0x00E1B164
 * COL:  0x00E6EB88
 */
using CAiBrainGetNoRushTicks_LuaFuncDef = ::moho::CScrLuaBinder;
