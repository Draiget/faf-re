#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/script/CScriptObject.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

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
     * Address: 0x0057BAA0 (FUN_0057BAA0, Moho::CAiBrain::DrawDebug)
     *
     * What it does:
     * Draws AI debug grid lines and per-attack-vector direction markers.
     */
    static CAiBrain* DrawDebug(CAiBrain* brain);

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
