#include "moho/ai/CAiBrain.h"

#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  enum EEconResource : std::int32_t
  {
    ECON_ENERGY = 0,
    ECON_MASS = 1,
  };

  class CUnitCommand;

  CUnitCommand* func_OrderBuildStructure(
    Wm3::Vector3f* ori,
    CAiBrain* brain,
    Unit* builder,
    const char* bpName,
    Wm3::Vector3f* pos,
    float angle
  );
  void func_ScheduleBuildStructure(Unit* builder, CAiBrain* brain, CUnitCommand* command, Wm3::Vector2i where);
}

namespace
{
  constexpr const char* kAiBrainModulePath = "/lua/aibrain.lua";
  constexpr const char* kAiBrainClassName = "AIBrain";
  constexpr const char* kAiBrainGiveStorageHelpText = "GiveStorage(type,amount)";
  constexpr const char* kAiBrainGiveStorageName = "GiveStorage";
  constexpr const char* kAiBrainTakeResourceHelpText = "taken = TakeResource(type,amount)";
  constexpr const char* kAiBrainFindUnitHelpText =
    "brain:FindUnit(unitCategory, needToBeIdle) -- Return an unit that matches the unit name (can specify idle or not)";
  constexpr const char* kAiBrainFindUnitName = "FindUnit";
  constexpr const char* kAiBrainFindUnitToUpgradeHelpText =
    "brain:FindUnitToUpgrade(upgradeList) -- Return a unit and it's upgrade blueprint";
  constexpr const char* kAiBrainFindUnitToUpgradeName = "FindUnitToUpgrade";
  constexpr const char* kAiBrainDecideWhatToBuildHelpText = "brain:DecideWhatToBuild(builder, type, buildingTypes)";
  constexpr const char* kAiBrainDecideWhatToBuildName = "DecideWhatToBuild";
  constexpr const char* kAiBrainBuildStructureHelpText = "brain:BuildStructure(builder, structureName, locationInfo)";
  constexpr const char* kAiBrainBuildStructureName = "BuildStructure";
  constexpr const char* kAiBrainIsAnyEngineerBuildingHelpText = "brain:IsAnyEngineerBuilding(category)";
  constexpr const char* kAiBrainIsAnyEngineerBuildingName = "IsAnyEngineerBuilding";
  constexpr const char* kAiBrainLuaClassName = "CAiBrain";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr std::int32_t kAiDebugGridStep = 32;
  constexpr std::int32_t kAiDebugGridLineDepth = static_cast<std::int32_t>(0xFF7FFF7Fu);
  constexpr std::int32_t kAiDebugAttackLineDepth = static_cast<std::int32_t>(0xFFFFFF00u);
  constexpr std::uint32_t kAiDebugAttackRingDepth = 0xFFFF0000u;
  constexpr std::uint32_t kAiDebugAttackRingPrecision = 6u;
  constexpr float kAiDebugAttackRingRadius = 5.0f;
  constexpr const char* kEngineerCategoryName = "ENGINEER";
  constexpr std::int32_t kBuildingStateTag = 5;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAiBrainIndex = 0;

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet* FindSimLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "sim") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindSimLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RRef MakeEconResourceRef(moho::EEconResource* const resource)
  {
    gpg::RRef enumRef{};
    if (resource == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEconResourceType = nullptr;
    if (sEconResourceType == nullptr) {
      sEconResourceType = gpg::LookupRType(typeid(moho::EEconResource));
    }

    enumRef.mObj = resource;
    enumRef.mType = sEconResourceType;
    return enumRef;
  }

  [[nodiscard]] float& SelectResourceLane(moho::SEconPair& value, const moho::EEconResource resource) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[nodiscard]] const float& SelectResourceLane(const moho::SEconPair& value, const moho::EEconResource resource) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  struct CEconStorageRuntimeView
  {
    std::uint8_t* economyRuntime; // +0x00
    float amounts[4];             // +0x04
  };

  static_assert(
    offsetof(CEconStorageRuntimeView, economyRuntime) == 0x00,
    "CEconStorageRuntimeView::economyRuntime offset must be 0x00"
  );
  static_assert(offsetof(CEconStorageRuntimeView, amounts) == 0x04, "CEconStorageRuntimeView::amounts offset must be 0x04");

  void ApplyEconStorageDelta(CEconStorageRuntimeView& storage, const std::int32_t direction)
  {
    // Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
    if (storage.economyRuntime == nullptr) {
      return;
    }

    const std::int64_t signedDirection = static_cast<std::int64_t>(direction);
    constexpr std::size_t kAccumOffset = 0x40;
    constexpr std::size_t kAccumCount = 4;
    for (std::size_t i = 0; i < kAccumCount; ++i) {
      auto* const accumulator =
        reinterpret_cast<std::int64_t*>(storage.economyRuntime + kAccumOffset + (i * sizeof(std::int64_t)));
      const std::int64_t delta = static_cast<std::int64_t>(storage.amounts[i]) * signedDirection;
      *accumulator += delta;
    }
  }

  [[nodiscard]] LuaPlus::LuaObject GetLuaTableFieldByName(const LuaPlus::LuaObject& tableObject, const char* fieldName)
  {
    LuaPlus::LuaObject out;
    if (!tableObject.IsTable()) {
      return out;
    }

    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(lstate);
    lua_pushstring(lstate, fieldName ? fieldName : "");
    lua_gettable(lstate, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, top);
    return out;
  }

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, top);
    return out;
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::EntityCategorySet));
    }
    return sType;
  }

  [[nodiscard]] moho::EntityCategorySet* ResolveEntityCategorySetFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = GetLuaTableFieldByName(payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    if (gpg::RType* const expectedType = CachedEntityCategorySetType(); expectedType != nullptr) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, expectedType);
      if (upcast.mObj != nullptr) {
        return static_cast<moho::EntityCategorySet*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr
        && (std::strstr(typeName, "EntityCategory") != nullptr || std::strstr(typeName, "BVSet") != nullptr)) {
      return static_cast<moho::EntityCategorySet*>(userDataRef.mObj);
    }

    return nullptr;
  }

  [[nodiscard]] bool CategoryContainsBlueprint(
    const moho::EntityCategorySet* const categorySet,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    if (categorySet == nullptr || blueprint == nullptr) {
      return false;
    }

    return categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] bool UnitHasHeadCommand(const moho::Unit* const unit)
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return false;
    }

    const msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>& commands = unit->CommandQueue->mCommandVec;
    if (commands.empty()) {
      return false;
    }

    return commands.front().GetObjectPtr() != nullptr;
  }

  [[nodiscard]] moho::Unit* FindUpgradeableArmyUnitByBlueprint(
    moho::CAiBrain* const brain,
    const moho::RUnitBlueprint* const fromBlueprint
  )
  {
    if (brain == nullptr || brain->mArmy == nullptr || fromBlueprint == nullptr) {
      return nullptr;
    }

    moho::Sim* const sim = brain->mArmy->Simulation;
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return nullptr;
    }

    const std::uint32_t armyIndex = static_cast<std::uint32_t>(brain->mArmy->ArmyId);
    moho::CEntityDbAllUnitsNode* node = sim->mEntityDB->AllUnitsEnd(armyIndex);
    moho::CEntityDbAllUnitsNode* const endNode = sim->mEntityDB->AllUnitsEnd(armyIndex + 1u);
    while (node != endNode) {
      moho::Unit* const unit = moho::CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      if (!unit->IsDead() && !unit->IsBeingBuilt() && !UnitHasHeadCommand(unit)) {
        const moho::RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
        if (
          unitBlueprint != nullptr
          && gpg::STR_EqualsNoCase(unitBlueprint->mBlueprintId.c_str(), fromBlueprint->mBlueprintId.c_str())
        ) {
          return unit;
        }
      }

      node = moho::CEntityDb::NextAllUnitsNode(node);
    }

    return nullptr;
  }

  [[nodiscard]] LuaPlus::LuaObject LoadAiBrainFactoryObject(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(state, kAiBrainModulePath);
    if (moduleObj) {
      LuaPlus::LuaObject classObj = SCR_GetLuaTableField(state, moduleObj, kAiBrainClassName);
      if (!classObj.IsNil()) {
        return classObj;
      }
    }

    gpg::Logf("Can't find AIBrain, using CAiBrain directly");
    return CScrLuaMetatableFactory<CScriptObject*>::Instance().Get(state);
  }

  [[nodiscard]] SBuildStructurePositionNode* AllocateBuildStructureNode()
  {
    auto* const node = static_cast<SBuildStructurePositionNode*>(::operator new(sizeof(SBuildStructurePositionNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->mGridPosition = {};
    node->mBuildInfo.mPlacementLink.mOwnerSlot = nullptr;
    node->mBuildInfo.mPlacementLink.mNext = nullptr;
    node->mBuildInfo.mResourceLink.mOwnerSlot = nullptr;
    node->mBuildInfo.mResourceLink.mNext = nullptr;
    node->mColor = 1;
    node->mIsNil = 0;
    node->mPad26[0] = 0;
    node->mPad26[1] = 0;
    return node;
  }

  void InitializeBuildStructureMap(SBuildStructurePositionMap& map)
  {
    map.mMeta00 = 0;
    map.mHead = AllocateBuildStructureNode();
    map.mHead->mIsNil = 1;
    map.mHead->parent = map.mHead;
    map.mHead->left = map.mHead;
    map.mHead->right = map.mHead;
    map.mSize = 0;
  }

  void UnlinkBuildResourceInfoLink(SBuildResourceInfoLink& link)
  {
    SBuildResourceInfoLink** cursor = link.mOwnerSlot;
    if (!cursor) {
      return;
    }

    while (*cursor != &link) {
      if (!*cursor) {
        return;
      }
      cursor = &(*cursor)->mNext;
    }

    *cursor = link.mNext;
    link.mOwnerSlot = nullptr;
    link.mNext = nullptr;
  }

  void DestroyBuildStructureTree(SBuildStructurePositionNode* node)
  {
    while (node && node->mIsNil == 0u) {
      DestroyBuildStructureTree(node->right);
      SBuildStructurePositionNode* const left = node->left;

      // Matches sub_5812C0 unlink order (+0x1C link first, then +0x14 link).
      UnlinkBuildResourceInfoLink(node->mBuildInfo.mResourceLink);
      UnlinkBuildResourceInfoLink(node->mBuildInfo.mPlacementLink);
      ::operator delete(node);

      node = left;
    }
  }

  void DestroyBuildStructureMap(SBuildStructurePositionMap& map)
  {
    if (!map.mHead) {
      return;
    }

    DestroyBuildStructureTree(map.mHead->parent);
    ::operator delete(map.mHead);
    map.mHead = nullptr;
    map.mSize = 0;
  }

  [[nodiscard]] CTaskStage* AllocateTaskStage()
  {
    auto* const stage = static_cast<CTaskStage*>(::operator new(sizeof(CTaskStage)));
    stage->mThreads.mPrev = &stage->mThreads;
    stage->mThreads.mNext = &stage->mThreads;
    stage->mStagedThreads.mPrev = &stage->mStagedThreads;
    stage->mStagedThreads.mNext = &stage->mStagedThreads;
    stage->mActive = true;
    stage->mAlignmentPad11[0] = 0;
    stage->mAlignmentPad11[1] = 0;
    stage->mAlignmentPad11[2] = 0;
    return stage;
  }

  void DestroyTaskStageAndDelete(CTaskStage*& stage)
  {
    if (!stage) {
      return;
    }

    stage->Teardown();
    stage->mStagedThreads.ListUnlink();
    stage->mThreads.ListUnlink();
    ::operator delete(stage);
    stage = nullptr;
  }

  struct CAiBrainStartupBootstrap
  {
    CAiBrainStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_CAiBrain_Index();
    }
  };

  [[maybe_unused]] CAiBrainStartupBootstrap gCAiBrainStartupBootstrap;
} // namespace

gpg::RType* CAiBrain::sType = nullptr;

/**
 * Address: 0x00579E40 (FUN_00579E40, default ctor)
 */
CAiBrain::CAiBrain()
  : mArmy(nullptr)
  , mCurrentEnemy(nullptr)
  , mPersonality(nullptr)
  , mCurrentPlan()
  , mAttackVectors()
  , mBuildCategoryRange()
  , mBuildStructureMap{}
  , mSim(nullptr)
  , mAiThreadStage(nullptr)
  , mAttackerThreadStage(nullptr)
  , mReservedThreadStage(nullptr)
  , mTailWord(0)
{
  mCurrentPlan.assign("", 0);
  InitializeBuildStructureMap(mBuildStructureMap);
}

/**
 * Address: 0x00579F80 (FUN_00579F80, army ctor)
 */
CAiBrain::CAiBrain(CArmyImpl* const army)
  : CAiBrain()
{
  mArmy = army;
  mCurrentEnemy = nullptr;
  mSim = army ? army->GetSim() : nullptr;

  if (mSim && mSim->mLuaState) {
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject factory = LoadAiBrainFactoryObject(mSim->mLuaState);
    CreateLuaObject(factory, arg1, arg2, arg3);
  }

  mPersonality = new (std::nothrow) CAiPersonality(mSim);

  mAiThreadStage = AllocateTaskStage();
  mAttackerThreadStage = AllocateTaskStage();
  mReservedThreadStage = AllocateTaskStage();

  if (mPersonality) {
    mPersonality->ReadData();
  }
}

/**
 * Address: 0x00579590 (FUN_00579590, ?GetClass@CAiBrain@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiBrain::GetClass() const
{
  gpg::RType* type = sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiBrain));
    sType = type;
  }
  return type;
}

/**
 * Address: 0x005795B0 (FUN_005795B0, ?GetDerivedObjectRef@CAiBrain@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiBrain::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x00BCB4B0 (FUN_00BCB4B0, sub_BCB4B0)
 *
 * What it does:
 * Allocates the next Lua metatable-factory object index for the CAiBrain startup lane.
 */
int moho::register_CScrLuaMetatableFactory_CAiBrain_Index()
{
  const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
  gRecoveredCScrLuaMetatableFactoryCAiBrainIndex = index;
  return index;
}

/**
 * Address: 0x00579F30 (FUN_00579F30, scalar deleting thunk)
 * Address: 0x0057A1E0 (FUN_0057A1E0, core destructor)
 */
CAiBrain::~CAiBrain()
{
  DestroyTaskStageAndDelete(mReservedThreadStage);
  DestroyTaskStageAndDelete(mAttackerThreadStage);
  DestroyTaskStageAndDelete(mAiThreadStage);

  DestroyBuildStructureMap(mBuildStructureMap);

  // mCurrentPlan has no automatic heap cleanup in this legacy wrapper.
  mCurrentPlan.tidy(true, 0U);

  delete mPersonality;
  mPersonality = nullptr;
}

/**
 * Address: 0x0057A6D0 (FUN_0057A6D0, Moho::CAiBrain::CanBuildUnit)
 *
 * What it does:
 * Resolves a unit blueprint id through active sim rules and tests whether
 * `builder` can construct that blueprint under current build restrictions.
 */
bool CAiBrain::CanBuildUnit(const char* const blueprintId, CAiBrain* const brain, Unit* const builder)
{
  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintId);

  const RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  return blueprint != nullptr && builder->CanBuild(blueprint);
}

/**
 * Address: 0x0057BAA0 (FUN_0057BAA0, Moho::CAiBrain::DrawDebug)
 *
 * What it does:
 * Draws terrain debug grid lines and attack-vector markers to the active
 * simulation debug canvas.
 */
CAiBrain* CAiBrain::DrawDebug(CAiBrain* const brain)
{
  CDebugCanvas* const debugCanvas = brain->mSim->GetDebugCanvas();
  CHeightField* const heightField = brain->mSim->mMapData->mHeightField.get();

  const std::int32_t maxX = heightField->width - 1;
  const std::int32_t maxZ = heightField->height - 1;

  std::int32_t zLineCount = maxX / kAiDebugGridStep;
  std::int32_t xLineCount = maxZ / kAiDebugGridStep;

  if (zLineCount > 0) {
    const float maxXf = static_cast<float>(maxX);
    std::int32_t z = 0;
    do {
      SDebugLine line{};
      line.p0.x = 0.0f;
      line.p0.y = 0.0f;
      line.p0.z = static_cast<float>(z);
      line.p1.x = maxXf;
      line.p1.y = 0.0f;
      line.p1.z = static_cast<float>(z);
      line.depth0 = kAiDebugGridLineDepth;
      line.depth1 = kAiDebugGridLineDepth;
      debugCanvas->DebugDrawLine(line);

      z += kAiDebugGridStep;
      --zLineCount;
    } while (zLineCount != 0);

    xLineCount = maxZ / kAiDebugGridStep;
  }

  if (xLineCount > 0) {
    const float maxZf = static_cast<float>(maxZ);
    std::int32_t x = 0;
    do {
      SDebugLine line{};
      line.p0.x = static_cast<float>(x);
      line.p0.y = 0.0f;
      line.p0.z = 0.0f;
      line.p1.x = static_cast<float>(x);
      line.p1.y = 0.0f;
      line.p1.z = maxZf;
      line.depth0 = kAiDebugGridLineDepth;
      line.depth1 = kAiDebugGridLineDepth;
      debugCanvas->DebugDrawLine(line);

      x += kAiDebugGridStep;
      --xLineCount;
    } while (xLineCount != 0);
  }

  const Wm3::Vector3f upAxis{0.0f, 1.0f, 0.0f};
  for (const SAiAttackVectorDebug& attackVector : brain->mAttackVectors) {
    debugCanvas->AddWireCircle(
      upAxis,
      attackVector.mOrigin,
      kAiDebugAttackRingRadius,
      kAiDebugAttackRingDepth,
      kAiDebugAttackRingPrecision
    );

    SDebugLine line{};
    line.p0 = attackVector.mOrigin;
    line.p1.x = attackVector.mOrigin.x + attackVector.mDirection.x;
    line.p1.y = attackVector.mOrigin.y + attackVector.mDirection.y;
    line.p1.z = attackVector.mOrigin.z + attackVector.mDirection.z;
    line.depth0 = kAiDebugAttackLineDepth;
    line.depth1 = kAiDebugAttackLineDepth;
    debugCanvas->DebugDrawLine(line);
  }

  return brain;
}

/**
 * Address: 0x005883E0 (FUN_005883E0, cfunc_CAiBrainGiveStorage)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGiveStorageL`.
 */
int moho::cfunc_CAiBrainGiveStorage(lua_State* const luaContext)
{
  return cfunc_CAiBrainGiveStorageL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588400 (FUN_00588400, func_CAiBrainGiveStorage_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GiveStorage(type,amount)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGiveStorage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGiveStorageName,
    &moho::cfunc_CAiBrainGiveStorage,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGiveStorageHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588460 (FUN_00588460, cfunc_CAiBrainGiveStorageL)
 *
 * What it does:
 * Replaces one economy extra-storage lane (`ENERGY` or `MASS`) with `amount`
 * after decoding `(brain, resourceType, amount)` from Lua.
 */
int moho::cfunc_CAiBrainGiveStorageL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGiveStorageHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EEconResource resource = ECON_ENERGY;
  gpg::RRef enumRef = MakeEconResourceRef(&resource);
  const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
  const char* const resourceTypeName = lua_tostring(rawState, 2);
  if (resourceTypeName == nullptr) {
    resourceTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, resourceTypeName, enumRef);

  const LuaPlus::LuaStackObject amountArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    amountArg.TypeError("number");
  }
  const float amount = static_cast<float>(lua_tonumber(rawState, 3));

  SEconPair newStorage{0.0f, 0.0f};
  SelectResourceLane(newStorage, resource) = amount;

  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  auto* const extraStorage = reinterpret_cast<CEconStorageRuntimeView*>(economyInfo->storageDelta);
  ApplyEconStorageDelta(*extraStorage, -1);
  extraStorage->amounts[0] = newStorage.ENERGY;
  extraStorage->amounts[1] = newStorage.MASS;
  ApplyEconStorageDelta(*extraStorage, 1);
  return 0;
}

/**
 * Address: 0x00588660 (FUN_00588660, cfunc_CAiBrainTakeResourceL)
 *
 * What it does:
 * Reads `(brain, resourceType, amount)`, removes up to `amount` from the
 * selected stored resource, and returns the actual amount removed.
 */
int moho::cfunc_CAiBrainTakeResourceL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainTakeResourceHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EEconResource resource = ECON_ENERGY;
  gpg::RRef enumRef = MakeEconResourceRef(&resource);
  const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
  const char* const resourceTypeName = lua_tostring(rawState, 2);
  if (resourceTypeName == nullptr) {
    resourceTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, resourceTypeName, enumRef);

  const LuaPlus::LuaStackObject amountArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    amountArg.TypeError("number");
  }
  const float amount = static_cast<float>(lua_tonumber(rawState, 3));

  SEconPair request{0.0f, 0.0f};
  SelectResourceLane(request, resource) = amount;

  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  SEconPair& stored = economyInfo->economy.mStored;

  SEconPair taken{
    request.ENERGY <= stored.ENERGY ? request.ENERGY : stored.ENERGY,
    request.MASS <= stored.MASS ? request.MASS : stored.MASS,
  };

  const float updatedEnergy = stored.ENERGY - taken.ENERGY;
  const float updatedMass = stored.MASS - taken.MASS;
  stored.ENERGY = updatedEnergy > 0.0f ? updatedEnergy : 0.0f;
  stored.MASS = updatedMass > 0.0f ? updatedMass : 0.0f;

  lua_pushnumber(rawState, SelectResourceLane(taken, resource));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005889A0 (FUN_005889A0, cfunc_CAiBrainFindUnit)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainFindUnitL`.
 */
int moho::cfunc_CAiBrainFindUnit(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindUnitL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588A20 (FUN_00588A20, cfunc_CAiBrainFindUnitL)
 *
 * What it does:
 * Returns the first live army unit matching the category filter in arg #2,
 * optionally requiring idle-state when arg #3 is true.
 */
int moho::cfunc_CAiBrainFindUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainFindUnitHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  const bool needToBeIdle = LuaPlus::LuaStackObject(state, 3).GetBoolean();

  SEntitySetTemplateUnit categoryUnits{};
  brain->mArmy->GetUnits(&categoryUnits, categorySet);

  for (Entity* const* it = categoryUnits.mVec.begin(); it != categoryUnits.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (unit == nullptr) {
      continue;
    }

    if (unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
      continue;
    }

    if (needToBeIdle && UnitHasHeadCommand(unit)) {
      continue;
    }

    unit->GetLuaObject().PushStack(state);
    return 1;
  }

  lua_pushnil(rawState);
  return 1;
}

/**
 * Address: 0x005889C0 (FUN_005889C0, func_CAiBrainFindUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:FindUnit(unitCategory, needToBeIdle)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindUnitName,
    &moho::cfunc_CAiBrainFindUnit,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588EB0 (FUN_00588EB0, cfunc_CAiBrainFindUnitToUpgrade)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainFindUnitToUpgradeL`.
 */
int moho::cfunc_CAiBrainFindUnitToUpgrade(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindUnitToUpgradeL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588F30 (FUN_00588F30, cfunc_CAiBrainFindUnitToUpgradeL)
 *
 * What it does:
 * Scans candidate `(fromBlueprintId, toBlueprintId)` upgrade pairs and returns
 * the first idle army unit matching `fromBlueprintId` plus `toBlueprintId`.
 */
int moho::cfunc_CAiBrainFindUnitToUpgradeL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainFindUnitToUpgradeHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject upgradeListObject(LuaPlus::LuaStackObject(state, 2));
  if (brain != nullptr && brain->mSim != nullptr && brain->mSim->mRules != nullptr && upgradeListObject.IsTable()) {
    const int pairCount = upgradeListObject.GetCount();
    for (int pairIndex = 1; pairIndex <= pairCount; ++pairIndex) {
      LuaPlus::LuaObject upgradePair = upgradeListObject[pairIndex];
      if (!upgradePair.IsTable()) {
        continue;
      }

      const char* const fromBlueprintId = upgradePair[1].GetString();
      const char* const toBlueprintId = upgradePair[2].GetString();
      if (fromBlueprintId == nullptr || toBlueprintId == nullptr) {
        continue;
      }

      RResId fromId{};
      gpg::STR_InitFilename(&fromId.name, fromBlueprintId);
      RResId toId{};
      gpg::STR_InitFilename(&toId.name, toBlueprintId);

      const RUnitBlueprint* const fromBlueprint = brain->mSim->mRules->GetUnitBlueprint(fromId);
      const RUnitBlueprint* const toBlueprint = brain->mSim->mRules->GetUnitBlueprint(toId);
      if (fromBlueprint == nullptr || toBlueprint == nullptr) {
        continue;
      }

      Unit* const candidateUnit = FindUpgradeableArmyUnitByBlueprint(brain, fromBlueprint);
      if (candidateUnit == nullptr) {
        continue;
      }

      candidateUnit->GetLuaObject().PushStack(state);
      lua_pushstring(rawState, toBlueprint->mBlueprintId.c_str());
      return 2;
    }
  }

  lua_pushnil(rawState);
  lua_pushnil(rawState);
  return 2;
}

/**
 * Address: 0x00588ED0 (FUN_00588ED0, func_CAiBrainFindUnitToUpgrade_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:FindUnitToUpgrade(upgradeList)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindUnitToUpgrade_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindUnitToUpgradeName,
    &moho::cfunc_CAiBrainFindUnitToUpgrade,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindUnitToUpgradeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00589380 (FUN_00589380, cfunc_CAiBrainDecideWhatToBuild)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainDecideWhatToBuildL`.
 */
int moho::cfunc_CAiBrainDecideWhatToBuild(lua_State* const luaContext)
{
  return cfunc_CAiBrainDecideWhatToBuildL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00589400 (FUN_00589400, cfunc_CAiBrainDecideWhatToBuildL)
 *
 * What it does:
 * Selects and returns the first buildable blueprint id from a typed
 * candidate table (`buildingTypes`) for the requested builder/type pair.
 */
int moho::cfunc_CAiBrainDecideWhatToBuildL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainDecideWhatToBuildHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject builderObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const builder = SCR_FromLua_Unit(builderObject);

  const LuaPlus::LuaStackObject typeArgument(state, 3);
  const char* const requestedType = lua_tostring(rawState, 3);
  if (requestedType == nullptr) {
    typeArgument.TypeError("string");
  }

  const LuaPlus::LuaObject typedCandidates(LuaPlus::LuaStackObject(state, 4));
  if (typedCandidates.IsTable()) {
    const int groupCount = typedCandidates.GetCount();
    for (int groupIndex = 1; groupIndex <= groupCount; ++groupIndex) {
      LuaPlus::LuaObject typeGroup = typedCandidates[groupIndex];
      const char* const groupType = typeGroup[1].GetString();
      if (_stricmp(groupType, requestedType) != 0) {
        continue;
      }

      const int candidateCount = typeGroup.GetCount();
      for (int candidateIndex = 2; candidateIndex <= candidateCount; ++candidateIndex) {
        LuaPlus::LuaObject blueprintToken = typeGroup[candidateIndex];
        if (CAiBrain::CanBuildUnit(blueprintToken.GetString(), brain, builder)) {
          blueprintToken.PushStack(state);
          return 1;
        }
      }
    }
  }

  lua_pushnil(rawState);
  return 1;
}

/**
 * Address: 0x005893A0 (FUN_005893A0, func_CAiBrainDecideWhatToBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:DecideWhatToBuild(builder, type, buildingTypes)`
 * Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainDecideWhatToBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainDecideWhatToBuildName,
    &moho::cfunc_CAiBrainDecideWhatToBuild,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainDecideWhatToBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058B610 (FUN_0058B610, cfunc_CAiBrainBuildStructure)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainBuildStructureL`.
 */
int moho::cfunc_CAiBrainBuildStructure(lua_State* const luaContext)
{
  return cfunc_CAiBrainBuildStructureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058B690 (FUN_0058B690, cfunc_CAiBrainBuildStructureL)
 *
 * What it does:
 * Reads `(brain, builder, blueprintId, locationInfo[, relativeToArmyStart])`,
 * issues one build-structure command, and schedules build-structure bookkeeping
 * at the integer cell derived from the final build position.
 */
int moho::cfunc_CAiBrainBuildStructureL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 5) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainBuildStructureHelpText,
      4,
      5,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject builderObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const builder = SCR_FromLua_Unit(builderObject);

  const LuaPlus::LuaObject blueprintObject(LuaPlus::LuaStackObject(state, 3));
  const char* const blueprintId = blueprintObject.GetString();

  const LuaPlus::LuaObject locationInfoObject(LuaPlus::LuaStackObject(state, 4));
  const LuaPlus::LuaObject locationZObject = locationInfoObject[2];
  const LuaPlus::LuaObject locationXObject = locationInfoObject[1];
  const float locationX = locationXObject.GetNumber();
  const float locationZ = locationZObject.GetNumber();

  Wm3::Vector3f buildPosition{};
  buildPosition.x = locationX;
  buildPosition.y = 0.0f;
  buildPosition.z = locationZ;

  Wm3::Vector3f orientation{};
  const LuaPlus::LuaObject angleObject = locationInfoObject[3];
  const float angle = angleObject.GetNumber();

  if (locationInfoObject.GetCount() > 3) {
    const LuaPlus::LuaObject orientationZObject = locationInfoObject[5];
    const LuaPlus::LuaObject orientationXObject = locationInfoObject[4];
    orientation.x = orientationXObject.GetNumber();
    orientation.y = 0.0f;
    orientation.z = orientationZObject.GetNumber();
  }

  if (argumentCount > 4) {
    if (LuaPlus::LuaStackObject(state, 5).GetBoolean()) {
      Wm3::Vector2f armyStartPosA{};
      brain->mArmy->GetArmyStartPos(armyStartPosA);
      Wm3::Vector2f armyStartPosB{};
      brain->mArmy->GetArmyStartPos(armyStartPosB);
      buildPosition.x = armyStartPosB.x + locationX;
      buildPosition.y = 0.0f;
      buildPosition.z = armyStartPosA.y + locationZ;
    }
  }

  CUnitCommand* const command = func_OrderBuildStructure(&orientation, brain, builder, blueprintId, &buildPosition, angle);
  const Wm3::Vector2i buildCellPosition{
    static_cast<int>(buildPosition.x),
    static_cast<int>(buildPosition.z),
  };
  func_ScheduleBuildStructure(builder, brain, command, buildCellPosition);
  return 1;
}

/**
 * Address: 0x0058B630 (FUN_0058B630, func_CAiBrainBuildStructure_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:BuildStructure(builder, structureName, locationInfo)`
 * Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainBuildStructure_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainBuildStructureName,
    &moho::cfunc_CAiBrainBuildStructure,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainBuildStructureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058CA40 (FUN_0058CA40, cfunc_CAiBrainIsAnyEngineerBuilding)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainIsAnyEngineerBuildingL`.
 */
int moho::cfunc_CAiBrainIsAnyEngineerBuilding(lua_State* const luaContext)
{
  return cfunc_CAiBrainIsAnyEngineerBuildingL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058CAC0 (FUN_0058CAC0, cfunc_CAiBrainIsAnyEngineerBuildingL)
 *
 * What it does:
 * Returns whether any engineer currently in build state matches the requested
 * category filter.
 */
int moho::cfunc_CAiBrainIsAnyEngineerBuildingL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainIsAnyEngineerBuildingHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  bool foundMatch = false;
  if (brain != nullptr && brain->mArmy != nullptr && brain->mSim != nullptr && brain->mSim->mRules != nullptr) {
    const CategoryWordRangeView* const engineerCategory = brain->mSim->mRules->GetEntityCategory(kEngineerCategoryName);

    SEntitySetTemplateUnit engineerUnits{};
    brain->mArmy->GetUnits(&engineerUnits, const_cast<CategoryWordRangeView*>(engineerCategory));

    for (Entity* const* it = engineerUnits.mVec.begin(); it != engineerUnits.mVec.end(); ++it) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      if (!unit->IsUnitState(static_cast<EUnitState>(kBuildingStateTag))) {
        continue;
      }

      if (CategoryContainsBlueprint(categorySet, unit->GetBlueprint())) {
        foundMatch = true;
        break;
      }
    }
  }

  lua_pushboolean(rawState, foundMatch ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0058CA60 (FUN_0058CA60, func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:IsAnyEngineerBuilding(category)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainIsAnyEngineerBuildingName,
    &moho::cfunc_CAiBrainIsAnyEngineerBuilding,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainIsAnyEngineerBuildingHelpText
  );
  return &binder;
}
