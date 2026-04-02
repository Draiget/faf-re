// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/Unit.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/animation/CAniActor.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/StatItem.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimStartupRegistrations.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UnitLuaFunctionThunks.h"
#include "moho/unit/core/UserUnit.h"

using namespace moho;

namespace moho
{
  int cfunc_UnitGetCargoL(LuaPlus::LuaState* state);
  int cfunc_UnitGetCargo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetCargo_LuaFuncDef();
  int cfunc_UnitEnableManipulatorsL(LuaPlus::LuaState* state);
  int cfunc_UnitEnableManipulators(lua_State* luaContext);
  CScrLuaInitForm* func_UnitEnableManipulators_LuaFuncDef();
  int cfunc_UnitKillManipulators(lua_State* luaContext);
  CScrLuaInitForm* func_UnitKillManipulators_LuaFuncDef();
  int cfunc_UnitKillManipulatorsL(LuaPlus::LuaState* state);
  int cfunc_UnitSetFireStateL(LuaPlus::LuaState* state);
  int cfunc_UnitSetFireState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetFireState_LuaFuncDef();
  int cfunc_UnitGetCommandQueueL(LuaPlus::LuaState* state);
  int cfunc_UnitGetCommandQueue(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetCommandQueue_LuaFuncDef();
  int cfunc_GetScriptBitL(LuaPlus::LuaState* state);
  int cfunc_UnitCanBuildL(LuaPlus::LuaState* state);
  int cfunc_UnitRecoilImpulseL(LuaPlus::LuaState* state);
  int cfunc_UnitCanPathToRectL(LuaPlus::LuaState* state);
  int cfunc_UnitCanPathToRect(lua_State* luaContext);
  CScrLuaInitForm* func_UnitCanPathToRect_LuaFuncDef();

  template <>
  class CScrLuaMetatableFactory<Unit> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<Unit>) == 0x08, "CScrLuaMetatableFactory<Unit> size must be 0x08");
} // namespace moho

namespace
{
  // Guard condition recovered from Unit::ToggleScriptBit: state 14 == UNITSTATE_Attached.
  constexpr EUnitState kTransportScriptBitGuardState = UNITSTATE_Attached;
  constexpr std::uint32_t kCommandCapPause = 0x00020000u;  // RULEUCC_Pause
  constexpr std::uint32_t kToggleCapGeneric = 0x00000040u; // RULEUTC_GenericToggle
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kUnitGetCargoName = "GetCargo";
  constexpr const char* kUnitGetCargoHelpText = "GetCargo(self)";
  constexpr const char* kUnitEnableManipulatorsName = "EnableManipulators";
  constexpr const char* kUnitEnableManipulatorsHelpText =
    "Unit:EnableManipulators([string boneName | int boneIndex], bool Enable)";
  constexpr const char* kUnitKillManipulatorsName = "KillManipulators";
  constexpr const char* kUnitKillManipulatorsHelpText = "Unit:KillManipulators([boneName|boneIndex])";
  constexpr const char* kUnitSetFireStateName = "SetFireState";
  constexpr const char* kUnitSetFireStateArgsHelpText = "SetFireState(units, newFireState)";
  constexpr const char* kUnitSetFireStateBindHelpText = "Set the specific fire state for the units passed in";
  constexpr const char* kUnitGetCommandQueueName = "GetCommandQueue";
  constexpr const char* kUnitGetCommandQueueHelpText = "Unit:GetCommandQueue()";
  constexpr const char* kUnitGetCommandQueueInvalidUnitError = "UnitScript:GetCommandQueue Passed in an invalid unit";
  constexpr const char* kUnitGetCommandQueueInvalidQueueError = "UnitScript:GetCommandQueue invalid UnitCommandQueue";
  constexpr const char* kUnitCanBuildHelpText = "CanBuild(self, blueprint";
  constexpr const char* kUnitCanBuildUnknownBlueprintError = "Unknown unit blueprint id: %s";
  constexpr const char* kUnitGetScriptBitHelpText = "GetScriptBit(units, bit)";
  constexpr const char* kUnitRecoilImpulseHelpText = "RecoilImpulse(self, x, y, z)";
  constexpr const char* kUnitCanPathToRectName = "CanPathToRect";
  constexpr const char* kUnitCanPathToRectHelpText = "See if the unit can path to the goal rectangle";
  constexpr const char* kUnitGetCargoTransportOnlyText = "Unit:GetCargo only valid for transport units";
  constexpr const char* kUnitLuaClassName = "Unit";
  constexpr const char* kGlobalLuaClassName = "<global>";

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] std::int32_t RoundGridCoordDown(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  [[nodiscard]] std::int32_t RoundGridCoordUp(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::ceil(value));
  }

  [[nodiscard]] Wm3::Vector3f& InvalidNavigatorTargetLane() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalidTarget{};

    if (!initialized) {
      invalidTarget = Wm3::Vector3f::NaN();
      initialized = true;
    }

    return invalidTarget;
  }

  using NavigatorCanPathToRectVFunc =
    bool(__thiscall*)(moho::IAiNavigator* navigator, const moho::SAiNavigatorGoal* goal, Wm3::Vector3f* outTargetPos);

  [[nodiscard]] bool InvokeNavigatorCanPathToRect(
    moho::IAiNavigator* const navigator,
    const moho::SAiNavigatorGoal& goal,
    Wm3::Vector3f* const outTargetPos
  )
  {
    // FUN_006CBD70 dispatches slot 15 with an additional out-target vector lane.
    // Keep this localized ABI shim until IAiNavigator slot typing is fully lifted.
    auto** const vtable = *reinterpret_cast<void***>(navigator);
    const auto method = reinterpret_cast<NavigatorCanPathToRectVFunc>(vtable[15]);
    return method(navigator, &goal, outTargetPos);
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

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "user") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("user");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RType* CachedUnitRType()
  {
    static gpg::RType* unitType = nullptr;
    if (unitType == nullptr) {
      unitType = gpg::LookupRType(typeid(Unit));
    }
    return unitType;
  }

  /**
   * Address: 0x00593970 (FUN_00593970, func_GetUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `Unit*` without throwing Lua conversion errors.
   */
  [[nodiscard]] Unit* GetUnitOptional(const LuaPlus::LuaObject& unitObject)
  {
    CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(unitObject);
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = scriptObject->GetDerivedObjectRef();
    const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, CachedUnitRType());
    return static_cast<Unit*>(unitRef.mObj);
  }

  [[nodiscard]] Unit* ResolveUnitBridge(UserUnit* const userUnit) noexcept
  {
    return userUnit ? reinterpret_cast<Unit*>(userUnit->mIUnitAndScriptBridge) : nullptr;
  }

  struct UnitAttributesBuildRestrictionRuntimeView
  {
    std::uint8_t mUnresolved00[0x08];
    CategoryWordRangeView mBuildRestrictionCategorySet; // +0x08
  };
  static_assert(
    offsetof(UnitAttributesBuildRestrictionRuntimeView, mBuildRestrictionCategorySet) == 0x08,
    "UnitAttributesBuildRestrictionRuntimeView::mBuildRestrictionCategorySet offset must be 0x08"
  );
  static_assert(sizeof(UnitAttributesBuildRestrictionRuntimeView) == 0x30, "UnitAttributes view size must be 0x30");

  struct CArmyBuildCategoryFilterRuntimeView
  {
    std::uint8_t mUnresolved00[0x198];
    CategoryWordRangeView mBuildCategoryFilterSet; // +0x198
  };
  static_assert(
    offsetof(CArmyBuildCategoryFilterRuntimeView, mBuildCategoryFilterSet) == 0x198,
    "CArmyBuildCategoryFilterRuntimeView::mBuildCategoryFilterSet offset must be 0x198"
  );

  static_assert(
    sizeof(RUnitBlueprintEconomyCategoryCache) == sizeof(CategoryWordRangeView),
    "RUnitBlueprintEconomyCategoryCache layout must match CategoryWordRangeView size"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, RuntimeWord08) == offsetof(CategoryWordRangeView, mStartWordIndex),
    "RUnitBlueprintEconomyCategoryCache::RuntimeWord08 offset must match CategoryWordRangeView::mStartWordIndex"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, First) == offsetof(CategoryWordRangeView, mWordsBegin),
    "RUnitBlueprintEconomyCategoryCache::First offset must match CategoryWordRangeView::mWordsBegin"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, Last) == offsetof(CategoryWordRangeView, mWordsEnd),
    "RUnitBlueprintEconomyCategoryCache::Last offset must match CategoryWordRangeView::mWordsEnd"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, End) == offsetof(CategoryWordRangeView, mWordsCapacityEnd),
    "RUnitBlueprintEconomyCategoryCache::End offset must match CategoryWordRangeView::mWordsCapacityEnd"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, InlineStoragePtr) == offsetof(CategoryWordRangeView, mWordsInlineBase),
    "RUnitBlueprintEconomyCategoryCache::InlineStoragePtr offset must match CategoryWordRangeView::mWordsInlineBase"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, InlineStorage) == offsetof(CategoryWordRangeView, mWordsInlineStorage),
    "RUnitBlueprintEconomyCategoryCache::InlineStorage offset must match CategoryWordRangeView::mWordsInlineStorage"
  );

  [[nodiscard]] const CategoryWordRangeView&
  AsCategoryWordRange(const RUnitBlueprintEconomyCategoryCache& categoryCache) noexcept
  {
    return reinterpret_cast<const CategoryWordRangeView&>(categoryCache);
  }

  [[nodiscard]] std::int32_t PickUniformIndexFromU32(const std::uint32_t randomValue, const std::uint32_t count) noexcept
  {
    const std::uint64_t product = static_cast<std::uint64_t>(randomValue) * static_cast<std::uint64_t>(count);
    return static_cast<std::int32_t>(product >> 32u);
  }

  [[nodiscard]] bool HasFootprintFlag(const EFootprintFlags value, const EFootprintFlags flag) noexcept
  {
    return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(flag)) != 0u;
  }

  [[nodiscard]] Wm3::Vector3f ForwardXZ(const Unit& unit) noexcept
  {
    Wm3::Vector3f forward = unit.GetTransform().orient_.Rotate({0.0f, 0.0f, 1.0f});
    forward.y = 0.0f;
    return Wm3::Vector3f::NormalizeOrZero(forward);
  }

  struct CollisionDBRect
  {
    std::uint16_t xPos;
    std::uint16_t zPos;
    std::uint16_t xSize;
    std::uint16_t zSize;
  };

  [[nodiscard]] CollisionDBRect COORDS_OgridRectToCollisionRect(const gpg::Rect2i& ogridRect) noexcept
  {
    // Address: 0x004FCAA0 (FUN_004FCAA0)
    const std::int32_t xPos = std::clamp(ogridRect.x0 >> 2, 0, 0xFFFF);
    const std::int32_t zPos = std::clamp(ogridRect.z0 >> 2, 0, 0xFFFF);
    const std::int32_t xEnd = (ogridRect.x1 + 3) >> 2;
    const std::int32_t zEnd = (ogridRect.z1 + 3) >> 2;

    CollisionDBRect collisionRect{};
    collisionRect.xPos = static_cast<std::uint16_t>(xPos);
    collisionRect.zPos = static_cast<std::uint16_t>(zPos);

    const std::int32_t maxXSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.xPos);
    const std::int32_t maxZSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.zPos);
    const std::int32_t xSpan =
      std::clamp(xEnd - static_cast<std::int32_t>(collisionRect.xPos), std::int32_t{1}, maxXSpan);
    const std::int32_t zSpan =
      std::clamp(zEnd - static_cast<std::int32_t>(collisionRect.zPos), std::int32_t{1}, maxZSpan);

    collisionRect.xSize = static_cast<std::uint16_t>(xSpan);
    collisionRect.zSize = static_cast<std::uint16_t>(zSpan);
    return collisionRect;
  }

  [[nodiscard]] bool IsCollisionRectEquivalentToZero(const gpg::Rect2i& ogridRect) noexcept
  {
    const gpg::Rect2i zeroRect{};
    const CollisionDBRect currentCollisionRect = COORDS_OgridRectToCollisionRect(ogridRect);
    const CollisionDBRect zeroCollisionRect = COORDS_OgridRectToCollisionRect(zeroRect);
    return currentCollisionRect.xPos == zeroCollisionRect.xPos &&
      currentCollisionRect.zPos == zeroCollisionRect.zPos &&
      currentCollisionRect.xSize == zeroCollisionRect.xSize &&
      currentCollisionRect.zSize == zeroCollisionRect.zSize;
  }

  [[nodiscard]] gpg::Rect2i GetReservedOgridRect(const Unit& unit) noexcept
  {
    return {
      unit.ReservedOgridRectMinX,
      unit.ReservedOgridRectMinZ,
      unit.ReservedOgridRectMaxX,
      unit.ReservedOgridRectMaxZ,
    };
  }

  void FillReservedOgridRect(Unit& unit, const bool occupied) noexcept
  {
    if (!unit.SimulationRef || !unit.SimulationRef->mOGrid) {
      return;
    }

    const gpg::Rect2i ogridRect = GetReservedOgridRect(unit);
    unit.SimulationRef->mOGrid->mOccupation.FillRect(
      ogridRect.x0,
      ogridRect.z0,
      ogridRect.x1 - ogridRect.x0,
      ogridRect.z1 - ogridRect.z0,
      occupied
    );
  }

  void DrawRaisedPlatformEdge(
    CDebugCanvas& canvas,
    const Wm3::Vector3f& a,
    const Wm3::Vector3f& b
  )
  {
    SDebugLine line{};
    line.p0 = a;
    line.p1 = b;
    line.depth0 = -16711936;
    line.depth1 = -16711936;
    canvas.DebugDrawLine(line);
  }

  /**
   * Address: 0x0062EAC0 (FUN_0062EAC0, func_UnitMoreInLineToOther)
   */
  [[nodiscard]] const Unit* UnitMoreInLineToOther(const Unit* const a1, const Unit* const a2) noexcept
  {
    if (!a1 || !a2) {
      return nullptr;
    }

    const Wm3::Vector3f a2Forward = ForwardXZ(*a2);
    const Wm3::Vector3f a1Forward = ForwardXZ(*a1);
    const Wm3::Vector3f a2ToA1 = Wm3::Vector3f::NormalizeOrZero(a1->GetPosition() - a2->GetPosition());
    const Wm3::Vector3f a1ToA2 = Wm3::Vector3f::NormalizeOrZero(a2->GetPosition() - a1->GetPosition());

    const float a2Alignment = Wm3::Vector3f::Dot(a2ToA1, a2Forward);
    const float a1Alignment = Wm3::Vector3f::Dot(a1ToA2, a1Forward);
    if (a2Alignment <= 0.0f && a1Alignment <= 0.0f) {
      return nullptr;
    }
    return (a2Alignment <= a1Alignment) ? a2 : a1;
  }

  class ExtraDataPairBuffer
  {
  public:
    explicit ExtraDataPairBuffer(SExtraUnitData* out) noexcept
      : out_(out)
    {}

    [[nodiscard]] SExtraUnitDataPair* begin() const noexcept
    {
      return out_ ? out_->pairsBegin : nullptr;
    }

    [[nodiscard]] SExtraUnitDataPair* end() const noexcept
    {
      return out_ ? out_->pairsEnd : nullptr;
    }

    [[nodiscard]] bool push_back(const SExtraUnitDataPair& pair) noexcept
    {
      if (!out_) {
        return false;
      }

      if (out_->pairsEnd == out_->pairsCapacityEnd) {
        const std::size_t nextCount = count() + 1u;
        if (!reserve(nextCount)) {
          return false;
        }
      }

      *out_->pairsEnd++ = pair;
      return true;
    }

  private:
    [[nodiscard]] std::size_t count() const noexcept
    {
      if (!out_ || !out_->pairsBegin || !out_->pairsEnd) {
        return 0u;
      }
      return static_cast<std::size_t>(out_->pairsEnd - out_->pairsBegin);
    }

    [[nodiscard]] std::size_t capacity() const noexcept
    {
      if (!out_ || !out_->pairsBegin || !out_->pairsCapacityEnd) {
        return 0u;
      }
      return static_cast<std::size_t>(out_->pairsCapacityEnd - out_->pairsBegin);
    }

    [[nodiscard]] bool reserve(const std::size_t requiredCapacity) noexcept
    {
      const std::size_t oldCapacity = capacity();
      if (oldCapacity >= requiredCapacity) {
        return true;
      }

      std::size_t newCapacity = oldCapacity == 0u ? 4u : oldCapacity;
      while (newCapacity < requiredCapacity) {
        newCapacity *= 2u;
      }

      const std::size_t oldCount = count();
      auto* const newStorage =
        static_cast<SExtraUnitDataPair*>(::operator new(newCapacity * sizeof(SExtraUnitDataPair), std::nothrow));
      if (!newStorage) {
        return false;
      }

      if (oldCount != 0u) {
        std::copy_n(out_->pairsBegin, oldCount, newStorage);
      }

      auto* const oldStorage = out_->pairsBegin;
      auto* const inlineStorage = out_->pairsInlineBegin ? out_->pairsInlineBegin : &out_->inlinePair;
      if (oldStorage && oldStorage != inlineStorage) {
        ::operator delete(oldStorage);
      }
      out_->pairsBegin = newStorage;
      out_->pairsEnd = newStorage + oldCount;
      out_->pairsCapacityEnd = newStorage + newCapacity;
      return true;
    }

  private:
    SExtraUnitData* out_;
  };
} // namespace

CScrLuaMetatableFactory<Unit> CScrLuaMetatableFactory<Unit>::sInstance{};

CScrLuaMetatableFactory<Unit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<Unit>& CScrLuaMetatableFactory<Unit>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject CScrLuaMetatableFactory<Unit>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x006C3E00 (FUN_006C3E00, cfunc_UnitGetCargoL)
 *
 * What it does:
 * Returns a Lua array containing script objects for all units currently loaded
 * by this transport unit.
 */
int moho::cfunc_UnitGetCargoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetCargoHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  IAiTransport* const transport = unit->AiTransport;
  if (transport == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCargoTransportOnlyText);
  }

  EntitySetTemplate<Unit> loadedUnits = transport->TransportGetLoadedUnits(false);

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0);

  int resultIndex = 1;
  for (Entity* const* it = loadedUnits.begin(); it != loadedUnits.end(); ++it, ++resultIndex) {
    Unit* const cargoUnit = static_cast<Unit*>(*it);
    LuaPlus::LuaObject cargoObject = cargoUnit->GetLuaObject();
    resultTable.Insert(resultIndex, cargoObject);
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x006C3D80 (FUN_006C3D80, cfunc_UnitGetCargo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetCargoL`.
 */
int moho::cfunc_UnitGetCargo(lua_State* const luaContext)
{
  return cfunc_UnitGetCargoL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3DA0 (FUN_006C3DA0, func_UnitGetCargo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCargo()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCargo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetCargoName,
    &moho::cfunc_UnitGetCargo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCargoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4FE0 (FUN_006C4FE0, cfunc_UnitEnableManipulatorsL)
 *
 * What it does:
 * Enables/disables one manipulator lane on a unit by bone index or bone name.
 */
int moho::cfunc_UnitEnableManipulatorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitEnableManipulatorsHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject enabledArg(state, 3);
  const bool enabled = enabledArg.GetBoolean();

  if (lua_type(rawState, 2) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    unit->AniActor->EnableBoneIndex(enabled, boneIndex);
    return 0;
  }

  const LuaPlus::LuaStackObject boneNameArg(state, 2);
  const char* boneName = lua_tostring(rawState, 2);
  if (boneName == nullptr) {
    boneNameArg.TypeError("string");
    boneName = "";
  }

  unit->AniActor->EnableBoneString(boneName, enabled);
  return 0;
}

/**
 * Address: 0x006C4F60 (FUN_006C4F60, cfunc_UnitEnableManipulators)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitEnableManipulatorsL`.
 */
int moho::cfunc_UnitEnableManipulators(lua_State* const luaContext)
{
  return cfunc_UnitEnableManipulatorsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4F80 (FUN_006C4F80, func_UnitEnableManipulators_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:EnableManipulators(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitEnableManipulators_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitEnableManipulatorsName,
    &moho::cfunc_UnitEnableManipulators,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitEnableManipulatorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C52E0 (FUN_006C52E0, cfunc_UnitKillManipulators)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitKillManipulatorsL`.
 */
int moho::cfunc_UnitKillManipulators(lua_State* const luaContext)
{
  return cfunc_UnitKillManipulatorsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5300 (FUN_006C5300, func_UnitKillManipulators_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:KillManipulators([boneName|boneIndex])` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitKillManipulators_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitKillManipulatorsName,
    &moho::cfunc_UnitKillManipulators,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitKillManipulatorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5360 (FUN_006C5360, cfunc_UnitKillManipulatorsL)
 *
 * What it does:
 * Kills each unit manipulator that matches arg #2 by bone index (`number`) or
 * bone name wildcard (`string`).
 */
int moho::cfunc_UnitKillManipulatorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitKillManipulatorsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (lua_type(rawState, 2) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    unit->AniActor->KillManipulatorByBoneIndex(boneIndex);
    return 0;
  }

  const LuaPlus::LuaStackObject boneNameArg(state, 2);
  const char* const boneName = lua_tostring(rawState, 2);
  if (boneName == nullptr) {
    boneNameArg.TypeError("string");
  }

  unit->AniActor->KillManipulatorsByBonePattern(boneName);
  return 0;
}

/**
 * Address: 0x008BBA10 (FUN_008BBA10, cfunc_SetFireStateL)
 *
 * What it does:
 * Applies one fire-state string command to each live unit in the input table.
 */
int moho::cfunc_UnitSetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetFireStateArgsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (!unitsObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitsObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    Unit* const unit = ResolveUnitBridge(userUnit);
    if (unit == nullptr || unit->IsDead()) {
      continue;
    }

    const LuaPlus::LuaStackObject fireStateArg(state, 2);
    const char* fireStateValue = lua_tostring(rawState, 2);
    if (fireStateValue == nullptr) {
      fireStateArg.TypeError("string");
      fireStateValue = "";
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      activeDriver->ProcessInfoPair(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(unit->GetEntityId())),
        kUnitSetFireStateName,
        fireStateValue
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BB990 (FUN_008BB990, cfunc_SetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFireStateL`.
 */
int moho::cfunc_UnitSetFireState(lua_State* const luaContext)
{
  return cfunc_UnitSetFireStateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB9B0 (FUN_008BB9B0, func_SetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `SetFireState(units, newFireState)`.
 */
CScrLuaInitForm* moho::func_UnitSetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUnitSetFireStateName,
    &moho::cfunc_UnitSetFireState,
    nullptr,
    kGlobalLuaClassName,
    kUnitSetFireStateBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CE280 (FUN_006CE280, cfunc_UnitGetCommandQueueL)
 *
 * What it does:
 * Returns Lua array copy of one unit's current command queue.
 */
int moho::cfunc_UnitGetCommandQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetCommandQueueHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidUnitError);
    return 0;
  }

  CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  if (commandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidQueueError);
    return 0;
  }

  const msvc8::vector<WeakPtr<CUnitCommand>> commandSnapshot = commandQueue->mCommandVec;

  LuaPlus::LuaObject queueArray{};
  const int commandCount = static_cast<int>(commandSnapshot.size());
  queueArray.AssignNewTable(state, commandCount, 0u);
  for (const WeakPtr<CUnitCommand>& commandWeakPtr : commandSnapshot) {
    CUnitCommand* const command = commandWeakPtr.GetObject();
    if (command == nullptr) {
      continue;
    }

    SimGetCommandQueueInsert(queueArray, *command);
  }

  queueArray.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CE200 (FUN_006CE200, cfunc_UnitGetCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetCommandQueueL`.
 */
int moho::cfunc_UnitGetCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitGetCommandQueueL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CE220 (FUN_006CE220, func_UnitGetCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCommandQueue()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetCommandQueueName,
    &moho::cfunc_UnitGetCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBC10 (FUN_008BBC10, cfunc_GetScriptBitL)
 *
 * What it does:
 * Returns true if any non-dead user unit in the input table supports `bit`
 * via toggle caps and currently has that script bit set.
 */
int moho::cfunc_GetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetScriptBitHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  const LuaPlus::LuaStackObject bitArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    bitArg.TypeError("integer");
  }
  const int bitIndex = static_cast<int>(lua_tonumber(rawState, 2));

  bool hasBitSet = false;
  if (unitsObject.IsTable()) {
    const int count = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= count; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      Unit* const unit = ResolveUnitBridge(userUnit);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      const std::uint32_t toggleMask = 1u << (static_cast<std::uint32_t>(bitIndex) & 0x1Fu);
      if ((unit->GetAttributes().toggleCapsMask & toggleMask) == 0u) {
        continue;
      }

      const std::uint32_t bitShift = static_cast<std::uint32_t>(bitIndex);
      const std::int64_t scriptBits = static_cast<std::int64_t>(static_cast<std::int32_t>(unit->ScriptBitMask));
      const std::int64_t scriptBitMask = bitShift < 64u ? static_cast<std::int64_t>(1ull << bitShift) : 0;
      if ((scriptBits & scriptBitMask) != 0) {
        hasBitSet = true;
        break;
      }
    }
  }

  lua_pushboolean(rawState, hasBitSet ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0460 (FUN_006D0460, cfunc_UnitCanBuildL)
 *
 * What it does:
 * Resolves one unit and one blueprint id string, then returns whether the
 * unit can build that blueprint according to `Unit::CanBuild`.
 */
int moho::cfunc_UnitCanBuildL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitCanBuildHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject blueprintArg(state, 2);
  const char* blueprintText = lua_tostring(rawState, 2);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }

  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);

  RUnitBlueprint* blueprint = nullptr;
  if (unit && unit->SimulationRef && unit->SimulationRef->mRules) {
    blueprint = unit->SimulationRef->mRules->GetUnitBlueprint(blueprintId);
  }

  if (!blueprint) {
    LuaPlus::LuaState::Error(state, kUnitCanBuildUnknownBlueprintError, blueprintText);
  }

  const bool canBuild = unit->CanBuild(blueprint);
  lua_pushboolean(rawState, canBuild ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CB600 (FUN_006CB600, cfunc_UnitRecoilImpulseL)
 *
 * What it does:
 * Applies one recoil impulse vector `(x,y,z)` to the target unit motion lane.
 */
int moho::cfunc_UnitRecoilImpulseL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRecoilImpulseHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }
  const float impulseX = static_cast<float>(lua_tonumber(rawState, 2));

  const LuaPlus::LuaStackObject yArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    yArg.TypeError("number");
  }
  const float impulseY = static_cast<float>(lua_tonumber(rawState, 3));

  const LuaPlus::LuaStackObject zArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }
  const float impulseZ = static_cast<float>(lua_tonumber(rawState, 4));

  const Wm3::Vector3f impulse{impulseX, impulseY, impulseZ};
  if (CUnitMotion* const motion = unit->UnitMotion; motion != nullptr) {
    motion->AddRecoilImpulse(impulse);
  }

  return 0;
}

/**
 * Address: 0x006CBD70 (FUN_006CBD70, cfunc_UnitCanPathToRectL)
 *
 * What it does:
 * Resolves one unit plus two world-space rectangle corners, queries navigator
 * pathability to that rectangle, then returns `(canPath, targetPos)` to Lua.
 */
int moho::cfunc_UnitCanPathToRectL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitCanPathToRectHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject minCornerObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f minCorner = SCR_FromLuaCopy<Wm3::Vector3f>(minCornerObject);

  const LuaPlus::LuaObject maxCornerObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vector3f maxCorner = SCR_FromLuaCopy<Wm3::Vector3f>(maxCornerObject);

  SAiNavigatorGoal goal{};
  goal.minX = RoundGridCoordDown(minCorner.x);
  goal.minZ = RoundGridCoordDown(minCorner.z);
  goal.maxX = RoundGridCoordUp(maxCorner.x);
  goal.maxZ = RoundGridCoordUp(maxCorner.z);

  Wm3::Vector3f targetPos = InvalidNavigatorTargetLane();
  const bool canPath = InvokeNavigatorCanPathToRect(unit->AiNavigator, goal, &targetPos);

  lua_pushboolean(rawState, canPath ? 1 : 0);
  (void)lua_gettop(rawState);

  LuaPlus::LuaObject targetPosObject = SCR_ToLua<Wm3::Vector3f>(state, targetPos);
  targetPosObject.PushStack(state);
  return 2;
}

/**
 * Address: 0x006CBCF0 (FUN_006CBCF0, cfunc_UnitCanPathToRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanPathToRectL`.
 */
int moho::cfunc_UnitCanPathToRect(lua_State* const luaContext)
{
  return cfunc_UnitCanPathToRectL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CBD10 (FUN_006CBD10, func_UnitCanPathToRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:CanPathToRect(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanPathToRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitCanPathToRectName,
    &moho::cfunc_UnitCanPathToRect,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanPathToRectHelpText
  );
  return &binder;
}

void SBeatResourceAccumulators::Clear() noexcept
{
  maintenanceEnergy = 0.0f;
  maintenanceMass = 0.0f;
  resourcesSpentEnergy = 0.0f;
  resourcesSpentMass = 0.0f;
}

bool Unit::NeedsKillCleanup() const noexcept
{
  return mNeedsKillCleanup;
}

void Unit::ClearBeatResourceAccumulators() noexcept
{
  mBeatResourceAccumulators.Clear();
}

CIntel* Unit::GetIntelManager() noexcept
{
  return mIntelManager;
}

CIntel const* Unit::GetIntelManager() const noexcept
{
  return mIntelManager;
}

SSTIUnitVariableData& Unit::VarDat() noexcept
{
  return *reinterpret_cast<SSTIUnitVariableData*>(mVarDatHead);
}

SSTIUnitVariableData const& Unit::VarDat() const noexcept
{
  return *reinterpret_cast<SSTIUnitVariableData const*>(mVarDatHead);
}

// 0x006A4BC0
Unit const* Unit::IsUnit() const
{
  return this;
}

// 0x006A4BB0
Unit* Unit::IsUnit()
{
  return this;
}

// 0x006A48E0
UserUnit const* Unit::IsUserUnit() const
{
  return nullptr;
}

// 0x006A48D0
UserUnit* Unit::IsUserUnit()
{
  return nullptr;
}

// 0x006A49A0
EntId Unit::GetEntityId() const
{
  return id_;
}

// 0x006A49B0
Wm3::Vec3f const& Unit::GetPosition() const
{
  return GetPositionWm3();
}

// 0x006A49C0
VTransform const& Unit::GetTransform() const
{
  return GetTransformWm3();
}

// 0x006A8B20
RUnitBlueprint const* Unit::GetBlueprint() const
{
  const REntityBlueprint* const blueprint = BluePrint;
  return blueprint ? blueprint->IsUnitBlueprint() : nullptr;
}

/**
 * Address: 0x006AAF50 (?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks a random index in `Blueprint->AI.TargetBones`; writes `-1` when
 * the list is empty. Returns true on all paths.
 */
bool Unit::PickTargetPoint(std::int32_t& outTargetPoint) const
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  const std::uint32_t targetBoneCount =
    (blueprint != nullptr) ? static_cast<std::uint32_t>(blueprint->AI.TargetBones.size()) : 0u;

  if (targetBoneCount == 0u || !SimulationRef || !SimulationRef->mRngState) {
    outTargetPoint = -1;
    return true;
  }

  const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
  outTargetPoint = PickUniformIndexFromU32(randomValue, targetBoneCount);
  return true;
}

/**
 * Address: 0x006A9E50 (FUN_006A9E50, ?CanBuild@Unit@Moho@@QBE_NPBVRUnitBlueprint@2@@Z)
 *
 * What it does:
 * Tests whether `blueprint` is present in this unit's effective build
 * category set after army and per-unit build restrictions are applied.
 */
bool Unit::CanBuild(const RUnitBlueprint* const blueprint) const
{
  const auto& armyBuildCategories =
    reinterpret_cast<const CArmyBuildCategoryFilterRuntimeView&>(*ArmyRef).mBuildCategoryFilterSet;
  const CategoryWordRangeView& unitBlueprintBuildCategories = AsCategoryWordRange(GetBlueprint()->Economy.CategoryCache);
  const auto& unitBuildRestrictions = reinterpret_cast<const UnitAttributesBuildRestrictionRuntimeView&>(GetAttributes())
                                        .mBuildRestrictionCategorySet;

  const std::uint32_t categoryBitIndex = blueprint->mCategoryBitIndex;
  return armyBuildCategories.ContainsBit(categoryBitIndex) &&
    unitBlueprintBuildCategories.ContainsBit(categoryBitIndex) &&
    !unitBuildRestrictions.ContainsBit(categoryBitIndex);
}

// 0x006A49D0
LuaPlus::LuaObject Unit::GetLuaObject()
{
  return mLuaObj;
}

// 0x006A8B30
float Unit::CalcTransportLoadFactor() const
{
  return 1.0f;
}

// 0x006A49F0
bool Unit::IsDead() const
{
  return Dead != 0;
}

// 0x006A4A00
bool Unit::DestroyQueued() const
{
  return DestroyQueuedFlag != 0;
}

// 0x006A4A10
bool Unit::IsMobile() const
{
  return UnitMotion != nullptr;
}

// 0x006A4A20
bool Unit::IsBeingBuilt() const
{
  return BeingBuilt != 0;
}

// 0x006A7DC0
bool Unit::IsNavigatorIdle() const
{
  return !AiNavigator || AiNavigator->GetStatus() == 0;
}

// 0x006A4AF0
bool Unit::IsUnitState(const EUnitState state) const
{
  const std::uint32_t bit = static_cast<std::uint32_t>(state);
  if (bit >= 64u) {
    return false;
  }
  return (UnitStateMask & (1ull << bit)) != 0ull;
}

/**
 * Address: 0x0059A430 (FUN_0059A430, ?GetGuardedUnit@Unit@Moho@@QBEPAV12@XZ)
 */
Unit* Unit::GetGuardedUnit() const
{
  return GuardedUnitRef.ResolveObjectPtr<Unit>();
}

/**
 * Address: 0x0062EE00 (FUN_0062EE00, Moho::Unit::GetStagingPlatform)
 */
Unit* Unit::GetStagingPlatform() const
{
  Unit* const transport = TransportedByRef.ResolveObjectPtr<Unit>();
  if (transport == nullptr) {
    return nullptr;
  }

  if (transport->IsDead()) {
    return nullptr;
  }

  IAiTransport* const aiTransport = transport->AiTransport;
  if (aiTransport == nullptr || !aiTransport->TransportIsAirStagingPlatform()) {
    return nullptr;
  }

  return transport;
}

/**
 * Address: 0x006A8D80 (FUN_006A8D80, ?IsHigherPriorityThan@Unit@Moho@@QBE_NPBV12@@Z)
 */
bool Unit::IsHigherPriorityThan(const Unit* const other) const
{
  if (!other) {
    return true;
  }

  if (IsUnitState(UNITSTATE_Immobile) || IsUnitState(UNITSTATE_Upgrading)) {
    return true;
  }
  if (other->IsUnitState(UNITSTATE_Immobile) || other->IsUnitState(UNITSTATE_Upgrading)) {
    return false;
  }

  if (mIsNaval) {
    if (!other->mIsNaval) {
      return true;
    }
  } else if (other->mIsNaval) {
    return false;
  }

  const bool thisIgnoreStructures = HasFootprintFlag(GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  const bool otherIgnoreStructures =
    HasFootprintFlag(other->GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  if (thisIgnoreStructures) {
    if (!otherIgnoreStructures) {
      return true;
    }
  } else if (otherIgnoreStructures) {
    return false;
  }

  if (const RUnitBlueprint* const blueprint = GetBlueprint()) {
    if (blueprint->Air.CanFly && mCurrentLayer != LAYER_Air) {
      return true;
    }
  }
  if (const RUnitBlueprint* const blueprint = other->GetBlueprint()) {
    if (blueprint->Air.CanFly && other->mCurrentLayer != LAYER_Air) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_WaitingForTransport) && !other->IsUnitState(UNITSTATE_WaitingForTransport)) {
    return true;
  }

  if (GetGuardedUnit() == other) {
    return false;
  }
  if (other->GetGuardedUnit() == this) {
    return true;
  }

  bool inSharedFormation = false;
  if (mInfoCache.mFormationLayer && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer) {
    inSharedFormation = true;

    const Unit* const formationLead = mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
    if (formationLead == this) {
      return true;
    }
    if (formationLead == other) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_Moving) && !other->IsUnitState(UNITSTATE_Moving)) {
    return false;
  }
  if (!IsUnitState(UNITSTATE_Moving) && other->IsUnitState(UNITSTATE_Moving)) {
    return true;
  }

  if (inSharedFormation) {
    if (mInfoCache.mFormationPriorityOrder != other->mInfoCache.mFormationPriorityOrder) {
      return mInfoCache.mFormationPriorityOrder < other->mInfoCache.mFormationPriorityOrder;
    }
    return other->mInfoCache.mFormationDistanceMetric > mInfoCache.mFormationDistanceMetric;
  }

  const SFootprint& thisFootprint = GetFootprint();
  const SFootprint& otherFootprint = other->GetFootprint();
  const std::uint8_t thisFootprintSize = std::max(thisFootprint.mSizeX, thisFootprint.mSizeZ);
  const std::uint8_t otherFootprintSize = std::max(otherFootprint.mSizeX, otherFootprint.mSizeZ);
  if (thisFootprintSize > otherFootprintSize) {
    return true;
  }
  if (thisFootprintSize != otherFootprintSize) {
    return false;
  }

  if (const Unit* const moreInLine = UnitMoreInLineToOther(other, this)) {
    return moreInLine == this;
  }

  return static_cast<std::uint32_t>(GetEntityId()) < static_cast<std::uint32_t>(other->GetEntityId());
}

/**
 * Address: 0x006AB6F0 (FUN_006AB6F0, ?ReserveOgridRect@Unit@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
 */
void Unit::ReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  FreeOgridRect();

  ReservedOgridRectMinX = ogridRect.x0;
  ReservedOgridRectMinZ = ogridRect.z0;
  ReservedOgridRectMaxX = ogridRect.x1;
  ReservedOgridRectMaxZ = ogridRect.z1;

  FillReservedOgridRect(*this, true);
}

/**
 * Address: 0x006AB760 (FUN_006AB760, ?FreeOgridRect@Unit@Moho@@QAEXXZ)
 */
void Unit::FreeOgridRect()
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  if (!IsCollisionRectEquivalentToZero(reservedRect)) {
    FillReservedOgridRect(*this, false);
  }

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;
}

/**
 * Address: 0x006AB810 (FUN_006AB810, ?CanReserveOgridRect@Unit@Moho@@QAE_NABV?$Rect2@H@gpg@@@Z)
 */
bool Unit::CanReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  const bool hadReservation = !IsCollisionRectEquivalentToZero(reservedRect);
  if (hadReservation) {
    FillReservedOgridRect(*this, false);
  }

  bool canReserve = true;
  if (SimulationRef && SimulationRef->mOGrid) {
    canReserve = !SimulationRef->mOGrid->mOccupation.GetRectOr(
      ogridRect.x0,
      ogridRect.z0,
      ogridRect.x1 - ogridRect.x0,
      ogridRect.z1 - ogridRect.z0,
      true
    );
  }

  if (hadReservation) {
    FillReservedOgridRect(*this, true);
  }

  return canReserve;
}

// 0x006A4990
UnitAttributes& Unit::GetAttributes()
{
  return Attributes;
}

// 0x006A4980
UnitAttributes const& Unit::GetAttributes() const
{
  return Attributes;
}

// 0x006A4B90
StatItem* Unit::GetStat(gpg::StrArg name, const std::string&)
{
  return moho::ResolveStatString(mConstDat.mStatsRoot, name);
}

// 0x006A4B70
StatItem* Unit::GetStat(gpg::StrArg name, const float&)
{
  return moho::ResolveStatFloat(mConstDat.mStatsRoot, name);
}

// 0x006A4B50
StatItem* Unit::GetStat(gpg::StrArg name, const int&)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot, name, 1);
}

// 0x006A4B30
StatItem* Unit::GetStat(gpg::StrArg name)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot, name, 0);
}

// 0x006A73A0
void Unit::SetAutoMode(const bool enabled)
{
  AutoMode = enabled;
  CallbackStr(enabled ? "OnAutoModeOn" : "OnAutoModeOff");
}

// 0x006A73E0
void Unit::SetAutoSurfaceMode(const bool enabled)
{
  AutoSurfaceMode = enabled;
}

// 0x006A4A30
bool Unit::IsAutoMode() const
{
  return AutoMode;
}

// 0x006A4A40
bool Unit::IsAutoSurfaceMode() const
{
  return AutoSurfaceMode;
}

// 0x006A4A50
void Unit::SetCustomName(const std::string name)
{
  CustomName = name.c_str();
}

// 0x006A4AB0
std::string Unit::GetCustomName() const
{
  return std::string(CustomName.c_str(), CustomName.size());
}

// 0x006A8790
void Unit::KillCleanup()
{
  mNeedsKillCleanup = false;

  if (AiAttacker) {
    AiAttacker->WeaponsOnDestroy();
  }

  auto* commandDispatch = AiCommandDispatch;
  AiCommandDispatch = nullptr;
  delete commandDispatch;

  if (CommandQueue) {
    CommandQueue->MarkForUnitKillCleanup();
  }

  auto* attacker = AiAttacker;
  AiAttacker = nullptr;
  delete attacker;

  auto* transport = AiTransport;
  AiTransport = nullptr;
  delete transport;

  auto* navigator = AiNavigator;
  AiNavigator = nullptr;
  delete navigator;

  auto* steering = AiSteering;
  AiSteering = nullptr;
  delete steering;

  auto* builder = AiBuilder;
  AiBuilder = nullptr;
  delete builder;

  auto* siloBuild = AiSiloBuild;
  AiSiloBuild = nullptr;
  delete siloBuild;

  CUnitCommandQueue* queue = CommandQueue;
  CommandQueue = nullptr;
  if (queue) {
    queue->DestroyForUnitKillCleanup();
    ::operator delete(queue);
  }
}

/**
 * Address: 0x006ACB20 (FUN_006ACB20)
 *
 * What it does:
 * Appends unit-side sync extra-data records into the provided output buffer.
 */
void Unit::GetExtraData(SExtraUnitData* out) const
{
  if (!out) {
    return;
  }
  ExtraDataPairBuffer pairBuffer{out};

  if (AiAttacker) {
    const int count = AiAttacker->GetWeaponCount();
    for (int i = 0; i < count; ++i) {
      CAiAttackerImpl::WeaponExtraData weaponExtra{};
      if (!AiAttacker->TryGetWeaponExtraData(i, weaponExtra)) {
        continue;
      }

      SExtraUnitDataPair pair{};
      pair.key = weaponExtra.key;
      pair.value = CAiAttackerImpl::ReadExtraDataValue(weaponExtra.ref);
      (void)pairBuffer.push_back(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      (void)pairBuffer.push_back(pair);
    }
  }

  out->unitEntityId = id_;
}

// 0x006A73F0
void Unit::SetPaused(const bool paused)
{
  const UnitAttributes& attributes = GetAttributes();
  const bool canToggle =
    (attributes.commandCapsMask & kCommandCapPause) != 0u || (attributes.toggleCapsMask & kToggleCapGeneric) != 0u;
  if (!canToggle) {
    return;
  }

  if (paused) {
    if (!IsPaused) {
      CallbackStr("OnPaused");
    }
  } else if (IsPaused) {
    CallbackStr("OnUnpaused");
  }

  IsPaused = paused;
  MarkNeedsSyncGameData();
}

// 0x006A7450
void Unit::SetRepeatQueue(const bool enabled)
{
  if (enabled) {
    if (!RepeatQueueEnabled) {
      CallbackStr("OnStartRepeatQueue");
    }
  } else if (RepeatQueueEnabled) {
    CallbackStr("OnStopRepeatQueue");
  }

  RepeatQueueEnabled = enabled;
  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006AA900 (FUN_006AA900, ?SetConsumptionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Rebuilds unit upkeep request lanes for active/inactive economy
 * consumption and dispatches matching Lua script callbacks.
 */
void Unit::SetConsumptionActive(const bool isActive)
{
  const bool oldConsumptionIsActive = ConsumptionActive;
  ConsumptionActive = isActive;

  SEconValue newConsumption{};
  newConsumption.energy = Attributes.consumptionPerSecondEnergy * 0.1f;
  newConsumption.mass = Attributes.consumptionPerSecondMass * 0.1f;

  if (mConsumptionData == nullptr) {
    auto* const request = new CEconRequest{};
    request->mRequested = newConsumption;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;

    if (ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        request->mNode.ListLinkBefore(&economyInfo->registrationNode);
      }
    }

    if (mConsumptionData != nullptr) {
      mConsumptionData->mNode.ListUnlink();
      delete mConsumptionData;
    }
    mConsumptionData = request;
  }

  if (!ConsumptionActive) {
    if (mConsumptionData != nullptr && ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        economyInfo->economy.mStored.ENERGY += mConsumptionData->mGranted.energy;
        economyInfo->economy.mStored.MASS += mConsumptionData->mGranted.mass;
      }
    }

    newConsumption.energy = 0.0f;
    newConsumption.mass = 0.0f;
  }

  if (mConsumptionData != nullptr) {
    mConsumptionData->mRequested = newConsumption;
  }

  MaintainenceCostEnergy = newConsumption.energy;
  MaintainenceCostMass = newConsumption.mass;

  if (ConsumptionActive != oldConsumptionIsActive) {
    if (ConsumptionActive) {
      CallbackStr("OnConsumptionActive");
    } else {
      CallbackStr("OnConsumptionInActive");
    }
  }
}

/**
 * Address: 0x006AC530 (FUN_006AC530, ?ShowAIDebugInfo@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Resolves this unit's `AIDebug_<UniqueName>` stat path and clears it from
 * owning army stats.
 */
void Unit::ShowAIDebugInfo(const bool isEnabled)
{
  (void)isEnabled;

  if (ArmyRef == nullptr) {
    return;
  }

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const msvc8::string debugStatPath = msvc8::string("AIDebug_") + GetUniqueName();
  armyStats->Delete(debugStatPath.c_str());
}

/**
 * Address: 0x006AC600 (FUN_006AC600, ?DebugShowRaisedPlatforms@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * When `ShowRaisedPlatforms` sim-convar is enabled, draws one debug quad per
 * raised-platform blueprint polygon in world space.
 */
void Unit::DebugShowRaisedPlatforms()
{
  if (!SimulationRef) {
    return;
  }

  CSimConVarBase* const showRaisedPlatformsDef = GetShowRaisedPlatformsSimConVarDef();
  if (!showRaisedPlatformsDef) {
    return;
  }

  CSimConVarInstanceBase* const showRaisedPlatforms = SimulationRef->GetSimVar(showRaisedPlatformsDef);
  const void* const valueStorage = showRaisedPlatforms ? showRaisedPlatforms->GetValueStorage() : nullptr;
  if (!valueStorage || !*reinterpret_cast<const std::uint8_t*>(valueStorage)) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (!blueprint) {
    return;
  }

  CDebugCanvas* const debugCanvas = SimulationRef->GetDebugCanvas();
  if (!debugCanvas) {
    return;
  }

  const Wm3::Vector3f unitPos = GetPosition();
  for (const RUnitBlueprintRaisedPlatform& platform : blueprint->Physics.RaisedPlatforms) {
    const Wm3::Vector3f p0{
      unitPos.x + platform.Vertex0X,
      unitPos.y + platform.Vertex0Y,
      unitPos.z + platform.Vertex0Z,
    };
    const Wm3::Vector3f p1{
      unitPos.x + platform.Vertex1X,
      unitPos.y + platform.Vertex1Y,
      unitPos.z + platform.Vertex1Z,
    };
    const Wm3::Vector3f p2{
      unitPos.x + platform.Vertex2X,
      unitPos.y + platform.Vertex2Y,
      unitPos.z + platform.Vertex2Z,
    };
    const Wm3::Vector3f p3{
      unitPos.x + platform.Vertex3X,
      unitPos.y + platform.Vertex3Y,
      unitPos.z + platform.Vertex3Z,
    };

    DrawRaisedPlatformEdge(*debugCanvas, p0, p1);
    DrawRaisedPlatformEdge(*debugCanvas, p1, p3);
    DrawRaisedPlatformEdge(*debugCanvas, p3, p2);
    DrawRaisedPlatformEdge(*debugCanvas, p2, p0);
  }
}

// 0x006A7490
void Unit::ToggleScriptBit(const int bitIndex)
{
  const std::uint32_t shift = static_cast<std::uint32_t>(static_cast<std::uint8_t>(bitIndex)) & 0x1Fu;
  const std::uint32_t mask = 1u << shift;

  const UnitAttributes& attributes = GetAttributes();
  if ((attributes.toggleCapsMask & mask) == 0u) {
    return;
  }

  if (IsUnitState(kTransportScriptBitGuardState) && IsInCategory("TRANSPORTATION")) {
    return;
  }

  if ((ScriptBitMask & mask) != 0u) {
    ScriptBitMask &= ~mask;
    CallbackInt("OnScriptBitClear", bitIndex);
  } else {
    ScriptBitMask |= mask;
    CallbackInt("OnScriptBitSet", bitIndex);
  }

  MarkNeedsSyncGameData();
}

// 0x006A97C0
void Unit::SetFireState(const std::int32_t fireState)
{
  if (FireState == fireState) {
    return;
  }

  FireState = fireState;
  MarkNeedsSyncGameData();
}
