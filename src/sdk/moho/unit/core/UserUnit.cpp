// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/UserUnit.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/animation/CAniPose.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/Stats.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyLuaFunctionRegistrations.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/vision/VisionDB.h"

using namespace moho;

namespace moho
{
  template <>
  class CScrLuaMetatableFactory<UserUnit> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<UserUnit>) == 0x08, "CScrLuaMetatableFactory<UserUnit> size must be 0x08");
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgsRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kUserUnitCanAttackTargetName = "CanAttackTarget";
  constexpr const char* kUserUnitCanAttackTargetHelpText = "UserUnit:CanAttackTarget(target, rangeCheck)";
  constexpr const char* kUserUnitGetFootPrintSizeName = "GetFootPrintSize";
  constexpr const char* kUserUnitGetFootPrintSizeHelpText = "UserUnit:GetFootPrintSize()";
  constexpr const char* kUserUnitGetUnitIdName = "GetUnitId";
  constexpr const char* kUserUnitGetUnitIdHelpText = "UserUnit:GetUnitId()";
  constexpr const char* kUserUnitGetBlueprintName = "GetBlueprint";
  constexpr const char* kUserUnitGetBlueprintHelpText = "blueprint = UserUnit:GetBlueprint()";
  constexpr const char* kUserUnitIsAutoModeName = "IsAutoMode";
  constexpr const char* kUserUnitIsAutoModeHelpText = "bool = UserUnit:IsAutoMode()";
  constexpr const char* kUserUnitIsAutoSurfaceModeName = "IsAutoSurfaceMode";
  constexpr const char* kUserUnitIsAutoSurfaceModeHelpText = "bool = UserUnit:IsAutoSurfaceMode()";
  constexpr const char* kUserUnitIsRepeatQueueName = "IsRepeatQueue";
  constexpr const char* kUserUnitIsRepeatQueueHelpText = "bool = UserUnit:IsRepeatQueue()";
  constexpr const char* kUserUnitIsInCategoryName = "IsInCategory";
  constexpr const char* kUserUnitLuaClassName = "UserUnit";
  constexpr const char* kUserUnitIsInCategoryHelpText = "bool = UserUnit:IsInCategory(category)";
  constexpr const char* kUserUnitProcessInfoName = "ProcessInfo";
  constexpr const char* kUserUnitProcessInfoHelpText = "UserUnit:ProcessInfoPair()";
  constexpr const char* kUserUnitGetEntityIdName = "GetEntityId";
  constexpr const char* kUserUnitGetEntityIdHelpText = "Entity:GetEntityId()";
  constexpr const char* kUserUnitHasUnloadCommandQueuedUpName = "HasUnloadCommandQueuedUp";
  constexpr const char* kUserUnitHasUnloadCommandQueuedUpHelpText =
    "See if this unit already has an unload from transport queued up";
  constexpr const char* kUserUnitSetCustomNameName = "SetCustomName";
  constexpr const char* kUserUnitSetCustomNameHelpText = "SetCustomName(string) -- Set a custom name for the unit";
  constexpr const char* kUserUnitSetCustomNameInfoKey = "CustomName";
  constexpr const char* kUserUnitAddSelectionSetName = "AddSelectionSet";
  constexpr const char* kUserUnitAddSelectionSetHelpText = "AddSelectionSet(string) -- add a selection set name to a unit";
  constexpr const char* kUserUnitRemoveSelectionSetName = "RemoveSelectionSet";
  constexpr const char* kUserUnitRemoveSelectionSetHelpText =
    "RemoveSelectionSet(string) -- remove a selection set name from a unit";
  constexpr const char* kUserUnitGetSelectionSetsName = "GetSelectionSets";
  constexpr const char* kUserUnitGetSelectionSetsHelpText =
    "table GetSelectionSets() -- get table of all selection sets unit belongs to";
  constexpr const char* kUserUnitGetHealthName = "GetHealth";
  constexpr const char* kUserUnitGetHealthHelpText = "GetHealth() -- return current health";
  constexpr const char* kUserUnitGetMaxHealthName = "GetMaxHealth";
  constexpr const char* kUserUnitGetMaxHealthHelpText = "GetMaxHealth() -- return max health";
  constexpr const char* kUserUnitGetBuildRateName = "GetBuildRate";
  constexpr const char* kUserUnitGetBuildRateHelpText = "GetBuildRate() -- return current unit build rate";
  constexpr const char* kUserUnitIsOverchargePausedName = "IsOverchargePaused";
  constexpr const char* kUserUnitIsOverchargePausedHelpText =
    "IsOverchargePaused() -- return current overcharge paused status";
  constexpr const char* kUserUnitIsDeadName = "IsDead";
  constexpr const char* kUserUnitIsDeadHelpText = "IsDead() -- return true if the unit has been destroyed";
  constexpr const char* kUserUnitGetFuelRatioName = "GetFuelRatio";
  constexpr const char* kUserUnitGetFuelRatioHelpText = "GetFuelRatio()";
  constexpr const char* kUserUnitGetShieldRatioName = "GetShieldRatio";
  constexpr const char* kUserUnitGetShieldRatioHelpText = "GetShieldRatio()";
  constexpr const char* kUserUnitGetWorkProgressName = "GetWorkProgress";
  constexpr const char* kUserUnitGetWorkProgressHelpText = "GetWorkProgress()";
  constexpr const char* kUserUnitGetStatName = "GetStat";
  constexpr const char* kUserUnitGetStatHelpText = "GetStat(Name[,defaultVal])";
  constexpr const char* kUserUnitIsStunnedName = "IsStunned";
  constexpr const char* kUserUnitIsStunnedHelpText = "flag = UserUnit:IsStunned()";
  constexpr const char* kUserUnitGetCustomNameName = "GetCustomName";
  constexpr const char* kUserUnitGetCustomNameHelpText =
    "string GetCustomName() -- get the current custom name, nil if none";
  constexpr const char* kUserUnitHasSelectionSetName = "HasSelectionSet";
  constexpr const char* kUserUnitHasSelectionSetHelpText =
    "bool HasSelectionSet(string) -- see if a unit belongs to a given selection set";
  constexpr const char* kUserUnitIsIdleName = "IsIdle";
  constexpr const char* kUserUnitIsIdleHelpText = "IsIdle() -- return true if the unit is idle";
  constexpr const char* kUserUnitGetFocusName = "GetFocus";
  constexpr const char* kUserUnitGetFocusHelpText = "GetFocus() -- returns the unit this unit is currently focused on, or nil";
  constexpr const char* kUserUnitGetGuardedEntityName = "GetGuardedEntity";
  constexpr const char* kUserUnitGetGuardedEntityHelpText =
    "GetGuardedEntity() -- returns the units guard target, or nil";
  constexpr const char* kUserUnitGetCreatorName = "GetCreator";
  constexpr const char* kUserUnitGetCreatorHelpText = "GetCreator() -- returns the units creator, or nil";
  constexpr const char* kUserUnitGetPositionName = "GetPosition";
  constexpr const char* kUserUnitGetPositionHelpText = "VECTOR3 GetPosition() - returns the current world posititon of the unit";
  constexpr const char* kUserUnitGetArmyName = "GetArmy";
  constexpr const char* kUserUnitGetArmyHelpText = "GetArmy() -- returns the army index";
  constexpr const char* kUserUnitGetEconDataName = "GetEconData";
  constexpr const char* kUserUnitGetEconDataHelpText = "GetEconData() - returns a table of economy data";
  constexpr const char* kUserUnitGetCommandQueueName = "GetCommandQueue";
  constexpr const char* kUserUnitGetCommandQueueHelpText = "table GetCommandQueue() - returns table of commands ";
  constexpr const char* kUserUnitGetMissileInfoName = "GetMissileInfo";
  constexpr const char* kUserUnitGetMissileInfoHelpText =
    "table GetMissileInfo() - returns a table of the missile info for this unit";
  constexpr const char* kSetCurrentFactoryForQueueDisplayName = "SetCurrentFactoryForQueueDisplay";
  constexpr const char* kSetCurrentFactoryForQueueDisplayHelpText =
    "currentQueueTable SetCurrentFactoryForQueueDisplay(unit)";
  constexpr const char* kGetBlueprintUserName = "GetBlueprint";
  constexpr const char* kGetBlueprintUserHelpText = "blueprint = GetBlueprint()";
  constexpr const char* kCommandQueueIdKey = "ID";
  constexpr const char* kCommandQueueTypeKey = "type";
  constexpr const char* kCommandQueuePositionKey = "position";
  constexpr const char* kFactoryQueueItemIdKey = "id";
  constexpr const char* kFactoryQueueItemCountKey = "count";
  constexpr const char* kEconEnergyConsumedKey = "energyConsumed";
  constexpr const char* kEconMassConsumedKey = "massConsumed";
  constexpr const char* kEconEnergyRequestedKey = "energyRequested";
  constexpr const char* kEconMassRequestedKey = "massRequested";
  constexpr const char* kEconEnergyProducedKey = "energyProduced";
  constexpr const char* kEconMassProducedKey = "massProduced";
  constexpr const char* kMissileTacticalBuildCountKey = "tacticalSiloBuildCount";
  constexpr const char* kMissileTacticalStorageCountKey = "tacticalSiloStorageCount";
  constexpr const char* kMissileTacticalMaxStorageCountKey = "tacticalSiloMaxStorageCount";
  constexpr const char* kMissileNukeBuildCountKey = "nukeSiloBuildCount";
  constexpr const char* kMissileNukeStorageCountKey = "nukeSiloStorageCount";
  constexpr const char* kMissileNukeMaxStorageCountKey = "nukeSiloMaxStorageCount";
  constexpr const char* kOverlayCategoryAntiAir = "OVERLAYANTIAIR";
  constexpr const char* kOverlayCategoryDirectFire = "OVERLAYDIRECTFIRE";
  constexpr const char* kOverlayCategoryAntiNavy = "OVERLAYANTINAVY";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  constexpr float kEconomyPerSecondToUiRate = 10.0f;
  constexpr std::uint32_t kCommandIssueEventIncreaseCount = 1u;
  constexpr std::uint32_t kCommandIssueEventDecreaseCount = 2u;
  constexpr std::uint32_t kCommandIssueEventSetTarget = 4u;
  constexpr std::uint32_t kCommandIssueEventSetType = 5u;
  constexpr std::uintptr_t kUserEntityWeakOwnerOffset = 0x08u;

  enum class UserUnitIntelLane : std::int32_t
  {
    None = 0,
    Vision = 1,
    WaterVision = 2,
    Radar = 3,
    Sonar = 4,
    Omni = 5,
    RadarStealthField = 6,
    SonarStealthField = 7,
    CloakField = 8,
    Jammer = 9,
    Spoof = 10,
    Cloak = 11,
    RadarStealth = 12,
    SonarStealth = 13,
  };

  constexpr std::uint32_t kIntelRangeMagnitudeMask = 0x7FFFFFFFu;
  constexpr std::uint8_t kToggleCapJamming = 0x04u;
  constexpr std::uint8_t kToggleCapIntel = 0x08u;
  constexpr std::uint8_t kToggleCapStealth = 0x20u;
  constexpr std::int32_t kRangeCategoryAll = 6;

  struct UserEntityUiFlagView
  {
    std::uint8_t pad_0000_0070[0x70];
    std::uint8_t isBeingBuilt; // +0x70
    std::uint8_t pad_0071;
    std::uint8_t requestRefreshUi; // +0x72
  };
  static_assert(
    offsetof(UserEntityUiFlagView, isBeingBuilt) == 0x70, "UserEntityUiFlagView::isBeingBuilt offset must be 0x70"
  );
  static_assert(
    offsetof(UserEntityUiFlagView, requestRefreshUi) == 0x72,
    "UserEntityUiFlagView::requestRefreshUi offset must be 0x72"
  );

  struct UserUnitIntelRangeView
  {
    std::uint8_t pad_0000_0100[0x100];
    std::uint32_t vision;       // +0x100
    std::uint32_t waterVision;  // +0x104
    std::uint32_t radar;        // +0x108
    std::uint32_t sonar;        // +0x10C
    std::uint32_t omni;         // +0x110
    std::uint32_t radarStealth; // +0x114
    std::uint32_t sonarStealth; // +0x118
    std::uint32_t cloak;        // +0x11C
  };
  static_assert(
    offsetof(UserUnitIntelRangeView, vision) == 0x100, "UserUnitIntelRangeView::vision offset must be 0x100"
  );
  static_assert(offsetof(UserUnitIntelRangeView, cloak) == 0x11C, "UserUnitIntelRangeView::cloak offset must be 0x11C");

  struct UserUnitWeaponRuntimeView
  {
    EntityCategorySet rejectCategorySet; // +0x00
    EntityCategorySet requireCategorySet; // +0x28
    ELayer layerMask; // +0x50
    float minRange; // +0x54
    float maxRange; // +0x58
    std::uint8_t pad_005C_0098[0x98 - 0x5C];
  };
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, rejectCategorySet) == 0x00,
    "UserUnitWeaponRuntimeView::rejectCategorySet offset must be 0x00"
  );
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, requireCategorySet) == 0x28,
    "UserUnitWeaponRuntimeView::requireCategorySet offset must be 0x28"
  );
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, layerMask) == 0x50,
    "UserUnitWeaponRuntimeView::layerMask offset must be 0x50"
  );
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, minRange) == 0x54, "UserUnitWeaponRuntimeView::minRange offset must be 0x54"
  );
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, maxRange) == 0x58, "UserUnitWeaponRuntimeView::maxRange offset must be 0x58"
  );
  static_assert(sizeof(UserUnitWeaponRuntimeView) == 0x98, "UserUnitWeaponRuntimeView size must be 0x98");

  struct UserUnitLuaRuntimeView
  {
    std::uint8_t pad_0000_0120[0x120];
    UserArmy* army; // +0x120
    std::uint8_t pad_0124_01A2[0x1A2 - 0x124];
    std::uint8_t isBusy; // +0x1A2
    std::uint8_t pad_01A3_01AC[0x1AC - 0x1A3];
    std::int32_t stunTicks; // +0x1AC
    std::uint8_t pad_01B0_01C0[0x1C0 - 0x1B0];
    std::int32_t tacticalSiloBuildCount;      // +0x1C0
    std::int32_t nukeSiloBuildCount;          // +0x1C4
    std::int32_t tacticalSiloStorageCount;    // +0x1C8
    std::int32_t nukeSiloStorageCount;        // +0x1CC
    std::int32_t tacticalSiloMaxStorageCount; // +0x1D0
    std::int32_t nukeSiloMaxStorageCount;     // +0x1D4
    std::uint8_t pad_01D8_01DC[0x1DC - 0x1D8];
    msvc8::string customName; // +0x1DC
    float energyProducedPerSecond;  // +0x1F8
    float massProducedPerSecond;    // +0x1FC
    float energyConsumedPerSecond;  // +0x200
    float massConsumedPerSecond;    // +0x204
    float energyRequestedPerSecond; // +0x208
    float massRequestedPerSecond;   // +0x20C
    EntId focusEntityId;            // +0x210
    EntId guardedEntityId;          // +0x214
    std::uint8_t pad_0218_03C0[0x3C0 - 0x218];
    std::uintptr_t creatorWeakOwnerSlot; // +0x3C0
  };
  static_assert(offsetof(UserUnitLuaRuntimeView, army) == 0x120, "UserUnitLuaRuntimeView::army offset must be 0x120");
  static_assert(
    offsetof(UserUnitLuaRuntimeView, isBusy) == 0x1A2, "UserUnitLuaRuntimeView::isBusy offset must be 0x1A2"
  );
  static_assert(
    offsetof(UserUnitLuaRuntimeView, stunTicks) == 0x1AC, "UserUnitLuaRuntimeView::stunTicks offset must be 0x1AC"
  );
  static_assert(
    offsetof(UserUnitLuaRuntimeView, customName) == 0x1DC, "UserUnitLuaRuntimeView::customName offset must be 0x1DC"
  );
  static_assert(
    offsetof(UserUnitLuaRuntimeView, focusEntityId) == 0x210,
    "UserUnitLuaRuntimeView::focusEntityId offset must be 0x210"
  );
  static_assert(
    offsetof(UserUnitLuaRuntimeView, guardedEntityId) == 0x214,
    "UserUnitLuaRuntimeView::guardedEntityId offset must be 0x214"
  );
  static_assert(
    offsetof(UserUnitLuaRuntimeView, creatorWeakOwnerSlot) == 0x3C0,
    "UserUnitLuaRuntimeView::creatorWeakOwnerSlot offset must be 0x3C0"
  );

  struct UserUnitLuaObjectRuntimeView
  {
    std::uint8_t pad_0000_0170[0x170];
    LuaPlus::LuaObject luaObject; // +0x170
  };
  static_assert(
    offsetof(UserUnitLuaObjectRuntimeView, luaObject) == 0x170,
    "UserUnitLuaObjectRuntimeView::luaObject offset must be 0x170"
  );

  struct UserEntityWeakLinkView
  {
    std::uintptr_t ownerLinkSlot;         // +0x00
    UserEntityWeakLinkView* nextInOwner;  // +0x04
  };
  static_assert(sizeof(UserEntityWeakLinkView) == 0x08, "UserEntityWeakLinkView size must be 0x08");

  enum class UserTargetType : std::int32_t
  {
    Entity = 1,
    Position = 2,
  };

  struct UserCommandTargetView
  {
    UserTargetType targetType;             // +0x00
    UserEntityWeakLinkView targetEntity;   // +0x04
    Wm3::Vector3<float> position;          // +0x0C
  };
  static_assert(
    offsetof(UserCommandTargetView, targetEntity) == 0x04, "UserCommandTargetView::targetEntity offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandTargetView, position) == 0x0C, "UserCommandTargetView::position offset must be 0x0C"
  );
  static_assert(sizeof(UserCommandTargetView) == 0x18, "UserCommandTargetView size must be 0x18");

  struct UserCommandRawTargetView
  {
    UserTargetType targetType;             // +0x00
    std::int32_t entityId;                 // +0x04
    Wm3::Vector3<float> position;          // +0x08
  };
  static_assert(
    offsetof(UserCommandRawTargetView, entityId) == 0x04, "UserCommandRawTargetView::entityId offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandRawTargetView, position) == 0x08, "UserCommandRawTargetView::position offset must be 0x08"
  );
  static_assert(sizeof(UserCommandRawTargetView) == 0x14, "UserCommandRawTargetView size must be 0x14");

  struct UserCommandIssueEventRuntimeView
  {
    std::uint8_t pad_0000_0004[0x04];
    std::uint32_t eventType;              // +0x04
    std::uint8_t pad_0008_0014[0x0C];
    std::int32_t countDelta;              // +0x14
    UserCommandTargetView target;         // +0x18
    std::int32_t commandType;             // +0x30
  };
  static_assert(
    offsetof(UserCommandIssueEventRuntimeView, eventType) == 0x04,
    "UserCommandIssueEventRuntimeView::eventType offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueEventRuntimeView, countDelta) == 0x14,
    "UserCommandIssueEventRuntimeView::countDelta offset must be 0x14"
  );
  static_assert(
    offsetof(UserCommandIssueEventRuntimeView, target) == 0x18,
    "UserCommandIssueEventRuntimeView::target offset must be 0x18"
  );
  static_assert(
    offsetof(UserCommandIssueEventRuntimeView, commandType) == 0x30,
    "UserCommandIssueEventRuntimeView::commandType offset must be 0x30"
  );

  struct UserCommandIssueHelperRuntimeView
  {
    std::uint8_t pad_0000_0004[0x04];
    CmdId commandId;                                    // +0x04
    std::uint8_t pad_0008_0020[0x18];
    const RBlueprint* buildBlueprint;                   // +0x20
    std::uint8_t pad_0024_0058[0x34];
    EUnitCommandType commandType;                       // +0x58
    UserCommandRawTargetView defaultTarget;             // +0x5C
    std::uint8_t pad_0070_00A4[0x34];
    std::int32_t baseCount;                             // +0xA4
    std::uint8_t pad_00A8_00BC[0x14];
    UserCommandIssueEventRuntimeView** eventSlots;      // +0xBC
    std::uint32_t eventWrapBase;                        // +0xC0
    std::uint32_t eventStart;                           // +0xC4
    std::uint32_t eventCount;                           // +0xC8
  };
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, commandId) == 0x04,
    "UserCommandIssueHelperRuntimeView::commandId offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, buildBlueprint) == 0x20,
    "UserCommandIssueHelperRuntimeView::buildBlueprint offset must be 0x20"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, commandType) == 0x58,
    "UserCommandIssueHelperRuntimeView::commandType offset must be 0x58"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, defaultTarget) == 0x5C,
    "UserCommandIssueHelperRuntimeView::defaultTarget offset must be 0x5C"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, baseCount) == 0xA4,
    "UserCommandIssueHelperRuntimeView::baseCount offset must be 0xA4"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, eventSlots) == 0xBC,
    "UserCommandIssueHelperRuntimeView::eventSlots offset must be 0xBC"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, eventWrapBase) == 0xC0,
    "UserCommandIssueHelperRuntimeView::eventWrapBase offset must be 0xC0"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, eventStart) == 0xC4,
    "UserCommandIssueHelperRuntimeView::eventStart offset must be 0xC4"
  );
  static_assert(
    offsetof(UserCommandIssueHelperRuntimeView, eventCount) == 0xC8,
    "UserCommandIssueHelperRuntimeView::eventCount offset must be 0xC8"
  );

  struct UserCommandQueueEntryView
  {
    UserCommandIssueHelperRuntimeView* helper;   // +0x00
    void* link;                                  // +0x04
  };
  static_assert(sizeof(UserCommandQueueEntryView) == 0x08, "UserCommandQueueEntryView size must be 0x08");

  struct UserCommandQueueRangeView
  {
    UserCommandQueueEntryView* begin;            // +0x00
    UserCommandQueueEntryView* end;              // +0x04
  };
  static_assert(sizeof(UserCommandQueueRangeView) == 0x08, "UserCommandQueueRangeView size must be 0x08");

  struct FactoryQueueDisplayItemRuntime
  {
    msvc8::string blueprintId;         // +0x00
    std::int32_t count;                // +0x1C
    CmdId commandId;                   // +0x20
    std::uint8_t pad_0024_0030[0x0C]{}; // +0x24
  };
  static_assert(offsetof(FactoryQueueDisplayItemRuntime, count) == 0x1C, "FactoryQueueDisplayItemRuntime::count offset must be 0x1C");
  static_assert(
    offsetof(FactoryQueueDisplayItemRuntime, commandId) == 0x20,
    "FactoryQueueDisplayItemRuntime::commandId offset must be 0x20"
  );
  static_assert(sizeof(FactoryQueueDisplayItemRuntime) == 0x30, "FactoryQueueDisplayItemRuntime size must be 0x30");

  msvc8::vector<FactoryQueueDisplayItemRuntime> sCurrentFactoryBuildQueue;

  struct UserCommandManagerPendingSlotView
  {
    std::int32_t dueSeqNo; // +0x00
    std::uint8_t pad_0004_0008[0x04];
  };
  static_assert(
    offsetof(UserCommandManagerPendingSlotView, dueSeqNo) == 0x00,
    "UserCommandManagerPendingSlotView::dueSeqNo offset must be 0x00"
  );

  struct UserCommandManagerRuntimeView
  {
    std::uint8_t pad_0000_0008[0x08];
    UserCommandQueueRangeView primaryRange;      // +0x08
    std::uint8_t pad_0010_002C[0x1C];
    UserCommandManagerPendingSlotView** pendingIssueSlots; // +0x2C
    std::uint32_t pendingSlotCount;              // +0x30
    std::uint32_t pendingCursor;                 // +0x34
    std::uint32_t pendingIssueCount;             // +0x38
    std::uint8_t pad_003C_0040[0x04];
    UserCommandQueueRangeView resolvedRange;     // +0x40
    UserCommandQueueEntryView* resolvedRangeEndStorage; // +0x48
    UserCommandQueueEntryView** resolvedRangeInlineStorage; // +0x4C
    std::uint8_t pad_0050_0060[0x10];
    std::uint8_t resolvedRangeDirty; // +0x60
  };
  static_assert(
    offsetof(UserCommandManagerRuntimeView, primaryRange) == 0x08,
    "UserCommandManagerRuntimeView::primaryRange offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, pendingIssueSlots) == 0x2C,
    "UserCommandManagerRuntimeView::pendingIssueSlots offset must be 0x2C"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, pendingSlotCount) == 0x30,
    "UserCommandManagerRuntimeView::pendingSlotCount offset must be 0x30"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, pendingCursor) == 0x34,
    "UserCommandManagerRuntimeView::pendingCursor offset must be 0x34"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, pendingIssueCount) == 0x38,
    "UserCommandManagerRuntimeView::pendingIssueCount offset must be 0x38"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, resolvedRange) == 0x40,
    "UserCommandManagerRuntimeView::resolvedRange offset must be 0x40"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, resolvedRangeEndStorage) == 0x48,
    "UserCommandManagerRuntimeView::resolvedRangeEndStorage offset must be 0x48"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, resolvedRangeInlineStorage) == 0x4C,
    "UserCommandManagerRuntimeView::resolvedRangeInlineStorage offset must be 0x4C"
  );
  static_assert(
    offsetof(UserCommandManagerRuntimeView, resolvedRangeDirty) == 0x60,
    "UserCommandManagerRuntimeView::resolvedRangeDirty offset must be 0x60"
  );

  struct UserUnitVisionRuntimeView
  {
    std::uint8_t pad_0000_0018[0x18];
    VisionDB::Handle* visionHandle; // +0x18
  };
  static_assert(
    offsetof(UserUnitVisionRuntimeView, visionHandle) == 0x18,
    "UserUnitVisionRuntimeView::visionHandle offset must be 0x18"
  );

  struct UserArmyIdleSetRuntimeView
  {
    std::uint8_t pad_0000_01F8[0x1F8];
    SSelectionSetUserEntity engineers; // +0x1F8
    SSelectionSetUserEntity factories; // +0x208
  };
  static_assert(
    offsetof(UserArmyIdleSetRuntimeView, engineers) == 0x1F8,
    "UserArmyIdleSetRuntimeView::engineers offset must be 0x1F8"
  );
  static_assert(
    offsetof(UserArmyIdleSetRuntimeView, factories) == 0x208,
    "UserArmyIdleSetRuntimeView::factories offset must be 0x208"
  );
  static_assert(sizeof(UserArmyIdleSetRuntimeView) == 0x218, "UserArmyIdleSetRuntimeView size must be 0x218");

  [[nodiscard]] const IUnit* GetIUnitBridge(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const IUnit*>(self->mIUnitAndScriptBridge);
  }

  [[nodiscard]] IUnit* GetIUnitBridge(UserUnit* const self) noexcept
  {
    return reinterpret_cast<IUnit*>(self->mIUnitAndScriptBridge);
  }

  [[nodiscard]] const UserUnitLuaRuntimeView& GetLuaRuntimeView(const UserUnit* const self) noexcept
  {
    return *reinterpret_cast<const UserUnitLuaRuntimeView*>(self);
  }

  [[nodiscard]] UserUnitLuaRuntimeView& GetLuaRuntimeView(UserUnit* const self) noexcept
  {
    return *reinterpret_cast<UserUnitLuaRuntimeView*>(self);
  }

  [[nodiscard]] const UserUnitLuaObjectRuntimeView& GetUserUnitLuaObjectView(const UserUnit* const self) noexcept
  {
    return *reinterpret_cast<const UserUnitLuaObjectRuntimeView*>(self);
  }

  [[nodiscard]] std::int32_t EncodeUserCommandManagerHandle(const UserUnitManager* const manager) noexcept
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(manager));
  }

  [[nodiscard]] UserCommandManagerRuntimeView* DecodeUserCommandManagerHandle(const std::int32_t managerHandle) noexcept
  {
    if (managerHandle == 0) {
      return nullptr;
    }

    const std::uintptr_t managerAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(managerHandle));
    return reinterpret_cast<UserCommandManagerRuntimeView*>(managerAddress);
  }

  [[nodiscard]] const UserCommandQueueRangeView* ResolveUserCommandQueueRange(const std::int32_t managerHandle) noexcept
  {
    const UserCommandManagerRuntimeView* const manager = DecodeUserCommandManagerHandle(managerHandle);
    if (manager == nullptr) {
      return nullptr;
    }

    return (manager->pendingIssueCount == 0u) ? &manager->primaryRange : &manager->resolvedRange;
  }

  [[nodiscard]] VisionDB::Handle*& GetUserUnitVisionHandle(UserUnit* const self) noexcept
  {
    return reinterpret_cast<UserUnitVisionRuntimeView*>(self)->visionHandle;
  }

  [[nodiscard]] const VisionDB::Handle* GetUserUnitVisionHandle(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const UserUnitVisionRuntimeView*>(self)->visionHandle;
  }

  [[nodiscard]] UserArmyIdleSetRuntimeView& GetUserArmyIdleSetView(UserArmy* const army) noexcept
  {
    return *reinterpret_cast<UserArmyIdleSetRuntimeView*>(army);
  }

  [[nodiscard]] const UserArmyIdleSetRuntimeView& GetUserArmyIdleSetView(const UserArmy* const army) noexcept
  {
    return *reinterpret_cast<const UserArmyIdleSetRuntimeView*>(army);
  }

  template <typename TNode>
  [[nodiscard]] bool IsWeakEntitySentinelNode(const TNode* const node) noexcept
  {
    return node == nullptr || node->mIsSentinel != 0u;
  }

  template <typename TNode>
  [[nodiscard]] TNode* NextWeakEntityNode(TNode* node) noexcept
  {
    if (node == nullptr || IsWeakEntitySentinelNode(node)) {
      return node;
    }

    if (!IsWeakEntitySentinelNode(node->mRight)) {
      node = node->mRight;
      while (!IsWeakEntitySentinelNode(node->mLeft)) {
        node = node->mLeft;
      }
      return node;
    }

    TNode* parent = node->mParent;
    while (!IsWeakEntitySentinelNode(parent) && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }
    return parent;
  }

  [[nodiscard]] std::uint32_t WeakEntitySetKey(const UserEntity* const entity) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entity));
  }

  void LinkWeakEntityOwner(UserEntity* const entity, SSelectionWeakRefUserEntity& weakRef) noexcept
  {
    weakRef.mOwnerLinkSlot = nullptr;
    weakRef.mNextOwner = nullptr;
    if (entity == nullptr) {
      return;
    }

    auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead);
    weakRef.mOwnerLinkSlot = ownerLinkSlot;
    weakRef.mNextOwner = *ownerLinkSlot;
    *ownerLinkSlot = &weakRef;
  }

  void UnlinkWeakEntityOwner(SSelectionWeakRefUserEntity& weakRef) noexcept
  {
    auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(weakRef.mOwnerLinkSlot);
    if (ownerLinkSlot == nullptr) {
      return;
    }

    while (*ownerLinkSlot != nullptr && *ownerLinkSlot != &weakRef) {
      ownerLinkSlot = &(*ownerLinkSlot)->mNextOwner;
    }

    if (*ownerLinkSlot == &weakRef) {
      *ownerLinkSlot = weakRef.mNextOwner;
    }

    weakRef.mOwnerLinkSlot = nullptr;
    weakRef.mNextOwner = nullptr;
  }

  [[nodiscard]] SSelectionNodeUserEntity*
  FindWeakEntitySetNodeByKey(const SSelectionSetUserEntity& selection, const std::uint32_t key) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    SSelectionNodeUserEntity* node = head->mParent;
    while (!IsWeakEntitySentinelNode(node)) {
      if (key < node->mKey) {
        node = node->mLeft;
      } else if (node->mKey < key) {
        node = node->mRight;
      } else {
        return node;
      }
    }

    return head;
  }

  [[nodiscard]] SSelectionNodeUserEntity*
  WeakEntitySelectionMin(SSelectionNodeUserEntity* node, SSelectionNodeUserEntity* const head) noexcept
  {
    while (!IsWeakEntitySentinelNode(node) && !IsWeakEntitySentinelNode(node->mLeft)) {
      node = node->mLeft;
    }
    return IsWeakEntitySentinelNode(node) ? head : node;
  }

  [[nodiscard]] SSelectionNodeUserEntity*
  WeakEntitySelectionMax(SSelectionNodeUserEntity* node, SSelectionNodeUserEntity* const head) noexcept
  {
    while (!IsWeakEntitySentinelNode(node) && !IsWeakEntitySentinelNode(node->mRight)) {
      node = node->mRight;
    }
    return IsWeakEntitySentinelNode(node) ? head : node;
  }

  void RecomputeWeakEntitySetExtrema(SSelectionSetUserEntity& selection) noexcept
  {
    if (selection.mHead == nullptr) {
      return;
    }

    SSelectionNodeUserEntity* const head = selection.mHead;
    SSelectionNodeUserEntity* const root = head->mParent;
    if (IsWeakEntitySentinelNode(root)) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      return;
    }

    head->mLeft = WeakEntitySelectionMin(root, head);
    head->mRight = WeakEntitySelectionMax(root, head);
  }

  void ReplaceWeakEntitySubtree(
    SSelectionSetUserEntity& selection,
    SSelectionNodeUserEntity* const oldNode,
    SSelectionNodeUserEntity* const newNode
  ) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    if (oldNode->mParent == head) {
      head->mParent = newNode;
    } else if (oldNode == oldNode->mParent->mLeft) {
      oldNode->mParent->mLeft = newNode;
    } else {
      oldNode->mParent->mRight = newNode;
    }

    if (!IsWeakEntitySentinelNode(newNode)) {
      newNode->mParent = oldNode->mParent;
    }
  }

  void RotateWeakEntityLeft(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* const node) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    SSelectionNodeUserEntity* const pivot = node->mRight;
    node->mRight = pivot->mLeft;
    if (!IsWeakEntitySentinelNode(pivot->mLeft)) {
      pivot->mLeft->mParent = node;
    }

    pivot->mParent = node->mParent;
    if (node->mParent == head) {
      head->mParent = pivot;
    } else if (node == node->mParent->mLeft) {
      node->mParent->mLeft = pivot;
    } else {
      node->mParent->mRight = pivot;
    }

    pivot->mLeft = node;
    node->mParent = pivot;
  }

  void RotateWeakEntityRight(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* const node) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    SSelectionNodeUserEntity* const pivot = node->mLeft;
    node->mLeft = pivot->mRight;
    if (!IsWeakEntitySentinelNode(pivot->mRight)) {
      pivot->mRight->mParent = node;
    }

    pivot->mParent = node->mParent;
    if (node->mParent == head) {
      head->mParent = pivot;
    } else if (node == node->mParent->mRight) {
      node->mParent->mRight = pivot;
    } else {
      node->mParent->mLeft = pivot;
    }

    pivot->mRight = node;
    node->mParent = pivot;
  }

  void FixupWeakEntityInsert(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* node) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    while (node != head->mParent && node->mParent->mColor == 0u) {
      SSelectionNodeUserEntity* const parent = node->mParent;
      SSelectionNodeUserEntity* const grand = parent->mParent;
      if (parent == grand->mLeft) {
        SSelectionNodeUserEntity* const uncle = grand->mRight;
        if (uncle->mColor == 0u) {
          parent->mColor = 1u;
          uncle->mColor = 1u;
          grand->mColor = 0u;
          node = grand;
        } else {
          if (node == parent->mRight) {
            node = parent;
            RotateWeakEntityLeft(selection, node);
          }
          node->mParent->mColor = 1u;
          grand->mColor = 0u;
          RotateWeakEntityRight(selection, grand);
        }
      } else {
        SSelectionNodeUserEntity* const uncle = grand->mLeft;
        if (uncle->mColor == 0u) {
          parent->mColor = 1u;
          uncle->mColor = 1u;
          grand->mColor = 0u;
          node = grand;
        } else {
          if (node == parent->mLeft) {
            node = parent;
            RotateWeakEntityRight(selection, node);
          }
          node->mParent->mColor = 1u;
          grand->mColor = 0u;
          RotateWeakEntityLeft(selection, grand);
        }
      }
    }

    head->mParent->mColor = 1u;
  }

  void FixupWeakEntityErase(
    SSelectionSetUserEntity& selection,
    SSelectionNodeUserEntity* node,
    SSelectionNodeUserEntity* nodeParent
  ) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    SSelectionNodeUserEntity* parent = !IsWeakEntitySentinelNode(node) ? node->mParent : nodeParent;
    while (node != head->mParent && (IsWeakEntitySentinelNode(node) || node->mColor == 1u)) {
      if (parent == nullptr) {
        break;
      }

      if (node == parent->mLeft) {
        SSelectionNodeUserEntity* sibling = parent->mRight;
        if (sibling == head) {
          node = parent;
          parent = node->mParent;
          continue;
        }
        if (sibling->mColor == 0u) {
          sibling->mColor = 1u;
          parent->mColor = 0u;
          RotateWeakEntityLeft(selection, parent);
          sibling = parent->mRight;
        }

        const bool leftBlack = IsWeakEntitySentinelNode(sibling->mLeft) || sibling->mLeft->mColor == 1u;
        const bool rightBlack = IsWeakEntitySentinelNode(sibling->mRight) || sibling->mRight->mColor == 1u;
        if (leftBlack && rightBlack) {
          sibling->mColor = 0u;
          node = parent;
          parent = node->mParent;
          continue;
        }

        if (IsWeakEntitySentinelNode(sibling->mRight) || sibling->mRight->mColor == 1u) {
          if (!IsWeakEntitySentinelNode(sibling->mLeft)) {
            sibling->mLeft->mColor = 1u;
          }
          sibling->mColor = 0u;
          RotateWeakEntityRight(selection, sibling);
          sibling = parent->mRight;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = 1u;
        if (!IsWeakEntitySentinelNode(sibling->mRight)) {
          sibling->mRight->mColor = 1u;
        }
        RotateWeakEntityLeft(selection, parent);
        node = head->mParent;
        break;
      }

      SSelectionNodeUserEntity* sibling = parent->mLeft;
      if (sibling == head) {
        node = parent;
        parent = node->mParent;
        continue;
      }
      if (sibling->mColor == 0u) {
        sibling->mColor = 1u;
        parent->mColor = 0u;
        RotateWeakEntityRight(selection, parent);
        sibling = parent->mLeft;
      }

      const bool rightBlack = IsWeakEntitySentinelNode(sibling->mRight) || sibling->mRight->mColor == 1u;
      const bool leftBlack = IsWeakEntitySentinelNode(sibling->mLeft) || sibling->mLeft->mColor == 1u;
      if (rightBlack && leftBlack) {
        sibling->mColor = 0u;
        node = parent;
        parent = node->mParent;
        continue;
      }

      if (IsWeakEntitySentinelNode(sibling->mLeft) || sibling->mLeft->mColor == 1u) {
        if (!IsWeakEntitySentinelNode(sibling->mRight)) {
          sibling->mRight->mColor = 1u;
        }
        sibling->mColor = 0u;
        RotateWeakEntityLeft(selection, sibling);
        sibling = parent->mLeft;
      }

      sibling->mColor = parent->mColor;
      parent->mColor = 1u;
      if (!IsWeakEntitySentinelNode(sibling->mLeft)) {
        sibling->mLeft->mColor = 1u;
      }
      RotateWeakEntityRight(selection, parent);
      node = head->mParent;
      break;
    }

    if (!IsWeakEntitySentinelNode(node)) {
      node->mColor = 1u;
    }
  }

  [[nodiscard]] SSelectionNodeUserEntity*
  EraseWeakEntityNodeAndAdvance(SSelectionSetUserEntity& selection, SSelectionNodeUserEntity* const node) noexcept
  {
    if (selection.mHead == nullptr || IsWeakEntitySentinelNode(node)) {
      return node;
    }

    SSelectionNodeUserEntity* const head = selection.mHead;
    SSelectionNodeUserEntity* const next = NextWeakEntityNode(node);
    SSelectionNodeUserEntity* removed = node;
    SSelectionNodeUserEntity* spliceTarget = node;
    std::uint8_t removedColor = spliceTarget->mColor;
    SSelectionNodeUserEntity* fixNode = head;
    SSelectionNodeUserEntity* fixParent = head;

    if (IsWeakEntitySentinelNode(node->mLeft)) {
      fixNode = node->mRight;
      fixParent = node->mParent;
      ReplaceWeakEntitySubtree(selection, node, node->mRight);
    } else if (IsWeakEntitySentinelNode(node->mRight)) {
      fixNode = node->mLeft;
      fixParent = node->mParent;
      ReplaceWeakEntitySubtree(selection, node, node->mLeft);
    } else {
      spliceTarget = WeakEntitySelectionMin(node->mRight, head);
      removedColor = spliceTarget->mColor;
      fixNode = spliceTarget->mRight;
      if (spliceTarget->mParent == node) {
        fixParent = spliceTarget;
        if (!IsWeakEntitySentinelNode(fixNode)) {
          fixNode->mParent = spliceTarget;
        }
      } else {
        fixParent = spliceTarget->mParent;
        ReplaceWeakEntitySubtree(selection, spliceTarget, spliceTarget->mRight);
        spliceTarget->mRight = node->mRight;
        spliceTarget->mRight->mParent = spliceTarget;
      }

      ReplaceWeakEntitySubtree(selection, node, spliceTarget);
      spliceTarget->mLeft = node->mLeft;
      spliceTarget->mLeft->mParent = spliceTarget;
      spliceTarget->mColor = node->mColor;
    }

    UnlinkWeakEntityOwner(removed->mEnt);
    ::operator delete(removed);

    if (selection.mSize > 0u) {
      --selection.mSize;
    }
    if (removedColor == 1u) {
      FixupWeakEntityErase(selection, fixNode, fixParent);
    }

    RecomputeWeakEntitySetExtrema(selection);
    return next;
  }

  [[nodiscard]] bool InsertWeakEntitySet(SSelectionSetUserEntity& selection, UserEntity* const entity) noexcept
  {
    SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr || entity == nullptr) {
      return false;
    }

    const std::uint32_t key = WeakEntitySetKey(entity);
    SSelectionNodeUserEntity* parent = head;
    SSelectionNodeUserEntity* probe = head->mParent;
    while (!IsWeakEntitySentinelNode(probe)) {
      parent = probe;
      if (key < probe->mKey) {
        probe = probe->mLeft;
      } else if (probe->mKey < key) {
        probe = probe->mRight;
      } else {
        return false;
      }
    }

    auto* const inserted = static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity)));
    inserted->mLeft = head;
    inserted->mRight = head;
    inserted->mParent = parent;
    inserted->mKey = key;
    inserted->mColor = 0u;
    inserted->mIsSentinel = 0u;
    inserted->pad_1A[0] = 0u;
    inserted->pad_1A[1] = 0u;
    LinkWeakEntityOwner(entity, inserted->mEnt);

    if (parent == head) {
      head->mParent = inserted;
    } else if (key < parent->mKey) {
      parent->mLeft = inserted;
    } else {
      parent->mRight = inserted;
    }

    ++selection.mSize;
    FixupWeakEntityInsert(selection, inserted);
    RecomputeWeakEntitySetExtrema(selection);
    return true;
  }

  [[nodiscard]] bool EraseWeakEntitySet(SSelectionSetUserEntity& selection, UserEntity* const entity) noexcept
  {
    if (selection.mHead == nullptr || entity == nullptr) {
      return false;
    }

    SSelectionNodeUserEntity* const node = FindWeakEntitySetNodeByKey(selection, WeakEntitySetKey(entity));
    if (node == nullptr || node == selection.mHead) {
      return false;
    }

    (void)EraseWeakEntityNodeAndAdvance(selection, node);
    return true;
  }

  [[nodiscard]] bool IsUserCommandManagerQueueEmpty(const UserUnitManager* const manager) noexcept
  {
    const UserCommandQueueRangeView* const queueRange =
      ResolveUserCommandQueueRange(EncodeUserCommandManagerHandle(manager));
    return queueRange == nullptr || queueRange->begin == queueRange->end;
  }

  void UnlinkResolvedQueueOwnerLinks(
    UserCommandQueueEntryView* const begin, UserCommandQueueEntryView* const end
  ) noexcept
  {
    for (UserCommandQueueEntryView* cursor = begin; cursor != end; ++cursor) {
      auto* ownerLink = reinterpret_cast<UserCommandQueueEntryView**>(cursor->helper);
      if (ownerLink == nullptr) {
        continue;
      }

      while (*ownerLink != nullptr && *ownerLink != cursor) {
        ownerLink = reinterpret_cast<UserCommandQueueEntryView**>(&(*ownerLink)->link);
      }
      if (*ownerLink == cursor) {
        *ownerLink = reinterpret_cast<UserCommandQueueEntryView*>(cursor->link);
      }
    }
  }

  void AdvanceUserCommandManagerBySeq(UserUnitManager* const managerPtr, const std::int32_t seqNo) noexcept
  {
    auto* const manager = reinterpret_cast<UserCommandManagerRuntimeView*>(managerPtr);
    if (manager == nullptr) {
      return;
    }

    while (manager->pendingIssueCount != 0u) {
      std::uint32_t queueIndex = manager->pendingCursor;
      if (manager->pendingSlotCount <= queueIndex) {
        queueIndex -= manager->pendingSlotCount;
      }

      const UserCommandManagerPendingSlotView* const slot = manager->pendingIssueSlots[queueIndex];
      if (slot == nullptr || (slot->dueSeqNo - seqNo) > 0) {
        break;
      }

      manager->pendingCursor += 1u;
      if (manager->pendingSlotCount <= manager->pendingCursor) {
        manager->pendingCursor = 0u;
      }

      manager->pendingIssueCount -= 1u;
      if (manager->pendingIssueCount == 0u) {
        manager->pendingCursor = 0u;
      }
      manager->resolvedRangeDirty = 1u;
    }

    if (manager->resolvedRangeDirty == 0u) {
      return;
    }

    UnlinkResolvedQueueOwnerLinks(manager->resolvedRange.begin, manager->resolvedRange.end);
    if (manager->resolvedRange.begin != reinterpret_cast<UserCommandQueueEntryView*>(manager->resolvedRangeInlineStorage)) {
      ::operator delete[](manager->resolvedRange.begin);
      manager->resolvedRange.begin = reinterpret_cast<UserCommandQueueEntryView*>(manager->resolvedRangeInlineStorage);
      manager->resolvedRangeEndStorage = manager->resolvedRangeInlineStorage != nullptr
        ? *manager->resolvedRangeInlineStorage
        : nullptr;
    }
    manager->resolvedRange.end = manager->resolvedRange.begin;
  }

  [[nodiscard]] UserEntity* DecodeWeakOwnerUserEntity(const UserEntityWeakLinkView& weakEntityLink) noexcept
  {
    const std::uintptr_t rawOwnerSlot = weakEntityLink.ownerLinkSlot;
    if (rawOwnerSlot <= kUserEntityWeakOwnerOffset) {
      return nullptr;
    }

    return reinterpret_cast<UserEntity*>(rawOwnerSlot - kUserEntityWeakOwnerOffset);
  }

  [[nodiscard]] Wm3::Vector3<float> InvalidCommandQueuePosition() noexcept
  {
    const float quietNan = std::numeric_limits<float>::quiet_NaN();
    return Wm3::Vector3<float>(quietNan, quietNan, quietNan);
  }

  [[nodiscard]] UserEntity* FindSessionEntityById(CWldSession* session, std::int32_t entityId) noexcept;

  [[nodiscard]] Wm3::Vector3<float> ResolvePositionFromTarget(const UserCommandTargetView& target) noexcept
  {
    if (target.targetType == UserTargetType::Position) {
      return target.position;
    }

    if (target.targetType == UserTargetType::Entity) {
      if (UserEntity* const targetEntity = DecodeWeakOwnerUserEntity(target.targetEntity); targetEntity != nullptr) {
        return targetEntity->mVariableData.mCurTransform.pos_;
      }
    }

    return InvalidCommandQueuePosition();
  }

  [[nodiscard]] Wm3::Vector3<float>
  ResolvePositionFromRawTarget(const UserCommandRawTargetView& target, CWldSession* const session) noexcept
  {
    if (target.targetType == UserTargetType::Position) {
      return target.position;
    }

    if (target.targetType == UserTargetType::Entity) {
      if (UserEntity* const targetEntity = FindSessionEntityById(session, target.entityId); targetEntity != nullptr) {
        return targetEntity->mVariableData.mCurTransform.pos_;
      }
    }

    return InvalidCommandQueuePosition();
  }

  [[nodiscard]] const UserCommandIssueEventRuntimeView*
  FindLatestIssueEvent(const UserCommandIssueHelperRuntimeView& helper, const std::uint32_t eventType) noexcept
  {
    if (helper.eventSlots == nullptr) {
      return nullptr;
    }

    std::uint32_t cursor = helper.eventCount + helper.eventStart;
    while (cursor != helper.eventStart) {
      const std::uint32_t scan = cursor - 1u;
      std::uint32_t slot = scan;
      if (helper.eventWrapBase <= scan) {
        slot = scan - helper.eventWrapBase;
      }

      const UserCommandIssueEventRuntimeView* const event = helper.eventSlots[slot];
      if (event != nullptr && event->eventType == eventType) {
        return event;
      }

      cursor = scan;
    }

    return nullptr;
  }

  [[nodiscard]] EUnitCommandType ResolveHelperCommandType(const UserCommandIssueHelperRuntimeView& helper) noexcept
  {
    if (const UserCommandIssueEventRuntimeView* const event = FindLatestIssueEvent(helper, kCommandIssueEventSetType);
        event != nullptr) {
      return static_cast<EUnitCommandType>(event->commandType);
    }

    return helper.commandType;
  }

  [[nodiscard]] Wm3::Vector3<float>
  ResolveHelperTargetPosition(const UserCommandIssueHelperRuntimeView& helper, CWldSession* const session) noexcept
  {
    if (const UserCommandIssueEventRuntimeView* const event = FindLatestIssueEvent(helper, kCommandIssueEventSetTarget);
        event != nullptr) {
      return ResolvePositionFromTarget(event->target);
    }

    return ResolvePositionFromRawTarget(helper.defaultTarget, session);
  }

  [[nodiscard]] bool IsFactoryQueueCommandType(const EUnitCommandType commandType) noexcept
  {
    return commandType == EUnitCommandType::UNITCOMMAND_BuildFactory
      || commandType == EUnitCommandType::UNITCOMMAND_BuildMobile
      || commandType == EUnitCommandType::UNITCOMMAND_Upgrade;
  }

  [[nodiscard]] std::int32_t ResolveHelperBuildCount(const UserCommandIssueHelperRuntimeView& helper) noexcept
  {
    std::int32_t count = helper.baseCount;
    const std::uint32_t end = helper.eventStart + helper.eventCount;
    for (std::uint32_t cursor = helper.eventStart; cursor != end; ++cursor) {
      if (helper.eventSlots == nullptr) {
        break;
      }

      std::uint32_t slot = cursor;
      if (helper.eventWrapBase <= cursor) {
        slot = cursor - helper.eventWrapBase;
      }

      const UserCommandIssueEventRuntimeView* const event = helper.eventSlots[slot];
      if (event == nullptr) {
        continue;
      }

      if (event->eventType == kCommandIssueEventDecreaseCount) {
        if (event->countDelta == -1) {
          count = 0;
        } else {
          count -= event->countDelta;
          if (count < 0) {
            count = 0;
          }
        }
        continue;
      }

      if (event->eventType == kCommandIssueEventIncreaseCount && event->countDelta > 0) {
        const std::int32_t updatedCount = count + event->countDelta;
        count = (updatedCount < 0) ? 0 : updatedCount;
      }
    }

    return count;
  }

  void RebuildCurrentFactoryBuildQueue(UserUnit* const userUnit)
  {
    sCurrentFactoryBuildQueue.clear();
    if (userUnit == nullptr) {
      return;
    }

    const UserCommandQueueRangeView* const commandRange = ResolveUserCommandQueueRange(userUnit->GetFactoryCommandQueue2());
    if (commandRange == nullptr) {
      return;
    }

    for (UserCommandQueueEntryView* entry = commandRange->begin; entry != commandRange->end; ++entry) {
      const UserCommandIssueHelperRuntimeView* const helper = entry->helper;
      if (helper == nullptr) {
        continue;
      }

      const EUnitCommandType commandType = ResolveHelperCommandType(*helper);
      if (!IsFactoryQueueCommandType(commandType)) {
        continue;
      }

      const RBlueprint* const blueprint = helper->buildBlueprint;
      if (blueprint == nullptr || blueprint->mBlueprintId.empty()) {
        continue;
      }

      const std::int32_t commandCount = ResolveHelperBuildCount(*helper);
      if (commandCount <= 0) {
        continue;
      }

      if (
        !sCurrentFactoryBuildQueue.empty()
        && sCurrentFactoryBuildQueue.back().blueprintId == blueprint->mBlueprintId
      ) {
        FactoryQueueDisplayItemRuntime& tail = sCurrentFactoryBuildQueue.back();
        tail.count += commandCount;
        tail.commandId = helper->commandId;
        continue;
      }

      FactoryQueueDisplayItemRuntime item{};
      item.blueprintId = blueprint->mBlueprintId;
      item.count = commandCount;
      item.commandId = helper->commandId;
      sCurrentFactoryBuildQueue.push_back(item);
    }
  }

  /**
   * Address: 0x00836080 (FUN_00836080, func_AddScriptUIBuildQueueItem)
   *
   * What it does:
   * Converts the current factory-build snapshot into one Lua array where each
   * row contains `id` and `count`.
   */
  [[nodiscard]] unsigned int BuildFactoryQueueLuaTable(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const outQueueTable
  )
  {
    outQueueTable->AssignNewTable(state, static_cast<int>(sCurrentFactoryBuildQueue.size()), 0);

    unsigned int tableIndex = 0;
    for (const FactoryQueueDisplayItemRuntime& buildItem : sCurrentFactoryBuildQueue) {
      LuaPlus::LuaObject row;
      row.AssignNewTable(state, 2, 0);
      row.SetString(kFactoryQueueItemIdKey, buildItem.blueprintId.c_str());
      row.SetInteger(kFactoryQueueItemCountKey, buildItem.count);
      outQueueTable->SetObject(static_cast<int>(++tableIndex), row);
    }

    return tableIndex;
  }

  [[nodiscard]] std::int32_t SelectActiveQueueHandle(UserUnit* const userUnit) noexcept
  {
    const std::int32_t factoryQueueHandle = userUnit->GetFactoryCommandQueue2();
    if (factoryQueueHandle != 0) {
      return userUnit->GetFactoryCommandQueue2();
    }

    return userUnit->GetCommandQueue2();
  }

  [[nodiscard]] const UserUnitIntelRangeView& GetIntelRangeView(const UserUnit* const self) noexcept
  {
    return *reinterpret_cast<const UserUnitIntelRangeView*>(self);
  }

  [[nodiscard]] std::uint32_t GetIntelRangeMagnitude(const UserUnit* const self, const UserUnitIntelLane intel) noexcept
  {
    const auto& ranges = GetIntelRangeView(self);

    // Binary parity with 0x005BD530 (EntityAttributes::GetRange):
    // enum ordinals are shifted relative to stored lanes.
    switch (intel) {
    case UserUnitIntelLane::None:
      return ranges.vision & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Vision:
      return ranges.waterVision & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::WaterVision:
      return ranges.radar & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Radar:
      return ranges.sonar & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Sonar:
      return ranges.omni & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Spoof:
      return ranges.cloak & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Cloak:
      return ranges.radarStealth & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::RadarStealth:
      return ranges.sonarStealth & kIntelRangeMagnitudeMask;
    case UserUnitIntelLane::Omni:
    case UserUnitIntelLane::RadarStealthField:
    case UserUnitIntelLane::SonarStealthField:
    case UserUnitIntelLane::CloakField:
    case UserUnitIntelLane::Jammer:
    case UserUnitIntelLane::SonarStealth:
      return 0u;
    }
    return 0u;
  }

  [[nodiscard]] float GetIntelRangeAsFloat(const UserUnit* const self, const UserUnitIntelLane intel) noexcept
  {
    return static_cast<float>(GetIntelRangeMagnitude(self, intel));
  }

  [[nodiscard]] const UserEntityUiFlagView& GetUiFlagView(const UserUnit* const self) noexcept
  {
    return *reinterpret_cast<const UserEntityUiFlagView*>(self);
  }

  [[nodiscard]] const UserUnitWeaponRuntimeView* GetWeaponInfoBegin(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const UserUnitWeaponRuntimeView*>(self->mWeaponTable);
  }

  [[nodiscard]] const UserUnitWeaponRuntimeView* GetWeaponInfoEnd(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const UserUnitWeaponRuntimeView*>(self->mWeaponTableEnd);
  }

  [[nodiscard]] bool ContainsBlueprintCategory(
    const EntityCategorySet& categorySet,
    const REntityBlueprint* const blueprint
  ) noexcept
  {
    return blueprint != nullptr && categorySet.Bits().Contains(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] bool WeaponAllowsBlueprint(
    const UserUnitWeaponRuntimeView& weaponInfo,
    const REntityBlueprint* const blueprint
  ) noexcept
  {
    if (!weaponInfo.rejectCategorySet.Bits().mWords.empty()
        && ContainsBlueprintCategory(weaponInfo.rejectCategorySet, blueprint)) {
      return false;
    }
    if (!weaponInfo.requireCategorySet.Bits().mWords.empty()
        && !ContainsBlueprintCategory(weaponInfo.requireCategorySet, blueprint)) {
      return false;
    }
    return true;
  }

  [[nodiscard]] bool IsUnitInOverlayCategory(const UserUnit* const unit, const char* const categoryName)
  {
    msvc8::string category{};
    category.assign_owned(categoryName != nullptr ? categoryName : "");
    const UserEntity* const entityView = (unit != nullptr) ? reinterpret_cast<const UserEntity*>(unit) : nullptr;
    return entityView != nullptr && entityView->IsInCategory(category);
  }

  [[nodiscard]] bool CanReuseSharedPoseForSkeleton(
    const boost::shared_ptr<CAniPose>& sharedPose,
    const boost::shared_ptr<const CAniSkel>& skeleton
  )
  {
    if (!sharedPose || !skeleton) {
      return false;
    }

    return sharedPose->GetSkeleton().get() == skeleton.get();
  }

  [[nodiscard]] float PlanarDistanceXZ(const Wm3::Vector3<float>& from, const Wm3::Vector3<float>& to) noexcept
  {
    const float dx = to.x - from.x;
    const float dz = to.z - from.z;
    return std::sqrt((dx * dx) + (dz * dz));
  }

  [[nodiscard]] UserEntity* ResolveUserEntityView(UserUnit* const userUnit) noexcept
  {
    return reinterpret_cast<UserEntity*>(userUnit);
  }

  struct SessionEntityMapNodeView
  {
    SessionEntityMapNodeView* left;   // +0x00
    SessionEntityMapNodeView* parent; // +0x04
    SessionEntityMapNodeView* right;  // +0x08
    std::int32_t key;                 // +0x0C
    UserEntity* value;                // +0x10
    std::uint8_t color;               // +0x14
    std::uint8_t isNil;               // +0x15
    std::uint8_t pad_0016_0017[0x02];
  };
  static_assert(offsetof(SessionEntityMapNodeView, key) == 0x0C, "SessionEntityMapNodeView::key offset must be 0x0C");
  static_assert(
    offsetof(SessionEntityMapNodeView, value) == 0x10, "SessionEntityMapNodeView::value offset must be 0x10"
  );
  static_assert(
    offsetof(SessionEntityMapNodeView, isNil) == 0x15, "SessionEntityMapNodeView::isNil offset must be 0x15"
  );
  static_assert(sizeof(SessionEntityMapNodeView) == 0x18, "SessionEntityMapNodeView size must be 0x18");

  struct SessionEntityMapView
  {
    void* allocProxy;             // +0x00
    SessionEntityMapNodeView* head; // +0x04
    std::uint32_t size;           // +0x08
  };
  static_assert(offsetof(SessionEntityMapView, head) == 0x04, "SessionEntityMapView::head offset must be 0x04");
  static_assert(offsetof(SessionEntityMapView, size) == 0x08, "SessionEntityMapView::size offset must be 0x08");
  static_assert(sizeof(SessionEntityMapView) == 0x0C, "SessionEntityMapView size must be 0x0C");
  static_assert(offsetof(CWldSession, mUnknownOwner44) == 0x44, "CWldSession::mUnknownOwner44 offset must be 0x44");

  [[nodiscard]] const SessionEntityMapView& GetSessionEntityMapView(const CWldSession* const session) noexcept
  {
    return *reinterpret_cast<const SessionEntityMapView*>(
      reinterpret_cast<const std::uint8_t*>(session) + offsetof(CWldSession, mUnknownOwner44)
    );
  }

  [[nodiscard]] const SessionEntityMapNodeView*
  FindSessionEntityNode(const SessionEntityMapView& map, const std::int32_t entityId) noexcept
  {
    const SessionEntityMapNodeView* const head = map.head;
    if (head == nullptr) {
      return nullptr;
    }

    const SessionEntityMapNodeView* result = head;
    const SessionEntityMapNodeView* node = head->parent;
    while (node != nullptr && node != head && node->isNil == 0u) {
      if (node->key >= entityId) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    if (result == head || entityId < result->key) {
      return head;
    }

    return result;
  }

  [[nodiscard]] UserEntity* FindSessionEntityById(CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    const SessionEntityMapView& entityMap = GetSessionEntityMapView(session);
    const SessionEntityMapNodeView* const node = FindSessionEntityNode(entityMap, entityId);
    if (node == nullptr || node == entityMap.head) {
      return nullptr;
    }

    return node->value;
  }

  [[nodiscard]] const UserUnit* ResolveAttachmentParentUserUnit(UserUnit* const userUnit) noexcept
  {
    if (userUnit == nullptr) {
      return nullptr;
    }

    UserEntity* const entityView = ResolveUserEntityView(userUnit);
    const std::int32_t attachmentParentId = static_cast<std::int32_t>(entityView->mVariableData.mAttachmentParentRef);
    if (attachmentParentId == 0) {
      return nullptr;
    }

    UserEntity* const attachmentParentEntity = FindSessionEntityById(entityView->mSession, attachmentParentId);
    return attachmentParentEntity ? attachmentParentEntity->IsUserUnit() : nullptr;
  }

  [[nodiscard]] bool TransportHasQueuedUnloadCommand(const UserUnit& transportUserUnit) noexcept
  {
    const IUnit* const iunitBridge = GetIUnitBridge(&transportUserUnit);
    const Unit* const unit = iunitBridge ? iunitBridge->IsUnit() : nullptr;
    const CUnitCommandQueue* const commandQueue = unit ? unit->CommandQueue : nullptr;
    if (commandQueue == nullptr) {
      return false;
    }

    for (const WeakPtr<CUnitCommand>& weakCommand : commandQueue->mCommandVec) {
      const CUnitCommand* const command = weakCommand.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }

      const EUnitCommandType commandType = command->mVarDat.mCmdType;
      if (commandType == EUnitCommandType::UNITCOMMAND_TransportUnloadUnits) {
        return true;
      }

      if (
        commandType == EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits
        && !command->mVarDat.mEntIds.empty()
      ) {
        return true;
      }
    }

    return false;
  }

  [[nodiscard]] gpg::RType* CachedUserUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(UserUnit));
    }
    return cached;
  }

  /**
   * Address: 0x008377E0 (FUN_008377E0, func_GetUserUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `UserUnit*`, raising Lua errors for missing or
   * type-mismatched game-object payloads while allowing destroyed-object slots.
   */
  [[nodiscard]] [[maybe_unused]] UserUnit*
  GetUserUnitOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    CScriptObject** const scriptObjectSlot = SCR_FromLua_CScriptObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserUnitType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<UserUnit*>(upcast.mObj);
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("user"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("user");
    return fallbackSet;
  }
} // namespace

CScrLuaMetatableFactory<UserUnit> CScrLuaMetatableFactory<UserUnit>::sInstance{};

CScrLuaMetatableFactory<UserUnit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<UserUnit>& CScrLuaMetatableFactory<UserUnit>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x008C5CD0 (FUN_008C5CD0, Moho::CScrLuaMetatableFactory<Moho::UserUnit>::Create)
 *
 * What it does:
 * Builds the simple Lua metatable used for `UserUnit` userdata bindings.
 */
LuaPlus::LuaObject CScrLuaMetatableFactory<UserUnit>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x008BF990 (FUN_008BF990)
 *
 * std::uint8_t deleteFlags
 *
 * What it does:
 * Performs deleting-style user-unit teardown, clears user-unit-local runtime
 * ownership lanes, and conditionally releases object memory.
 */
UserUnit* UserUnit::DestroyUserUnit(const std::uint8_t deleteFlags)
{
  UserEntity* const entityView = reinterpret_cast<UserEntity*>(this);
  UserArmy* const army = GetLuaRuntimeView(this).army;
  const IUnit* const iunitBridge = GetIUnitBridge(this);

  if (army != nullptr && iunitBridge != nullptr) {
    auto& idleSets = GetUserArmyIdleSetView(army);
    const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
    if (blueprint != nullptr && blueprint->General.QuickSelectPriority <= 0) {
      if (mQueueEmptyCached) {
        if (mIsFactory) {
          (void)EraseWeakEntitySet(idleSets.factories, entityView);
        }
        if (mIsEngineer) {
          (void)EraseWeakEntitySet(idleSets.engineers, entityView);
        }
      }
    } else {
      (void)EraseWeakEntitySet(idleSets.factories, entityView);
      (void)EraseWeakEntitySet(idleSets.engineers, entityView);
    }
  }

  mSelectionSets.clear();

  if (mFactoryManager != nullptr) {
    AdvanceUserCommandManagerBySeq(mFactoryManager, std::numeric_limits<std::int32_t>::max());
    ::operator delete(mFactoryManager);
    mFactoryManager = nullptr;
  }
  if (mManager != nullptr) {
    AdvanceUserCommandManagerBySeq(mManager, std::numeric_limits<std::int32_t>::max());
    ::operator delete(mManager);
    mManager = nullptr;
  }

  if (VisionDB::Handle* const handle = GetUserUnitVisionHandle(this); handle != nullptr) {
    delete handle;
    GetUserUnitVisionHandle(this) = nullptr;
  }

  entityView->UserEntity::~UserEntity();
  if ((deleteFlags & 1u) != 0u) {
    ::operator delete(this);
  }
  return this;
}

/**
 * Address: 0x008C09B0 (FUN_008C09B0, moho::UserUnit::UpdateVisibility)
 *
 * What it does:
 * Updates mesh hidden-state from replicated visibility mode/intel bits and
 * toggles mesh-pose lock lane for non-mobile units in recon-grid mode.
 */
void UserUnit::UpdateVisibility()
{
  UserEntity* const entityView = reinterpret_cast<UserEntity*>(this);
  MeshInstance* const meshInstance = entityView->mMeshInstance;
  if (meshInstance == nullptr) {
    return;
  }

  switch (entityView->mVariableData.mVisibilityMode) {
  case EUserEntityVisibilityMode::Hidden:
    meshInstance->isHidden = 1u;
    break;
  case EUserEntityVisibilityMode::MapPlayableRect:
    meshInstance->isHidden = 0u;
    break;
  case EUserEntityVisibilityMode::ReconGrid:
    if (GetIUnitBridge(this)->IsMobile()) {
      meshInstance->isHidden = ((mIntelStateFlags & 0x08u) == 0u) ? 1u : 0u;
      return;
    }

    meshInstance->isHidden = ((mIntelStateFlags & 0x10u) == 0u) ? 1u : 0u;
    meshInstance->isLocked = ((mIntelStateFlags & 0x08u) == 0u) ? 1u : 0u;
    if (meshInstance->isLocked == 0u) {
      meshInstance->frameCounter = static_cast<std::int8_t>(MeshInstance::sFrameCounter);
      meshInstance->currInterpolant = -1.0f;
    }
    break;
  }
}

/**
 * Address: 0x008C0A30 (FUN_008C0A30, moho::UserUnit::Tick)
 *
 * What it does:
 * Advances command-manager queue state, updates idle engineer/factory weak-set
 * membership, and maintains the vision-handle lane for fog/recon tracking.
 */
void UserUnit::Tick(const std::int32_t seqNo)
{
  AdvanceUserCommandManagerBySeq(mManager, seqNo);
  if (mFactoryManager != nullptr) {
    AdvanceUserCommandManagerBySeq(mFactoryManager, seqNo);
  }

  if (IsBeingBuilt()) {
    return;
  }

  UserEntity* const entityView = reinterpret_cast<UserEntity*>(this);
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  UserArmy* const army = GetLuaRuntimeView(this).army;
  if (iunitBridge->IsDead()) {
    if (army != nullptr) {
      auto& idleSets = GetUserArmyIdleSetView(army);
      const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
      if (blueprint != nullptr && blueprint->General.QuickSelectPriority <= 0) {
        if (mQueueEmptyCached) {
          if (mIsFactory) {
            (void)EraseWeakEntitySet(idleSets.factories, entityView);
          }
          if (mIsEngineer) {
            (void)EraseWeakEntitySet(idleSets.engineers, entityView);
          }
        }
      } else {
        (void)EraseWeakEntitySet(idleSets.factories, entityView);
        (void)EraseWeakEntitySet(idleSets.engineers, entityView);
      }
    }

    if (VisionDB::Handle* const handle = GetUserUnitVisionHandle(this); handle != nullptr) {
      delete handle;
      GetUserUnitVisionHandle(this) = nullptr;
    }
    return;
  }

  const bool isQueueEmpty = GetLuaRuntimeView(this).isBusy == 0u && IsUserCommandManagerQueueEmpty(mManager);
  if (isQueueEmpty != mQueueEmptyCached) {
    if (army != nullptr) {
      auto& idleSets = GetUserArmyIdleSetView(army);
      if (mIsEngineer) {
        if (isQueueEmpty) {
          (void)InsertWeakEntitySet(idleSets.engineers, entityView);
        } else {
          (void)EraseWeakEntitySet(idleSets.engineers, entityView);
        }
      }
      if (mIsFactory) {
        if (isQueueEmpty) {
          (void)InsertWeakEntitySet(idleSets.factories, entityView);
        } else {
          (void)EraseWeakEntitySet(idleSets.factories, entityView);
        }
      }
    }
    mQueueEmptyCached = isQueueEmpty;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  const std::uint32_t visionRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::None);
  VisionDB::Handle*& visionHandle = GetUserUnitVisionHandle(this);
  if (visionRange != 0u && visionHandle == nullptr && !mIsFake) {
    const Wm3::Vector2f zero(0.0f, 0.0f);
    struct SessionVisionRuntimeView
    {
      std::uint8_t pad_0000_03C8[0x3C8];
      VisionDB visionDb; // +0x3C8
    };
    static_assert(
      offsetof(SessionVisionRuntimeView, visionDb) == 0x3C8,
      "SessionVisionRuntimeView::visionDb offset must be 0x3C8"
    );
    VisionDB& visionDb = reinterpret_cast<SessionVisionRuntimeView*>(session)->visionDb;
    visionHandle = visionDb.NewHandle(zero, zero);
  }

  if (visionHandle == nullptr) {
    return;
  }

  if (mIsFake) {
    delete visionHandle;
    visionHandle = nullptr;
    return;
  }

  bool isAlly = false;
  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  if (focusArmy != nullptr && army != nullptr) {
    isAlly = focusArmy->IsAlly(army->mArmyIndex);
  }

  const Wm3::Vector2f currentPos(entityView->mVariableData.mCurTransform.pos_.x, entityView->mVariableData.mCurTransform.pos_.z);
  const Wm3::Vector2f previousPos(
    entityView->mVariableData.mLastTransform.pos_.x, entityView->mVariableData.mLastTransform.pos_.z
  );
  visionHandle->Update(currentPos, previousPos, static_cast<float>(visionRange), isAlly);
}

/**
 * Address: 0x008B8EB0 (FUN_008B8EB0, ?UpdateEntityData@UserEntity@Moho@@UAEXABUSSTIEntityVariableData@2@@Z)
 *
 * What it does:
 * For UserUnit instances, forwards replicated variable-data updates to the
 * shared UserEntity implementation for mesh/visibility/vision refresh.
 */
void UserUnit::UpdateEntityData(const SSTIEntityVariableData& variableData)
{
  reinterpret_cast<UserEntity*>(this)->UserEntity::UpdateEntityData(variableData);
}

/**
 * Address: 0x008BF120 (FUN_008BF120)
 *
 * What it does:
 * Returns this object as the const UserUnit identity view.
 */
UserUnit const* UserUnit::IsUserUnit1() const
{
  return this;
}

/**
 * Address: 0x008BF110 (FUN_008BF110)
 *
 * What it does:
 * Returns this object as the mutable UserUnit identity view.
 */
UserUnit* UserUnit::IsUserUnit2()
{
  return this;
}

/**
 * Address: 0x008BF170 (FUN_008BF170)
 *
 * What it does:
 * Calls IUnit::GetBlueprint through the embedded +0x148 subobject and reads
 * blueprint uniform scale at +0x270.
 */
float UserUnit::GetUnitformScale() const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  return blueprint->Display.UniformScale;
}

/**
 * Address: 0x008BF150 (FUN_008BF150)
 *
 * What it does:
 * Returns the current user command-queue handle (mutable view slot).
 */
std::int32_t UserUnit::GetCommandQueue1()
{
  return EncodeUserCommandManagerHandle(mManager);
}

/**
 * Address: 0x008BF130 (FUN_008BF130)
 *
 * What it does:
 * Returns the current user command-queue handle (const view slot).
 */
std::int32_t UserUnit::GetCommandQueue2() const
{
  return EncodeUserCommandManagerHandle(mManager);
}

/**
 * Address: 0x008BF160 (FUN_008BF160)
 *
 * What it does:
 * Returns the current factory command-queue handle (mutable view slot).
 */
std::int32_t UserUnit::GetFactoryCommandQueue1()
{
  return EncodeUserCommandManagerHandle(mFactoryManager);
}

/**
 * Address: 0x008BF140 (FUN_008BF140)
 *
 * What it does:
 * Returns the current factory command-queue handle (const view slot).
 */
std::int32_t UserUnit::GetFactoryCommandQueue2() const
{
  return EncodeUserCommandManagerHandle(mFactoryManager);
}

/**
 * Address: 0x008B8530 (FUN_008B8530)
 *
 * What it does:
 * Returns replicated UI-dirty state from UserEntity variable-data bytes.
 */
bool UserUnit::RequiresUIRefresh() const
{
  return GetUiFlagView(this).requestRefreshUi != 0;
}

/**
 * Address: 0x008BEFB0 (FUN_008BEFB0)
 *
 * What it does:
 * Returns replicated "being built" state from UserEntity variable-data bytes.
 */
bool UserUnit::IsBeingBuilt() const
{
  return GetUiFlagView(this).isBeingBuilt != 0;
}

/**
 * Address: 0x008C0500 (FUN_008C0500, moho::UserUnit::Select)
 *
 * What it does:
 * Evaluates whether this user unit is currently selectable by UI selectors.
 */
bool UserUnit::Select()
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  if (iunitBridge == nullptr || !mSelectableOverride || !iunitBridge->IsMobile()) {
    return false;
  }

  const UserEntity* const entityView = reinterpret_cast<const UserEntity*>(this);
  if (entityView == nullptr) {
    return false;
  }

  const msvc8::string podCategory("POD", 3u);
  if (entityView->IsInCategory(podCategory)) {
    return false;
  }

  if (iunitBridge->IsUnitState(UNITSTATE_UnSelectable)) {
    return false;
  }

  if (iunitBridge->IsDead()) {
    return false;
  }

  if (IsBeingBuilt()) {
    const msvc8::string factoryCategory("FACTORY", 7u);
    if (!entityView->IsInCategory(factoryCategory)) {
      return false;
    }
  }

  const msvc8::string selectableCategory("SELECTABLE", 10u);
  return entityView->IsInCategory(selectableCategory);
}

/**
 * Address: 0x008C1350 (FUN_008C1350, moho::UserUnit::NotifyFocusArmyUnitDamaged)
 *
 * What it does:
 * Imports the game-main Lua module and calls
 * `OnFocusArmyUnitDamaged` with this unit's Lua object.
 */
void UserUnit::NotifyFocusArmyUnitDamaged()
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  LuaPlus::LuaObject gameMainModule = SCR_Import(session->mState, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaObject onFocusArmyUnitDamaged = gameMainModule["OnFocusArmyUnitDamaged"];
  LuaPlus::LuaFunction callback(onFocusArmyUnitDamaged);

  IUnit* const iunitBridge = GetIUnitBridge(this);
  const LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
  callback.Call_Object(unitObject);
}

/**
 * Address: 0x008C00E0 (FUN_008C00E0, moho::UserUnit::CreateMeshInstance)
 *
 * What it does:
 * Creates the unit mesh instance, applies team-color lookup parameter, and
 * wires animation poses from shared unit pose lanes when skeletons match.
 */
void UserUnit::CreateMeshInstance()
{
  UserEntity* const entityView = ResolveUserEntityView(this);
  if (entityView == nullptr || entityView->mSession == nullptr) {
    return;
  }

  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const Unit* const unitView = iunitBridge ? iunitBridge->IsUnit() : nullptr;
  const SSTIUnitVariableData* const unitVarDat = unitView ? &unitView->VarDat() : nullptr;

  const UserArmy* const army = entityView->mArmy;
  const std::int32_t playerColor = army ? static_cast<std::int32_t>(army->mVarDat.mPlayerColorBgra) : -1;
  const std::int32_t colorIndex = army ? func_GetColorIndex(playerColor) : 0;

  const float uniformScale = GetUnitformScale();
  const Wm3::Vec3f uniformMeshScale{uniformScale, uniformScale, uniformScale};

  entityView->mMeshInstance = MeshRenderer::GetInstance()->CreateMeshInstance(
    entityView->mSession->mGameTick,
    playerColor,
    static_cast<const RMeshBlueprint*>(entityView->mVariableData.mMeshBlueprint),
    uniformMeshScale,
    true,
    boost::shared_ptr<MeshMaterial>{}
  );

  if (entityView->mMeshInstance == nullptr) {
    entityView->mPosePrimary.reset();
    entityView->mPoseSecondary.reset();
    return;
  }

  std::uint32_t teamColorLookupCount = GetPlayerColorCount();
  if (teamColorLookupCount == 0u) {
    teamColorLookupCount = 1u;
  }

  const float lookupCount = static_cast<float>(teamColorLookupCount);
  float clampedColorIndex = static_cast<float>(colorIndex);
  const float maxColorIndex = lookupCount - 1.0f;
  if (clampedColorIndex > maxColorIndex) {
    clampedColorIndex = maxColorIndex;
  }
  if (clampedColorIndex < 0.0f) {
    clampedColorIndex = 0.0f;
  }
  entityView->mMeshInstance->meshColor = (clampedColorIndex + 0.5f) / lookupCount;

  const boost::shared_ptr<Mesh> mesh = entityView->mMeshInstance->GetMesh();
  const boost::shared_ptr<RScmResource> resource = mesh ? mesh->GetResource(0) : boost::shared_ptr<RScmResource>{};
  const boost::shared_ptr<const CAniSkel> skeleton = resource ? resource->GetSkeleton() : boost::shared_ptr<const CAniSkel>{};

  const boost::shared_ptr<CAniPose> priorSharedPose =
    unitVarDat ? unitVarDat->mPriorSharedPose : boost::shared_ptr<CAniPose>{};
  if (CanReuseSharedPoseForSkeleton(priorSharedPose, skeleton)) {
    entityView->mPosePrimary = priorSharedPose;
  } else {
    entityView->mPosePrimary.reset(new CAniPose(skeleton, uniformScale));
    if (entityView->mPosePrimary) {
      entityView->mPosePrimary->mLocalTransform = entityView->mVariableData.mLastTransform;
    }
  }

  const boost::shared_ptr<CAniPose> sharedPose = unitVarDat ? unitVarDat->mSharedPose : boost::shared_ptr<CAniPose>{};
  if (CanReuseSharedPoseForSkeleton(sharedPose, skeleton)) {
    entityView->mPoseSecondary = sharedPose;
  } else {
    entityView->mPoseSecondary.reset(new CAniPose(skeleton, uniformScale));
    if (entityView->mPoseSecondary) {
      entityView->mPoseSecondary->mLocalTransform = entityView->mVariableData.mCurTransform;
    }
  }
}

/**
 * Address: 0x008C04D0 (FUN_008C04D0, j_?DestroyMeshInstance@UserEntity@Moho@@MAEXXZ)
 *
 * What it does:
 * Forwards user-unit mesh teardown to the base `UserEntity` destroy path.
 */
void UserUnit::DestroyMeshInstance()
{
  auto* const entityView = reinterpret_cast<UserEntity*>(this);
  entityView->UserEntity::DestroyMeshInstance();
}

/**
 * Address: 0x008BFC50 (FUN_008BFC50)
 *
 * What it does:
 * Aggregates weapon min/max radii over runtime weapon entries filtered by
 * range category (`6` means match all categories).
 */
bool UserUnit::FindWeaponBy(
  const std::int32_t rangeCategoryFilter, float* const outMinRange, float* const outMaxRange
) const
{
  constexpr float kInitialMinRangeSentinel = std::numeric_limits<float>::max();
  constexpr float kInitialMaxRangeSentinel = std::numeric_limits<float>::lowest();

  *outMaxRange = kInitialMaxRangeSentinel;
  *outMinRange = kInitialMinRangeSentinel;

  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  const auto& weaponBlueprints = blueprint->Weapons.WeaponBlueprints;
  const auto* const weaponRuntime = reinterpret_cast<const UserUnitWeaponRuntimeView*>(mWeaponTable);

  for (std::size_t i = 0; i < weaponBlueprints.size(); ++i) {
    const auto& weaponBlueprint = weaponBlueprints[i];
    if (rangeCategoryFilter != kRangeCategoryAll &&
        rangeCategoryFilter != static_cast<std::int32_t>(weaponBlueprint.RangeCategory)) {
      continue;
    }

    const auto& weaponStats = weaponRuntime[weaponBlueprint.WeaponIndex];
    if (weaponStats.maxRange > *outMaxRange) {
      *outMaxRange = weaponStats.maxRange;
    }
    if (weaponStats.minRange <= *outMinRange) {
      *outMinRange = weaponStats.minRange;
    }
  }

  if (*outMaxRange <= kInitialMaxRangeSentinel) {
    *outMaxRange = 0.0f;
  }
  if (kInitialMinRangeSentinel <= *outMinRange) {
    *outMinRange = 0.0f;
  }

  return *outMaxRange > 0.0f || *outMinRange > 0.0f;
}

/**
 * Address: 0x008BFD70 (FUN_008BFD70)
 *
 * What it does:
 * Returns active intel ranges (`omni`, `radar`, `sonar`) unless Intel toggle
 * state currently disables this intel block.
 */
bool UserUnit::GetIntelRanges(float* const outOmniRange, float* const outRadarRange, float* const outSonarRange) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const std::uint32_t toggleCaps = iunitBridge->GetAttributes().toggleCapsMask;
  if ((toggleCaps & kToggleCapIntel) != 0u && (mIntelToggleStateMask & kToggleCapIntel) != 0u) {
    return false;
  }

  *outOmniRange = GetIntelRangeAsFloat(this, UserUnitIntelLane::Sonar);
  *outRadarRange = GetIntelRangeAsFloat(this, UserUnitIntelLane::WaterVision);
  *outSonarRange = GetIntelRangeAsFloat(this, UserUnitIntelLane::Radar);

  return *outOmniRange > 0.0f || *outRadarRange > 0.0f || *outSonarRange > 0.0f;
}

/**
 * Address: 0x008BFE50 (FUN_008BFE50)
 *
 * What it does:
 * Computes the largest active counter-intel radius from replicated intel
 * ranges plus blueprint jam/spoof maxima.
 */
bool UserUnit::GetMaxCounterIntel(float* const outMaxCounterIntelRange) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const std::uint32_t toggleCaps = iunitBridge->GetAttributes().toggleCapsMask;
  if (((toggleCaps & kToggleCapJamming) != 0u && (mIntelToggleStateMask & kToggleCapJamming) != 0u) ||
      ((toggleCaps & kToggleCapStealth) != 0u && (mIntelToggleStateMask & kToggleCapStealth) != 0u)) {
    return false;
  }

  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  const std::uint32_t spoofRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::Spoof);
  const std::uint32_t cloakRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::Cloak);
  const std::uint32_t radarStealthRange = GetIntelRangeMagnitude(this, UserUnitIntelLane::RadarStealth);

  std::uint32_t maxCounterIntel = radarStealthRange;
  if (maxCounterIntel < cloakRange) {
    maxCounterIntel = cloakRange;
  }

  std::uint32_t maxJamOrSpoof = blueprint->Intel.SpoofRadius.max;
  if (maxJamOrSpoof < blueprint->Intel.JamRadius.max) {
    maxJamOrSpoof = blueprint->Intel.JamRadius.max;
  }
  if (maxCounterIntel < maxJamOrSpoof) {
    maxCounterIntel = maxJamOrSpoof;
  }
  if (maxCounterIntel < spoofRange) {
    maxCounterIntel = spoofRange;
  }

  *outMaxCounterIntelRange = static_cast<float>(maxCounterIntel);
  return *outMaxCounterIntelRange > 0.0f;
}

/**
 * Address: 0x008BEFD0 (FUN_008BEFD0)
 *
 * What it does:
 * Returns UI mirror of auto-mode state.
 */
bool UserUnit::GetAutoMode() const
{
  return mAutoMode;
}

/**
 * Address: 0x008BEFE0 (FUN_008BEFE0)
 *
 * What it does:
 * Returns UI mirror of auto-surface mode state.
 */
bool UserUnit::IsAutoSurfaceMode() const
{
  return mAutoSurfaceMode;
}

/**
 * Address: 0x008BEFF0 (FUN_008BEFF0)
 *
 * What it does:
 * Returns UI mirror of repeat-queue state.
 */
bool UserUnit::Func1() const
{
  return mRepeatQueueEnabled;
}

/**
 * Address: 0x008BF000 (FUN_008BF000)
 *
 * What it does:
 * Returns whether overcharge is currently paused in UI state.
 */
bool UserUnit::IsOverchargePaused() const
{
  return mOverchargePaused;
}

/**
 * Address: 0x008BF010 (FUN_008BF010)
 *
 * What it does:
 * Returns the in-object custom-name storage anchor at +0x1DC.
 */
char* UserUnit::GetCustomName()
{
  return mCustomNameStorage;
}

/**
 * Address: 0x008BF060 (FUN_008BF060)
 *
 * What it does:
 * Returns UI fuel ratio.
 */
float UserUnit::GetFuel() const
{
  return mFuelRatio;
}

/**
 * Address: 0x008BF070 (FUN_008BF070)
 *
 * What it does:
 * Returns UI shield ratio.
 */
float UserUnit::GetShield() const
{
  return mShieldRatio;
}

/**
 * Address: 0x00893080 (FUN_00893080)
 *
 * What it does:
 * Inserts one selection-set name into this unit's persisted selection-set
 * container.
 */
void UserUnit::AddSelectionSet(const char* const selectionSetName)
{
  msvc8::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  (void)mSelectionSets.insert(selectionSet);
}

/**
 * Address: 0x008BF190 (FUN_008BF190)
 *
 * What it does:
 * Removes one selection-set name from this unit's persisted selection-set
 * container.
 */
void UserUnit::RemoveSelectionSet(const char* const selectionSetName)
{
  msvc8::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  (void)mSelectionSets.erase(selectionSet);
}

/**
 * Address: 0x008BF220 (FUN_008BF220)
 *
 * What it does:
 * Returns whether this unit currently stores one named selection-set key.
 */
bool UserUnit::HasSelectionSet(const char* const selectionSetName) const
{
  msvc8::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  return mSelectionSets.find(selectionSet) != mSelectionSets.end();
}

bool UserUnit::IsRepeatQueueEnabled() const
{
  return Func1();
}

/**
 * Address: 0x008C0D30 (FUN_008C0D30, Moho::UserUnit::CanAttackTarget)
 *
 * What it does:
 * Evaluates attack viability against one optional target entity by applying
 * movement-layer overlays, weapon layer/category filters, and optional
 * range-gating checks.
 */
bool UserUnit::CanAttackTarget(const UserEntity* targetEntity, bool rangeCheck) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const UserEntity* const selfEntity = reinterpret_cast<const UserEntity*>(this);
  const REntityBlueprint* const targetBlueprint = (targetEntity != nullptr) ? targetEntity->mParams.mBlueprint : nullptr;

  if (targetBlueprint != nullptr) {
    if (iunitBridge->IsMobile() && targetEntity != nullptr) {
      const std::uint32_t targetLayerMask = targetEntity->mVariableData.mLayerMask;

      if (mAutoSurfaceMode) {
        if ((targetLayerMask & static_cast<std::uint32_t>(LAYER_Air)) != 0u
            && IsUnitInOverlayCategory(this, kOverlayCategoryAntiAir)) {
          return true;
        }
        if ((targetLayerMask & static_cast<std::uint32_t>(LAYER_Land)) != 0u
            && IsUnitInOverlayCategory(this, kOverlayCategoryDirectFire)) {
          return true;
        }
      }

      const std::uint32_t selfLayerMask = selfEntity->mVariableData.mLayerMask;
      const RUnitBlueprint* const selfBlueprint = iunitBridge->GetBlueprint();
      const bool selfOnLand = (selfLayerMask & static_cast<std::uint32_t>(LAYER_Land)) != 0u;
      const bool selfOnSeabed = (selfLayerMask & static_cast<std::uint32_t>(LAYER_Seabed)) != 0u;
      const bool targetUnderwater = (targetLayerMask
                                     & (static_cast<std::uint32_t>(LAYER_Sub) | static_cast<std::uint32_t>(LAYER_Seabed)))
                                    != 0u;
      const bool targetOnLand = (targetLayerMask & static_cast<std::uint32_t>(LAYER_Land)) != 0u;

      if (selfOnLand && targetUnderwater) {
        const ERuleBPUnitMovementType motionType = selfBlueprint->Physics.MotionType;
        if ((motionType == RULEUMT_Amphibious || motionType == RULEUMT_AmphibiousFloating)
            && IsUnitInOverlayCategory(this, kOverlayCategoryAntiNavy)) {
          return true;
        }
      } else if (selfOnSeabed && targetOnLand
                 && selfBlueprint->Physics.MotionType == RULEUMT_Amphibious
                 && IsUnitInOverlayCategory(this, kOverlayCategoryDirectFire)) {
        return true;
      }
    }

    const float targetDistance = rangeCheck
      ? PlanarDistanceXZ(selfEntity->mVariableData.mCurTransform.pos_, targetEntity->mVariableData.mCurTransform.pos_)
      : 0.0f;
    const std::uint32_t targetLayerMask = targetEntity->mVariableData.mLayerMask;

    const UserUnitWeaponRuntimeView* weaponInfo = GetWeaponInfoBegin(this);
    const UserUnitWeaponRuntimeView* const weaponInfoEnd = GetWeaponInfoEnd(this);
    while (weaponInfo != weaponInfoEnd) {
      if ((static_cast<std::uint32_t>(weaponInfo->layerMask) & targetLayerMask) != 0u
          && WeaponAllowsBlueprint(*weaponInfo, targetBlueprint)) {
        if (iunitBridge->IsMobile() || !rangeCheck
            || (weaponInfo->minRange <= targetDistance && targetDistance <= weaponInfo->maxRange)) {
          return true;
        }
      }
      ++weaponInfo;
    }
    return false;
  }

  if (!rangeCheck) {
    return false;
  }

  if (iunitBridge->IsMobile()) {
    return true;
  }

  CWldSession* const activeSession = WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return false;
  }

  const float cursorDistance = PlanarDistanceXZ(selfEntity->mVariableData.mCurTransform.pos_, activeSession->CursorWorldPos);
  const UserUnitWeaponRuntimeView* weaponInfo = GetWeaponInfoBegin(this);
  const UserUnitWeaponRuntimeView* const weaponInfoEnd = GetWeaponInfoEnd(this);
  while (weaponInfo != weaponInfoEnd) {
    if (cursorDistance > weaponInfo->minRange && weaponInfo->maxRange > cursorDistance) {
      return true;
    }
    ++weaponInfo;
  }

  return false;
}

/**
 * Address: 0x008C1610 (FUN_008C1610, ?USERUNIT_WithinBuildDistance@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@@Z)
 *
 * What it does:
 * Checks whether all selected user units are within each unit's own
 * `Economy.MaxBuildDistance` from the snapped world-space center of one
 * candidate blueprint footprint.
 */
bool moho::USERUNIT_WithinBuildDistance(
  CWldSession& session, const RUnitBlueprint* const buildBlueprint, const SCoordsVec2& buildPosition
)
{
  msvc8::vector<UserUnit*> selectedUnits{};
  session.GetSelectionUnits(selectedUnits);
  if (selectedUnits.empty()) {
    return false;
  }

  const float halfSizeX = static_cast<float>(buildBlueprint->mFootprint.mSizeX) * 0.5f;
  const float halfSizeZ = static_cast<float>(buildBlueprint->mFootprint.mSizeZ) * 0.5f;
  const std::int32_t anchorCellX = static_cast<std::int32_t>(buildPosition.x - halfSizeX);
  const std::int32_t anchorCellZ = static_cast<std::int32_t>(buildPosition.z - halfSizeZ);

  const float snappedBuildCenterX = static_cast<float>(anchorCellX) + halfSizeX;
  const float snappedBuildCenterZ = static_cast<float>(anchorCellZ) + halfSizeZ;

  for (std::size_t i = 0; i < selectedUnits.size(); ++i) {
    UserUnit* const selected = selectedUnits[i];
    if (selected == nullptr) {
      continue;
    }

    const IUnit* const iunit = GetIUnitBridge(selected);
    const RUnitBlueprint* const selectedBlueprint = iunit->GetBlueprint();
    const float maxBuildDistance = selectedBlueprint->Economy.MaxBuildDistance;
    if (maxBuildDistance <= 0.0f) {
      continue;
    }

    const Wm3::Vec3f& unitPosition = iunit->GetPosition();
    const float dx = unitPosition.x - snappedBuildCenterX;
    const float dz = unitPosition.z - snappedBuildCenterZ;
    const float planarDistance = std::sqrt((dx * dx) + (dz * dz));
    if (planarDistance > maxBuildDistance) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x008C2010 (FUN_008C2010, cfunc_UserUnitCanAttackTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitCanAttackTargetL`.
 */
int moho::cfunc_UserUnitCanAttackTarget(lua_State* const luaContext)
{
  return cfunc_UserUnitCanAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2030 (FUN_008C2030, func_UserUnitCanAttackTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:CanAttackTarget(target, rangeCheck)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitCanAttackTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitCanAttackTargetName,
    &moho::cfunc_UserUnitCanAttackTarget,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitCanAttackTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2090 (FUN_008C2090, cfunc_UserUnitCanAttackTargetL)
 *
 * What it does:
 * Resolves one user-unit, one target-entity, and one range-check flag; then
 * pushes whether the unit can attack that target.
 */
int moho::cfunc_UserUnitCanAttackTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitCanAttackTargetHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const LuaPlus::LuaObject targetEntityObject(LuaPlus::LuaStackObject(state, 2));
  UserEntity* const targetEntity = SCR_FromLua_UserEntity(targetEntityObject, state);
  const bool rangeCheck = LuaPlus::LuaStackObject(state, 3).GetBoolean();
  (void)GetIUnitBridge(userUnit)->GetBlueprint();

  const bool canAttack = targetEntity != nullptr && userUnit->CanAttackTarget(targetEntity, rangeCheck);
  lua_pushboolean(rawState, canAttack ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C21D0 (FUN_008C21D0, cfunc_UserUnitGetFootPrintSize)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetFootPrintSizeL`.
 */
int moho::cfunc_UserUnitGetFootPrintSize(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFootPrintSizeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C21F0 (FUN_008C21F0, func_UserUnitGetFootPrintSize_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetFootPrintSize()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetFootPrintSize_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetFootPrintSizeName,
    &moho::cfunc_UserUnitGetFootPrintSize,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetFootPrintSizeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2250 (FUN_008C2250, cfunc_UserUnitGetFootPrintSizeL)
 *
 * What it does:
 * Returns the larger footprint axis (`max(SizeX, SizeZ)`) for one user unit.
 */
int moho::cfunc_UserUnitGetFootPrintSizeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetFootPrintSizeHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const RUnitBlueprint* const blueprint = GetIUnitBridge(userUnit)->GetBlueprint();
  const std::uint8_t sizeX = blueprint->mFootprint.mSizeX;
  const std::uint8_t sizeZ = blueprint->mFootprint.mSizeZ;
  const std::uint8_t maxSize = sizeX < sizeZ ? sizeZ : sizeX;
  lua_pushnumber(rawState, static_cast<float>(maxSize));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2340 (FUN_008C2340, cfunc_UserUnitGetUnitId)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetUnitIdL`.
 */
int moho::cfunc_UserUnitGetUnitId(lua_State* const luaContext)
{
  return cfunc_UserUnitGetUnitIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2360 (FUN_008C2360, func_UserUnitGetUnitId_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetUnitId()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetUnitId_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetUnitIdName,
    &moho::cfunc_UserUnitGetUnitId,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetUnitIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C23C0 (FUN_008C23C0, cfunc_UserUnitGetUnitIdL)
 *
 * What it does:
 * Pushes one user-unit blueprint id string.
 */
int moho::cfunc_UserUnitGetUnitIdL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetUnitIdHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const RUnitBlueprint* const blueprint = GetIUnitBridge(userUnit)->GetBlueprint();
  lua_pushstring(rawState, blueprint->mBlueprintId.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2620 (FUN_008C2620, cfunc_UserUnitGetBlueprint)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBlueprintL`.
 */
int moho::cfunc_UserUnitGetBlueprint(lua_State* const luaContext)
{
  return cfunc_UserUnitGetBlueprintL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2640 (FUN_008C2640, func_UserUnitGetBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the `blueprint = UserUnit:GetBlueprint()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetBlueprintName,
    &moho::cfunc_UserUnitGetBlueprint,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C26A0 (FUN_008C26A0, cfunc_UserUnitGetBlueprintL)
 *
 * What it does:
 * Resolves one user unit and pushes its Lua blueprint object.
 */
int moho::cfunc_UserUnitGetBlueprintL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetBlueprintHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const RUnitBlueprint* const blueprint = GetIUnitBridge(userUnit)->GetBlueprint();
  LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
  luaBlueprint.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C2B60 (FUN_008C2B60, cfunc_UserUnitIsAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsAutoModeL`.
 */
int moho::cfunc_UserUnitIsAutoMode(lua_State* const luaContext)
{
  return cfunc_UserUnitIsAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2B80 (FUN_008C2B80, func_UserUnitIsAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsAutoMode()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsAutoModeName,
    &moho::cfunc_UserUnitIsAutoMode,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2BE0 (FUN_008C2BE0, cfunc_UserUnitIsAutoModeL)
 *
 * What it does:
 * Pushes one user-unit auto-mode flag.
 */
int moho::cfunc_UserUnitIsAutoModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsAutoModeHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->GetAutoMode() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2CA0 (FUN_008C2CA0, cfunc_UserUnitIsAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitIsAutoSurfaceModeL`.
 */
int moho::cfunc_UserUnitIsAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_UserUnitIsAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2CC0 (FUN_008C2CC0, func_UserUnitIsAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsAutoSurfaceMode()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsAutoSurfaceModeName,
    &moho::cfunc_UserUnitIsAutoSurfaceMode,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsAutoSurfaceModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2D20 (FUN_008C2D20, cfunc_UserUnitIsAutoSurfaceModeL)
 *
 * What it does:
 * Pushes one user-unit auto-surface-mode flag.
 */
int moho::cfunc_UserUnitIsAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsAutoSurfaceModeHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->IsAutoSurfaceMode() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2DE0 (FUN_008C2DE0, cfunc_UserUnitIsRepeatQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsRepeatQueueL`.
 */
int moho::cfunc_UserUnitIsRepeatQueue(lua_State* const luaContext)
{
  return cfunc_UserUnitIsRepeatQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2E00 (FUN_008C2E00, func_UserUnitIsRepeatQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsRepeatQueue()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsRepeatQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsRepeatQueueName,
    &moho::cfunc_UserUnitIsRepeatQueue,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsRepeatQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2E60 (FUN_008C2E60, cfunc_UserUnitIsRepeatQueueL)
 *
 * What it does:
 * Pushes one user-unit repeat-queue flag.
 */
int moho::cfunc_UserUnitIsRepeatQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsRepeatQueueHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->IsRepeatQueueEnabled() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C24A0 (FUN_008C24A0, cfunc_UserUnitGetEntityId)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_UserUnitGetEntityIdL`.
 */
int moho::cfunc_UserUnitGetEntityId(lua_State* const luaContext)
{
  return cfunc_UserUnitGetEntityIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C24C0 (FUN_008C24C0, func_UserUnitGetEntityId_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetEntityId()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetEntityId_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetEntityIdName,
    &moho::cfunc_UserUnitGetEntityId,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetEntityIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2520 (FUN_008C2520, cfunc_UserUnitGetEntityIdL)
 *
 * What it does:
 * Validates one `UserUnit` argument and pushes the unit entity id as string.
 */
int moho::cfunc_UserUnitGetEntityIdL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetEntityIdHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserEntity* const entityView = ResolveUserEntityView(userUnit);
  const std::int32_t entityId = entityView != nullptr ? static_cast<std::int32_t>(entityView->mParams.mEntityId) : 0;
  const msvc8::string entityIdText = gpg::STR_Printf("%d", entityId);

  const char* const entityIdChars = entityIdText.c_str();
  lua_pushstring(rawState, entityIdChars ? entityIdChars : "");
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2790 (FUN_008C2790, cfunc_UserUnitHasUnloadCommandQueuedUp)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitHasUnloadCommandQueuedUpL`.
 */
int moho::cfunc_UserUnitHasUnloadCommandQueuedUp(lua_State* const luaContext)
{
  return cfunc_UserUnitHasUnloadCommandQueuedUpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C27B0 (FUN_008C27B0, func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:HasUnloadCommandQueuedUp()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitHasUnloadCommandQueuedUpName,
    &moho::cfunc_UserUnitHasUnloadCommandQueuedUp,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitHasUnloadCommandQueuedUpHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2810 (FUN_008C2810, cfunc_UserUnitHasUnloadCommandQueuedUpL)
 *
 * What it does:
 * Returns whether the transport this unit is attached to already has an
 * unload command queued.
 */
int moho::cfunc_UserUnitHasUnloadCommandQueuedUpL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitHasUnloadCommandQueuedUpHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserUnit* const attachmentParentUserUnit = ResolveAttachmentParentUserUnit(userUnit);

  const bool hasUnloadCommandQueued =
    attachmentParentUserUnit != nullptr && TransportHasQueuedUnloadCommand(*attachmentParentUserUnit);
  lua_pushboolean(rawState, hasUnloadCommandQueued ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C29D0 (FUN_008C29D0, cfunc_UserUnitProcessInfo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitProcessInfoL`.
 */
int moho::cfunc_UserUnitProcessInfo(lua_State* const luaContext)
{
  return cfunc_UserUnitProcessInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C29F0 (FUN_008C29F0, func_UserUnitProcessInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:ProcessInfoPair(key, value)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitProcessInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitProcessInfoName,
    &moho::cfunc_UserUnitProcessInfo,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitProcessInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2A50 (FUN_008C2A50, cfunc_UserUnitProcessInfoL)
 *
 * What it does:
 * Validates one `UserUnit`, one key string, and one value string, then
 * forwards the pair through `ISTIDriver::ProcessInfoPair`.
 */
int moho::cfunc_UserUnitProcessInfoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitProcessInfoHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  UserEntity* const entityView = ResolveUserEntityView(userUnit);

  const LuaPlus::LuaStackObject keyArg(state, 2);
  const char* infoKey = lua_tostring(rawState, 2);
  if (infoKey == nullptr) {
    keyArg.TypeError("string");
    infoKey = "";
  }

  const LuaPlus::LuaStackObject valueArg(state, 3);
  const char* infoValue = lua_tostring(rawState, 3);
  if (infoValue == nullptr) {
    valueArg.TypeError("string");
    infoValue = "";
  }

  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
    activeDriver->ProcessInfoPair(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(entityView->mParams.mEntityId)),
      infoKey,
      infoValue
    );
  }

  return 0;
}

/**
 * Address: 0x008C3580 (FUN_008C3580, cfunc_UserUnitSetCustomName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitSetCustomNameL`.
 */
int moho::cfunc_UserUnitSetCustomName(lua_State* const luaContext)
{
  return cfunc_UserUnitSetCustomNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C35A0 (FUN_008C35A0, func_UserUnitSetCustomName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:SetCustomName(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitSetCustomName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitSetCustomNameName,
    &moho::cfunc_UserUnitSetCustomName,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitSetCustomNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3600 (FUN_008C3600, cfunc_UserUnitSetCustomNameL)
 *
 * What it does:
 * Validates one `UserUnit` plus name string, then forwards
 * `("CustomName", name)` through `ISTIDriver::ProcessInfoPair`.
 */
int moho::cfunc_UserUnitSetCustomNameL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitSetCustomNameHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject nameArg(state, 2);
  const char* customName = lua_tostring(rawState, 2);
  if (customName == nullptr) {
    nameArg.TypeError("string");
    customName = "";
  }

  UserEntity* const entityView = ResolveUserEntityView(userUnit);
  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
    activeDriver->ProcessInfoPair(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(entityView->mParams.mEntityId)),
      kUserUnitSetCustomNameInfoKey,
      customName
    );
  }

  return 0;
}

/**
 * Address: 0x008C3880 (FUN_008C3880, cfunc_UserUnitAddSelectionSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitAddSelectionSetL`.
 */
int moho::cfunc_UserUnitAddSelectionSet(lua_State* const luaContext)
{
  return cfunc_UserUnitAddSelectionSetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C38A0 (FUN_008C38A0, func_UserUnitAddSelectionSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:AddSelectionSet(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitAddSelectionSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitAddSelectionSetName,
    &moho::cfunc_UserUnitAddSelectionSet,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitAddSelectionSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3900 (FUN_008C3900, cfunc_UserUnitAddSelectionSetL)
 *
 * What it does:
 * Resolves one `UserUnit` plus one selection-set name and inserts the name
 * into the unit's selection-set container.
 */
int moho::cfunc_UserUnitAddSelectionSetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitAddSelectionSetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject selectionSetArg(state, 2);
  const char* selectionSetName = lua_tostring(rawState, 2);
  if (selectionSetName == nullptr) {
    selectionSetArg.TypeError("string");
    selectionSetName = "";
  }

  userUnit->AddSelectionSet(selectionSetName);
  return 0;
}

/**
 * Address: 0x008C39E0 (FUN_008C39E0, cfunc_UserUnitRemoveSelectionSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitRemoveSelectionSetL`.
 */
int moho::cfunc_UserUnitRemoveSelectionSet(lua_State* const luaContext)
{
  return cfunc_UserUnitRemoveSelectionSetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3A00 (FUN_008C3A00, func_UserUnitRemoveSelectionSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:RemoveSelectionSet(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitRemoveSelectionSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitRemoveSelectionSetName,
    &moho::cfunc_UserUnitRemoveSelectionSet,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitRemoveSelectionSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3A60 (FUN_008C3A60, cfunc_UserUnitRemoveSelectionSetL)
 *
 * What it does:
 * Resolves one `UserUnit` plus one selection-set name and erases that name
 * from the unit's selection-set container.
 */
int moho::cfunc_UserUnitRemoveSelectionSetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitRemoveSelectionSetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject selectionSetArg(state, 2);
  const char* selectionSetName = lua_tostring(rawState, 2);
  if (selectionSetName == nullptr) {
    selectionSetArg.TypeError("string");
    selectionSetName = "";
  }

  userUnit->RemoveSelectionSet(selectionSetName);
  return 0;
}

/**
 * Address: 0x008C3CD0 (FUN_008C3CD0, cfunc_UserUnitGetSelectionSets)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetSelectionSetsL`.
 */
int moho::cfunc_UserUnitGetSelectionSets(lua_State* const luaContext)
{
  return cfunc_UserUnitGetSelectionSetsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3CF0 (FUN_008C3CF0, func_UserUnitGetSelectionSets_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetSelectionSets()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetSelectionSets_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetSelectionSetsName,
    &moho::cfunc_UserUnitGetSelectionSets,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetSelectionSetsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3D50 (FUN_008C3D50, cfunc_UserUnitGetSelectionSetsL)
 *
 * What it does:
 * Returns a Lua array of selection-set names currently attached to one
 * `UserUnit`.
 */
int moho::cfunc_UserUnitGetSelectionSetsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetSelectionSetsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable;
  resultTable.AssignNewTable(state, static_cast<int>(userUnit->mSelectionSets.size()), 0);

  int luaIndex = 1;
  for (const msvc8::string& selectionSetName : userUnit->mSelectionSets) {
    resultTable.SetString(luaIndex++, selectionSetName.c_str());
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C2F20 (FUN_008C2F20, cfunc_UserUnitIsInCategory)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitIsInCategoryL`.
 */
int moho::cfunc_UserUnitIsInCategory(lua_State* const luaContext)
{
  return cfunc_UserUnitIsInCategoryL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2F40 (FUN_008C2F40, func_UserUnitIsInCategory_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsInCategory(category)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitIsInCategory_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsInCategoryName,
    &moho::cfunc_UserUnitIsInCategory,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsInCategoryHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2FA0 (FUN_008C2FA0, cfunc_UserUnitIsInCategoryL)
 *
 * What it does:
 * Validates one category string and returns whether the input user-unit is
 * a member of that category.
 */
int moho::cfunc_UserUnitIsInCategoryL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsInCategoryHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  const LuaPlus::LuaStackObject categoryArg(state, 2);
  const char* categoryText = lua_tostring(rawState, 2);
  if (categoryText == nullptr) {
    categoryArg.TypeError("string");
    categoryText = "";
  }

  const msvc8::string category(categoryText);
  const UserEntity* const entityView = ResolveUserEntityView(userUnit);
  const bool inCategory = entityView != nullptr && entityView->IsInCategory(category);
  lua_pushboolean(rawState, inCategory ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C3EA0 (FUN_008C3EA0, cfunc_UserUnitGetHealth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetHealthL`.
 */
int moho::cfunc_UserUnitGetHealth(lua_State* const luaContext)
{
  return cfunc_UserUnitGetHealthL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3EC0 (FUN_008C3EC0, func_UserUnitGetHealth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetHealth()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetHealth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetHealthName,
    &moho::cfunc_UserUnitGetHealth,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetHealthHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3F20 (FUN_008C3F20, cfunc_UserUnitGetHealthL)
 *
 * What it does:
 * Returns current health for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetHealthL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetHealthHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserEntity* const entityView = ResolveUserEntityView(userUnit);
  lua_pushnumber(rawState, entityView->mVariableData.mHealth);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C3FE0 (FUN_008C3FE0, cfunc_UserUnitGetMaxHealth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetMaxHealthL`.
 */
int moho::cfunc_UserUnitGetMaxHealth(lua_State* const luaContext)
{
  return cfunc_UserUnitGetMaxHealthL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4000 (FUN_008C4000, func_UserUnitGetMaxHealth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetMaxHealth()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetMaxHealth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetMaxHealthName,
    &moho::cfunc_UserUnitGetMaxHealth,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetMaxHealthHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4060 (FUN_008C4060, cfunc_UserUnitGetMaxHealthL)
 *
 * What it does:
 * Returns max health for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetMaxHealthL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetMaxHealthHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserEntity* const entityView = ResolveUserEntityView(userUnit);
  lua_pushnumber(rawState, entityView->mVariableData.mMaxHealth);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4120 (FUN_008C4120, cfunc_UserUnitGetBuildRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBuildRateL`.
 */
int moho::cfunc_UserUnitGetBuildRate(lua_State* const luaContext)
{
  return cfunc_UserUnitGetBuildRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4140 (FUN_008C4140, func_UserUnitGetBuildRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetBuildRate()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetBuildRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetBuildRateName,
    &moho::cfunc_UserUnitGetBuildRate,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetBuildRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C41A0 (FUN_008C41A0, cfunc_UserUnitGetBuildRateL)
 *
 * What it does:
 * Returns current build-rate value for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetBuildRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetBuildRateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const IUnit* const iunit = GetIUnitBridge(userUnit);
  const UnitAttributes& attributes = iunit->GetAttributes();
  lua_pushnumber(rawState, static_cast<lua_Number>(attributes.buildRate));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4270 (FUN_008C4270, cfunc_UserUnitIsOverchargePaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsOverchargePausedL`.
 */
int moho::cfunc_UserUnitIsOverchargePaused(lua_State* const luaContext)
{
  return cfunc_UserUnitIsOverchargePausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4290 (FUN_008C4290, func_UserUnitIsOverchargePaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsOverchargePaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitIsOverchargePaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsOverchargePausedName,
    &moho::cfunc_UserUnitIsOverchargePaused,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsOverchargePausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C42F0 (FUN_008C42F0, cfunc_UserUnitIsOverchargePausedL)
 *
 * What it does:
 * Returns overcharge-paused state for one user-unit as Lua boolean.
 */
int moho::cfunc_UserUnitIsOverchargePausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsOverchargePausedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->IsOverchargePaused() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C43B0 (FUN_008C43B0, cfunc_UserUnitIsDead)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsDeadL`.
 */
int moho::cfunc_UserUnitIsDead(lua_State* const luaContext)
{
  return cfunc_UserUnitIsDeadL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C43D0 (FUN_008C43D0, func_UserUnitIsDead_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsDead()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitIsDead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsDeadName,
    &moho::cfunc_UserUnitIsDead,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsDeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4430 (FUN_008C4430, cfunc_UserUnitIsDeadL)
 *
 * What it does:
 * Returns true when input user-unit is missing or reports dead.
 */
int moho::cfunc_UserUnitIsDeadL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsDeadHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  const bool isDead = (userUnit == nullptr) || GetIUnitBridge(userUnit)->IsDead();
  lua_pushboolean(rawState, isDead ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4DA0 (FUN_008C4DA0, cfunc_UserUnitGetFuelRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFuelRatioL`.
 */
int moho::cfunc_UserUnitGetFuelRatio(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFuelRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4DC0 (FUN_008C4DC0, func_UserUnitGetFuelRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetFuelRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetFuelRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetFuelRatioName,
    &moho::cfunc_UserUnitGetFuelRatio,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetFuelRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4E20 (FUN_008C4E20, cfunc_UserUnitGetFuelRatioL)
 *
 * What it does:
 * Returns current fuel ratio for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetFuelRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetFuelRatioHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushnumber(rawState, userUnit->GetFuel());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4EE0 (FUN_008C4EE0, cfunc_UserUnitGetShieldRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetShieldRatioL`.
 */
int moho::cfunc_UserUnitGetShieldRatio(lua_State* const luaContext)
{
  return cfunc_UserUnitGetShieldRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4F00 (FUN_008C4F00, func_UserUnitGetShieldRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetShieldRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetShieldRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetShieldRatioName,
    &moho::cfunc_UserUnitGetShieldRatio,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetShieldRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4F60 (FUN_008C4F60, cfunc_UserUnitGetShieldRatioL)
 *
 * What it does:
 * Returns current shield ratio for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetShieldRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetShieldRatioHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushnumber(rawState, userUnit->GetShield());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C5020 (FUN_008C5020, cfunc_UserUnitGetWorkProgress)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetWorkProgressL`.
 */
int moho::cfunc_UserUnitGetWorkProgress(lua_State* const luaContext)
{
  return cfunc_UserUnitGetWorkProgressL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5040 (FUN_008C5040, func_UserUnitGetWorkProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetWorkProgress()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetWorkProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetWorkProgressName,
    &moho::cfunc_UserUnitGetWorkProgress,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetWorkProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C50A0 (FUN_008C50A0, cfunc_UserUnitGetWorkProgressL)
 *
 * What it does:
 * Returns current unit work-progress ratio as Lua number.
 */
int moho::cfunc_UserUnitGetWorkProgressL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetWorkProgressHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushnumber(rawState, userUnit->mWorkProgress);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C30E0 (FUN_008C30E0, cfunc_UserUnitGetStat)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetStatL`.
 */
int moho::cfunc_UserUnitGetStat(lua_State* const luaContext)
{
  return cfunc_UserUnitGetStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3100 (FUN_008C3100, func_UserUnitGetStat_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetStat(name[, defaultVal])` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetStatName,
    &moho::cfunc_UserUnitGetStat,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3160 (FUN_008C3160, cfunc_UserUnitGetStatL)
 *
 * What it does:
 * Resolves one stat path and pushes the resolved stat-item Lua table (or
 * `nil`) with optional default-type dispatch.
 */
int moho::cfunc_UserUnitGetStatL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kUserUnitGetStatHelpText, 2, 3, argumentCount);
  }

  lua_settop(rawState, 3);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  IUnit* const iunit = GetIUnitBridge(userUnit);

  StatItem* statItem = nullptr;
  if (lua_type(rawState, 3) == LUA_TNIL) {
    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }
    statItem = iunit->GetStat(statName);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      defaultArg.TypeError("integer");
    }
    const int defaultValue = defaultArg.GetInteger();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }

    statItem = iunit->GetStat(statName, defaultValue);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const float defaultValue = defaultArg.GetNumber();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = iunit->GetStat(statName, defaultValue);
  } else {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const char* const defaultString = defaultArg.GetString();
    const std::string defaultValue = defaultString ? std::string(defaultString) : std::string();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = iunit->GetStat(statName, defaultValue);
  }

  if (statItem != nullptr) {
    LuaPlus::LuaObject statTable;
    STAT_GetLuaTable(state, statItem, statTable);
    statTable.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C3440 (FUN_008C3440, cfunc_UserUnitIsStunned)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsStunnedL`.
 */
int moho::cfunc_UserUnitIsStunned(lua_State* const luaContext)
{
  return cfunc_UserUnitIsStunnedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3460 (FUN_008C3460, func_UserUnitIsStunned_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsStunned()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsStunned_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsStunnedName,
    &moho::cfunc_UserUnitIsStunned,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsStunnedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C34C0 (FUN_008C34C0, cfunc_UserUnitIsStunnedL)
 *
 * What it does:
 * Pushes one stunned-state boolean from replicated user-unit runtime state.
 */
int moho::cfunc_UserUnitIsStunnedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsStunnedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, GetLuaRuntimeView(userUnit).stunTicks != 0 ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C3700 (FUN_008C3700, cfunc_UserUnitGetCustomName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetCustomNameL`.
 */
int moho::cfunc_UserUnitGetCustomName(lua_State* const luaContext)
{
  return cfunc_UserUnitGetCustomNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3720 (FUN_008C3720, func_UserUnitGetCustomName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetCustomName()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetCustomName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetCustomNameName,
    &moho::cfunc_UserUnitGetCustomName,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetCustomNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3780 (FUN_008C3780, cfunc_UserUnitGetCustomNameL)
 *
 * What it does:
 * Pushes one custom-name string (or `nil` when empty).
 */
int moho::cfunc_UserUnitGetCustomNameL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetCustomNameHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  if (userUnit != nullptr) {
    const msvc8::string& customName = GetLuaRuntimeView(userUnit).customName;
    if (!customName.empty()) {
      lua_pushstring(rawState, customName.c_str());
      (void)lua_gettop(rawState);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  }

  return 1;
}

/**
 * Address: 0x008C3B40 (FUN_008C3B40, cfunc_UserUnitHasSelectionSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitHasSelectionSetL`.
 */
int moho::cfunc_UserUnitHasSelectionSet(lua_State* const luaContext)
{
  return cfunc_UserUnitHasSelectionSetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3B60 (FUN_008C3B60, func_UserUnitHasSelectionSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:HasSelectionSet(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitHasSelectionSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitHasSelectionSetName,
    &moho::cfunc_UserUnitHasSelectionSet,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitHasSelectionSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3BC0 (FUN_008C3BC0, cfunc_UserUnitHasSelectionSetL)
 *
 * What it does:
 * Pushes one boolean membership result for the provided selection-set name.
 */
int moho::cfunc_UserUnitHasSelectionSetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitHasSelectionSetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit != nullptr) {
    const LuaPlus::LuaStackObject selectionSetNameArg(state, 2);
    const char* const selectionSetName = lua_tostring(rawState, 2);
    if (selectionSetName == nullptr) {
      selectionSetNameArg.TypeError("string");
    }

    const bool hasSelectionSet = userUnit->HasSelectionSet(selectionSetName);
    lua_pushboolean(rawState, hasSelectionSet ? 1 : 0);
    (void)lua_gettop(rawState);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C4500 (FUN_008C4500, cfunc_UserUnitIsIdle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsIdleL`.
 */
int moho::cfunc_UserUnitIsIdle(lua_State* const luaContext)
{
  return cfunc_UserUnitIsIdleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4520 (FUN_008C4520, func_UserUnitIsIdle_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsIdle()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsIdle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitIsIdleName,
    &moho::cfunc_UserUnitIsIdle,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsIdleHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4580 (FUN_008C4580, cfunc_UserUnitIsIdleL)
 *
 * What it does:
 * Pushes one idle-state boolean derived from busy + queue-empty state.
 */
int moho::cfunc_UserUnitIsIdleL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitIsIdleHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);

  bool isIdle = false;
  if (userUnit != nullptr && GetLuaRuntimeView(userUnit).isBusy == 0u) {
    const UserCommandQueueRangeView* const commandRange = ResolveUserCommandQueueRange(userUnit->GetCommandQueue2());
    if (commandRange == nullptr || commandRange->begin == commandRange->end) {
      isIdle = true;
    }
  }

  lua_pushboolean(rawState, isIdle ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4660 (FUN_008C4660, cfunc_UserUnitGetFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFocusL`.
 */
int moho::cfunc_UserUnitGetFocus(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFocusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4680 (FUN_008C4680, func_UserUnitGetFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetFocus()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetFocusName,
    &moho::cfunc_UserUnitGetFocus,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C46E0 (FUN_008C46E0, cfunc_UserUnitGetFocusL)
 *
 * What it does:
 * Pushes focused target user-unit Lua object, or `nil` when unresolved.
 */
int moho::cfunc_UserUnitGetFocusL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetFocusHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  UserEntity* const userEntity = ResolveUserEntityView(userUnit);
  UserEntity* const focusEntity =
    FindSessionEntityById(userEntity ? userEntity->mSession : nullptr, static_cast<std::int32_t>(GetLuaRuntimeView(userUnit).focusEntityId));

  if (focusEntity != nullptr) {
    if (UserUnit* const focusUnit = focusEntity->IsUserUnit(); focusUnit != nullptr) {
      GetUserUnitLuaObjectView(focusUnit).luaObject.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C47F0 (FUN_008C47F0, cfunc_UserUnitGetGuardedEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetGuardedEntityL`.
 */
int moho::cfunc_UserUnitGetGuardedEntity(lua_State* const luaContext)
{
  return cfunc_UserUnitGetGuardedEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4810 (FUN_008C4810, func_UserUnitGetGuardedEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetGuardedEntity()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetGuardedEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetGuardedEntityName,
    &moho::cfunc_UserUnitGetGuardedEntity,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetGuardedEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4870 (FUN_008C4870, cfunc_UserUnitGetGuardedEntityL)
 *
 * What it does:
 * Pushes guarded-target user-unit Lua object, or `nil` when unresolved.
 */
int moho::cfunc_UserUnitGetGuardedEntityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetGuardedEntityHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  UserEntity* const userEntity = ResolveUserEntityView(userUnit);
  UserEntity* const guardedEntity = FindSessionEntityById(
    userEntity ? userEntity->mSession : nullptr, static_cast<std::int32_t>(GetLuaRuntimeView(userUnit).guardedEntityId)
  );

  if (guardedEntity != nullptr) {
    if (UserUnit* const guardedUnit = guardedEntity->IsUserUnit(); guardedUnit != nullptr) {
      GetUserUnitLuaObjectView(guardedUnit).luaObject.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C4980 (FUN_008C4980, cfunc_UserUnitGetCreator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetCreatorL`.
 */
int moho::cfunc_UserUnitGetCreator(lua_State* const luaContext)
{
  return cfunc_UserUnitGetCreatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C49A0 (FUN_008C49A0, func_UserUnitGetCreator_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetCreator()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetCreator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetCreatorName,
    &moho::cfunc_UserUnitGetCreator,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetCreatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4A00 (FUN_008C4A00, cfunc_UserUnitGetCreatorL)
 *
 * What it does:
 * Pushes creator user-unit Lua object, or `nil` when unavailable.
 */
int moho::cfunc_UserUnitGetCreatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetCreatorHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  const std::uintptr_t creatorOwnerSlot = GetLuaRuntimeView(userUnit).creatorWeakOwnerSlot;
  UserEntity* creatorEntity = nullptr;
  if (creatorOwnerSlot > kUserEntityWeakOwnerOffset) {
    creatorEntity = reinterpret_cast<UserEntity*>(creatorOwnerSlot - kUserEntityWeakOwnerOffset);
  }

  if (creatorEntity != nullptr) {
    if (UserUnit* const creatorUnit = creatorEntity->IsUserUnit(); creatorUnit != nullptr) {
      GetUserUnitLuaObjectView(creatorUnit).luaObject.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C4AF0 (FUN_008C4AF0, cfunc_UserUnitGetPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetPositionL`.
 */
int moho::cfunc_UserUnitGetPosition(lua_State* const luaContext)
{
  return cfunc_UserUnitGetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4B10 (FUN_008C4B10, func_UserUnitGetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetPosition()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetPositionName,
    &moho::cfunc_UserUnitGetPosition,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4B70 (FUN_008C4B70, cfunc_UserUnitGetPositionL)
 *
 * What it does:
 * Pushes world position as one Lua VECTOR3 object.
 */
int moho::cfunc_UserUnitGetPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetPositionHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const Wm3::Vec3f& unitPosition = GetIUnitBridge(userUnit)->GetPosition();

  LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, unitPosition);
  positionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C4C50 (FUN_008C4C50, cfunc_UserUnitGetArmy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetArmyL`.
 */
int moho::cfunc_UserUnitGetArmy(lua_State* const luaContext)
{
  return cfunc_UserUnitGetArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4C70 (FUN_008C4C70, func_UserUnitGetArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetArmy()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetArmyName,
    &moho::cfunc_UserUnitGetArmy,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4CD0 (FUN_008C4CD0, cfunc_UserUnitGetArmyL)
 *
 * What it does:
 * Pushes one-based army index for the unit owner, preserving `-1` sentinel.
 */
int moho::cfunc_UserUnitGetArmyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetArmyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  int armyIndex = -1;
  if (const UserArmy* const army = GetLuaRuntimeView(userUnit).army; army != nullptr) {
    armyIndex = static_cast<int>(army->mArmyIndex);
  }
  if (armyIndex != -1) {
    ++armyIndex;
  }

  lua_pushnumber(rawState, static_cast<float>(armyIndex));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C5160 (FUN_008C5160, cfunc_UserUnitGetEconData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetEconDataL`.
 */
int moho::cfunc_UserUnitGetEconData(lua_State* const luaContext)
{
  return cfunc_UserUnitGetEconDataL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5180 (FUN_008C5180, func_UserUnitGetEconData_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetEconData()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetEconData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetEconDataName,
    &moho::cfunc_UserUnitGetEconData,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetEconDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C51E0 (FUN_008C51E0, cfunc_UserUnitGetEconDataL)
 *
 * What it does:
 * Pushes one Lua table with per-second economy lanes for this user unit.
 */
int moho::cfunc_UserUnitGetEconDataL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetEconDataHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserUnitLuaRuntimeView& runtime = GetLuaRuntimeView(userUnit);

  LuaPlus::LuaObject econTable;
  econTable.AssignNewTable(state, 0, 0);
  econTable.SetNumber(kEconEnergyConsumedKey, runtime.energyConsumedPerSecond * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconMassConsumedKey, runtime.massConsumedPerSecond * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconEnergyRequestedKey, runtime.energyRequestedPerSecond * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconMassRequestedKey, runtime.massRequestedPerSecond * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconEnergyProducedKey, runtime.energyProducedPerSecond * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconMassProducedKey, runtime.massProducedPerSecond * kEconomyPerSecondToUiRate);
  econTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C5400 (FUN_008C5400, cfunc_UserUnitGetCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetCommandQueueL`.
 */
int moho::cfunc_UserUnitGetCommandQueue(lua_State* const luaContext)
{
  return cfunc_UserUnitGetCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5420 (FUN_008C5420, func_UserUnitGetCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetCommandQueue()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetCommandQueueName,
    &moho::cfunc_UserUnitGetCommandQueue,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C5480 (FUN_008C5480, cfunc_UserUnitGetCommandQueueL)
 *
 * What it does:
 * Pushes one Lua array of queued command descriptors (`ID`, `type`,
 * `position`) for this user unit.
 */
int moho::cfunc_UserUnitGetCommandQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetCommandQueueHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  const UserCommandQueueRangeView* const commandRange = ResolveUserCommandQueueRange(SelectActiveQueueHandle(userUnit));
  if (commandRange == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject queueTable;
  queueTable.AssignNewTable(state, 0, 0);

  UserEntity* const userEntity = ResolveUserEntityView(userUnit);
  CWldSession* const session = userEntity ? userEntity->mSession : nullptr;

  int tableIndex = 1;
  for (UserCommandQueueEntryView* entry = commandRange->begin; entry != commandRange->end; ++entry) {
    UserCommandIssueHelperRuntimeView* const helper = entry->helper;
    if (helper == nullptr) {
      continue;
    }

    LuaPlus::LuaObject row;
    row.AssignNewTable(state, 0, 0);
    row.SetInteger(kCommandQueueIdKey, static_cast<int>(helper->commandId));

    EUnitCommandType commandTypeValue = ResolveHelperCommandType(*helper);
    gpg::RRef commandTypeRef{};
    gpg::RRef_EUnitCommandType(&commandTypeRef, &commandTypeValue);
    const msvc8::string commandTypeLexical = commandTypeRef.GetLexical();
    row.SetString(kCommandQueueTypeKey, commandTypeLexical.c_str());

    const Wm3::Vector3<float> commandPosition = ResolveHelperTargetPosition(*helper, session);
    LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, commandPosition);
    row.SetObject(kCommandQueuePositionKey, positionObject);

    queueTable.SetObject(tableIndex++, row);
  }

  queueTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C5750 (FUN_008C5750, cfunc_UserUnitGetMissileInfo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetMissileInfoL`.
 */
int moho::cfunc_UserUnitGetMissileInfo(lua_State* const luaContext)
{
  return cfunc_UserUnitGetMissileInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5770 (FUN_008C5770, func_UserUnitGetMissileInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetMissileInfo()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetMissileInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kUserUnitGetMissileInfoName,
    &moho::cfunc_UserUnitGetMissileInfo,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetMissileInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C57D0 (FUN_008C57D0, cfunc_UserUnitGetMissileInfoL)
 *
 * What it does:
 * Pushes one Lua table with tactical/nuke silo build and storage counters.
 */
int moho::cfunc_UserUnitGetMissileInfoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUserUnitGetMissileInfoHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserUnitLuaRuntimeView& runtime = GetLuaRuntimeView(userUnit);

  LuaPlus::LuaObject missileInfoTable;
  missileInfoTable.AssignNewTable(state, 0, 0);
  missileInfoTable.SetInteger(kMissileTacticalBuildCountKey, runtime.tacticalSiloBuildCount);
  missileInfoTable.SetInteger(kMissileTacticalStorageCountKey, runtime.tacticalSiloStorageCount);
  missileInfoTable.SetInteger(kMissileTacticalMaxStorageCountKey, runtime.tacticalSiloMaxStorageCount);
  missileInfoTable.SetInteger(kMissileNukeBuildCountKey, runtime.nukeSiloBuildCount);
  missileInfoTable.SetInteger(kMissileNukeStorageCountKey, runtime.nukeSiloStorageCount);
  missileInfoTable.SetInteger(kMissileNukeMaxStorageCountKey, runtime.nukeSiloMaxStorageCount);
  missileInfoTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x00836360 (FUN_00836360, cfunc_SetCurrentFactoryForQueueDisplay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_SetCurrentFactoryForQueueDisplayL`.
 */
int moho::cfunc_SetCurrentFactoryForQueueDisplay(lua_State* const luaContext)
{
  return cfunc_SetCurrentFactoryForQueueDisplayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00836380 (FUN_00836380, func_SetCurrentFactoryForQueueDisplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `SetCurrentFactoryForQueueDisplay(unit)` Lua binder.
 */
CScrLuaInitForm* moho::func_SetCurrentFactoryForQueueDisplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kSetCurrentFactoryForQueueDisplayName,
    &moho::cfunc_SetCurrentFactoryForQueueDisplay,
    nullptr,
    "<global>",
    kSetCurrentFactoryForQueueDisplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x008363E0 (FUN_008363E0, cfunc_SetCurrentFactoryForQueueDisplayL)
 *
 * What it does:
 * Resolves one optional `UserUnit` argument, rebuilds the factory build-queue
 * snapshot (`id` + `count` rows), and returns that queue table (or `nil` when
 * no factory build queue is available).
 */
int moho::cfunc_SetCurrentFactoryForQueueDisplayL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCurrentFactoryForQueueDisplayHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  RebuildCurrentFactoryBuildQueue(userUnit);

  LuaPlus::LuaObject queueTable;
  if (!sCurrentFactoryBuildQueue.empty()) {
    (void)BuildFactoryQueueLuaTable(state, &queueTable);
  } else {
    queueTable.AssignNil(state);
  }

  queueTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C5930 (FUN_008C5930, cfunc_GetBlueprintUser)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetBlueprintUserL`.
 */
int moho::cfunc_GetBlueprintUser(lua_State* const luaContext)
{
  return cfunc_GetBlueprintUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5950 (FUN_008C5950, func_GetBlueprintUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua `GetBlueprint` binder.
 */
CScrLuaInitForm* moho::func_GetBlueprintUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetBlueprintUserName,
    &moho::cfunc_GetBlueprintUser,
    nullptr,
    "<global>",
    kGetBlueprintUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C59B0 (FUN_008C59B0, cfunc_GetBlueprintUserL)
 *
 * What it does:
 * Resolves one `UserUnit` Lua object argument and pushes its unit blueprint
 * Lua object result.
 */
int moho::cfunc_GetBlueprintUserL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetBlueprintUserHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const IUnit* const iunitBridge = GetIUnitBridge(userUnit);
  const RUnitBlueprint* const blueprint = iunitBridge ? iunitBridge->GetBlueprint() : nullptr;

  if (blueprint != nullptr) {
    LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
    luaBlueprint.PushStack(state);
  } else {
    lua_pushnil(rawState);
  }
  return 1;
}
