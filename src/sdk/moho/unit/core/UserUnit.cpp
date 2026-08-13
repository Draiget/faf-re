// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/UserUnit.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/sim/BuildQueueCommandDecrement.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/math/Vector3f.h"
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
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/command/UserCommandQueue.h"
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
  void WarnFocusArmyUnitDamagedCallbackError(const std::exception& exception) noexcept;

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
  static_assert(
    offsetof(UserCommandIssueHelper, mConstantData) == offsetof(UserCommandIssueHelperRuntimeView, commandId),
    "UserCommandIssueHelper/UserCommandIssueHelperRuntimeView command-id lane mismatch"
  );
  static_assert(
    offsetof(UserCommandIssueHelper, mLocalQueue) == 0xB8,
    "UserCommandIssueHelper local queue lane must stay at +0xB8"
  );
  static_assert(
    offsetof(UserCommandIssueHelper, mCursorEntitySet) == 0xCC,
    "UserCommandIssueHelper cursor weak-set lane must stay at +0xCC"
  );

} // namespace

namespace moho
{
  struct UserCommandQueueEntry
  {
    UserCommandIssueHelperRuntimeView* helper;   // +0x00
    void* link;                                  // +0x04
  };
  static_assert(sizeof(UserCommandQueueEntry) == 0x08, "UserCommandQueueEntry size must be 0x08");
} // namespace moho

namespace
{

  struct UserCommandQueueRangeView
  {
    UserCommandQueueEntry* begin;            // +0x00
    UserCommandQueueEntry* end;              // +0x04
  };
  static_assert(sizeof(UserCommandQueueRangeView) == 0x08, "UserCommandQueueRangeView size must be 0x08");

  struct FactoryQueueDisplayItemRuntime
  {
    FactoryQueueDisplayItemRuntime() noexcept;
    FactoryQueueDisplayItemRuntime(const msvc8::string& sourceBlueprintId, std::int32_t sourceCount);
    ~FactoryQueueDisplayItemRuntime() noexcept;

    msvc8::string blueprintId;         // +0x00
    std::int32_t count;                // +0x1C
    CmdId commandId;                   // +0x20
    std::uint8_t* auxBufferBegin;      // +0x24
    std::uint8_t* auxBufferEnd;        // +0x28
    std::uint8_t* auxBufferCapacity;   // +0x2C
  };
  static_assert(offsetof(FactoryQueueDisplayItemRuntime, count) == 0x1C, "FactoryQueueDisplayItemRuntime::count offset must be 0x1C");
  static_assert(
    offsetof(FactoryQueueDisplayItemRuntime, commandId) == 0x20,
    "FactoryQueueDisplayItemRuntime::commandId offset must be 0x20"
  );
  static_assert(
    offsetof(FactoryQueueDisplayItemRuntime, auxBufferBegin) == 0x24,
    "FactoryQueueDisplayItemRuntime::auxBufferBegin offset must be 0x24"
  );
  static_assert(
    offsetof(FactoryQueueDisplayItemRuntime, auxBufferEnd) == 0x28,
    "FactoryQueueDisplayItemRuntime::auxBufferEnd offset must be 0x28"
  );
  static_assert(
    offsetof(FactoryQueueDisplayItemRuntime, auxBufferCapacity) == 0x2C,
    "FactoryQueueDisplayItemRuntime::auxBufferCapacity offset must be 0x2C"
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
    UserCommandQueueEntry* resolvedRangeEndStorage; // +0x48
    UserCommandQueueEntry** resolvedRangeInlineStorage; // +0x4C
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

  struct UserCommandIssueWeakSetRuntimeView
  {
    void* allocatorProxy;            // +0x00
    SSelectionNodeUserEntity* head;  // +0x04
    std::uint32_t size;              // +0x08
  };
  static_assert(
    offsetof(UserCommandIssueWeakSetRuntimeView, head) == 0x04,
    "UserCommandIssueWeakSetRuntimeView::head offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueWeakSetRuntimeView, size) == 0x08,
    "UserCommandIssueWeakSetRuntimeView::size offset must be 0x08"
  );
  static_assert(sizeof(UserCommandIssueWeakSetRuntimeView) == 0x0C, "UserCommandIssueWeakSetRuntimeView size must be 0x0C");

  struct UserCommandIssueCellVectorRuntimeView
  {
    void* begin;        // +0x00
    void* end;          // +0x04
    void* capacityEnd;  // +0x08
    void** inlineBase;  // +0x0C
    std::uint8_t pad_0010_0018[0x08];
  };
  static_assert(offsetof(UserCommandIssueCellVectorRuntimeView, begin) == 0x00, "UserCommandIssueCellVectorRuntimeView::begin offset must be 0x00");
  static_assert(offsetof(UserCommandIssueCellVectorRuntimeView, end) == 0x04, "UserCommandIssueCellVectorRuntimeView::end offset must be 0x04");
  static_assert(
    offsetof(UserCommandIssueCellVectorRuntimeView, capacityEnd) == 0x08,
    "UserCommandIssueCellVectorRuntimeView::capacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandIssueCellVectorRuntimeView, inlineBase) == 0x0C,
    "UserCommandIssueCellVectorRuntimeView::inlineBase offset must be 0x0C"
  );
  static_assert(sizeof(UserCommandIssueCellVectorRuntimeView) == 0x18, "UserCommandIssueCellVectorRuntimeView size must be 0x18");

  struct UserCommandIssueLocalEventRuntimeView
  {
    CmdId commandId;                                // +0x00
    std::uint32_t eventType;                        // +0x04
    UserCommandIssueWeakSetRuntimeView entitySet;   // +0x08
    std::int32_t countDelta;                        // +0x14
    std::uint8_t pad_0018_001C[0x04];
    SSelectionWeakRefUserEntity targetEntityWeak;   // +0x1C
    std::uint8_t pad_0024_0038[0x14];
    UserCommandIssueCellVectorRuntimeView cells;    // +0x38
  };
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, entitySet) == 0x08,
    "UserCommandIssueLocalEventRuntimeView::entitySet offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, countDelta) == 0x14,
    "UserCommandIssueLocalEventRuntimeView::countDelta offset must be 0x14"
  );
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, targetEntityWeak) == 0x1C,
    "UserCommandIssueLocalEventRuntimeView::targetEntityWeak offset must be 0x1C"
  );
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, cells) == 0x38,
    "UserCommandIssueLocalEventRuntimeView::cells offset must be 0x38"
  );
  static_assert(sizeof(UserCommandIssueLocalEventRuntimeView) == 0x50, "UserCommandIssueLocalEventRuntimeView size must be 0x50");

  struct UserCommandIssueLocalQueueRuntimeView
  {
    std::uint32_t allocatorProxy;                        // +0x00
    UserCommandIssueLocalEventRuntimeView** slots;       // +0x04
    std::uint32_t capacity;                              // +0x08
    std::uint32_t readIndex;                             // +0x0C
    std::uint32_t count;                                 // +0x10
  };
  static_assert(
    offsetof(UserCommandIssueLocalQueueRuntimeView, slots) == 0x04,
    "UserCommandIssueLocalQueueRuntimeView::slots offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueLocalQueueRuntimeView, capacity) == 0x08,
    "UserCommandIssueLocalQueueRuntimeView::capacity offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandIssueLocalQueueRuntimeView, readIndex) == 0x0C,
    "UserCommandIssueLocalQueueRuntimeView::readIndex offset must be 0x0C"
  );
  static_assert(
    offsetof(UserCommandIssueLocalQueueRuntimeView, count) == 0x10,
    "UserCommandIssueLocalQueueRuntimeView::count offset must be 0x10"
  );
  static_assert(sizeof(UserCommandIssueLocalQueueRuntimeView) == 0x14, "UserCommandIssueLocalQueueRuntimeView size must be 0x14");

  struct UserCommandIssueEventEntitySetRuntimeView
  {
    std::uint8_t pad_0000_0004[0x04];
    std::uint32_t eventType;                          // +0x04
    UserCommandIssueWeakSetRuntimeView entitySet;     // +0x08
    std::int32_t countDelta;                          // +0x14
    std::uint8_t pad_0018_0034[0x1C];
  };
  static_assert(
    offsetof(UserCommandIssueEventEntitySetRuntimeView, eventType) == 0x04,
    "UserCommandIssueEventEntitySetRuntimeView::eventType offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueEventEntitySetRuntimeView, entitySet) == 0x08,
    "UserCommandIssueEventEntitySetRuntimeView::entitySet offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandIssueEventEntitySetRuntimeView, countDelta) == 0x14,
    "UserCommandIssueEventEntitySetRuntimeView::countDelta offset must be 0x14"
  );
  static_assert(sizeof(UserCommandIssueEventEntitySetRuntimeView) == 0x34, "UserCommandIssueEventEntitySetRuntimeView size must be 0x34");

  struct UserCommandIssueCursorEntityCacheRuntimeView
  {
    std::uint8_t pad_0000_0040[0x40];
    EntId* cursorEntityIdsBegin;                                  // +0x40
    EntId* cursorEntityIdsEnd;                                    // +0x44
    std::uint8_t pad_0048_00B2[0x6A];
    std::uint8_t cursorEntityCacheDirty;                          // +0xB2
    std::uint8_t pad_00B3_00BC[0x09];
    UserCommandIssueEventEntitySetRuntimeView** eventSlots;       // +0xBC
    std::uint32_t eventWrapBase;                                  // +0xC0
    std::uint32_t eventStart;                                     // +0xC4
    std::uint32_t eventCount;                                     // +0xC8
    UserCommandIssueWeakSetRuntimeView cursorEntitySet;           // +0xCC
  };
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, cursorEntityIdsBegin) == 0x40,
    "UserCommandIssueCursorEntityCacheRuntimeView::cursorEntityIdsBegin offset must be 0x40"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, cursorEntityIdsEnd) == 0x44,
    "UserCommandIssueCursorEntityCacheRuntimeView::cursorEntityIdsEnd offset must be 0x44"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, cursorEntityCacheDirty) == 0xB2,
    "UserCommandIssueCursorEntityCacheRuntimeView::cursorEntityCacheDirty offset must be 0xB2"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, eventSlots) == 0xBC,
    "UserCommandIssueCursorEntityCacheRuntimeView::eventSlots offset must be 0xBC"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, eventWrapBase) == 0xC0,
    "UserCommandIssueCursorEntityCacheRuntimeView::eventWrapBase offset must be 0xC0"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, eventStart) == 0xC4,
    "UserCommandIssueCursorEntityCacheRuntimeView::eventStart offset must be 0xC4"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, eventCount) == 0xC8,
    "UserCommandIssueCursorEntityCacheRuntimeView::eventCount offset must be 0xC8"
  );
  static_assert(
    offsetof(UserCommandIssueCursorEntityCacheRuntimeView, cursorEntitySet) == 0xCC,
    "UserCommandIssueCursorEntityCacheRuntimeView::cursorEntitySet offset must be 0xCC"
  );

} // namespace

namespace moho
{
  struct UserManagerHelperEntry
  {
    std::int32_t commandType;     // +0x00
    std::int32_t isResetCommand;  // +0x04
    void* subject;                // +0x08
    std::int32_t sequenceOrCount; // +0x0C
  };
  static_assert(sizeof(UserManagerHelperEntry) == 0x10, "UserManagerHelperEntry size must be 0x10");
} // namespace moho

namespace
{

  // UserCommandQueue and its two sub-runs are real types now, declared in
  // moho/command/UserCommandQueue.h so the layout is stated once instead of
  // living as a reinterpret view over an opaque forward declaration.

  struct SessionCommandIssueMapNodeView
  {
    SessionCommandIssueMapNodeView* left;   // +0x00
    SessionCommandIssueMapNodeView* parent; // +0x04
    SessionCommandIssueMapNodeView* right;  // +0x08
    std::uint32_t key;                      // +0x0C
    UserCommandIssueHelperRuntimeView* value; // +0x10
    std::uint8_t color;                     // +0x14
    std::uint8_t isNil;                     // +0x15
    std::uint8_t pad_16_18[2];              // +0x16
  };
  static_assert(sizeof(SessionCommandIssueMapNodeView) == 0x18, "SessionCommandIssueMapNodeView size must be 0x18");
  static_assert(
    offsetof(SessionCommandIssueMapNodeView, key) == 0x0C,
    "SessionCommandIssueMapNodeView::key offset must be 0x0C"
  );
  static_assert(
    offsetof(SessionCommandIssueMapNodeView, value) == 0x10,
    "SessionCommandIssueMapNodeView::value offset must be 0x10"
  );
  static_assert(
    offsetof(SessionCommandIssueMapNodeView, isNil) == 0x15,
    "SessionCommandIssueMapNodeView::isNil offset must be 0x15"
  );

  struct SessionCommandIssueMapView
  {
    void* allocatorProxy;                   // +0x00
    SessionCommandIssueMapNodeView* head;   // +0x04
    std::uint32_t size;                     // +0x08
  };
  static_assert(sizeof(SessionCommandIssueMapView) == 0x0C, "SessionCommandIssueMapView size must be 0x0C");
  static_assert(
    offsetof(SessionCommandIssueMapView, head) == 0x04,
    "SessionCommandIssueMapView::head offset must be 0x04"
  );

  /// `moho::CommandManager` owns the layout; this file only needs the
  /// command map as raw tree nodes, which it walks itself.
  [[nodiscard]] inline SessionCommandIssueMapView& CommandIssueMapOf(moho::CommandManager& manager) noexcept
  {
    return *reinterpret_cast<SessionCommandIssueMapView*>(&manager.mCommands);
  }
  static_assert(sizeof(moho::CommandManager) == 0xCC0, "CommandManager size must be 0xCC0");

  struct UserUnitVisionRuntimeView
  {
    std::uint8_t pad_0000_0018[0x18];
    VisionDB::Handle* visionHandle; // +0x18
  };
  static_assert(
    offsetof(UserUnitVisionRuntimeView, visionHandle) == 0x18,
    "UserUnitVisionRuntimeView::visionHandle offset must be 0x18"
  );

} // namespace

namespace moho
{
  const IUnit* GetIUnitBridge(const UserUnit* const self) noexcept
  {
    return self;
  }

  IUnit* GetIUnitBridge(UserUnit* const self) noexcept
  {
    return self;
  }
} // namespace moho

namespace
{

  struct UserUnitIUnitStateBridgeView
  {
    std::uint8_t pad_0000_0268[0x268];
    std::uint64_t unitStates; // +0x268
  };
  static_assert(
    offsetof(UserUnitIUnitStateBridgeView, unitStates) == 0x268,
    "UserUnitIUnitStateBridgeView::unitStates offset must be 0x268"
  );

  struct IUnitBridgeLuaObjectRuntimeView
  {
    std::uint8_t pad_0000_0028[0x28];
    LuaPlus::LuaObject luaObject; // +0x28
  };
  static_assert(
    offsetof(IUnitBridgeLuaObjectRuntimeView, luaObject) == 0x28,
    "IUnitBridgeLuaObjectRuntimeView::luaObject offset must be 0x28"
  );

  /**
   * Address: 0x008BEF60 (FUN_008BEF60, Moho::IUnit_UserUnit::GetLuaObject)
   *
   * What it does:
   * Copy-constructs one Lua object result lane from the UserUnit IUnit-bridge
   * Lua-object payload at `+0x28`.
   */
  [[maybe_unused]] LuaPlus::LuaObject* IUnitBridgeCopyLuaObjectToOut(
    const IUnit* const bridge,
    LuaPlus::LuaObject* const outLuaObject
  ) noexcept
  {
    const auto* const bridgeView = reinterpret_cast<const IUnitBridgeLuaObjectRuntimeView*>(bridge);
    new (outLuaObject) LuaPlus::LuaObject(bridgeView->luaObject);
    return outLuaObject;
  }

  /**
   * Address: 0x008BEF80 (FUN_008BEF80, Moho::IUnit_UserUnit::CalcTransportLoadFactor)
   *
   * What it does:
   * Returns the fixed transport-load factor used by the UserUnit IUnit bridge.
   */
  [[nodiscard]] float IUnitBridgeCalcTransportLoadFactor(const IUnit* const bridge) noexcept
  {
    (void)bridge;
    return 1.0f;
  }

  /**
   * Address: 0x008BEFA0 (FUN_008BEFA0, Moho::IUnit_UserUnit::DestroyQueued)
   *
   * What it does:
   * Returns false for the UserUnit IUnit bridge destroy-queued lane.
   */
  [[nodiscard]] bool IUnitBridgeDestroyQueued(const IUnit* const bridge) noexcept
  {
    (void)bridge;
    return false;
  }

  /**
   * Address: 0x008BEFC0 (FUN_008BEFC0, Moho::IUnit_UserUnit::IsNavigatorIdle)
   *
   * What it does:
   * Returns false for the UserUnit IUnit bridge navigator-idle lane.
   */
  [[nodiscard]] bool IUnitBridgeIsNavigatorIdle(const IUnit* const bridge) noexcept
  {
    (void)bridge;
    return false;
  }

  /**
   * Address: 0x008BF020 (FUN_008BF020, Moho::IUnit_UserUnit::IsUnitState)
   *
   * What it does:
   * Tests one unit-state bit in the `UserUnit` IUnit-bridge state mask.
   */
  [[nodiscard]] bool IUnitBridgeIsUnitState(const IUnit* const bridge, const EUnitState state) noexcept
  {
    if (bridge == nullptr) {
      return false;
    }

    const std::uint32_t stateIndex = static_cast<std::uint32_t>(state);
    if (stateIndex >= 64u) {
      return false;
    }

    const auto* const stateView = reinterpret_cast<const UserUnitIUnitStateBridgeView*>(bridge);
    const std::uint64_t stateMask = (std::uint64_t{1} << stateIndex);
    return (stateView->unitStates & stateMask) != 0u;
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

  [[nodiscard]] UserCommandQueueLinkVector* RebuildAndGetUserUnitManagerQueue(UserCommandQueue* managerPtr) noexcept;

  [[nodiscard]] const UserCommandQueueRangeView* ResolveUserCommandQueueRange(const UserCommandQueue* const queue) noexcept
  {
    UserCommandQueue* const manager = const_cast<UserCommandQueue*>(queue);
    if (manager == nullptr) {
      return nullptr;
    }

    const UserCommandQueueLinkVector* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    return reinterpret_cast<const UserCommandQueueRangeView*>(queueVector);
  }

  [[nodiscard]] VisionDB::Handle*& GetUserUnitVisionHandle(UserUnit* const self) noexcept
  {
    return reinterpret_cast<UserUnitVisionRuntimeView*>(self)->visionHandle;
  }

  [[nodiscard]] const VisionDB::Handle* GetUserUnitVisionHandle(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const UserUnitVisionRuntimeView*>(self)->visionHandle;
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

  [[nodiscard]] SSelectionSetUserEntity BuildSelectionAdapterFromIssueWeakSet(
    const UserCommandIssueWeakSetRuntimeView& set
  ) noexcept
  {
    SSelectionSetUserEntity adapter{};
    adapter.mAllocProxy = set.allocatorProxy;
    adapter.mHead = set.head;
    adapter.mSize = set.size;
    adapter.mSizeMirrorOrUnused = set.size;
    return adapter;
  }

  void CommitSelectionAdapterToIssueWeakSet(
    const SSelectionSetUserEntity& adapter,
    UserCommandIssueWeakSetRuntimeView& set
  ) noexcept
  {
    set.allocatorProxy = adapter.mAllocProxy;
    set.head = adapter.mHead;
    set.size = adapter.mSize;
  }

  [[nodiscard]] UserEntity* DecodeSelectionWeakOwnerUserEntity(
    const SSelectionWeakRefUserEntity& weakRef
  ) noexcept
  {
    const std::uintptr_t ownerLinkSlot = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
    if (ownerLinkSlot <= kUserEntityWeakOwnerOffset) {
      return nullptr;
    }

    return reinterpret_cast<UserEntity*>(ownerLinkSlot - kUserEntityWeakOwnerOffset);
  }

  void ClearIssueWeakSetKeepHead(UserCommandIssueWeakSetRuntimeView& set) noexcept
  {
    SSelectionSetUserEntity adapter = BuildSelectionAdapterFromIssueWeakSet(set);
    if (adapter.mHead != nullptr) {
      SSelectionNodeUserEntity* eraseCursor = adapter.mHead->mLeft;
      (void)adapter.EraseRange(&eraseCursor, adapter.mHead->mLeft, adapter.mHead);
      adapter.mSizeMirrorOrUnused = adapter.mSize;
    }
    CommitSelectionAdapterToIssueWeakSet(adapter, set);
  }

  void PruneIssueWeakSetTombstones(UserCommandIssueWeakSetRuntimeView& set) noexcept
  {
    SSelectionSetUserEntity adapter = BuildSelectionAdapterFromIssueWeakSet(set);
    if (adapter.mHead == nullptr) {
      return;
    }

    SSelectionNodeUserEntity* cursor = adapter.mHead->mLeft;
    cursor = *adapter.PruneTombstonesAndFindLive(&cursor, cursor);
    while (cursor != adapter.mHead) {
      SSelectionSetUserEntity::Iterator_inc(&cursor);
      cursor = SSelectionSetUserEntity::find(&adapter, cursor, &cursor);
    }

    CommitSelectionAdapterToIssueWeakSet(adapter, set);
  }

  void AddIssueWeakSetEntity(UserCommandIssueWeakSetRuntimeView& set, UserEntity* const entity) noexcept
  {
    SSelectionSetUserEntity adapter = BuildSelectionAdapterFromIssueWeakSet(set);
    if (entity != nullptr && adapter.mHead != nullptr) {
      SSelectionSetUserEntity::AddResult addResult{};
      (void)SSelectionSetUserEntity::Add(&addResult, &adapter, entity);
      adapter.mSizeMirrorOrUnused = adapter.mSize;
    }
    CommitSelectionAdapterToIssueWeakSet(adapter, set);
  }

  void EraseIssueWeakSetEntity(UserCommandIssueWeakSetRuntimeView& set, UserEntity* const entity) noexcept
  {
    if (entity == nullptr) {
      return;
    }

    SSelectionSetUserEntity adapter = BuildSelectionAdapterFromIssueWeakSet(set);
    if (adapter.mHead == nullptr) {
      return;
    }

    while (true) {
      SSelectionSetUserEntity::FindResult found{};
      (void)SSelectionSetUserEntity::Find(&found, &adapter, entity);
      if (found.mRes == adapter.mHead) {
        break;
      }

      SSelectionNodeUserEntity* next = found.mRes;
      SSelectionSetUserEntity::Iterator_inc(&next);
      next = SSelectionSetUserEntity::find(&adapter, next, &next);

      SSelectionNodeUserEntity* eraseCursor = found.mRes;
      (void)adapter.EraseRange(&eraseCursor, found.mRes, next);
      adapter.mSizeMirrorOrUnused = adapter.mSize;
    }

    CommitSelectionAdapterToIssueWeakSet(adapter, set);
  }

  void MergeIssueWeakSetEntities(
    UserCommandIssueWeakSetRuntimeView& destination,
    UserCommandIssueWeakSetRuntimeView& source
  ) noexcept
  {
    SSelectionSetUserEntity sourceAdapter = BuildSelectionAdapterFromIssueWeakSet(source);
    if (sourceAdapter.mHead == nullptr) {
      return;
    }

    SSelectionNodeUserEntity* cursor = sourceAdapter.mHead->mLeft;
    cursor = *sourceAdapter.PruneTombstonesAndFindLive(&cursor, cursor);
    while (cursor != sourceAdapter.mHead) {
      if (UserEntity* const entity = DecodeSelectionWeakOwnerUserEntity(cursor->mEnt); entity != nullptr) {
        AddIssueWeakSetEntity(destination, entity);
      }

      SSelectionSetUserEntity::Iterator_inc(&cursor);
      cursor = SSelectionSetUserEntity::find(&sourceAdapter, cursor, &cursor);
    }

    CommitSelectionAdapterToIssueWeakSet(sourceAdapter, source);
  }

  void EraseIssueWeakSetEntities(
    UserCommandIssueWeakSetRuntimeView& destination,
    UserCommandIssueWeakSetRuntimeView& source
  ) noexcept
  {
    SSelectionSetUserEntity sourceAdapter = BuildSelectionAdapterFromIssueWeakSet(source);
    if (sourceAdapter.mHead == nullptr) {
      return;
    }

    SSelectionNodeUserEntity* cursor = sourceAdapter.mHead->mLeft;
    cursor = *sourceAdapter.PruneTombstonesAndFindLive(&cursor, cursor);
    while (cursor != sourceAdapter.mHead) {
      if (UserEntity* const entity = DecodeSelectionWeakOwnerUserEntity(cursor->mEnt); entity != nullptr) {
        EraseIssueWeakSetEntity(destination, entity);
      }

      SSelectionSetUserEntity::Iterator_inc(&cursor);
      cursor = SSelectionSetUserEntity::find(&sourceAdapter, cursor, &cursor);
    }

    CommitSelectionAdapterToIssueWeakSet(sourceAdapter, source);
  }

  void DestroyCommandIssueWeakSetNodes(
    SSelectionNodeUserEntity* const node,
    SSelectionNodeUserEntity* const head
  ) noexcept
  {
    if (node == nullptr || node == head || node->mIsSentinel != 0u) {
      return;
    }

    DestroyCommandIssueWeakSetNodes(node->mLeft, head);
    DestroyCommandIssueWeakSetNodes(node->mRight, head);
    UnlinkWeakEntityOwner(node->mEnt);
    ::operator delete(node);
  }

  void DestroyCommandIssueWeakSet(UserCommandIssueWeakSetRuntimeView& set) noexcept
  {
    SSelectionNodeUserEntity* const head = set.head;
    if (head == nullptr) {
      return;
    }

    SSelectionNodeUserEntity* const root = head->mParent;
    if (root != nullptr && root != head && root->mIsSentinel == 0u) {
      DestroyCommandIssueWeakSetNodes(root, head);
    }

    ::operator delete(head);
    set.head = nullptr;
    set.size = 0u;
  }

  void UnlinkCommandIssueTargetWeakOwnerNoReset(SSelectionWeakRefUserEntity& weakRef) noexcept
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
  }

  /**
   * Address: 0x008B4800 (FUN_008B4800)
   *
   * What it does:
   * Releases dynamic command-cell storage back to inline capacity, detaches
   * target weak-owner linkage, and destroys the local weak-entity set lane.
   */
  void DestroyCommandIssueLocalEvent(UserCommandIssueLocalEventRuntimeView& event) noexcept
  {
    if (event.cells.begin != event.cells.inlineBase) {
      ::operator delete[](event.cells.begin);
      event.cells.begin = event.cells.inlineBase;
      event.cells.capacityEnd = (event.cells.inlineBase != nullptr) ? *event.cells.inlineBase : nullptr;
    }
    event.cells.end = event.cells.begin;

    UnlinkCommandIssueTargetWeakOwnerNoReset(event.targetEntityWeak);
    DestroyCommandIssueWeakSet(event.entitySet);
  }

  [[nodiscard]] SSelectionNodeUserEntity*
  FindWeakEntitySetNodeByKey(const WeakEntitySetUserEntity& selection, const std::uint32_t key) noexcept
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

  void RecomputeWeakEntitySetExtrema(WeakEntitySetUserEntity& selection) noexcept
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
    WeakEntitySetUserEntity& selection,
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

  void RotateWeakEntityLeft(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* const node) noexcept
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

  void RotateWeakEntityRight(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* const node) noexcept
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

  void FixupWeakEntityInsert(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* node) noexcept
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
    WeakEntitySetUserEntity& selection,
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
  EraseWeakEntityNodeAndAdvance(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* const node) noexcept
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

  [[nodiscard]] bool InsertWeakEntitySet(WeakEntitySetUserEntity& selection, UserEntity* const entity) noexcept
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

  /**
   * Address: 0x008676E0 (FUN_008676E0, sub_8676E0)
   *
   * The erase itself lives on the type, in CWldSession.cpp, so the session
   * selection, the extra-select list and the army idle registries all remove
   * entries the same way — including the weak-owner guard the binary holds
   * across the erase, which this file's open-coded version was missing.
   */
  [[nodiscard]] bool EraseWeakEntitySet(WeakEntitySetUserEntity& selection, UserEntity* const entity) noexcept
  {
    return SSelectionSetUserEntity::Erase(selection, entity);
  }

  /**
   * Address: 0x008C06A0 (FUN_008C06A0)
   *
   * IDA signature:
   * void __usercall sub_8C06A0(Moho::UserEntity *unit@<esi>);
   *
   * What it does:
   * Takes one entity out of the player's current selection. Works on a copy of
   * the session selection and only republishes when the entity really was
   * selected, so a unit going busy off-screen never disturbs the selection.
   */
  void DeselectFromSessionSelection(UserEntity* const entity) noexcept
  {
    if (entity == nullptr || entity->mSession == nullptr) {
      return;
    }

    ScopedCopiedSelectionSet selection{};
    (void)CopySessionSelectionSet(&selection.get(), &entity->mSession->mSelection);

    SSelectionSetUserEntity::FindResult found{};
    (void)SSelectionSetUserEntity::Find(&found, &selection.get(), entity);
    if (found.mRes == selection.get().mHead) {
      return;
    }

    (void)SSelectionSetUserEntity::Erase(selection.get(), entity);
    entity->mSession->SetSelection(selection.get());
  }

  /**
   * Address: 0x008B2300 (FUN_008B2300)
   *
   * IDA signature:
   * struct _EXCEPTION_REGISTRATION_RECORD *__stdcall sub_8B2300(
   *   Moho::UserArmy *army, Moho::UserUnit *unit);
   *
   * What it does:
   * Files one unit into its army's quick-select avatar run, which the binary
   * keeps sorted by ascending blueprint `QuickSelectPriority`. The scan skips
   * lanes whose weak reference has already gone stale and inserts before the
   * first surviving avatar that outranks the new unit, appending when none
   * does.
   */
  void AddArmyAvatar(UserArmy* const army, UserUnit* const unit)
  {
    if (unit == nullptr || army == nullptr) {
      return;
    }

    const IUnit* const unitBridge = unit;
    const RUnitBlueprint* const unitBlueprint = unitBridge->GetBlueprint();
    if (unitBlueprint == nullptr) {
      return;
    }
    const std::int32_t unitPriority = unitBlueprint->General.QuickSelectPriority;

    msvc8::vector<WeakPtr<UserUnit>>& avatars = army->mAvatars;
    std::size_t insertIndex = avatars.size();
    for (std::size_t index = 0; index < avatars.size(); ++index) {
      UserUnit* const avatar = avatars[index].GetObjectPtr();
      if (avatar == nullptr) {
        continue;
      }

      const IUnit* const avatarBridge = avatar;
      const RUnitBlueprint* const avatarBlueprint = avatarBridge->GetBlueprint();
      if (avatarBlueprint != nullptr && avatarBlueprint->General.QuickSelectPriority > unitPriority) {
        insertIndex = index;
        break;
      }
    }

    InsertWeakPtrVectorObjectAt(avatars, unit, insertIndex);
  }

  /**
   * Address: 0x008B2520 (FUN_008B2520, idle engineer weak-set insert helper)
   *
   * What it does:
   * Inserts one `UserUnit` into the owning army idle-engineer weak set.
   */
  [[nodiscard]] bool InsertIdleEngineerWeakSetEntry(UserUnit* const unit, UserArmy* const army) noexcept
  {
    if (unit == nullptr || army == nullptr) {
      return false;
    }

    return InsertWeakEntitySet(army->mEngineers, reinterpret_cast<UserEntity*>(unit));
  }

  /**
   * Address: 0x008B2590 (FUN_008B2590, idle factory weak-set insert helper)
   *
   * What it does:
   * Inserts one `UserUnit` into the owning army idle-factory weak set.
   */
  [[nodiscard]] bool InsertIdleFactoryWeakSetEntry(UserUnit* const unit, UserArmy* const army) noexcept
  {
    if (unit == nullptr || army == nullptr) {
      return false;
    }

    return InsertWeakEntitySet(army->mFactories, reinterpret_cast<UserEntity*>(unit));
  }

  /**
   * Address: 0x008B3870 (FUN_008B3870, detach_user_unit_priority_record_tail)
   *
   * IDA signature:
   * int __usercall sub_8B3870@<eax>(int result@<eax>, _DWORD **a2@<edx>,
   *                                  _DWORD **a3@<esi>);
   *
   * What it does:
   * Drains the half-open priority-registry record run starting at `result`
   * against the update stream `[a2, a3)`. For each record that still points
   * at its source hook, the helper unchains the record through its intrusive
   * next-link slot (`*hook -> ... -> record`) and reseats the new target so
   * the registry stays linked to live hooks while one element is being
   * retired. The helper is shared with other `UserArmy` unit-registry lanes
   * (`sub_8B2820`, `sub_8B2A70`, `sub_8B35F0`), and the pair advances
   * 8 bytes at a time in lock-step with `a2`.
   */
  void PatchUserArmyPriorityRegistryRecordTail(
    std::uint32_t* record,
    std::uint32_t* const replacementBegin,
    std::uint32_t* const replacementEnd
  )
  {
    std::uint32_t* cursor = replacementBegin;
    while (cursor != replacementEnd) {
      std::uint32_t* const currentHook = reinterpret_cast<std::uint32_t*>(record[0]);
      if (reinterpret_cast<std::uint32_t*>(cursor[0]) != currentHook) {
        if (currentHook != nullptr) {
          std::uint32_t* chainSlot = currentHook;
          while (*chainSlot != reinterpret_cast<std::uintptr_t>(record)) {
            chainSlot = reinterpret_cast<std::uint32_t*>(*chainSlot);
            chainSlot += 1;
          }
          *chainSlot = record[1];
        }

        std::uint32_t* const replacementHook = reinterpret_cast<std::uint32_t*>(cursor[0]);
        record[0] = reinterpret_cast<std::uintptr_t>(replacementHook);
        if (replacementHook == nullptr) {
          record[1] = 0u;
        } else {
          record[1] = *replacementHook;
          *replacementHook = reinterpret_cast<std::uintptr_t>(record);
        }
      }

      cursor += 2;
      record += 2;
    }
  }

  /**
   * Address: 0x008B2470 (FUN_008B2470, UserArmy::UnregisterPrioritySelectionSlot)
   *
   * IDA signature:
   * _DWORD *__usercall sub_8B2470@<eax>(Moho::UserUnit *unit@<eax>,
   *                                      Moho::UserArmy *army@<edi>);
   *
   * What it does:
   * Removes `unit` from the `UserArmy` high-priority selection registry run
   * that lives at UserArmy `[+0x1EC, +0x1F0)`. The loop scans the run for
   * the record whose first dword dereferences back to `unit` (via the
   * `*(hook) - 8` decoding shared with other unit registry lanes), then (1)
   * calls the shared tail-patching helper to re-chain every record past the
   * removed slot via `PatchUserArmyPriorityRegistryRecordTail`, (2) drains
   * each pair's intrusive back-link slot, and (3) compacts the run end by
   * one 8-byte record.
   *
   * Called from `UserUnit::DestroyUserUnit` (FUN_008BF9B0) when the unit's
   * blueprint `QuickSelectPriority` is positive, and from `UserUnit::Tick`
   * (FUN_008C0A30) during the dead-unit cleanup sweep.
   */
  void UnregisterUserArmyPrioritySelectionSlot(UserUnit* const unit, UserArmy* const army) noexcept
  {
    if (army == nullptr || unit == nullptr) {
      return;
    }

    // The registry run is the army's avatar vector: one 8-byte
    // `WeakPtr<UserUnit>` record per quick-select unit.
    msvc8::vector<WeakPtr<UserUnit>>& avatars = army->mAvatars;
    auto* const runBegin = reinterpret_cast<std::uint32_t*>(avatars.data());
    std::uint32_t* const runEnd = runBegin + (avatars.size() * 2u);
    std::uint32_t* cursor = runBegin;
    if (cursor == runEnd) {
      return;
    }

    while (cursor != runEnd) {
      const std::uintptr_t hook = cursor[0];
      UserUnit* const recordOwner = (hook != 0u)
        ? reinterpret_cast<UserUnit*>(hook - 8u)
        : nullptr;
      if (recordOwner == unit) {
        break;
      }
      cursor += 2;
    }

    if (cursor == runEnd) {
      return;
    }

    // Apply the shared tail-patch walk over everything strictly after the
    // matched record so each remaining priority record's intrusive chain is
    // re-seated in lock-step.
    std::uint32_t* const tailBegin = cursor + 2;
    PatchUserArmyPriorityRegistryRecordTail(cursor, tailBegin, runEnd);

    // Walk the [cursor+2, runEnd) records one more time to retire their
    // per-record intrusive back-link entries -- this matches the second loop
    // in FUN_008B2470 which drains the old chain slot for each sliding pair.
    std::uint32_t* drainCursor = cursor + 2;
    while (drainCursor != runEnd) {
      std::uint32_t* const hook = reinterpret_cast<std::uint32_t*>(drainCursor[0]);
      if (hook != nullptr) {
        std::uint32_t* chainSlot = hook;
        while (*chainSlot != reinterpret_cast<std::uintptr_t>(drainCursor)) {
          chainSlot = reinterpret_cast<std::uint32_t*>(*chainSlot);
          chainSlot += 1;
        }
        *chainSlot = drainCursor[1];
      }
      drainCursor += 2;
    }

    avatars.pop_back_no_destroy();
  }

  /**
   * Address: 0x008B72F0 (FUN_008B72F0, struct_UserUnitManager::Get empty-check helper)
   *
   * What it does:
   * Resolves one command-manager active range and returns whether it is empty.
   */
  [[nodiscard]] bool IsUserCommandManagerQueueEmpty(const UserCommandQueue* const manager) noexcept
  {
    const UserCommandQueueRangeView* const queueRange =
      ResolveUserCommandQueueRange(manager);
    return queueRange == nullptr || queueRange->begin == queueRange->end;
  }

  /**
   * Address: 0x008B7320 (FUN_008B7320, struct_UserUnitManager::Get)
   *
   * What it does:
   * Resolves one command-manager queue view and returns the most recent
   * non-null helper entry, scanning backward from the logical tail.
   */
  [[maybe_unused]] [[nodiscard]] UserCommandIssueHelperRuntimeView* GetLastQueuedUserCommandHelper(
    UserCommandQueue* const managerPtr
  ) noexcept
  {
    UserCommandQueueLinkVector* const queueVector = RebuildAndGetUserUnitManagerQueue(managerPtr);
    UserCommandQueueEntry* const begin = queueVector->begin;

    std::ptrdiff_t index = static_cast<std::ptrdiff_t>(queueVector->end - begin) - 1;
    if (index < 0) {
      return nullptr;
    }

    UserCommandQueueEntry* cursor = begin + index;
    while (cursor->helper == nullptr) {
      --index;
      --cursor;
      if (index < 0) {
        return nullptr;
      }
    }

    return begin[index].helper;
  }

  /**
   * Address: 0x008C0D00 (FUN_008C0D00, cfunc_IssueDockCommandL idle candidate helper)
   *
   * What it does:
   * Returns whether one `UserUnit` is currently idle enough for dock-target
   * candidate selection (not busy and no pending command queue entries).
   */
  [[maybe_unused]] [[nodiscard]] bool IsDockTargetQueueIdle(const UserUnit* const unit) noexcept
  {
    if (unit == nullptr || GetLuaRuntimeView(unit).isBusy != 0u) {
      return false;
    }

    const UserCommandQueueRangeView* const queueRange = ResolveUserCommandQueueRange(unit->GetCommandQueue());
    return queueRange != nullptr && queueRange->begin == queueRange->end;
  }

  /**
   * Address: 0x008B5210 (FUN_008B5210)
   *
   * What it does:
   * Destroys every live local command-issue event from one helper ring queue,
   * releases per-slot event storage, then frees queue slot-map storage and
   * clears queue slot-capacity lanes.
   */
  [[maybe_unused]] void DestroyCommandIssueLocalQueue(UserCommandIssueLocalQueueRuntimeView* const queuePtr) noexcept
  {
    auto& queue = *queuePtr;
    while (queue.count != 0u) {
      std::uint32_t slot = queue.count + queue.readIndex - 1u;
      if (queue.capacity <= slot) {
        slot -= queue.capacity;
      }

      UserCommandIssueLocalEventRuntimeView* const event = queue.slots[slot];
      if (event != nullptr) {
        DestroyCommandIssueLocalEvent(*event);
      }

      queue.count -= 1u;
      if (queue.count == 0u) {
        queue.readIndex = 0u;
      }
    }

    for (std::uint32_t slot = queue.capacity; slot != 0u; --slot) {
      if (queue.slots == nullptr) {
        break;
      }

      UserCommandIssueLocalEventRuntimeView* const event = queue.slots[slot - 1u];
      if (event != nullptr) {
        ::operator delete(event);
      }
    }

    if (queue.slots != nullptr) {
      ::operator delete(queue.slots);
    }
    queue.slots = nullptr;
    queue.capacity = 0u;
  }

  void DestroyCommandIssueLocalQueue(CommandIssueLocalQueue& queue) noexcept
  {
    DestroyCommandIssueLocalQueue(reinterpret_cast<UserCommandIssueLocalQueueRuntimeView*>(&queue));
  }

  void DestroyCommandIssueWeakSet(CommandIssueWeakSet& set) noexcept
  {
    DestroyCommandIssueWeakSet(reinterpret_cast<UserCommandIssueWeakSetRuntimeView&>(set));
  }

  /**
   * Address: 0x008B79A0 (FUN_008B79A0)
   *
   * What it does:
   * Unlinks each resolved-queue entry from its helper-owned intrusive owner
   * chain across one half-open `[begin,end)` range.
   */
  /**
   * Address: 0x0082BA90 (FUN_0082BA90)
   *
   * What it does:
   * Unlinks one command-queue entry from its helper-owned intrusive owner
   * chain and returns the final owner-link cursor slot.
   */
  [[nodiscard]] UserCommandQueueEntry** UnlinkCommandQueueOwnerEntry(
    UserCommandQueueEntry* const entry
  ) noexcept
  {
    auto* ownerLink = reinterpret_cast<UserCommandQueueEntry**>(entry != nullptr ? entry->helper : nullptr);
    if (ownerLink == nullptr) {
      return ownerLink;
    }

    while (*ownerLink != nullptr && *ownerLink != entry) {
      ownerLink = reinterpret_cast<UserCommandQueueEntry**>(&(*ownerLink)->link);
    }

    if (*ownerLink == entry) {
      *ownerLink = reinterpret_cast<UserCommandQueueEntry*>(entry->link);
    }

    return ownerLink;
  }

  void UnlinkResolvedQueueOwnerLinks(
    UserCommandQueueEntry* const begin, UserCommandQueueEntry* const end
  ) noexcept
  {
    for (UserCommandQueueEntry* cursor = begin; cursor != end; ++cursor) {
      (void)UnlinkCommandQueueOwnerEntry(cursor);
    }
  }

  [[nodiscard]] inline WeakPtr<void>* AsWeakLane(
    UserCommandQueueEntry* const lane
  ) noexcept
  {
    return reinterpret_cast<WeakPtr<void>*>(lane);
  }

  [[nodiscard]] inline const WeakPtr<void>* AsWeakLane(
    const UserCommandQueueEntry* const lane
  ) noexcept
  {
    return reinterpret_cast<const WeakPtr<void>*>(lane);
  }

  [[nodiscard]] UserCommandQueueEntry* CopyQueueLinkRangeWithOwnerRelink(
    UserCommandQueueEntry* const destination,
    const UserCommandQueueEntry* const sourceBegin,
    const UserCommandQueueEntry* const sourceEnd
  ) noexcept
  {
    return reinterpret_cast<UserCommandQueueEntry*>(
      CopyWeakPtrRangeStdOrder(
        AsWeakLane(destination),
        AsWeakLane(sourceBegin),
        AsWeakLane(sourceEnd)
      )
    );
  }

  [[nodiscard]] UserCommandQueueEntry* AssignQueueLinkRangeWithOwnerRelink(
    UserCommandQueueEntry* const destination,
    const UserCommandQueueEntry* const sourceBegin,
    const UserCommandQueueEntry* const sourceEnd
  ) noexcept
  {
    return reinterpret_cast<UserCommandQueueEntry*>(
      AssignWeakPtrRangeForward(
        AsWeakLane(destination),
        AsWeakLane(sourceBegin),
        AsWeakLane(sourceEnd)
      )
    );
  }

  [[nodiscard]] UserCommandQueueEntry* AssignQueueLinkRangeBackwardWithOwnerRelink(
    UserCommandQueueEntry* const destinationEnd,
    const UserCommandQueueEntry* const sourceBegin,
    const UserCommandQueueEntry* const sourceEnd
  ) noexcept
  {
    return reinterpret_cast<UserCommandQueueEntry*>(
      AssignWeakPtrRangeBackward(
        AsWeakLane(destinationEnd),
        AsWeakLane(sourceBegin),
        AsWeakLane(sourceEnd)
      )
    );
  }

  /**
   * Address: 0x008B74A0 (FUN_008B74A0)
   *
   * What it does:
   * Unlinks one queue-link vector range, then restores inline storage ownership
   * when the active storage pointer differs from the inline lane.
   */
  [[maybe_unused]] UserCommandQueueEntry* ResetQueueLinkVectorToInlineStorage(
    UserCommandQueueLinkVector* const linkVector
  ) noexcept
  {
    UnlinkResolvedQueueOwnerLinks(linkVector->begin, linkVector->end);

    UserCommandQueueEntry* result = linkVector->begin;
    if (linkVector->begin == reinterpret_cast<UserCommandQueueEntry*>(linkVector->inlineBase))
    {
      linkVector->end = result;
      return result;
    }

    ::operator delete[](linkVector->begin);
    linkVector->begin = reinterpret_cast<UserCommandQueueEntry*>(linkVector->inlineBase);
    result = (linkVector->inlineBase != nullptr) ? *linkVector->inlineBase : nullptr;
    linkVector->capacityEnd = result;
    linkVector->end = linkVector->begin;
    return result;
  }

  /**
   * Address: 0x008B7540 (FUN_008B7540)
   *
   * What it does:
   * Erases one queue-link entry by shift-assigning `[erase+1,end)` over the
   * erased slot, then unlinks the trailing stale owner-link lane.
   */
  [[maybe_unused]] UserCommandQueueEntry* EraseQueueLinkEntryAndShrinkRange(
    UserCommandQueueEntry* const eraseAt,
    UserCommandQueueLinkVector* const linkVector
  ) noexcept
  {
    UserCommandQueueEntry* const oldEnd = linkVector->end;
    if (eraseAt != oldEnd)
    {
      UserCommandQueueEntry* const newEnd = AssignQueueLinkRangeWithOwnerRelink(
        eraseAt,
        eraseAt + 1,
        oldEnd
      );
      UnlinkResolvedQueueOwnerLinks(newEnd, oldEnd);
      linkVector->end = newEnd;
    }

    return eraseAt;
  }

  /**
   * Address: 0x008B7CC0 (FUN_008B7CC0)
   *
   * What it does:
   * Reallocates one queue-link vector to `targetElementCapacity` lanes, copies
   * `{prefix,insertRange,suffix}` in order, unlinks old owner links, then swaps
   * storage and updates `{begin,end,capacity}` lanes.
   */
  UserCommandQueueEntry* GrowQueueLinkVectorAndInsertRange(
    UserCommandQueueLinkVector* const linkVector,
    const std::uint32_t targetElementCapacity,
    UserCommandQueueEntry* const insertionPoint,
    const UserCommandQueueEntry* const sourceBegin,
    const UserCommandQueueEntry* const sourceEnd
  )
  {
    const std::size_t byteCount =
      static_cast<std::size_t>(targetElementCapacity) * sizeof(UserCommandQueueEntry);
    auto* const newStorage = static_cast<UserCommandQueueEntry*>(::operator new(byteCount));

    UserCommandQueueEntry* writeCursor = CopyQueueLinkRangeWithOwnerRelink(
      newStorage,
      linkVector->begin,
      insertionPoint
    );
    writeCursor = CopyQueueLinkRangeWithOwnerRelink(
      writeCursor,
      sourceBegin,
      sourceEnd
    );
    UserCommandQueueEntry* const newEnd = CopyQueueLinkRangeWithOwnerRelink(
      writeCursor,
      insertionPoint,
      linkVector->end
    );

    UnlinkResolvedQueueOwnerLinks(linkVector->begin, linkVector->end);
    if (linkVector->begin == reinterpret_cast<UserCommandQueueEntry*>(linkVector->inlineBase))
    {
      if (linkVector->inlineBase != nullptr)
      {
        *linkVector->inlineBase = linkVector->capacityEnd;
      }
    }
    else
    {
      ::operator delete[](linkVector->begin);
    }

    linkVector->begin = newStorage;
    linkVector->end = newEnd;
    linkVector->capacityEnd = newStorage + targetElementCapacity;
    return linkVector->capacityEnd;
  }

  /**
   * Address: 0x008B7900 (FUN_008B7900)
   *
   * IDA signature:
   * int __userpurge sub_8B7900@<eax>(int newEnd@<edx>, int linkVector@<ebx>, int a3);
   *
   * What it does:
   * Drops the tail `[newEnd, end)` of one queue-link run. The binary reaches
   * the shared assign-range helper first, but its only caller hands that call
   * an empty source range, so the whole effect is the unlink of the dropped
   * lanes followed by the shortened end.
   */
  UserCommandQueueEntry* ShrinkQueueLinkVectorTo(
    UserCommandQueueLinkVector* const linkVector,
    UserCommandQueueEntry* const newEnd
  ) noexcept
  {
    if (newEnd != linkVector->end) {
      (void)AssignQueueLinkRangeWithOwnerRelink(newEnd, linkVector->end, linkVector->end);
      UnlinkResolvedQueueOwnerLinks(newEnd, linkVector->end);
      linkVector->end = newEnd;
    }
    return newEnd;
  }

  /**
   * Address: 0x008B7590 (FUN_008B7590)
   *
   * IDA signature:
   * unsigned int __usercall sub_8B7590@<eax>(unsigned int count@<eax>,
   *   unsigned int *linkVector@<ecx>, unsigned int **fillEntry@<edi>);
   *
   * What it does:
   * Resizes one queue-link run to `elementCount`. Shrinking drops the tail;
   * growing reallocates when the request outruns capacity and then appends
   * copies of `fillEntry`, each linked into whatever owner chain that template
   * entry names. `UserUnit`'s command resync passes a cleared template, so the
   * appended lanes come out unbound.
   */
  void ResizeQueueLinkVector(
    UserCommandQueueLinkVector* const linkVector,
    const std::size_t elementCount,
    const UserCommandQueueEntry& fillEntry
  )
  {
    const std::size_t size = static_cast<std::size_t>(linkVector->end - linkVector->begin);
    if (elementCount < size) {
      (void)ShrinkQueueLinkVectorTo(linkVector, linkVector->begin + elementCount);
      return;
    }
    if (elementCount == size) {
      return;
    }

    const std::size_t capacity = static_cast<std::size_t>(linkVector->capacityEnd - linkVector->begin);
    if (elementCount > capacity) {
      (void)GrowQueueLinkVectorAndInsertRange(
        linkVector,
        static_cast<std::uint32_t>(elementCount),
        linkVector->begin,
        linkVector->begin,
        linkVector->begin
      );
    }

    UserCommandQueueEntry* const target = linkVector->begin + elementCount;
    while (linkVector->end != target) {
      UserCommandQueueEntry* const slot = linkVector->end;
      linkVector->end = slot + 1;

      slot->helper = fillEntry.helper;
      if (fillEntry.helper != nullptr) {
        auto** const ownerHead = reinterpret_cast<UserCommandQueueEntry**>(fillEntry.helper);
        slot->link = *ownerHead;
        *ownerHead = slot;
      } else {
        slot->link = nullptr;
      }
    }
  }

  /**
   * Address: 0x008B77D0 (FUN_008B77D0)
   *
   * What it does:
   * Inserts one queue-link range at `insertionPoint` with in-place move/copy
   * when capacity is sufficient, otherwise grows storage through `FUN_008B7CC0`.
   * Preserves intrusive weak-owner relink semantics for all shifted/copied lanes.
   */
  [[maybe_unused]] UserCommandQueueEntry* InsertQueueLinkRangeWithGrowth(
    UserCommandQueueLinkVector* const linkVector,
    UserCommandQueueEntry* const insertionPoint,
    const UserCommandQueueEntry* const sourceBegin,
    const UserCommandQueueEntry* const sourceEnd
  )
  {
    const std::ptrdiff_t insertCount = sourceEnd - sourceBegin;
    const std::ptrdiff_t size = linkVector->end - linkVector->begin;
    const std::ptrdiff_t capacity = linkVector->capacityEnd - linkVector->begin;
    const std::ptrdiff_t requestedSize = size + insertCount;

    if (requestedSize > capacity)
    {
      std::uint32_t targetCapacity = static_cast<std::uint32_t>(requestedSize);
      const std::uint32_t doubledCapacity = static_cast<std::uint32_t>(capacity * 2);
      if (targetCapacity < doubledCapacity)
      {
        targetCapacity = doubledCapacity;
      }

      return GrowQueueLinkVectorAndInsertRange(
        linkVector,
        targetCapacity,
        insertionPoint,
        sourceBegin,
        sourceEnd
      );
    }

    UserCommandQueueEntry* const oldEnd = linkVector->end;
    UserCommandQueueEntry* const insertionEnd = insertionPoint + insertCount;

    if (insertionEnd > oldEnd)
    {
      const std::ptrdiff_t tailCount = oldEnd - insertionPoint;
      const UserCommandQueueEntry* const sourceMiddle = sourceBegin + tailCount;

      linkVector->end = CopyQueueLinkRangeWithOwnerRelink(
        oldEnd,
        sourceMiddle,
        sourceEnd
      );
      linkVector->end = CopyQueueLinkRangeWithOwnerRelink(
        linkVector->end,
        insertionPoint,
        oldEnd
      );
      return AssignQueueLinkRangeBackwardWithOwnerRelink(
        oldEnd,
        sourceBegin,
        sourceMiddle
      );
    }

    UserCommandQueueEntry* const tailStart = oldEnd - insertCount;
    linkVector->end = CopyQueueLinkRangeWithOwnerRelink(
      oldEnd,
      tailStart,
      oldEnd
    );
    (void)AssignQueueLinkRangeBackwardWithOwnerRelink(
      oldEnd,
      insertionPoint,
      tailStart
    );
    return AssignQueueLinkRangeBackwardWithOwnerRelink(
      insertionEnd,
      sourceBegin,
      sourceEnd
    );
  }

  [[nodiscard]] SessionCommandIssueMapNodeView*
  FindSessionCommandIssueNode(SessionCommandIssueMapView& map, const CmdId commandId) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    if (head == nullptr) {
      return nullptr;
    }

    const std::uint32_t key = static_cast<std::uint32_t>(commandId);
    SessionCommandIssueMapNodeView* result = head;
    SessionCommandIssueMapNodeView* node = head->parent;
    while (node != nullptr && node != head && node->isNil == 0u) {
      if (node->key >= key) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    if (result == head || key < result->key) {
      return head;
    }

    return result;
  }

  [[nodiscard]] UserCommandIssueHelperRuntimeView*
  FindSessionCommandIssueHelperById(CWldSession* const session, const CmdId commandId) noexcept
  {
    if (session == nullptr || session->mCommandManager == nullptr) {
      return nullptr;
    }

    auto* const commandManager =
      session->mCommandManager;
    SessionCommandIssueMapView& issueMap = CommandIssueMapOf(*commandManager);
    SessionCommandIssueMapNodeView* const node = FindSessionCommandIssueNode(issueMap, commandId);
    if (node == nullptr || node == issueMap.head) {
      return nullptr;
    }

    return node->value;
  }

  [[nodiscard]] SessionCommandIssueMapNodeView* NextSessionCommandIssueNode(
    SessionCommandIssueMapNodeView* node,
    SessionCommandIssueMapNodeView* const head
  ) noexcept
  {
    if (node == nullptr || head == nullptr || node == head) {
      return head;
    }

    if (node->right != nullptr && node->right != head && node->right->isNil == 0u) {
      node = node->right;
      while (node->left != nullptr && node->left != head && node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    SessionCommandIssueMapNodeView* parent = node->parent;
    while (parent != nullptr && parent != head && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }

    return (parent != nullptr) ? parent : head;
  }

  [[nodiscard]] bool IsSessionCommandIssueNil(const SessionCommandIssueMapNodeView* const node) noexcept
  {
    return node == nullptr || node->isNil != 0u;
  }

  [[nodiscard]] std::uint8_t SessionCommandIssueNodeColor(
    const SessionCommandIssueMapNodeView* const node,
    const SessionCommandIssueMapNodeView* const head
  ) noexcept
  {
    return (node == nullptr || node == head || node->isNil != 0u) ? 1u : node->color;
  }

  [[nodiscard]] SessionCommandIssueMapNodeView*
  SessionCommandIssueMin(SessionCommandIssueMapNodeView* node, SessionCommandIssueMapNodeView* const head) noexcept
  {
    while (!IsSessionCommandIssueNil(node->left) && node->left != head) {
      node = node->left;
    }
    return node;
  }

  [[nodiscard]] SessionCommandIssueMapNodeView*
  SessionCommandIssueMax(SessionCommandIssueMapNodeView* node, SessionCommandIssueMapNodeView* const head) noexcept
  {
    while (!IsSessionCommandIssueNil(node->right) && node->right != head) {
      node = node->right;
    }
    return node;
  }

  void RefreshSessionCommandIssueMapBounds(SessionCommandIssueMapView& map) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    if (head == nullptr) {
      return;
    }

    SessionCommandIssueMapNodeView* const root = head->parent;
    if (root == nullptr || root == head || root->isNil != 0u) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    head->left = SessionCommandIssueMin(root, head);
    head->right = SessionCommandIssueMax(root, head);
  }

  void RotateSessionCommandIssueLeft(SessionCommandIssueMapView& map, SessionCommandIssueMapNodeView* const node) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    SessionCommandIssueMapNodeView* const pivot = node->right;
    node->right = pivot->left;
    if (pivot->left != head && !IsSessionCommandIssueNil(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void RotateSessionCommandIssueRight(SessionCommandIssueMapView& map, SessionCommandIssueMapNodeView* const node) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    SessionCommandIssueMapNodeView* const pivot = node->left;
    node->left = pivot->right;
    if (pivot->right != head && !IsSessionCommandIssueNil(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void ReplaceSessionCommandIssueSubtree(
    SessionCommandIssueMapView& map,
    SessionCommandIssueMapNodeView* const oldNode,
    SessionCommandIssueMapNodeView* const newNode
  ) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    if (oldNode->parent == head) {
      head->parent = newNode;
    } else if (oldNode == oldNode->parent->left) {
      oldNode->parent->left = newNode;
    } else {
      oldNode->parent->right = newNode;
    }

    if (newNode != head && !IsSessionCommandIssueNil(newNode)) {
      newNode->parent = oldNode->parent;
    }
  }

  void FixupSessionCommandIssueErase(
    SessionCommandIssueMapView& map,
    SessionCommandIssueMapNodeView* node,
    SessionCommandIssueMapNodeView* nodeParent
  ) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    SessionCommandIssueMapNodeView* parent =
      (node != head && !IsSessionCommandIssueNil(node)) ? node->parent : nodeParent;

    while (node != head->parent && SessionCommandIssueNodeColor(node, head) == 1u) {
      if (parent == nullptr || parent == head) {
        break;
      }

      if (node == parent->left) {
        SessionCommandIssueMapNodeView* sibling = parent->right;
        if (sibling == head || IsSessionCommandIssueNil(sibling)) {
          node = parent;
          parent = node->parent;
          continue;
        }

        if (SessionCommandIssueNodeColor(sibling, head) == 0u) {
          sibling->color = 1u;
          parent->color = 0u;
          RotateSessionCommandIssueLeft(map, parent);
          sibling = parent->right;
        }

        if (
          SessionCommandIssueNodeColor(sibling->left, head) == 1u
          && SessionCommandIssueNodeColor(sibling->right, head) == 1u
        ) {
          sibling->color = 0u;
          node = parent;
          parent = node->parent;
          continue;
        }

        if (SessionCommandIssueNodeColor(sibling->right, head) == 1u) {
          if (sibling->left != head && !IsSessionCommandIssueNil(sibling->left)) {
            sibling->left->color = 1u;
          }
          sibling->color = 0u;
          RotateSessionCommandIssueRight(map, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = 1u;
        if (sibling->right != head && !IsSessionCommandIssueNil(sibling->right)) {
          sibling->right->color = 1u;
        }
        RotateSessionCommandIssueLeft(map, parent);
        node = head->parent;
      } else {
        SessionCommandIssueMapNodeView* sibling = parent->left;
        if (sibling == head || IsSessionCommandIssueNil(sibling)) {
          node = parent;
          parent = node->parent;
          continue;
        }

        if (SessionCommandIssueNodeColor(sibling, head) == 0u) {
          sibling->color = 1u;
          parent->color = 0u;
          RotateSessionCommandIssueRight(map, parent);
          sibling = parent->left;
        }

        if (
          SessionCommandIssueNodeColor(sibling->right, head) == 1u
          && SessionCommandIssueNodeColor(sibling->left, head) == 1u
        ) {
          sibling->color = 0u;
          node = parent;
          parent = node->parent;
          continue;
        }

        if (SessionCommandIssueNodeColor(sibling->left, head) == 1u) {
          if (sibling->right != head && !IsSessionCommandIssueNil(sibling->right)) {
            sibling->right->color = 1u;
          }
          sibling->color = 0u;
          RotateSessionCommandIssueLeft(map, sibling);
          sibling = parent->left;
        }

        sibling->color = parent->color;
        parent->color = 1u;
        if (sibling->left != head && !IsSessionCommandIssueNil(sibling->left)) {
          sibling->left->color = 1u;
        }
        RotateSessionCommandIssueRight(map, parent);
        node = head->parent;
      }
    }

    if (node != head && !IsSessionCommandIssueNil(node)) {
      node->color = 1u;
    }
  }

  void EraseSessionCommandIssueNode(SessionCommandIssueMapView& map, SessionCommandIssueMapNodeView* const node) noexcept
  {
    SessionCommandIssueMapNodeView* const head = map.head;
    if (head == nullptr || node == nullptr || node == head || node->isNil != 0u) {
      return;
    }

    SessionCommandIssueMapNodeView* spliceTarget = node;
    SessionCommandIssueMapNodeView* fixNode = head;
    SessionCommandIssueMapNodeView* fixParent = head;
    std::uint8_t removedColor = spliceTarget->color;

    if (node->left == head || IsSessionCommandIssueNil(node->left)) {
      fixNode = node->right;
      fixParent = node->parent;
      ReplaceSessionCommandIssueSubtree(map, node, node->right);
    } else if (node->right == head || IsSessionCommandIssueNil(node->right)) {
      fixNode = node->left;
      fixParent = node->parent;
      ReplaceSessionCommandIssueSubtree(map, node, node->left);
    } else {
      spliceTarget = SessionCommandIssueMin(node->right, head);
      removedColor = spliceTarget->color;
      fixNode = spliceTarget->right;
      if (spliceTarget->parent == node) {
        fixParent = spliceTarget;
        if (fixNode != head && !IsSessionCommandIssueNil(fixNode)) {
          fixNode->parent = spliceTarget;
        }
      } else {
        fixParent = spliceTarget->parent;
        ReplaceSessionCommandIssueSubtree(map, spliceTarget, spliceTarget->right);
        spliceTarget->right = node->right;
        spliceTarget->right->parent = spliceTarget;
      }

      ReplaceSessionCommandIssueSubtree(map, node, spliceTarget);
      spliceTarget->left = node->left;
      spliceTarget->left->parent = spliceTarget;
      spliceTarget->color = node->color;
    }

    if (removedColor == 1u) {
      FixupSessionCommandIssueErase(map, fixNode, fixParent);
    }

    ::operator delete(node);
    if (map.size != 0u) {
      --map.size;
    }
    RefreshSessionCommandIssueMapBounds(map);
  }

  void RemoveCommandIssueHelperFromActiveSessionMap(const UserCommandIssueHelper& helper) noexcept
  {
    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr || session->mCommandManager == nullptr) {
      return;
    }

    auto* const commandManager = session->mCommandManager;
    SessionCommandIssueMapView& issueMap = CommandIssueMapOf(*commandManager);
    SessionCommandIssueMapNodeView* const node =
      FindSessionCommandIssueNode(issueMap, static_cast<CmdId>(helper.mConstantData.cmd));
    if (node == nullptr || node == issueMap.head) {
      return;
    }

    // Source-level coverage for FUN_008B5EB0: this is the original
    // `std::map<CmdId, CommandIssueHelper*>::erase(iterator)` construct.
    EraseSessionCommandIssueNode(issueMap, node);
  }

  void AppendQueueLinkStagedEntry(
    UserCommandQueueLinkVector* const linkVector,
    UserCommandQueueEntry* const stagedEntry
  )
  {
    UserCommandQueueEntry* const appendAt = linkVector->end;
    if (appendAt == linkVector->capacityEnd) {
      (void)InsertQueueLinkRangeWithGrowth(linkVector, appendAt, stagedEntry, stagedEntry + 1);
      return;
    }

    if (appendAt != nullptr) {
      appendAt->helper = stagedEntry->helper;
      if (stagedEntry->helper != nullptr) {
        appendAt->link = stagedEntry->link;
        *reinterpret_cast<UserCommandQueueEntry**>(stagedEntry->helper) = appendAt;
      } else {
        appendAt->link = nullptr;
      }
    }
    linkVector->end += 1;
  }

  /**
   * Address: 0x008B6F60 (FUN_008B6F60, struct_UserUnitManager::Get)
   *
   * What it does:
   * Rebuilds one resolved command queue from the primary queue and pending
   * issue operations when the resolved view is dirty, then returns the active
   * queue vector (`primary` when no pending issues, otherwise `resolved`).
   */
  [[nodiscard]] UserCommandQueueLinkVector* RebuildAndGetUserUnitManagerQueue(
    UserCommandQueue* const managerPtr
  ) noexcept
  {
    if (managerPtr == nullptr) {
      return nullptr;
    }

    auto& manager = *managerPtr;
    if (manager.issueQueue.size == 0u) {
      return &manager.primaryLinks;
    }

    if (manager.resolvedLinksDirty == 0u) {
      return &manager.resolvedLinks;
    }

    manager.resolvedLinksDirty = 0u;
    (void)ResetQueueLinkVectorToInlineStorage(&manager.resolvedLinks);

    for (UserCommandQueueEntry* entry = manager.primaryLinks.begin;
         entry != manager.primaryLinks.end;
         ++entry) {
      UserCommandIssueHelperRuntimeView* const helper = entry->helper;
      if (helper == nullptr) {
        continue;
      }

      UserCommandQueueEntry staged{};
      auto** const ownerHead = reinterpret_cast<UserCommandQueueEntry**>(helper);
      staged.helper = helper;
      staged.link = *ownerHead;
      *ownerHead = &staged;

      AppendQueueLinkStagedEntry(&manager.resolvedLinks, &staged);
      (void)UnlinkCommandQueueOwnerEntry(&staged);
    }

    if (manager.issueQueue.blockCount == 0u || manager.issueQueue.blocks == nullptr) {
      return &manager.resolvedLinks;
    }

    const std::uint32_t queueSize = manager.issueQueue.size;
    for (std::uint32_t ordinal = 0; ordinal < queueSize; ++ordinal) {
      std::uint32_t slot = manager.issueQueue.startOffset + ordinal;
      if (slot >= manager.issueQueue.blockCount) {
        slot -= manager.issueQueue.blockCount;
      }

      UserManagerHelperEntry* const pending = manager.issueQueue.blocks[slot];
      if (pending == nullptr) {
        continue;
      }

      if (pending->commandType == 1) {
        (void)ResetQueueLinkVectorToInlineStorage(&manager.resolvedLinks);
        continue;
      }

      if (pending->commandType == 2) {
        UserCommandIssueHelperRuntimeView* const helperToRemove =
          reinterpret_cast<UserCommandIssueHelperRuntimeView*>(pending->subject);
        if (helperToRemove == nullptr) {
          continue;
        }

        UserCommandQueueEntry* found = manager.resolvedLinks.begin;
        while (found != manager.resolvedLinks.end && found->helper != helperToRemove) {
          ++found;
        }
        if (found != manager.resolvedLinks.end) {
          (void)EraseQueueLinkEntryAndShrinkRange(found, &manager.resolvedLinks);
        }
        continue;
      }

      if (pending->commandType != 0 || pending->subject == nullptr) {
        continue;
      }

      const std::uint32_t encodedCommandId = static_cast<std::uint32_t>(pending->sequenceOrCount);
      if ((encodedCommandId & 0xFF000000u) != 0xFF000000u) {
        CWldSession* const activeSession = WLD_GetActiveSession();
        UserCommandIssueHelperRuntimeView* const helperToInsert =
          FindSessionCommandIssueHelperById(activeSession, static_cast<CmdId>(pending->sequenceOrCount));
        if (helperToInsert == nullptr) {
          continue;
        }

        UserCommandQueueEntry* insertionPoint = manager.resolvedLinks.begin;
        while (insertionPoint != manager.resolvedLinks.end && insertionPoint->helper != helperToInsert) {
          ++insertionPoint;
        }
        if (insertionPoint == nullptr) {
          continue;
        }

        UserCommandQueueEntry staged{};
        auto** const ownerHead = reinterpret_cast<UserCommandQueueEntry**>(helperToInsert);
        staged.helper = helperToInsert;
        staged.link = *ownerHead;
        *ownerHead = &staged;

        (void)InsertQueueLinkRangeWithGrowth(
          &manager.resolvedLinks,
          insertionPoint,
          &staged,
          &staged + 1
        );
        (void)UnlinkCommandQueueOwnerEntry(&staged);
        continue;
      }

      UserCommandIssueHelperRuntimeView* const helperToAppend =
        reinterpret_cast<UserCommandIssueHelperRuntimeView*>(pending->subject);
      if (helperToAppend == nullptr) {
        continue;
      }

      UserCommandQueueEntry staged{};
      auto** const ownerHead = reinterpret_cast<UserCommandQueueEntry**>(helperToAppend);
      staged.helper = helperToAppend;
      staged.link = *ownerHead;
      *ownerHead = &staged;

      AppendQueueLinkStagedEntry(&manager.resolvedLinks, &staged);
      (void)UnlinkCommandQueueOwnerEntry(&staged);
    }

    return &manager.resolvedLinks;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0081D030 (FUN_0081D030)
   *
   * What it does:
   * Returns the active user-command queue length (element count) by rebuilding
   * and resolving the current queue vector, then computing `(end - begin)`.
   * Exposed (namespace moho, declared in UserUnit.h) so the client-side
   * `ISSUE_Command` keystone (Sim.cpp) can enforce the 500-entry depth cap.
   */
  [[nodiscard]] std::int32_t GetUserUnitManagerQueueSize(
    UserCommandQueue* const managerPtr
  ) noexcept
  {
    const UserCommandQueueLinkVector* const queueVector = RebuildAndGetUserUnitManagerQueue(managerPtr);
    return static_cast<std::int32_t>(queueVector->end - queueVector->begin);
  }
} // namespace moho

namespace
{

  [[nodiscard]] UserManagerHelperEntry* AllocateUserManagerHelperSlots(const std::uint32_t count)
  {
    if (count > (std::numeric_limits<std::uint32_t>::max() / sizeof(UserManagerHelperEntry))) {
      throw std::bad_alloc();
    }

    const std::size_t byteCount = static_cast<std::size_t>(count) * sizeof(UserManagerHelperEntry);
    return static_cast<UserManagerHelperEntry*>(::operator new(byteCount));
  }

  /**
   * Address: 0x008B79E0 (FUN_008B79E0, std::deque map-growth lane for the issue queue)
   *
   * What it does:
   * Grows one user-manager issue-queue block map (the deque of 16-byte helper
   * entries) by ~1.5x (min +8, clamped to 0x0FFFFFFF slots), re-homing existing
   * block pointers into the freshly-allocated map by modulo-reindex. Behaviorally
   * identical to the binary's 3-part memmove recentering (verified vs .asm).
   */
  void GrowUserManagerIssueQueueMap(UserManagerIssueQueue& queue)
  {
    constexpr std::uint32_t kMaxMapSlots = 0x0FFFFFFFu;

    const std::uint32_t oldSlotCount = queue.blockCount;
    if ((kMaxMapSlots - oldSlotCount) < 1u) {
      throw std::length_error("User manager issue queue map overflow");
    }

    std::uint32_t growth = 1u;
    std::uint32_t candidateGrowth = oldSlotCount >> 1u;
    if (candidateGrowth < 8u) {
      candidateGrowth = 8u;
    }
    if (candidateGrowth > 1u && oldSlotCount <= (kMaxMapSlots - candidateGrowth)) {
      growth = candidateGrowth;
    }

    const std::uint32_t newSlotCount = oldSlotCount + growth;
    auto** const newBlocks =
      static_cast<UserManagerHelperEntry**>(::operator new(sizeof(UserManagerHelperEntry*) * newSlotCount));
    std::memset(newBlocks, 0, sizeof(UserManagerHelperEntry*) * newSlotCount);

    if (oldSlotCount != 0u && queue.blocks != nullptr) {
      for (std::uint32_t ordinal = 0; ordinal < oldSlotCount; ++ordinal) {
        std::uint32_t oldIndex = queue.startOffset + ordinal;
        if (oldIndex >= oldSlotCount) {
          oldIndex -= oldSlotCount;
        }

        std::uint32_t newIndex = queue.startOffset + ordinal;
        if (newIndex >= newSlotCount) {
          newIndex -= newSlotCount;
        }

        newBlocks[newIndex] = queue.blocks[oldIndex];
      }

      ::operator delete(queue.blocks);
    }

    queue.blockCount = newSlotCount;
    queue.blocks = newBlocks;
  }

  void ClearUserManagerIssueQueue(UserManagerIssueQueue& queue) noexcept
  {
    while (queue.size != 0u) {
      queue.size -= 1u;
      if (queue.size == 0u) {
        queue.startOffset = 0u;
      }
    }

    for (std::uint32_t slot = queue.blockCount; slot != 0u; --slot) {
      if (queue.blocks == nullptr) {
        break;
      }

      if (UserManagerHelperEntry* const block = queue.blocks[slot - 1u]; block != nullptr) {
        ::operator delete(block);
      }
    }

    if (queue.blocks != nullptr) {
      ::operator delete(queue.blocks);
      queue.blocks = nullptr;
    }
    queue.blockCount = 0u;
  }

  /**
   * Address: 0x008B76D0 (FUN_008B76D0, std::queue<UserManagerHelperEntry>::push_back)
   *
   * What it does:
   * Pushes one `UserManagerHelperEntry` (0x10 bytes) onto the tail of the
   * user-manager issue-queue deque, growing the block map (GrowUserManagerIssueQueueMap)
   * and allocating a fresh block (AllocateUserManagerHelperSlots) when the tail
   * block is full.
   */
  void PushUserManagerIssue(UserManagerIssueQueue& queue, const UserManagerHelperEntry& entry)
  {
    if (queue.blockCount <= (queue.size + 1u)) {
      GrowUserManagerIssueQueueMap(queue);
    }

    std::uint32_t slot = queue.startOffset + queue.size;
    if (queue.blockCount <= slot) {
      slot -= queue.blockCount;
    }

    if (queue.blocks[slot] == nullptr) {
      queue.blocks[slot] = AllocateUserManagerHelperSlots(1u);
    }
    if (queue.blocks[slot] != nullptr) {
      *queue.blocks[slot] = entry;
    }

    queue.size += 1u;
  }

  void DestroyUserUnitManagerState(UserCommandQueue* managerPtr) noexcept;

  /**
   * Address: 0x008C5D00 (FUN_008C5D00)
   *
   * What it does:
   * Runs one deleting teardown path for `UserCommandQueue` and returns the
   * original pointer lane.
   */
  [[maybe_unused]] UserCommandQueue* DeleteUserUnitManagerAndReturn(UserCommandQueue* const managerPtr) noexcept
  {
    DestroyUserUnitManagerState(managerPtr);
    ::operator delete(managerPtr);
    return managerPtr;
  }

  /**
   * Address: 0x008C5AF0 (FUN_008C5AF0)
   *
   * What it does:
   * Replaces one `UserCommandQueue*` owner slot and deletes the previous manager
   * when it is distinct from the replacement pointer.
   */
  [[maybe_unused]] void ReplaceOwnedUserUnitManager(
    UserCommandQueue** const slot,
    UserCommandQueue* const replacement
  ) noexcept
  {
    UserCommandQueue* const previous = *slot;
    if (previous != nullptr && previous != replacement) {
      DestroyUserUnitManagerState(previous);
      ::operator delete(previous);
    }
    *slot = replacement;
  }

  /**
   * Address: 0x008B6BE0 (FUN_008B6BE0, struct_UserUnitManager::~struct_UserUnitManager)
   *
   * What it does:
   * Releases owner-link lanes for resolved/primary vectors, clears pending
   * issue queue blocks, and restores both vectors to inline storage.
   */
  void DestroyUserUnitManagerState(UserCommandQueue* const managerPtr) noexcept
  {
    if (managerPtr == nullptr) {
      return;
    }

    auto& manager = *managerPtr;

    (void)ResetQueueLinkVectorToInlineStorage(&manager.resolvedLinks);

    ClearUserManagerIssueQueue(manager.issueQueue);

    (void)ResetQueueLinkVectorToInlineStorage(&manager.primaryLinks);
  }

  /**
   * Address: 0x008B6C50 (FUN_008B6C50)
   *
   * IDA signature:
   * _DWORD *__stdcall sub_8B6C50(int queue, _DWORD *commandIdRun);
   *
   * What it does:
   * Rebinds one command queue's primary link run to the command ids the sim
   * just replicated. The run is resized to the id count with cleared lanes,
   * then each lane is pointed at the live `UserCommandIssueHelper` the session
   * command manager holds for that id - unbinding first when the lane already
   * named a different helper, and left null when the id is unknown. The
   * resolved run is then invalidated back onto its inline storage and marked
   * dirty so the next reader rebuilds it.
   */
  void ResyncUserCommandQueueLinks(UserCommandQueue* const queue, const CmdId* const idBegin, const CmdId* const idEnd)
  {
    if (queue == nullptr) {
      return;
    }

    CommandManager* const commandManager = WLD_GetActiveSession()->mCommandManager;
    const std::size_t idCount = static_cast<std::size_t>(idEnd - idBegin);

    // The template entry is a plain unbound lane; it is a local in the binary
    // too (0x008B6C8A), unlinked again right after the resize.
    const UserCommandQueueEntry unboundEntry{nullptr, nullptr};
    ResizeQueueLinkVector(&queue->primaryLinks, idCount, unboundEntry);

    for (std::size_t index = 0; index < idCount; ++index) {
      UserCommandIssueHelper* liveHelper = nullptr;
      if (commandManager != nullptr) {
        const auto found = commandManager->mCommands.find(idBegin[index]);
        if (found != commandManager->mCommands.end()) {
          liveHelper = found->second;
        }
      }

      auto* const helperView = reinterpret_cast<UserCommandIssueHelperRuntimeView*>(liveHelper);
      UserCommandQueueEntry* const lane = queue->primaryLinks.begin + index;
      if (lane->helper == helperView) {
        continue;
      }

      (void)UnlinkCommandQueueOwnerEntry(lane);

      lane->helper = helperView;
      if (helperView != nullptr) {
        // A helper's own observer chain head is its first word, so the helper
        // pointer doubles as the owner-link slot.
        auto** const ownerHead = reinterpret_cast<UserCommandQueueEntry**>(helperView);
        lane->link = *ownerHead;
        *ownerHead = lane;
      } else {
        lane->link = nullptr;
      }
    }

    queue->resolvedLinksDirty = 1u;
    (void)ResetQueueLinkVectorToInlineStorage(&queue->resolvedLinks);
  }

  /**
   * Address: 0x008B7350 (FUN_008B7350)
   *
   * What it does:
   * Consumes pending command-issue slots whose due sequence is <= `seqNo`,
   * marks resolved links dirty, then rebuilds resolved-link storage back to
   * inline mode when any slot was consumed.
   */
  void AdvanceUserCommandManagerBySeq(UserCommandQueue* const managerPtr, const std::int32_t seqNo) noexcept
  {
    auto* const manager = reinterpret_cast<UserCommandManagerRuntimeView*>(managerPtr);

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
    if (manager->resolvedRange.begin != reinterpret_cast<UserCommandQueueEntry*>(manager->resolvedRangeInlineStorage)) {
      ::operator delete[](manager->resolvedRange.begin);
      manager->resolvedRange.begin = reinterpret_cast<UserCommandQueueEntry*>(manager->resolvedRangeInlineStorage);
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

  /**
   * Address: 0x008BEE30 (FUN_008BEE30)
   *
   * What it does:
   * Resolves one command-target entity owner when target type is `Entity`
   * (`1`) and the weak-owner slot is non-null; returns null otherwise.
   */
  [[maybe_unused]] [[nodiscard]] UserEntity* DecodeEntityFromCommandTargetIfEntity(
    const UserCommandTargetView* const target
  ) noexcept
  {
    if (target->targetType == UserTargetType::Entity && target->targetEntity.ownerLinkSlot != 0u) {
      return reinterpret_cast<UserEntity*>(target->targetEntity.ownerLinkSlot - kUserEntityWeakOwnerOffset);
    }

    return nullptr;
  }

  [[nodiscard]] Wm3::Vector3<float> InvalidCommandQueuePosition() noexcept
  {
    return Invalid<Wm3::Vector3<float>>();
  }

  [[nodiscard]] UserEntity* FindSessionEntityById(CWldSession* session, std::int32_t entityId) noexcept;

  /**
   * Address: 0x008BED50 (FUN_008BED50, sub_8BED50)
   *
   * What it does:
   * Resolves one command-target world position: returns entity position when
   * target type is `Entity` and weak owner resolves, returns inline target
   * position for `Position`, otherwise returns `Invalid<Wm3::Vector3f>()`.
   */
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

  /**
   * Address: 0x008B4140 (FUN_008B4140)
   *
   * What it does:
   * Scans command-issue events from newest to oldest and returns the most
   * recent explicit command-type override; otherwise returns helper baseline
   * command type.
   */
  [[nodiscard]] EUnitCommandType ResolveHelperCommandType(const UserCommandIssueHelperRuntimeView& helper) noexcept
  {
    if (const UserCommandIssueEventRuntimeView* const event = FindLatestIssueEvent(helper, kCommandIssueEventSetType);
        event != nullptr) {
      return static_cast<EUnitCommandType>(event->commandType);
    }

    return helper.commandType;
  }

  /**
   * Address: 0x008B43F0 (FUN_008B43F0, func_GetEntitiesUnderCursor)
   *
   * What it does:
   * Rebuilds one cached command-issue cursor entity weak-set when dirty:
   * seeds from stored cursor entity-id lanes, then replays queued issue events
   * (`type 0` merge, `type 3` erase) into the cache and returns that set.
   */
  [[maybe_unused]] [[nodiscard]] UserCommandIssueWeakSetRuntimeView* GetEntitiesUnderCursor(
    UserCommandIssueCursorEntityCacheRuntimeView* const helper
  ) noexcept
  {
    if (helper == nullptr) {
      return nullptr;
    }

    if (helper->cursorEntityCacheDirty != 0u) {
      helper->cursorEntityCacheDirty = 0u;
      ClearIssueWeakSetKeepHead(helper->cursorEntitySet);

      for (EntId* entityIdCursor = helper->cursorEntityIdsBegin; entityIdCursor != helper->cursorEntityIdsEnd;
           ++entityIdCursor) {
        UserEntity* const entity = FindSessionEntityById(WLD_GetActiveSession(), static_cast<std::int32_t>(*entityIdCursor));
        AddIssueWeakSetEntity(helper->cursorEntitySet, entity);
      }

      const std::uint32_t eventEnd = helper->eventStart + helper->eventCount;
      for (std::uint32_t eventCursor = helper->eventStart; eventCursor != eventEnd; ++eventCursor) {
        std::uint32_t eventSlot = eventCursor;
        if (helper->eventWrapBase <= eventCursor) {
          eventSlot = eventCursor - helper->eventWrapBase;
        }

        UserCommandIssueEventEntitySetRuntimeView* const event =
          (helper->eventSlots != nullptr) ? helper->eventSlots[eventSlot] : nullptr;
        if (event == nullptr) {
          continue;
        }

        if (event->eventType == 3u) {
          EraseIssueWeakSetEntities(helper->cursorEntitySet, event->entitySet);
        } else if (event->eventType == 0u) {
          PruneIssueWeakSetTombstones(helper->cursorEntitySet);
          MergeIssueWeakSetEntities(helper->cursorEntitySet, event->entitySet);
        }
      }
    }

    return &helper->cursorEntitySet;
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

  /**
   * Address: 0x008B4220 (FUN_008B4220)
   *
   * What it does:
   * Resolves one effective queued-build count from helper baseline count and
   * queued increase/decrease issue events.
   */
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

  FactoryQueueDisplayItemRuntime::FactoryQueueDisplayItemRuntime() noexcept
    : blueprintId()
    , count(0)
    , commandId{}
    , auxBufferBegin(nullptr)
    , auxBufferEnd(nullptr)
    , auxBufferCapacity(nullptr)
  {
  }

  /**
   * Address: 0x00835D50 (FUN_00835D50)
   *
   * What it does:
   * Builds one queue-display item from blueprint-id and count lanes, zeroing
   * trailing auxiliary storage pointers.
   */
  FactoryQueueDisplayItemRuntime::FactoryQueueDisplayItemRuntime(
    const msvc8::string& sourceBlueprintId,
    const std::int32_t sourceCount
  )
    : blueprintId(sourceBlueprintId)
    , count(sourceCount)
    , commandId{}
    , auxBufferBegin(nullptr)
    , auxBufferEnd(nullptr)
    , auxBufferCapacity(nullptr)
  {
  }

  /**
   * Address: 0x00836040 (FUN_00836040)
   *
   * What it does:
   * Releases one queue-display item's auxiliary buffer lane and clears pointer
   * bounds before string teardown.
   */
  FactoryQueueDisplayItemRuntime::~FactoryQueueDisplayItemRuntime() noexcept
  {
    if (auxBufferBegin != nullptr) {
      operator delete[](auxBufferBegin);
    }
    auxBufferBegin = nullptr;
    auxBufferEnd = nullptr;
    auxBufferCapacity = nullptr;
  }

  /**
   * Address: 0x00836EF0 (FUN_00836EF0)
   *
   * What it does:
   * Appends one queue-display item to the global factory queue snapshot.
   */
  void AppendFactoryQueueDisplayItem(
    msvc8::vector<FactoryQueueDisplayItemRuntime>& queueItems,
    const FactoryQueueDisplayItemRuntime& item
  )
  {
    queueItems.push_back(item);
  }

  /**
   * Address: 0x00835DF0 (FUN_00835DF0)
   *
   * What it does:
   * Rebuilds the current factory queue-display snapshot from a unit's command
   * queue, coalescing adjacent blueprint ids and updating count/cmd-id lanes.
   */
  void RebuildCurrentFactoryBuildQueue(UserUnit* const userUnit)
  {
    sCurrentFactoryBuildQueue.clear();
    if (userUnit == nullptr) {
      return;
    }

    const UserCommandQueueRangeView* const commandRange = ResolveUserCommandQueueRange(userUnit->GetFactoryCommandQueue());
    if (commandRange == nullptr) {
      return;
    }

    for (UserCommandQueueEntry* entry = commandRange->begin; entry != commandRange->end; ++entry) {
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

      FactoryQueueDisplayItemRuntime item(blueprint->mBlueprintId, commandCount);
      item.commandId = helper->commandId;
      AppendFactoryQueueDisplayItem(sCurrentFactoryBuildQueue, item);
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

  [[nodiscard]] const UserCommandQueue* SelectActiveQueue(const UserUnit* const userUnit) noexcept
  {
    if (const UserCommandQueue* const factoryQueue = userUnit->GetFactoryCommandQueue();
        factoryQueue != nullptr) {
      return factoryQueue;
    }

    return userUnit->GetCommandQueue();
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
    return reinterpret_cast<const UserUnitWeaponRuntimeView*>(self->mUnitVarDat.mWeaponInfo.data());
  }

  [[nodiscard]] const UserUnitWeaponRuntimeView* GetWeaponInfoEnd(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const UserUnitWeaponRuntimeView*>(
      self->mUnitVarDat.mWeaponInfo.data() + self->mUnitVarDat.mWeaponInfo.size()
    );
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

  /**
   * Address: 0x008528B0 (FUN_008528B0)
   *
   * What it does:
   * Copies one contiguous `Vector3<float>` range `[sourceBegin, sourceEnd)`
   * into destination storage and returns one-past the copied destination lane.
   */
  [[maybe_unused]] Wm3::Vector3<float>* CopyVector3RangeNullable(
    Wm3::Vector3<float>* destination,
    const Wm3::Vector3<float>* const sourceBegin,
    const Wm3::Vector3<float>* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const Wm3::Vector3<float>* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        auto* const out = reinterpret_cast<Wm3::Vector3<float>*>(destinationAddress);
        out->x = source->x;
        out->y = source->y;
        out->z = source->z;
      }
      destinationAddress += sizeof(Wm3::Vector3<float>);
    }

    return reinterpret_cast<Wm3::Vector3<float>*>(destinationAddress);
  }

  /**
   * Address: 0x008526A0 (FUN_008526A0)
   *
   * What it does:
   * Stdcall adapter lane that forwards one `Vector3<float>` range copy as
   * `(sourceBegin, sourceEnd, destination)`.
   */
  [[maybe_unused]] Wm3::Vector3<float>* __stdcall CopyVector3RangeNullableStdcallAdapterA(
    const Wm3::Vector3<float>* const sourceBegin,
    const Wm3::Vector3<float>* const sourceEnd,
    Wm3::Vector3<float>* const destination
  ) noexcept
  {
    return CopyVector3RangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00852750 (FUN_00852750)
   *
   * What it does:
   * Cdecl adapter lane that forwards one `Vector3<float>` range copy as
   * `(sourceBegin, sourceEnd, destination)`.
   */
  [[maybe_unused]] Wm3::Vector3<float>* CopyVector3RangeNullableCdeclAdapterA(
    const Wm3::Vector3<float>* const sourceBegin,
    const Wm3::Vector3<float>* const sourceEnd,
    Wm3::Vector3<float>* const destination
  ) noexcept
  {
    return CopyVector3RangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00852800 (FUN_00852800)
   *
   * What it does:
   * Secondary cdecl compatibility lane that forwards one `Vector3<float>` range
   * copy into `CopyVector3RangeNullable(...)`.
   */
  [[maybe_unused]] Wm3::Vector3<float>* CopyVector3RangeNullableCdeclAdapterB(
    const Wm3::Vector3<float>* const sourceBegin,
    const Wm3::Vector3<float>* const sourceEnd,
    Wm3::Vector3<float>* const destination
  ) noexcept
  {
    return CopyVector3RangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00852850 (FUN_00852850)
   * Address: 0x0085FF50 (FUN_0085FF50)
   *
   * What it does:
   * Third cdecl compatibility lane that forwards one `Vector3<float>` range
   * copy into `CopyVector3RangeNullable(...)`.
   */
  [[maybe_unused]] Wm3::Vector3<float>* CopyVector3RangeNullableCdeclAdapterC(
    const Wm3::Vector3<float>* const sourceBegin,
    const Wm3::Vector3<float>* const sourceEnd,
    Wm3::Vector3<float>* const destination
  ) noexcept
  {
    return CopyVector3RangeNullable(destination, sourceBegin, sourceEnd);
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

  /**
   * Address: 0x008BEEC0 (the caching half of `UserUnit::GetClass`)
   *
   * What it does:
   * Resolves the reflected `UserUnit` type once into the static the binary
   * caches at 0x010C77AC.
   */
  [[nodiscard]] gpg::RType* CachedUserUnitType()
  {
    if (UserUnit::sType == nullptr) {
      UserUnit::sType = gpg::LookupRType(typeid(UserUnit));
    }
    return UserUnit::sType;
  }

} // namespace

namespace moho
{
  /**
   * Bridge exposing the file-local ResolveHelperBuildCount (FUN_008B4220) to the
   * recovered `cfunc_DecreaseBuildCountInQueueL` worker in Sim.cpp. The worker
   * holds command-issue helpers as the canonical `UserCommandIssueHelper`; this
   * reinterprets that same object as the UserUnit-local event-ring view the
   * count resolver was recovered against (identical binary layout).
   */
  std::int32_t QueuedBuildCommandCount(const UserCommandIssueHelper& helper) noexcept
  {
    return ResolveHelperBuildCount(reinterpret_cast<const UserCommandIssueHelperRuntimeView&>(helper));
  }

  /**
   * Bridge exposing the file-local `IsDockTargetQueueIdle` (FUN_008C0D00) to the
   * recovered `cfunc_IssueDockCommandL` worker in CCommandLuaFunctionRegistrations.cpp.
   * Returns whether one candidate platform unit is idle enough (not busy, no
   * pending command queue entries) to be considered a dock target.
   */
  bool USERUNIT_IsDockTargetIdle(const UserUnit* const unit) noexcept
  {
    return IsDockTargetQueueIdle(unit);
  }

  /**
   * Bridge exposing the file-local `GetLastQueuedUserCommandHelper` (FUN_008B7320)
   * to the recovered `cfunc_IssueDockCommandL` worker. Resolves the unit's
   * command-manager handle (`UserUnit::GetCommandQueue`, slot 6) and returns the
   * most recent queued command-issue helper as an opaque cross-TU handle. The
   * dock worker reinterprets this handle as the command-graph anchor history the
   * binary walks to seed its centroid (identical binary object).
   */
  const QueuedUserCommandRecord* GetLastQueuedUserCommandAnchor(const UserUnit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    UserCommandQueue* const manager = const_cast<UserUnit*>(unit)->GetCommandQueue();
    if (manager == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<const QueuedUserCommandRecord*>(GetLastQueuedUserCommandHelper(manager));
  }

  /**
   * Address: 0x008C1220 (FUN_008C1220, sub_8C1220)
   *
   * IDA signature:
   * void __thiscall sub_8C1220(UserUnit *unit, std::set<RUnitBlueprint const*> *out);
   *
   * What it does:
   * Walks one unit's active command queue and collects the target unit
   * blueprints referenced by every pending `Upgrade` command into `out`.
   * Each queued upgrade helper's build blueprint is wrapped in a reflection
   * reference, upcast to `RUnitBlueprint`, and inserted into the output set.
   */
  void CollectUpgradeCommandTargetBlueprints(UserUnit* const unit, msvc8::set<const RUnitBlueprint*>& out)
  {
    UserCommandQueueLinkVector* const queue = RebuildAndGetUserUnitManagerQueue(unit->mManager);
    if (queue == nullptr) {
      return;
    }

    for (UserCommandQueueEntry* entry = queue->begin; entry != queue->end; ++entry) {
      UserCommandIssueHelperRuntimeView* const helper = entry->helper;
      if (helper == nullptr) {
        continue;
      }

      if (ResolveHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_Upgrade) {
        continue;
      }

      gpg::RRef entityRef{};
      (void)gpg::RRef_REntityBlueprint(
        &entityRef,
        reinterpret_cast<REntityBlueprint*>(const_cast<RBlueprint*>(helper->buildBlueprint))
      );
      const gpg::RRef upcast = gpg::REF_UpcastPtr(entityRef, RUnitBlueprint::GetPointerType());
      if (upcast.mObj != nullptr) {
        out.insert(static_cast<const RUnitBlueprint*>(upcast.mObj));
      }
    }
  }
}

namespace moho
{
  /**
   * Address: 0x008377E0 (FUN_008377E0, func_GetUserUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `UserUnit*`, raising Lua errors for missing or
   * type-mismatched game-object payloads while allowing destroyed-object slots.
   */
  [[nodiscard]] UserUnit*
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

  /**
   * Address: 0x008B6DE0 (FUN_008B6DE0, struct_UserUnitManager::add)
   *
   * IDA signature:
   * int *__userpurge struct_UserUnitManager::add@<eax>(
   *     struct_UserUnitManager *a1@<edi>, _DWORD *eax0@<eax>, int a3, int a4);
   *
   * What it does:
   * Records one pending command-issue for `manager`: appends a
   * `UserManagerHelperEntry` {commandType=cmdId, isResetCommand=0,
   * subject=helper, sequenceOrCount=clearFlag} onto the manager's issue queue,
   * enqueues the helper's select-unit update event against the manager owner
   * unit, marks the resolved-link range dirty, and restores that range to
   * inline storage.
   */
  void UserUnitManagerAdd(
    UserCommandQueue* const manager,
    UserCommandIssueHelper* const helper,
    const CmdId cmdId,
    const bool clearFlag)
  {
    auto& view = *reinterpret_cast<UserCommandQueue*>(manager);

    UserManagerHelperEntry entry{};
    entry.commandType = static_cast<std::int32_t>(cmdId);
    entry.isResetCommand = 0;
    entry.subject = helper;
    entry.sequenceOrCount = static_cast<std::int32_t>(clearFlag);
    PushUserManagerIssue(view.issueQueue, entry);

    QueueCommandIssueSelectUnitEvent(helper, cmdId, view.ownerUnit);

    view.resolvedLinksDirty = 1u;
    (void)ResetQueueLinkVectorToInlineStorage(&view.resolvedLinks);
  }

  /**
   * Address: 0x008B6E60 (FUN_008B6E60, struct_UserUnitManager::reset)
   *
   * What it does:
   * Clears one user-unit command-issue queue and pushes a reset marker entry
   * {commandType, isResetCommand=1, subject=null, sequenceOrCount=-1}, marks the
   * resolved-link range dirty, and restores it to inline storage.
   */
  void ResetUserUnitManagerState(UserCommandQueue* const managerPtr, const std::int32_t commandType)
  {
    if (managerPtr == nullptr) {
      return;
    }

    auto& manager = *managerPtr;
    ClearUserManagerIssueQueue(manager.issueQueue);

    UserManagerHelperEntry resetHelper{};
    resetHelper.commandType = commandType;
    resetHelper.isResetCommand = 1;
    resetHelper.subject = nullptr;
    resetHelper.sequenceOrCount = -1;
    PushUserManagerIssue(manager.issueQueue, resetHelper);

    manager.resolvedLinksDirty = 1u;
    (void)ResetQueueLinkVectorToInlineStorage(&manager.resolvedLinks);
  }
} // namespace moho

namespace
{

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  /**
   * Address: 0x008C1410 (FUN_008C1410)
   *
   * What it does:
   * Emits one fixed warning when the focus-army-damaged Lua callback throws.
   */
  void WarnFocusArmyUnitDamagedCallbackError(const std::exception& exception) noexcept
  {
    const char* const message = exception.what() != nullptr ? exception.what() : "";
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnFocusArmyUnitDamaged': %s", message);
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
 * Address: 0x008C63B0 (FUN_008C63B0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<UserUnit>` and returns that singleton.
 */
namespace moho
{
  CommandIssueObserverChain::~CommandIssueObserverChain() noexcept
  {
    for (CommandIssueObserverLink* link = mHead; mHead != nullptr; link = mHead) {
      mHead = link->mNext;
      link->mOwnerLinkSlot = nullptr;
      link->mNext = nullptr;
    }
  }

  /**
   * Address: 0x008B3EC0 (FUN_008B3EC0, struct_CommandIssueHelper::struct_CommandIssueHelper)
   *
   * What it does:
   * Copies command constant data, initializes variable command payload
   * state and local queue lanes, and creates an empty cursor weak-set.
   */
  UserCommandIssueHelper::UserCommandIssueHelper(
    const SSTICommandConstantData& constantData,
    const std::uint8_t deleteWhenDue,
    const std::int32_t dueSeqNo
  )
    : mObserverLinks{}
    , mConstantData(constantData)
    , mVariableData()
    , mVariableDataTailPad{}
    , mReservedB0(0u)
    , mDeleteWhenDue(deleteWhenDue)
    , mVariableDataDirty(1u)
    , mReservedB3(0u)
    , mDueSeqNo(dueSeqNo)
    , mLocalQueue{}
    , mCursorEntitySet{}
  {
    auto* const head = static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity)));
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mKey = 0u;
    head->mEnt.mOwnerLinkSlot = nullptr;
    head->mEnt.mNextOwner = nullptr;
    head->mColor = 1u;
    head->mIsSentinel = 1u;
    head->pad_1A[0] = 0u;
    head->pad_1A[1] = 0u;

    mCursorEntitySet.mHead = head;
    mCursorEntitySet.mSize = 0u;
  }

  /**
   * Address: 0x008B4C20 (FUN_008B4C20)
   *
   * What it does:
   * Retires this helper once its due sequence is reached, otherwise drains
   * due local command-issue events and marks variable data dirty.
   */
  void UserCommandIssueHelper::AdvanceLocalEventsToBeat(const std::int32_t beat) noexcept
  {
    const auto dueDelta = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(mDueSeqNo) - static_cast<std::uint32_t>(beat)
    );
    if (mDeleteWhenDue != 0u && dueDelta <= 0) {
      this->~UserCommandIssueHelper();
      ::operator delete(this);
      return;
    }

    auto& queue = reinterpret_cast<UserCommandIssueLocalQueueRuntimeView&>(mLocalQueue);
    while (queue.count != 0u) {
      std::uint32_t slot = queue.readIndex;
      if (queue.capacity <= slot) {
        slot -= queue.capacity;
      }

      UserCommandIssueLocalEventRuntimeView* const event = queue.slots[slot];
      const auto eventDelta = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(event->commandId) - static_cast<std::uint32_t>(beat)
      );
      if (eventDelta > 0) {
        break;
      }

      DestroyCommandIssueLocalEvent(*event);
      ++queue.readIndex;
      if (queue.capacity <= queue.readIndex) {
        queue.readIndex = 0u;
      }
      if (queue.count-- == 1u) {
        queue.readIndex = 0u;
      }
      mVariableDataDirty = 1u;
    }
  }

  /**
   * Address: 0x008B3F80 (FUN_008B3F80, struct_CommandIssueHelper::~struct_CommandIssueHelper)
   * Mangled: ??1struct_CommandIssueHelper@@QAE@@Z
   *
   * What it does:
   * Removes this helper's command-id entry from the active session command
   * map, releases cursor/entity weak-set storage and local queued issue
   * events, and then relies on typed command payload members for teardown.
   */
  UserCommandIssueHelper::~UserCommandIssueHelper() noexcept
  {
    RemoveCommandIssueHelperFromActiveSessionMap(*this);
    DestroyCommandIssueWeakSet(mCursorEntitySet);
    DestroyCommandIssueLocalQueue(mLocalQueue);
  }

  UserCommandIssueHelper* FindCommandIssueHelperInSession(CWldSession* const session, const CmdId commandId) noexcept
  {
    return reinterpret_cast<UserCommandIssueHelper*>(FindSessionCommandIssueHelperById(session, commandId));
  }

  EUnitCommandType ResolveCommandIssueHelperCommandType(const UserCommandIssueHelper& helper) noexcept
  {
    return ResolveHelperCommandType(reinterpret_cast<const UserCommandIssueHelperRuntimeView&>(helper));
  }

  SSelectionSetUserEntity* ResolveCommandIssueCursorEntities(UserCommandIssueHelper& helper) noexcept
  {
    UserCommandIssueWeakSetRuntimeView* const cursorSet =
      GetEntitiesUnderCursor(reinterpret_cast<UserCommandIssueCursorEntityCacheRuntimeView*>(&helper));
    return reinterpret_cast<SSelectionSetUserEntity*>(cursorSet);
  }

  /**
   * Address: 0x008B73E0 (FUN_008B73E0)
   *
   * What it does:
   * Rebuilds/resolves one user-unit command queue and returns whether it
   * currently contains the supplied command-issue helper.
   */
  bool UserUnitManagerContainsCommandIssueHelper(
    UserCommandQueue* const manager,
    const UserCommandIssueHelper* const helper
  ) noexcept
  {
    if (manager == nullptr || helper == nullptr) {
      return false;
    }

    const UserCommandQueueLinkVector* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr) {
      return false;
    }

    const auto* const helperView = reinterpret_cast<const UserCommandIssueHelperRuntimeView*>(helper);
    for (const UserCommandQueueEntry* entry = queueVector->begin; entry != queueVector->end; ++entry) {
      if (entry->helper == helperView) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x008C60F0 (FUN_008C60F0)
   *
   * What it does:
   * Returns cached `UserUnit` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_GetUserUnitFactory(
    LuaPlus::LuaObject* const object,
    LuaPlus::LuaState* const state
  )
  {
    if (object == nullptr) {
      return nullptr;
    }

    *object = CScrLuaMetatableFactory<UserUnit>::Instance().Get(state);
    return object;
  }

  CScrLuaMetatableFactory<UserUnit>* startup_CScrLuaMetatableFactory_UserUnit_Index()
  {
    auto& instance = CScrLuaMetatableFactory<UserUnit>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }
} // namespace moho

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

namespace
{
  /// The metatable the `CScriptObject` sub-object is built against, fetched
  /// through the recovered factory accessor at 0x008C60F0.
  [[nodiscard]] LuaPlus::LuaObject MakeUserUnitScriptMetatable(moho::CWldSession* const session)
  {
    LuaPlus::LuaObject metatable;
    (void)moho::func_GetUserUnitFactory(&metatable, session != nullptr ? session->mState : nullptr);
    return metatable;
  }

  /**
   * Address: 0x008BF612 (inside FUN_008BF420)
   *
   * What it does:
   * Stands up one per-unit command queue: owner back-pointer, both link runs
   * seeded onto their own inline storage, the pending-issue ring cleared and
   * the resolved-run dirty flag down. The constructor open-codes this twice,
   * once per queue.
   */
  [[nodiscard]] moho::UserCommandQueue* CreateUserCommandQueue(moho::UserUnit* const owner)
  {
    auto* const queue = static_cast<moho::UserCommandQueue*>(::operator new(sizeof(moho::UserCommandQueue)));

    queue->ownerUnit = owner;

    auto* const primaryInline = reinterpret_cast<moho::UserCommandQueueEntry*>(queue->primaryInlineStorage);
    queue->primaryLinks.begin = primaryInline;
    queue->primaryLinks.end = primaryInline;
    queue->primaryLinks.inlineBase = reinterpret_cast<moho::UserCommandQueueEntry**>(primaryInline);
    queue->primaryLinks.capacityEnd = primaryInline + moho::kUserCommandQueueInlineEntries;

    queue->issueQueue.blocks = nullptr;
    queue->issueQueue.blockCount = 0u;
    queue->issueQueue.startOffset = 0u;
    queue->issueQueue.size = 0u;

    auto* const resolvedInline = reinterpret_cast<moho::UserCommandQueueEntry*>(queue->resolvedInlineStorage);
    queue->resolvedLinks.begin = resolvedInline;
    queue->resolvedLinks.end = resolvedInline;
    queue->resolvedLinks.capacityEnd = resolvedInline + moho::kUserCommandQueueInlineEntries;
    queue->resolvedLinks.inlineBase = reinterpret_cast<moho::UserCommandQueueEntry**>(resolvedInline);

    queue->resolvedLinksDirty = 0u;
    return queue;
  }
} // namespace

/**
 * Address: 0x008BF420 (FUN_008BF420, ??0UserUnit@Moho@@QAE@@Z)
 *
 * IDA signature:
 * Moho::UserUnit *__thiscall Moho::UserUnit::UserUnit(
 *   Moho::CWldSession *session, Moho::UserUnit *this, Moho::SCreateUnitParams *params);
 *
 * What it does:
 * Builds one client-side unit from a sim create packet: runs the UserEntity,
 * IUnit and CScriptObject sub-objects, copies the constant data, allocates the
 * primary command queue (and a second one for factories), then files the unit
 * either into its army's quick-select avatar run or into the engineer
 * classification.
 */
UserUnit::UserUnit(CWldSession* const session, const SCreateUnitParams& params)
  : UserEntity(*session, params)
  , IUnit()
  , CScriptObject(
      MakeUserUnitScriptMetatable(session),
      LuaPlus::LuaObject(),
      LuaPlus::LuaObject(),
      LuaPlus::LuaObject()
    )
  , mUnitConstDat(params.mConstDat)
  , mReserved0194(0u)
  , mUnitVarDat()
  , mCreator()
  , mManager(nullptr)
  , mFactoryManager(nullptr)
  , mSelectionSets()
  , mQueueEmptyCached(false)
  , mIsEngineer(false)
  , mIsFactory(false)
{
  mManager = CreateUserCommandQueue(this);

  // 0x008BF66F: factories carry a second queue for what they are building.
  if (IsInCategory(msvc8::string("FACTORY", 7u))) {
    mFactoryManager = CreateUserCommandQueue(this);

    // 0x008BF745: only a factory that is also a structure counts as one for
    // the idle-factory registry; mobile factories are handled as engineers.
    if (IsInCategory(msvc8::string("STRUCTURE", 9u))) {
      mIsFactory = true;
    }
  }

  // 0x008BF7B7: a unit the blueprint gives a quick-select priority goes into
  // the army's avatar run; everything else is a candidate for the idle
  // engineer registry instead. The two are exclusive in the binary.
  const auto* const unitBlueprint = static_cast<const RUnitBlueprint*>(mParams.mBlueprint);
  if (mArmy != nullptr && unitBlueprint != nullptr && unitBlueprint->General.QuickSelectPriority > 0) {
    AddArmyAvatar(mArmy, this);
    return;
  }

  mIsEngineer = IsInCategory(msvc8::string("ENGINEER", 8u))
    && !IsInCategory(msvc8::string("COMMAND", 7u))
    && !IsInCategory(msvc8::string("SCOUT", 5u))
    && !IsInCategory(msvc8::string("UNTARGETABLE", 12u));
}

/**
 * Address: 0x008BF9B0 (FUN_008BF9B0, ??1UserUnit@Moho@@UAE@XZ)
 * Deleting-destructor thunk: 0x008BF990 (FUN_008BF990, ??_GUserUnit@Moho@@UAEPAXI@Z)
 *
 * What it does:
 * Drops the unit from its army's registries, hands its selection to the
 * successor named by `mUnitVarDat.mSelectionInheritorId`, and tears down the
 * per-unit command queues. The three-instruction thunk at 0x008BF990 that
 * forwards here and conditionally frees the storage is what C++ emits for a
 * virtual destructor, so it has no separate body.
 */
UserUnit::~UserUnit()
{
  UserEntity* const entityView = this;
  UserArmy* const army = GetLuaRuntimeView(this).army;
  const IUnit* const iunitBridge = GetIUnitBridge(this);

  if (army != nullptr && iunitBridge != nullptr) {
    const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
    if (blueprint != nullptr && blueprint->General.QuickSelectPriority > 0) {
      // Binary lane at 0x008BFA0B: `QuickSelectPriority > 0` units are
      // tracked in the UserArmy high-priority selection registry (not in
      // the idle weak-sets), and must be unregistered from that run via
      // FUN_008B2470.
      UnregisterUserArmyPrioritySelectionSlot(this, army);
    } else if (mQueueEmptyCached) {
      if (mIsFactory) {
        (void)EraseWeakEntitySet(army->mFactories, entityView);
      }
      if (mIsEngineer) {
        (void)EraseWeakEntitySet(army->mEngineers, entityView);
      }
    }
  }

  // 0x008BFA49..0x008BFB1A: a unit that names a successor hands its selection
  // over on the way out. The successor only joins the selection if this unit
  // was itself selected, so an off-screen death never steals the player's
  // current selection.
  if (mUnitVarDat.mSelectionInheritorId != ToRaw(EEntityIdSentinel::Invalid)) {
    ScopedCopiedSelectionSet selectionSnapshot{};
    (void)CopySessionSelectionSet(&selectionSnapshot.get(), &entityView->mSession->mSelection);

    SSelectionSetUserEntity::FindResult selfInSelection{};
    (void)SSelectionSetUserEntity::Find(&selfInSelection, &selectionSnapshot.get(), entityView);

    if (selfInSelection.mRes != selectionSnapshot.get().mHead) {
      UserEntity* const inheritor =
        entityView->mSession->LookupEntityId(static_cast<EntId>(mUnitVarDat.mSelectionInheritorId));
      if (inheritor != nullptr) {
        SSelectionSetUserEntity::AddResult inserted{};
        (void)SSelectionSetUserEntity::Add(&inserted, &selectionSnapshot.get(), inheritor);
        entityView->mSession->SetSelection(selectionSnapshot.get());

        if (UserUnit* const inheritorUnit = inheritor->IsUserUnit(); inheritorUnit != nullptr) {
          UserUnit::AddToSelectionSet(inheritorUnit, this);
        }
      }
    }
  }

  mSelectionSets.clear();

  if (mFactoryManager != nullptr) {
    DestroyUserUnitManagerState(mFactoryManager);
    ::operator delete(mFactoryManager);
    mFactoryManager = nullptr;
  }
  if (mManager != nullptr) {
    DestroyUserUnitManagerState(mManager);
    ::operator delete(mManager);
    mManager = nullptr;
  }

  if (VisionDB::Handle* const handle = GetUserUnitVisionHandle(this); handle != nullptr) {
    delete handle;
    GetUserUnitVisionHandle(this) = nullptr;
  }
}

/**
 * Address: 0x00852950 (FUN_00852950, Moho::UserUnit::GetSkirt)
 *
 * What it does:
 * Samples this unit's current world XZ position and writes the resolved
 * blueprint skirt rectangle into `outSkirtRect`.
 */
gpg::Rect2f* UserUnit::GetSkirt(gpg::Rect2f* const outSkirtRect) const
{
  const UserEntity* const entityView = reinterpret_cast<const UserEntity*>(this);
  const SCoordsVec2 currentPosition{
    entityView->mVariableData.mCurTransform.pos_.x,
    entityView->mVariableData.mCurTransform.pos_.z
  };
  const RUnitBlueprint* const blueprint = GetIUnitBridge(this)->GetBlueprint();
  *outSkirtRect = blueprint->GetSkirtRect(currentPosition);
  return outSkirtRect;
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
 * Address: 0x008C0750 (FUN_008C0750, Moho::UserUnit::UpdateUnitData)
 *
 * IDA signature:
 * void __thiscall Moho::UserUnit::UpdateUnitData(
 *   Moho::UserUnit *this, Moho::SSTIUnitVariableData *payload, int *mask);
 *
 * What it does:
 * Applies one replicated variable-data payload from a sync beat: assigns the
 * payload wholesale, records the intel mask, re-seats both shared poses,
 * re-resolves the creator weak reference (inheriting the creator's selection
 * sets when a factory built this unit), and resyncs both command queues when
 * the payload says the sim refreshed them. A unit that has just gone busy
 * drops out of the current selection.
 */
void UserUnit::UpdateUnitData(const SSTIUnitVariableData& payload, const std::uint32_t intelStateFlags)
{
  const bool wasBusy = mUnitVarDat.mIsBusy;
  mUnitVarDat.AssignFrom(payload);
  mIntelStateFlags = intelStateFlags;

  if (!wasBusy && mUnitVarDat.mIsBusy) {
    DeselectFromSessionSelection(this);
  }

  mPosePrimary = mUnitVarDat.mPriorSharedPose;
  mPoseSecondary = mUnitVarDat.mSharedPose;

  const EntId replicatedCreator = mUnitVarDat.mCreator;
  if ((replicatedCreator & 0xF0000000u) == 0xF0000000u) {
    // 0x008C0823: the sentinel id means "no creator"; drop whatever we held.
    mCreator.UnlinkFromOwnerChain();
  } else {
    const UserEntity* const heldCreator = mCreator.GetObjectPtr();
    if (heldCreator == nullptr || heldCreator->mParams.mEntityId != replicatedCreator) {
      mCreator.ResetFromObject(WLD_GetActiveSession()->LookupEntityId(static_cast<EntId>(replicatedCreator)));

      UserEntity* const creator = mCreator.GetObjectPtr();
      if (creator != nullptr && creator->IsInCategory(msvc8::string("FACTORY", 7u))) {
        // 0x008C0949: a unit rolling off a factory inherits that factory's
        // selection-set membership. The binary decodes the weak lane straight
        // to a `UserUnit` here; the category test is what makes that safe.
        UserUnit::AddToSelectionSet(this, static_cast<UserUnit*>(creator));
      }
    }
  }

  if (mUnitVarDat.mDidRefresh) {
    if (mManager != nullptr) {
      ResyncUserCommandQueueLinks(mManager, mUnitVarDat.mCommands.start_, mUnitVarDat.mCommands.end_);
    }
    if (mFactoryManager != nullptr) {
      ResyncUserCommandQueueLinks(mFactoryManager, mUnitVarDat.mBuildQueue.start_, mUnitVarDat.mBuildQueue.end_);
    }
  }
}

gpg::RType* UserUnit::sType = nullptr;

/**
 * Address: 0x008BEF00 (FUN_008BEF00, Moho::IUnit_UserUnit::GetEntityId)
 * IUnit slot 4.
 */
EntId UserUnit::GetEntityId() const
{
  return static_cast<EntId>(mParams.mEntityId);
}

/**
 * Address: 0x008BEF10 (FUN_008BEF10, Moho::IUnit_UserUnit::GetPosition)
 * IUnit slot 5.
 */
const Wm3::Vec3f& UserUnit::GetPosition() const
{
  return mVariableData.mCurTransform.pos_;
}

/**
 * Address: 0x008BEF20 (FUN_008BEF20, Moho::IUnit_UserUnit::GetTransform)
 * IUnit slot 6.
 */
const VTransform& UserUnit::GetTransform() const
{
  return mVariableData.mCurTransform;
}

/**
 * Address: 0x008BEF30 (FUN_008BEF30, Moho::IUnit_UserUnit::GetBlueprint)
 * IUnit slot 7.
 *
 * What it does:
 * Hands back the entity blueprint the unit was created with, narrowed to the
 * unit blueprint it is known to be - `SCreateUnitParams` only ever carries one.
 */
const RUnitBlueprint* UserUnit::GetBlueprint() const
{
  return static_cast<const RUnitBlueprint*>(mParams.mBlueprint);
}

/**
 * Address: 0x008BEF60 (FUN_008BEF60, Moho::IUnit_UserUnit::GetLuaObject)
 * IUnit slot 8.
 */
LuaPlus::LuaObject UserUnit::GetLuaObject()
{
  return mLuaObj;
}

/**
 * Address: 0x008BEF80 (FUN_008BEF80, Moho::IUnit_UserUnit::CalcTransportLoadFactor)
 * IUnit slot 9.
 */
float UserUnit::CalcTransportLoadFactor() const
{
  return 1.0f;
}

/**
 * Address: 0x008BEF90 (FUN_008BEF90, Moho::IUnit_UserUnit::IsDead)
 * IUnit slot 10.
 */
bool UserUnit::IsDead() const
{
  return mVariableData.mIsDead != 0u;
}

/**
 * Address: 0x008BEFA0 (FUN_008BEFA0, Moho::IUnit_UserUnit::DestroyQueued)
 * IUnit slot 11.
 */
bool UserUnit::DestroyQueued() const
{
  return false;
}

/**
 * Address: 0x008C04E0 (FUN_008C04E0, Moho::IUnit_UserUnit::IsMobile)
 * IUnit slot 12.
 *
 * What it does:
 * One unsigned range test over the blueprint's motion type: everything from
 * `Land` through `AmphibiousFloating` moves, `None` and `Special` do not.
 */
bool UserUnit::IsMobile() const
{
  const auto motionType = static_cast<std::uint32_t>(GetBlueprint()->Physics.MotionType);
  return (motionType - 1u) <= (static_cast<std::uint32_t>(RULEUMT_AmphibiousFloating) - 1u);
}

/**
 * Address: 0x008BEFC0 (FUN_008BEFC0, Moho::IUnit_UserUnit::IsNavigatorIdle)
 * IUnit slot 14.
 */
bool UserUnit::IsNavigatorIdle() const
{
  return false;
}

/**
 * Address: 0x008BF020 (FUN_008BF020, Moho::IUnit_UserUnit::IsUnitState)
 * IUnit slot 15.
 *
 * What it does:
 * Tests one bit of the replicated state mask. The binary shifts through
 * `__allshl`, which yields zero once the count reaches 64; the explicit bound
 * keeps that same answer without the shift being undefined.
 */
bool UserUnit::IsUnitState(const EUnitState state) const
{
  const auto stateIndex = static_cast<std::uint32_t>(state);
  if (stateIndex >= 64u) {
    return false;
  }
  return (mUnitVarDat.mUnitStates & (std::uint64_t{1} << stateIndex)) != 0u;
}

/**
 * Address: 0x008BEF50 (FUN_008BEF50, Moho::IUnit_UserUnit::GetAttributes)
 * IUnit slot 16.
 */
UnitAttributes& UserUnit::GetAttributes()
{
  return mUnitVarDat.mAttributes;
}

/**
 * Address: 0x008BEF40 (FUN_008BEF40, Moho::IUnit_UserUnit::GetAttributes)
 * IUnit slot 17.
 */
const UnitAttributes& UserUnit::GetAttributes() const
{
  return mUnitVarDat.mAttributes;
}

/**
 * Address: 0x008BF0C0 (FUN_008BF0C0, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 18.
 *
 * What it does:
 * The default value only picks the lane: a string default routes to the
 * string-typed stat under this unit's stats root.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath, const std::string& defaultValue)
{
  (void)defaultValue;
  return mUnitConstDat.mStatsRoot->GetStringItem(statPath);
}

/**
 * Address: 0x008BF0B0 (FUN_008BF0B0, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 19.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath, const float& defaultValue)
{
  (void)defaultValue;
  return mUnitConstDat.mStatsRoot->GetFloatItem(statPath);
}

/**
 * Address: 0x008BF0A0 (FUN_008BF0A0, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 20.
 *
 * What it does:
 * The int-defaulted lane is the only one that creates the stat when it is
 * missing - the binary rewrites the second argument to `true` and tail-calls
 * the same lookup slot 21 uses.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath, const int& defaultValue)
{
  (void)defaultValue;
  return mUnitConstDat.mStatsRoot->GetItem(statPath, true);
}

/**
 * Address: 0x008BF080 (FUN_008BF080, Moho::IUnit_UserUnit::GetStat)
 * IUnit slot 21.
 */
StatItem* UserUnit::GetStat(const gpg::StrArg statPath)
{
  return mUnitConstDat.mStatsRoot->GetItem(statPath, false);
}

/**
 * Address: 0x008BEEC0 (FUN_008BEEC0, Moho::CScriptObject_UserUnit::GetClass)
 * CScriptObject slot 0.
 */
gpg::RType* UserUnit::GetClass() const
{
  return CachedUserUnitType();
}

/**
 * Address: 0x008BEEE0 (FUN_008BEEE0, Moho::CScriptObject_UserUnit::GetDerivedObjectRef)
 * CScriptObject slot 1.
 *
 * What it does:
 * Pairs the whole-object pointer with the reflected type. There is no dynamic
 * walk here - `UserUnit` is the most-derived type by construction.
 */
gpg::RRef UserUnit::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
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
      const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
      if (blueprint != nullptr && blueprint->General.QuickSelectPriority > 0) {
        // Matches FUN_008C0A30 @ 0x008C0AA8: priority units leave the
        // high-priority selection registry instead of the idle weak-sets.
        UnregisterUserArmyPrioritySelectionSlot(this, army);
      } else if (mQueueEmptyCached) {
          if (mIsFactory) {
          (void)EraseWeakEntitySet(army->mFactories, entityView);
        }
        if (mIsEngineer) {
          (void)EraseWeakEntitySet(army->mEngineers, entityView);
        }
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
      if (mIsEngineer) {
        if (isQueueEmpty) {
          (void)InsertIdleEngineerWeakSetEntry(this, army);
        } else {
          (void)EraseWeakEntitySet(army->mEngineers, entityView);
        }
      }
      if (mIsFactory) {
        if (isQueueEmpty) {
          (void)InsertIdleFactoryWeakSetEntry(this, army);
        } else {
          (void)EraseWeakEntitySet(army->mFactories, entityView);
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
  if (visionRange != 0u && visionHandle == nullptr && !mUnitConstDat.mFake) {
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

  if (mUnitConstDat.mFake) {
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
  * Alias of FUN_008B8EB0 (non-canonical helper lane).
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
const UserUnit* UserUnit::IsUserUnit() const
{
  return this;
}

/**
 * Address: 0x008BF110 (FUN_008BF110)
 *
 * What it does:
 * Returns this object as the mutable UserUnit identity view.
 */
UserUnit* UserUnit::IsUserUnit()
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
float UserUnit::GetUniformScale() const
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
const UserCommandQueue* UserUnit::GetCommandQueue() const
{
  return mManager;
}

/**
 * Address: 0x008BF130 (FUN_008BF130)
 *
 * What it does:
 * Returns the current user command-queue handle (const view slot).
 */
UserCommandQueue* UserUnit::GetCommandQueue()
{
  return mManager;
}

/**
 * Address: 0x008BF160 (FUN_008BF160)
 *
 * What it does:
 * Returns the current factory command-queue handle (mutable view slot).
 */
const UserCommandQueue* UserUnit::GetFactoryCommandQueue() const
{
  return mFactoryManager;
}

/**
 * Address: 0x008BF140 (FUN_008BF140)
 *
 * What it does:
 * Returns the current factory command-queue handle (const view slot).
 */
UserCommandQueue* UserUnit::GetFactoryCommandQueue()
{
  return mFactoryManager;
}

/**
  * Alias of FUN_008B8530 (non-canonical helper lane).
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
 * Address: 0x008C0500 (FUN_008C0500, moho::UserUnit::IsSelectable)
 *
 * What it does:
 * Evaluates whether this user unit is currently selectable by UI selectors.
 */
bool UserUnit::IsSelectable() const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  if (iunitBridge == nullptr || !mUnitVarDat.mIsBusy || !iunitBridge->IsMobile()) {
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

  if (IUnitBridgeIsUnitState(iunitBridge, UNITSTATE_UnSelectable)) {
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
  try {
    callback.Call_Object(unitObject);
  } catch (const std::exception& exception) {
    WarnFocusArmyUnitDamagedCallbackError(exception);
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnFocusArmyUnitDamaged': unknown exception");
  }
}

/**
 * Address: 0x0083EEC0 (FUN_0083EEC0, moho::UserUnit::DoOnDetectAdjacencyBonusFor)
 *
 * What it does:
 * Invokes `/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus(unitObject, blueprintObject)`
 * and returns the callback boolean result.
 */
bool UserUnit::DoOnDetectAdjacencyBonusFor(const RUnitBlueprint* const blueprint)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || blueprint == nullptr) {
    return false;
  }

  LuaPlus::LuaObject gameMainModule = SCR_Import(session->mState, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaObject onDetectAdjacencyBonus = gameMainModule["OnDetectAdjacencyBonus"];
  LuaPlus::LuaFunction callback(onDetectAdjacencyBonus);

  const LuaPlus::LuaObject blueprintObject = blueprint->GetLuaBlueprint(session->mState);
  IUnit* const iunitBridge = GetIUnitBridge(this);
  const LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();

  try {
    const LuaPlus::LuaObject callbackResult = callback.Call_Obj2_Obj(unitObject, blueprintObject);
    return callbackResult.GetBoolean();
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus': %s",
      exception.what() != nullptr ? exception.what() : "<unknown>"
    );
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus': %s", "<unknown>");
  }

  return false;
}

/**
 * Address: 0x008C00E0 (FUN_008C00E0, moho::UserUnit::CreateMeshInstance)
 *
 * What it does:
 * Creates the unit mesh instance, applies team-color lookup parameter, and
 * wires animation poses from shared unit pose lanes when skeletons match.
 */
void UserUnit::CreateMeshInstance(const bool forUnitPose)
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

  const float uniformScale = GetUniformScale();
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
  const auto* const weaponRuntime = reinterpret_cast<const UserUnitWeaponRuntimeView*>(mUnitVarDat.mWeaponInfo.data());

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
  if ((toggleCaps & kToggleCapIntel) != 0u && (mUnitVarDat.mScriptbits & kToggleCapIntel) != 0u) {
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
  if (((toggleCaps & kToggleCapJamming) != 0u && (mUnitVarDat.mScriptbits & kToggleCapJamming) != 0u) ||
      ((toggleCaps & kToggleCapStealth) != 0u && (mUnitVarDat.mScriptbits & kToggleCapStealth) != 0u)) {
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
  return mUnitVarDat.mAutoMode;
}

/**
 * Address: 0x008BEFE0 (FUN_008BEFE0)
 *
 * What it does:
 * Returns UI mirror of auto-surface mode state.
 */
bool UserUnit::IsAutoSurfaceMode() const
{
  return mUnitVarDat.mAutoSurfaceMode;
}

/**
 * Address: 0x008BEFF0 (FUN_008BEFF0)
 *
 * What it does:
 * Returns UI mirror of repeat-queue state.
 */
bool UserUnit::Func1() const
{
  return mUnitVarDat.mRepeatQueue;
}

/**
 * Address: 0x008BF000 (FUN_008BF000)
 *
 * What it does:
 * Returns whether overcharge is currently paused in UI state.
 */
bool UserUnit::IsOverchargePaused() const
{
  return mUnitVarDat.mOverchargePaused;
}

/**
 * Address: 0x008BF010 (FUN_008BF010)
 *
 * What it does:
 * Returns the in-object custom-name storage anchor at +0x1DC.
 */
char* UserUnit::GetCustomName()
{
  return reinterpret_cast<char*>(&mUnitVarDat.mCustomName);
}

/**
 * Address: 0x008BF060 (FUN_008BF060)
 *
 * What it does:
 * Returns UI fuel ratio.
 */
float UserUnit::GetFuel() const
{
  return mUnitVarDat.mFuelRatio;
}

/**
 * Address: 0x008BF070 (FUN_008BF070)
 *
 * What it does:
 * Returns UI shield ratio.
 */
float UserUnit::GetShield() const
{
  return mUnitVarDat.mShieldRatio;
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
 * Address: 0x008BFF30 (FUN_008BFF30, Moho::UserUnit::AddToSelectionSet)
 *
 * IDA signature:
 * void __stdcall Moho::UserUnit::AddToSelectionSet(Moho::UserUnit *a1, Moho::UserUnit *a2);
 *
 * What it does:
 * Hands every selection-set name owned by `source` to `target`, and tells the UI
 * about each one through `/lua/ui/game/selection.lua:AddUnitToSelectionSet`.
 * Called when a unit leaves play and its successor takes over its named sets
 * (0x008BFAEE), and when a freshly replicated unit inherits them from the
 * factory that built it (0x008C0956).
 */
void UserUnit::AddToSelectionSet(UserUnit* const target, UserUnit* const source)
{
  if (source == nullptr) {
    return;
  }

  // 0x008BFF41: the source's names are snapshotted before anything is added to
  // the target, so the walk is stable even when `target == source`.
  const msvc8::set<msvc8::string> inheritedNames = source->mSelectionSets;

  LuaPlus::LuaObject selectionModule =
    SCR_Import(WLD_GetActiveSession()->mState, "/lua/ui/game/selection.lua");
  LuaPlus::LuaObject addUnitToSelectionSet = selectionModule["AddUnitToSelectionSet"];
  LuaPlus::LuaFunction callback(addUnitToSelectionSet);

  // 0x008BFF9E: the bridge is resolved once, but `GetLuaObject` is dispatched
  // per name because the call below consumes the object.
  IUnit* const targetBridge = GetIUnitBridge(target);
  for (const msvc8::string& selectionSetName : inheritedNames) {
    target->AddSelectionSet(selectionSetName.c_str());
    const LuaPlus::LuaObject targetObject = targetBridge->GetLuaObject();
    callback.Call_StringObject(std::string(selectionSetName.c_str(), selectionSetName.size()), targetObject);
  }
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
 * Address: 0x008C5B90 (FUN_008C5B90, msvc8::set<msvc8::string>::find)
 *
 * What it does:
 * Per-T canonical-template-helper binding for the engine-instantiated
 * `msvc8::set<msvc8::string>::find(const key&)` _Tree::_Lbound walk +
 * key-equal check body. Returns the iterator to the matching node or
 * `end()` if the key is not present.
 *
 * Used by `UserUnit::HasSelectionSet` (FUN_008BF220, the only recovered
 * caller of FUN_008C5B90 in the binary) to preserve the MSVC8 per-T
 * `_Tree::find` template emission symbol shape even when the modern
 * compiler would inline the natural `mSelectionSets.find(...)` call.
 */
msvc8::set<msvc8::string>::iterator FindStringSetEntry(
  const msvc8::set<msvc8::string>& storage,
  const msvc8::string& key)
{
  return storage.find(key);
}

/**
 * Address: 0x008BF220 (FUN_008BF220)
 *
 * What it does:
 * Returns whether this unit currently stores one named selection-set key.
 * Routes the per-T `msvc8::set<msvc8::string>::find` through the named
 * helper (FUN_008C5B90) to preserve the MSVC8 template emission symbol.
 */
bool UserUnit::HasSelectionSet(const char* const selectionSetName) const
{
  msvc8::string selectionSet{};
  selectionSet.assign_owned(selectionSetName != nullptr ? selectionSetName : "");
  return FindStringSetEntry(mSelectionSets, selectionSet) != mSelectionSets.end();
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

      if (mUnitVarDat.mAutoSurfaceMode) {
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
 * Address: 0x008C1880 (FUN_008C1880, ?USERUNIT_CanBeBuiltAt@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@_NPAUSBuildInfo@1@PBVUserCommand@1@@Z)
 *
 * What it does:
 * Runs world-space placement validation, then rejects placements that overlap
 * visible static/dead unit skirts or queued mobile-build command skirts.
 */
bool moho::USERUNIT_CanBeBuiltAt(
  CWldSession& session,
  const RUnitBlueprint* const buildBlueprint,
  const SCoordsVec2& buildPosition,
  const bool allowCommandOverlap,
  SOccupationResult* const buildInfo,
  const UserCommand* const ignoredCommand
)
{
  (void)allowCommandOverlap;

  auto* const map = reinterpret_cast<STIMap*>(session.mWldMap->mTerrainRes->mPlayableRectSource);
  auto* const resources = reinterpret_cast<ISimResources*>(session.mSimResources.px);
  if (!OCCUPY_Check(*map, *buildBlueprint, buildPosition, *resources, *buildInfo)) {
    return false;
  }

  const SCoordsVec2 candidatePosition{buildInfo->pos.x, buildInfo->pos.z};
  const gpg::Rect2f candidateSkirt = buildBlueprint->GetSkirtRect(candidatePosition);
  const gpg::Rect2i& playableRect = map->mPlayableRect;
  if (static_cast<float>(playableRect.x0 + 2) >= candidateSkirt.x0
      || static_cast<float>(playableRect.z0 + 2) >= candidateSkirt.z0
      || candidateSkirt.x1 >= static_cast<float>(playableRect.x1 - 2)
      || candidateSkirt.z1 >= static_cast<float>(playableRect.z1 - 2)) {
    return false;
  }

  Wm3::AxisAlignedBox3f overlapQuery{};
  overlapQuery.Min.x = candidateSkirt.x0 - 8.0f;
  overlapQuery.Min.y = -std::numeric_limits<float>::max();
  overlapQuery.Min.z = candidateSkirt.z0 - 8.0f;
  overlapQuery.Max.x = candidateSkirt.x1 + 8.0f;
  overlapQuery.Max.y = std::numeric_limits<float>::max();
  overlapQuery.Max.z = candidateSkirt.z1 + 8.0f;

  constexpr std::uint32_t kIntelVisibleMask = 0x08u;
  gpg::fastvector_n<UserEntity*, 100> nearbyUnits{};
  auto* const spatialStorage = reinterpret_cast<SpatialDB_MeshInstance*>(session.GetEntitySpatialDbStorage());
  spatialStorage->CollectInBox(nearbyUnits, overlapQuery);

  for (UserEntity* const nearbyEntity : nearbyUnits) {
    UserUnit* const nearbyUnit = nearbyEntity != nullptr ? nearbyEntity->IsUserUnit() : nullptr;
    if (nearbyUnit == nullptr || (nearbyUnit->mIntelStateFlags & kIntelVisibleMask) == 0u) {
      continue;
    }

    const IUnit* const iunitBridge = GetIUnitBridge(nearbyUnit);
    const RUnitBlueprint* const nearbyBlueprint = iunitBridge->GetBlueprint();
    if (!nearbyBlueprint->IsMobile() || iunitBridge->IsDead()) {
      gpg::Rect2f nearbySkirt{};
      if (nearbyUnit->GetSkirt(&nearbySkirt)->Overlaps(candidateSkirt)) {
        return false;
      }
    }
  }

  auto* const commandManager = session.mCommandManager;
  if (commandManager == nullptr || CommandIssueMapOf(*commandManager).head == nullptr) {
    return true;
  }

  SessionCommandIssueMapView& issueMap = CommandIssueMapOf(*commandManager);
  SessionCommandIssueMapNodeView* const mapHead = issueMap.head;
  for (SessionCommandIssueMapNodeView* node = mapHead->left;
       node != nullptr && node != mapHead;
       node = NextSessionCommandIssueNode(node, mapHead)) {
    UserCommandIssueHelperRuntimeView* const helper = node->value;
    if (helper == nullptr || ResolveHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile) {
      continue;
    }

    if (ignoredCommand != nullptr && reinterpret_cast<const UserCommand*>(helper) == ignoredCommand) {
      continue;
    }

    gpg::RRef buildBlueprintRef{};
    (void)gpg::RRef_REntityBlueprint(
      &buildBlueprintRef,
      reinterpret_cast<REntityBlueprint*>(const_cast<RBlueprint*>(helper->buildBlueprint))
    );
    const gpg::RRef unitBlueprintRef = gpg::REF_UpcastPtr(buildBlueprintRef, RUnitBlueprint::GetPointerType());
    const auto* const queuedBuildBlueprint = static_cast<const RUnitBlueprint*>(unitBlueprintRef.mObj);
    if (queuedBuildBlueprint == nullptr) {
      continue;
    }

    const Wm3::Vector3<float> queuedTarget = ResolveHelperTargetPosition(*helper, &session);
    const SCoordsVec2 queuedPosition{queuedTarget.x, queuedTarget.z};
    const gpg::Rect2f queuedSkirt = queuedBuildBlueprint->GetSkirtRect(queuedPosition);
    if (queuedSkirt.Overlaps(candidateSkirt)) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x008C1BC0 (FUN_008C1BC0, ?USERUNIT_CanBeBuiltAt@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSOCellPos@1@_NPAUSBuildInfo@1@@Z)
 *
 * What it does:
 * Converts one cell-origin placement probe into world-space center
 * coordinates and forwards to the world-space buildability path.
 */
bool moho::USERUNIT_CanBeBuiltAt(
  CWldSession& session,
  const RUnitBlueprint* const buildBlueprint,
  const SOCellPos& cellPosition,
  const bool allowCommandOverlap,
  SOccupationResult* const buildInfo
)
{
  const float halfSizeX = static_cast<float>(buildBlueprint->mFootprint.mSizeX) * 0.5f;
  const float halfSizeZ = static_cast<float>(buildBlueprint->mFootprint.mSizeZ) * 0.5f;

  const SCoordsVec2 buildPosition{
    static_cast<float>(cellPosition.x) + halfSizeX,
    static_cast<float>(cellPosition.z) + halfSizeZ,
  };

  return USERUNIT_CanBeBuiltAt(
    session,
    buildBlueprint,
    buildPosition,
    allowCommandOverlap,
    buildInfo,
    nullptr
  );
}

/**
 * Address: 0x008C1430 (FUN_008C1430, ?USERUNIT_CanOccupy@Moho@@YA_NAAVCWldSession@1@ABUSFootprint@1@AAUSOCellPos@1@@Z)
 *
 * What it does:
 * Validates one candidate occupancy rectangle against map bounds and rejects
 * placement if it overlaps a visible non-mobile unit footprint in the spatial
 * database.
 */
bool moho::USERUNIT_CanOccupy(CWldSession& session, const SFootprint& footprint, SOCellPos& position)
{
  const std::int16_t cellX = position.x;
  if (cellX < 0 || position.z < 0) {
    return false;
  }

  STIMap* const map = reinterpret_cast<STIMap*>(session.mWldMap->mTerrainRes->mPlayableRectSource);
  CHeightField* const field = map->GetHeightField();

  const std::int32_t rectX1 = static_cast<std::int32_t>(cellX) + static_cast<std::int32_t>(footprint.mSizeX);
  if (rectX1 >= (field->width - 1)) {
    return false;
  }

  const std::int32_t rectZ1 = static_cast<std::int32_t>(position.z) + static_cast<std::int32_t>(footprint.mSizeZ);
  if (rectZ1 >= (field->height - 1)) {
    return false;
  }

  const gpg::Rect2i queryRect{
    static_cast<std::int32_t>(cellX),
    static_cast<std::int32_t>(position.z),
    rectX1,
    rectZ1,
  };

  constexpr EEntityType kSpatialTypeUnit = static_cast<EEntityType>(0x00000100u);
  constexpr std::uint32_t kIntelVisibleMask = 0x08u;

  gpg::fastvector_n<UserEntity*, 100> nearbyUnits{};
  auto* const spatialStorage = reinterpret_cast<SpatialDB_MeshInstance*>(session.GetEntitySpatialDbStorage());
  spatialStorage->Collect(nearbyUnits, kSpatialTypeUnit);

  for (UserEntity* const nearbyEntity : nearbyUnits) {
    auto* const nearbyUserUnit = reinterpret_cast<UserUnit*>(nearbyEntity);
    const IUnit* const iunitBridge = GetIUnitBridge(nearbyUserUnit);
    const RUnitBlueprint* const unitBlueprint = iunitBridge->GetBlueprint();
    if (unitBlueprint->IsMobile() || (nearbyUserUnit->mIntelStateFlags & kIntelVisibleMask) == 0u) {
      continue;
    }

    const SFootprint& nearbyFootprint = unitBlueprint->mFootprint;
    const SOCellPos nearbyCell = nearbyFootprint.ToCellPos(nearbyEntity->mVariableData.mCurTransform.pos_);
    const gpg::Rect2i nearbyRect{
      static_cast<std::int32_t>(nearbyCell.x),
      static_cast<std::int32_t>(nearbyCell.z),
      static_cast<std::int32_t>(nearbyCell.x) + static_cast<std::int32_t>(nearbyFootprint.mSizeX),
      static_cast<std::int32_t>(nearbyCell.z) + static_cast<std::int32_t>(nearbyFootprint.mSizeZ),
    };

    if (queryRect.Overlaps(nearbyRect)) {
      return false;
    }
  }

  return true;
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
 * Address: 0x008C1C30 (FUN_008C1C30, ?USERUNIT_GetBounds@Moho@@YA?AV?$AxisAlignedBox3@M@Wm3@@PBVRUnitBlueprint@1@ABV?$Vector3@M@3@@Z)
 *
 * What it does:
 * Builds one world-space unit bounds AABB from collision offsets/sizes for
 * mobile blueprints, and from skirt-rectangle extents for non-mobile
 * blueprints.
 */
Wm3::AxisAlignedBox3f moho::USERUNIT_GetBounds(
  const RUnitBlueprint* const unitBlueprint,
  const Wm3::Vector3f& worldPosition
)
{
  Wm3::AxisAlignedBox3f bounds{};

  if (unitBlueprint->IsMobile()) {
    const float minX =
      (worldPosition.x + unitBlueprint->mCollisionOffsetX) - (unitBlueprint->mSizeX * 0.5f);
    const float minY = worldPosition.y + unitBlueprint->mCollisionOffsetY;
    const float minZ =
      (worldPosition.z + unitBlueprint->mCollisionOffsetZ) - (unitBlueprint->mSizeZ * 0.5f);

    bounds.Min.x = minX;
    bounds.Min.y = minY;
    bounds.Min.z = minZ;
    bounds.Max.x = minX + unitBlueprint->mSizeX;
    bounds.Max.y = minY + unitBlueprint->mSizeY;
    bounds.Max.z = minZ + unitBlueprint->mSizeZ;
    return bounds;
  }

  const SCoordsVec2 footprintPosition{worldPosition.x, worldPosition.z};
  const gpg::Rect2f skirtRect = unitBlueprint->GetSkirtRect(footprintPosition);

  bounds.Min.x = skirtRect.x0;
  bounds.Min.y = worldPosition.y;
  bounds.Min.z = skirtRect.z0;
  bounds.Max.x = skirtRect.x1;
  bounds.Max.y = worldPosition.y + unitBlueprint->mSizeY;
  bounds.Max.z = skirtRect.z1;
  return bounds;
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
  lua_pushnumber(rawState, userUnit->mUnitVarDat.mWorkProgress);
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
    const UserCommandQueueRangeView* const commandRange = ResolveUserCommandQueueRange(userUnit->GetCommandQueue());
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

  const UserCommandQueueRangeView* const commandRange = ResolveUserCommandQueueRange(SelectActiveQueue(userUnit));
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
  for (UserCommandQueueEntry* entry = commandRange->begin; entry != commandRange->end; ++entry) {
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

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct UserUnitLuaFuncDefBootstrap
  {
    UserUnitLuaFuncDefBootstrap()
    {
      (void)::moho::func_UserUnitCanAttackTarget_LuaFuncDef();
      (void)::moho::func_UserUnitGetFootPrintSize_LuaFuncDef();
      (void)::moho::func_UserUnitGetUnitId_LuaFuncDef();
      (void)::moho::func_UserUnitGetBlueprint_LuaFuncDef();
      (void)::moho::func_UserUnitIsAutoMode_LuaFuncDef();
      (void)::moho::func_UserUnitIsAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_UserUnitIsRepeatQueue_LuaFuncDef();
      (void)::moho::func_UserUnitGetEntityId_LuaFuncDef();
      (void)::moho::func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef();
      (void)::moho::func_UserUnitProcessInfo_LuaFuncDef();
      (void)::moho::func_UserUnitSetCustomName_LuaFuncDef();
      (void)::moho::func_UserUnitAddSelectionSet_LuaFuncDef();
      (void)::moho::func_UserUnitRemoveSelectionSet_LuaFuncDef();
      (void)::moho::func_UserUnitGetSelectionSets_LuaFuncDef();
      (void)::moho::func_UserUnitIsInCategory_LuaFuncDef();
      (void)::moho::func_UserUnitGetHealth_LuaFuncDef();
      (void)::moho::func_UserUnitGetMaxHealth_LuaFuncDef();
      (void)::moho::func_UserUnitGetBuildRate_LuaFuncDef();
      (void)::moho::func_UserUnitIsOverchargePaused_LuaFuncDef();
      (void)::moho::func_UserUnitIsDead_LuaFuncDef();
      (void)::moho::func_UserUnitGetFuelRatio_LuaFuncDef();
      (void)::moho::func_UserUnitGetShieldRatio_LuaFuncDef();
      (void)::moho::func_UserUnitGetWorkProgress_LuaFuncDef();
      (void)::moho::func_UserUnitGetStat_LuaFuncDef();
      (void)::moho::func_UserUnitIsStunned_LuaFuncDef();
      (void)::moho::func_UserUnitGetCustomName_LuaFuncDef();
      (void)::moho::func_UserUnitHasSelectionSet_LuaFuncDef();
      (void)::moho::func_UserUnitIsIdle_LuaFuncDef();
      (void)::moho::func_UserUnitGetFocus_LuaFuncDef();
      (void)::moho::func_UserUnitGetGuardedEntity_LuaFuncDef();
      (void)::moho::func_UserUnitGetCreator_LuaFuncDef();
      (void)::moho::func_UserUnitGetPosition_LuaFuncDef();
      (void)::moho::func_UserUnitGetArmy_LuaFuncDef();
      (void)::moho::func_UserUnitGetEconData_LuaFuncDef();
      (void)::moho::func_UserUnitGetCommandQueue_LuaFuncDef();
      (void)::moho::func_UserUnitGetMissileInfo_LuaFuncDef();
      (void)::moho::func_SetCurrentFactoryForQueueDisplay_LuaFuncDef();
      (void)::moho::func_GetBlueprintUser_LuaFuncDef();
    }
  };

  const UserUnitLuaFuncDefBootstrap gUserUnitLuaFuncDefBootstrap{};
} // namespace
