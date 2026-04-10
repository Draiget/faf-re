#include "moho/unit/core/UnitWeapon.h"

#include <cmath>
#include <cstring>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/entity/EntityCategorySetVectorReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/serialization/SBlackListInfoVectorReflection.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CFireWeaponTask.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kUnitWeaponLuaClassName = "UnitWeapon";
  constexpr const char* kUnitWeaponPlaySoundName = "PlaySound";
  constexpr const char* kUnitWeaponPlaySoundHelpText = "UnitWeapon:PlaySound(weapon,ParamTable)";
  constexpr const char* kUnitWeaponSetEnabledName = "SetEnabled";
  constexpr const char* kUnitWeaponSetEnabledHelpText = "UnitWeapon:SetEnabled(enabled)";
  constexpr const char* kUnitWeaponSetTargetEntityName = "SetTargetEntity";
  constexpr const char* kUnitWeaponSetTargetEntityHelpText = "UnitWeapon:SetTarget(entity)";
  constexpr const char* kUnitWeaponSetTargetGroundName = "SetTargetGround";
  constexpr const char* kUnitWeaponSetTargetGroundHelpText = "UnitWeapon:SetTarget(location)";
  constexpr const char* kUnitWeaponResetTargetName = "ResetTarget";
  constexpr const char* kUnitWeaponResetTargetHelpText = "UnitWeapon:ResetTarget()";
  constexpr const char* kUnitWeaponCreateProjectileName = "CreateProjectile";
  constexpr const char* kUnitWeaponCreateProjectileHelpText = "UnitWeapon:CreateProjectile(muzzlebone)";
  constexpr const char* kUnitWeaponDoInstaHitName = "DoInstaHit";
  constexpr const char* kUnitWeaponDoInstaHitHelpText =
    "UnitWeapon:DoInstaHit(bone, r,g,b, glow, width, texture, lifetime)";
  constexpr const char* kUnitWeaponGetProjectileBlueprintName = "GetProjectileBlueprint";
  constexpr const char* kUnitWeaponGetProjectileBlueprintHelpText = "blueprint = UnitWeapon:GetProjectileBlueprint()";
  constexpr const char* kUnitWeaponHasTargetName = "WeaponHasTarget";
  constexpr const char* kUnitWeaponHasTargetHelpText = "bool = UnitWeapon:HasTarget()";
  constexpr const char* kUnitWeaponFireWeaponName = "FireWeapon";
  constexpr const char* kUnitWeaponFireWeaponHelpText = "bool = UnitWeapon:FireWeapon()";
  constexpr const char* kUnitWeaponIsFireControlName = "IsFireControl";
  constexpr const char* kUnitWeaponIsFireControlHelpText = "UnitWeapon:IsFireControl(label)";
  constexpr const char* kUnitWeaponGetCurrentTargetName = "GetCurrentTarget";
  constexpr const char* kUnitWeaponGetCurrentTargetHelpText = "UnitWeapon:GetCurrentTarget()";
  constexpr const char* kUnitWeaponGetCurrentTargetPosName = "GetCurrentTargetPos";
  constexpr const char* kUnitWeaponGetCurrentTargetPosHelpText = "UnitWeapon:GetCurrentTargetPos()";
  constexpr const char* kUnitWeaponCanFireName = "CanFire";
  constexpr const char* kUnitWeaponCanFireHelpText = "UnitWeapon:CanFire()";
  constexpr const char* kUnitWeaponSetTargetingPrioritiesName = "SetTargetingPriorities";
  constexpr const char* kUnitWeaponSetTargetingPrioritiesHelpText = "Set the targeting priorities for the unit";
  constexpr const char* kUnitWeaponGetFiringRandomnessName = "GetFiringRandomness";
  constexpr const char* kUnitWeaponGetFiringRandomnessHelpText = "Get the firing randomness";
  constexpr const char* kUnitWeaponGetFireClockPctName = "GetFireClockPct";
  constexpr const char* kUnitWeaponGetFireClockPctHelpText = "Get the firing clock percent (0 - 1)";
  constexpr const char* kUnitWeaponChangeProjectileBlueprintName = "ChangeProjectileBlueprint";
  constexpr const char* kUnitWeaponChangeProjectileBlueprintHelpText = "Change the projectile blueprint of a weapon";
  constexpr const char* kUnitWeaponTransferTargetName = "TransferTarget";
  constexpr const char* kUnitWeaponTransferTargetHelpText = "Transfer target from 1 weapon to another";
  constexpr const char* kUnitWeaponBeenDestroyedName = "BeenDestroyed";
  constexpr const char* kUnitWeaponBeenDestroyedHelpText = "UnitWeapon:BeenDestroyed()";
  constexpr const char* kUnitWeaponGetBlueprintName = "GetBlueprint";
  constexpr const char* kUnitWeaponGetBlueprintHelpText = "blueprint = UnitWeapon:GetBlueprint()";
  constexpr const char* kUnitWeaponSetFireControlName = "SetFireControl";
  constexpr const char* kUnitWeaponSetFireControlHelpText = "UnitWeapon:SetFireControl(label)";
  constexpr const char* kUnitWeaponChangeFiringToleranceName = "ChangeFiringTolerance";
  constexpr const char* kUnitWeaponChangeFiringToleranceHelpText = "UnitWeapon:ChangeFiringTolerance(value)";
  constexpr const char* kUnitWeaponChangeRateOfFireName = "ChangeRateOfFire";
  constexpr const char* kUnitWeaponChangeRateOfFireHelpText = "UnitWeapon:ChangeRateOfFire(value)";
  constexpr const char* kUnitWeaponChangeMinRadiusName = "ChangeMinRadius";
  constexpr const char* kUnitWeaponChangeMinRadiusHelpText = "UnitWeapon:ChangeMinRadius(value)";
  constexpr const char* kUnitWeaponChangeMaxRadiusName = "ChangeMaxRadius";
  constexpr const char* kUnitWeaponChangeMaxRadiusHelpText = "UnitWeapon:ChangeMaxRadius(value)";
  constexpr const char* kUnitWeaponChangeMaxHeightDiffName = "ChangeMaxHeightDiff";
  constexpr const char* kUnitWeaponChangeMaxHeightDiffHelpText = "UnitWeapon:ChangeMaxHeightDiff(value)";
  constexpr const char* kUnitWeaponChangeDamageTypeName = "ChangeDamageType";
  constexpr const char* kUnitWeaponChangeDamageTypeHelpText = "UnitWeapon:ChangeDamageType(typeName)";
  constexpr const char* kUnitWeaponChangeDamageRadiusName = "ChangeDamageRadius";
  constexpr const char* kUnitWeaponChangeDamageRadiusHelpText = "UnitWeapon:ChangeDamageRadius(value)";
  constexpr const char* kUnitWeaponChangeDamageName = "ChangeDamage";
  constexpr const char* kUnitWeaponChangeDamageHelpText = "UnitWeapon:ChangeDamage(value)";
  constexpr const char* kUnitWeaponSetFiringRandomnessName = "SetFiringRandomness";
  constexpr const char* kUnitWeaponSetFiringRandomnessHelpText = "Set the firing randomness";
  constexpr const char* kUnitWeaponSetFireTargetLayerCapsName = "SetFireTargetLayerCaps";
  constexpr const char* kUnitWeaponSetFireTargetLayerCapsHelpText = "UnitWeapon:SetFireTargetLayerCaps(mask)";

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const rawState = userDataObject.GetActiveCState();
    if (!rawState) {
      return out;
    }

    const int top = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(rawState);
    void* const rawUserData = lua_touserdata(rawState, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(rawState, top);
    return out;
  }

  [[nodiscard]] moho::CSndParams* ResolveSoundParamsFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    static gpg::RType* sSoundParamsType = nullptr;
    if (!sSoundParamsType) {
      sSoundParamsType = gpg::LookupRType(typeid(moho::CSndParams));
    }

    if (sSoundParamsType) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, sSoundParamsType);
      if (upcast.mObj != nullptr) {
        return static_cast<moho::CSndParams*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr && std::strstr(typeName, "CSndParams") != nullptr) {
      return static_cast<moho::CSndParams*>(userDataRef.mObj);
    }

    return nullptr;
  }

  [[nodiscard]] bool IsFiniteVector3(const Wm3::Vec3f& value) noexcept
  {
    return std::isfinite(value.x) && std::isfinite(value.y) && std::isfinite(value.z);
  }

  enum class UnitWeaponTargetSolutionStatus : std::uint8_t
  {
    Available = 0u,
    InsideMinRange = 1u,
    NoSolution = 2u,
    OutsideMaxRange = 3u,
  };

  [[nodiscard]] float NormalizeAngleRadians(const float angleRadians) noexcept
  {
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kTwoPi = 6.28318530717958647692f;

    float normalized = std::fmod(angleRadians + kPi, kTwoPi);
    if (normalized < 0.0f) {
      normalized += kTwoPi;
    }
    return normalized - kPi;
  }

  [[nodiscard]] UnitWeaponTargetSolutionStatus EvaluateTargetSolutionStatusGun(
    moho::UnitWeapon* const weapon,
    const Wm3::Vec3f& targetPosition,
    float* const inOutDistanceSq
  )
  {
    if (weapon == nullptr || weapon->mUnit == nullptr) {
      return UnitWeaponTargetSolutionStatus::NoSolution;
    }

    float distanceSq = 0.0f;
    if (inOutDistanceSq != nullptr && *inOutDistanceSq > 0.0f) {
      distanceSq = *inOutDistanceSq;
    } else {
      const Wm3::Vec3f& weaponPosition = weapon->mUnit->GetPosition();
      const float dx = targetPosition.x - weaponPosition.x;
      const float dz = targetPosition.z - weaponPosition.z;
      distanceSq = (dx * dx) + (dz * dz);
    }

    if (const moho::RUnitBlueprintWeapon* const blueprint = weapon->mAttributes.mBlueprint; blueprint != nullptr) {
      if (weapon->mAttributes.mMaxRadiusSq < 0.0f) {
        weapon->mAttributes.mMaxRadiusSq = blueprint->MaxRadius * blueprint->MaxRadius;
      }
      if (weapon->mAttributes.mMinRadiusSq < 0.0f) {
        weapon->mAttributes.mMinRadiusSq = blueprint->MinRadius * blueprint->MinRadius;
      }
    }

    if (distanceSq > weapon->mAttributes.mMaxRadiusSq) {
      return UnitWeaponTargetSolutionStatus::OutsideMaxRange;
    }
    if (distanceSq <= weapon->mAttributes.mMinRadiusSq) {
      return UnitWeaponTargetSolutionStatus::InsideMinRange;
    }

    float maxHeightDiff = weapon->mAttributes.mMaxHeightDiff;
    if (maxHeightDiff < 0.0f && weapon->mAttributes.mBlueprint != nullptr) {
      maxHeightDiff = weapon->mAttributes.mBlueprint->MaxHeightDiff;
    }
    const float heightDiff = std::fabs(targetPosition.y - weapon->mUnit->GetPosition().y);
    if (heightDiff > maxHeightDiff) {
      return UnitWeaponTargetSolutionStatus::OutsideMaxRange;
    }

    if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->HeadingArcRange < 180.0f) {
      Wm3::Vec3f muzzlePosition = weapon->mUnit->GetPosition();
      if (weapon->mBone >= 0) {
        muzzlePosition = weapon->mUnit->GetBoneWorldTransform(weapon->mBone).pos_;
      }

      const float targetHeading = std::atan2(targetPosition.x - muzzlePosition.x, targetPosition.z - muzzlePosition.z);
      const Wm3::Vec3f forward = weapon->mUnit->GetTransform().orient_.Rotate(Wm3::Vec3f{0.0f, 0.0f, 1.0f});
      const float unitHeading = std::atan2(forward.x, forward.z);

      constexpr float kDegreesToRadians = 0.017453292f;
      const float headingArcCenter = weapon->mWeaponBlueprint->HeadingArcCenter * kDegreesToRadians;
      const float headingArcRange = weapon->mWeaponBlueprint->HeadingArcRange * kDegreesToRadians;
      const float headingDelta = NormalizeAngleRadians(targetHeading - unitHeading - headingArcCenter);
      if (std::fabs(headingDelta) > headingArcRange) {
        return UnitWeaponTargetSolutionStatus::NoSolution;
      }
    }

    if (inOutDistanceSq != nullptr) {
      *inOutDistanceSq = distanceSq;
    }

    return UnitWeaponTargetSolutionStatus::Available;
  }

  [[nodiscard]] bool UnitWeaponHasSiloAmmo(const moho::UnitWeapon* const weapon) noexcept
  {
    if (weapon == nullptr || weapon->mWeaponBlueprint == nullptr || weapon->mWeaponBlueprint->CountedProjectile == 0u) {
      return true;
    }
    if (weapon->mUnit == nullptr || weapon->mUnit->AiSiloBuild == nullptr) {
      return true;
    }
    const std::int32_t storageCount =
      weapon->mUnit->AiSiloBuild->SiloGetStorageCount(static_cast<moho::ESiloType>(weapon->mWeaponBlueprint->NukeWeapon));
    return storageCount != 0;
  }

  [[nodiscard]] bool CanWeaponFireCurrentTarget(moho::UnitWeapon* const weapon)
  {
    if (weapon == nullptr || !weapon->mTarget.HasTarget()) {
      return false;
    }
    if (weapon->mWeaponBlueprint != nullptr) {
      if (weapon->mWeaponBlueprint->IgnoreIfDisabled != 0u && weapon->mEnabled == 0u) {
        return false;
      }
      if (weapon->mTarget.targetType == moho::EAiTargetType::AITARGET_Ground
          && weapon->mWeaponBlueprint->CannotAttackGround != 0u) {
        return false;
      }
    }
    if (!UnitWeaponHasSiloAmmo(weapon)) {
      return false;
    }

    const Wm3::Vec3f targetPosition = weapon->mTarget.GetTargetPosGun(true);
    if (!IsFiniteVector3(targetPosition)) {
      return false;
    }

    return EvaluateTargetSolutionStatusGun(weapon, targetPosition, nullptr) == UnitWeaponTargetSolutionStatus::Available;
  }

  /**
   * Address: 0x006DAF30 (FUN_006DAF30, sub_6DAF30)
   *
   * What it does:
   * Tests whether one entity blueprint category-bit ordinal is present in one
   * category-set bit vector.
   */
  [[nodiscard]] bool EntityCategoryContainsBlueprint(
    const moho::REntityBlueprint* const blueprint,
    const moho::EntityCategorySet& categorySet
  ) noexcept
  {
    GPG_ASSERT(blueprint != nullptr);
    return blueprint != nullptr && categorySet.Bits().Contains(blueprint->mCategoryBitIndex);
  }

  /**
   * Address: 0x006D5590 (FUN_006D5590, func_PickTargetPoint)
   *
   * What it does:
   * Validates one entity target against weapon layer/category constraints and
   * resolves above/below-water aim-point pick requirements.
   */
  [[nodiscard]] bool CanWeaponAttackEntityTarget(moho::Entity* const targetEntity, moho::UnitWeapon* const weapon)
  {
    if (targetEntity == nullptr) {
      return false;
    }

    moho::RUnitBlueprintWeapon* const weaponBlueprint = weapon->mWeaponBlueprint;
    if (weaponBlueprint->IgnoreIfDisabled != 0u && weapon->mEnabled == 0u) {
      return false;
    }

    const moho::ELayer targetLayer = targetEntity->mCurrentLayer;
    if ((weapon->mFireTargetLayerCaps & targetLayer) == 0) {
      return false;
    }

    if (targetLayer == moho::LAYER_Seabed) {
      std::int32_t targetPoint = 0;
      if (weaponBlueprint->AboveWaterTargetsOnly != 0u) {
        if (moho::Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
          if (!targetUnit->PickTargetPointAboveWater(targetPoint)) {
            return false;
          }
        } else if (moho::ReconBlip* const targetBlip = targetEntity->IsReconBlip(); targetBlip != nullptr) {
          if (!targetBlip->PickTargetPointAboveWater(targetPoint)) {
            return false;
          }
        } else {
          return false;
        }
      } else if (weaponBlueprint->BelowWaterTargetsOnly != 0u) {
        if (moho::Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
          if (!targetUnit->PickTargetPointBelowWater(targetPoint)) {
            return false;
          }
        } else if (moho::ReconBlip* const targetBlip = targetEntity->IsReconBlip(); targetBlip != nullptr) {
          if (!targetBlip->PickTargetPointBelowWater(targetPoint)) {
            return false;
          }
        } else {
          return false;
        }
      }
    }

    const moho::REntityBlueprint* const blueprint = targetEntity->BluePrint;
    if (blueprint == nullptr) {
      return false;
    }

    if (!weapon->mCat1.Bits().mWords.empty() && !EntityCategoryContainsBlueprint(blueprint, weapon->mCat1)) {
      return false;
    }
    if (!weapon->mCat2.Bits().mWords.empty() && EntityCategoryContainsBlueprint(blueprint, weapon->mCat2)) {
      return false;
    }

    return true;
  }

  void UpdateProjectileBlueprintFromText(moho::UnitWeapon* const weapon, const char* const blueprintText)
  {
    if (weapon == nullptr || blueprintText == nullptr || blueprintText[0] == '\0') {
      return;
    }

    moho::RResId projectileId{};
    gpg::STR_InitFilename(&projectileId.name, blueprintText);
    weapon->mProjectileBlueprint =
      (weapon->mSim != nullptr && weapon->mSim->mRules != nullptr) ? weapon->mSim->mRules->GetProjectileBlueprint(projectileId)
                                                                    : nullptr;

    if (weapon->mUnit != nullptr && weapon->mUnit->AiSiloBuild != nullptr) {
      weapon->mUnit->AiSiloBuild->SiloUpdateProjectileBlueprint();
    }
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  template <class T>
  [[nodiscard]] gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }

    return cached;
  }

  template <class T>
  [[nodiscard]] T* ReadTrackedPointer(gpg::ReadArchive& archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(&archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    const gpg::RRef source{tracked.object, tracked.type};
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRType<T>());
    if (upcast.mObj) {
      return static_cast<T*>(upcast.mObj);
    }

    const char* const expectedTypeName = CachedRType<T>() ? CachedRType<T>()->GetName() : "null";
    const char* const actualTypeName = source.GetTypeName();
    const msvc8::string errorMessage = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedTypeName ? expectedTypeName : "null",
      actualTypeName ? actualTypeName : "null"
    );
    throw gpg::SerializationError(errorMessage.c_str());
  }

  template <class T>
  [[nodiscard]] gpg::RRef MakeTrackedRef(T* object)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedRType<T>();
    if (!object) {
      return out;
    }

    gpg::RType* runtimeType = out.mType;
    try {
      runtimeType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      runtimeType = out.mType;
    }

    if (!runtimeType || !out.mType) {
      out.mObj = object;
      out.mType = runtimeType ? runtimeType : out.mType;
      return out;
    }

    std::int32_t baseOffset = 0;
    const bool derived = runtimeType->IsDerivedFrom(out.mType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = runtimeType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = runtimeType;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeLayerRef(moho::ELayer* const layerMask)
  {
    gpg::RRef out{};
    out.mObj = layerMask;
    out.mType = CachedRType<moho::ELayer>();
    return out;
  }

  template <class T>
  void WriteTrackedPointer(
    gpg::WriteArchive& archive,
    T* pointer,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef pointerRef = MakeTrackedRef(pointer);
    gpg::WriteRawPointer(&archive, pointerRef, state, ownerRef);
  }

  [[nodiscard]] const Wm3::Vector3f& GetRecoveredInvalidAimingVector() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalid{};
    if (!initialized) {
      const float qnan = std::numeric_limits<float>::quiet_NaN();
      invalid = Wm3::Vector3f{qnan, qnan, qnan};
      initialized = true;
    }

    return invalid;
  }
} // namespace

namespace moho
{
  gpg::RType* UnitWeapon::sType = nullptr;

  // Callback bodies are recovered in adjacent lanes; publishers are required
  // here so startup thunk registration resolves to source-defined binders.
  int cfunc_UnitWeaponSetTargetEntity(lua_State* luaContext);
  int cfunc_UnitWeaponSetTargetGround(lua_State* luaContext);
  int cfunc_UnitWeaponResetTarget(lua_State* luaContext);
  int cfunc_UnitWeaponResetTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponCreateProjectile(lua_State* luaContext);
  int cfunc_UnitWeaponCreateProjectileL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponDoInstaHit(lua_State* luaContext);
  int cfunc_UnitWeaponGetProjectileBlueprint(lua_State* luaContext);
  int cfunc_UnitWeaponHasTarget(lua_State* luaContext);
  int cfunc_UnitWeaponFireWeapon(lua_State* luaContext);
  int cfunc_UnitWeaponIsFireControl(lua_State* luaContext);
  int cfunc_UnitWeaponGetCurrentTarget(lua_State* luaContext);
  int cfunc_UnitWeaponGetCurrentTargetPos(lua_State* luaContext);
  int cfunc_UnitWeaponCanFire(lua_State* luaContext);
  int cfunc_UnitWeaponSetTargetingPriorities(lua_State* luaContext);
  int cfunc_UnitWeaponGetFiringRandomness(lua_State* luaContext);
  int cfunc_UnitWeaponGetFireClockPct(lua_State* luaContext);
  int cfunc_UnitWeaponChangeProjectileBlueprint(lua_State* luaContext);
  int cfunc_UnitWeaponTransferTarget(lua_State* luaContext);
  int cfunc_UnitWeaponBeenDestroyed(lua_State* luaContext);

  /**
   * Address: 0x006D7BD0 (FUN_006D7BD0, cfunc_UnitWeaponPlaySound)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponPlaySoundL`.
   */
  int cfunc_UnitWeaponPlaySound(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponPlaySoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D7BF0 (FUN_006D7BF0, func_UnitWeaponPlaySound_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:PlaySound(weapon,ParamTable)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponPlaySound_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponPlaySoundName,
      &moho::cfunc_UnitWeaponPlaySound,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponPlaySoundHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D7C50 (FUN_006D7C50, cfunc_UnitWeaponPlaySoundL)
   *
   * What it does:
   * Resolves `(weapon, soundParams)` and queues one weapon-owner sound request.
   */
  int cfunc_UnitWeaponPlaySoundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponPlaySoundHelpText, 2, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaObject paramsObject(LuaPlus::LuaStackObject(state, 2));
    CSndParams* const params = ResolveSoundParamsFromLuaObject(paramsObject);

    if (sim && sim->mSoundManager) {
      Entity* const entity = weapon->mUnit ? static_cast<Entity*>(weapon->mUnit) : nullptr;
      sim->mSoundManager->AddEntitySound(entity, params);
    }

    return 0;
  }

  /**
   * Address: 0x006D7D70 (FUN_006D7D70, cfunc_UnitWeaponSetEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetEnabledL`.
   */
  int cfunc_UnitWeaponSetEnabled(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetEnabledL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D7D90 (FUN_006D7D90, func_UnitWeaponSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetEnabled(enabled)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetEnabled_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetEnabledName,
      &moho::cfunc_UnitWeaponSetEnabled,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetEnabledHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D7DF0 (FUN_006D7DF0, cfunc_UnitWeaponSetEnabledL)
   *
   * What it does:
   * Updates enabled state and unstages the fire task thread when re-enabled.
   */
  int cfunc_UnitWeaponSetEnabledL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetEnabledHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject enabledArg(state, 2);
    const bool enabled = enabledArg.GetBoolean();
    weapon->mEnabled = enabled;
    if (enabled) {
      CTaskThread* const taskThread = weapon->mFireWeaponTask->mOwnerThread;
      taskThread->mPendingFrames = 0;
      if (taskThread->mStaged) {
        taskThread->Unstage();
      }
    }

    lua_settop(rawState, 1);
    return 1;
  }

  /**
   * Address: 0x006D7F20 (FUN_006D7F20, func_UnitWeaponSetTargetEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetTargetEntity(entity)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetTargetEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetTargetEntityName,
      &moho::cfunc_UnitWeaponSetTargetEntity,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetTargetEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D80E0 (FUN_006D80E0, func_UnitWeaponSetTargetGround_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetTargetGround(location)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetTargetGround_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetTargetGroundName,
      &moho::cfunc_UnitWeaponSetTargetGround,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetTargetGroundHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8340 (FUN_006D8340, func_UnitWeaponResetTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ResetTarget()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponResetTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponResetTargetName,
      &moho::cfunc_UnitWeaponResetTarget,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponResetTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8320 (FUN_006D8320, cfunc_UnitWeaponResetTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponResetTargetL`.
   */
  int cfunc_UnitWeaponResetTarget(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponResetTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D83A0 (FUN_006D83A0, cfunc_UnitWeaponResetTargetL)
   *
   * What it does:
   * Resolves one weapon from Lua and clears its target payload to the default
   * `AITARGET_None` state.
   */
  int cfunc_UnitWeaponResetTargetL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponResetTargetHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    CAiTarget clearedTarget{};
    clearedTarget.targetType = EAiTargetType::AITARGET_None;
    clearedTarget.targetEntity.ownerLinkSlot = nullptr;
    clearedTarget.targetEntity.nextInOwner = nullptr;
    clearedTarget.targetPoint = -1;
    clearedTarget.targetIsMobile = false;

    weapon->mTarget = clearedTarget;
    return 0;
  }

  /**
   * Address: 0x006D8490 (FUN_006D8490, cfunc_UnitWeaponCreateProjectile)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponCreateProjectileL`.
   */
  int cfunc_UnitWeaponCreateProjectile(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponCreateProjectileL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D84B0 (FUN_006D84B0, func_UnitWeaponCreateProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:CreateProjectile(muzzlebone)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponCreateProjectile_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponCreateProjectileName,
      &moho::cfunc_UnitWeaponCreateProjectile,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponCreateProjectileHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8510 (FUN_006D8510, cfunc_UnitWeaponCreateProjectileL)
   *
   * What it does:
   * Resolves `(weapon, muzzlebone)`, spawns one projectile, and pushes the
   * projectile Lua object when creation succeeds.
   */
  int cfunc_UnitWeaponCreateProjectileL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponCreateProjectileHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    Entity* const ownerEntity = weapon->mUnit ? static_cast<Entity*>(weapon->mUnit) : nullptr;
    LuaPlus::LuaStackObject muzzleBoneArg(state, 2);
    const std::int32_t muzzleBoneIndex = ENTSCR_ResolveBoneIndex(ownerEntity, muzzleBoneArg, true);

    Projectile* const projectile = weapon->CreateProjectile(muzzleBoneIndex);
    if (projectile == nullptr) {
      return 0;
    }

    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006D8630 (FUN_006D8630, func_UnitWeaponDoInstaHit_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:DoInstaHit(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponDoInstaHit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponDoInstaHitName,
      &moho::cfunc_UnitWeaponDoInstaHit,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponDoInstaHitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8C30 (FUN_006D8C30, func_UnitWeaponGetProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes `blueprint = UnitWeapon:GetProjectileBlueprint()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetProjectileBlueprint_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponGetProjectileBlueprintName,
      &moho::cfunc_UnitWeaponGetProjectileBlueprint,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponGetProjectileBlueprintHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8D90 (FUN_006D8D90, func_UnitWeaponHasTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `bool = UnitWeapon:HasTarget()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponHasTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponHasTargetName,
      &moho::cfunc_UnitWeaponHasTarget,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponHasTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8ED0 (FUN_006D8ED0, func_UnitWeaponFireWeapon_LuaFuncDef)
   *
   * What it does:
   * Publishes `bool = UnitWeapon:FireWeapon()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponFireWeapon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponFireWeaponName,
      &moho::cfunc_UnitWeaponFireWeapon,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponFireWeaponHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9170 (FUN_006D9170, func_UnitWeaponIsFireControl_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:IsFireControl(label)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponIsFireControl_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponIsFireControlName,
      &moho::cfunc_UnitWeaponIsFireControl,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponIsFireControlHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D91D0 (FUN_006D91D0, cfunc_UnitWeaponIsFireControlL)
   *
   * What it does:
   * Compares one label string against `UnitWeapon::mLabel` (case-insensitive)
   * and pushes one boolean result.
   */
  int cfunc_UnitWeaponIsFireControlL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponIsFireControlHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject labelArg(state, 2);
    const char* labelText = lua_tostring(rawState, 2);
    if (labelText == nullptr) {
      labelArg.TypeError("string");
      labelText = "";
    }

    const bool isFireControlLabel = (_stricmp(labelText, weapon->mLabel.c_str()) == 0);
    lua_pushboolean(rawState, isFireControlLabel ? 1 : 0);
    (void)lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x006D9150 (FUN_006D9150, cfunc_UnitWeaponIsFireControl)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponIsFireControlL`.
   */
  int cfunc_UnitWeaponIsFireControl(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponIsFireControlL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9330 (FUN_006D9330, func_UnitWeaponGetCurrentTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetCurrentTarget()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetCurrentTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponGetCurrentTargetName,
      &moho::cfunc_UnitWeaponGetCurrentTarget,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponGetCurrentTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D94B0 (FUN_006D94B0, func_UnitWeaponGetCurrentTargetPos_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetCurrentTargetPos()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetCurrentTargetPos_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponGetCurrentTargetPosName,
      &moho::cfunc_UnitWeaponGetCurrentTargetPos,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponGetCurrentTargetPosHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9650 (FUN_006D9650, func_UnitWeaponCanFire_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:CanFire()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponCanFire_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponCanFireName,
      &moho::cfunc_UnitWeaponCanFire,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponCanFireHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA500 (FUN_006DA500, func_UnitWeaponSetTargetingPriorities_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetTargetingPriorities(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetTargetingPriorities_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetTargetingPrioritiesName,
      &moho::cfunc_UnitWeaponSetTargetingPriorities,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetTargetingPrioritiesHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA6D0 (FUN_006DA6D0, func_UnitWeaponGetFiringRandomness_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetFiringRandomness()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetFiringRandomness_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponGetFiringRandomnessName,
      &moho::cfunc_UnitWeaponGetFiringRandomness,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponGetFiringRandomnessHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA980 (FUN_006DA980, func_UnitWeaponGetFireClockPct_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:GetFireClockPct()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetFireClockPct_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponGetFireClockPctName,
      &moho::cfunc_UnitWeaponGetFireClockPct,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponGetFireClockPctHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DAB00 (FUN_006DAB00, func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeProjectileBlueprint(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeProjectileBlueprintName,
      &moho::cfunc_UnitWeaponChangeProjectileBlueprint,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeProjectileBlueprintHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DACA0 (FUN_006DACA0, func_UnitWeaponTransferTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:TransferTarget(...)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponTransferTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponTransferTargetName,
      &moho::cfunc_UnitWeaponTransferTarget,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponTransferTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DAE10 (FUN_006DAE10, func_UnitWeaponBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:BeenDestroyed()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponBeenDestroyed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponBeenDestroyedName,
      &moho::cfunc_UnitWeaponBeenDestroyed,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponBeenDestroyedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8C90 (FUN_006D8C90, cfunc_UnitWeaponGetProjectileBlueprintL)
   *
   * What it does:
   * Pushes the current projectile blueprint Lua table for this weapon.
   */
  int cfunc_UnitWeaponGetProjectileBlueprintL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponGetProjectileBlueprintHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    LuaPlus::LuaObject blueprintObject = weapon->mProjectileBlueprint->GetLuaBlueprint(state);
    blueprintObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006D8C10 (FUN_006D8C10, cfunc_UnitWeaponGetProjectileBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetProjectileBlueprintL`.
   */
  int cfunc_UnitWeaponGetProjectileBlueprint(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponGetProjectileBlueprintL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D8DF0 (FUN_006D8DF0, cfunc_UnitWeaponHasTargetL)
   *
   * What it does:
   * Pushes whether this weapon currently has any non-none target payload.
   */
  int cfunc_UnitWeaponHasTargetL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponHasTargetHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const bool hasTarget = weapon->mTarget.targetType != EAiTargetType::AITARGET_None;
    lua_pushboolean(rawState, hasTarget ? 1 : 0);
    (void)lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x006D8D70 (FUN_006D8D70, cfunc_UnitWeaponHasTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponHasTargetL`.
   */
  int cfunc_UnitWeaponHasTarget(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponHasTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9390 (FUN_006D9390, cfunc_UnitWeaponGetCurrentTargetL)
   *
   * What it does:
   * Pushes the current target entity Lua object, or `nil` when target is empty.
   */
  int cfunc_UnitWeaponGetCurrentTargetL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponGetCurrentTargetHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    if (Entity* const targetEntity = weapon->mTarget.targetEntity.GetObjectPtr(); targetEntity != nullptr) {
      targetEntity->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x006D9310 (FUN_006D9310, cfunc_UnitWeaponGetCurrentTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetCurrentTargetL`.
   */
  int cfunc_UnitWeaponGetCurrentTarget(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponGetCurrentTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9510 (FUN_006D9510, cfunc_UnitWeaponGetCurrentTargetPosL)
   *
   * What it does:
   * Pushes current weapon target position or `nil` when target position is invalid.
   */
  int cfunc_UnitWeaponGetCurrentTargetPosL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponGetCurrentTargetPosHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const Wm3::Vec3f targetPosition = weapon->mTarget.GetTargetPosGun(false);
    if (!IsFiniteVector3(targetPosition)) {
      lua_pushnil(rawState);
      return 1;
    }

    LuaPlus::LuaObject targetPositionObject = SCR_ToLua<Wm3::Vector3<float>>(state, targetPosition);
    targetPositionObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006D9490 (FUN_006D9490, cfunc_UnitWeaponGetCurrentTargetPos)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetCurrentTargetPosL`.
   */
  int cfunc_UnitWeaponGetCurrentTargetPos(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponGetCurrentTargetPosL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D96B0 (FUN_006D96B0, cfunc_UnitWeaponCanFireL)
   *
   * What it does:
   * Evaluates target/silo/range gates and pushes one fire-availability boolean.
   */
  int cfunc_UnitWeaponCanFireL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponCanFireHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const bool canFire = CanWeaponFireCurrentTarget(weapon);
    lua_pushboolean(rawState, canFire ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x006D9630 (FUN_006D9630, cfunc_UnitWeaponCanFire)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponCanFireL`.
   */
  int cfunc_UnitWeaponCanFire(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponCanFireL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA560 (FUN_006DA560, cfunc_UnitWeaponSetTargetingPrioritiesL)
   *
   * What it does:
   * Rebuilds `mTargetPriorities` from a Lua table of `EntityCategory` values.
   */
  int cfunc_UnitWeaponSetTargetingPrioritiesL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetTargetingPrioritiesHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaObject prioritiesObject(LuaPlus::LuaStackObject(state, 2));
    if (!prioritiesObject.IsTable()) {
      LuaPlus::LuaState::Error(state, "Passed in an invalid table to priority categories");
      return 0;
    }

    weapon->mTargetPriorities.clear();
    const int count = prioritiesObject.GetCount();
    for (int index = 1; index <= count; ++index) {
      const LuaPlus::LuaObject categoryObject = prioritiesObject[index];
      EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
      if (categorySet == nullptr) {
        LuaPlus::LuaState::Error(state, "Passed in an invalid table to priority categories");
        return 0;
      }
      weapon->mTargetPriorities.push_back(*categorySet);
    }

    return 0;
  }

  /**
   * Address: 0x006DA4E0 (FUN_006DA4E0, cfunc_UnitWeaponSetTargetingPriorities)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetTargetingPrioritiesL`.
   */
  int cfunc_UnitWeaponSetTargetingPriorities(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetTargetingPrioritiesL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA730 (FUN_006DA730, cfunc_UnitWeaponGetFiringRandomnessL)
   *
   * What it does:
   * Pushes the current weapon firing-randomness scalar.
   */
  int cfunc_UnitWeaponGetFiringRandomnessL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponGetFiringRandomnessHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    lua_pushnumber(rawState, weapon->mFiringRandomness);
    return 1;
  }

  /**
   * Address: 0x006DA6B0 (FUN_006DA6B0, cfunc_UnitWeaponGetFiringRandomness)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetFiringRandomnessL`.
   */
  int cfunc_UnitWeaponGetFiringRandomness(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponGetFiringRandomnessL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA9E0 (FUN_006DA9E0, cfunc_UnitWeaponGetFireClockPctL)
   *
   * What it does:
   * Pushes normalized fire cooldown progress in `[0, 1]`.
   */
  int cfunc_UnitWeaponGetFireClockPctL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponGetFireClockPctHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    float rateOfFire = weapon->mAttributes.mRateOfFire;
    if (rateOfFire < 0.0f) {
      rateOfFire = weapon->mAttributes.mBlueprint->RateOfFire;
    }

    const float fireClockPct = 1.0f - (static_cast<float>(weapon->mFireWeaponTask->mFireClock) / (10.0f / rateOfFire));
    lua_pushnumber(rawState, fireClockPct);
    return 1;
  }

  /**
   * Address: 0x006DA960 (FUN_006DA960, cfunc_UnitWeaponGetFireClockPct)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetFireClockPctL`.
   */
  int cfunc_UnitWeaponGetFireClockPct(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponGetFireClockPctL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DAB60 (FUN_006DAB60, cfunc_UnitWeaponChangeProjectileBlueprintL)
   *
   * What it does:
   * Resolves a projectile blueprint id from Lua text and updates this weapon.
   */
  int cfunc_UnitWeaponChangeProjectileBlueprintL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeProjectileBlueprintHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* const blueprintText = lua_tostring(rawState, 2);
    if (blueprintText == nullptr) {
      blueprintArg.TypeError("string");
      return 0;
    }

    UpdateProjectileBlueprintFromText(weapon, blueprintText);
    return 0;
  }

  /**
   * Address: 0x006DAAE0 (FUN_006DAAE0, cfunc_UnitWeaponChangeProjectileBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeProjectileBlueprintL`.
   */
  int cfunc_UnitWeaponChangeProjectileBlueprint(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeProjectileBlueprintL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DAD00 (FUN_006DAD00, cfunc_UnitWeaponTransferTargetL)
   *
   * What it does:
   * Copies one weapon target payload onto another weapon.
   */
  int cfunc_UnitWeaponTransferTargetL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponTransferTargetHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject sourceWeaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const sourceWeapon = SCR_FromLua_UnitWeapon(sourceWeaponObject, state);

    const LuaPlus::LuaObject destinationWeaponObject(LuaPlus::LuaStackObject(state, 2));
    UnitWeapon* const destinationWeapon = SCR_FromLua_UnitWeapon(destinationWeaponObject, state);

    destinationWeapon->mTarget = sourceWeapon->mTarget;
    destinationWeapon->PickNewTargetAimSpot();
    destinationWeapon->mShotsAtTarget = 0;
    return 0;
  }

  /**
   * Address: 0x006DAC80 (FUN_006DAC80, cfunc_UnitWeaponTransferTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponTransferTargetL`.
   */
  int cfunc_UnitWeaponTransferTarget(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponTransferTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DAE70 (FUN_006DAE70, cfunc_UnitWeaponBeenDestroyedL)
   *
   * What it does:
   * Pushes true when the passed weapon handle resolves to no live object.
   */
  int cfunc_UnitWeaponBeenDestroyedL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponBeenDestroyedHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    const UnitWeapon* const weapon = SCR_FromLua_UnitWeaponOpt(weaponObject, state);
    lua_pushboolean(rawState, weapon == nullptr ? 1 : 0);
    return 1;
  }

  /**
   * Address: 0x006DADF0 (FUN_006DADF0, cfunc_UnitWeaponBeenDestroyed)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponBeenDestroyedL`.
   */
  int cfunc_UnitWeaponBeenDestroyed(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponBeenDestroyedL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D8AE0 (FUN_006D8AE0, cfunc_UnitWeaponGetBlueprintL)
   *
   * What it does:
   * Resolves a weapon from arg#1 and pushes the indexed `Weapon[]` blueprint
   * entry for that weapon.
   */
  int cfunc_UnitWeaponGetBlueprintL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponGetBlueprintHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const RUnitBlueprint* const unitBlueprint = weapon->mUnit->GetBlueprint();
    LuaPlus::LuaObject blueprintObject = unitBlueprint->GetLuaBlueprint(state);
    LuaPlus::LuaObject weaponArrayObject = blueprintObject["Weapon"];
    LuaPlus::LuaObject weaponEntryObject = weaponArrayObject[weapon->mWeaponIndex + 1];
    weaponEntryObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006D8A60 (FUN_006D8A60, cfunc_UnitWeaponGetBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponGetBlueprintL`.
   */
  int cfunc_UnitWeaponGetBlueprint(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponGetBlueprintL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D8A80 (FUN_006D8A80, func_UnitWeaponGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes `blueprint = UnitWeapon:GetBlueprint()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponGetBlueprint_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponGetBlueprintName,
      &moho::cfunc_UnitWeaponGetBlueprint,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponGetBlueprintHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D8FE0 (FUN_006D8FE0, cfunc_UnitWeaponSetFireControl)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetFireControlL`.
   */
  int cfunc_UnitWeaponSetFireControl(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetFireControlL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9000 (FUN_006D9000, func_UnitWeaponSetFireControl_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetFireControl(label)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetFireControl_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetFireControlName,
      &moho::cfunc_UnitWeaponSetFireControl,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetFireControlHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9060 (FUN_006D9060, cfunc_UnitWeaponSetFireControlL)
   *
   * What it does:
   * Resolves `(weapon, label)` and rewrites `UnitWeapon::mLabel`.
   */
  int cfunc_UnitWeaponSetFireControlL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetFireControlHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject labelArg(state, 2);
    const char* labelText = lua_tostring(rawState, 2);
    if (labelText == nullptr) {
      labelArg.TypeError("string");
      labelText = "";
    }

    weapon->mLabel = labelText;
    return 1;
  }

  /**
   * Address: 0x006D9840 (FUN_006D9840, cfunc_UnitWeaponChangeFiringToleranceL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mFiringTolerance`.
   */
  int cfunc_UnitWeaponChangeFiringToleranceL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeFiringToleranceHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    weapon->mAttributes.mFiringTolerance = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006D97C0 (FUN_006D97C0, cfunc_UnitWeaponChangeFiringTolerance)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeFiringToleranceL`.
   */
  int cfunc_UnitWeaponChangeFiringTolerance(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeFiringToleranceL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D97E0 (FUN_006D97E0, func_UnitWeaponChangeFiringTolerance_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeFiringTolerance(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeFiringTolerance_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeFiringToleranceName,
      &moho::cfunc_UnitWeaponChangeFiringTolerance,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeFiringToleranceHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D99A0 (FUN_006D99A0, cfunc_UnitWeaponChangeRateOfFireL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mRateOfFire`.
   */
  int cfunc_UnitWeaponChangeRateOfFireL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeRateOfFireHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    weapon->mAttributes.mRateOfFire = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006D9920 (FUN_006D9920, cfunc_UnitWeaponChangeRateOfFire)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeRateOfFireL`.
   */
  int cfunc_UnitWeaponChangeRateOfFire(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeRateOfFireL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9940 (FUN_006D9940, func_UnitWeaponChangeRateOfFire_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeRateOfFire(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeRateOfFire_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeRateOfFireName,
      &moho::cfunc_UnitWeaponChangeRateOfFire,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeRateOfFireHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9B00 (FUN_006D9B00, cfunc_UnitWeaponChangeMinRadiusL)
   *
   * What it does:
   * Writes min radius and cached squared radius, then marks unit focus dirty.
   */
  int cfunc_UnitWeaponChangeMinRadiusL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeMinRadiusHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    const float minRadius = static_cast<float>(lua_tonumber(rawState, 2));
    weapon->mAttributes.mMinRadius = minRadius;
    weapon->mAttributes.mMinRadiusSq = minRadius * minRadius;
    if (weapon->mUnit) {
      weapon->mUnit->NeedSyncGameData = true;
    }
    return 0;
  }

  /**
   * Address: 0x006D9A80 (FUN_006D9A80, cfunc_UnitWeaponChangeMinRadius)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeMinRadiusL`.
   */
  int cfunc_UnitWeaponChangeMinRadius(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeMinRadiusL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9AA0 (FUN_006D9AA0, func_UnitWeaponChangeMinRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeMinRadius(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeMinRadius_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeMinRadiusName,
      &moho::cfunc_UnitWeaponChangeMinRadius,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeMinRadiusHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9C80 (FUN_006D9C80, cfunc_UnitWeaponChangeMaxRadiusL)
   *
   * What it does:
   * Writes max radius and cached squared radius, then marks unit focus dirty.
   */
  int cfunc_UnitWeaponChangeMaxRadiusL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeMaxRadiusHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    const float maxRadius = static_cast<float>(lua_tonumber(rawState, 2));
    weapon->mAttributes.mMaxRadius = maxRadius;
    weapon->mAttributes.mMaxRadiusSq = maxRadius * maxRadius;
    if (weapon->mUnit) {
      weapon->mUnit->NeedSyncGameData = true;
    }
    return 0;
  }

  /**
   * Address: 0x006D9C00 (FUN_006D9C00, cfunc_UnitWeaponChangeMaxRadius)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeMaxRadiusL`.
   */
  int cfunc_UnitWeaponChangeMaxRadius(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeMaxRadiusL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9C20 (FUN_006D9C20, func_UnitWeaponChangeMaxRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeMaxRadius(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeMaxRadius_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeMaxRadiusName,
      &moho::cfunc_UnitWeaponChangeMaxRadius,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeMaxRadiusHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9E00 (FUN_006D9E00, cfunc_UnitWeaponChangeMaxHeightDiffL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mMaxHeightDiff`.
   */
  int cfunc_UnitWeaponChangeMaxHeightDiffL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeMaxHeightDiffHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    weapon->mAttributes.mMaxHeightDiff = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006D9D80 (FUN_006D9D80, cfunc_UnitWeaponChangeMaxHeightDiff)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeMaxHeightDiffL`.
   */
  int cfunc_UnitWeaponChangeMaxHeightDiff(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeMaxHeightDiffL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9DA0 (FUN_006D9DA0, func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeMaxHeightDiff(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeMaxHeightDiffName,
      &moho::cfunc_UnitWeaponChangeMaxHeightDiff,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeMaxHeightDiffHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006D9F60 (FUN_006D9F60, cfunc_UnitWeaponChangeDamageTypeL)
   *
   * What it does:
   * Resolves a weapon from arg#1 and rewrites its damage type string from arg#2.
   */
  int cfunc_UnitWeaponChangeDamageTypeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeDamageTypeHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject damageTypeArg(state, 2);
    const char* const damageTypeName = lua_tostring(rawState, 2);
    if (damageTypeName == nullptr) {
      damageTypeArg.TypeError("string");
    }

    weapon->mAttributes.SetType(msvc8::string(damageTypeName));
    return 0;
  }

  /**
   * Address: 0x006D9EE0 (FUN_006D9EE0, cfunc_UnitWeaponChangeDamageType)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeDamageTypeL`.
   */
  int cfunc_UnitWeaponChangeDamageType(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeDamageTypeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D9F00 (FUN_006D9F00, func_UnitWeaponChangeDamageType_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeDamageType(typeName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeDamageType_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeDamageTypeName,
      &moho::cfunc_UnitWeaponChangeDamageType,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeDamageTypeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA0F0 (FUN_006DA0F0, cfunc_UnitWeaponChangeDamageRadiusL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mDamageRadius`.
   */
  int cfunc_UnitWeaponChangeDamageRadiusL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeDamageRadiusHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    weapon->mAttributes.mDamageRadius = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006DA070 (FUN_006DA070, cfunc_UnitWeaponChangeDamageRadius)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponChangeDamageRadiusL`.
   */
  int cfunc_UnitWeaponChangeDamageRadius(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeDamageRadiusL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA090 (FUN_006DA090, func_UnitWeaponChangeDamageRadius_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeDamageRadius(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeDamageRadius_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeDamageRadiusName,
      &moho::cfunc_UnitWeaponChangeDamageRadius,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeDamageRadiusHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA260 (FUN_006DA260, cfunc_UnitWeaponChangeDamageL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `CWeaponAttributes::mDamage`.
   */
  int cfunc_UnitWeaponChangeDamageL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponChangeDamageHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    weapon->mAttributes.mDamage = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006DA1E0 (FUN_006DA1E0, cfunc_UnitWeaponChangeDamage)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitWeaponChangeDamageL`.
   */
  int cfunc_UnitWeaponChangeDamage(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponChangeDamageL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA200 (FUN_006DA200, func_UnitWeaponChangeDamage_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:ChangeDamage(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponChangeDamage_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponChangeDamageName,
      &moho::cfunc_UnitWeaponChangeDamage,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponChangeDamageHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA870 (FUN_006DA870, cfunc_UnitWeaponSetFiringRandomnessL)
   *
   * What it does:
   * Resolves `(weapon, value)` and writes `UnitWeapon::mFiringRandomness`.
   */
  int cfunc_UnitWeaponSetFiringRandomnessL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetFiringRandomnessHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      valueArg.TypeError("number");
    }

    weapon->mFiringRandomness = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006DA7F0 (FUN_006DA7F0, cfunc_UnitWeaponSetFiringRandomness)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetFiringRandomnessL`.
   */
  int cfunc_UnitWeaponSetFiringRandomness(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetFiringRandomnessL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA810 (FUN_006DA810, func_UnitWeaponSetFiringRandomness_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetFiringRandomness(value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetFiringRandomness_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetFiringRandomnessName,
      &moho::cfunc_UnitWeaponSetFiringRandomness,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetFiringRandomnessHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006DA3D0 (FUN_006DA3D0, cfunc_UnitWeaponSetFireTargetLayerCapsL)
   *
   * What it does:
   * Resolves `(weapon, layerName)` and writes one fire-target layer mask lane.
   */
  int cfunc_UnitWeaponSetFireTargetLayerCapsL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetFireTargetLayerCapsHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    ELayer layerMask = LAYER_None;
    gpg::RRef enumRef = MakeLayerRef(&layerMask);

    const LuaPlus::LuaStackObject layerArg(state, 2);
    const char* const layerName = lua_tostring(rawState, 2);
    if (layerName == nullptr) {
      layerArg.TypeError("string");
    }
    SCR_GetEnum(state, layerName, enumRef);

    weapon->mFireTargetLayerCaps = layerMask;
    weapon->mUnit->NeedSyncGameData = true;
    return 0;
  }

  /**
   * Address: 0x006DA350 (FUN_006DA350, cfunc_UnitWeaponSetFireTargetLayerCaps)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetFireTargetLayerCapsL`.
   */
  int cfunc_UnitWeaponSetFireTargetLayerCaps(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetFireTargetLayerCapsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006DA370 (FUN_006DA370, func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef)
   *
   * What it does:
   * Publishes `UnitWeapon:SetFireTargetLayerCaps(mask)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUnitWeaponSetFireTargetLayerCapsName,
      &moho::cfunc_UnitWeaponSetFireTargetLayerCaps,
      &CScrLuaMetatableFactory<UnitWeapon>::Instance(),
      kUnitWeaponLuaClassName,
      kUnitWeaponSetFireTargetLayerCapsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0062FD70 (FUN_0062FD70, Moho::UnitWeapon::GetLabel)
   *
   * What it does:
   * Copies this weapon label into caller-provided output string storage.
   */
  msvc8::string* UnitWeapon::GetLabel(msvc8::string* const outLabel) const
  {
    *outLabel = mLabel;
    return outLabel;
  }

  /**
   * Address: 0x006D4100 (FUN_006D4100, sub_6D4100)
   */
  UnitWeapon::UnitWeapon()
    : CScriptEvent()
    , mSim(nullptr)
    , mWeaponBlueprint(nullptr)
    , mProjectileBlueprint(nullptr)
    , mAttacker(nullptr)
    , mAttributes(nullptr)
    , mUnit(nullptr)
    , mWeaponIndex(0)
    , mBone(-1)
    , mEnabled(0u)
    , mPadAD{0u, 0u, 0u}
    , mLabel()
    , mTarget()
    , mFireWeaponTask(nullptr)
    , mCanFire(0u)
    , mPadF1ToF7{0u, 0u, 0u, 0u, 0u, 0u, 0u}
    , mCat1{}
    , mCat2{}
    , mFireTargetLayerCaps(LAYER_None)
    , mFiringRandomness(0.0f)
    , mTargetPriorities()
    , mBlacklist()
    , mUnknown170(0)
    , mUnknown174(1u)
    , mPad175To177{0u, 0u, 0u}
    , mAimingAt(GetRecoveredInvalidAimingVector())
    , mShotsAtTarget(0)
  {
    mTarget.targetType = EAiTargetType::AITARGET_None;
    mTarget.targetEntity.ownerLinkSlot = nullptr;
    mTarget.targetEntity.nextInOwner = nullptr;
    mTarget.targetPoint = -1;
    mTarget.targetIsMobile = false;

    // Default member initialization already seeds both sets.
  }

  /**
   * Address: 0x006D4A90 (FUN_006D4A90, Moho::UnitWeapon::~UnitWeapon)
   *
   * What it does:
   * Releases the owned fire-task lane before member/base teardown.
   */
  UnitWeapon::~UnitWeapon()
  {
    if (mFireWeaponTask != nullptr) {
      delete mFireWeaponTask;
      mFireWeaponTask = nullptr;
    }
  }

  /**
   * Address: 0x006D5200 (FUN_006D5200, sub_6D5200)
   *
   * What it does:
   * Computes this weapon forward vector from either owner transform or muzzle
   * bone world transform quaternion lanes.
   */
  Wm3::Vector3f UnitWeapon::GetForwardVector(const UnitWeapon* const weapon)
  {
    if (weapon == nullptr || weapon->mUnit == nullptr) {
      return Wm3::Vector3f::Zero();
    }

    Wm3::Quaternionf orientation{};
    if (weapon->mBone >= 0) {
      orientation = weapon->mUnit->GetBoneWorldTransform(weapon->mBone).orient_;
    } else {
      orientation = weapon->mUnit->GetTransform().orient_;
    }

    const float w = orientation.w;
    const float x = orientation.x;
    const float y = orientation.y;
    const float z = orientation.z;

    return Wm3::Vector3f{
      ((w * y) + (x * z)) * 2.0f,
      ((y * z) - (w * x)) * 2.0f,
      1.0f - (((x * x) + (y * y)) * 2.0f),
    };
  }

  /**
   * Address: 0x006D78C0 (FUN_006D78C0, sub_6D78C0)
   *
   * What it does:
   * Returns whether `entity` is present in weapon blacklist rows.
   */
  bool UnitWeapon::IsEntityBlacklisted(const UnitWeapon* const weapon, const Entity* const entity)
  {
    if (weapon == nullptr || entity == nullptr) {
      return false;
    }

    for (const SBlackListInfo& entry : weapon->mBlacklist) {
      if (entry.mEntity.GetObjectPtr() == entity) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x006D5720 (FUN_006D5720, Moho::UnitWeapon::CanAttackTarget)
   *
   * What it does:
   * Validates whether `weapon` can attack the current `target` payload, with
   * entity-layer/category checks and ground height-vs-water gating.
   */
  bool UnitWeapon::CanAttackTarget(CAiTarget* const target, UnitWeapon* const weapon)
  {
    const EAiTargetType targetType = target->targetType;
    if (targetType == EAiTargetType::AITARGET_None) {
      return false;
    }

    RUnitBlueprintWeapon* const weaponBlueprint = weapon->mWeaponBlueprint;
    if (weaponBlueprint->IgnoreIfDisabled != 0u && weapon->mEnabled == 0u) {
      return false;
    }

    if (targetType == EAiTargetType::AITARGET_Entity) {
      Entity* const targetEntity = target->GetEntity();
      return targetEntity != nullptr && CanWeaponAttackEntityTarget(targetEntity, weapon);
    }

    if (targetType != EAiTargetType::AITARGET_Ground) {
      return true;
    }

    if (weaponBlueprint->CannotAttackGround != 0u) {
      return false;
    }

    const Wm3::Vec3f targetPosition = target->GetTargetPosGun(false);
    STIMap* const mapData = (weapon->mUnit != nullptr && weapon->mUnit->SimulationRef != nullptr)
                              ? weapon->mUnit->SimulationRef->mMapData
                              : nullptr;
    if (mapData == nullptr || mapData->mHeightField == nullptr) {
      return false;
    }
    const float terrainElevation = mapData->mHeightField->GetElevation(targetPosition.x, targetPosition.z);
    const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

    if (terrainElevation > waterElevation) {
      return (weapon->mFireTargetLayerCaps & LAYER_Land) != 0;
    }
    if (waterElevation > terrainElevation) {
      return (weapon->mFireTargetLayerCaps & LAYER_Water) != 0;
    }

    return false;
  }

  /**
   * Address: 0x006D5DE0 (FUN_006D5DE0, Moho::UnitWeapon::PickNewTargetAimSpot)
   *
   * What it does:
   * Logs and checksums current target lanes, then picks one target-point
   * according to weapon above/below-water targeting rules.
   */
  void UnitWeapon::PickNewTargetAimSpot()
  {
    const Entity* const targetEntity = mTarget.targetEntity.GetObjectPtr();

    const char* targetEntityText = "NULL";
    msvc8::string targetEntityIdText{};
    if (targetEntity != nullptr) {
      targetEntityIdText = gpg::STR_Printf("0x%08x", static_cast<std::uint32_t>(targetEntity->id_));
      targetEntityText = targetEntityIdText.c_str();
    }

    mSim->Logf(
      "UnitWeapon::PickNewTargetAimSpot() for 0x%08x, mTarget.mEntity=%s\n",
      static_cast<std::uint32_t>(mUnit->id_),
      targetEntityText
    );

    const std::int32_t ownerUnitId = mUnit->id_;
    mSim->mContext.Update(&ownerUnitId, 4u);

    const std::int32_t targetEntityId = (targetEntity != nullptr) ? targetEntity->id_ : -1;
    mSim->mContext.Update(&targetEntityId, 4u);

    if (mTarget.targetType == EAiTargetType::AITARGET_None) {
      return;
    }

    if (mWeaponBlueprint->AboveWaterTargetsOnly != 0u) {
      if (Entity* const entity = mTarget.targetEntity.GetObjectPtr(); entity != nullptr) {
        if (Unit* const targetUnit = entity->IsUnit(); targetUnit != nullptr) {
          targetUnit->PickTargetPointAboveWater(mTarget.targetPoint);
        } else if (ReconBlip* const targetBlip = entity->IsReconBlip(); targetBlip != nullptr) {
          targetBlip->PickTargetPointAboveWater(mTarget.targetPoint);
        }
      }
      return;
    }

    if (mWeaponBlueprint->BelowWaterTargetsOnly != 0u) {
      if (Entity* const entity = mTarget.targetEntity.GetObjectPtr(); entity != nullptr) {
        if (Unit* const targetUnit = entity->IsUnit(); targetUnit != nullptr) {
          targetUnit->PickTargetPointBelowWater(mTarget.targetPoint);
        } else if (ReconBlip* const targetBlip = entity->IsReconBlip(); targetBlip != nullptr) {
          targetBlip->PickTargetPointBelowWater(mTarget.targetPoint);
        }
      }
      return;
    }

    mTarget.PickTargetPoint();
  }

  gpg::RType* UnitWeapon::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(UnitWeapon));
    }

    return sType;
  }

  /**
   * Address: 0x006DF3A0 (FUN_006DF3A0, Moho::UnitWeapon::MemberDeserialize)
   */
  void UnitWeapon::MemberDeserialize(gpg::ReadArchive& archive)
  {
    const gpg::RRef ownerRef{};

    archive.Read(CScriptEvent::StaticGetClass(), this, ownerRef);
    mSim = ReadTrackedPointer<Sim>(archive, ownerRef);
    mWeaponBlueprint = ReadTrackedPointer<RUnitBlueprintWeapon>(archive, ownerRef);
    mProjectileBlueprint = ReadTrackedPointer<RProjectileBlueprint>(archive, ownerRef);
    mAttacker = ReadTrackedPointer<IAiAttacker>(archive, ownerRef);
    archive.Read(CachedRType<CWeaponAttributes>(), &mAttributes, ownerRef);
    mUnit = ReadTrackedPointer<Unit>(archive, ownerRef);
    archive.ReadInt(&mWeaponIndex);
    archive.ReadInt(&mBone);

    bool enabled = (mEnabled != 0u);
    archive.ReadBool(&enabled);
    mEnabled = enabled ? 1u : 0u;

    archive.ReadString(&mLabel);
    archive.Read(CachedRType<CAiTarget>(), &mTarget, ownerRef);

    CFireWeaponTask* const oldTask = mFireWeaponTask;
    mFireWeaponTask = ReadTrackedPointer<CFireWeaponTask>(archive, ownerRef);
    if (oldTask) {
      delete oldTask;
    }

    bool canFire = (mCanFire != 0u);
    archive.ReadBool(&canFire);
    mCanFire = canFire ? 1u : 0u;

    archive.Read(CachedRType<EntityCategorySet>(), &mCat1, ownerRef);
    archive.Read(CachedRType<EntityCategorySet>(), &mCat2, ownerRef);
    archive.Read(CachedRType<ELayer>(), &mFireTargetLayerCaps, ownerRef);
    archive.ReadFloat(&mFiringRandomness);
    archive.Read(CachedRType<msvc8::vector<EntityCategorySet>>(), &mTargetPriorities, ownerRef);
    archive.Read(CachedRType<msvc8::vector<SBlackListInfo>>(), &mBlacklist, ownerRef);
    archive.ReadInt(&mUnknown170);

    bool unknown174 = (mUnknown174 != 0u);
    archive.ReadBool(&unknown174);
    mUnknown174 = unknown174 ? 1u : 0u;

    archive.Read(CachedRType<Wm3::Vector3f>(), &mAimingAt, ownerRef);
    archive.ReadInt(&mShotsAtTarget);
  }

  /**
   * Address: 0x006DF6E0 (FUN_006DF6E0, Moho::UnitWeapon::MemberSerialize)
   */
  void UnitWeapon::MemberSerialize(gpg::WriteArchive& archive) const
  {
    const gpg::RRef ownerRef{};

    archive.Write(CScriptEvent::StaticGetClass(), this, ownerRef);
    WriteTrackedPointer(archive, mSim, gpg::TrackedPointerState::Unowned, ownerRef);
    WriteTrackedPointer(archive, mWeaponBlueprint, gpg::TrackedPointerState::Unowned, ownerRef);
    WriteTrackedPointer(archive, mProjectileBlueprint, gpg::TrackedPointerState::Unowned, ownerRef);
    WriteTrackedPointer(archive, mAttacker, gpg::TrackedPointerState::Unowned, ownerRef);
    archive.Write(CachedRType<CWeaponAttributes>(), &mAttributes, ownerRef);
    WriteTrackedPointer(archive, mUnit, gpg::TrackedPointerState::Unowned, ownerRef);
    archive.WriteInt(mWeaponIndex);
    archive.WriteInt(mBone);
    archive.WriteBool(mEnabled != 0u);
    archive.WriteString(const_cast<msvc8::string*>(&mLabel));
    archive.Write(CachedRType<CAiTarget>(), &mTarget, ownerRef);
    WriteTrackedPointer(archive, mFireWeaponTask, gpg::TrackedPointerState::Owned, ownerRef);
    archive.WriteBool(mCanFire != 0u);
    archive.Write(CachedRType<EntityCategorySet>(), &mCat1, ownerRef);
    archive.Write(CachedRType<EntityCategorySet>(), &mCat2, ownerRef);
    archive.Write(CachedRType<ELayer>(), &mFireTargetLayerCaps, ownerRef);
    archive.WriteFloat(mFiringRandomness);
    archive.Write(CachedRType<msvc8::vector<EntityCategorySet>>(), &mTargetPriorities, ownerRef);
    archive.Write(CachedRType<msvc8::vector<SBlackListInfo>>(), &mBlacklist, ownerRef);
    archive.WriteInt(mUnknown170);
    archive.WriteBool(mUnknown174 != 0u);
    archive.Write(CachedRType<Wm3::Vector3f>(), &mAimingAt, ownerRef);
    archive.WriteInt(mShotsAtTarget);
  }
} // namespace moho
