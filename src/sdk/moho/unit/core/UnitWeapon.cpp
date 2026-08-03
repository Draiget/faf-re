#include "moho/unit/core/UnitWeapon.h"

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <intrin.h>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategorySetVectorReflection.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/serialization/SBlackListInfoVectorReflection.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/sim/CDamage.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CFireWeaponTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  /**
   * Address: 0x006DD5B0 (FUN_006DD5B0)
   *
   * What it does:
   * Returns cached `UnitWeapon` metatable object from Lua object-factory
   * storage.
   */
  [[nodiscard]] LuaPlus::LuaObject GetUnitWeaponFactory(LuaPlus::LuaState* const state)
  {
    return moho::CScrLuaMetatableFactory<moho::UnitWeapon>::Instance().Get(state);
  }

  void AttachTaskToStage(moho::CTask* const task, moho::CTaskStage* const stage)
  {
    if (task == nullptr || stage == nullptr) {
      return;
    }

    auto* const thread = new moho::CTaskThread(stage);
    task->mOwnerThread = thread;
    task->mSubtask = thread->mTaskTop;
    thread->mTaskTop = task;
  }

  /**
   * Address: 0x006DEAE0 (FUN_006DEAE0)
   *
   * What it does:
   * Unlinks each blacklist-row weak-entity lane in `[begin, end)` from its
   * owner-chain intrusive list.
   */
  void UnlinkBlacklistWeakEntityRange(
    moho::SBlackListInfo* begin,
    moho::SBlackListInfo* end
  ) noexcept
  {
    for (; begin != end; ++begin) {
      auto** ownerCursor = reinterpret_cast<moho::WeakPtr<moho::Entity>**>(begin->mEntity.ownerLinkSlot);
      if (ownerCursor == nullptr) {
        continue;
      }

      while (*ownerCursor != &begin->mEntity) {
        ownerCursor = &(*ownerCursor)->nextInOwner;
      }
      *ownerCursor = begin->mEntity.nextInOwner;
    }
  }

  /**
   * Address: 0x006DBE20 (FUN_006DBE20)
   *
   * What it does:
   * Jump-thunk alias that forwards one zero-length blacklist range
   * `[cursor, cursor)` into `FUN_006DEAE0`.
   */
  [[maybe_unused]] void UnlinkBlacklistWeakEntityRangeEmptyAtCursor(moho::SBlackListInfo* const cursor) noexcept
  {
    UnlinkBlacklistWeakEntityRange(cursor, cursor);
  }

  /**
   * Address: 0x006DBD70 (FUN_006DBD70)
   *
   * What it does:
   * Unlinks weak-owner lanes in the blacklist element range and rewinds the
   * logical vector end back to begin without releasing capacity storage.
   */
  [[nodiscard]] moho::SBlackListInfo* ResetBlacklistRangeToBegin(
    msvc8::vector<moho::SBlackListInfo>& blacklist
  ) noexcept
  {
    auto& runtime = msvc8::AsVectorRuntimeView(blacklist);
    if (runtime.begin != runtime.end) {
      UnlinkBlacklistWeakEntityRange(runtime.begin, runtime.end);
      runtime.end = runtime.begin;
    }

    return runtime.begin;
  }

  /**
   * Address: 0x006DE7E0 (FUN_006DE7E0)
   *
   * What it does:
   * Copy-assigns one contiguous blacklist range while preserving intrusive
   * weak-owner chain semantics for each copied `mEntity` lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::SBlackListInfo* CopyBlacklistRangeAssignWeakLinks(
    moho::SBlackListInfo* destination,
    const moho::SBlackListInfo* const sourceBegin,
    const moho::SBlackListInfo* const sourceEnd
  ) noexcept
  {
    const moho::SBlackListInfo* source = sourceBegin;
    while (source != sourceEnd) {
      if (destination->mEntity.ownerLinkSlot != source->mEntity.ownerLinkSlot) {
        if (destination->mEntity.ownerLinkSlot != nullptr) {
          auto** ownerCursor = reinterpret_cast<moho::WeakPtr<moho::Entity>**>(destination->mEntity.ownerLinkSlot);
          while (*ownerCursor != &destination->mEntity) {
            ownerCursor = &(*ownerCursor)->nextInOwner;
          }
          *ownerCursor = destination->mEntity.nextInOwner;
        }

        destination->mEntity.ownerLinkSlot = source->mEntity.ownerLinkSlot;
        if (source->mEntity.ownerLinkSlot == nullptr) {
          destination->mEntity.nextInOwner = nullptr;
        } else {
          auto** const sourceHead = reinterpret_cast<moho::WeakPtr<moho::Entity>**>(source->mEntity.ownerLinkSlot);
          destination->mEntity.nextInOwner = *sourceHead;
          *sourceHead = &destination->mEntity;
        }
      }

      destination->mValue = source->mValue;
      ++source;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x006DDA00 (FUN_006DDA00)
   *
   * What it does:
   * Adapts one reordered caller lane into `CopyBlacklistRangeAssignWeakLinks`
   * and returns the advanced destination cursor.
   */
  [[maybe_unused]] [[nodiscard]] moho::SBlackListInfo* CopyBlacklistRangeAssignWeakLinksBridgeRuntime(
    const moho::SBlackListInfo* const sourceEnd,
    const moho::SBlackListInfo* const sourceBegin,
    moho::SBlackListInfo* const destination
  ) noexcept
  {
    return CopyBlacklistRangeAssignWeakLinks(destination, sourceBegin, sourceEnd);
  }

  [[nodiscard]] bool AllocateBlacklistInfoStorage(
    msvc8::vector<moho::SBlackListInfo>& storage,
    const std::size_t elementCount
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (elementCount == 0u) {
      view.begin = nullptr;
      view.end = nullptr;
      view.capacityEnd = nullptr;
      return true;
    }

    if (elementCount > (static_cast<std::size_t>(-1) / sizeof(moho::SBlackListInfo))) {
      return false;
    }

    void* rawStorage = nullptr;
    try {
      rawStorage = ::operator new(sizeof(moho::SBlackListInfo) * elementCount);
    } catch (...) {
      return false;
    }

    view.begin = static_cast<moho::SBlackListInfo*>(rawStorage);
    view.end = view.begin;
    view.capacityEnd = view.begin + elementCount;
    return true;
  }

  [[nodiscard]] moho::SBlackListInfo* CopyConstructBlacklistWeakEntityRange(
    moho::SBlackListInfo* destination,
    const moho::SBlackListInfo* sourceBegin,
    const moho::SBlackListInfo* sourceEnd
  ) noexcept
  {
    auto* const destinationLane =
      reinterpret_cast<moho::WeakPtrPayloadLane<std::uint32_t>*>(destination);
    const auto* const sourceBeginLane =
      reinterpret_cast<const moho::WeakPtrPayloadLane<std::uint32_t>*>(sourceBegin);
    const auto* const sourceEndLane =
      reinterpret_cast<const moho::WeakPtrPayloadLane<std::uint32_t>*>(sourceEnd);

    auto* const writtenEndLane = moho::CopyWeakPtrDwordPayloadRange(
      destinationLane,
      sourceEndLane,
      sourceBeginLane
    );
    return reinterpret_cast<moho::SBlackListInfo*>(writtenEndLane);
  }

  /**
   * Address: 0x006DE400 (FUN_006DE400)
   *
   * What it does:
   * Assigns one `vector<SBlackListInfo>` lane with explicit weak-entity
   * relink/unlink semantics, reusing destination storage whenever capacity
   * permits and preserving intrusive owner-chain integrity.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::vector<moho::SBlackListInfo>& AssignBlacklistInfoVectorPreservingWeakLinks(
    msvc8::vector<moho::SBlackListInfo>& destination,
    const msvc8::vector<moho::SBlackListInfo>& source
  ) noexcept
  {
    if (&destination == &source) {
      return destination;
    }

    auto& destinationView = msvc8::AsVectorRuntimeView(destination);
    const auto& sourceView = msvc8::AsVectorRuntimeView(source);

    const std::size_t sourceCount =
      sourceView.begin ? static_cast<std::size_t>(sourceView.end - sourceView.begin) : 0u;
    if (sourceCount == 0u) {
      (void)ResetBlacklistRangeToBegin(destination);
      return destination;
    }

    const std::size_t currentCount =
      destinationView.begin ? static_cast<std::size_t>(destinationView.end - destinationView.begin) : 0u;
    const moho::SBlackListInfo* const sourceBegin = sourceView.begin;
    const moho::SBlackListInfo* const sourceEnd = sourceView.end;

    if (sourceCount > currentCount) {
      const std::size_t capacityCount =
        destinationView.begin ? static_cast<std::size_t>(destinationView.capacityEnd - destinationView.begin) : 0u;
      if (sourceCount <= capacityCount) {
        const moho::SBlackListInfo* const sourceTailBegin = sourceBegin + currentCount;
        (void)CopyBlacklistRangeAssignWeakLinks(destinationView.begin, sourceBegin, sourceTailBegin);
        destinationView.end = CopyConstructBlacklistWeakEntityRange(destinationView.end, sourceTailBegin, sourceEnd);
        return destination;
      }

      if (destinationView.begin != nullptr) {
        UnlinkBlacklistWeakEntityRange(destinationView.begin, destinationView.end);
        ::operator delete(destinationView.begin);
      }

      destinationView.begin = nullptr;
      destinationView.end = nullptr;
      destinationView.capacityEnd = nullptr;
      if (AllocateBlacklistInfoStorage(destination, sourceCount)) {
        destinationView.end = CopyConstructBlacklistWeakEntityRange(destinationView.begin, sourceBegin, sourceEnd);
      }
      return destination;
    }

    moho::SBlackListInfo* const assignedEnd =
      CopyBlacklistRangeAssignWeakLinks(destinationView.begin, sourceBegin, sourceEnd);
    UnlinkBlacklistWeakEntityRange(assignedEnd, destinationView.end);
    destinationView.end = destinationView.begin + sourceCount;
    return destination;
  }

  /**
   * Address: 0x006DB1E0 (FUN_006DB1E0)
   *
   * What it does:
   * Erases one blacklist row at `erasePosition` by shift-assigning the tail
   * range left, unlinking the former tail weak-owner lane, shrinking logical
   * end by one element, and returning `erasePosition` through `outPosition`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SBlackListInfo** EraseBlacklistEntryShiftLeftRuntime(
    msvc8::vector<moho::SBlackListInfo>& storage,
    moho::SBlackListInfo** const outPosition,
    moho::SBlackListInfo* const erasePosition
  ) noexcept
  {
    if (outPosition == nullptr) {
      return nullptr;
    }

    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin == nullptr || view.end == nullptr || view.end <= view.begin || erasePosition == nullptr) {
      *outPosition = erasePosition;
      return outPosition;
    }

    if (erasePosition < view.begin || erasePosition >= view.end) {
      *outPosition = erasePosition;
      return outPosition;
    }

    moho::SBlackListInfo* const readBegin = erasePosition + 1;
    if (readBegin != view.end) {
      (void)CopyBlacklistRangeAssignWeakLinks(erasePosition, readBegin, view.end);
    }

    UnlinkBlacklistWeakEntityRange(view.end - 1, view.end);
    view.end -= 1;
    *outPosition = erasePosition;
    return outPosition;
  }

  /**
   * The reflected reference is assembled from the userdata HEADER, not read out
   * of its payload. This fork carries the `gpg::RType*` in `Udata::len`, and the
   * value itself starts one header past the allocation, which is exactly what
   * `LuaPlus::LuaObject::GetUserData` (0x00907540) does:
   *
   *     lea edx, [ecx+10h]   ; mObj  = payload, laid out after the header
   *     mov ecx, [ecx+0Ch]   ; mType = Udata::len reinterpreted as RType*
   *
   * Reading `*(gpg::RRef*)lua_touserdata(...)` instead - as this helper used to -
   * takes the first eight payload bytes as if they were a reference. For a
   * `_c_object` slot those bytes are the `CScriptObject*` value followed by
   * whatever the allocator left, so every upcast failed and each caller reported
   * "Expected a game object" for a perfectly good object.
   */
  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
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

  [[nodiscard]] Wm3::Box3f BuildAxisAlignedCollisionProbe(
    const Wm3::Vec3f& center,
    const Wm3::Vec3f& extents
  ) noexcept
  {
    Wm3::Box3f probe{};
    probe.Center[0] = center.x;
    probe.Center[1] = center.y;
    probe.Center[2] = center.z;

    probe.Axis[0][0] = 1.0f;
    probe.Axis[0][1] = 0.0f;
    probe.Axis[0][2] = 0.0f;
    probe.Axis[1][0] = 0.0f;
    probe.Axis[1][1] = 1.0f;
    probe.Axis[1][2] = 0.0f;
    probe.Axis[2][0] = 0.0f;
    probe.Axis[2][1] = 0.0f;
    probe.Axis[2][2] = 1.0f;

    probe.Extent[0] = extents.x;
    probe.Extent[1] = extents.y;
    probe.Extent[2] = extents.z;
    return probe;
  }

  [[nodiscard]] moho::ESolutionStatus EvaluateTargetSolutionStatusGun(
    moho::UnitWeapon* const weapon,
    const Wm3::Vec3f& targetPosition,
    float* const inOutDistanceSq
  )
  {
    if (weapon == nullptr || weapon->mUnit == nullptr) {
      return moho::ESolutionStatus::TRS_NoSolution;
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
      return moho::ESolutionStatus::TRS_OutsideMaxRange;
    }
    if (distanceSq <= weapon->mAttributes.mMinRadiusSq) {
      return moho::ESolutionStatus::TRS_InsideMinRange;
    }

    float maxHeightDiff = weapon->mAttributes.mMaxHeightDiff;
    if (maxHeightDiff < 0.0f && weapon->mAttributes.mBlueprint != nullptr) {
      maxHeightDiff = weapon->mAttributes.mBlueprint->MaxHeightDiff;
    }
    const float heightDiff = std::fabs(targetPosition.y - weapon->mUnit->GetPosition().y);
    if (heightDiff > maxHeightDiff) {
      return moho::ESolutionStatus::TRS_OutsideMaxRange;
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
      const float headingDelta = moho::NormalizeAngleSignedRadians(targetHeading - unitHeading - headingArcCenter);
      if (std::fabs(headingDelta) > headingArcRange) {
        return moho::ESolutionStatus::TRS_NoSolution;
      }
    }

    if (inOutDistanceSq != nullptr) {
      *inOutDistanceSq = distanceSq;
    }

    return moho::ESolutionStatus::TRS_Available;
  }

  constexpr float kBombDropHeadingDotThreshold = 0.866f;
  constexpr std::uint32_t kBombDropInnerCircleDepth = 0xFFFF7F3Fu;
  constexpr std::uint32_t kBombDropOuterCircleDepth = 0xFF7F3F00u;

  [[nodiscard]] bool ShouldRenderBombDropZone(moho::Sim* const sim)
  {
    static moho::TSimConVar<bool> sAiRenderBombDropZone(false, "AI_RenderBombDropZone", false);

    moho::CSimConVarInstanceBase* const instance = sim ? sim->GetSimVar(&sAiRenderBombDropZone) : nullptr;
    const void* const valueStorage = instance ? instance->GetValueStorage() : nullptr;
    return valueStorage != nullptr && *static_cast<const bool*>(valueStorage);
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
   * Address: 0x005562C0 (FUN_005562C0, category end-iterator lane helper)
   *
   * What it does:
   * Builds one legacy `EntityCategoryIterator` end lane from raw category-set
   * storage (`firstWordIndex + wordCount`, then `* 32`) without extra guards.
   */
  [[maybe_unused]] [[nodiscard]] moho::EntityCategoryIterator* BuildCategoryEndIteratorLaneUnchecked(
    moho::EntityCategoryIterator* const out,
    moho::EntityCategorySet* const categorySet
  ) noexcept
  {
    moho::BVIntSet* const bits = &categorySet->mBits;
    const std::uintptr_t wordBegin = reinterpret_cast<std::uintptr_t>(bits->mWords.start_);
    const std::uintptr_t wordEnd = reinterpret_cast<std::uintptr_t>(bits->mWords.end_);
    const std::uint32_t wordCount = static_cast<std::uint32_t>((wordEnd - wordBegin) >> 2u);
    const std::uint32_t endWordIndex = bits->mFirstWordIndex + wordCount;

    out->mWordUniverseHandle = categorySet->mUniverse.mWordUniverseHandle;
    out->mSet = bits;
    out->mCurBit = static_cast<std::int32_t>(endWordIndex << 5u);
    return out;
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
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
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

  struct UnitWeaponProjectileVelocityRuntimeView
  {
    std::uint8_t mUnknown0000[0x280];
    Wm3::Vector3f mVelocity; // +0x280
  };

  static_assert(
    offsetof(UnitWeaponProjectileVelocityRuntimeView, mVelocity) == 0x280,
    "UnitWeaponProjectileVelocityRuntimeView::mVelocity offset must be 0x280"
  );

  [[nodiscard]] Wm3::Vector3f& AccessProjectileVelocity(moho::Projectile& projectile) noexcept
  {
    return reinterpret_cast<UnitWeaponProjectileVelocityRuntimeView*>(&projectile)->mVelocity;
  }

} // namespace

namespace moho
{
  gpg::RType* UnitWeapon::sType = nullptr;
  gpg::RType* UnitWeapon::sPointerType = nullptr;

  /**
   * Address: 0x006D5590 (FUN_006D5590, func_PickTargetPoint)
   *
   * Public entry point onto the recovered `CanWeaponAttackEntityTarget` body
   * (file-static in this TU), so out-of-TU callers can invoke FUN_006D5590 by
   * name.
   */
  bool WeaponCanAttackEntityTarget(Entity* const targetEntity, UnitWeapon* const weapon)
  {
    return CanWeaponAttackEntityTarget(targetEntity, weapon);
  }

  /**
   * Address: 0x006DBD70 (FUN_006DBD70)
   *
   * Public entry point onto the recovered `ResetBlacklistRangeToBegin` body
   * (file-static in this TU), so out-of-TU callers can clear a weapon's target
   * blacklist by name.
   */
  void WeaponResetBlacklist(UnitWeapon& weapon)
  {
    (void)ResetBlacklistRangeToBegin(weapon.mBlacklist);
  }

  // Callback bodies are recovered in adjacent lanes; publishers are required
  // here so startup thunk registration resolves to source-defined binders.
  int cfunc_UnitWeaponSetTargetEntity(lua_State* luaContext);
  int cfunc_UnitWeaponSetTargetEntityL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponSetTargetGround(lua_State* luaContext);
  int cfunc_UnitWeaponSetTargetGroundL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponResetTarget(lua_State* luaContext);
  int cfunc_UnitWeaponResetTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponCreateProjectile(lua_State* luaContext);
  int cfunc_UnitWeaponCreateProjectileL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponDoInstaHit(lua_State* luaContext);
  int cfunc_UnitWeaponDoInstaHitL(LuaPlus::LuaState* state);
  int cfunc_UnitWeaponGetProjectileBlueprint(lua_State* luaContext);
  int cfunc_UnitWeaponHasTarget(lua_State* luaContext);
  int cfunc_UnitWeaponFireWeapon(lua_State* luaContext);
  int cfunc_UnitWeaponFireWeaponL(LuaPlus::LuaState* state);
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
   * Address: 0x006D7F00 (FUN_006D7F00, cfunc_UnitWeaponSetTargetEntity)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetTargetEntityL`.
   */
  int cfunc_UnitWeaponSetTargetEntity(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetTargetEntityL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D7F80 (FUN_006D7F80, cfunc_UnitWeaponSetTargetEntityL)
   *
   * What it does:
   * Resolves `(weapon, unitTarget)`, validates entity-targeting gates, and
   * applies one recovered target transition when targeting is allowed.
   */
  int cfunc_UnitWeaponSetTargetEntityL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetTargetEntityHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Unit* const targetUnit = SCR_FromLua_Unit(targetObject);
    Entity* const targetEntity = (targetUnit != nullptr) ? static_cast<Entity*>(targetUnit) : nullptr;
    if (CanWeaponAttackEntityTarget(targetEntity, weapon)) {
      CAiTarget target{};
      (void)target.UpdateTarget(targetEntity);
      weapon->SetTarget(&target);
    }

    return 0;
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
   * Address: 0x006D80C0 (FUN_006D80C0, cfunc_UnitWeaponSetTargetGround)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponSetTargetGroundL`.
   */
  int cfunc_UnitWeaponSetTargetGround(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponSetTargetGroundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D8140 (FUN_006D8140, cfunc_UnitWeaponSetTargetGroundL)
   *
   * What it does:
   * Resolves `(weapon, position)`, validates ground-targeting gates, and
   * applies one recovered target transition when targeting is allowed.
   */
  int cfunc_UnitWeaponSetTargetGroundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponSetTargetGroundHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vector3f location = SCR_FromLuaCopy<Wm3::Vector3f>(locationObject);

    CAiTarget groundTarget{};
    groundTarget.position = location;
    groundTarget.targetType = EAiTargetType::AITARGET_Ground;
    groundTarget.targetEntity.ClearLinkState();
    groundTarget.targetPoint = -1;
    groundTarget.targetIsMobile = false;

    if (UnitWeapon::CanAttackTarget(&groundTarget, weapon)) {
      weapon->SetTarget(&groundTarget);
    }

    return 0;
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
   * Address: 0x006D8610 (FUN_006D8610, cfunc_UnitWeaponDoInstaHit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponDoInstaHitL`.
   */
  int cfunc_UnitWeaponDoInstaHit(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponDoInstaHitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D8690 (FUN_006D8690, cfunc_UnitWeaponDoInstaHitL)
   *
   * What it does:
   * Validates Lua insta-hit argument lanes and resolves typed inputs for the
   * deferred `UnitWeapon::DoInstaHit` recovery path.
   */
  int cfunc_UnitWeaponDoInstaHitL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 9) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponDoInstaHitHelpText, 9, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);
    Entity* const ownerEntity = (weapon->mUnit != nullptr) ? static_cast<Entity*>(weapon->mUnit) : nullptr;

    LuaPlus::LuaStackObject boneArg(state, 2);
    const std::int32_t boneIndex = ENTSCR_ResolveBoneIndex(ownerEntity, boneArg, false);

    LuaPlus::LuaStackObject redArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      redArg.TypeError("number");
    }
    LuaPlus::LuaStackObject greenArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      greenArg.TypeError("number");
    }
    LuaPlus::LuaStackObject blueArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      blueArg.TypeError("number");
    }
    LuaPlus::LuaStackObject glowArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      glowArg.TypeError("number");
    }
    LuaPlus::LuaStackObject widthArg(state, 7);
    if (lua_type(rawState, 7) != LUA_TNUMBER) {
      widthArg.TypeError("number");
    }
    LuaPlus::LuaStackObject textureArg(state, 8);
    const char* textureName = lua_tostring(rawState, 8);
    if (textureName == nullptr) {
      textureArg.TypeError("string");
      textureName = "";
    }
    // Resolve the texture sheet handle up front; the binary (FUN_006D8690 0x006D88EC:
    // D3D_GetDevice()->GetResources()->GetTexture(...allowFallback=true)) owns the
    // handle across the DoInstaHit call. DoInstaHit hardcodes the beam texture and
    // never dereferences the handle -- it just keeps it alive, then releases it.
    ID3DDeviceResources::TextureResourceHandle textureSheet{};
    D3D_GetDevice()->GetResources()->GetTexture(textureSheet, textureName, 0, true);

    LuaPlus::LuaStackObject lifetimeArg(state, 9);
    if (lua_type(rawState, 9) != LUA_TNUMBER) {
      lifetimeArg.TypeError("number");
    }

    const Wm3::Quaternionf colorAndGlow{
      static_cast<float>(lua_tonumber(rawState, 6)),
      static_cast<float>(lua_tonumber(rawState, 3)),
      static_cast<float>(lua_tonumber(rawState, 4)),
      static_cast<float>(lua_tonumber(rawState, 5))
    };
    const float beamWidth = static_cast<float>(lua_tonumber(rawState, 7));

    // Beam lifetime = seconds * 10 (ticks), floored at 1 tick (binary FUN_006D8690
    // 0x006D8975 mulss *10.0, 0x006D8980 comiss vs 1.0).
    const float scaledLifetime = static_cast<float>(lua_tonumber(rawState, 9)) * 10.0f;
    const float beamLifetime = (scaledLifetime <= 1.0f) ? 1.0f : scaledLifetime;

    weapon->DoInstaHit(colorAndGlow, boneIndex, beamWidth, beamLifetime, textureSheet);
    return 0;
  }

  /**
   * Address: 0x006D7300 (FUN_006D7300)
   *
   * What it does:
   * Applies one insta-hit's impact. If the beam struck a projectile, detonate it
   * (Projectile::Impact); otherwise deal direct CDamage (instigator = firing unit,
   * target = struck entity, amount = weapon damage, origin/vector from world
   * positions) via SIM_Damage. Then, for realtime-stats-enabled units with a bound
   * target, bump the army "RealTimeStats_<unit>_Shots_Hit"/"_Shots_Missed" int stat.
   */
  void ApplyInstaHitDamageAndTrackShot(CollisionBeamHelper& helper, UnitWeapon& weapon)
  {
    Unit* const firingUnit = weapon.mUnit;

    // helper.mEntity is the entity the beam actually struck this pass; HasValue()
    // folds the null / sentinel(==0x04) test.
    if (helper.mEntity.HasValue()) {
      Entity* const impactEntity = helper.mEntity.GetObjectPtr();
      if (Projectile* const impactProjectile =
            (impactEntity != nullptr) ? impactEntity->IsProjectile() : nullptr;
          impactProjectile != nullptr) {
        impactProjectile->Impact();
      } else {
        CDamage damage(firingUnit->SimulationRef);
        damage.mTarget.ResetFromOwnerLinkSlot(helper.mEntity.ownerLinkSlot);
        damage.mInstigator.Set(static_cast<Entity*>(firingUnit));
        damage.mAmount = weapon.mAttributes.GetDamage();
        damage.mType.assign(weapon.mAttributes.GetName(), 0, msvc8::string::npos);
        const Wm3::Vec3f& firingPosition = firingUnit->GetPosition();
        const Wm3::Vec3f& impactPosition = impactEntity->Position;
        damage.mVector.x = firingPosition.x - impactPosition.x;
        damage.mVector.y = firingPosition.y - impactPosition.y;
        damage.mVector.z = firingPosition.z - impactPosition.z;
        damage.mOrigin = firingPosition;
        SIM_Damage(firingUnit->SimulationRef, damage);
      }
    }

    if (firingUnit == nullptr || !firingUnit->RealtimeStatsEnabled) {
      return;
    }
    if (!weapon.mTarget.targetEntity.HasValue()) {
      return;
    }

    CArmyStats* const armyStats = firingUnit->ArmyRef->GetArmyStats();
    const bool impactResolved = helper.mEntity.HasValue();
    const msvc8::string statPath = msvc8::string("RealTimeStats_") + firingUnit->GetUniqueName()
      + (impactResolved ? "_Shots_Hit" : "_Shots_Missed");
    CArmyStatItem* const shotItem = armyStats->GetItem(statPath.c_str());
    shotItem->SynchronizeAsInt();
    (void)_InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&shotItem->mPrimaryValueBits), 1);
  }

  /**
   * Address: 0x006D75D0 (FUN_006D75D0, Moho::UnitWeapon::DoInstaHit)
   *
   * What it does:
   * Fires one instant-hit beam from `bone`: resolves the collision result, applies
   * impact damage / shot-tracking, then spawns a one-shot white beam from the bone
   * world position to the collision point. `colorAndGlow` is the packed Lua
   * color+glow quaternion ({w=glow, x=r, y=g, z=b}), copied into the beam spawn
   * orientation. The texture is hardcoded to /textures/particles/beam_white_01.dds;
   * the caller's looked-up textureSheet handle is unused beyond its owned lifetime,
   * matching the binary keeping then releasing it.
   */
  void UnitWeapon::DoInstaHit(
    const Wm3::Quaternionf& colorAndGlow,
    std::int32_t bone,
    float thickness,
    float lifetime,
    boost::shared_ptr<RD3DTextureResource> textureSheet)
  {
    (void)textureSheet; // Owned handle intentionally unused (see doc block).

    CollisionBeamHelper helper;
    CreateCollisionBeamHelper(&helper, bone);
    ApplyInstaHitDamageAndTrackShot(helper, *this);

    const VTransform boneTransform = mUnit->GetBoneWorldTransform(bone);

    SCreateBeamParams beamParams;
    beamParams.mStart = boneTransform.pos_;
    beamParams.mEnd = helper.mPos;
    beamParams.mLifetime = lifetime;
    beamParams.mWidth = thickness;
    beamParams.mTexture = "/textures/particles/beam_white_01.dds";
    beamParams.mSpawnTransform.mOrientation = {
      colorAndGlow.w,
      colorAndGlow.x,
      colorAndGlow.y,
      colorAndGlow.z,
    };

    mSim->mEffectManager->CreateBeam(beamParams);
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
   * Address: 0x006D8EB0 (FUN_006D8EB0, cfunc_UnitWeaponFireWeapon)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UnitWeaponFireWeaponL`.
   */
  int cfunc_UnitWeaponFireWeapon(lua_State* const luaContext)
  {
    return cfunc_UnitWeaponFireWeaponL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006D8F30 (FUN_006D8F30, cfunc_UnitWeaponFireWeaponL)
   *
   * What it does:
   * Resolves one weapon from Lua and dispatches one manual fire script lane.
   */
  int cfunc_UnitWeaponFireWeaponL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitWeaponFireWeaponHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, 1));
    UnitWeapon* const weapon = SCR_FromLua_UnitWeapon(weaponObject, state);
    if (weapon != nullptr) {
      (void)weapon->RunScript("OnFire");
      ++weapon->mShotsAtTarget;
    }
    return 0;
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

    bool canFire = false;
    if (weapon != nullptr
        && weapon->mTarget.HasTarget()
        && UnitWeapon::CanFire(weapon, &weapon->mTarget)
        && weapon->CheckSilo()) {
      const Wm3::Vec3f targetPosition = weapon->mTarget.GetTargetPosGun(true);
      canFire = weapon->TargetSolutionStatusGun(&targetPosition, nullptr) == ESolutionStatus::TRS_Available;
    }

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
      // Route per-T push_back through the canonical helper (FUN_006DB010)
      // so the MSVC8 vector<EntityCategorySet>::push_back template emission
      // symbol shape is preserved.
      moho::PushBackEntityCategorySetVector(weapon->mTargetPriorities, *categorySet);
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

    weapon->ChangeProjectileBlueprint(msvc8::string(blueprintText));
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

    weapon->SetFiringRandomness(static_cast<float>(lua_tonumber(rawState, 2)));
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

    weapon->SetFireTargetLayerCaps(layerMask);
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
   * Address: 0x006A4C70 (FUN_006A4C70, Moho::UnitWeapon::GetCat1)
   *
   * What it does:
   * Copies this weapon primary target category set into caller-provided
   * output storage.
   */
  EntityCategorySet* UnitWeapon::GetCat1(EntityCategorySet* const outCategory) const
  {
    *outCategory = mCat1;
    return outCategory;
  }

  /**
   * Address: 0x006A4CA0 (FUN_006A4CA0, Moho::UnitWeapon::GetCat2)
   *
   * What it does:
   * Copies this weapon secondary target category set into caller-provided
   * output storage.
   */
  EntityCategorySet* UnitWeapon::GetCat2(EntityCategorySet* const outCategory) const
  {
    *outCategory = mCat2;
    return outCategory;
  }

  /**
   * Address: 0x006A4C60 (FUN_006A4C60, Moho::UnitWeapon::GetBone)
   *
   * What it does:
   * Returns the configured muzzle/bone index lane.
   */
  std::int32_t UnitWeapon::GetBone() const
  {
    return mBone;
  }

  /**
   * Address: 0x006D53C0 (FUN_006D53C0, Moho::UnitWeapon::ChangeProjectileBlueprint)
   *
   * What it does:
   * Resolves one projectile blueprint id text into a projectile blueprint
   * resource and updates this weapon's silo-dependent projectile lane.
   */
  void UnitWeapon::ChangeProjectileBlueprint(const msvc8::string& blueprint)
  {
    if (blueprint.empty()) {
      return;
    }

    UpdateProjectileBlueprintFromText(this, blueprint.c_str());
  }

  /**
   * Address: 0x006D61E0 (FUN_006D61E0)
   *
   * What it does:
   * Dispatches the weapon script callback lane `OnGotTarget`.
   */
  void UnitWeapon::NotifyOnGotTarget()
  {
    (void)RunScript("OnGotTarget");
  }

  /**
   * Address: 0x006D5330 (FUN_006D5330, Moho::UnitWeapon::GetTransform)
   *
   * What it does:
   * Writes this weapon world position into caller-provided output storage,
   * using muzzle-bone transform when a valid muzzle bone is configured.
   */
  Wm3::Vector3f* UnitWeapon::GetTransform(Wm3::Vector3f* const outPosition) const
  {
    VTransform transform{};
    const VTransform* source = nullptr;
    if (mBone >= 0) {
      transform = mUnit->GetBoneWorldTransform(mBone);
      source = &transform;
    } else {
      source = &mUnit->GetTransform();
    }

    *outPosition = source->pos_;
    return outPosition;
  }

  /**
   * Address: 0x006D4100 (FUN_006D4100, sub_6D4100)
   */
  UnitWeapon::UnitWeapon()
    : CScriptEvent(LuaPlus::LuaObject{})
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
   * Address: 0x006D4310 (FUN_006D4310, Moho::UnitWeapon::UnitWeapon)
   *
   * What it does:
   * Binds this weapon to one attacker/blueprint lane, allocates and stages
   * the fire task thread, creates script-object state, and applies parsed
   * category restrictions from weapon blueprint text lanes.
   */
  UnitWeapon::UnitWeapon(
    CAiAttackerImpl* const attackerImpl,
    RUnitBlueprintWeapon* const weaponBlueprint,
    const int weaponIndex
  )
    : CScriptEvent(LuaPlus::LuaObject{})
    , mSim(attackerImpl->GetUnit()->SimulationRef)
    , mWeaponBlueprint(weaponBlueprint)
    , mProjectileBlueprint(nullptr)
    , mAttacker(reinterpret_cast<IAiAttacker*>(attackerImpl))
    , mAttributes(weaponBlueprint)
    , mUnit(attackerImpl->GetUnit())
    , mWeaponIndex(weaponIndex)
    , mBone(-1)
    , mEnabled(1u)
    , mPadAD{0u, 0u, 0u}
    , mLabel("Default")
    , mTarget()
    , mFireWeaponTask(nullptr)
    , mCanFire(1u)
    , mPadF1ToF7{0u, 0u, 0u, 0u, 0u, 0u, 0u}
    , mCat1{}
    , mCat2{}
    , mFireTargetLayerCaps(LAYER_None)
    , mFiringRandomness(weaponBlueprint->FiringRandomness)
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

    const std::uint32_t categoryUniverseBits =
      static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(mSim->mRules));
    mCat1.ResetToEmpty(categoryUniverseBits);
    mCat2.ResetToEmpty(categoryUniverseBits);

    if (!mWeaponBlueprint->ProjectileId.name.empty()) {
      mProjectileBlueprint = mSim->mRules->GetProjectileBlueprint(mWeaponBlueprint->ProjectileId);
    }

    mFireWeaponTask = new CFireWeaponTask(this);
    AttachTaskToStage(mFireWeaponTask, attackerImpl->GetTaskStage());

    CreateInstance();
    (void)ResetBlacklistRangeToBegin(mBlacklist);
    (void)RunScript("OnCreate");

    if (!mWeaponBlueprint->TargetRestrictDisallow.empty()) {
      mCat1 = mSim->mRules->ParseEntityCategory(mWeaponBlueprint->TargetRestrictDisallow.c_str());
      mUnit->NeedSyncGameData = true;
    }

    if (!mWeaponBlueprint->TargetRestrictOnlyAllow.empty()) {
      mCat2 = mSim->mRules->ParseEntityCategory(mWeaponBlueprint->TargetRestrictOnlyAllow.c_str());
      mUnit->NeedSyncGameData = true;
    }
  }

  /**
   * Address: 0x006D4740 (FUN_006D4740, Moho::UnitWeapon::CreateInstance)
   *
   * What it does:
   * Resolves weapon script class from blueprint label/index and binds one Lua
   * script instance for this weapon object.
   */
  void UnitWeapon::CreateInstance()
  {
    const LuaPlus::LuaObject unitLuaObject = mUnit->GetLuaObject();
    LuaPlus::LuaState* const state = unitLuaObject.GetActiveState();
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject weaponBlueprintClass{};
    if (!mWeaponBlueprint->Label.empty()) {
      weaponBlueprintClass.AssignString(state, mWeaponBlueprint->Label.c_str());
    } else {
      weaponBlueprintClass.AssignInteger(state, mWeaponIndex);
    }

    LuaPlus::LuaObject scriptClass = mUnit->GetWeaponClass(weaponBlueprintClass);
    if (!scriptClass) {
      const msvc8::string classNameText =
        !mWeaponBlueprint->Label.empty() ? gpg::STR_Printf("\"%s\"", mWeaponBlueprint->Label.c_str())
                                         : gpg::STR_Printf("%d", mWeaponIndex);

      const RUnitBlueprint* const ownerBlueprint = mUnit->GetBlueprint();
      gpg::Logf(
        "%s:GetWeaponClass(%s) returned nil, falling back to Weapon",
        ownerBlueprint ? ownerBlueprint->mBlueprintId.c_str() : "<unknown>",
        classNameText.c_str()
      );

      LuaPlus::LuaObject weaponModule = SCR_Import(state, "/lua/sim/Weapon.lua");
      if (!weaponModule.IsNil()) {
        LuaPlus::LuaObject weaponClass = weaponModule.GetByName("Weapon");
        if (!weaponClass.IsNil()) {
          scriptClass = weaponClass;
        }
      }

      if (scriptClass.IsNil()) {
        gpg::Logf(" can't find Weapon, using UnitWeapon directly");
        scriptClass = GetUnitWeaponFactory(state);
      }
    }

    LuaPlus::LuaObject nilArg1{};
    LuaPlus::LuaObject nilArg2{};
    CreateLuaObject(scriptClass, unitLuaObject, nilArg1, nilArg2);
  }

  /**
   * Address: 0x006DBB50 (FUN_006DBB50, std::vector<EntityCategorySet>::erase range lane)
   *
   * IDA signature:
   * _DWORD *__userpurge sub_6DBB50@<eax>(int a1@<edi>, _DWORD *a2, int a3, int a4);
   *
   * What it does:
   * Erases the half-open range `[rangeBegin, rangeEnd)` from the weapon's
   * targeting-priorities vector lane by copying the surviving tail entries
   * down over the erased window, unlinking any weak-link state held by the
   * displaced entries, then shrinking the active end cursor. The result
   * iterator is written to `*outIterator` and returned, matching the
   * binary's tail-call shape used by the MSVC8 `std::vector::erase` range
   * overload instantiation for `EntityCategorySet`.
   */
  EntityCategorySet* EraseTargetPrioritiesRange(
    UnitWeapon& weapon,
    EntityCategorySet** const outIterator,
    EntityCategorySet* const rangeBegin,
    EntityCategorySet* const rangeEnd
  )
  {
    auto& priorities = weapon.mTargetPriorities;
    if (rangeBegin != rangeEnd) {
      EntityCategorySet* const liveEnd = priorities.data() + priorities.size();
      // Shift `[rangeEnd, liveEnd)` down to `rangeBegin` using the MSVC8
      // move-copy helper (`std::copy` on trivially-copyable lane). The
      // resulting `newEnd` is the new logical end of the vector after the
      // range has been erased.
      EntityCategorySet* const newEnd = std::copy(rangeEnd, liveEnd, rangeBegin);

      // Shrink the active size lane to the new end. `msvc8::vector::resize`
      // runs `~EntityCategorySet` on every slot in `[newEnd, liveEnd)`,
      // mirroring the MSVC8 destructor dispatch that FUN_006DBB50 delegated
      // to `sub_6DEB80`.
      priorities.resize(static_cast<std::size_t>(newEnd - priorities.data()));
    }

    if (outIterator != nullptr) {
      *outIterator = rangeBegin;
    }
    return rangeBegin;
  }

  /**
   * Address: 0x006D4A90 (FUN_006D4A90, Moho::UnitWeapon::~UnitWeapon)
   *
   * What it does:
   * Releases the owned fire-task lane and clears the target-priorities
   * vector lane via the recovered range-erase helper before member/base
   * teardown finishes the remaining containers.
   */
  UnitWeapon::~UnitWeapon()
  {
    if (mFireWeaponTask != nullptr) {
      delete mFireWeaponTask;
      mFireWeaponTask = nullptr;
    }

    if (!mTargetPriorities.empty()) {
      EntityCategorySet* eraseResult = nullptr;
      (void)EraseTargetPrioritiesRange(
        *this, &eraseResult, mTargetPriorities.data(), mTargetPriorities.data() + mTargetPriorities.size());
    }

    // Unlink each blacklist entry's mEntity WeakPtr from its owner chain before
    // the msvc8::vector<SBlackListInfo> member destructor frees the storage
    // (binary sub_6DBD70 at 0x006D4AA4). SBlackListInfo has no destructor and
    // WeakPtr<Entity>::~WeakPtr is trivial, so the member vector teardown would
    // leave every blacklisted entity's weak node dangling in its owner chain
    // -> use-after-free when that entity later walks or tears down the chain.
    (void)ResetBlacklistRangeToBegin(mBlacklist);
  }

  /**
   * Address: 0x006D4C80 (FUN_006D4C80, Moho::UnitWeapon::CanFire)
   *
   * What it does:
   * Evaluates one weapon-owner fire gate lane (state, movement, water level,
   * bomb-drop release timing, and heading constraints) for one target payload.
   */
  bool UnitWeapon::CanFire(UnitWeapon* const weapon, CAiTarget* const targetData)
  {
    if (weapon == nullptr || weapon->mUnit == nullptr || weapon->mWeaponBlueprint == nullptr) {
      return false;
    }

    Unit* const ownerUnit = weapon->mUnit;
    const RUnitBlueprint* const unitBlueprint = ownerUnit->GetBlueprint();
    if (unitBlueprint == nullptr) {
      return false;
    }

    if (ownerUnit->VarDat().mStunTicks != 0
        || ownerUnit->IsUnitState(UNITSTATE_Busy)
        || (unitBlueprint->Air.CanFly != 0u && ownerUnit->mCurrentLayer != LAYER_Air)) {
      return false;
    }

    if (unitBlueprint->AI.NeedUnpack != 0u && !ownerUnit->IsUnitState(UNITSTATE_Immobile)) {
      return false;
    }

    const RUnitBlueprintWeapon* const weaponBlueprint = weapon->mWeaponBlueprint;
    if (weaponBlueprint->AboveWaterFireOnly != 0u || weaponBlueprint->BelowWaterFireOnly != 0u) {
      const STIMap* const mapData = (ownerUnit->SimulationRef != nullptr) ? ownerUnit->SimulationRef->mMapData : nullptr;
      const float waterElevation = (mapData != nullptr && mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

      Wm3::Vec3f muzzlePosition{};
      weapon->GetTransform(&muzzlePosition);
      const bool isAboveWater = muzzlePosition.y > waterElevation;

      if (weaponBlueprint->AboveWaterFireOnly != 0u && !isAboveWater) {
        return false;
      }
      if (weaponBlueprint->BelowWaterFireOnly != 0u && isAboveWater) {
        return false;
      }
    }

    if (unitBlueprint->Air.Winged == 0u) {
      return weapon->mCanFire != 0u;
    }

    if (weaponBlueprint->AutoInitiateAttackCommand != 0u) {
      const Wm3::Vec3f velocity = ownerUnit->GetVelocity();
      const float velocityMagnitude =
        std::sqrt((velocity.x * velocity.x) + (velocity.y * velocity.y) + (velocity.z * velocity.z));
      const float velocityLane = velocityMagnitude * 10.0f;
      const float speedGate = ownerUnit->GetAttributes().moveSpeedMult * unitBlueprint->Air.MaxAirspeed * 0.25f;
      if (speedGate > velocityLane) {
        return false;
      }
    }

    if (weaponBlueprint->NeedToComputeBombDrop == 0u || targetData == nullptr || !targetData->HasTarget()) {
      return weapon->mCanFire != 0u;
    }

    if (!ownerUnit->IsUnitState(UNITSTATE_MakingAttackRun)) {
      return false;
    }

    Wm3::Vec3f targetPosition = targetData->GetTargetPosGun(false);
    if (unitBlueprint->Air.PredictAheadForBombDrop > 0.0f && targetData->targetIsMobile) {
      if (Entity* const targetEntity = targetData->GetEntity(); targetEntity != nullptr) {
        if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
          Wm3::Vec3f predictedTargetPosition{};
          targetUnit->PredictAheadBomb(&predictedTargetPosition, unitBlueprint->Air.PredictAheadForBombDrop);
          targetPosition = predictedTargetPosition;
        }
      }
    }

    Wm3::Vec3f bombDropPosition{};
    ownerUnit->CalcBombDrop(&bombDropPosition, targetPosition);
    if (!moho::IsValidVector3f(bombDropPosition)) {
      return false;
    }

    const Wm3::Vec3f& unitPosition = ownerUnit->GetPosition();
    const float bombDx = bombDropPosition.x - unitPosition.x;
    const float bombDz = bombDropPosition.z - unitPosition.z;
    const float bombDropDistance = std::sqrt((bombDx * bombDx) + (bombDz * bombDz));

    if (ShouldRenderBombDropZone(ownerUnit->SimulationRef)) {
      if (CDebugCanvas* const debugCanvas = ownerUnit->SimulationRef->GetDebugCanvas(); debugCanvas != nullptr) {
        const Wm3::Vec3f upAxis{0.0f, 1.0f, 0.0f};
        debugCanvas->AddWireCircle(upAxis, bombDropPosition, bombDropDistance, kBombDropInnerCircleDepth, 6u);
        debugCanvas->AddWireCircle(upAxis, bombDropPosition, bombDropDistance * 2.0f, kBombDropOuterCircleDepth, 6u);
      }
    }

    const float bombDropThreshold = weaponBlueprint->BombDropThreshold;
    if (bombDropThreshold >= bombDropDistance * 2.0f) {
      return false;
    }
    if (bombDropThreshold < bombDropDistance) {
      return weapon->mCanFire != 0u;
    }

    const Wm3::Vec3f forward = ownerUnit->GetTransform().orient_.Rotate(Wm3::Vec3f{0.0f, 0.0f, 1.0f});
    const float releaseDot = ((bombDropPosition.z - unitPosition.z) * forward.z) + ((bombDropPosition.x - unitPosition.x) * forward.x);
    if (releaseDot > 0.0f) {
      return false;
    }

    const float targetDot = ((targetPosition.z - unitPosition.z) * forward.z) + ((targetPosition.x - unitPosition.x) * forward.x);
    if (targetDot < kBombDropHeadingDotThreshold) {
      return false;
    }

    return weapon->mCanFire != 0u;
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
   * Address: 0x006D5500 (FUN_006D5500, Moho::UnitWeapon::CheckSilo)
   *
   * What it does:
   * Returns true when this weapon does not require counted-projectile silo
   * storage, or when required silo storage is currently available.
   */
  bool UnitWeapon::CheckSilo()
  {
    if (mWeaponBlueprint == nullptr || mWeaponBlueprint->CountedProjectile == 0u) {
      return true;
    }

    if (mUnit == nullptr || mUnit->AiSiloBuild == nullptr) {
      return true;
    }

    return mUnit->AiSiloBuild->SiloGetStorageCount(static_cast<ESiloType>(mWeaponBlueprint->NukeWeapon)) != 0;
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
   * Address: 0x006D5B40 (FUN_006D5B40, Moho::UnitWeapon::TargetSolutionStatusGun)
   *
   * What it does:
   * Evaluates one gun target-position lane and returns one range/heading
   * solution status.
   */
  ESolutionStatus UnitWeapon::TargetSolutionStatusGun(const Wm3::Vector3f* const targetPosition, float* const inOutDistanceSq)
  {
    return EvaluateTargetSolutionStatusGun(this, *targetPosition, inOutDistanceSq);
  }

  /**
   * Address: 0x006D5810 (FUN_006D5810, Moho::UnitWeapon::TargetIsTooCloseMelee)
   *
   * What it does:
   * Evaluates melee target reachability using collision-shell probes for large
   * mobile targets and footprint-edge touch checks for unit targets.
   */
  ESolutionStatus UnitWeapon::TargetIsTooCloseMelee(Entity* const targetEntity)
  {
    if (targetEntity->IsMobile()) {
      const SFootprint& targetFootprint = targetEntity->GetFootprint();
      std::uint8_t targetSize = targetFootprint.mSizeZ;
      if (targetFootprint.mSizeX > targetSize) {
        targetSize = targetFootprint.mSizeX;
      }

      if (targetSize > 1u) {
        CollisionResult collisionResult{};

        const SFootprint& ownerFootprint = mUnit->GetFootprint();
        const Wm3::Vec3f& ownerPosition = mUnit->GetPosition();
        const float ownerHalfSizeX = static_cast<float>(ownerFootprint.mSizeX) * 0.5f;
        const float ownerHalfSizeZ = static_cast<float>(ownerFootprint.mSizeZ) * 0.5f;
        const std::int16_t ownerGridMinX = static_cast<std::int16_t>(
          static_cast<std::int32_t>(ownerPosition.x - ownerHalfSizeX)
        );
        const std::int16_t ownerGridMinZ = static_cast<std::int16_t>(
          static_cast<std::int32_t>(ownerPosition.z - ownerHalfSizeZ)
        );

        const Wm3::Vec3f probeCenter{
          static_cast<float>(ownerGridMinX) + ownerHalfSizeX,
          0.0f,
          static_cast<float>(ownerGridMinZ) + ownerHalfSizeZ,
        };

        constexpr float kMeleeProbeHalfHeight = 1000.0f;
        const Wm3::Box3f outerProbe = BuildAxisAlignedCollisionProbe(
          probeCenter,
          Wm3::Vec3f{ownerHalfSizeX + 1.0f, kMeleeProbeHalfHeight, ownerHalfSizeZ + 1.0f}
        );
        const Wm3::Box3f innerProbe = BuildAxisAlignedCollisionProbe(
          probeCenter,
          Wm3::Vec3f{ownerHalfSizeX, kMeleeProbeHalfHeight, ownerHalfSizeZ}
        );

        EntityCollisionUpdater* const targetCollisionShape = targetEntity->CollisionExtents;
        if (targetCollisionShape != nullptr && targetCollisionShape->CollideBox(&outerProbe, &collisionResult)) {
          collisionResult.sourceEntity = targetEntity;
          if (!targetCollisionShape->CollideBox(&innerProbe, &collisionResult)) {
            return ESolutionStatus::TRS_Available;
          }
        }

        return ESolutionStatus::TRS_OutsideMaxRange;
      }
    }

    if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
      const Wm3::Vec3f& targetPosition = targetEntity->GetPositionWm3();
      const SCoordsVec2 targetFootprintCenter{targetPosition.x, targetPosition.z};
      const RUnitBlueprint* const targetBlueprint = targetUnit->GetBlueprint();
      const gpg::Rect2i targetFootprintRect = targetBlueprint->GetFootprintRect(targetFootprintCenter);

      const Wm3::Vec3f& ownerPosition = mUnit->GetPosition();
      const SCoordsVec2 ownerFootprintCenter{ownerPosition.x, ownerPosition.z};
      const RUnitBlueprint* const ownerBlueprint = mUnit->GetBlueprint();
      const gpg::Rect2i ownerFootprintRect = ownerBlueprint->GetFootprintRect(ownerFootprintCenter);

      if (targetFootprintRect.Touches(ownerFootprintRect)) {
        return ESolutionStatus::TRS_Available;
      }
    }

    return ESolutionStatus::TRS_OutsideMaxRange;
  }

  /**
   * Address: 0x006D5D40 (FUN_006D5D40, Moho::UnitWeapon::GetSolutionStatus)
   *
   * What it does:
   * Returns one melee/gun target-solution status for a direct target entity
   * lane.
   */
  ESolutionStatus UnitWeapon::GetSolutionStatus(Entity* const targetEntity)
  {
    if (targetEntity == nullptr) {
      return ESolutionStatus::TRS_OutsideMaxRange;
    }

    if (mUnit->mIsMelee) {
      return TargetIsTooCloseMelee(targetEntity);
    }

    const Wm3::Vec3f& targetPosition = targetEntity->GetPositionWm3();
    return TargetSolutionStatusGun(&targetPosition, nullptr);
  }

  /**
   * Address: 0x006D5D80 (FUN_006D5D80, Moho::UnitWeapon::TargetIsTooClose)
   *
   * What it does:
   * Returns one melee/gun solution status for the current `CAiTarget` payload.
   */
  ESolutionStatus UnitWeapon::TargetIsTooClose(CAiTarget* const targetData)
  {
    if (mUnit->mIsMelee) {
      if (Entity* const targetEntity = targetData->GetEntity(); targetEntity != nullptr) {
        return TargetIsTooCloseMelee(targetEntity);
      }
    }

    const Wm3::Vec3f targetPosition = targetData->GetTargetPosGun(true);
    return TargetSolutionStatusGun(&targetPosition, nullptr);
  }

  /**
   * Address: 0x00673580 (FUN_00673580, Moho::CollisionBeamHelper::~CollisionBeamHelper)
   *
   * What it does:
   * Unlinks the resolved-impact and bound-target weak-entity links from their
   * owner chains before teardown.
   */
  CollisionBeamHelper::~CollisionBeamHelper()
  {
    mEntity.UnlinkFromOwnerChain();
    mTarget.targetEntity.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x006D6B00 sub-flow (inline init inside CreateCollisionBeamHelper)
   *
   * What it does:
   * Zero-initializes the impact lane, the bound source target, and the resolved
   * weak-entity link. `CreateCollisionBeamHelper` overwrites every other field
   * before the helper is used, so only the link/impact lanes need defaulting.
   */
  CollisionBeamHelper::CollisionBeamHelper()
    : mImpactType(IMPACT_Invalid)
    , mTarget{}
    , mEntity{}
    , mPos{}
    , mBeamLength(0.0f)
    , mLine{}
    , mLineScale(0.0f)
  {
  }

  /**
   * Address: 0x006D78F0 (FUN_006D78F0, sub_6D78F0)
   *
   * What it does:
   * Ages the per-weapon target blacklist: decrements each row's remaining-tick
   * counter and erases rows whose entity is gone, has moved off its recorded
   * spot, or whose counter has reached zero.
   */
  void UnitWeapon::AgeBlacklist()
  {
    for (auto it = mBlacklist.begin(); it != mBlacklist.end();) {
      SBlackListInfo& row = *it;
      --row.mValue;

      const Entity* const blacklistedEntity = row.mEntity.GetObjectPtr();
      const bool entityGone = (blacklistedEntity == nullptr);

      bool entityMoved = false;
      if (!entityGone) {
        // The original tests whether the blacklisted entity moved this tick by
        // comparing its current world position against its previous-tick world
        // position. `Wm3::Vector3f::Compare` returns true when the vectors DIFFER.
        entityMoved = Wm3::Vector3f::Compare(&blacklistedEntity->Position, &blacklistedEntity->PrevPosition);
      }

      if (entityGone || entityMoved || row.mValue <= 0) {
        it = mBlacklist.erase(it);
      } else {
        ++it;
      }
    }
  }

  namespace
  {
    /**
     * Address: 0x00593220 (FUN_00593220, func_SetUnitStat)
     *
     * What it does:
     * Resolves one army-stat float lane by path, marks it float-typed, and
     * atomically replaces its stored value with `value`.
     */
    void SetArmyFloatStat(CArmyStats& armyStats, const char* const statPath, const float value)
    {
      CArmyStatItem* const item = ResolveArmyStatItemCachedCreate(&armyStats, statPath);
      item->SynchronizeAsFloat();

      volatile long* const counter = reinterpret_cast<volatile long*>(&item->mPrimaryValueBits);
      std::int32_t desiredBits = 0;
      std::memcpy(&desiredBits, &value, sizeof(desiredBits));
      for (;;) {
        const std::int32_t observed = _InterlockedCompareExchange(counter, 0, 0);
        const std::int32_t result = _InterlockedCompareExchange(counter, desiredBits, observed);
        if (result == observed) {
          return;
        }
      }
    }

    /**
     * Address: 0x006D31D0 (FUN_006D31D0, sub_6D31D0)
     *
     * What it does:
     * Returns whether two AI targets currently resolve to the same target: same
     * target type, same raw target entity, and (for ground targets only) the same
     * ground position.
     */
    [[nodiscard]] bool AiTargetsAreSame(const CAiTarget& current, const CAiTarget& candidate) noexcept
    {
      if (current.targetType != candidate.targetType) {
        return false;
      }
      if (current.targetEntity.GetObjectPtr() != candidate.targetEntity.GetObjectPtr()) {
        return false;
      }
      if (candidate.targetType == EAiTargetType::AITARGET_Ground) {
        // `Wm3::Vector3f::Compare` returns true when the vectors DIFFER, so the
        // targets are "same" only when the ground positions do NOT differ.
        return !Wm3::Vector3f::Compare(&candidate.position, &current.position);
      }
      return true;
    }

    /**
     * Address: 0x006D5F30 sub-flow (inline block inside SetTarget).
     *
     * What it does:
     * When `weapon` is the unit's controlling weapon for its current target,
     * rebinds the owning unit's target-blip lane: binds it directly to a recon
     * blip target, resolves a unit target to its recon blip, or clears it
     * otherwise. Marks the unit's sync-game-data lane dirty afterward.
     */
    void MaintainTargetBlip(UnitWeapon& weapon)
    {
      Unit* const unit = weapon.mUnit;
      if (unit == nullptr) {
        return;
      }

      CAiAttackerImpl* const attacker = unit->AiAttacker;
      if (attacker == nullptr) {
        return;
      }

      // Only the weapon that "owns" this target drives the unit's target blip.
      UnitWeapon* const targetWeapon = attacker->GetTargetWeapon(&weapon.mTarget);
      const bool weaponControlsTarget = (targetWeapon != nullptr)
        ? (&weapon == targetWeapon)
        : (&weapon == attacker->GetPrimaryWeapon());
      if (!weaponControlsTarget) {
        return;
      }

      Entity* const targetEntity = weapon.mTarget.targetEntity.GetObjectPtr();
      if (targetEntity != nullptr) {
        if (targetEntity->IsReconBlip() != nullptr) {
          // Target is already a recon blip: bind the blip lane straight to it.
          unit->TargetBlipEntityRef.ResetObjectPtr<Entity>(targetEntity);
          unit->NeedSyncGameData = true;
          return;
        }

        if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
          // Real unit target: resolve the owning army's recon blip for it.
          CAiReconDBImpl* const reconDb = (unit->ArmyRef != nullptr) ? unit->ArmyRef->GetReconDB() : nullptr;
          ReconBlip* const reconBlip = (reconDb != nullptr) ? reconDb->ReconGetBlip(targetUnit) : nullptr;
          unit->SetTargetBlipEntity(reconBlip);
          return;
        }
      }

      // No bindable target: clear the blip lane.
      unit->TargetBlipEntityRef.AsWeakPtr<Entity>().UnlinkFromOwnerChain();
      unit->NeedSyncGameData = true;
    }

    /**
     * Address: 0x006D61F0 sub-flow (inline block inside Fire).
     *
     * What it does:
     * Records this weapon's realtime fire statistics for the owning unit:
     * increments shots-fired, stores the configured max fire range, accumulates
     * the actual target range into the total/average lanes. Mirrors the engine's
     * `RealTimeStats_<unitName>_Shots_*` accounting.
     */
    void AccountFireRangeStats(Unit& unit, UnitWeapon& weapon)
    {
      CArmyStats* const armyStats = (unit.ArmyRef != nullptr) ? unit.ArmyRef->GetArmyStats() : nullptr;
      if (armyStats == nullptr) {
        return;
      }

      const msvc8::string statPrefix = msvc8::string("RealTimeStats_") + unit.GetUniqueName();

      // _Shots_Fired: integer counter, atomically incremented by one.
      const msvc8::string shotsFiredPath = statPrefix + "_Shots_Fired";
      {
        CArmyStatItem* const shotsFired = armyStats->GetItem(shotsFiredPath.c_str());
        shotsFired->Synchronize();
        (void)_InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&shotsFired->mPrimaryValueBits), 1);
      }

      // Number of shots fired so far, used to average the fire-range lanes.
      const int shotCount = armyStats->TraverseTables(shotsFiredPath.c_str(), true)->GetInt(false);

      // _Shots_MaxFireRange: store the weapon's configured max radius.
      {
        const msvc8::string statPath = statPrefix + "_Shots_MaxFireRange";
        const float maxFireRange = weapon.mWeaponBlueprint->MaxRadius;
        SetArmyFloatStat(*armyStats, statPath.c_str(), maxFireRange);
      }

      // Actual range to the current target point.
      const Wm3::Vec3f& unitPosition = unit.GetPosition();
      const Wm3::Vec3f targetPosition = weapon.mTarget.GetTargetPosGun(false);
      const float dx = targetPosition.x - unitPosition.x;
      const float dy = targetPosition.y - unitPosition.y;
      const float dz = targetPosition.z - unitPosition.z;
      const float targetRange = std::sqrt((dx * dx) + (dy * dy) + (dz * dz));

      // _Shots_TotalFireRange: accumulate the actual range, then average it.
      {
        const msvc8::string totalPath = statPrefix + "_Shots_TotalFireRange";

        CArmyStatItem* const totalRange = ResolveArmyStatItemCachedCreate(armyStats, totalPath.c_str());
        totalRange->SynchronizeAsFloat();
        float rangeDelta = targetRange;
        (void)totalRange->AddFloat(&rangeDelta);

        const float accumulatedTotal = armyStats->TraverseTablesCreate(totalPath.c_str())->GetFloat(false);

        // _Shots_AvgFireRange: accumulated total divided by the shots-fired count.
        const msvc8::string avgPath = statPrefix + "_Shots_AvgFireRange";
        const float averageRange = accumulatedTotal / static_cast<float>(shotCount);
        SetArmyFloatStat(*armyStats, avgPath.c_str(), averageRange);
      }
    }
  } // namespace

  /**
   * Address: 0x006D5F30 (FUN_006D5F30, Moho::UnitWeapon::SetTarget)
   *
   * IDA signature:
   * Moho::CTaskThread *__thiscall Moho::UnitWeapon::SetTarget(Moho::UnitWeapon *this, Moho::CAiTarget *target);
   *
   * What it does:
   * Replaces this weapon's active AI target. No-ops when the new target equals
   * the current one. Otherwise: ages the blacklist (or runs the `OnLostTarget`
   * script when losing a target), maintains the old/new target entities' shooter
   * sets, rebinds the owning unit's target-blip lane when this is the controlling
   * weapon, re-aims, fires the `OnGotTarget` script on a fresh acquisition, and
   * restages the fire task.
   */
  void UnitWeapon::SetTarget(CAiTarget* const target)
  {
    if (AiTargetsAreSame(mTarget, *target)) {
      return;
    }

    const bool hadTarget = (mTarget.targetType != EAiTargetType::AITARGET_None);
    const bool wantsTarget = (target->targetType != EAiTargetType::AITARGET_None);

    if (hadTarget) {
      if (wantsTarget) {
        AgeBlacklist();
      } else {
        RunScript("OnLostTarget");
      }
    } else if (wantsTarget) {
      AgeBlacklist();
    }

    // Drop this unit from the previous target entity's shooter set.
    if (Entity* const previousTargetEntity = mTarget.GetEntity(); previousTargetEntity != nullptr) {
      if (previousTargetEntity->Dead == 0u && previousTargetEntity->DestroyQueuedFlag == 0u) {
        if (mUnit != nullptr) {
          previousTargetEntity->RemoveShooter(static_cast<Entity*>(mUnit));
        }
      }
    }

    mTarget = *target;

    MaintainTargetBlip(*this);

    PickNewTargetAimSpot();

    // Add this unit to the new target entity's shooter set.
    if (Entity* const newTargetEntity = mTarget.GetEntity(); newTargetEntity != nullptr) {
      if (newTargetEntity->Dead == 0u && newTargetEntity->DestroyQueuedFlag == 0u) {
        Entity* const ownerEntity = (mUnit != nullptr) ? static_cast<Entity*>(mUnit) : nullptr;
        newTargetEntity->AddShooter(ownerEntity);
      }
    }

    if (!hadTarget && wantsTarget) {
      RunScript("OnGotTarget");
    }

    // Restage the fire task so it re-evaluates against the new target next tick.
    CTaskThread* const fireThread = mFireWeaponTask->mOwnerThread;
    fireThread->mPendingFrames = 0;
    if (fireThread->mStaged) {
      fireThread->Unstage();
    }

    mUnknown170 = 0;
    mUnknown174 = 1u;
    mShotsAtTarget = 0;
  }

  /**
   * Address: 0x006D61F0 (FUN_006D61F0, Moho::UnitWeapon::Fire)
   *
   * IDA signature:
   * void __thiscall Moho::UnitWeapon::Fire(Moho::UnitWeapon *this);
   *
   * What it does:
   * Performs one weapon fire when the owning unit is not stunned. When the unit
   * has realtime-stats accounting enabled, records shots-fired, max/total/average
   * fire-range statistics. Always runs the `OnFire` script and bumps the
   * shots-at-target counter.
   */
  void UnitWeapon::Fire()
  {
    Unit* const unit = mUnit;
    if (unit->VarDat().mStunTicks != 0) {
      return;
    }

    if (unit != nullptr && unit->IsRealtimeStatsEnabled()) {
      AccountFireRangeStats(*unit, *this);
    }

    RunScript("OnFire");
    ++mShotsAtTarget;
  }

  /**
   * Address: 0x006D6A00 (FUN_006D6A00, Moho::UnitWeapon::GetClosestCollision)
   *
   * What it does:
   * Scans collision candidates, applies script and ally filters, and returns
   * the nearest surviving collision lane.
   */
  WeaponCollisionEntry* UnitWeapon::GetClosestCollision(
    WeaponCollisionEntryVec* const collisions,
    UnitWeapon* const weapon,
    Unit* const ownerUnit,
    const bool ignoreAlly
  )
  {
    if (collisions == nullptr) {
      return nullptr;
    }

    WeaponCollisionEntry* const begin = collisions->begin();
    WeaponCollisionEntry* const end = collisions->end();
    if (begin == nullptr || end == nullptr || begin == end) {
      return nullptr;
    }

    std::int32_t closestIndex = -1;
    float closestDistance = std::numeric_limits<float>::infinity();
    const std::size_t collisionCount = static_cast<std::size_t>(end - begin);
    for (std::size_t index = 0; index < collisionCount; ++index) {
      WeaponCollisionEntry& candidate = begin[index];
      Entity* const candidateEntity = candidate.entity;
      if (candidateEntity != nullptr && !candidateEntity->RunScriptOnCollisionCheckWeapon(weapon)) {
        continue;
      }

      if (ignoreAlly && ownerUnit != nullptr && candidateEntity != nullptr) {
        Unit* const candidateUnit = candidateEntity->IsUnit();
        if (candidateUnit != nullptr && candidateUnit->mCurrentLayer == LAYER_Air && ownerUnit->ArmyRef != nullptr) {
          const std::uint32_t candidateArmyIndex = (candidateUnit->ArmyRef != nullptr)
            ? static_cast<std::uint32_t>(candidateUnit->ArmyRef->ArmyId)
            : std::numeric_limits<std::uint32_t>::max();
          if (!ownerUnit->ArmyRef->IsEnemy(candidateArmyIndex)) {
            continue;
          }
        }
      }

      if (closestDistance > candidate.dist) {
        if (candidateEntity == nullptr || candidateEntity->IsUnit() != ownerUnit) {
          closestIndex = static_cast<std::int32_t>(index);
          closestDistance = candidate.dist;
        }
      }
    }

    if (closestIndex < 0) {
      return nullptr;
    }

    return begin + closestIndex;
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

  /**
   * Address: 0x006D64E0 (FUN_006D64E0, Moho::UnitWeapon::CreateProjectile)
   *
   * What it does:
   * Spawns one projectile from the requested muzzle bone and applies launch
   * orientation/randomness, damage payload, velocity, and lifetime lanes.
   */
  Projectile* UnitWeapon::CreateProjectile(const std::int32_t muzzleBoneIndex)
  {
    if (mProjectileBlueprint == nullptr) {
      const char* const weaponName = (mWeaponBlueprint != nullptr) ? mWeaponBlueprint->DisplayName.c_str() : "UnknownWeapon";
      const RUnitBlueprint* const unitBlueprint = (mUnit != nullptr) ? mUnit->GetBlueprint() : nullptr;
      const char* const unitName = (unitBlueprint != nullptr) ? unitBlueprint->mBlueprintId.c_str() : "UnknownUnit";
      gpg::Logf("%s:%s:CreateProjectile: no projectile blueprint, doing instahit instead.", unitName, weaponName);
      return nullptr;
    }

    if (mUnit == nullptr) {
      return nullptr;
    }

    VTransform launchTransform = mUnit->GetBoneWorldTransform(muzzleBoneIndex);
    if (mProjectileBlueprint->Physics.StraightDownOrdinance != 0u) {
      launchTransform.orient_ = COORDS_Orient(Wm3::Vector3f{0.0f, -1.0f, 0.0f});
    } else if (mWeaponBlueprint != nullptr && mWeaponBlueprint->UseFiringSolutionInsteadOfAimBone != 0u) {
      const Wm3::Vector3f& invalidAimingVector = GetRecoveredInvalidAimingVector();
      if (Wm3::Vector3f::Compare(&mAimingAt, &invalidAimingVector)) {
        Wm3::Vector3f recoveredAimDirection = mAimingAt;
        if (Wm3::Vector3f::Normalize(&recoveredAimDirection) > 0.0f) {
          launchTransform.orient_ = COORDS_Orient(recoveredAimDirection);
        }
      }
    }

    if (mFiringRandomness > 0.0f && mSim != nullptr && mSim->mRngState != nullptr) {
      constexpr float kDegreesToRadians = 0.017453292f;
      const float pitchJitter = mSim->mRngState->FRandGaussian() * mFiringRandomness * kDegreesToRadians;
      const float headingJitter = mSim->mRngState->FRandGaussian() * mFiringRandomness * kDegreesToRadians;
      const Wm3::Quaternionf jitterOrientation = COORDS_Orient(headingJitter, pitchJitter);
      launchTransform.orient_ = Wm3::Quaternionf::Multiply(jitterOrientation, launchTransform.orient_);
    }

    const float damageRadius =
      (mAttributes.mDamageRadius < 0.0f && mAttributes.mBlueprint != nullptr)
      ? mAttributes.mBlueprint->DamageRadius
      : mAttributes.mDamageRadius;
    const float damage = (mAttributes.mDamage < 0.0f && mAttributes.mBlueprint != nullptr) ? mAttributes.mBlueprint->Damage
                                                                                            : mAttributes.mDamage;
    const msvc8::string damageType = mAttributes.GetName();
    const bool ignoreAlly = (mWeaponBlueprint != nullptr) ? (mWeaponBlueprint->IgnoresAlly != 0u) : false;

    Projectile* const projectile = PROJ_Create(
      mSim,
      mProjectileBlueprint,
      mUnit->ArmyRef,
      static_cast<Entity*>(mUnit),
      launchTransform,
      damage,
      damageRadius,
      damageType,
      mTarget,
      ignoreAlly
    );
    if (projectile == nullptr) {
      return nullptr;
    }

    if (mWeaponBlueprint != nullptr && mWeaponBlueprint->MuzzleVelocity != 0.0f) {
      const Wm3::Vec3f targetPosition = mTarget.GetTargetPosGun(false);
      const float deltaX = launchTransform.pos_.x - targetPosition.x;
      const float deltaY = launchTransform.pos_.y - targetPosition.y;
      const float deltaZ = launchTransform.pos_.z - targetPosition.z;
      const float targetDistance = std::sqrt((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ));

      const float muzzleVelocity = mWeaponBlueprint->GetMuzzleVelocity(targetDistance, mSim->mRngState);
      Wm3::Vector3f& projectileVelocity = AccessProjectileVelocity(*projectile);
      (void)Wm3::Vector3f::Normalize(&projectileVelocity);
      projectileVelocity.x *= muzzleVelocity;
      projectileVelocity.y *= muzzleVelocity;
      projectileVelocity.z *= muzzleVelocity;
    }

    if (mWeaponBlueprint != nullptr && mWeaponBlueprint->ProjectileLifetime > 0.0f) {
      projectile->SetLifetime(mWeaponBlueprint->ProjectileLifetime);
    }

    if (mWeaponBlueprint != nullptr && mWeaponBlueprint->ProjectileLifetimeUsesMultiplier > 0.0f
        && mWeaponBlueprint->MuzzleVelocity > 0.0f) {
      const float scaledLifetimeSeconds =
        (mWeaponBlueprint->MaxRadius / mWeaponBlueprint->MuzzleVelocity) * mWeaponBlueprint->ProjectileLifetimeUsesMultiplier;
      projectile->SetLifetime(scaledLifetimeSeconds);
    }

    if (mWeaponBlueprint != nullptr && mWeaponBlueprint->ReTargetOnMiss != 0u && mAttacker != nullptr
        && mTarget.targetEntity.GetObjectPtr() != nullptr) {
      CAiAttackerImpl* const attackerImpl = reinterpret_cast<CAiAttackerImpl*>(mAttacker);
      attackerImpl->TransmitProjectileImpactEvent(this, projectile);
    }

    return projectile;
  }

  /**
   * Address: 0x006D6B00 (FUN_006D6B00, Moho::UnitWeapon::CreateCollisionBeamHelper)
   *
   * IDA signature:
   * Moho::CollisionBeamHelper *__thiscall Moho::UnitWeapon::CreateCollisionBeamHelper(
   *   Moho::UnitWeapon *this, Moho::CollisionBeamHelper *outHelper, int bone);
   *
   * What it does:
   * Places a beam center line from the requested muzzle bone along its forward
   * axis, scaled to the weapon's maximum beam length, then resolves the nearest
   * entity collision and terrain/water surface intersection along it. Fills
   * `outHelper` with the resolved contact entity, contact point, beam length, and
   * impact type.
   */
  void UnitWeapon::CreateCollisionBeamHelper(CollisionBeamHelper* const outHelper, const std::int32_t bone)
  {
    // Resolve the beam reach: weapon blueprint override, else the (clamped)
    // attribute max radius, else the blueprint max radius.
    float beamReach = mWeaponBlueprint->MaximumBeamLength;
    if (beamReach <= 0.0f) {
      beamReach = mAttributes.mMaxRadius;
      if (beamReach < 0.0f) {
        beamReach = mAttributes.mBlueprint->MaxRadius;
      }
    }
    const float maxBeamLength = beamReach;

    // Copy the current weapon target and reset the resolved-impact lanes.
    outHelper->mTarget = mTarget;
    outHelper->mPos = GetRecoveredInvalidAimingVector();
    outHelper->mBeamLength = maxBeamLength;
    outHelper->mImpactType = IMPACT_Invalid;

    // Forward axis of the firing bone (same construction as GetForwardVector).
    const VTransform boneTransform = mUnit->GetBoneWorldTransform(bone);
    const Wm3::Quaternionf& q = boneTransform.orient_;
    Wm3::Vector3f forward{
      ((q.w * q.y) + (q.z * q.x)) * 2.0f,
      ((q.w * q.z) - (q.y * q.x)) * 2.0f,
      1.0f - (((q.y * q.y) + (q.z * q.z)) * 2.0f),
    };

    const Wm3::Vec3f beamStart = boneTransform.pos_;

    // Far endpoint at full reach, used to size the swept segment.
    const Wm3::Vec3f reachEnd{
      (forward.x * maxBeamLength) + boneTransform.pos_.x,
      (forward.y * maxBeamLength) + boneTransform.pos_.y,
      (forward.z * maxBeamLength) + boneTransform.pos_.z,
    };

    // Planar (XZ) length of the swept segment, used to clamp very-short beams.
    const float planarDx = boneTransform.pos_.x - reachEnd.x;
    const float planarDz = boneTransform.pos_.z - reachEnd.z;
    const float planarLength = std::sqrt((planarDx * planarDx) + (planarDz * planarDz));

    float reachScale;
    if (planarLength <= 0.001f) {
      reachScale = 1.0f;
    } else {
      reachScale = maxBeamLength / planarLength;
      if ((maxBeamLength / planarLength) > 5.0f) {
        reachScale = 5.0f;
      }
    }
    const float sweepLength = reachScale * maxBeamLength;

    // Swept segment end point and beam center-line midpoint.
    const Wm3::Vec3f sweepEnd{
      (forward.x * sweepLength) + boneTransform.pos_.x,
      boneTransform.pos_.y + (forward.y * sweepLength),
      boneTransform.pos_.z + (forward.z * sweepLength),
    };

    outHelper->mLine.Origin = Wm3::Vector3f{
      ((forward.x * sweepLength) * 0.5f) + boneTransform.pos_.x,
      boneTransform.pos_.y + ((forward.y * sweepLength) * 0.5f),
      boneTransform.pos_.z + ((forward.z * sweepLength) * 0.5f),
    };
    outHelper->mLine.Direction = forward;
    outHelper->mLineScale = sweepLength * 0.5f;

    // Gather entity collisions along the segment and pick the nearest valid hit.
    WeaponCollisionEntryVec collisions;
    mSim->mOGrid->GetEntityCollisionsInLine(
      reinterpret_cast<EntityLineCollisionVector&>(collisions),
      beamStart,
      sweepEnd
    );

    if (collisions.begin() != collisions.end()) {
      const bool ignoreAlly = (mWeaponBlueprint->IgnoresAlly != 0u);
      if (WeaponCollisionEntry* const closest = GetClosestCollision(&collisions, this, mUnit, ignoreAlly);
          closest != nullptr) {
        Entity* const hitEntity = closest->entity;
        outHelper->mPos = closest->contactPoint;
        outHelper->mEntity.Set(hitEntity);

        // Distance from the beam start to the contact point (using a per-entity
        // reference position depending on what the beam hit).
        Entity* const boundEntity = outHelper->mEntity.GetObjectPtr();
        Wm3::Vec3f referencePoint{};
        if (boundEntity != nullptr && (static_cast<std::uint32_t>(boundEntity->id_) & 0xF0000000u) == 0x40000000u) {
          referencePoint = closest->contactPoint;
        } else if (boundEntity != nullptr && boundEntity->IsUnit() == nullptr) {
          referencePoint = boundEntity->Position;
        } else if (boundEntity != nullptr) {
          referencePoint = boundEntity->GetBoneWorldTransform(-1).pos_;
        }

        const float dx = beamStart.x - referencePoint.x;
        const float dy = beamStart.y - referencePoint.y;
        const float dz = beamStart.z - referencePoint.z;
        outHelper->mBeamLength = std::sqrt((dx * dx) + (dy * dy) + (dz * dz));
      }
    }

    // Resolve the terrain/water surface intersection along the centered segment.
    GeomLine3 surfaceLine{};
    surfaceLine.pos = Wm3::Vec3f{
      outHelper->mLine.Origin.x - (outHelper->mLine.Direction.x * outHelper->mLineScale),
      outHelper->mLine.Origin.y - (outHelper->mLine.Direction.y * outHelper->mLineScale),
      outHelper->mLine.Origin.z - (outHelper->mLine.Direction.z * outHelper->mLineScale),
    };
    surfaceLine.dir = outHelper->mLine.Direction;
    surfaceLine.closest = 0.0f;
    surfaceLine.farthest = outHelper->mLineScale * 2.0f;

    CColHitResult surfaceHit{};
    surfaceHit.distance = std::numeric_limits<float>::quiet_NaN();
    surfaceHit.v1 = std::numeric_limits<float>::quiet_NaN();
    surfaceHit.hitKind = 0;
    const Wm3::Vec3f surfacePoint = mSim->mMapData->SurfaceIntersection(surfaceLine, &surfaceHit);

    if (IsValidVector3f(surfacePoint) && outHelper->mBeamLength > surfaceHit.distance) {
      // Surface hit is closer than any entity hit: unbind the entity and adopt
      // the surface contact point + impact type.
      outHelper->mBeamLength = surfaceHit.distance;
      outHelper->mEntity.UnlinkFromOwnerChain();
      outHelper->mPos = surfacePoint;

      if (surfaceHit.hitKind == 3) {
        outHelper->mImpactType = IMPACT_Water;
        return;
      }
      if (surfaceHit.hitKind == 1) {
        outHelper->mImpactType = IMPACT_Terrain;
        return;
      }
    }

    // No closer surface: classify the resolved impact point if still unset.
    if (outHelper->mImpactType == IMPACT_Invalid) {
      if (IsValidVector3f(outHelper->mPos)) {
        Entity* const boundEntity = outHelper->mEntity.GetObjectPtr();
        outHelper->mImpactType = ENT_GetImpactType(mSim, boundEntity, outHelper->mPos);
      } else {
        outHelper->mPos = sweepEnd;
        outHelper->mImpactType = IMPACT_Air;
      }
    }
  }

  /**
   * Address: 0x006D34B0 (FUN_006D34B0)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI for `UnitWeapon`.
   */
  gpg::RType* UnitWeapon::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(UnitWeapon));
    }

    return sType;
  }

  namespace
  {
    /**
     * Static `RPointerType<UnitWeapon>` descriptor that the binary exposes as
     * `Moho::UnitWeapon::PointerType`. Default static-init runs the
     * RPointerTypeBase → RType → RObject ctor chain and installs the most-
     * derived vftable lane.
     */
    gpg::RPointerType<moho::UnitWeapon> sUnitWeaponPointerTypeStorage{};

    /**
     * Address: 0x005DDC00 (FUN_005DDC00)
     *
     * What it does:
     * Pre-registers the static `RPointerType<UnitWeapon>` descriptor under the
     * `UnitWeapon*` type-info key so subsequent `LookupRType` queries from the
     * lazy `GetPointerType` lane resolve to this descriptor.
     */
    void PreregisterUnitWeaponPointerType()
    {
      gpg::PreRegisterRType(typeid(moho::UnitWeapon*), &sUnitWeaponPointerTypeStorage);
    }

    /**
     * Address: 0x00BF8610 (FUN_00BF8610)
     *
     * What it does:
     * Tears down the static `RPointerType<UnitWeapon>` descriptor at process
     * exit: frees heap-backed `bases_`/`fields_` vector storage and resets the
     * RType vftable lane to the `RObject` base. Registered via `atexit` from
     * `GetPointerType`'s once-init path.
     */
    void CleanupUnitWeaponPointerType()
    {
      sUnitWeaponPointerTypeStorage.~RPointerType<moho::UnitWeapon>();
    }
  } // namespace

  /**
   * Address: 0x005DCD70 (FUN_005DCD70, Moho::UnitWeapon::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<UnitWeapon>`
   * descriptor and installs the matching atexit teardown. After that, lazily
   * caches the `LookupRType(typeid(UnitWeapon*))` result in `sPointerType` and
   * returns it.
   */
  gpg::RType* UnitWeapon::GetPointerType()
  {
    static const bool sOnceInit = []() {
      PreregisterUnitWeaponPointerType();
      (void)std::atexit(&CleanupUnitWeaponPointerType);
      return true;
    }();
    (void)sOnceInit;

    (void)StaticGetClass();

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(UnitWeapon*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x006D3540 (FUN_006D3540)
   */
  UnitWeapon* UnitWeapon::SetFiringRandomness(const float value)
  {
    mFiringRandomness = value;
    return this;
  }

  /**
   * Address: 0x006D3550 (FUN_006D3550)
   */
  float UnitWeapon::GetFiringRandomness() const
  {
    return mFiringRandomness;
  }

  /**
   * Address: 0x006D3560 (FUN_006D3560)
   */
  UnitWeapon* UnitWeapon::SetFireTargetLayerCaps(const ELayer layerMask)
  {
    mFireTargetLayerCaps = layerMask;
    if (mUnit != nullptr) {
      mUnit->NeedSyncGameData = true;
    }
    return this;
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(PreregisterUnitWeaponPointerType_2b5e7d, moho::PreregisterUnitWeaponPointerType)

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
  struct UnitWeaponLuaFuncDefBootstrap
  {
    UnitWeaponLuaFuncDefBootstrap()
    {
      (void)::moho::func_UnitWeaponPlaySound_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetEnabled_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetTargetEntity_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetTargetGround_LuaFuncDef();
      (void)::moho::func_UnitWeaponResetTarget_LuaFuncDef();
      (void)::moho::func_UnitWeaponCreateProjectile_LuaFuncDef();
      (void)::moho::func_UnitWeaponDoInstaHit_LuaFuncDef();
      (void)::moho::func_UnitWeaponGetProjectileBlueprint_LuaFuncDef();
      (void)::moho::func_UnitWeaponHasTarget_LuaFuncDef();
      (void)::moho::func_UnitWeaponFireWeapon_LuaFuncDef();
      (void)::moho::func_UnitWeaponIsFireControl_LuaFuncDef();
      (void)::moho::func_UnitWeaponGetCurrentTarget_LuaFuncDef();
      (void)::moho::func_UnitWeaponGetCurrentTargetPos_LuaFuncDef();
      (void)::moho::func_UnitWeaponCanFire_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetTargetingPriorities_LuaFuncDef();
      (void)::moho::func_UnitWeaponGetFiringRandomness_LuaFuncDef();
      (void)::moho::func_UnitWeaponGetFireClockPct_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeProjectileBlueprint_LuaFuncDef();
      (void)::moho::func_UnitWeaponTransferTarget_LuaFuncDef();
      (void)::moho::func_UnitWeaponBeenDestroyed_LuaFuncDef();
      (void)::moho::func_UnitWeaponGetBlueprint_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetFireControl_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeFiringTolerance_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeRateOfFire_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeMinRadius_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeMaxRadius_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeMaxHeightDiff_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeDamageType_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeDamageRadius_LuaFuncDef();
      (void)::moho::func_UnitWeaponChangeDamage_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetFiringRandomness_LuaFuncDef();
      (void)::moho::func_UnitWeaponSetFireTargetLayerCaps_LuaFuncDef();
    }
  };

  const UnitWeaponLuaFuncDefBootstrap gUnitWeaponLuaFuncDefBootstrap{};
} // namespace
