#pragma once

// Private to gpg/core/reflection: helpers the pieces of the former Reflection.cpp share.

#include "Reflection.h"

#include "legacy/algorithms/Sort.h"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <boost/shared_ptr.hpp>

#include "BadRefCast.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/String.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiBuilderImpl.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiNavigatorAir.h"
#include "moho/ai/CAiNavigatorLand.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/ai/CAiPathNavigator.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/CAiSteeringImpl.h"
#include "moho/ai/CAiTransportImpl.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/ai/EAiTargetType.h"
#include "moho/ai/EAiResult.h"
#include "moho/ai/ECompareType.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/ai/IAiSteering.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/LAiAttackerImpl.h"
#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/ai/SPointVector.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAnimationManipulator.h"
#include "moho/animation/CSlaveManipulator.h"
#include "moho/animation/CSlideManipulator.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/audio/CSndVar.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "moho/audio/ISoundManager.h"
#include "moho/audio/SAudioRequest.h"
#include "moho/command/CCommandDb.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/collision/RDebugCollision.h"
#include "moho/debug/RDebugGrid.h"
#include "moho/debug/RDebugNavSteering.h"
#include "moho/debug/RDebugNavWaypoints.h"
#include "moho/debug/RDebugRadar.h"
#include "moho/entity/Motor.h"
#include "moho/entity/PositionHistory.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/Entity.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/Prop.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelCounterHandle.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/Shield.h"
#include "moho/lua/CLuaConOutputHandler.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/CountedObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/path/RDebugNavPath.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/net/NetTransportEnums.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CEfxTrailEmitter.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ISimResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/math/Vector4f.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CDecalHandle.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ESquadClass.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/SimArmy.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/IdPool.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/EGenericIconTypeTypeInfo.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/sim/ESTITargetTypeTypeInfo.h"
#include "moho/task/CLuaTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/task/CWaitForTask.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "moho/ui/EMauiScrollAxisTypeInfo.h"
#include "moho/ui/UiStateTypes.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/EUnitCommandQueueStatus.h"
#include "moho/unit/core/EIntelTypeInfo.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/RDebugWeapons.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "moho/unit/tasks/CFactoryBuildTask.h"
#include "moho/unit/tasks/CUnitAssistMoveTask.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"
#include "moho/unit/tasks/CUnitCallLandTransport.h"
#include "moho/unit/tasks/CUnitCarrierLand.h"
#include "moho/unit/tasks/CUnitCarrierLaunch.h"
#include "moho/unit/tasks/CUnitCarrierRetrieve.h"
#include "moho/unit/tasks/CUnitRepairTask.h"
#include "moho/unit/tasks/CUnitSacrificeTask.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"
#include "moho/unit/tasks/CUnitCallTransport.h"
#include "moho/unit/tasks/CUnitCaptureTask.h"
#include "moho/unit/tasks/CUnitGetBuiltTask.h"
#include "moho/unit/tasks/CUnitGuardTask.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"
#include "moho/unit/tasks/CUnitMobileBuildTask.h"
#include "moho/unit/tasks/CUnitPodAssist.h"
#include "moho/unit/tasks/CUnitReclaimTask.h"
#include "moho/unit/tasks/CUnitUnloadUnits.h"
#include "moho/unit/tasks/CUnitUpgradeTask.h"
#include "moho/unit/tasks/CFireWeaponTask.h"
#include "lua/LuaRuntimeTypes.h"
#include "lua/LuaObject.h"
#include "Wm3Vector3.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"


// The MSVC runtime's polymorphic typeid entry point (vcruntime). cl declares
// it implicitly; clang-cl needs the declaration.
extern "C" void* __cdecl __RTtypeid(void* object);
using namespace gpg;
namespace
{

  constexpr const char* kReflectionHeaderPath = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.h";

  struct TypeInfoRTypePair
  {
    const std::type_info* typeInfo;
    gpg::RType* rType;
  };

  struct TypeInfoCache3
  {
    bool initialized;
    TypeInfoRTypePair entries[3];
  };

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildTypedRefWithCache(
    gpg::RRef* const out,
    TObject* const object,
    const std::type_info& declaredType,
    gpg::RType*& declaredTypeCache,
    TypeInfoCache3& cache
  )
  {
    if (!out) {
      return nullptr;
    }

    gpg::RType* declaredRType = declaredTypeCache;
    if (!declaredRType) {
      declaredRType = gpg::LookupRType(declaredType);
      declaredTypeCache = declaredRType;
    }

    const std::type_info* runtimeTypeInfo = &declaredType;
    if constexpr (std::is_polymorphic_v<TObject>) {
      if (object) {
        runtimeTypeInfo = &typeid(*object);
      }
    }

    if (!object || (*runtimeTypeInfo == declaredType)) {
      out->mObj = object;
      out->mType = declaredRType;
      return out;
    }

    if (!cache.initialized) {
      cache.initialized = true;
      for (TypeInfoRTypePair& entry : cache.entries) {
        entry.typeInfo = nullptr;
        entry.rType = nullptr;
      }
    }

    int foundSlot = 0;
    while (foundSlot < 3) {
      const TypeInfoRTypePair& entry = cache.entries[foundSlot];
      if (entry.typeInfo == runtimeTypeInfo || (entry.typeInfo && (*entry.typeInfo == *runtimeTypeInfo))) {
        break;
      }
      ++foundSlot;
    }

    gpg::RType* runtimeRType = nullptr;
    if (foundSlot >= 3) {
      runtimeRType = gpg::LookupRType(*runtimeTypeInfo);
      foundSlot = 2;
    } else {
      runtimeRType = cache.entries[foundSlot].rType;
    }

    for (int slot = foundSlot; slot > 0; --slot) {
      cache.entries[slot] = cache.entries[slot - 1];
    }
    cache.entries[0].typeInfo = runtimeTypeInfo;
    cache.entries[0].rType = runtimeRType;

    int32_t baseOffset = 0;
    if (!runtimeRType->IsDerivedFrom(declaredRType, &baseOffset)) {
      gpg::HandleAssertFailure("isDer", 458, kReflectionHeaderPath);
    }

    out->mType = runtimeRType;
    out->mObj = static_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    return out;
  }

  /**
   * Reflected-reference pointer upcast: one function template the compiler
   * emits out-of-line once per RPointerType<T>. Every real call site inlines
   * it (so IDA reports no direct caller); collapsed here from 15 identical
   * per-type copies. The explicit instantiations below preserve each
   * out-of-line COMDAT the linker keeps -- one FUN_ per type:
   *   RBlueprint 0x00557D50
   *   IFormationInstance 0x0059E7F0
   *   RUnitBlueprint 0x005A2420
   *   ReconBlip 0x005CC300
   *   UnitWeapon 0x005E1030
   *   CAcquireTargetTask 0x005E1050
   *   IAniManipulator 0x0063E970
   *   IEffect 0x0066D190
   *   Entity 0x00680F70
   *   CEconomyEvent 0x006B4410
   *   CUnitCommand 0x006E3EF0
   *   CArmyStatItem 0x00713F10
   *   SimArmy 0x007542D0
   *   Shield 0x00754470
   *   CDecalHandle 0x0077F600
   */
  template <class T>
  [[nodiscard]] void* TryUpcastRefObjectVariantB(gpg::RRef* const sourceRef)
  {
    const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, T::GetPointerType());
    return upcast.mObj;
  }

  // Address: 0x00557D50 (FUN_00557D50, TryUpcastRefObjectVariantB<moho::RBlueprint> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::RBlueprint>(gpg::RRef* const);
  // Address: 0x0059E7F0 (FUN_0059E7F0, TryUpcastRefObjectVariantB<moho::IFormationInstance> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::IFormationInstance>(gpg::RRef* const);
  // Address: 0x005A2420 (FUN_005A2420, TryUpcastRefObjectVariantB<moho::RUnitBlueprint> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::RUnitBlueprint>(gpg::RRef* const);
  // Address: 0x005CC300 (FUN_005CC300, TryUpcastRefObjectVariantB<moho::ReconBlip> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::ReconBlip>(gpg::RRef* const);
  // Address: 0x005E1030 (FUN_005E1030, TryUpcastRefObjectVariantB<moho::UnitWeapon> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::UnitWeapon>(gpg::RRef* const);
  // Address: 0x005E1050 (FUN_005E1050, TryUpcastRefObjectVariantB<moho::CAcquireTargetTask> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::CAcquireTargetTask>(gpg::RRef* const);
  // Address: 0x0063E970 (FUN_0063E970, TryUpcastRefObjectVariantB<moho::IAniManipulator> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::IAniManipulator>(gpg::RRef* const);
  // Address: 0x0066D190 (FUN_0066D190, TryUpcastRefObjectVariantB<moho::IEffect> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::IEffect>(gpg::RRef* const);
  // Address: 0x00680F70 (FUN_00680F70, TryUpcastRefObjectVariantB<moho::Entity> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::Entity>(gpg::RRef* const);
  // Address: 0x006B4410 (FUN_006B4410, TryUpcastRefObjectVariantB<moho::CEconomyEvent> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::CEconomyEvent>(gpg::RRef* const);
  // Address: 0x006E3EF0 (FUN_006E3EF0, TryUpcastRefObjectVariantB<moho::CUnitCommand> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::CUnitCommand>(gpg::RRef* const);
  // Address: 0x00713F10 (FUN_00713F10, TryUpcastRefObjectVariantB<moho::CArmyStatItem> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::CArmyStatItem>(gpg::RRef* const);
  // Address: 0x007542D0 (FUN_007542D0, TryUpcastRefObjectVariantB<moho::SimArmy> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::SimArmy>(gpg::RRef* const);
  // Address: 0x00754470 (FUN_00754470, TryUpcastRefObjectVariantB<moho::Shield> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::Shield>(gpg::RRef* const);
  // Address: 0x0077F600 (FUN_0077F600, TryUpcastRefObjectVariantB<moho::CDecalHandle> explicit instantiation)
  template void* TryUpcastRefObjectVariantB<moho::CDecalHandle>(gpg::RRef* const);

/**
 * Address: 0x004C8F30 (FUN_004C8F30, gpg::RRef::TryUpcast_CScriptObject_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CScriptObject*` slot and throws
 * `BadRefCast` on mismatch.
 */
moho::CScriptObject** TryUpcastCScriptObjectPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, moho::CScriptObject::GetPointerType());
    auto* const slot = static_cast<moho::CScriptObject**>(upcast.mObj);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x004C8AC0 (FUN_004C8AC0, sub_4C8AC0)
 *
 * What it does:
 * Allocates one `CScriptObject*` slot and returns it as typed `RRef`.
 */
RRef NewCScriptObjectPointerSlotRef()
{
    auto* const slot = static_cast<moho::CScriptObject**>(::operator new(sizeof(moho::CScriptObject*)));
    RRef out{};
    out = gpg::MakeRRef<moho::CScriptObject*>(slot);
    return out;
}

/**
 * Address: 0x004C8AF0 (FUN_004C8AF0, sub_4C8AF0)
 *
 * What it does:
 * Allocates one `CScriptObject*` slot and copies pointer lane value from source.
 */
RRef CopyCScriptObjectPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CScriptObject**>(::operator new(sizeof(moho::CScriptObject*)));
    if (slot) {
        *slot = *TryUpcastCScriptObjectPointerSlotOrThrow(*sourceRef);
    }
    else {
        slot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CScriptObject*>(slot);
    return out;
}

/**
 * Address: 0x004C8B80 (FUN_004C8B80, sub_4C8B80)
 *
 * What it does:
 * Wraps existing `CScriptObject*` slot storage as typed `RRef`.
 */
RRef ConstructCScriptObjectPointerSlotRef(void* const slotObject)
{
    RRef out{};
    out = gpg::MakeRRef<moho::CScriptObject*>(static_cast<moho::CScriptObject**>(slotObject));
    return out;
}

/**
 * Address: 0x004C8BB0 (FUN_004C8BB0, sub_4C8BB0)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CScriptObject*` slot.
 */
RRef MoveCScriptObjectPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CScriptObject**>(slotObject);
    if (slot) {
        *slot = *TryUpcastCScriptObjectPointerSlotOrThrow(*sourceRef);
    }
    else {
        slot = nullptr;
    }

    RRef out{};
    out = gpg::MakeRRef<moho::CScriptObject*>(slot);
    return out;
}

  /**
   * Address: 0x00C09760 (FUN_00C09760, atexit destructor of the gpg::Rect2iTypeInfo object)
   */
  [[nodiscard]] gpg::Rect2iTypeInfo& GetRect2iTypeInfo() noexcept
  {
    static gpg::Rect2iTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00C097C0 (FUN_00C097C0, atexit destructor of the gpg::Rect2fTypeInfo object)
   */
  [[nodiscard]] gpg::Rect2fTypeInfo& GetRect2fTypeInfo() noexcept
  {
    static gpg::Rect2fTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BE9DB0 (FUN_00BE9DB0, register_Rect2iTypeInfo)
   *
   * What it does:
   * Constructs the `Rect2<int>` reflection type descriptor, whose constructor
   * preregisters it under `typeid(Rect2i)`.
   */
  void register_Rect2iTypeInfo()
  {
    (void)GetRect2iTypeInfo();
  }

  /**
   * Address: 0x00BE9E50 (FUN_00BE9E50, register_Rect2fTypeInfo)
   *
   * What it does:
   * Constructs the `Rect2<float>` reflection type descriptor, whose
   * constructor preregisters it under `typeid(Rect2f)`.
   */
  void register_Rect2fTypeInfo()
  {
    (void)GetRect2fTypeInfo();
  }
}

namespace gpg
{

// ---------------------------------------------------------------------------
// gpg::RVectorType<moho::SimArmy*> — reflection of std::vector<moho::SimArmy*>.
// First exemplar of the RVectorType<T> family (22 element types). Vtable
// @ 0x00E34778 (primary) / 0x00E347A8 (RIndexed subobject @ +0x64).
// ---------------------------------------------------------------------------


}

namespace gpg
{
  [[nodiscard]] REnumType::ROptionValue* AppendEnumOptionValue(
    msvc8::vector<REnumType::ROptionValue>& options,
    const REnumType::ROptionValue& value
  );
}

// windows.h, pulled in above, renames GetObject; RRef declares it under its own name.
#ifdef GetObject
#undef GetObject
#endif
