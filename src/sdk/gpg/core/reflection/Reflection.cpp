#include "Reflection.h"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <sstream>
#include <stdexcept>

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
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityMotor.h"
#include "moho/entity/EntityTransformPayload.h"
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
#include "moho/ui/UiRuntimeTypes.h"
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
#include "moho/unit/tasks/CUnitAssistMoveTask.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"
#include "moho/unit/tasks/CUnitCallLandTransport.h"
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
using namespace gpg;


namespace gpg
{
/**
 * Address: 0x005F1A20 (FUN_005F1A20)
 * Address: 0x005F44A0 (FUN_005F44A0)
 * Address: 0x005FBB50 (FUN_005FBB50)
 * Address: 0x005FBC40 (FUN_005FBC40)
 * Address: 0x005FBD00 (FUN_005FBD00)
 * Address: 0x005FBDC0 (FUN_005FBDC0)
 * Address: 0x005FBE80 (FUN_005FBE80)
 * Address: 0x005FBFC0 (FUN_005FBFC0)
 * Address: 0x00602360 (FUN_00602360)
 * Address: 0x00602420 (FUN_00602420)
 * Address: 0x006024E0 (FUN_006024E0)
 * Address: 0x006025A0 (FUN_006025A0)
 * Address: 0x006052D0 (FUN_006052D0)
 * Address: 0x006076E0 (FUN_006076E0)
 * Address: 0x006077A0 (FUN_006077A0)
 * Address: 0x00607860 (FUN_00607860)
 * Address: 0x0060BA90 (FUN_0060BA90)
 * Address: 0x0060BB50 (FUN_0060BB50)
 * Address: 0x0060BC10 (FUN_0060BC10)
 * Address: 0x00610070 (FUN_00610070)
 * Address: 0x00614850 (FUN_00614850)
 * Address: 0x00617760 (FUN_00617760)
 * Address: 0x0061E4B0 (FUN_0061E4B0)
 * Address: 0x006221C0 (FUN_006221C0)
 * Address: 0x00623B30 (FUN_00623B30)
 * Address: 0x00626F40 (FUN_00626F40)
 * Address: 0x00627000 (FUN_00627000)
 * Address: 0x00632D30 (FUN_00632D30)
 * Address: 0x006350F0 (FUN_006350F0)
 * Address: 0x00638690 (FUN_00638690)
 * Address: 0x0064E270 (FUN_0064E270)
 * Address: 0x0064E2B0 (FUN_0064E2B0)
 * Address: 0x00650B90 (FUN_00650B90)
 * Address: 0x00650BD0 (FUN_00650BD0)
 * Address: 0x00650C10 (FUN_00650C10)
 * Address: 0x00653280 (FUN_00653280)
 * Address: 0x00657B30 (FUN_00657B30)
 * Address: 0x0065F100 (FUN_0065F100)
 * Address: 0x00699E80 (FUN_00699E80)
 * Address: 0x006DB800 (FUN_006DB800)
 * Address: 0x0076E7C0 (FUN_0076E7C0)
 * Address: 0x00897450 (FUN_00897450)
 *
 * What it does:
 * Writes one `gpg::RType` lifecycle callback lane set (`newRef`, `ctorRef`,
 * `delete`, `destruct`) into one destination type-info object.
 */
[[nodiscard]] RType* BindRTypeLifecycleCallbacks(
  RType* const typeInfo,
  const RType::new_ref_func_t newRefFunc,
  const RType::ctor_ref_func_t ctorRefFunc,
  const RType::delete_func_t deleteFunc,
  const RType::dtr_func_t dtrFunc
) noexcept
{
  if (typeInfo == nullptr) {
    return nullptr;
  }

  typeInfo->newRefFunc_ = newRefFunc;
  typeInfo->ctorRefFunc_ = ctorRefFunc;
  typeInfo->deleteFunc_ = deleteFunc;
  typeInfo->dtrFunc_ = dtrFunc;
  return typeInfo;
}
} // namespace gpg

namespace
{
  /**
   * Address: 0x00525DA0 (FUN_00525DA0)
   *
   * What it does:
   * Builds one temporary reflected `RUnitBlueprint` reference and copies its
   * `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildRUnitBlueprintRefIntoOutput(
    moho::RUnitBlueprint* const blueprint,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_RUnitBlueprint(&ref, blueprint);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x00525E30 (FUN_00525E30)
   *
   * What it does:
   * Builds one temporary reflected `RUnitBlueprintWeapon` reference and copies
   * its `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildRUnitBlueprintWeaponRefIntoOutput(
    moho::RUnitBlueprintWeapon* const weaponBlueprint,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_RUnitBlueprintWeapon(&ref, weaponBlueprint);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x00525E60 (FUN_00525E60)
   *
   * What it does:
   * Builds one temporary reflected `float` reference and copies its
   * `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildFloatRefIntoOutput(float* const value, gpg::RRef* const out)
  {
    gpg::RRef ref{};
    (void)gpg::RRef_float(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  struct ReflectionAdapterLaneView
  {
    std::uint32_t mAdapterTag;
    std::uint32_t mPayloadLane0;
    std::uint32_t mPayloadLane1;
  };

  struct ReflectionAdapterSwapTailView
  {
    std::uint32_t mAdapterTag;
    std::uint32_t mPayloadLane0;
    std::uint32_t mPayloadLane1;
    std::uint32_t mPayloadLane2;
  };

  [[nodiscard]] std::uint32_t* CopyAdapterPayloadLane0(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    *outLane = source->mPayloadLane0;
    return outLane;
  }

  [[nodiscard]] std::uint32_t* CopyAdapterPayloadLane1(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    *outLane = source->mPayloadLane1;
    return outLane;
  }

  [[nodiscard]] ReflectionAdapterSwapTailView* SwapAdapterPayloadTail(
    ReflectionAdapterSwapTailView* const left,
    ReflectionAdapterSwapTailView* const right
  )
  {
    std::uint32_t lane = right->mPayloadLane0;
    right->mPayloadLane0 = left->mPayloadLane0;
    left->mPayloadLane0 = lane;

    lane = right->mPayloadLane1;
    right->mPayloadLane1 = left->mPayloadLane1;
    left->mPayloadLane1 = lane;

    lane = right->mPayloadLane2;
    right->mPayloadLane2 = left->mPayloadLane2;
    left->mPayloadLane2 = lane;
    return left;
  }

  struct ReflectionWordTripleLaneView
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
  };
  static_assert(sizeof(ReflectionWordTripleLaneView) == 0x0C, "ReflectionWordTripleLaneView size must be 0x0C");

  struct ReflectionWordBytePairLaneView
  {
    std::uint32_t lane00;
    std::uint8_t lane04;
    std::uint8_t pad05[3];
  };
  static_assert(sizeof(ReflectionWordBytePairLaneView) == 0x08, "ReflectionWordBytePairLaneView size must be 0x08");
  static_assert(
    offsetof(ReflectionWordBytePairLaneView, lane04) == 0x04,
    "ReflectionWordBytePairLaneView::lane04 offset must be 0x04"
  );

  struct ReflectionWordTripleByteLaneView
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint8_t lane0C;
    std::uint8_t pad0D[3];
  };
  static_assert(sizeof(ReflectionWordTripleByteLaneView) == 0x10, "ReflectionWordTripleByteLaneView size must be 0x10");
  static_assert(
    offsetof(ReflectionWordTripleByteLaneView, lane0C) == 0x0C,
    "ReflectionWordTripleByteLaneView::lane0C offset must be 0x0C"
  );

  struct ReflectionInlineTreeBootstrapLaneView
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint32_t lane0C;
    std::uint32_t* parent;
    std::uint32_t* left;
    std::uint32_t* right;
    std::uint32_t* self;
    std::uint32_t inlineWord0;
    std::uint32_t inlineWord1;
  };
  static_assert(
    offsetof(ReflectionInlineTreeBootstrapLaneView, inlineWord0) == 0x20,
    "ReflectionInlineTreeBootstrapLaneView::inlineWord0 offset must be 0x20"
  );

  /**
   * Address: 0x005567C0 (FUN_005567C0)
   *
   * What it does:
   * Initializes one `{dword,byte}` adapter lane from source word/byte slots.
   */
  [[maybe_unused]] [[nodiscard]] ReflectionWordBytePairLaneView* InitializeReflectionWordBytePairLane(
    ReflectionWordBytePairLaneView* const outLane,
    const std::uint32_t* const wordSource,
    const std::uint8_t* const byteSource
  ) noexcept
  {
    outLane->lane00 = *wordSource;
    outLane->lane04 = *byteSource;
    return outLane;
  }

  /**
   * Address: 0x005567D0 (FUN_005567D0)
   *
   * What it does:
   * Initializes one `{dword,dword,dword}` adapter lane from one source head
   * word and two caller-provided tail words.
   */
  [[maybe_unused]] [[nodiscard]] ReflectionWordTripleLaneView* InitializeReflectionWordTripleLane(
    ReflectionWordTripleLaneView* const outLane,
    const std::uint32_t* const headWordSource,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    outLane->lane00 = *headWordSource;
    outLane->lane04 = lane04;
    outLane->lane08 = lane08;
    return outLane;
  }

  /**
   * Address: 0x00556E50 (FUN_00556E50)
   *
   * What it does:
   * Initializes one inline tree-bootstrap lane with zeroed count lanes and
   * self-linked sentinel pointers.
   */
  [[maybe_unused]] [[nodiscard]] ReflectionInlineTreeBootstrapLaneView* InitializeReflectionInlineTreeBootstrapLane(
    ReflectionInlineTreeBootstrapLaneView* const outLane
  ) noexcept
  {
    outLane->lane00 = 0u;
    outLane->lane08 = 0u;
    outLane->parent = &outLane->inlineWord0;
    outLane->left = &outLane->inlineWord0;
    outLane->right = &outLane->inlineWord0 + 2;
    outLane->self = &outLane->inlineWord0;
    return outLane;
  }

  /**
   * Address: 0x00557850 (FUN_00557850)
   *
   * What it does:
   * Initializes one `{dword,dword,dword,byte}` reflection adapter lane from
   * scalar input lanes.
   */
  [[maybe_unused]] [[nodiscard]] ReflectionWordTripleByteLaneView* InitializeReflectionWordTripleByteLane(
    ReflectionWordTripleByteLaneView* const outLane,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint8_t lane0C
  ) noexcept
  {
    outLane->lane00 = lane00;
    outLane->lane04 = lane04;
    outLane->lane08 = lane08;
    outLane->lane0C = lane0C;
    return outLane;
  }

  /**
   * Address: 0x00557B10 (FUN_00557B10)
   *
   * What it does:
   * Copies one `{dword,dword,dword}` payload triple and one trailing byte into
   * destination reflection adapter storage.
   */
  [[maybe_unused]] [[nodiscard]] ReflectionWordTripleByteLaneView* CopyReflectionWordTripleAndByteLane(
    ReflectionWordTripleByteLaneView* const outLane,
    const ReflectionWordTripleLaneView* const sourceWords,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outLane->lane00 = sourceWords->lane00;
    outLane->lane04 = sourceWords->lane04;
    outLane->lane08 = sourceWords->lane08;
    outLane->lane0C = *sourceByte;
    return outLane;
  }

  /**
   * Address: 0x00557D80 (FUN_00557D80)
   *
   * What it does:
   * Writes the invalid `EntId` sentinel word (`0xF0000000`) to output storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* WriteInvalidEntIdSentinelWordLaneB(
    std::uint32_t* const outWord
  ) noexcept
  {
    *outWord = 0xF0000000u;
    return outWord;
  }

  /**
   * Address: 0x0051AAA0 (FUN_0051AAA0)
   *
   * What it does:
   * Copies one low payload lane (`+0x04`) from the mesh-blueprint adapter
   * frame into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRMeshBlueprintAdapterPayloadLane0(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    return CopyAdapterPayloadLane0(outLane, source);
  }

  /**
   * Address: 0x0051AAB0 (FUN_0051AAB0)
   *
   * What it does:
   * Copies one high payload lane (`+0x08`) from the mesh-blueprint adapter
   * frame into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRMeshBlueprintAdapterPayloadLane1(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    return CopyAdapterPayloadLane1(outLane, source);
  }

  /**
   * Address: 0x00525EC0 (FUN_00525EC0)
   *
   * What it does:
   * Swaps three payload lanes (`+0x04/+0x08/+0x0C`) between two
   * unit-blueprint adapter frames while preserving the adapter tag lane.
   */
  [[maybe_unused]] ReflectionAdapterSwapTailView* SwapRUnitBlueprintAdapterPayloadTail(
    ReflectionAdapterSwapTailView* const left,
    ReflectionAdapterSwapTailView* const right
  )
  {
    return SwapAdapterPayloadTail(left, right);
  }

  /**
   * Address: 0x00525F30 (FUN_00525F30)
   *
   * What it does:
   * Swaps three payload lanes (`+0x04/+0x08/+0x0C`) between two
   * unit-blueprint-weapon adapter frames while preserving the adapter tag lane.
   */
  [[maybe_unused]] ReflectionAdapterSwapTailView* SwapRUnitBlueprintWeaponAdapterPayloadTail(
    ReflectionAdapterSwapTailView* const left,
    ReflectionAdapterSwapTailView* const right
  )
  {
    return SwapAdapterPayloadTail(left, right);
  }

  /**
   * Address: 0x00526C20 (FUN_00526C20)
   *
   * What it does:
   * Copies one low payload lane (`+0x04`) from a unit-blueprint adapter
   * frame into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRUnitBlueprintAdapterPayloadLane0(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    return CopyAdapterPayloadLane0(outLane, source);
  }

  /**
   * Address: 0x00526C30 (FUN_00526C30)
   *
   * What it does:
   * Copies one high payload lane (`+0x08`) from a unit-blueprint adapter
   * frame into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRUnitBlueprintAdapterPayloadLane1(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    return CopyAdapterPayloadLane1(outLane, source);
  }

  /**
   * Address: 0x00526C40 (FUN_00526C40)
   *
   * What it does:
   * Copies one low payload lane (`+0x04`) from a unit-blueprint-weapon adapter
   * frame into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRUnitBlueprintWeaponAdapterPayloadLane0(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    return CopyAdapterPayloadLane0(outLane, source);
  }

  /**
   * Address: 0x00526C50 (FUN_00526C50)
   *
   * What it does:
   * Copies one high payload lane (`+0x08`) from a unit-blueprint-weapon adapter
   * frame into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRUnitBlueprintWeaponAdapterPayloadLane1(
    std::uint32_t* const outLane,
    const ReflectionAdapterLaneView* const source
  )
  {
    return CopyAdapterPayloadLane1(outLane, source);
  }

  /**
   * Address: 0x00599A00 (FUN_00599A00)
   *
   * What it does:
   * Builds one temporary reflected `IAiCommandDispatchImpl` reference and
   * copies its `(mObj,mType)` pair into the caller-provided output lane.
   */
  [[maybe_unused]] gpg::RRef* BuildIAiCommandDispatchImplRefIntoOutput(
    moho::IAiCommandDispatchImpl* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_IAiCommandDispatchImpl(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0059DC30 (FUN_0059DC30)
   *
   * What it does:
   * Builds one temporary reflected `IFormationInstance*` pointer-slot
   * reference and copies its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildIFormationInstancePointerRefIntoOutput(
    moho::IFormationInstance** const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_IFormationInstance_P(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0059DD90 (FUN_0059DD90)
   *
   * What it does:
   * Builds one temporary reflected `CAiFormationDBImpl` reference and copies
   * its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildCAiFormationDBImplRefIntoOutput(
    moho::CAiFormationDBImpl* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CAiFormationDBImpl(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0059DDD0 (FUN_0059DDD0)
   *
   * What it does:
   * Builds one temporary reflected `IFormationInstance` reference and copies
   * its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildIFormationInstanceRefIntoOutput(
    moho::IFormationInstance* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_IFormationInstance(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x005A1CB0 (FUN_005A1CB0)
   *
   * What it does:
   * Builds one temporary reflected `CAiBuilderImpl` reference and copies its
   * `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildCAiBuilderImplRefIntoOutput(
    moho::CAiBuilderImpl* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CAiBuilderImpl(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x005A1E60 (FUN_005A1E60)
   *
   * What it does:
   * Builds one temporary reflected `RUnitBlueprint*` pointer-slot reference
   * and copies its `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildRUnitBlueprintPointerRefIntoOutput(
    moho::RUnitBlueprint** const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_RUnitBlueprint_P(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x005B5710 (FUN_005B5710)
   *
   * What it does:
   * Builds one temporary reflected `CPathPoint` reference and copies its
   * `(mObj,mType)` pair into output.
   */
  [[maybe_unused]] gpg::RRef* BuildCPathPointRefIntoOutput(
    moho::CPathPoint* const value,
    gpg::RRef* const out
  )
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CPathPoint(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  /**
   * Address: 0x0050D390 (FUN_0050D390)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `gpg::Rect2i`.
   */
  RType* CachedRect2iType()
  {
    RType* type = gpg::Rect2i::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  RType* CachedRect2fType()
  {
    RType* type = gpg::Rect2f::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2f));
      gpg::Rect2f::sType = type;
    }
    return type;
  }

  RType* CachedIntType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  RType* CachedBoolType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  RType* CachedStringType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  RType* CachedVector3fType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  RType* CachedRResIdType()
  {
    RType* type = moho::RResId::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RResId));
      moho::RResId::sType = type;
    }
    return type;
  }

  RType* CachedUCharType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(unsigned char));
    }
    return cached;
  }

  RType* CachedEmitterBlueprintCurveType()
  {
    RType* type = moho::REmitterBlueprintCurve::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::REmitterBlueprintCurve));
      moho::REmitterBlueprintCurve::sType = type;
    }
    return type;
  }

  RType* CachedVector4fType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Vector4f));
    }
    return cached;
  }

  RType* CachedVectorStringType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<msvc8::string>));
    }
    return cached;
  }

  RType* CachedSFootprintType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SFootprint));
    }
    return cached;
  }

  /**
   * Address: 0x0040E140 (FUN_0040E140)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for `float`.
   */
  RType* CachedFloatType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

RType* CachedUIntType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(unsigned int));
    }
    return cached;
}

RType* CachedCTaskThreadType()
{
    RType* cached = moho::CTaskThread::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CTaskThread));
        moho::CTaskThread::sType = cached;
    }
    return cached;
}

RType* CachedCAcquireTargetTaskType()
{
    RType* cached = moho::CAcquireTargetTask::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CAcquireTargetTask));
        moho::CAcquireTargetTask::sType = cached;
    }
    return cached;
}

RType* CachedEntityType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Entity));
    }
    return cached;
}

RType* CachedCEconomyEventType()
{
    RType* cached = moho::CEconomyEvent::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CEconomyEvent));
        moho::CEconomyEvent::sType = cached;
    }
    return cached;
}

RType* CachedCLuaConOutputHandlerType()
{
    RType* cached = moho::CLuaConOutputHandler::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CLuaConOutputHandler));
        moho::CLuaConOutputHandler::sType = cached;
    }
    return cached;
}

RType* CachedCScriptObjectType()
{
    RType* cached = moho::CScriptObject::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CScriptObject));
        moho::CScriptObject::sType = cached;
    }
    return cached;
}

RType* CachedCSndParamsType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CSndParams));
    }
    return cached;
}

RType* CachedIFormationInstanceType()
{
    RType* cached = moho::IFormationInstance::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::IFormationInstance));
        moho::IFormationInstance::sType = cached;
    }
    return cached;
}

RType* CachedRUnitBlueprintType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::RUnitBlueprint));
    }
    return cached;
}

RType* CachedReconBlipType()
{
    RType* cached = moho::ReconBlip::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::ReconBlip));
        moho::ReconBlip::sType = cached;
    }
    return cached;
}

RType* CachedCArmyStatItemType()
{
    RType* cached = moho::CArmyStatItem::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CArmyStatItem));
        moho::CArmyStatItem::sType = cached;
    }
    return cached;
}

RType* CachedUnitWeaponType()
{
    RType* cached = moho::UnitWeapon::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::UnitWeapon));
        moho::UnitWeapon::sType = cached;
    }
    return cached;
}

RType* CachedIAniManipulatorType()
{
    RType* cached = moho::IAniManipulator::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::IAniManipulator));
        moho::IAniManipulator::sType = cached;
    }
    return cached;
}

RType* CachedIEffectType()
{
    RType* cached = moho::IEffect::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::IEffect));
        moho::IEffect::sType = cached;
    }
    return cached;
}

RType* CachedCUnitCommandType()
{
    RType* cached = moho::CUnitCommand::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CUnitCommand));
        moho::CUnitCommand::sType = cached;
    }
    return cached;
}

RType* CachedRBlueprintType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::RBlueprint));
    }
    return cached;
}

  struct LegacyRTypeMapNodeRuntime
  {
    LegacyRTypeMapNodeRuntime* left;
    LegacyRTypeMapNodeRuntime* parent;
    LegacyRTypeMapNodeRuntime* right;
    void* payload0;
    void* payload1;
    std::uint8_t color;
    std::uint8_t isNil;
    std::uint16_t padding;
  };

  /**
   * Address: 0x008DA1A0 (FUN_008DA1A0, func_CreateRTypeNode)
   *
   * What it does:
   * Allocates and initializes one red-black tree node header used by the
   * preregistered RTTI map bootstrap lane.
   */
  [[maybe_unused]] LegacyRTypeMapNodeRuntime* AllocatePreregisteredRTypeMapNode()
  {
    auto* const node = static_cast<LegacyRTypeMapNodeRuntime*>(::operator new(sizeof(LegacyRTypeMapNodeRuntime)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->payload0 = nullptr;
    node->payload1 = nullptr;
    node->color = 1u;
    node->isNil = 0u;
    node->padding = 0u;
    return node;
  }

  /**
   * Address: 0x008DA1F0 (FUN_008DA1F0, func_CreateRTypeNode_0)
   *
   * What it does:
   * Allocates and initializes one red-black tree node header used by the
   * named runtime type map bootstrap lane.
   */
  [[maybe_unused]] LegacyRTypeMapNodeRuntime* AllocateRuntimeTypeMapNode()
  {
    auto* const node = static_cast<LegacyRTypeMapNodeRuntime*>(::operator new(sizeof(LegacyRTypeMapNodeRuntime)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->payload0 = nullptr;
    node->payload1 = nullptr;
    node->color = 1u;
    node->isNil = 0u;
    node->padding = 0u;
    return node;
  }

  constexpr const char* kReflectionHeaderPath = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.h";

  template <class TPointee>
  void AssignPointerSlotWithTypeCache(void* const obj, const gpg::RRef& from, gpg::RType*& typeCache)
  {
    auto* const slot = static_cast<TPointee**>(obj);
    if (!slot) {
      gpg::HandleAssertFailure("void_pptr", 663, kReflectionHeaderPath);
    }

    gpg::RType* pointeeType = typeCache;
    if (!pointeeType) {
      pointeeType = gpg::LookupRType(typeid(TPointee));
      typeCache = pointeeType;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(from, pointeeType);
    if (from.mObj && !upcast.mObj) {
      throw gpg::BadRefCast("type error");
    }

    *slot = static_cast<TPointee*>(upcast.mObj);
  }

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

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildNamedPolymorphicRefWithCache(
    gpg::RRef* const out,
    TObject* const object,
    const char* const unqualifiedTypeName,
    const char* const qualifiedTypeName,
    gpg::RType*& declaredTypeCache,
    TypeInfoCache3& cache
  )
  {
    if (!out) {
      return nullptr;
    }

    gpg::RType* declaredRType = declaredTypeCache;
    if (!declaredRType) {
      declaredRType = gpg::REF_FindTypeNamed(unqualifiedTypeName);
      if (!declaredRType && qualifiedTypeName) {
        declaredRType = gpg::REF_FindTypeNamed(qualifiedTypeName);
      }
      declaredTypeCache = declaredRType;
    }

    out->mObj = object;
    out->mType = declaredRType;
    if (!object) {
      return out;
    }

    const std::type_info* runtimeTypeInfo = nullptr;
    try {
      runtimeTypeInfo = static_cast<const std::type_info*>(__RTtypeid(static_cast<void*>(object)));
    } catch (...) {
      runtimeTypeInfo = nullptr;
    }

    if (!runtimeTypeInfo) {
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

    if (!runtimeRType) {
      return out;
    }

    if (!declaredRType) {
      declaredTypeCache = runtimeRType;
      out->mType = runtimeRType;
      return out;
    }

    if (runtimeRType == declaredRType) {
      return out;
    }

    int32_t baseOffset = 0;
    if (!runtimeRType->IsDerivedFrom(declaredRType, &baseOffset)) {
      gpg::HandleAssertFailure("isDer", 458, kReflectionHeaderPath);
    }

    out->mType = runtimeRType;
    out->mObj = static_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    return out;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildNamedDeclaredRefWithCache(
    gpg::RRef* const out,
    TObject* const object,
    const char* const unqualifiedTypeName,
    const char* const qualifiedTypeName,
    gpg::RType*& declaredTypeCache
  )
  {
    if (!out) {
      return nullptr;
    }

    gpg::RType* declaredRType = declaredTypeCache;
    if (!declaredRType) {
      declaredRType = gpg::REF_FindTypeNamed(unqualifiedTypeName);
      if (!declaredRType && qualifiedTypeName) {
        declaredRType = gpg::REF_FindTypeNamed(qualifiedTypeName);
      }
      declaredTypeCache = declaredRType;
    }

    out->mObj = object;
    out->mType = declaredRType;
    return out;
  }

  gpg::RType* gUIntRRefType = nullptr;
  thread_local TypeInfoCache3 gUIntRRefCache{false, {}};
  gpg::RType* gIntRRefType = nullptr;
  thread_local TypeInfoCache3 gIntRRefCache{false, {}};
  gpg::RType* gFloatRRefType = nullptr;
  thread_local TypeInfoCache3 gFloatRRefCache{false, {}};
  gpg::RType* gBoolRRefType = nullptr;
  thread_local TypeInfoCache3 gBoolRRefCache{false, {}};
  gpg::RType* gVectorBoolReferenceRRefType = nullptr;
  thread_local TypeInfoCache3 gVectorBoolReferenceRRefCache{false, {}};
  gpg::RType* gVector3fRRefType = nullptr;
  thread_local TypeInfoCache3 gVector3fRRefCache{false, {}};
  gpg::RType* gStringRRefType = nullptr;
  thread_local TypeInfoCache3 gStringRRefCache{false, {}};
  gpg::RType* gCharRRefType = nullptr;
  thread_local TypeInfoCache3 gCharRRefCache{false, {}};
  gpg::RType* gShortRRefType = nullptr;
  thread_local TypeInfoCache3 gShortRRefCache{false, {}};
  gpg::RType* gLongRRefType = nullptr;
  thread_local TypeInfoCache3 gLongRRefCache{false, {}};
  gpg::RType* gSCharRRefType = nullptr;
  thread_local TypeInfoCache3 gSCharRRefCache{false, {}};
  gpg::RType* gUCharRRefType = nullptr;
  thread_local TypeInfoCache3 gUCharRRefCache{false, {}};
  gpg::RType* gUShortRRefType = nullptr;
  thread_local TypeInfoCache3 gUShortRRefCache{false, {}};
  gpg::RType* gULongRRefType = nullptr;
  thread_local TypeInfoCache3 gULongRRefCache{false, {}};
  gpg::RType* gEEconResourceRRefType = nullptr;
  thread_local TypeInfoCache3 gEEconResourceRRefCache{false, {}};
  gpg::RType* gEAllianceRRefType = nullptr;
  thread_local TypeInfoCache3 gEAllianceRRefCache{false, {}}; 
  gpg::RType* gETriggerOperatorRRefType = nullptr;
  thread_local TypeInfoCache3 gETriggerOperatorRRefCache{false, {}};
  gpg::RType* gECompareTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gECompareTypeRRefCache{false, {}};
  gpg::RType* gESquadClassRRefType = nullptr;
  thread_local TypeInfoCache3 gESquadClassRRefCache{false, {}}; 
  gpg::RType* gEReconFlagsRRefType = nullptr;
  thread_local TypeInfoCache3 gEReconFlagsRRefCache{false, {}};
  gpg::RType* gEAiTargetTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gEAiTargetTypeRRefCache{false, {}};
  gpg::RType* gESTITargetTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gESTITargetTypeRRefCache{false, {}};
  gpg::RType* gEMauiScrollAxisRRefType = nullptr;
  thread_local TypeInfoCache3 gEMauiScrollAxisRRefCache{false, {}};
  gpg::RType* gEMauiKeyCodeRRefType = nullptr;
  thread_local TypeInfoCache3 gEMauiKeyCodeRRefCache{false, {}};
  gpg::RType* gEMauiEventTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gEMauiEventTypeRRefCache{false, {}};
  gpg::RType* gEUnitCommandTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gEUnitCommandTypeRRefCache{false, {}}; 
  gpg::RType* gEAiResultRRefType = nullptr;
  thread_local TypeInfoCache3 gEAiResultRRefCache{false, {}}; 
  gpg::RType* gEUIStateRRefType = nullptr;
  thread_local TypeInfoCache3 gEUIStateRRefCache{false, {}};
  gpg::RType* gEVisibilityModeRRefType = nullptr;
  thread_local TypeInfoCache3 gEVisibilityModeRRefCache{false, {}};
  gpg::RType* gEUnitStateRRefType = nullptr;
  thread_local TypeInfoCache3 gEUnitStateRRefCache{false, {}};
  gpg::RType* gEFireStateRRefType = nullptr;
  thread_local TypeInfoCache3 gEFireStateRRefCache{false, {}}; 
  gpg::RType* gELayerRRefType = nullptr;
  thread_local TypeInfoCache3 gELayerRRefCache{false, {}};
  gpg::RType* gENetProtocolRRefType = nullptr;
  thread_local TypeInfoCache3 gENetProtocolRRefCache{false, {}};
  gpg::RType* gEIntelRRefType = nullptr;
  thread_local TypeInfoCache3 gEIntelRRefCache{false, {}}; 
  gpg::RType* gEThreatTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gEThreatTypeRRefCache{false, {}};
  gpg::RType* gERuleBPUnitToggleCapsRRefType = nullptr;
  thread_local TypeInfoCache3 gERuleBPUnitToggleCapsRRefCache{false, {}}; 
  gpg::RType* gERuleBPUnitCommandCapsRRefType = nullptr;
  thread_local TypeInfoCache3 gERuleBPUnitCommandCapsRRefCache{false, {}};
  gpg::RType* gESpecialFileTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gESpecialFileTypeRRefCache{false, {}};
  gpg::RType* gEGenericIconTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gEGenericIconTypeRRefCache{false, {}};
  gpg::RType* gCTaskThreadRRefType = nullptr;
  thread_local TypeInfoCache3 gCTaskThreadRRefCache{false, {}};
  gpg::RType* gCLuaTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCLuaTaskRRefCache{false, {}};
  gpg::RType* gCWaitForTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCWaitForTaskRRefCache{false, {}};
  gpg::RType* gCFootPlantManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCFootPlantManipulatorRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAnimationManipulatorRRefCache{false, {}};
  gpg::RType* gCRotateManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCRotateManipulatorRRefCache{false, {}};
  gpg::RType* gCStorageManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCStorageManipulatorRRefCache{false, {}};
  gpg::RType* gCThrustManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gCThrustManipulatorRRefCache{false, {}};
  gpg::RType* gCAniActorRRefType = nullptr;
  thread_local TypeInfoCache3 gCAniActorRRefCache{false, {}};
  gpg::RType* gIAniManipulatorRRefType = nullptr;
  thread_local TypeInfoCache3 gIAniManipulatorRRefCache{false, {}};
  gpg::RType* gSAniManipBindingRRefType = nullptr;
  thread_local TypeInfoCache3 gSAniManipBindingRRefCache{false, {}};
  gpg::RType* gCAcquireTargetTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCAcquireTargetTaskRRefCache{false, {}};
  gpg::RType* gCFireWeaponTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCFireWeaponTaskRRefCache{false, {}};
  gpg::RType* gCUnitCaptureTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCUnitCaptureTaskRRefCache{false, {}};
  gpg::RType* gCUnitGetBuiltTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCUnitGetBuiltTaskRRefCache{false, {}};
  gpg::RType* gCUnitGuardTaskRRefType = nullptr;
  thread_local TypeInfoCache3 gCUnitGuardTaskRRefCache{false, {}};
  gpg::RType* gCUnitUnloadUnitsRRefType = nullptr;
  thread_local TypeInfoCache3 gCUnitUnloadUnitsRRefCache{false, {}};
  thread_local TypeInfoCache3 gManyToOneListenerEProjectileImpactEventRRefCache{false, {}};
  gpg::RType* gCAiAttackerImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCAiAttackerImplRRefCache{false, {}};
  gpg::RType* gCAiTransportImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCAiTransportImplRRefCache{false, {}};
  gpg::RType* gCAiReconDBImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCAiReconDBImplRRefCache{false, {}};
  gpg::RType* gCAiSteeringImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCAiSteeringImplRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiSiloBuildImplRRefCache{false, {}};
  gpg::RType* gLAiAttackerImplRRefType = nullptr;
  thread_local TypeInfoCache3 gLAiAttackerImplRRefCache{false, {}};
  gpg::RType* gIAiSteeringRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiSteeringRRefCache{false, {}};
  thread_local TypeInfoCache3 gIAiCommandDispatchImplRRefCache{false, {}};
  gpg::RType* gIAiCommandDispatchRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiCommandDispatchRRefCache{false, {}};
  gpg::RType* gIAiNavigatorRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiNavigatorRRefCache{false, {}};
  gpg::RType* gIAiBuilderRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiBuilderRRefCache{false, {}};
  gpg::RType* gIAiSiloBuildRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiSiloBuildRRefCache{false, {}};
  gpg::RType* gIAiTransportRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiTransportRRefCache{false, {}};
  gpg::RType* gListenerECommandEventRRefType = nullptr;
  thread_local TypeInfoCache3 gListenerECommandEventRRefCache{false, {}};
  gpg::RType* gListenerEUnitCommandQueueStatusRRefType = nullptr;
  thread_local TypeInfoCache3 gListenerEUnitCommandQueueStatusRRefCache{false, {}};
  gpg::RType* gListenerNavPathRRefType = nullptr;
  thread_local TypeInfoCache3 gListenerNavPathRRefCache{false, {}};
  gpg::RType* gListenerEAiNavigatorEventRRefType = nullptr;
  thread_local TypeInfoCache3 gListenerEAiNavigatorEventRRefCache{false, {}};
  gpg::RType* gListenerEAiAttackerEventRRefType = nullptr;
  thread_local TypeInfoCache3 gListenerEAiAttackerEventRRefCache{false, {}};
  gpg::RType* gListenerEAiTransportEventRRefType = nullptr;
  thread_local TypeInfoCache3 gListenerEAiTransportEventRRefCache{false, {}};
  gpg::RType* gSAssignedLocInfoRRefType = nullptr;
  gpg::RType* gSPickUpInfoRRefType = nullptr;
  gpg::RType* gSAttachPointRRefType = nullptr;
  thread_local TypeInfoCache3 gSAttachPointRRefCache{false, {}};
  gpg::RType* gSPointVectorRRefType = nullptr;
  thread_local TypeInfoCache3 gSPointVectorRRefCache{false, {}};
  thread_local TypeInfoCache3 gSAiReservedTransportBoneRRefCache{false, {}};
  gpg::RType* gIAiFormationDBRRefType = nullptr;
  thread_local TypeInfoCache3 gIAiFormationDBRRefCache{false, {}};
  gpg::RType* gISimResourcesRRefType = nullptr;
  thread_local TypeInfoCache3 gISimResourcesRRefCache{false, {}};
  thread_local TypeInfoCache3 gIAiAttackerRRefCache{false, {}};
  thread_local TypeInfoCache3 gIAiReconDBRRefCache{false, {}};
  gpg::RType* gIPathTravelerRRefType = nullptr;
  thread_local TypeInfoCache3 gIPathTravelerRRefCache{false, {}};
  gpg::RType* gShieldRRefType = nullptr;
  thread_local TypeInfoCache3 gShieldRRefCache{false, {}};
  thread_local TypeInfoCache3 gIEffectManagerRRefCache{false, {}};
  thread_local TypeInfoCache3 gReconBlipRRefCache{false, {}};
  thread_local TypeInfoCache3 gSPerArmyReconInfoRRefCache{false, {}};
  gpg::RType* gIEffectRRefType = nullptr;
  thread_local TypeInfoCache3 gIEffectRRefCache{false, {}};
  gpg::RType* gCEffectManagerImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCEffectManagerImplRRefCache{false, {}};
  gpg::RType* gArmyLaunchInfoRRefType = nullptr;
  gpg::RType* gUnitWeaponInfoRRefType = nullptr;
  gpg::RType* gSOffsetInfoRRefType = nullptr;
  gpg::RType* gCEfxEmitterRRefType = nullptr;
  thread_local TypeInfoCache3 gCEfxEmitterRRefCache{false, {}};
  gpg::RType* gCEfxTrailEmitterRRefType = nullptr;
  thread_local TypeInfoCache3 gCEfxTrailEmitterRRefCache{false, {}};
  thread_local TypeInfoCache3 gCEfxBeamRRefCache{false, {}};
  gpg::RType* gCountedPtrCParticleTextureRRefType = nullptr;
  thread_local TypeInfoCache3 gCountedPtrCParticleTextureRRefCache{false, {}};
  gpg::RType* gSEfxCurveRRefType = nullptr;
  thread_local TypeInfoCache3 gSEfxCurveRRefCache{false, {}};
  gpg::RType* gCAniPoseRRefType = nullptr;
  thread_local TypeInfoCache3 gCAniPoseRRefCache{false, {}}; 
  gpg::RType* gCAniPoseBoneRRefType = nullptr;
  thread_local TypeInfoCache3 gCAniPoseBoneRRefCache{false, {}};
  gpg::RType* gSharedPtrCAniPoseRRefType = nullptr;
  thread_local TypeInfoCache3 gSharedPtrCAniPoseRRefCache{false, {}};
  thread_local TypeInfoCache3 gCScriptObjectRRefCache{false, {}};
  thread_local TypeInfoCache3 gCScriptEventRRefCache{false, {}};
  gpg::RType* gCSndParamsRRefType = nullptr;
  thread_local TypeInfoCache3 gCSndParamsRRefCache{false, {}};
  gpg::RType* gCSndVarRRefType = nullptr;
  thread_local TypeInfoCache3 gCSndVarRRefCache{false, {}};
  gpg::RType* gHSoundRRefType = nullptr;
  thread_local TypeInfoCache3 gHSoundRRefCache{false, {}};
  gpg::RType* gISoundManagerRRefType = nullptr;
  thread_local TypeInfoCache3 gISoundManagerRRefCache{false, {}};
  thread_local TypeInfoCache3 gSAudioRequestRRefCache{false, {}};
  gpg::RType* gSPhysConstantsRRefType = nullptr;
  thread_local TypeInfoCache3 gSPhysConstantsRRefCache{false, {}};
  gpg::RType* gSPhysBodyRRefType = nullptr;
  thread_local TypeInfoCache3 gSPhysBodyRRefCache{false, {}};
  gpg::RType* gEntityRRefType = nullptr;
  thread_local TypeInfoCache3 gEntityRRefCache{false, {}};
  thread_local TypeInfoCache3 gCollisionBeamEntityRRefCache{false, {}};
  thread_local TypeInfoCache3 gPropRRefCache{false, {}};
  gpg::RType* gEntIdRRefType = nullptr;
  thread_local TypeInfoCache3 gEntIdRRefCache{false, {}};
  gpg::RType* gWeakPtrEntityRRefType = nullptr;
  thread_local TypeInfoCache3 gWeakPtrEntityRRefCache{false, {}};
  gpg::RType* gEntityDBRRefType = nullptr;
  thread_local TypeInfoCache3 gEntityDBRRefCache{false, {}};
  thread_local TypeInfoCache3 gEntitySetBaseRRefCache{false, {}};
  gpg::RType* gUnitRRefType = nullptr;
  thread_local TypeInfoCache3 gUnitRRefCache{false, {}}; 
  gpg::RType* gIUnitRRefType = nullptr;
  thread_local TypeInfoCache3 gIUnitRRefCache{false, {}};
  gpg::RType* gWeakPtrIUnitRRefType = nullptr;
  thread_local TypeInfoCache3 gWeakPtrIUnitRRefCache{false, {}};
  gpg::RType* gSSTIEntityAttachInfoRRefType = nullptr;
  thread_local TypeInfoCache3 gSSTIEntityAttachInfoRRefCache{false, {}};
  gpg::RType* gPathQueueRRefType = nullptr;
  thread_local TypeInfoCache3 gPathQueueRRefCache{false, {}};
  gpg::RType* gRUnitBlueprintRRefType = nullptr;
  thread_local TypeInfoCache3 gRUnitBlueprintRRefCache{false, {}}; 
  gpg::RType* gRBlueprintRRefType = nullptr;
  thread_local TypeInfoCache3 gRBlueprintRRefCache{false, {}};
  gpg::RType* gRUnitBlueprintWeaponRRefType = nullptr;
  thread_local TypeInfoCache3 gRUnitBlueprintWeaponRRefCache{false, {}}; 
  gpg::RType* gRRuleGameRulesRRefType = nullptr;
  thread_local TypeInfoCache3 gRRuleGameRulesRRefCache{false, {}};  
  thread_local TypeInfoCache3 gSRuleFootprintsBlueprintRRefCache{false, {}};
  thread_local TypeInfoCache3 gRScmResourceRRefCache{false, {}};
  gpg::RType* gResourceDepositRRefType = nullptr;
  thread_local TypeInfoCache3 gResourceDepositRRefCache{false, {}};
  gpg::RType* gREmitterBlueprintRRefType = nullptr;
  thread_local TypeInfoCache3 gREmitterBlueprintRRefCache{false, {}};
  thread_local TypeInfoCache3 gREmitterCurveKeyRRefCache{false, {}};
  gpg::RType* gREmitterBlueprintCurveRRefType = nullptr;
  thread_local TypeInfoCache3 gREmitterBlueprintCurveRRefCache{false, {}};
  thread_local TypeInfoCache3 gRBeamBlueprintRRefCache{false, {}};
  gpg::RType* gRTrailBlueprintRRefType = nullptr;
  thread_local TypeInfoCache3 gRTrailBlueprintRRefCache{false, {}};
  thread_local TypeInfoCache3 gRProjectileBlueprintRRefCache{false, {}};
  thread_local TypeInfoCache3 gRMeshBlueprintRRefCache{false, {}};
  gpg::RType* gRMeshBlueprintLODRRefType = nullptr;
  thread_local TypeInfoCache3 gRMeshBlueprintLODRRefCache{false, {}};
  thread_local TypeInfoCache3 gRPropBlueprintRRefCache{false, {}};
  gpg::RType* gCColPrimitiveSphere3fRRefType = nullptr;
  thread_local TypeInfoCache3 gCColPrimitiveSphere3fRRefCache{false, {}};
  gpg::RType* gCColPrimitiveBox3fRRefType = nullptr;
  thread_local TypeInfoCache3 gCColPrimitiveBox3fRRefCache{false, {}};
  gpg::RType* gCColPrimitiveBaseRRefType = nullptr;
  thread_local TypeInfoCache3 gCColPrimitiveBaseRRefCache{false, {}};
  thread_local TypeInfoCache3 gMotorRRefCache{false, {}};
  thread_local TypeInfoCache3 gEntityCategorySetRRefCache{false, {}};
  gpg::RType* gCOGridRRefType = nullptr;
  thread_local TypeInfoCache3 gCOGridRRefCache{false, {}}; 
  thread_local TypeInfoCache3 gCAiBrainRRefCache{false, {}}; 
  thread_local TypeInfoCache3 gCAiPersonalityRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiBuilderImplRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiNavigatorLandRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiNavigatorAirRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiPathNavigatorRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiPathFinderRRefCache{false, {}};
  thread_local TypeInfoCache3 gCAiPathSplineRRefCache{false, {}};
  gpg::RType* gCAiFormationInstanceRRefType = nullptr;
  thread_local TypeInfoCache3 gCAiFormationInstanceRRefCache{false, {}};
  gpg::RType* gCAiFormationDBImplRRefType = nullptr;
  thread_local TypeInfoCache3 gCAiFormationDBImplRRefCache{false, {}};
  thread_local TypeInfoCache3 gSimArmyRRefCache{false, {}}; 
  thread_local TypeInfoCache3 gCArmyImplRRefCache{false, {}};
  gpg::RType* gLaunchInfoNewRRefType = nullptr;
  thread_local TypeInfoCache3 gLaunchInfoNewRRefCache{false, {}};
  gpg::RType* gCSimResourcesRRefType = nullptr;
  thread_local TypeInfoCache3 gCSimResourcesRRefCache{false, {}};
  gpg::RType* gCUnitCommandRRefType = nullptr;
  thread_local TypeInfoCache3 gCUnitCommandRRefCache{false, {}}; 
  gpg::RType* gWeakPtrCUnitCommandRRefType = nullptr;
  thread_local TypeInfoCache3 gWeakPtrCUnitCommandRRefCache{false, {}};
  gpg::RType* gCCommandDbRRefType = nullptr;
  thread_local TypeInfoCache3 gCCommandDbRRefCache{false, {}};
  thread_local TypeInfoCache3 gCUnitCommandQueueRRefCache{false, {}};
  gpg::RType* gUnitWeaponRRefType = nullptr;
  thread_local TypeInfoCache3 gUnitWeaponRRefCache{false, {}};
  gpg::RType* gCRandomStreamRRefType = nullptr;
  thread_local TypeInfoCache3 gCRandomStreamRRefCache{false, {}};
  gpg::RType* gCPathPointRRefType = nullptr;
  thread_local TypeInfoCache3 gCPathPointRRefCache{false, {}};
  gpg::RType* gSOCellPosRRefType = nullptr;
  thread_local TypeInfoCache3 gSOCellPosRRefCache{false, {}};
  gpg::RType* gHPathCellRRefType = nullptr;
  thread_local TypeInfoCache3 gHPathCellRRefCache{false, {}};
  gpg::RType* gPathTablesRRefType = nullptr;
  thread_local TypeInfoCache3 gPathTablesRRefCache{false, {}};
  thread_local TypeInfoCache3 gCArmyStatsRRefCache{false, {}};
  thread_local TypeInfoCache3 gStatsCArmyStatItemRRefCache{false, {}};
  thread_local TypeInfoCache3 gSConditionRRefCache{false, {}};
  thread_local TypeInfoCache3 gInfluenceGridRRefCache{false, {}};
  thread_local TypeInfoCache3 gSThreatRRefCache{false, {}};
  thread_local TypeInfoCache3 gPositionHistoryRRefCache{false, {}};
  thread_local TypeInfoCache3 gSTriggerRRefCache{false, {}};
  thread_local TypeInfoCache3 gCEconomyEventRRefCache{false, {}};
  thread_local TypeInfoCache3 gCDecalBufferRRefCache{false, {}};
  thread_local TypeInfoCache3 gCDecalHandleRRefCache{false, {}};
  thread_local TypeInfoCache3 gCInfluenceMapRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugCollisionRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugGridRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugRadarRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugNavPathRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugNavWaypointsRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugNavSteeringRRefCache{false, {}};
  thread_local TypeInfoCache3 gRDebugWeaponsRRefCache{false, {}};
  thread_local TypeInfoCache3 gCIntelRRefCache{false, {}};
  thread_local TypeInfoCache3 gCIntelPosHandleRRefCache{false, {}};
  thread_local TypeInfoCache3 gCIntelCounterHandleRRefCache{false, {}};
  thread_local TypeInfoCache3 gCUnitMotionRRefCache{false, {}};
  gpg::RType* gCPlatoonRRefType = nullptr;
  thread_local TypeInfoCache3 gCPlatoonRRefCache{false, {}}; 
  gpg::RType* gSSessionSaveDataRRefType = nullptr;
  thread_local TypeInfoCache3 gSSessionSaveDataRRefCache{false, {}};
  gpg::RType* gIdPoolRRefType = nullptr;
  thread_local TypeInfoCache3 gIdPoolRRefCache{false, {}};
  gpg::RType* gCLuaConOutputHandlerRRefType = nullptr;
  thread_local TypeInfoCache3 gCLuaConOutputHandlerRRefCache{false, {}};
  gpg::RType* gLuaStateRRefType = nullptr;
  thread_local TypeInfoCache3 gLuaStateRRefCache{false, {}};
  gpg::RType* gTStringRRefType = nullptr;
  thread_local TypeInfoCache3 gTStringRRefCache{false, {}};
  gpg::RType* gTableRRefType = nullptr;
  thread_local TypeInfoCache3 gTableRRefCache{false, {}};
  gpg::RType* gLClosureRRefType = nullptr;
  thread_local TypeInfoCache3 gLClosureRRefCache{false, {}};
  gpg::RType* gCClosureRRefType = nullptr;
  thread_local TypeInfoCache3 gCClosureRRefCache{false, {}};
  gpg::RType* gUdataRRefType = nullptr;
  thread_local TypeInfoCache3 gUdataRRefCache{false, {}};
  gpg::RType* gUpValRRefType = nullptr;
  thread_local TypeInfoCache3 gUpValRRefCache{false, {}};
  gpg::RType* gProtoRRefType = nullptr;
  thread_local TypeInfoCache3 gProtoRRefCache{false, {}};
  gpg::RType* gLuaRawStateRRefType = nullptr;
  thread_local TypeInfoCache3 gLuaRawStateRRefCache{false, {}};

/**
 * Address: 0x004023E0 (FUN_004023E0)
 *
 * What it does:
 * Lazily resolves and caches the reflection descriptor for `gpg::RType`.
 */
RType* CachedRTypeDescriptor()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(RType));
    }
    return cached;
}

template <class T>
RType* CachedPointerType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(T*));
    }
    return cached;
}

template <class T>
RRef MakePointerSlotRef(T** const slot)
{
    RRef out{};
    out.mObj = slot;
    out.mType = CachedPointerType<T>();
    return out;
}

template <class T>
T* const* TryUpcastPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, CachedPointerType<T>());
    if (!upcast.mObj) {
        throw gpg::BadRefCast("type error");
    }

    return static_cast<T* const*>(upcast.mObj);
}

template <class TValue>
TValue* TryUpcastValueOrThrow(const RRef& source, const std::type_info& targetTypeInfo, RType*& cachedTargetType)
{
    if (!cachedTargetType) {
        cachedTargetType = gpg::LookupRType(targetTypeInfo);
    }

    const RRef upcast = gpg::REF_UpcastPtr(source, cachedTargetType);
    if (!upcast.mObj) {
        if (!cachedTargetType) {
            cachedTargetType = gpg::LookupRType(targetTypeInfo);
        }

        const char* const sourceName = source.mType ? source.mType->GetName() : "null";
        const char* const targetName = cachedTargetType->GetName();
        throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }

    return static_cast<TValue*>(upcast.mObj);
}

template <class T>
T** TryUpcastPointerSlotWithTypeNameOrThrow(const RRef& source)
{
  RType* const targetType = CachedPointerType<T>();
  const RRef upcast = gpg::REF_UpcastPtr(source, targetType);
  auto* const slot = static_cast<T**>(upcast.mObj);
  if (!slot) {
    const char* const sourceName = source.mType ? source.mType->GetName() : "null";
    const char* const targetName = targetType ? targetType->GetName() : "null";
    throw gpg::BadRefCast(nullptr, sourceName, targetName);
  }

  return slot;
}

[[nodiscard]] RType* ResolveTypeByNameFallbacks(
  RType*& cachedType,
  const char* const primaryName,
  const char* const fallbackName = nullptr
)
{
  if (!cachedType && primaryName) {
    cachedType = gpg::REF_FindTypeNamed(primaryName);
  }
  if (!cachedType && fallbackName) {
    cachedType = gpg::REF_FindTypeNamed(fallbackName);
  }
  return cachedType;
}

/**
 * Address: 0x00554FE0 (FUN_00554FE0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `REntityBlueprint`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastREntityBlueprintRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(cachedType, "REntityBlueprint", "Moho::REntityBlueprint");
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00557B90 (FUN_00557B90)
 *
 * What it does:
 * Upcasts one reflected reference lane to `EntityCategorySet` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastEntityCategorySetRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "BVSet<RBlueprint const *,EntityCategoryHelper>",
    "Moho::BVSet<RBlueprint const *,EntityCategoryHelper>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0055AD10 (FUN_0055AD10)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RMeshBlueprint`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRMeshBlueprintRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::RMeshBlueprint::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::RMeshBlueprint));
    moho::RMeshBlueprint::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0055AD60 (FUN_0055AD60)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CSndParams` using the secondary
 * runtime type cache lane.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCSndParamsRefObjectVariantB(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::CSndParams::sType2;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::CSndParams));
    moho::CSndParams::sType2 = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0055FD20 (FUN_0055FD20)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RUnitBlueprint`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRUnitBlueprintRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::RUnitBlueprint::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::RUnitBlueprint));
    moho::RUnitBlueprint::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00572C50 (FUN_00572C50)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Listener<EFormationdStatus>`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastListenerEFormationdStatusRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "Listener<EFormationdStatus>",
    "Moho::Listener<EFormationdStatus>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00585650 (FUN_00585650)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Sim`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastSimRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(cachedType, "Sim", "Moho::Sim");
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005ACE40 (FUN_005ACE40)
 *
 * What it does:
 * Upcasts one reflected reference lane to `COGrid`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCOGridRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::COGrid::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::COGrid));
    moho::COGrid::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005CB6D0 (FUN_005CB6D0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `ReconBlip`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastReconBlipRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  RType* targetType = moho::ReconBlip::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::ReconBlip));
    moho::ReconBlip::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005E06E0 (FUN_005E06E0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CAiAttackerImpl`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCAiAttackerImplRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::CAiAttackerImpl));
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x005E0A50 (FUN_005E0A50)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Listener<EAiAttackerEvent>`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastListenerEAiAttackerEventRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "Listener<EAiAttackerEvent>",
    "Moho::Listener<EAiAttackerEvent>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x005EE170 (FUN_005EE170)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Listener<EAiTransportEvent>`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastListenerEAiTransportEventRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "Listener<EAiTransportEvent>",
    "Moho::Listener<EAiTransportEvent>"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x0060DA80 (FUN_0060DA80)
 *
 * What it does:
 * Upcasts one reflected reference lane to `EAiResult`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastEAiResultRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::EAiResult));
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x00634270 (FUN_00634270)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RUnitBlueprintWeapon`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRUnitBlueprintWeaponRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x006342C0 (FUN_006342C0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RProjectileBlueprint` using the
 * secondary runtime-type lane.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRProjectileBlueprintRefObjectVariantB(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  if (!cachedType) {
    cachedType = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
  }
  if (!cachedType) {
    cachedType = gpg::REF_FindTypeNamed("RProjectileBlueprint");
  }
  if (!cachedType) {
    cachedType = gpg::REF_FindTypeNamed("Moho::RProjectileBlueprint");
  }
  if (!cachedType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, cachedType);
  return upcast.mObj;
}

/**
 * Address: 0x006354E0 (FUN_006354E0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CBoneEntityManipulator`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCBoneEntityManipulatorRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "CBoneEntityManipulator",
    "Moho::CBoneEntityManipulator"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00637320 (FUN_00637320)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CBuilderArmManipulator`.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCBuilderArmManipulatorRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(
    cachedType,
    "CBuilderArmManipulator",
    "Moho::CBuilderArmManipulator"
  );
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x00698D20 (FUN_00698D20)
 *
 * What it does:
 * Upcasts one reflected reference lane to `SPhysConstants` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastSPhysConstantsRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  if (!gSPhysConstantsRRefType) {
    gSPhysConstantsRRefType = gpg::LookupRType(typeid(moho::SPhysConstants));
  }
  if (!gSPhysConstantsRRefType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, gSPhysConstantsRRefType);
  return upcast.mObj;
}

/**
 * Address: 0x006A00B0 (FUN_006A00B0)
 *
 * What it does:
 * Upcasts one reflected reference lane to
 * `ManyToOneListener<EProjectileImpactEvent>` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastManyToOneProjectileImpactListenerRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  gpg::RType* targetType = moho::ManyToOneListener<moho::EProjectileImpactEvent>::sType;
  if (!targetType) {
    targetType = gpg::LookupRType(typeid(moho::ManyToOneListener<moho::EProjectileImpactEvent>));
    moho::ManyToOneListener<moho::EProjectileImpactEvent>::sType = targetType;
  }
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x006A4650 (FUN_006A4650)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Projectile` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastProjectileRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  static RType* cachedProjectileType = nullptr;
  RType* const targetType = ResolveTypeByNameFallbacks(cachedProjectileType, "Projectile", "Moho::Projectile");
  if (!targetType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
  return upcast.mObj;
}

/**
 * Address: 0x006BC340 (FUN_006BC340)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CPathPoint` object storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCPathPointRefObject(gpg::RRef* const sourceRef)
{
  if (!sourceRef) {
    return nullptr;
  }

  if (!gCPathPointRRefType) {
    gCPathPointRRefType = gpg::LookupRType(typeid(moho::CPathPoint));
  }
  if (!gCPathPointRRefType) {
    return nullptr;
  }

  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, gCPathPointRRefType);
  return upcast.mObj;
}

/**
 * Address: 0x00557D50 (FUN_00557D50)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RBlueprint*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRBlueprintRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::RBlueprint::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x0059E7F0 (FUN_0059E7F0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `IFormationInstance*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastIFormationInstanceRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::IFormationInstance::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x005A2420 (FUN_005A2420)
 *
 * What it does:
 * Upcasts one reflected reference lane to `RUnitBlueprint*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastRUnitBlueprintRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::RUnitBlueprint::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x005CC300 (FUN_005CC300)
 *
 * What it does:
 * Upcasts one reflected reference lane to `ReconBlip*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastReconBlipRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::ReconBlip::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x005E1030 (FUN_005E1030)
 *
 * What it does:
 * Upcasts one reflected reference lane to `UnitWeapon*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastUnitWeaponRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::UnitWeapon::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x005E1050 (FUN_005E1050)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CAcquireTargetTask*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCAcquireTargetTaskRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CAcquireTargetTask::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x0063E970 (FUN_0063E970)
 *
 * What it does:
 * Upcasts one reflected reference lane to `IAniManipulator*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastIAniManipulatorRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::IAniManipulator::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x0066D190 (FUN_0066D190)
 *
 * What it does:
 * Upcasts one reflected reference lane to `IEffect*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastIEffectRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::IEffect::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x00680F70 (FUN_00680F70)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Entity*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastEntityRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::Entity::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x006B4410 (FUN_006B4410)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CEconomyEvent*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCEconomyEventRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CEconomyEvent::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x006E3EF0 (FUN_006E3EF0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CUnitCommand*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCUnitCommandRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CUnitCommand::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x00713F10 (FUN_00713F10)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CArmyStatItem*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCArmyStatItemRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CArmyStatItem::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x007542D0 (FUN_007542D0)
 *
 * What it does:
 * Upcasts one reflected reference lane to `SimArmy*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastSimArmyRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::SimArmy::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x00754470 (FUN_00754470)
 *
 * What it does:
 * Upcasts one reflected reference lane to `Shield*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastShieldRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::Shield::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x0077F600 (FUN_0077F600)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CDecalHandle*` storage.
 */
[[maybe_unused]] [[nodiscard]] void* TryUpcastCDecalHandleRefObjectVariantB(gpg::RRef* const sourceRef)
{
  const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, moho::CDecalHandle::GetPointerType());
  return upcast.mObj;
}

/**
 * Address: 0x00750100 (FUN_00750100)
 *
 * What it does:
 * Upcasts one reflected source reference to `SimArmy*` and stores it into one
 * destination pointer-slot lane.
 */
[[maybe_unused]] void AssignSimArmyPointerSlotFromRef(void* const slotObject, gpg::RRef* const sourceRef)
{
  const gpg::RRef source = (sourceRef != nullptr) ? *sourceRef : gpg::RRef{};
  AssignPointerSlotWithTypeCache<moho::SimArmy>(slotObject, source, moho::SimArmy::sType);
}

/**
 * Address: 0x00750510 (FUN_00750510)
 *
 * What it does:
 * Upcasts one reflected source reference to `Shield*` and stores it into one
 * destination pointer-slot lane.
 */
[[maybe_unused]] void AssignShieldPointerSlotFromRef(void* const slotObject, gpg::RRef* const sourceRef)
{
  const gpg::RRef source = (sourceRef != nullptr) ? *sourceRef : gpg::RRef{};
  AssignPointerSlotWithTypeCache<moho::Shield>(slotObject, source, moho::Shield::sType);
}

/**
 * Address: 0x0077EE30 (FUN_0077EE30)
 *
 * What it does:
 * Upcasts one reflected source reference to `CDecalHandle*` and stores it
 * into one destination pointer-slot lane.
 */
[[maybe_unused]] void AssignCDecalHandlePointerSlotFromRef(void* const slotObject, gpg::RRef* const sourceRef)
{
  const gpg::RRef source = (sourceRef != nullptr) ? *sourceRef : gpg::RRef{};
  AssignPointerSlotWithTypeCache<moho::CDecalHandle>(slotObject, source, moho::CDecalHandle::sType);
}

template <class T>
RRef MakePointeeRef(T* const object, RType* const baseType)
{
    RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;

    if (!object || !baseType) {
        return out;
    }

    RType* dynamicType = baseType;
    try {
        dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
        dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
        out.mObj = object;
        out.mType = dynamicType;
        return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
}

template <class T>
msvc8::string BuildPointerLexical(void* const slotObject, RType* const pointeeType)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (!slot || !*slot) {
        return msvc8::string("NULL");
    }

    const RRef pointeeRef = MakePointeeRef<T>(*slot, pointeeType);
    if (!pointeeRef.mObj) {
        return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return STR_Printf("[%s]", inner.c_str());
}

msvc8::string BuildPointerName(RType* const pointeeType)
{
    const char* pointeeName = pointeeType ? pointeeType->GetName() : "null";
    if (!pointeeName) {
        pointeeName = "null";
    }
    return STR_Printf("%s*", pointeeName);
}

template <class T>
RRef NewPointerSlotRef()
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    return MakePointerSlotRef<T>(slot);
}

template <class T>
RRef CopyPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    *slot = nullptr;
    if (sourceRef) {
        T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakePointerSlotRef<T>(slot);
}

/**
 * Address: 0x005C8C80 (FUN_005C8C80)
 *
 * What it does:
 * Allocates one `ReconBlip*` slot, copies the source lane pointer, and wraps
 * it as `gpg::RRef_ReconBlip_P`.
 */
RRef CopyReconBlipPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::ReconBlip**>(::operator new(sizeof(moho::ReconBlip*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastReconBlipPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    gpg::RRef_ReconBlip_P(&out, slot);
    return out;
}

/**
 * Address: 0x005C8D10 (FUN_005C8D10)
 *
 * What it does:
 * Wraps one existing `ReconBlip*` slot lane as `gpg::RRef_ReconBlip_P`.
 */
RRef ConstructReconBlipPointerSlotRef(void* const slotObject)
{
    RRef out{};
    gpg::RRef_ReconBlip_P(&out, static_cast<moho::ReconBlip**>(slotObject));
    return out;
}

/**
 * Address: 0x005C8D40 (FUN_005C8D40)
 *
 * What it does:
 * Moves one reflected `ReconBlip*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_ReconBlip_P` payload.
 */
RRef MoveReconBlipPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::ReconBlip**>(slotObject);
    moho::ReconBlip** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastReconBlipPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    gpg::RRef_ReconBlip_P(&out, resolvedSlot);
    return out;
}

/**
 * Address: 0x005B5850 (FUN_005B5850)
 *
 * What it does:
 * Value-first adapter that forwards one `CAiPathSpline*` object pointer into
 * the canonical `gpg::RRef_CAiPathSpline` builder.
 */
[[maybe_unused]] gpg::RRef* BuildCAiPathSplineRefValueFirst(
  moho::CAiPathSpline* const value,
  gpg::RRef* const out
)
{
    return gpg::RRef_CAiPathSpline(out, value);
}

/**
 * Address: 0x005B95B0 (FUN_005B95B0)
 *
 * What it does:
 * Value-first adapter that forwards one `CAiPersonality*` object pointer into
 * the canonical `gpg::RRef_CAiPersonality` builder.
 */
[[maybe_unused]] gpg::RRef* BuildCAiPersonalityRefValueFirst(
  moho::CAiPersonality* const value,
  gpg::RRef* const out
)
{
    return gpg::RRef_CAiPersonality(out, value);
}

/**
 * Address: 0x005C9290 (FUN_005C9290)
 *
 * What it does:
 * Value-first adapter that forwards one `EReconFlags*` value pointer into the
 * canonical `gpg::RRef_EReconFlags` builder.
 */
[[maybe_unused]] gpg::RRef* BuildEReconFlagsRefValueFirst(
  moho::EReconFlags* const value,
  gpg::RRef* const out
)
{
    return gpg::RRef_EReconFlags(out, value);
}

/**
 * Address: 0x005C9A10 (FUN_005C9A10)
 *
 * What it does:
 * Value-first adapter that forwards one `SPerArmyReconInfo*` object pointer
 * into the canonical `gpg::RRef_SPerArmyReconInfo` builder.
 */
[[maybe_unused]] gpg::RRef* BuildSPerArmyReconInfoRefValueFirst(
  moho::SPerArmyReconInfo* const value,
  gpg::RRef* const out
)
{
    return gpg::RRef_SPerArmyReconInfo(out, value);
}

/**
 * Address: 0x005C9A40 (FUN_005C9A40)
 *
 * What it does:
 * Value-first adapter that forwards one `ReconBlip*` slot pointer into the
 * canonical `gpg::RRef_ReconBlip_P` builder.
 */
[[maybe_unused]] gpg::RRef* BuildReconBlipSlotRefValueFirst(
  moho::ReconBlip** const value,
  gpg::RRef* const out
)
{
    return gpg::RRef_ReconBlip_P(out, value);
}

/**
 * Address: 0x005CA170 (FUN_005CA170)
 *
 * What it does:
 * Value-first adapter that forwards one `CAiReconDBImpl*` object pointer into
 * the canonical `gpg::RRef_CAiReconDBImpl` builder.
 */
[[maybe_unused]] gpg::RRef* BuildCAiReconDBImplRefValueFirst(
  moho::CAiReconDBImpl* const value,
  gpg::RRef* const out
)
{
    return gpg::RRef_CAiReconDBImpl(out, value);
}

/**
 * Address: 0x0066CF40 (FUN_0066CF40)
 *
 * What it does:
 * Allocates one `IEffect*` slot, copies the source lane pointer, and wraps it
 * as `gpg::RRef_IEffect_P`.
 */
RRef CopyIEffectPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::IEffect**>(::operator new(sizeof(moho::IEffect*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastIEffectPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    gpg::RRef_IEffect_P(&out, slot);
    return out;
}

/**
 * Address: 0x0066CFD0 (FUN_0066CFD0)
 *
 * What it does:
 * Wraps one existing `IEffect*` slot lane as `gpg::RRef_IEffect_P`.
 */
RRef ConstructIEffectPointerSlotRef(void* const slotObject)
{
    RRef out{};
    gpg::RRef_IEffect_P(&out, static_cast<moho::IEffect**>(slotObject));
    return out;
}

/**
 * Address: 0x0066D000 (FUN_0066D000)
 *
 * What it does:
 * Moves one reflected `IEffect*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_IEffect_P` payload.
 */
RRef MoveIEffectPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::IEffect**>(slotObject);
    moho::IEffect** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastIEffectPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    gpg::RRef_IEffect_P(&out, resolvedSlot);
    return out;
}

/**
 * Address: 0x006B2A10 (FUN_006B2A10)
 *
 * What it does:
 * Allocates one `CEconomyEvent*` slot, copies the source lane pointer, and
 * wraps it as `gpg::RRef_CEconomyEvent_P`.
 */
RRef CopyCEconomyEventPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CEconomyEvent**>(::operator new(sizeof(moho::CEconomyEvent*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastCEconomyEventPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    gpg::RRef_CEconomyEvent_P(&out, slot);
    return out;
}

/**
 * Address: 0x006B2AA0 (FUN_006B2AA0)
 *
 * What it does:
 * Wraps one existing `CEconomyEvent*` slot lane as
 * `gpg::RRef_CEconomyEvent_P`.
 */
RRef ConstructCEconomyEventPointerSlotRef(void* const slotObject)
{
    RRef out{};
    gpg::RRef_CEconomyEvent_P(&out, static_cast<moho::CEconomyEvent**>(slotObject));
    return out;
}

/**
 * Address: 0x006B2AD0 (FUN_006B2AD0)
 *
 * What it does:
 * Moves one reflected `CEconomyEvent*` source slot into one destination slot
 * lane and wraps the destination as one `gpg::RRef_CEconomyEvent_P` payload.
 */
RRef MoveCEconomyEventPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CEconomyEvent**>(slotObject);
    moho::CEconomyEvent** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastCEconomyEventPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    gpg::RRef_CEconomyEvent_P(&out, resolvedSlot);
    return out;
}

/**
 * Address: 0x00750B60 (FUN_00750B60)
 *
 * What it does:
 * Allocates one `SimArmy*` slot, copies the source lane pointer, and wraps it
 * as `gpg::RRef_SimArmy_P`.
 */
[[maybe_unused]] RRef CopySimArmyPointerSlotRef(RRef* const sourceRef)
{
    auto* slot = static_cast<moho::SimArmy**>(::operator new(sizeof(moho::SimArmy*), std::nothrow));
    if (slot) {
        try {
            *slot = *sourceRef->TryUpcastSimArmyPointerSlot();
        } catch (...) {
            ::operator delete(slot);
            throw;
        }
    }

    RRef out{};
    gpg::RRef_SimArmy_P(&out, slot);
    return out;
}

/**
 * Address: 0x00750BF0 (FUN_00750BF0)
 *
 * What it does:
 * Wraps one existing `SimArmy*` slot lane as `gpg::RRef_SimArmy_P`.
 */
[[maybe_unused]] RRef ConstructSimArmyPointerSlotRef(void* const slotObject)
{
    RRef out{};
    gpg::RRef_SimArmy_P(&out, static_cast<moho::SimArmy**>(slotObject));
    return out;
}

/**
 * Address: 0x00750C20 (FUN_00750C20)
 *
 * What it does:
 * Moves one reflected `SimArmy*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_SimArmy_P` payload.
 */
[[maybe_unused]] RRef MoveSimArmyPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::SimArmy**>(slotObject);
    moho::SimArmy** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastSimArmyPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    gpg::RRef_SimArmy_P(&out, resolvedSlot);
    return out;
}

/**
 * Address: 0x00750D60 (FUN_00750D60)
 *
 * What it does:
 * Wraps one `Shield*` slot pointer as a reflected `gpg::RRef_Shield_P`
 * payload.
 */
[[maybe_unused]] RRef CopyShieldPointerSlotRef(moho::Shield** const slot)
{
    RRef out{};
    gpg::RRef_Shield_P(&out, slot);
    return out;
}

/**
 * Address: 0x00750D90 (FUN_00750D90)
 *
 * What it does:
 * Moves one reflected `Shield*` source slot into one destination slot lane
 * and wraps the destination as one `gpg::RRef_Shield_P` payload.
 */
[[maybe_unused]] RRef MoveShieldPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::Shield**>(slotObject);
    moho::Shield** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastShieldPointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    gpg::RRef_Shield_P(&out, resolvedSlot);
    return out;
}

/**
 * Address: 0x0077F040 (FUN_0077F040)
 *
 * What it does:
 * Wraps one `CDecalHandle*` slot pointer as a reflected
 * `gpg::RRef_CDecalHandle_P` payload.
 */
[[maybe_unused]] RRef CopyCDecalHandlePointerSlotRef(moho::CDecalHandle** const slot)
{
    RRef out{};
    gpg::RRef_CDecalHandle_P(&out, slot);
    return out;
}

/**
 * Address: 0x0077F070 (FUN_0077F070)
 *
 * What it does:
 * Moves one reflected `CDecalHandle*` source slot into one destination slot
 * lane and wraps the destination as one `gpg::RRef_CDecalHandle_P` payload.
 */
[[maybe_unused]] RRef MoveCDecalHandlePointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CDecalHandle**>(slotObject);
    moho::CDecalHandle** resolvedSlot = slot;
    if (slot != nullptr) {
        *slot = *sourceRef->TryUpcastCDecalHandlePointerSlot();
    } else {
        resolvedSlot = nullptr;
    }

    RRef out{};
    gpg::RRef_CDecalHandle_P(&out, resolvedSlot);
    return out;
}

/**
 * Address: 0x00672380 (FUN_00672380)
 *
 * What it does:
 * Allocates one `CEfxTrailEmitter` object and wraps it as
 * `gpg::RRef_CEfxTrailEmitter`.
 */
[[maybe_unused]] RRef NewCEfxTrailEmitterRef()
{
    moho::CEfxTrailEmitter* const emitter = new (std::nothrow) moho::CEfxTrailEmitter();

    RRef out{};
    gpg::RRef_CEfxTrailEmitter(&out, emitter);
    return out;
}

/**
 * Address: 0x00672410 (FUN_00672410)
 *
 * What it does:
 * Constructs one in-place `CEfxTrailEmitter` object when storage is provided
 * and wraps it as one `gpg::RRef_CEfxTrailEmitter` payload.
 */
[[maybe_unused]] RRef ConstructCEfxTrailEmitterRefInPlace(void* const objectStorage)
{
    auto* emitter = static_cast<moho::CEfxTrailEmitter*>(objectStorage);
    if (emitter != nullptr) {
        emitter = new (emitter) moho::CEfxTrailEmitter();
    }

    RRef out{};
    gpg::RRef_CEfxTrailEmitter(&out, emitter);
    return out;
}

struct DeletingDestructorSlot8VTable
{
    void* reserved0;
    int(__thiscall* invoke)(void* self, unsigned int deleteFlag);
};

struct DeletingDestructorSlot8Runtime
{
    DeletingDestructorSlot8VTable* vtable;
};

void InvokeDeletingDestructorSlot8(void* const objectStorage, const unsigned int deleteFlag)
{
    auto* const runtime = static_cast<DeletingDestructorSlot8Runtime*>(objectStorage);
    (void)runtime->vtable->invoke(objectStorage, deleteFlag);
}

/**
 * Address: 0x006723F0 (FUN_006723F0)
 *
 * What it does:
 * Calls the polymorphic deleting-destructor lane (`+0x08`) for one
 * `CEfxTrailEmitter` instance when storage is non-null.
 */
[[maybe_unused]] void DeleteCEfxTrailEmitterStorage(void* const objectStorage)
{
    if (objectStorage != nullptr) {
        InvokeDeletingDestructorSlot8(objectStorage, 1u);
    }
}

/**
 * Address: 0x00672480 (FUN_00672480)
 *
 * What it does:
 * Calls the polymorphic non-deleting destructor lane (`+0x08`) for one
 * `CEfxTrailEmitter` instance.
 */
[[maybe_unused]] void DestructCEfxTrailEmitterStorage(void* const objectStorage)
{
    InvokeDeletingDestructorSlot8(objectStorage, 0u);
}

/**
 * Address: 0x006722A0 (FUN_006722A0)
 *
 * What it does:
 * Binds `CEfxTrailEmitter` lifecycle callback lanes (`newRef`, `ctorRef`,
 * `delete`, `destruct`) onto one runtime `RType` descriptor.
 */
[[maybe_unused]] gpg::RType* BindCEfxTrailEmitterLifecycleCallbacks(gpg::RType* const typeInfo)
{
    return gpg::BindRTypeLifecycleCallbacks(
      typeInfo,
      &NewCEfxTrailEmitterRef,
      &ConstructCEfxTrailEmitterRefInPlace,
      &DeleteCEfxTrailEmitterStorage,
      &DestructCEfxTrailEmitterStorage
    );
}

/**
 * Address: 0x00672490 (FUN_00672490)
 *
 * What it does:
 * Resolves cached reflection type for `CEffectImpl`, builds a zero-offset base
 * descriptor, and appends it to the target `RType`.
 */
[[maybe_unused]] void AddCEffectImplBaseField(gpg::RType* const typeInfo)
{
    gpg::RType* baseType = moho::CEffectImpl::sType;
    if (!baseType) {
        baseType = gpg::LookupRType(typeid(moho::CEffectImpl));
        moho::CEffectImpl::sType = baseType;
    }

    gpg::RField baseField{};
    baseField.mName = baseType ? baseType->GetName() : nullptr;
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
}

template <class T>
RRef ConstructPointerSlotRef(void* const slotObject)
{
    return MakePointerSlotRef<T>(static_cast<T**>(slotObject));
}

template <class T>
RRef MovePointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakePointerSlotRef<T>(slot);
}

template <class T>
void DeletePointerSlot(void* const slotObject)
{
    ::operator delete(slotObject);
}

/**
 * Address: 0x0040D3B0 (FUN_0040D3B0, sub_40D3B0)
 *
 * What it does:
 * Wraps a `CTaskThread*` slot pointer as reflected pointer-slot `RRef`.
 */
RRef MakeCTaskThreadPointerSlotRef(moho::CTaskThread** const slot)
{
    return MakePointerSlotRef<moho::CTaskThread>(slot);
}

/**
 * Address: 0x0040D580 (FUN_0040D580, sub_40D580)
 *
 * What it does:
 * Attempts to upcast one reflected reference lane to `CTaskThread*` slot and
 * returns null on mismatch.
 */
moho::CTaskThread** TryUpcastCTaskThreadPointerSlot(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, moho::CTaskThread::GetPointerType());
    return static_cast<moho::CTaskThread**>(upcast.mObj);
}

/**
 * Address: 0x0040D3E0 (FUN_0040D3E0, gpg::RRef::TryUpcast_CTaskThread_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CTaskThread*` slot and throws
 * `BadRefCast` on mismatch.
 */
moho::CTaskThread** TryUpcastCTaskThreadPointerSlotOrThrow(const RRef& source)
{
    moho::CTaskThread** const slot = TryUpcastCTaskThreadPointerSlot(source);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x0040CDB0 (FUN_0040CDB0, sub_40CDB0)
 *
 * What it does:
 * Allocates one `CTaskThread*` slot and returns it as typed `RRef`.
 */
RRef NewCTaskThreadPointerSlotRef()
{
    auto* const slot = static_cast<moho::CTaskThread**>(::operator new(sizeof(moho::CTaskThread*)));
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CDE0 (FUN_0040CDE0, sub_40CDE0)
 *
 * What it does:
 * Allocates one `CTaskThread*` slot and copies pointer lane value from source.
 */
RRef CopyCTaskThreadPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CTaskThread**>(::operator new(sizeof(moho::CTaskThread*)));
    *slot = nullptr;
    if (sourceRef) {
        moho::CTaskThread** const sourceSlot = TryUpcastCTaskThreadPointerSlotOrThrow(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CE70 (FUN_0040CE70, sub_40CE70)
 *
 * What it does:
 * Wraps existing `CTaskThread*` slot storage as typed `RRef`.
 */
RRef ConstructCTaskThreadPointerSlotRef(void* const slotObject)
{
    return MakeCTaskThreadPointerSlotRef(static_cast<moho::CTaskThread**>(slotObject));
}

/**
 * Address: 0x0040CEA0 (FUN_0040CEA0, sub_40CEA0)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CTaskThread*` slot.
 */
RRef MoveCTaskThreadPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CTaskThread**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            moho::CTaskThread** const sourceSlot = TryUpcastCTaskThreadPointerSlotOrThrow(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CD90 (FUN_0040CD90, sub_40CD90)
 *
 * What it does:
 * Binds new/construct callback lanes for `CTaskThread*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCTaskThreadPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCTaskThreadPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCTaskThreadPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x0040CDA0 (FUN_0040CDA0, sub_40CDA0)
 *
 * What it does:
 * Binds copy/move callback lanes for `CTaskThread*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCTaskThreadPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCTaskThreadPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCTaskThreadPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421910 (FUN_00421910, gpg::RRef_CLuaConOutputHandler_P)
 *
 * What it does:
 * Wraps one `CLuaConOutputHandler*` slot pointer as reflected pointer-slot `RRef`.
 */
RRef MakeCLuaConOutputHandlerPointerSlotRef(moho::CLuaConOutputHandler** const slot)
{
    return MakePointerSlotRef<moho::CLuaConOutputHandler>(slot);
}

/**
 * Address: 0x00421BD0 (FUN_00421BD0, gpg::RRef::TryUpcast_CLuaConOutputHandler_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CLuaConOutputHandler*` slot and
 * throws `BadRefCast` on mismatch.
 */
moho::CLuaConOutputHandler** TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, CachedPointerType<moho::CLuaConOutputHandler>());
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(upcast.mObj);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x00421680 (FUN_00421680, sub_421680)
 *
 * What it does:
 * Allocates one `CLuaConOutputHandler*` slot and returns it as typed `RRef`.
 */
RRef NewCLuaConOutputHandlerPointerSlotRef()
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(::operator new(sizeof(moho::CLuaConOutputHandler*)));
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x004216B0 (FUN_004216B0, sub_4216B0)
 *
 * What it does:
 * Allocates one `CLuaConOutputHandler*` slot and copies pointer lane value from source.
 */
RRef CopyCLuaConOutputHandlerPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(::operator new(sizeof(moho::CLuaConOutputHandler*)));
    *slot = nullptr;
    if (sourceRef) {
        moho::CLuaConOutputHandler** const sourceSlot = TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x00421740 (FUN_00421740, sub_421740)
 *
 * What it does:
 * Wraps existing `CLuaConOutputHandler*` slot storage as typed `RRef`.
 */
RRef ConstructCLuaConOutputHandlerPointerSlotRef(void* const slotObject)
{
    return MakeCLuaConOutputHandlerPointerSlotRef(static_cast<moho::CLuaConOutputHandler**>(slotObject));
}

/**
 * Address: 0x00421770 (FUN_00421770, sub_421770)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CLuaConOutputHandler*` slot.
 */
RRef MoveCLuaConOutputHandlerPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            moho::CLuaConOutputHandler** const sourceSlot = TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x00421660 (FUN_00421660, sub_421660)
 *
 * What it does:
 * Binds new/construct callback lanes for `CLuaConOutputHandler*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCLuaConOutputHandlerPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCLuaConOutputHandlerPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421670 (FUN_00421670, sub_421670)
 *
 * What it does:
 * Binds copy/move callback lanes for `CLuaConOutputHandler*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCLuaConOutputHandlerPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCLuaConOutputHandlerPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421620 (FUN_00421620, sub_421620)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `CLuaConOutputHandler*` reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::CLuaConOutputHandler*);
    BindCLuaConOutputHandlerPointerNewAndConstruct(typeInfo);
    BindCLuaConOutputHandlerPointerCopyAndMove(typeInfo);
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::CLuaConOutputHandler>;
    return typeInfo;
}

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
    gpg::RRef_CScriptObject_P(&out, slot);
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
    gpg::RRef_CScriptObject_P(&out, slot);
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
    gpg::RRef_CScriptObject_P(&out, static_cast<moho::CScriptObject**>(slotObject));
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
    gpg::RRef_CScriptObject_P(&out, slot);
    return out;
}

/**
 * Address: 0x004C8AA0 (FUN_004C8AA0, sub_4C8AA0)
 *
 * What it does:
 * Binds new/construct callback lanes for `CScriptObject*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCScriptObjectPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCScriptObjectPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCScriptObjectPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x004C8AB0 (FUN_004C8AB0, sub_4C8AB0)
 *
 * What it does:
 * Binds copy/move callback lanes for `CScriptObject*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCScriptObjectPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCScriptObjectPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCScriptObjectPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x004C8A60 (FUN_004C8A60, sub_4C8A60)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `CScriptObject*` reflection.
 */
gpg::RPointerTypeBase* BindCScriptObjectPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::CScriptObject*);
    typeInfo->newRefFunc_ = &NewCScriptObjectPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCScriptObjectPointerSlotRef;
    typeInfo->cpyRefFunc_ = &CopyCScriptObjectPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCScriptObjectPointerSlotRef;
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::CScriptObject>;
    return typeInfo;
}

/**
 * Address: 0x004E6060 (FUN_004E6060, gpg::RPointerType_CSndParams::Delete)
 *
 * What it does:
 * Releases one allocated `CSndParams*` pointer-slot lane.
 */
void DeleteCSndParamsPointerSlot(void* const slotObject)
{
    ::operator delete(slotObject);
}

/**
 * Address: 0x004E6090 (FUN_004E6090, gpg::RPointerType_CSndParams::NewRef)
 *
 * What it does:
 * Allocates one `CSndParams*` pointer-slot lane and wraps it as `RRef`.
 */
RRef NewCSndParamsPointerSlotRef()
{
    auto* const slot = static_cast<moho::CSndParams**>(::operator new(sizeof(moho::CSndParams*)));
    RRef out{};
    gpg::RRef_CSndParams_P(&out, slot);
    return out;
}

/**
 * Address: 0x004E60C0 (FUN_004E60C0, gpg::RPointerType_CSndParams::CpyRef)
 *
 * What it does:
 * Allocates one `CSndParams*` pointer-slot lane and copies source slot value.
 */
RRef CopyCSndParamsPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CSndParams**>(::operator new(sizeof(moho::CSndParams*)));
    if (slot) {
        const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedPointerType<moho::CSndParams>());
        auto* const sourceSlot = static_cast<moho::CSndParams**>(upcast.mObj);
        if (!sourceSlot) {
            throw gpg::BadRefCast("type error");
        }
        *slot = *sourceSlot;
    }

    RRef out{};
    gpg::RRef_CSndParams_P(&out, slot);
    return out;
}

/**
 * Address: 0x004E6150 (FUN_004E6150, gpg::RPointerType_CSndParams::CtrRef)
 *
 * What it does:
 * Wraps existing `CSndParams*` pointer-slot storage as reflected `RRef`.
 */
RRef ConstructCSndParamsPointerSlotRef(void* const slotObject)
{
    RRef out{};
    gpg::RRef_CSndParams_P(&out, static_cast<moho::CSndParams**>(slotObject));
    return out;
}

/**
 * Address: 0x004E6180 (FUN_004E6180, gpg::RPointerType_CSndParams::MovRef)
 *
 * What it does:
 * Writes source slot pointer value into destination `CSndParams*` slot lane.
 */
RRef MoveCSndParamsPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* slot = static_cast<moho::CSndParams**>(slotObject);
    if (slot) {
        const RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedPointerType<moho::CSndParams>());
        auto* const sourceSlot = static_cast<moho::CSndParams**>(upcast.mObj);
        if (!sourceSlot) {
            throw gpg::BadRefCast("type error");
        }
        *slot = *sourceSlot;
    } else {
        slot = nullptr;
    }

    RRef out{};
    gpg::RRef_CSndParams_P(&out, slot);
    return out;
}

/**
 * Address: 0x004E6380 (FUN_004E6380)
 *
 * What it does:
 * Upcasts one reflected reference to a `CSndParams*` pointer-slot lane and
 * returns the upcast object pointer lane without mismatch checks.
 */
[[maybe_unused]] [[nodiscard]] void* UpcastCSndParamsPointerSlotUnchecked(const gpg::RRef* const sourceRef)
{
    gpg::RType* const pointerType = moho::CSndParams::GetPointerType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, pointerType);
    return upcast.mObj;
}

  void SerializeRect2i(WriteArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2i*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->WriteInt(rect->x0);
    archive->WriteInt(rect->z0);
    archive->WriteInt(rect->x1);
    archive->WriteInt(rect->z1);
  }

  void DeserializeRect2i(ReadArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2i*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->ReadInt(&rect->x0);
    archive->ReadInt(&rect->z0);
    archive->ReadInt(&rect->x1);
    archive->ReadInt(&rect->z1);
  }

  void SerializeRect2f(WriteArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2f*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->WriteFloat(rect->x0);
    archive->WriteFloat(rect->z0);
    archive->WriteFloat(rect->x1);
    archive->WriteFloat(rect->z1);
  }

  void DeserializeRect2f(ReadArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2f*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->ReadFloat(&rect->x0);
    archive->ReadFloat(&rect->z0);
    archive->ReadFloat(&rect->x1);
    archive->ReadFloat(&rect->z1);
  }

  void AddRect2IntField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, CachedIntType(), offset));
  }

  void AddRect2FloatField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, CachedFloatType(), offset));
  }

  template <class TTypeInfo>
  struct TypeInfoStorage
  {
    alignas(TTypeInfo) unsigned char bytes[sizeof(TTypeInfo)];
    bool constructed;
  };

  template <class TTypeInfo>
  [[nodiscard]] TTypeInfo& EnsureTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      new (storage.bytes) TTypeInfo();
      storage.constructed = true;
    }

    return *reinterpret_cast<TTypeInfo*>(storage.bytes);
  }

  template <class TTypeInfo>
  void DestroyTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      return;
    }

    reinterpret_cast<TTypeInfo*>(storage.bytes)->~TTypeInfo();
    storage.constructed = false;
  }

  struct PreregisteredTypeInfoMapNodeRuntime
  {
    PreregisteredTypeInfoMapNodeRuntime* left;
    PreregisteredTypeInfoMapNodeRuntime* parent;
    PreregisteredTypeInfoMapNodeRuntime* right;
    const std::type_info* typeInfo;
    gpg::RType* type;
    std::uint8_t color;
    std::uint8_t isNil;
    std::uint8_t reserved16[2];
  };
  static_assert(
    sizeof(PreregisteredTypeInfoMapNodeRuntime) == 0x18,
    "PreregisteredTypeInfoMapNodeRuntime size must be 0x18"
  );
  static_assert(
    offsetof(PreregisteredTypeInfoMapNodeRuntime, isNil) == 0x15,
    "PreregisteredTypeInfoMapNodeRuntime::isNil offset must be 0x15"
  );

  struct RuntimeTypeInfoMapOwnerView
  {
    void* unknown00;
    PreregisteredTypeInfoMapNodeRuntime* head;
  };
  static_assert(offsetof(RuntimeTypeInfoMapOwnerView, head) == 0x04, "RuntimeTypeInfoMapOwnerView::head offset must be 0x04");

  [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* RotateRuntimeTypeNodeLeft(
    PreregisteredTypeInfoMapNodeRuntime* const head,
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* const pivot = node->right;
    node->right = pivot->left;
    if (node->right->isNil == 0u) {
      node->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node == head->parent) {
      head->parent = pivot;
    } else {
      PreregisteredTypeInfoMapNodeRuntime* const nodeParent = node->parent;
      if (node == nodeParent->left) {
        nodeParent->left = pivot;
      } else {
        nodeParent->right = pivot;
      }
    }

    pivot->left = node;
    node->parent = pivot;
    return pivot;
  }

  [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* RotateRuntimeTypeNodeRight(
    PreregisteredTypeInfoMapNodeRuntime* const head,
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* const pivot = node->left;
    node->left = pivot->right;
    if (node->left->isNil == 0u) {
      node->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node == head->parent) {
      head->parent = pivot;
    } else {
      PreregisteredTypeInfoMapNodeRuntime* const nodeParent = node->parent;
      if (node == nodeParent->right) {
        nodeParent->right = pivot;
      } else {
        nodeParent->left = pivot;
      }
    }

    pivot->right = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x008D9930 (FUN_008D9930, func_TreeRotateLeft02)
   *
   * What it does:
   * Rotates one runtime type-info RB-tree node left around `node`, using
   * the sentinel head node passed directly as `head`.
   */
  [[maybe_unused]] void RotateRuntimeTypeTreeLeftOnHead(
    PreregisteredTypeInfoMapNodeRuntime* const head,
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    (void)RotateRuntimeTypeNodeLeft(head, node);
  }

  /**
   * Address: 0x008D9980 (FUN_008D9980, func_TreeRotateRight02)
   *
   * What it does:
   * Rotates one runtime type-info RB-tree node right around `node`, using
   * the sentinel head node passed directly as `head`.
   */
  [[maybe_unused]] void RotateRuntimeTypeTreeRightOnHead(
    PreregisteredTypeInfoMapNodeRuntime* const head,
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    (void)RotateRuntimeTypeNodeRight(head, node);
  }

  /**
   * Address: 0x008D8CB0 (FUN_008D8CB0, _Tree::_Rrotate)
   *
   * What it does:
   * Rotates one runtime type-info RB-tree node right around `node`, using
   * the tree owner object's sentinel-head lane at `+0x04`.
   */
  [[maybe_unused]] [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* RotateRuntimeTypeTreeRight(
    RuntimeTypeInfoMapOwnerView* const tree,
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    return RotateRuntimeTypeNodeRight(tree->head, node);
  }

  /**
   * Address: 0x008D9BC0 (FUN_008D9BC0, _Tree::_Lrotate)
   *
   * What it does:
   * Rotates one runtime type-info RB-tree node left around `node`, using
   * the tree owner object's sentinel-head lane at `+0x04`.
   */
  [[maybe_unused]] [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* RotateRuntimeTypeTreeLeft(
    RuntimeTypeInfoMapOwnerView* const tree,
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    return RotateRuntimeTypeNodeLeft(tree->head, node);
  }

  /**
   * Address: 0x008D8C50 (FUN_008D8C50)
   *
   * What it does:
   * Returns the leftmost live descendant in one runtime-type RB-tree branch,
   * starting from `node->left` and stopping at the first nil sentinel.
   */
  [[maybe_unused]] [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* FindRuntimeTypeTreeLeftmostFromLeftChild(
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* result = node;
    PreregisteredTypeInfoMapNodeRuntime* cursor = node->left;
    while (cursor->isNil == 0u) {
      result = cursor;
      cursor = cursor->left;
    }
    return result;
  }

  /**
   * Address: 0x008D8DE0 (FUN_008D8DE0)
   *
   * What it does:
   * Returns the rightmost live descendant in one runtime-type RB-tree branch,
   * starting from `node->right` and stopping at the first nil sentinel.
   */
  [[maybe_unused]] [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* FindRuntimeTypeTreeRightmostFromRightChild(
    PreregisteredTypeInfoMapNodeRuntime* const node
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* result = node;
    PreregisteredTypeInfoMapNodeRuntime* cursor = node->right;
    while (cursor->isNil == 0u) {
      result = cursor;
      cursor = cursor->right;
    }
    return result;
  }

  TypeInfoStorage<gpg::Rect2iTypeInfo> gRect2iTypeInfoStorage{};
  TypeInfoStorage<gpg::Rect2fTypeInfo> gRect2fTypeInfoStorage{};
  gpg::Rect2iSerializer gRect2iSerializer;
  gpg::Rect2fSerializer gRect2fSerializer;
  gpg::RPointerType<moho::CTaskThread> gCTaskThreadPointerType;
  gpg::RPointerType<moho::CAcquireTargetTask> gCAcquireTargetTaskPointerType;
  gpg::RPointerType<moho::RBlueprint> gRBlueprintPointerType;
  gpg::RPointerType<moho::UnitWeapon> gUnitWeaponPointerType;
  gpg::RPointerType<moho::IAniManipulator> gIAniManipulatorPointerType;
  gpg::RPointerType<moho::IEffect> gIEffectPointerType;
  gpg::RPointerType<moho::CUnitCommand> gCUnitCommandPointerType;
  gpg::RPointerType<moho::Entity> gEntityPointerType;
  gpg::RPointerType<moho::CEconomyEvent> gCEconomyEventPointerType;
  gpg::RPointerType<moho::CLuaConOutputHandler> gCLuaConOutputHandlerPointerType;
  /**
   * Address: 0x004C86E0 (FUN_004C86E0, ??0?$RPointerType@VCScriptObject@moho@@@gpg@@QAE@XZ)
   * Demangled: gpg::RPointerType_CScriptObject::RPointerType_CScriptObject
   *
   * What it does:
   * Global storage slot for the reflected pointer-type descriptor
   * `gpg::RPointerType<moho::CScriptObject>`. The binary's one-shot
   * ctor at this address runs the base `gpg::RType` ctor and then
   * calls `gpg::PreRegisterRType(typeid(moho::CScriptObject*), this)`;
   * the recovered code factors the preregistration out into the
   * `PointerTypeRegistration` struct below so all pointer-type
   * descriptors are wired in one pass, preserving the same observable
   * side effect (registration is live before first reflection query).
   */
  gpg::RPointerType<moho::CScriptObject> gCScriptObjectPointerType;
  gpg::RPointerType<moho::CSndParams> gCSndParamsPointerType;
  gpg::RPointerType<moho::IFormationInstance> gIFormationInstancePointerType;
  gpg::RPointerType<moho::RUnitBlueprint> gRUnitBlueprintPointerType;
  gpg::RPointerType<moho::ReconBlip> gReconBlipPointerType;
  gpg::RPointerType<moho::CArmyStatItem> gCArmyStatItemPointerType;

  [[nodiscard]] gpg::Rect2iTypeInfo& GetRect2iTypeInfo() noexcept
  {
    return EnsureTypeInfo(gRect2iTypeInfoStorage);
  }

  [[nodiscard]] gpg::Rect2fTypeInfo& GetRect2fTypeInfo() noexcept
  {
    return EnsureTypeInfo(gRect2fTypeInfoStorage);
  }

  /**
   * Address: 0x008DA2A0 (FUN_008DA2A0, func_DeleteTreeNode)
   *
   * What it does:
   * Recursively releases one preregistered RTTI-map subtree by walking the
   * right branch first, then deleting each traversed node while following left
   * links.
   */
  [[maybe_unused]] void DestroyPreregisteredTypeInfoTree(
    PreregisteredTypeInfoMapNodeRuntime* node
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* current = node;
    if (current->isNil != 0u) {
      return;
    }

    do {
      DestroyPreregisteredTypeInfoTree(current->right);
      PreregisteredTypeInfoMapNodeRuntime* const next = current->left;
      ::operator delete(current);
      current = next;
    } while (current->isNil == 0u);
  }

  /**
   * Address: 0x008DA2E0 (FUN_008DA2E0, erase_Node)
   *
   * What it does:
   * Recursively releases one RTTI-map subtree by visiting the right branch
   * first, then deleting each traversed node while following left links.
   */
  [[maybe_unused]] void DestroyRuntimeTypeMapTree(
    PreregisteredTypeInfoMapNodeRuntime* node
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* current = node;
    if (current->isNil != 0u) {
      return;
    }

    do {
      DestroyRuntimeTypeMapTree(current->right);
      PreregisteredTypeInfoMapNodeRuntime* const next = current->left;
      ::operator delete(current);
      current = next;
    } while (current->isNil == 0u);
  }

  struct TypeInfoMapStorageRuntimeView
  {
    std::uint32_t reserved00 = 0;
    PreregisteredTypeInfoMapNodeRuntime* header = nullptr; // +0x04
    std::uint32_t size = 0;                                // +0x08
  };
  static_assert(offsetof(TypeInfoMapStorageRuntimeView, header) == 0x04, "TypeInfoMapStorageRuntimeView::header offset must be 0x04");
  static_assert(offsetof(TypeInfoMapStorageRuntimeView, size) == 0x08, "TypeInfoMapStorageRuntimeView::size offset must be 0x08");
  static_assert(sizeof(TypeInfoMapStorageRuntimeView) == 0x0C, "TypeInfoMapStorageRuntimeView size must be 0x0C");

  /**
   * Address: 0x008DF620 (FUN_008DF620)
   *
   * What it does:
   * Initializes one runtime `map_type_info` storage lane by allocating a
   * sentinel header node and wiring the header self-links.
   */
  [[maybe_unused]] TypeInfoMapStorageRuntimeView* InitializeTypeInfoMapStorageRuntime(
    TypeInfoMapStorageRuntimeView* storage
  ) noexcept;

  /**
   * Address: 0x008DF620 (FUN_008DF620)
   *
   * What it does:
   * Initializes one runtime `map_type_info` storage lane by allocating a
   * sentinel header node and wiring the header self-links.
   */
  [[maybe_unused]] TypeInfoMapStorageRuntimeView* InitializeTypeInfoMapStorageRuntime(
    TypeInfoMapStorageRuntimeView* const storage
  ) noexcept
  {
    auto* const header = reinterpret_cast<PreregisteredTypeInfoMapNodeRuntime*>(AllocatePreregisteredRTypeMapNode());
    storage->header = header;
    header->isNil = 1u;
    header->parent = header;
    header->left = header;
    header->right = header;
    storage->size = 0;
    return storage;
  }

  /**
   * Address: 0x008DF5C0 (FUN_008DF5C0)
   *
   * What it does:
   * Destroys one `map_type_info` tree header and owned nodes, then nulls the
   * header lane and resets stored node-count to zero.
   */
  [[maybe_unused]] int DestroyTypeInfoMapStorageAndResetRuntime(
    TypeInfoMapStorageRuntimeView* const storage
  ) noexcept
  {
    if (storage == nullptr || storage->header == nullptr) {
      return 0;
    }

    DestroyPreregisteredTypeInfoTree(storage->header->left);
    ::operator delete(storage->header);
    storage->header = nullptr;
    storage->size = 0;
    return 0;
  }

  /**
   * Address: 0x008D8EB0 (func_TreeNodeSetNextFree)
   * Address: 0x00946830 (FUN_00946830)
   * Address: 0x00946880 (FUN_00946880)
   * Address: 0x009468D0 (FUN_009468D0)
   *
   * What it does:
   * Advances one RTTI-map cursor to the next in-order live node, following the
   * same right-subtree / parent-climb successor rules as the binary helper.
   */
  [[maybe_unused]] PreregisteredTypeInfoMapNodeRuntime* AdvanceRuntimeTypeMapCursor(
    PreregisteredTypeInfoMapNodeRuntime** cursor
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* node = *cursor;
    if (node->isNil == 0u) {
      PreregisteredTypeInfoMapNodeRuntime* right = node->right;
      if (right->isNil == 0u) {
        for (node = right->left; node->isNil == 0u; node = node->left) {
          right = node;
        }
        *cursor = right;
      } else {
        for (node = node->parent; node->isNil == 0u; node = node->parent) {
          if (*cursor != node->right) {
            break;
          }
          *cursor = node;
        }
        *cursor = node;
      }
    }
    return node;
  }

  /**
   * Address: 0x008D98E0 (FUN_008D98E0, func_RTypeTreeFind)
   *
   * What it does:
   * Finds the first preregistered type-map node that is not strictly less than
   * `*lookupTypeInfo`, following the original tree-lane traversal.
   */
  [[maybe_unused]] [[nodiscard]] PreregisteredTypeInfoMapNodeRuntime* FindRuntimeTypeInfoLowerBoundNode(
    PreregisteredTypeInfoMapNodeRuntime* const treeHeader,
    const std::type_info* const* const lookupTypeInfo
  ) noexcept
  {
    PreregisteredTypeInfoMapNodeRuntime* const result = treeHeader->parent;
    PreregisteredTypeInfoMapNodeRuntime* parent = result->parent;
    PreregisteredTypeInfoMapNodeRuntime* candidate = result;

    if (parent->isNil == 0u) {
      while (true) {
        const std::type_info* const nodeTypeInfo = parent->typeInfo;
        const bool hasLookup = lookupTypeInfo != nullptr && *lookupTypeInfo != nullptr;
        const bool goRight = (nodeTypeInfo != nullptr)
          ? (hasLookup && nodeTypeInfo->before(**lookupTypeInfo))
          : hasLookup;

        if (goRight) {
          parent = parent->right;
        } else {
          candidate = parent;
          parent = parent->left;
        }

        if (parent->isNil != 0u) {
          return candidate;
        }
      }
    }

    return result;
  }

  struct NamedTypeMapNodeRuntime
  {
    NamedTypeMapNodeRuntime* left;
    NamedTypeMapNodeRuntime* parent;
    NamedTypeMapNodeRuntime* right;
    const char* typeName;
    gpg::RType* type;
    std::uint8_t color;
    std::uint8_t isNil;
    std::uint8_t reserved16[2];
  };
  static_assert(sizeof(NamedTypeMapNodeRuntime) == 0x18, "NamedTypeMapNodeRuntime size must be 0x18");
  static_assert(offsetof(NamedTypeMapNodeRuntime, isNil) == 0x15, "NamedTypeMapNodeRuntime::isNil offset must be 0x15");

  /**
   * Address: 0x008D9A50 (FUN_008D9A50, _Tree::_Lbound)
   *
   * What it does:
   * Finds the first named-type map node whose key is not lexically less than
   * `*lookupTypeName`, following the original header-sentinel tree traversal.
   */
  [[maybe_unused]] [[nodiscard]] NamedTypeMapNodeRuntime* FindNamedTypeMapLowerBoundNode(
    NamedTypeMapNodeRuntime* const treeHeader,
    const char* const* const lookupTypeName
  ) noexcept
  {
    NamedTypeMapNodeRuntime* result = treeHeader;
    NamedTypeMapNodeRuntime* parent = result->parent;

    while (parent->isNil == 0u) {
      if (std::strcmp(parent->typeName, *lookupTypeName) < 0) {
        parent = parent->right;
      } else {
        result = parent;
        parent = parent->left;
      }
    }

    return result;
  }

  struct TypeInfoMapValueRuntime
  {
    const std::type_info* typeInfo;
    gpg::RType* type;
  };
  static_assert(sizeof(TypeInfoMapValueRuntime) == 0x08, "TypeInfoMapValueRuntime size must be 0x08");

  /**
   * Address: 0x008D9290 (FUN_008D9290)
   *
   * What it does:
   * Fills one dword range `[begin, end)` with the scalar lane `*value`.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeWithLaneValue(
    std::uint32_t* const begin,
    std::uint32_t* const end,
    const std::uint32_t* const value
  ) noexcept
  {
    std::uint32_t* cursor = begin;
    while (cursor != end) {
      *cursor = *value;
      ++cursor;
    }
    return cursor;
  }

  /**
   * Address: 0x008D92D0 (FUN_008D92D0)
   *
   * What it does:
   * Copies one `[begin, end)` array of type-map value pairs into destination
   * storage in reverse order and returns the destination begin cursor.
   */
  [[maybe_unused]] TypeInfoMapValueRuntime* CopyTypeInfoMapValueRangeBackward(
    const TypeInfoMapValueRuntime* const begin,
    const TypeInfoMapValueRuntime* end,
    TypeInfoMapValueRuntime* destEnd
  ) noexcept
  {
    while (end != begin) {
      --end;
      --destEnd;
      *destEnd = *end;
    }

    return destEnd;
  }

  /**
   * Address: 0x008D9330 (FUN_008D9330)
   *
   * What it does:
   * Copies one type-map value pair into `outValue` when `outValue` is not
   * null and returns the output cursor.
   */
  [[maybe_unused]] TypeInfoMapValueRuntime* CopyTypeInfoMapValueIfPresent(
    TypeInfoMapValueRuntime* const outValue,
    const TypeInfoMapValueRuntime* const sourceValue
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceValue;
    }

    return outValue;
  }

  /**
   * Address: 0x008D9390 (FUN_008D9390)
   *
   * What it does:
   * Compares two type-map keys by raw key-lane address ordering.
   */
  [[maybe_unused]] bool IsTypeInfoMapKeyLaneLessThan(
    const TypeInfoMapValueRuntime* const lhs,
    const TypeInfoMapValueRuntime* const rhs
  ) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(lhs->typeInfo) < reinterpret_cast<std::uintptr_t>(rhs->typeInfo);
  }

  /**
   * Address: 0x008D93A0 (FUN_008D93A0)
   *
   * What it does:
   * Assigns one `(type_info, RType*)` value pair from separate key/value
   * source lanes.
   */
  [[maybe_unused]] TypeInfoMapValueRuntime* AssignTypeInfoMapValueLanes(
    TypeInfoMapValueRuntime* const outValue,
    const std::type_info* const* const keyLane,
    gpg::RType* const* const valueLane
  ) noexcept
  {
    outValue->typeInfo = *keyLane;
    outValue->type = *valueLane;
    return outValue;
  }

  struct FieldArrayByteCursorRuntime
  {
    std::uint32_t byteOffset;
  };
  static_assert(sizeof(FieldArrayByteCursorRuntime) == 0x04, "FieldArrayByteCursorRuntime size must be 0x04");

  /**
   * Address: 0x008D93C0 (FUN_008D93C0)
   *
   * What it does:
   * Advances one byte-offset cursor by one `RField` record stride (0x14).
   */
  [[maybe_unused]] FieldArrayByteCursorRuntime* AdvanceFieldArrayByteCursor(
    FieldArrayByteCursorRuntime* const cursor
  ) noexcept
  {
    cursor->byteOffset += static_cast<std::uint32_t>(sizeof(gpg::RField));
    return cursor;
  }

  /**
   * Address: 0x008D93D0 (FUN_008D93D0)
   *
   * What it does:
   * Rewinds one byte-offset cursor by one `RField` record stride (0x14).
   */
  [[maybe_unused]] FieldArrayByteCursorRuntime* RewindFieldArrayByteCursor(
    FieldArrayByteCursorRuntime* const cursor
  ) noexcept
  {
    cursor->byteOffset -= static_cast<std::uint32_t>(sizeof(gpg::RField));
    return cursor;
  }

  /**
   * Address: 0x008D9410 (FUN_008D9410)
   *
   * What it does:
   * Swaps two `RField` records in place and returns `lhs`.
   */
  [[maybe_unused]] gpg::RField* SwapRFieldRecords(
    gpg::RField* const lhs,
    gpg::RField* const rhs
  ) noexcept
  {
    const gpg::RField saved = *lhs;
    *lhs = *rhs;
    *rhs = saved;
    return lhs;
  }

  /**
   * Address: 0x008D9480 (FUN_008D9480)
   *
   * What it does:
   * Writes `count` dwords from `begin` with the scalar lane `*value`.
   */
  [[maybe_unused]] int FillDwordCountWithLaneValue(
    std::uint32_t* begin,
    const int count,
    const std::uint32_t* const value
  ) noexcept
  {
    int remaining = count;
    while (remaining > 0) {
      *begin = *value;
      ++begin;
      --remaining;
    }

    return remaining;
  }

  struct TripleLaneRuntime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
  };
  static_assert(sizeof(TripleLaneRuntime) == 0x0C, "TripleLaneRuntime size must be 0x0C");

  /**
   * Address: 0x008D97B0 (FUN_008D97B0)
   *
   * What it does:
   * Loads lane1 from a triple-lane runtime object into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane1(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane1;
    return outValue;
  }

  /**
   * Address: 0x008D97C0 (FUN_008D97C0)
   *
   * What it does:
   * Loads lane2 from a triple-lane runtime object into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane2_A(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane2;
    return outValue;
  }

  /**
   * Address: 0x008D9830 (FUN_008D9830)
   *
   * What it does:
   * Alias lane that also loads lane2 from a triple-lane runtime object.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane2_B(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane2;
    return outValue;
  }

  /**
   * Address: 0x008D9860 (FUN_008D9860)
   *
   * What it does:
   * Stores one value into lane0 and returns `state`.
   */
  [[maybe_unused]] TripleLaneRuntime* WriteTripleLane0_A(
    TripleLaneRuntime* const state,
    const std::uint32_t value
  ) noexcept
  {
    state->lane0 = value;
    return state;
  }

  /**
   * Address: 0x008D98A0 (FUN_008D98A0)
   *
   * What it does:
   * Alias lane that stores one value into lane0 and returns `state`.
   */
  [[maybe_unused]] TripleLaneRuntime* WriteTripleLane0_B(
    TripleLaneRuntime* const state,
    const std::uint32_t value
  ) noexcept
  {
    state->lane0 = value;
    return state;
  }

  /**
   * Address: 0x008D98C0 (FUN_008D98C0)
   *
   * What it does:
   * Loads lane1 from a triple-lane runtime object into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane1_B(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane1;
    return outValue;
  }

  struct IndirectLaneRuntime
  {
    std::uint32_t lane0;
    std::uint32_t* lane1Ptr;
  };
  static_assert(sizeof(IndirectLaneRuntime) == 0x08, "IndirectLaneRuntime size must be 0x08");

  /**
   * Address: 0x008D9A40 (FUN_008D9A40)
   *
   * What it does:
   * Reads one doubly-indirect dword lane (`*lane1Ptr`) into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadIndirectLaneValue_A(
    const IndirectLaneRuntime* const state,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = *state->lane1Ptr;
    return outValue;
  }

  /**
   * Address: 0x008D9AF0 (FUN_008D9AF0)
   *
   * What it does:
   * Resets one dword lane to zero.
   */
  [[maybe_unused]] std::uint32_t* ResetDwordLaneToZero(
    std::uint32_t* const lane
  ) noexcept
  {
    *lane = 0u;
    return lane;
  }

  /**
   * Address: 0x008D9B10 (FUN_008D9B10)
   *
   * What it does:
   * Writes one value into a dword lane.
   */
  [[maybe_unused]] std::uint32_t* WriteDwordLaneValue(
    std::uint32_t* const lane,
    const std::uint32_t value
  ) noexcept
  {
    *lane = value;
    return lane;
  }

  /**
   * Address: 0x008DA020 (FUN_008DA020)
   *
   * What it does:
   * Reads one doubly-indirect dword lane (`*lane1Ptr`) into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadIndirectLaneValue_B(
    const IndirectLaneRuntime* const state,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = *state->lane1Ptr;
    return outValue;
  }

  /**
   * Address: 0x008DA030 (FUN_008DA030)
   *
   * What it does:
   * Loads lane1 from a triple-lane runtime object into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane1_C(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane1;
    return outValue;
  }

  /**
   * Address: 0x008DA050 (FUN_008DA050)
   *
   * What it does:
   * Alias lane that loads lane1 from a triple-lane runtime object.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane1_D(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane1;
    return outValue;
  }

  /**
   * Address: 0x008DA0C0 (FUN_008DA0C0)
   *
   * What it does:
   * Loads lane2 from a triple-lane runtime object into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane2_C(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane2;
    return outValue;
  }

  /**
   * Address: 0x008DA120 (FUN_008DA120)
   *
   * What it does:
   * Loads lane1 from a triple-lane runtime object into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ReadTripleLane1_E(
    const TripleLaneRuntime* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->lane1;
    return outValue;
  }

  /**
   * Address: 0x008DA160 (FUN_008DA160)
   * Address: 0x00941A40 (FUN_00941A40)
   *
   * What it does:
   * Computes one byte-offset lane by `base + (index * 8)` and stores it in
   * `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ComputeByteOffsetLaneStride8(
    const std::uint32_t* const base,
    std::uint32_t* const outValue,
    const int index
  ) noexcept
  {
    *outValue = *base + static_cast<std::uint32_t>(sizeof(TypeInfoMapValueRuntime) * index);
    return outValue;
  }

  /**
   * Address: 0x008DA180 (FUN_008DA180)
   *
   * What it does:
   * Computes one byte-offset lane by `base + (index * 4)` and stores it in
   * `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ComputeByteOffsetLaneStride4(
    const std::uint32_t* const base,
    std::uint32_t* const outValue,
    const int index
  ) noexcept
  {
    *outValue = *base + static_cast<std::uint32_t>(sizeof(std::uint32_t) * index);
    return outValue;
  }

  struct VTableAndThreeStateLanesRuntime
  {
    void* vftable;
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint32_t lane0C;
  };
  static_assert(sizeof(VTableAndThreeStateLanesRuntime) == 0x10, "VTableAndThreeStateLanesRuntime size must be 0x10");

  /**
   * Address: 0x008DD480 (FUN_008DD480)
   *
   * What it does:
   * Clears runtime state lanes `+0x04/+0x08/+0x0C` and returns `state`.
   */
  [[maybe_unused]] VTableAndThreeStateLanesRuntime* ResetThreeStateLanes_A(
    VTableAndThreeStateLanesRuntime* const state
  ) noexcept
  {
    state->lane04 = 0u;
    state->lane08 = 0u;
    state->lane0C = 0u;
    return state;
  }

  /**
   * Address: 0x008DD490 (FUN_008DD490)
   *
   * What it does:
   * Alias lane that clears runtime state lanes `+0x04/+0x08/+0x0C`.
   */
  [[maybe_unused]] VTableAndThreeStateLanesRuntime* ResetThreeStateLanes_B(
    VTableAndThreeStateLanesRuntime* const state
  ) noexcept
  {
    state->lane04 = 0u;
    state->lane08 = 0u;
    state->lane0C = 0u;
    return state;
  }

  /**
   * Address: 0x00C09760 (FUN_00C09760, gpg::Rect2iTypeInfo::~Rect2iTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `Rect2<int>` descriptor.
   */
  void cleanup_Rect2iTypeInfo()
  {
    DestroyTypeInfo(gRect2iTypeInfoStorage);
  }

  /**
   * Address: 0x00C097C0 (FUN_00C097C0, gpg::Rect2fTypeInfo::~Rect2fTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `Rect2<float>` descriptor.
   */
  void cleanup_Rect2fTypeInfo()
  {
    DestroyTypeInfo(gRect2fTypeInfoStorage);
  }

  /**
   * Address: 0x00BE9DB0 (FUN_00BE9DB0, register_Rect2iTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the `Rect2<int>` reflection type descriptor and
   * wires its teardown callback into CRT `atexit`.
   */
  void register_Rect2iTypeInfo()
  {
    gpg::Rect2iTypeInfo& typeInfo = GetRect2iTypeInfo();
    gpg::PreRegisterRType(typeid(gpg::Rect2i), &typeInfo);
    (void)std::atexit(&cleanup_Rect2iTypeInfo);
  }

  /**
   * Address: 0x00BE9E50 (FUN_00BE9E50, register_Rect2fTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the `Rect2<float>` reflection type descriptor
   * and wires its teardown callback into CRT `atexit`.
   */
  void register_Rect2fTypeInfo()
  {
    gpg::Rect2fTypeInfo& typeInfo = GetRect2fTypeInfo();
    gpg::PreRegisterRType(typeid(gpg::Rect2f), &typeInfo);
    (void)std::atexit(&cleanup_Rect2fTypeInfo);
  }

  struct Rect2ReflectionRegistration
  {
    Rect2ReflectionRegistration()
    {
      register_Rect2iTypeInfo();
      register_Rect2fTypeInfo();

      gRect2iSerializer.mHelperNext = nullptr;
      gRect2iSerializer.mHelperPrev = nullptr;
      gRect2iSerializer.mLoadCallback = &DeserializeRect2i;
      gRect2iSerializer.mSaveCallback = &SerializeRect2i;

      gRect2fSerializer.mHelperNext = nullptr;
      gRect2fSerializer.mHelperPrev = nullptr;
      gRect2fSerializer.mLoadCallback = &DeserializeRect2f;
      gRect2fSerializer.mSaveCallback = &SerializeRect2f;
    }
  };

Rect2ReflectionRegistration gRect2ReflectionRegistration;

struct PointerTypeRegistration
{
    PointerTypeRegistration()
    {
        (void)gpg::preregister_CAcquireTargetTaskPointerTypeStartup();
        gpg::PreRegisterRType(typeid(moho::RBlueprint*), &gRBlueprintPointerType);
        gpg::PreRegisterRType(typeid(moho::UnitWeapon*), &gUnitWeaponPointerType);
        gpg::PreRegisterRType(typeid(moho::IAniManipulator*), &gIAniManipulatorPointerType);
        gpg::PreRegisterRType(typeid(moho::IEffect*), &gIEffectPointerType);
        gpg::PreRegisterRType(typeid(moho::CUnitCommand*), &gCUnitCommandPointerType);
        gpg::PreRegisterRType(typeid(moho::Entity*), &gEntityPointerType);
        gpg::PreRegisterRType(typeid(moho::CEconomyEvent*), &gCEconomyEventPointerType);
        gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), &gCLuaConOutputHandlerPointerType);
        gpg::PreRegisterRType(typeid(moho::CScriptObject*), &gCScriptObjectPointerType);
        gpg::PreRegisterRType(typeid(moho::CSndParams*), &gCSndParamsPointerType);
    }
};

PointerTypeRegistration gPointerTypeRegistration;
} // namespace

/**
 * Address: 0x005DE010 (FUN_005DE010, preregister_CAcquireTargetTaskPointerTypeStartup)
 *
 * What it does:
 * Preregisters the startup-owned pointer reflection descriptor for
 * `moho::CAcquireTargetTask*`.
 */
namespace gpg
{
gpg::RType* preregister_CAcquireTargetTaskPointerTypeStartup()
{
  gpg::PreRegisterRType(typeid(moho::CAcquireTargetTask*), &gCAcquireTargetTaskPointerType);
  return &gCAcquireTargetTaskPointerType;
}

RType* RType::sType = nullptr;

RField::RField()
  : mName(nullptr)
  , mType(nullptr)
  , mOffset(0)
  , v4(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , v4(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset, const int v, const char* desc)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , v4(v)
  , mDesc(desc)
{}

/**
 * Address: 0x008DA730 (FUN_008DA730, func_RTypeTreeSetToFind)
 *
 * What it does:
 * Resolves one preregistered RTTI-map node for `lookupTypeInfo` and returns
 * end-iterator when the lower-bound candidate is not an exact/equivalent key.
 */
[[nodiscard]] static TypeInfoMap::iterator FindRTypePreregisteredNode(
  TypeInfoMap& preregistered,
  const std::type_info* const lookupTypeInfo
)
{
  const TypeInfoMap::iterator found = preregistered.lower_bound(lookupTypeInfo);
  if (found == preregistered.end()) {
    return found;
  }

  const std::type_info* const candidateTypeInfo = found->first;
  if (lookupTypeInfo != nullptr) {
    if (candidateTypeInfo == nullptr || !lookupTypeInfo->before(*candidateTypeInfo)) {
      return found;
    }
  } else if (candidateTypeInfo == nullptr) {
    return found;
  }

  return preregistered.end();
}

RType* LookupRType(const std::type_info& typeInfo)
{
  TypeInfoMap& preregistered = GetRTypePreregisteredMap();
  const TypeInfoMap::iterator it = FindRTypePreregisteredNode(preregistered, &typeInfo);
  if (it == preregistered.end()) {
    const msvc8::string msg =
      STR_Printf("Attempting to lookup the RType for %s before it is registered.", typeInfo.name());
    throw std::runtime_error(msg.c_str());
  }

  RType* type = it->second;
  if (!type->finished_) {
    type->finished_ = true;
    type->Init();
    type->RegisterType();
    type->initFinished_ = true;
  }

  return type;
}

/**
 * Address: 0x008DF850 (FUN_008DF850, gpg::PreRegisterRType)
 *
 * What it does:
 * Adds `{type_info*, RType*}` to the preregistration map used by lazy
 * reflection type finalization.
 */
void PreRegisterRType(const std::type_info& typeInfo, RType* type)
{
  GetRTypePreregisteredMap().insert(TypeInfoMap::value_type(&typeInfo, type));
}

/**
 * Address: 0x008E0810 (FUN_008E0810, gpg::REF_RegisterAllTypes)
 *
 * What it does:
 * Iterates the preregistered RTTI map, forces each type through lazy
 * registration, aggregates initialization errors, and throws one runtime
 * error containing concatenated messages when any registration fails.
 */
void REF_RegisterAllTypes()
{
  // The `std::basic_stringstream<char>` destructor used to tear down `errs`
  // below compiles to the shared CRT body at `0x008D49F0` (FUN_008D49F0):
  // it reseats the ios/iostream/ostream/istream vtable lanes back to their
  // base-class vtables, then destroys the embedded `std::stringbuf` member
  // via `std::stringbuf::~stringbuf` (FUN_0047AC80). Binary-only wiring.
  std::stringstream errs;

  for (TypeInfoMap::const_iterator it = GetRTypePreregisteredMap().begin(); it != GetRTypePreregisteredMap().end();
       ++it) {
    try {
      (void)LookupRType(*it->first);
    } catch (const std::exception& ex) {
      errs << ex.what() << std::endl;
    }
  }

  const std::string aggregated = errs.str();
  if (!aggregated.empty()) {
    // The `std::runtime_error(const std::string&)` constructor the compiler
    // inlines here is at `0x008D4A80` (FUN_008D4A80): it stores the message
    // into the exception's `std::string` member via the runtime string-copy
    // helper at `0x0047B610` (FUN_0047B610). Binary-only wiring.
    throw std::runtime_error(aggregated);
  }
}

/**
 * Address: 0x008DD940 (FUN_008DD940, gpg::REF_GetTypeIndexed)
 *
 * What it does:
 * Returns the reflected type descriptor at one global type-vector index.
 */
const RType* REF_GetTypeIndexed(const int index)
{
  return GetRTypeVec()[index];
}

/**
 * Address: 0x008DF950 (FUN_008DF950, gpg::REF_GetTypeCount)
 *
 * What it does:
 * Returns the number of reflected types currently present in the global
 * registration map.
 */
std::size_t REF_GetTypeCount()
{
  return GetRTypeMap().size();
}

/**
 * Address: 0x008DF910 (FUN_008DF910, gpg::REF_FindTypeNamed `_0` overload)
 *
 * What it does:
 * Looks up one reflected type by exact name and returns null when the input
 * name is null or missing from the global RTTI map.
 */
RType* REF_FindTypeNamed(const char* const name)
{
  if (!name) {
    return nullptr;
  }

  const TypeMap::const_iterator it = GetRTypeMap().find(name);
  if (it == GetRTypeMap().end()) {
    return nullptr;
  }

  return it->second;
}

/**
 * Address: 0x008D9590 (FUN_008D9590, gpg::REF_UpcastPtr)
 *
 * What it does:
 * Recursively traverses reflected base lanes to find one compatible base pointer
 * view and returns `{nullptr, targetType}` for null-object upcast lanes.
 */
RRef REF_UpcastPtr(const RRef& source, const RType* const targetType)
{
  if (source.mType == targetType) {
    return source;
  }

  if (!source.mObj) {
    return RRef{nullptr, const_cast<RType*>(targetType)};
  }

  if (!source.mType) {
    return {};
  }

  const RField* base = source.mType->bases_.begin();
  if (!base) {
    return {};
  }

  const RField* const baseEnd = source.mType->bases_.end();
  for (; base != baseEnd; ++base) {
    RRef baseRef{};
    baseRef.mObj =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(source.mObj) + static_cast<std::uintptr_t>(base->mOffset));
    baseRef.mType = base->mType;

    const RRef upcast = REF_UpcastPtr(baseRef, targetType);
    if (upcast.mObj) {
      return upcast;
    }
  }

  return {};
}

RRef RRef_ArchiveToken(ArchiveToken* const token)
{
  RRef out{};
  out.mObj = token;

  try {
    out.mType = LookupRType(typeid(ArchiveToken));
  } catch (...) {
    out.mType = nullptr;
  }

  return out;
}

/**
 * Address: 0x00402400 (FUN_00402400, gpg::SerHelperBase::SerHelperBase)
 *
 * What it does:
 * Self-links this helper node as an empty singleton list.
 */
gpg::SerHelperBase::SerHelperBase()
  : mNext(this)
  , mPrev(this)
{
}

gpg::SerHelperBase* gpg::SerHelperBase::sNewHelpers = nullptr;

namespace
{
  struct SerHelperCtorQueueNodeRuntimeView
  {
    SerHelperCtorQueueNodeRuntimeView* mNext = nullptr; // +0x00
    SerHelperCtorQueueNodeRuntimeView* mPrev = nullptr; // +0x04
  };
  static_assert(
    sizeof(SerHelperCtorQueueNodeRuntimeView) == 0x8,
    "SerHelperCtorQueueNodeRuntimeView size must be 0x8"
  );

  struct SerHelperCtorRuntimeView
  {
    void** vtable = nullptr;                               // +0x00
    SerHelperCtorQueueNodeRuntimeView links{};             // +0x04
  };
  static_assert(
    offsetof(SerHelperCtorRuntimeView, links) == 0x4,
    "SerHelperCtorRuntimeView::links offset must be 0x4"
  );
  static_assert(sizeof(SerHelperCtorRuntimeView) == 0xC, "SerHelperCtorRuntimeView size must be 0xC");

  void* gSerHelperBaseCtorRuntimeVTableTag = nullptr;
}

/**
 * Address: 0x009501D0 (FUN_009501D0, gpg::SerHelperBase::SerHelperBase)
 *
 * What it does:
 * Initializes one serializer-helper runtime node (`vtable + links`), ensures
 * the process-global pending-helper list root exists, then inserts this node
 * into that pending intrusive list.
 */
[[maybe_unused]] SerHelperCtorRuntimeView* ConstructSerHelperRuntimeAndQueueForInit(
  SerHelperCtorRuntimeView* const runtime
)
{
  if (runtime == nullptr) {
    return nullptr;
  }

  auto* const links = &runtime->links;
  links->mPrev = links;
  links->mNext = links;
  runtime->vtable = reinterpret_cast<void**>(&gSerHelperBaseCtorRuntimeVTableTag);

  auto* root = reinterpret_cast<SerHelperCtorQueueNodeRuntimeView*>(gpg::SerHelperBase::sNewHelpers);
  if (root == nullptr) {
    root = static_cast<SerHelperCtorQueueNodeRuntimeView*>(
      ::operator new(sizeof(SerHelperCtorQueueNodeRuntimeView), std::nothrow)
    );
    if (root != nullptr) {
      root->mPrev = root;
      root->mNext = root;
    }
    gpg::SerHelperBase::sNewHelpers = reinterpret_cast<gpg::SerHelperBase*>(root);
  }

  links->mNext->mPrev = links->mPrev;
  links->mPrev->mNext = links->mNext;
  links->mNext = links;
  links->mPrev = links;

  if (root != nullptr) {
    links->mNext = root->mNext;
    links->mPrev = root;
    root->mNext = links;
    links->mNext->mPrev = links;
  }

  return runtime;
}

/**
 * Address: 0x004027D0 (FUN_004027D0, duplicate helper body)
 *
 * What it does:
 * Unlinks this helper node from current intrusive links, then self-links it.
 */
void gpg::SerHelperBase::ResetLinks()
{
  mNext->mPrev = mPrev;
  mPrev->mNext = mNext;
  mPrev = this;
  mNext = this;
}

/**
 * Address: 0x00950D50 (FUN_00950D50, gpg::SerHelperBase::InitNewHelpers)
 *
 * What it does:
 * Drains the pending serializer-helper intrusive list by unlinking each helper
 * node, dispatching its first virtual lane, then releases the list root.
 */
void gpg::SerHelperBase::InitNewHelpers()
{
  struct SerHelperNodeRuntimeView
  {
    SerHelperNodeRuntimeView* mNext;
    SerHelperNodeRuntimeView* mPrev;
  };
  static_assert(sizeof(SerHelperNodeRuntimeView) == 0x8, "SerHelperNodeRuntimeView size must be 0x8");

  struct SerHelperRuntimeObjectView
  {
    void** vtable;
    SerHelperNodeRuntimeView links;
  };
  static_assert(offsetof(SerHelperRuntimeObjectView, links) == 0x4, "SerHelperRuntimeObjectView::links offset must be 0x4");

  using SerHelperInitFn = void(__thiscall*)(SerHelperRuntimeObjectView*);

  auto* root = reinterpret_cast<SerHelperNodeRuntimeView*>(sNewHelpers);
  if (root == nullptr) {
    return;
  }

  for (auto* node = root->mPrev; node != root; node = root->mPrev) {
    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;

    auto* const helper = reinterpret_cast<SerHelperRuntimeObjectView*>(reinterpret_cast<std::uint8_t*>(node) - 4);
    auto* const vtable = helper->vtable;
    if (vtable != nullptr && vtable[0] != nullptr) {
      reinterpret_cast<SerHelperInitFn>(vtable[0])(helper);
    }

    root = reinterpret_cast<SerHelperNodeRuntimeView*>(sNewHelpers);
    if (root == nullptr) {
      break;
    }
  }

  if (root == nullptr) {
    return;
  }

  root->mNext->mPrev = root->mPrev;
  root->mPrev->mNext = root->mNext;
  root->mPrev = root;
  root->mNext = root;
  ::operator delete(root);
  sNewHelpers = nullptr;
}

/**
 * Address: 0x00403020 (FUN_00403020, gpg::RRef_uint)
 *
 * What it does:
 * Builds a reflection reference for `unsigned int` using cached RTTI lookups.
 */
gpg::RRef* RRef_uint(RRef* const out, unsigned int* const value)
{
  return BuildTypedRefWithCache<unsigned int>(out, value, typeid(unsigned int), gUIntRRefType, gUIntRRefCache);
}

/**
 * Address: 0x00583450 (FUN_00583450, gpg::RRef_int)
 *
 * What it does:
 * Builds a reflection reference for `int` using cached RTTI lookups.
 */
gpg::RRef* RRef_int(RRef* const out, int* const value)
{
  return BuildTypedRefWithCache<int>(out, value, typeid(int), gIntRRefType, gIntRRefCache);
}

/**
 * Address: 0x00582080 (FUN_00582080, gpg::RRef_int pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_int` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_int(RRef* const out, int* const value)
{
  RRef tmp{};
  (void)RRef_int(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00526FD0 (FUN_00526FD0, gpg::RRef_float)
 *
 * What it does:
 * Builds a reflection reference for `float` using cached RTTI lookups.
 */
gpg::RRef* RRef_float(RRef* const out, float* const value)
{
  return BuildTypedRefWithCache<float>(out, value, typeid(float), gFloatRRefType, gFloatRRefCache);
}

/**
 * Address: 0x005832B0 (FUN_005832B0, gpg::RRef_bool)
 *
 * What it does:
 * Builds a reflection reference for `bool` using cached RTTI lookups.
 */
gpg::RRef* RRef_bool(RRef* const out, bool* const value)
{
  return BuildTypedRefWithCache<bool>(out, value, typeid(bool), gBoolRRefType, gBoolRRefCache);
}

/**
 * Address: 0x00582050 (FUN_00582050, gpg::RRef_bool pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_bool` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_bool(RRef* const out, bool* const value)
{
  RRef tmp{};
  (void)RRef_bool(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00642860 (FUN_00642860, gpg::RRef__Vb_reference)
 *
 * What it does:
 * Builds a reflection reference for one legacy `std::vector<bool>::reference`
 * proxy value pointer.
 */
gpg::RRef* RRef_VectorBoolReference(RRef* const out, std::vector<bool>::reference* const value)
{
  return BuildTypedRefWithCache<std::vector<bool>::reference>(
    out,
    value,
    typeid(std::vector<bool>::reference),
    gVectorBoolReferenceRRefType,
    gVectorBoolReferenceRRefCache
  );
}

/**
 * Address: 0x006424B0 (FUN_006424B0)
 *
 * What it does:
 * Packs one `RRef_VectorBoolReference` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_VectorBoolReference(
  RRef* const out,
  std::vector<bool>::reference* const value
)
{
  RRef tmp{};
  (void)RRef_VectorBoolReference(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00517940 (FUN_00517940, gpg::RRef_Vector3f)
 *
 * What it does:
 * Builds a reflection reference for `Wm3::Vector3f` using cached RTTI lookups.
 */
gpg::RRef* RRef_Vector3f(RRef* const out, Wm3::Vector3f* const value)
{
  return BuildTypedRefWithCache<Wm3::Vector3f>(out, value, typeid(Wm3::Vector3f), gVector3fRRefType, gVector3fRRefCache);
}

/**
 * Address: 0x00517030 (FUN_00517030)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_Vector3f` and writes
 * the resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildVector3fRefAdapterLane(
  Wm3::Vector3f* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  (void)gpg::RRef_Vector3f(&temp, value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x00513760 (FUN_00513760, gpg::RRef_string)
 *
 * What it does:
 * Builds a reflection reference for `msvc8::string` using cached RTTI
 * lookups.
 */
gpg::RRef* RRef_string(RRef* const out, msvc8::string* const value)
{
  return BuildTypedRefWithCache<msvc8::string>(out, value, typeid(msvc8::string), gStringRRefType, gStringRRefCache);
}

/**
 * Address: 0x005133B0 (FUN_005133B0)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_string` and writes the
 * resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildStringRefAdapterLane(
  msvc8::string* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  (void)gpg::RRef_string(&temp, value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x008E0A60 (FUN_008E0A60, gpg::RRef_char)
 *
 * What it does:
 * Builds a reflection reference for `char` using cached RTTI lookups.
 */
gpg::RRef* RRef_char(RRef* const out, char* const value)
{
  return BuildTypedRefWithCache<char>(out, value, typeid(char), gCharRRefType, gCharRRefCache);
}

/**
 * Address: 0x008E0C00 (FUN_008E0C00, gpg::RRef_short)
 *
 * What it does:
 * Builds a reflection reference for `short` using cached RTTI lookups.
 */
gpg::RRef* RRef_short(RRef* const out, short* const value)
{
  return BuildTypedRefWithCache<short>(out, value, typeid(short), gShortRRefType, gShortRRefCache);
}

/**
 * Address: 0x008E0DE0 (FUN_008E0DE0, gpg::RRef_long)
 *
 * What it does:
 * Builds a reflection reference for `long` using cached RTTI lookups.
 */
gpg::RRef* RRef_long(RRef* const out, long* const value)
{
  return BuildTypedRefWithCache<long>(out, value, typeid(long), gLongRRefType, gLongRRefCache);
}

/**
 * Address: 0x008E0FC0 (FUN_008E0FC0, gpg::RRef_schar)
 *
 * What it does:
 * Builds a reflection reference for `signed char` using cached RTTI lookups.
 */
gpg::RRef* RRef_schar(RRef* const out, signed char* const value)
{
  return BuildTypedRefWithCache<signed char>(out, value, typeid(signed char), gSCharRRefType, gSCharRRefCache);
}

/**
 * Address: 0x00736A30 (FUN_00736A30, gpg::RRef_uchar)
 *
 * What it does:
 * Builds a reflection reference for `unsigned char` using cached RTTI
 * lookups.
 */
gpg::RRef* RRef_uchar(RRef* const out, unsigned char* const value)
{
  return BuildTypedRefWithCache<unsigned char>(out, value, typeid(unsigned char), gUCharRRefType, gUCharRRefCache);
}

/**
 * Address: 0x008E11A0 (FUN_008E11A0, gpg::RRef_ushort)
 *
 * What it does:
 * Builds a reflection reference for `unsigned short` using cached RTTI
 * lookups.
 */
gpg::RRef* RRef_ushort(RRef* const out, unsigned short* const value)
{
  return BuildTypedRefWithCache<unsigned short>(
    out,
    value,
    typeid(unsigned short),
    gUShortRRefType,
    gUShortRRefCache
  );
}

/**
 * Address: 0x008E1380 (FUN_008E1380, gpg::RRef_ulong)
 *
 * What it does:
 * Builds a reflection reference for `unsigned long` using cached RTTI
 * lookups.
 */
gpg::RRef* RRef_ulong(RRef* const out, unsigned long* const value)
{
  return BuildTypedRefWithCache<unsigned long>(
    out,
    value,
    typeid(unsigned long),
    gULongRRefType,
    gULongRRefCache
  );
}

/**
 * Address: 0x00402D30 (FUN_00402D30, sub_402D30)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_uint` and copies lanes out.
 */
gpg::RRef* AssignUIntRef(RRef* const out, unsigned int* const value)
{
  RRef tmp{};
  RRef_uint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x008E1B70 (FUN_008E1B70)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ulong` and copies lanes
 * into caller-provided output storage.
 */
gpg::RRef* AssignULongRef(RRef* const out, unsigned long* const value)
{
  RRef tmp{};
  RRef_ulong(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00593520 (FUN_00593520, gpg::RRef_EEconResource)
 *
 * What it does:
 * Builds a reflection reference for `moho::EEconResource` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EEconResource(RRef* const out, moho::EEconResource* const value)
{
  return BuildTypedRefWithCache<moho::EEconResource>(
    out,
    value,
    typeid(moho::EEconResource),
    gEEconResourceRRefType,
    gEEconResourceRRefCache
  );
}

/**
 * Address: 0x0084A280 (FUN_0084A280)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EEconResource` and copies
 * lanes out.
 */
gpg::RRef* AssignEEconResourceRefAdapter(RRef* const out, moho::EEconResource* const value)
{
  RRef tmp{};
  RRef_EEconResource(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005937D0 (FUN_005937D0, gpg::RRef_EAlliance)
 *
 * What it does:
 * Builds a reflection reference for `moho::EAlliance` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EAlliance(RRef* const out, moho::EAlliance* const value)
{
  return BuildTypedRefWithCache<moho::EAlliance>(
    out,
    value,
    typeid(moho::EAlliance),
    gEAllianceRRefType,
    gEAllianceRRefCache
  );
}

/**
 * Address: 0x00593380 (FUN_00593380, gpg::RRef_ETriggerOperator)
 *
 * What it does:
 * Builds a reflection reference for `moho::ETriggerOperator` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_ETriggerOperator(RRef* const out, moho::ETriggerOperator* const value)
{
  return BuildTypedRefWithCache<moho::ETriggerOperator>(
    out,
    value,
    typeid(moho::ETriggerOperator),
    gETriggerOperatorRRefType,
    gETriggerOperatorRRefCache
  );
}

/**
 * Address: 0x00593D60 (FUN_00593D60, gpg::RRef_ECompareType)
 *
 * What it does:
 * Builds a reflection reference for `moho::ECompareType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_ECompareType(RRef* const out, moho::ECompareType* const value)
{
  return BuildTypedRefWithCache<moho::ECompareType>(
    out,
    value,
    typeid(moho::ECompareType),
    gECompareTypeRRefType,
    gECompareTypeRRefCache
  );
}

/**
 * Address: 0x00593BC0 (FUN_00593BC0, gpg::RRef_ESquadClass)
 *
 * What it does:
 * Builds a reflection reference for `moho::ESquadClass` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_ESquadClass(RRef* const out, moho::ESquadClass* const value)
{
  return BuildTypedRefWithCache<moho::ESquadClass>(
    out,
    value,
    typeid(moho::ESquadClass),
    gESquadClassRRefType,
    gESquadClassRRefCache
  );
}

/**
 * Address: 0x005CB020 (FUN_005CB020, gpg::RRef_EReconFlags)
 *
 * What it does:
 * Builds a reflection reference for `moho::EReconFlags` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EReconFlags(RRef* const out, moho::EReconFlags* const value)
{
  return BuildTypedRefWithCache<moho::EReconFlags>(
    out,
    value,
    typeid(moho::EReconFlags),
    gEReconFlagsRRefType,
    gEReconFlagsRRefCache
  );
}

/**
 * Address: 0x005E3660 (FUN_005E3660, gpg::RRef_EAiTargetType)
 *
 * What it does:
 * Builds a reflection reference for `moho::EAiTargetType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EAiTargetType(RRef* const out, moho::EAiTargetType* const value)
{
  return BuildTypedRefWithCache<moho::EAiTargetType>(
    out,
    value,
    typeid(moho::EAiTargetType),
    gEAiTargetTypeRRefType,
    gEAiTargetTypeRRefCache
  );
}

/**
 * Address: 0x0084A6F0 (FUN_0084A6F0, gpg::RRef_ESTITargetType)
 *
 * What it does:
 * Builds a reflection reference for `moho::ESTITargetType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_ESTITargetType(RRef* const out, moho::ESTITargetType* const value)
{
  return BuildTypedRefWithCache<moho::ESTITargetType>(
    out,
    value,
    typeid(moho::ESTITargetType),
    gESTITargetTypeRRefType,
    gESTITargetTypeRRefCache
  );
}

/**
 * Address: 0x0084A140 (FUN_0084A140, sub_84A140)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESTITargetType` and copies
 * lanes out.
 */
gpg::RRef* AssignESTITargetTypeRef(RRef* const out, moho::ESTITargetType* const value)
{
  RRef tmp{};
  RRef_ESTITargetType(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00704040 (FUN_00704040, sub_704040)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESquadClass` and copies
 * lanes out.
 */
gpg::RRef* AssignESquadClassRef(RRef* const out, moho::ESquadClass* const value)
{
  RRef tmp{};
  RRef_ESquadClass(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0078B020 (FUN_0078B020, gpg::RRef_EMauiScrollAxis)
 *
 * What it does:
 * Builds a reflection reference for `moho::EMauiScrollAxis` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EMauiScrollAxis(RRef* const out, moho::EMauiScrollAxis* const value)
{
  return BuildTypedRefWithCache<moho::EMauiScrollAxis>(
    out,
    value,
    typeid(moho::EMauiScrollAxis),
    gEMauiScrollAxisRRefType,
    gEMauiScrollAxisRRefCache
  );
}

/**
 * Address: 0x0078A9D0 (FUN_0078A9D0, sub_78A9D0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EMauiScrollAxis` and
 * copies lanes out.
 */
gpg::RRef* AssignEMauiScrollAxisRef(RRef* const out, moho::EMauiScrollAxis* const value)
{
  RRef tmp{};
  RRef_EMauiScrollAxis(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0078E880 (FUN_0078E880, gpg::RRef_EMauiKeyCode)
 *
 * What it does:
 * Builds a reflection reference for `moho::EMauiKeyCode` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EMauiKeyCode(RRef* const out, moho::EMauiKeyCode* const value)
{
  return BuildTypedRefWithCache<moho::EMauiKeyCode>(
    out,
    value,
    typeid(moho::EMauiKeyCode),
    gEMauiKeyCodeRRefType,
    gEMauiKeyCodeRRefCache
  );
}

/**
 * Address: 0x00795E00 (FUN_00795E00, gpg::RRef_EMauiEventType)
 *
 * What it does:
 * Builds a reflection reference for `moho::EMauiEventType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EMauiEventType(RRef* const out, moho::EMauiEventType* const value)
{
  return BuildTypedRefWithCache<moho::EMauiEventType>(
    out,
    value,
    typeid(moho::EMauiEventType),
    gEMauiEventTypeRRefType,
    gEMauiEventTypeRRefCache
  );
}

/**
 * Address: 0x00795DD0 (FUN_00795DD0, sub_795DD0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EMauiEventType` and
 * copies lanes out.
 */
gpg::RRef* AssignEMauiEventTypeRef(RRef* const out, moho::EMauiEventType* const value)
{
  RRef tmp{};
  RRef_EMauiEventType(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00831EC0 (FUN_00831EC0, gpg::RRef_EUnitCommandType)
 *
 * What it does:
 * Builds a reflection reference for `moho::EUnitCommandType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EUnitCommandType(RRef* const out, moho::EUnitCommandType* const value)
{
  return BuildTypedRefWithCache<moho::EUnitCommandType>(
    out,
    value,
    typeid(moho::EUnitCommandType),
    gEUnitCommandTypeRRefType,
    gEUnitCommandTypeRRefCache
  );
}

/**
 * Address: 0x00830D40 (FUN_00830D40, sub_830D40)
 *
 * What it does:
 * Primary wrapper that materializes a temporary `RRef_EUnitCommandType` and
 * copies lanes out.
 */
gpg::RRef* AssignEUnitCommandTypeRefPrimary(RRef* const out, moho::EUnitCommandType* const value)
{
  RRef tmp{};
  RRef_EUnitCommandType(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0084A170 (FUN_0084A170, sub_84A170)
 *
 * What it does:
 * Secondary wrapper that materializes a temporary `RRef_EUnitCommandType` and
 * copies lanes out.
 */
gpg::RRef* AssignEUnitCommandTypeRefSecondary(RRef* const out, moho::EUnitCommandType* const value)
{
  RRef tmp{};
  RRef_EUnitCommandType(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0060D7A0 (FUN_0060D7A0, gpg::RRef_EAiResult)
 *
 * What it does:
 * Builds a reflection reference for `moho::EAiResult` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EAiResult(RRef* const out, moho::EAiResult* const value)
{
  return BuildTypedRefWithCache<moho::EAiResult>(
    out,
    value,
    typeid(moho::EAiResult),
    gEAiResultRRefType,
    gEAiResultRRefCache
  );
}

/**
 * Address: 0x00692DB0 (FUN_00692DB0, gpg::RRef_EVisibilityMode)
 *
 * What it does:
 * Builds a reflection reference for `moho::EVisibilityMode` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EVisibilityMode(RRef* const out, moho::EVisibilityMode* const value)
{
  return BuildTypedRefWithCache<moho::EVisibilityMode>(
    out,
    value,
    typeid(moho::EVisibilityMode),
    gEVisibilityModeRRefType,
    gEVisibilityModeRRefCache
  );
}

/**
 * Address: 0x006B1C90 (FUN_006B1C90, gpg::RRef_EUnitState)
 *
 * What it does:
 * Builds a reflection reference for `moho::EUnitState` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EUnitState(RRef* const out, moho::EUnitState* const value)
{
  return BuildTypedRefWithCache<moho::EUnitState>(
    out,
    value,
    typeid(moho::EUnitState),
    gEUnitStateRRefType,
    gEUnitStateRRefCache
  );
}

/**
 * Address: 0x006B0C20 (FUN_006B0C20)
 *
 * What it does:
 * Materializes one temporary `RRef_EUnitState` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_EUnitState(RRef* const out, moho::EUnitState* const value)
{
  RRef tmp{};
  (void)RRef_EUnitState(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006D2150 (FUN_006D2150, gpg::RRef_EFireState)
 *
 * What it does:
 * Builds a reflection reference for `moho::EFireState` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EFireState(RRef* const out, moho::EFireState* const value)
{
  return BuildTypedRefWithCache<moho::EFireState>(
    out,
    value,
    typeid(moho::EFireState),
    gEFireStateRRefType,
    gEFireStateRRefCache
  );
}

/**
 * Address: 0x008BEC10 (FUN_008BEC10)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EFireState` and copies
 * lanes out.
 */
gpg::RRef* PackRRef_EFireState(RRef* const out, moho::EFireState* const value)
{
  RRef tmp{};
  RRef_EFireState(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006DD790 (FUN_006DD790, gpg::RRef_ELayer)
 *
 * What it does:
 * Builds a reflection reference for `moho::ELayer` using cached RTTI lookup.
 */
gpg::RRef* RRef_ELayer(RRef* const out, moho::ELayer* const value)
{
  return BuildTypedRefWithCache<moho::ELayer>(
    out,
    value,
    typeid(moho::ELayer),
    gELayerRRefType,
    gELayerRRefCache
  );
}

/**
 * Address: 0x007CB300 (FUN_007CB300, gpg::RRef_ENetProtocol)
 *
 * What it does:
 * Builds a reflection reference for network protocol enum lanes using cached
 * RTTI lookup (`moho::ENetProtocolType`, binary symbol tag `ENetProtocol`).
 */
gpg::RRef* RRef_ENetProtocol(RRef* const out, moho::ENetProtocolType* const value)
{
  return BuildTypedRefWithCache<moho::ENetProtocolType>(
    out,
    value,
    typeid(moho::ENetProtocolType),
    gENetProtocolRRefType,
    gENetProtocolRRefCache
  );
}

/**
 * Address: 0x00692F50 (FUN_00692F50, gpg::RRef_EIntel)
 *
 * What it does:
 * Builds a reflection reference for `moho::EIntel` using cached RTTI lookup.
 */
gpg::RRef* RRef_EIntel(RRef* const out, moho::EIntel* const value)
{
  return BuildTypedRefWithCache<moho::EIntel>(
    out,
    value,
    typeid(moho::EIntel),
    gEIntelRRefType,
    gEIntelRRefCache
  );
}

/**
 * Address: 0x00593F00 (FUN_00593F00, gpg::RRef_EThreatType)
 *
 * What it does:
 * Builds a reflection reference for `moho::EThreatType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EThreatType(RRef* const out, moho::EThreatType* const value)
{
  return BuildTypedRefWithCache<moho::EThreatType>(
    out,
    value,
    typeid(moho::EThreatType),
    gEThreatTypeRRefType,
    gEThreatTypeRRefCache
  );
}

/**
 * Address: 0x006D1FB0 (FUN_006D1FB0, gpg::RRef_ERuleBPUnitToggleCaps)
 *
 * What it does:
 * Builds a reflection reference for `moho::ERuleBPUnitToggleCaps` using
 * cached RTTI lookup.
 */
gpg::RRef* RRef_ERuleBPUnitToggleCaps(RRef* const out, moho::ERuleBPUnitToggleCaps* const value)
{
  return BuildTypedRefWithCache<moho::ERuleBPUnitToggleCaps>(
    out,
    value,
    typeid(moho::ERuleBPUnitToggleCaps),
    gERuleBPUnitToggleCapsRRefType,
    gERuleBPUnitToggleCapsRRefCache
  );
}

/**
 * Address: 0x0084A2B0 (FUN_0084A2B0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ERuleBPUnitToggleCaps` and
 * copies lanes out.
 */
gpg::RRef* AssignERuleBPUnitToggleCapsRefAdapter(
  RRef* const out,
  moho::ERuleBPUnitToggleCaps* const value
)
{
  RRef tmp{};
  RRef_ERuleBPUnitToggleCaps(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006D22F0 (FUN_006D22F0, gpg::RRef_ERuleBPUnitCommandCaps)
 *
 * What it does:
 * Builds a reflection reference for `moho::ERuleBPUnitCommandCaps` using
 * cached RTTI lookup.
 */
gpg::RRef* RRef_ERuleBPUnitCommandCaps(RRef* const out, moho::ERuleBPUnitCommandCaps* const value)
{
  return BuildTypedRefWithCache<moho::ERuleBPUnitCommandCaps>(
    out,
    value,
    typeid(moho::ERuleBPUnitCommandCaps),
    gERuleBPUnitCommandCapsRRefType,
    gERuleBPUnitCommandCapsRRefCache
  );
}

/**
 * Address: 0x0084ACA0 (FUN_0084ACA0, gpg::RRef_ESpecialFileType)
 *
 * What it does:
 * Builds a reflection reference for `moho::ESpecialFileType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_ESpecialFileType(RRef* const out, moho::ESpecialFileType* const value)
{
  return BuildTypedRefWithCache<moho::ESpecialFileType>(
    out,
    value,
    typeid(moho::ESpecialFileType),
    gESpecialFileTypeRRefType,
    gESpecialFileTypeRRefCache
  );
}

/**
 * Address: 0x0084A380 (FUN_0084A380)
 * Address: 0x008CD130 (FUN_008CD130)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESpecialFileType` and
 * copies lanes out.
 */
gpg::RRef* AssignESpecialFileTypeRefAdapter(
  RRef* const out,
  moho::ESpecialFileType* const value
)
{
  RRef tmp{};
  RRef_ESpecialFileType(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0085FB70 (FUN_0085FB70, gpg::RRef_EGenericIconType)
 *
 * What it does:
 * Builds a reflection reference for `moho::EGenericIconType` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_EGenericIconType(RRef* const out, moho::EGenericIconType* const value)
{
  return BuildTypedRefWithCache<moho::EGenericIconType>(
    out,
    value,
    typeid(moho::EGenericIconType),
    gEGenericIconTypeRRefType,
    gEGenericIconTypeRRefCache
  );
}

/**
 * Address: 0x0085F840 (FUN_0085F840, sub_85F840)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EGenericIconType` and
 * copies lanes out.
 */
gpg::RRef* AssignEGenericIconTypeRef(RRef* const out, moho::EGenericIconType* const value)
{
  RRef tmp{};
  RRef_EGenericIconType(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0040C030 (FUN_0040C030, gpg::RRef_CTaskThread_P)
 *
 * What it does:
 * Builds a reflection reference for `moho::CTaskThread` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CTaskThread(RRef* const out, moho::CTaskThread* const value)
{
  return BuildTypedRefWithCache<moho::CTaskThread>(
    out,
    value,
    typeid(moho::CTaskThread),
    gCTaskThreadRRefType,
    gCTaskThreadRRefCache
  );
}

/**
 * Address: 0x0063A2B0 (FUN_0063A2B0, gpg::RRef_CFootPlantManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CFootPlantManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CFootPlantManipulator(RRef* const out, moho::CFootPlantManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CFootPlantManipulator",
    "Moho::CFootPlantManipulator",
    gCFootPlantManipulatorRRefType,
    gCFootPlantManipulatorRRefCache
  );
}

/**
 * Address: 0x0063A230 (FUN_0063A230)
 *
 * What it does:
 * Wrapper lane that materializes one temporary `RRef_CFootPlantManipulator`
 * and copies object/type fields into the destination reference record.
 */
[[maybe_unused]] gpg::RRef* AssignCFootPlantManipulatorRef(
  RRef* const out, moho::CFootPlantManipulator* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  RRef_CFootPlantManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00642650 (FUN_00642650, gpg::RRef_CAnimationManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAnimationManipulator` using named
 * declared type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CAnimationManipulator(RRef* const out, moho::CAnimationManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CAnimationManipulator",
    "Moho::CAnimationManipulator",
    moho::CAnimationManipulator::sType,
    gCAnimationManipulatorRRefCache
  );
}

/**
 * Address: 0x00642370 (FUN_00642370)
 *
 * What it does:
 * Packs one `RRef_CAnimationManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CAnimationManipulator(
  RRef* const out,
  moho::CAnimationManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CAnimationManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006456F0 (FUN_006456F0, gpg::RRef_CRotateManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CRotateManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CRotateManipulator(RRef* const out, moho::CRotateManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CRotateManipulator",
    "Moho::CRotateManipulator",
    gCRotateManipulatorRRefType,
    gCRotateManipulatorRRefCache
  );
}

/**
 * Address: 0x00645630 (FUN_00645630)
 *
 * What it does:
 * Packs one `RRef_CRotateManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CRotateManipulator(
  RRef* const out,
  moho::CRotateManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CRotateManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006469D0 (FUN_006469D0)
 *
 * What it does:
 * Packs one `RRef_CSlaveManipulator` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CSlaveManipulator(
  RRef* const out,
  moho::CSlaveManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CSlaveManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006488A0 (FUN_006488A0)
 *
 * What it does:
 * Packs one `RRef_CSlideManipulator` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CSlideManipulator(
  RRef* const out,
  moho::CSlideManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_CSlideManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00649B80 (FUN_00649B80)
 *
 * What it does:
 * Packs one `RRef_CStorageManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CStorageManipulator(
  RRef* const out,
  moho::CStorageManipulator* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CStorageManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00649C00 (FUN_00649C00, gpg::RRef_CStorageManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CStorageManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CStorageManipulator(RRef* const out, moho::CStorageManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CStorageManipulator",
    "Moho::CStorageManipulator",
    gCStorageManipulatorRRefType,
    gCStorageManipulatorRRefCache
  );
}

/**
 * Address: 0x0064B470 (FUN_0064B470)
 * Address: 0x00635460 (FUN_00635460)
 * Address: 0x006372A0 (FUN_006372A0)
 *
 * What it does:
 * Packs one `RRef_CThrustManipulator` result into caller-owned output
 * storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CThrustManipulator(
  RRef* const out,
  moho::CThrustManipulator* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CThrustManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064B530 (FUN_0064B530, gpg::RRef_CThrustManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CThrustManipulator` using the
 * manipulator runtime type cache and base-offset normalization.
 */
gpg::RRef* RRef_CThrustManipulator(RRef* const out, moho::CThrustManipulator* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CThrustManipulator",
    "Moho::CThrustManipulator",
    gCThrustManipulatorRRefType,
    gCThrustManipulatorRRefCache
  );
}

/**
 * Address: 0x0063D230 (FUN_0063D230, gpg::RRef_CAniActor)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAniActor` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CAniActor(RRef* const out, moho::CAniActor* const value)
{
  return BuildTypedRefWithCache<moho::CAniActor>(
    out,
    value,
    typeid(moho::CAniActor),
    gCAniActorRRefType,
    gCAniActorRRefCache
  );
}

/**
 * Address: 0x0063CAE0 (FUN_0063CAE0)
 *
 * What it does:
 * Packs one `RRef_CAniActor` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CAniActor(RRef* const out, moho::CAniActor* const value)
{
  RRef tmp{};
  (void)RRef_CAniActor(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063D3F0 (FUN_0063D3F0, gpg::RRef_IAniManipulator)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAniManipulator` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_IAniManipulator(RRef* const out, moho::IAniManipulator* const value)
{
  return BuildTypedRefWithCache<moho::IAniManipulator>(
    out,
    value,
    typeid(moho::IAniManipulator),
    gIAniManipulatorRRefType,
    gIAniManipulatorRRefCache
  );
}

/**
 * Address: 0x0063E680 (FUN_0063E680)
 *
 * What it does:
 * Packs one `RRef_IAniManipulator` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_IAniManipulator(
  RRef* const out,
  moho::IAniManipulator* const value
)
{
  RRef tmp{};
  (void)RRef_IAniManipulator(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063D800 (FUN_0063D800, gpg::RRef_SAniManipBinding)
 *
 * What it does:
 * Builds a reflected reference for one `moho::SAniManipBinding` value
 * pointer.
 */
gpg::RRef* RRef_SAniManipBinding(RRef* const out, moho::SAniManipBinding* const value)
{
  return BuildTypedRefWithCache<moho::SAniManipBinding>(
    out,
    value,
    typeid(moho::SAniManipBinding),
    gSAniManipBindingRRefType,
    gSAniManipBindingRRefCache
  );
}

/**
 * Address: 0x0063CF70 (FUN_0063CF70)
 *
 * What it does:
 * Packs one `RRef_SAniManipBinding` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_SAniManipBinding(
  RRef* const out,
  moho::SAniManipBinding* const value
)
{
  RRef tmp{};
  (void)RRef_SAniManipBinding(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063D5A0 (FUN_0063D5A0, gpg::RRef_IAniManipulator_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::IAniManipulator*` slot.
 */
gpg::RRef* RRef_IAniManipulator_P(RRef* const out, moho::IAniManipulator** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::IAniManipulator>();
  return out;
}

/**
 * Address: 0x0063E6B0 (FUN_0063E6B0)
 *
 * What it does:
 * Packs one `RRef_IAniManipulator_P` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_IAniManipulator_P(
  RRef* const out,
  moho::IAniManipulator** const value
)
{
  RRef tmp{};
  (void)RRef_IAniManipulator_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005E04D0 (FUN_005E04D0, gpg::RRef_CAcquireTargetTask)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAcquireTargetTask` using cached
 * RTTI lookups and derived-type normalization.
 */
gpg::RRef* RRef_CAcquireTargetTask(RRef* const out, moho::CAcquireTargetTask* const value)
{
  return BuildTypedRefWithCache<moho::CAcquireTargetTask>(
    out,
    value,
    typeid(moho::CAcquireTargetTask),
    gCAcquireTargetTaskRRefType,
    gCAcquireTargetTaskRRefCache
  );
}

/**
 * Address: 0x006DED40 (FUN_006DED40, gpg::RRef_CFireWeaponTask)
 *
 * What it does:
 * Builds a reflection reference for `moho::CFireWeaponTask` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CFireWeaponTask(RRef* const out, moho::CFireWeaponTask* const value)
{
  return BuildTypedRefWithCache<moho::CFireWeaponTask>(
    out,
    value,
    typeid(moho::CFireWeaponTask),
    gCFireWeaponTaskRRefType,
    gCFireWeaponTaskRRefCache
  );
}

gpg::RRef* RRef_CUnitCaptureTask(RRef* const out, moho::CUnitCaptureTask* const value)
{
  return BuildTypedRefWithCache<moho::CUnitCaptureTask>(
    out,
    value,
    typeid(moho::CUnitCaptureTask),
    gCUnitCaptureTaskRRefType,
    gCUnitCaptureTaskRRefCache
  );
}

/**
 * Address: 0x0060CAB0 (FUN_0060CAB0, gpg::RRef_CUnitGetBuiltTask)
 * Mangled: ?RRef_CUnitGetBuiltTask@gpg@@YAPAURRef@1@AAU21@PAVCUnitGetBuiltTask@Moho@@@Z
 *
 * IDA signature:
 * gpg::RRef *__cdecl gpg::RRef_CUnitGetBuiltTask(gpg::RRef *out, Moho::CUnitGetBuiltTask *value);
 *
 * What it does:
 * Builds one typed reflection reference for `moho::CUnitGetBuiltTask*`,
 * preserving dynamic-derived ownership and base-offset adjustment. Caches
 * `typeid` -> `RType*` resolution in a TLS 3-slot MRU table to avoid
 * re-entering `gpg::LookupRType` for each call. Asserts
 * `IsDerivedFrom(runtime, declared)` when the caller's value is polymorphically
 * derived.
 */
gpg::RRef* RRef_CUnitGetBuiltTask(RRef* const out, moho::CUnitGetBuiltTask* const value)
{
  return BuildTypedRefWithCache<moho::CUnitGetBuiltTask>(
    out,
    value,
    typeid(moho::CUnitGetBuiltTask),
    gCUnitGetBuiltTaskRRefType,
    gCUnitGetBuiltTaskRRefCache
  );
}

gpg::RRef* RRef_CUnitGuardTask(RRef* const out, moho::CUnitGuardTask* const value)
{
  return BuildTypedRefWithCache<moho::CUnitGuardTask>(
    out,
    value,
    typeid(moho::CUnitGuardTask),
    gCUnitGuardTaskRRefType,
    gCUnitGuardTaskRRefCache
  );
}

gpg::RRef* RRef_CUnitUnloadUnits(RRef* const out, moho::CUnitUnloadUnits* const value)
{
  return BuildTypedRefWithCache<moho::CUnitUnloadUnits>(
    out,
    value,
    typeid(moho::CUnitUnloadUnits),
    gCUnitUnloadUnitsRRefType,
    gCUnitUnloadUnitsRRefCache
  );
}

/**
 * Address: 0x006DDDC0 (FUN_006DDDC0)
 *
 * What it does:
 * Packs one `RRef_CFireWeaponTask` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CFireWeaponTask(RRef* const out, moho::CFireWeaponTask* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CFireWeaponTask(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006A00F0 (FUN_006A00F0, gpg::RRef_ManyToOneListener_EProjectileImpactEvent)
 *
 * What it does:
 * Builds a reflection reference for `ManyToOneListener<EProjectileImpactEvent>`
 * using cached RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_ManyToOneListener_EProjectileImpactEvent(
  RRef* const out,
  moho::ManyToOneListener<moho::EProjectileImpactEvent>* const value
)
{
  return BuildTypedRefWithCache<moho::ManyToOneListener<moho::EProjectileImpactEvent>>(
    out,
    value,
    typeid(moho::ManyToOneListener<moho::EProjectileImpactEvent>),
    moho::ManyToOneListener<moho::EProjectileImpactEvent>::sType,
    gManyToOneListenerEProjectileImpactEventRRefCache
  );
}

/**
 * Address: 0x005E08D0 (FUN_005E08D0, gpg::RRef_CAcquireTargetTask_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CAcquireTargetTask*` slot.
 */
gpg::RRef* RRef_CAcquireTargetTask_P(RRef* const out, moho::CAcquireTargetTask** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CAcquireTargetTask>();
  return out;
}

/**
 * Address: 0x005DF0C0 (FUN_005DF0C0)
 *
 * What it does:
 * Packs one `RRef_CAcquireTargetTask_P` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_CAcquireTargetTask_P(
  RRef* const out,
  moho::CAcquireTargetTask** const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CAcquireTargetTask_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0059E080 (FUN_0059E080, gpg::RRef_IFormationInstance_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::IFormationInstance*` slot.
 */
gpg::RRef* RRef_IFormationInstance_P(RRef* const out, moho::IFormationInstance** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::IFormationInstance>();
  return out;
}

/**
 * Address: 0x0066C650 (FUN_0066C650, gpg::RRef_IEffect)
 *
 * What it does:
 * Builds a reflection reference for `moho::IEffect` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_IEffect(RRef* const out, moho::IEffect* const value)
{
  return BuildTypedRefWithCache<moho::IEffect>(out, value, typeid(moho::IEffect), gIEffectRRefType, gIEffectRRefCache);
}

/**
 * Address: 0x0066C480 (FUN_0066C480, gpg::RRef_CEffectManagerImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEffectManagerImpl` using named
 * declared type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CEffectManagerImpl(RRef* const out, moho::CEffectManagerImpl* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CEffectManagerImpl",
    "Moho::CEffectManagerImpl",
    gCEffectManagerImplRRefType,
    gCEffectManagerImplRRefCache
  );
}

/**
 * Address: 0x0066C2A0 (FUN_0066C2A0, gpg::RRef_CEffectManagerImpl pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CEffectManagerImpl` and copies its
 * `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEffectManagerImpl(RRef* const out, moho::CEffectManagerImpl* const value)
{
  RRef tmp{};
  (void)RRef_CEffectManagerImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0066D0B0 (FUN_0066D0B0, gpg::RRef_IEffect pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_IEffect` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_IEffect(RRef* const out, moho::IEffect* const value)
{
  RRef tmp{};
  (void)RRef_IEffect(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00658860 (FUN_00658860, gpg::RRef_CEfxBeam)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEfxBeam` using `CEfxBeam::sType`
 * cache and derived-type normalization.
 */
gpg::RRef* RRef_CEfxBeam(RRef* const out, moho::CEfxBeam* const value)
{
  return BuildTypedRefWithCache<moho::CEfxBeam>(
    out,
    value,
    typeid(moho::CEfxBeam),
    moho::CEfxBeam::sType,
    gCEfxBeamRRefCache
  );
}

/**
 * Address: 0x00658750 (FUN_00658750, gpg::RRef_CEfxBeam pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CEfxBeam` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEfxBeam(RRef* const out, moho::CEfxBeam* const value)
{
  RRef tmp{};
  (void)RRef_CEfxBeam(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0065ADC0 (FUN_0065ADC0, gpg::RRef_CountedPtr_CParticleTexture)
 *
 * What it does:
 * Builds a reflected reference for one counted particle-texture pointer
 * wrapper.
 */
gpg::RRef* RRef_CountedPtr_CParticleTexture(
  RRef* const out,
  moho::CountedPtr<moho::CParticleTexture>* const value
)
{
  return BuildTypedRefWithCache<moho::CountedPtr<moho::CParticleTexture>>(
    out,
    value,
    typeid(moho::CountedPtr<moho::CParticleTexture>),
    gCountedPtrCParticleTextureRRefType,
    gCountedPtrCParticleTextureRRefCache
  );
}

/**
 * Address: 0x0065A7E0 (FUN_0065A7E0, gpg::RRef_CountedPtr_CParticleTexture pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CountedPtr_CParticleTexture` and copies its
 * `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CountedPtr_CParticleTexture(
  RRef* const out,
  moho::CountedPtr<moho::CParticleTexture>* const value
)
{
  RRef tmp{};
  (void)RRef_CountedPtr_CParticleTexture(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0065FCF0 (FUN_0065FCF0, gpg::RRef_SEfxCurve)
 *
 * What it does:
 * Builds a reflected reference for one `moho::SEfxCurve` value pointer.
 */
gpg::RRef* RRef_SEfxCurve(RRef* const out, moho::SEfxCurve* const value)
{
  return BuildTypedRefWithCache<moho::SEfxCurve>(
    out,
    value,
    typeid(moho::SEfxCurve),
    gSEfxCurveRRefType,
    gSEfxCurveRRefCache
  );
}

/**
 * Address: 0x0065FA20 (FUN_0065FA20, gpg::RRef_SEfxCurve pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SEfxCurve` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_SEfxCurve(RRef* const out, moho::SEfxCurve* const value)
{
  RRef tmp{};
  (void)RRef_SEfxCurve(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0065FF20 (FUN_0065FF20, gpg::RRef_CEfxEmitter)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEfxEmitter` using named declared
 * type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CEfxEmitter(RRef* const out, moho::CEfxEmitter* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CEfxEmitter",
    "Moho::CEfxEmitter",
    gCEfxEmitterRRefType,
    gCEfxEmitterRRefCache
  );
}

/**
 * Address: 0x0065FB30 (FUN_0065FB30, gpg::RRef_CEfxEmitter pack lane)
 * Address: 0x00608000 (FUN_00608000)
 *
 * What it does:
 * Builds one temporary `RRef_CEfxEmitter` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEfxEmitter(RRef* const out, moho::CEfxEmitter* const value)
{
  RRef tmp{};
  (void)RRef_CEfxEmitter(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00672560 (FUN_00672560, gpg::RRef_CEfxTrailEmitter)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEfxTrailEmitter` using named
 * declared type lookup, runtime RTTI cache, and base-offset normalization.
 */
gpg::RRef* RRef_CEfxTrailEmitter(RRef* const out, moho::CEfxTrailEmitter* const value)
{
  return BuildNamedPolymorphicRefWithCache(
    out,
    value,
    "CEfxTrailEmitter",
    "Moho::CEfxTrailEmitter",
    gCEfxTrailEmitterRRefType,
    gCEfxTrailEmitterRRefCache
  );
}

/**
 * Address: 0x00672510 (FUN_00672510, gpg::RRef_CEfxTrailEmitter pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CEfxTrailEmitter` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEfxTrailEmitter(RRef* const out, moho::CEfxTrailEmitter* const value)
{
  RRef tmp{};
  (void)RRef_CEfxTrailEmitter(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0066C800 (FUN_0066C800, gpg::RRef_IEffect_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::IEffect*` slot.
 */
gpg::RRef* RRef_IEffect_P(RRef* const out, moho::IEffect** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::IEffect>();
  return out;
}

/**
 * Address: 0x0066D0E0 (FUN_0066D0E0, gpg::RRef_IEffect_P pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_IEffect_P` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_IEffect_P(RRef* const out, moho::IEffect** const value)
{
  RRef tmp{};
  (void)RRef_IEffect_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0054EA20 (FUN_0054EA20, gpg::RRef_CAniPose)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAniPose` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CAniPose(RRef* const out, moho::CAniPose* const value)
{
  return BuildTypedRefWithCache<moho::CAniPose>(
    out,
    value,
    typeid(moho::CAniPose),
    gCAniPoseRRefType,
    gCAniPoseRRefCache
  );
}

/**
 * Address: 0x0054E690 (FUN_0054E690, gpg::RRef_CAniPoseBone)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CAniPoseBone` value pointer.
 */
gpg::RRef* RRef_CAniPoseBone(RRef* const out, moho::CAniPoseBone* const value)
{
  return BuildTypedRefWithCache<moho::CAniPoseBone>(
    out,
    value,
    typeid(moho::CAniPoseBone),
    gCAniPoseBoneRRefType,
    gCAniPoseBoneRRefCache
  );
}

/**
 * Address: 0x0063EAD0 (FUN_0063EAD0, gpg::RRef_shared_ptr_CAniPose)
 *
 * What it does:
 * Builds a reflection reference for `boost::shared_ptr<moho::CAniPose>` using
 * cached RTTI lookup.
 */
gpg::RRef* RRef_shared_ptr_CAniPose(RRef* const out, boost::shared_ptr<moho::CAniPose>* const value)
{
  return BuildTypedRefWithCache<boost::shared_ptr<moho::CAniPose>>(
    out,
    value,
    typeid(boost::shared_ptr<moho::CAniPose>),
    gSharedPtrCAniPoseRRefType,
    gSharedPtrCAniPoseRRefCache
  );
}

/**
 * Address: 0x004C9030 (FUN_004C9030, gpg::RRef_CScriptObject)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CScriptObject` pointer with
 * derived-type normalization.
 */
gpg::RRef* RRef_CScriptObject(RRef* const out, moho::CScriptObject* const value)
{
  return BuildTypedRefWithCache<moho::CScriptObject>(
    out,
    value,
    typeid(moho::CScriptObject),
    moho::CScriptObject::sType,
    gCScriptObjectRRefCache
  );
}

/**
 * Address: 0x004C8EC0 (FUN_004C8EC0, sub_4C8EC0)
 *
 * What it does:
 * Builds one temporary `gpg::RRef` for a script object and copies `{mObj,mType}`
 * into caller-provided output storage.
 */
[[maybe_unused]] static gpg::RRef* CopyScriptObjectRefToOutput(moho::CScriptObject* const value, gpg::RRef* const out)
{
  gpg::RRef ref{};
  gpg::RRef_CScriptObject(&ref, value);
  out->mObj = ref.mObj;
  out->mType = ref.mType;
  return out;
}

/**
 * Address: 0x004C8C30 (FUN_004C8C30, gpg::RRef_CScriptObject_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CScriptObject*` slot.
 */
gpg::RRef* RRef_CScriptObject_P(RRef* const out, moho::CScriptObject** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CScriptObject>();
  return out;
}

/**
 * Address: 0x004CC040 (FUN_004CC040, gpg::RRef_CScriptEvent)
 *
 * What it does:
 * Builds a reflection reference for `moho::CScriptEvent` using
 * `CScriptEvent::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CScriptEvent(RRef* const out, moho::CScriptEvent* const value)
{
  return BuildTypedRefWithCache<moho::CScriptEvent>(
    out,
    value,
    typeid(moho::CScriptEvent),
    moho::CScriptEvent::sType,
    gCScriptEventRRefCache
  );
}

/**
 * Address: 0x004CBB60 (FUN_004CBB60, gpg::RRef_CLuaTask)
 *
 * What it does:
 * Builds a reflection reference for `moho::CLuaTask` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CLuaTask(RRef* const out, moho::CLuaTask* const value)
{
  return BuildTypedRefWithCache<moho::CLuaTask>(
    out,
    value,
    typeid(moho::CLuaTask),
    gCLuaTaskRRefType,
    gCLuaTaskRRefCache
  );
}

/**
 * Address: 0x004CBE70 (FUN_004CBE70, gpg::RRef_CWaitForTask)
 *
 * What it does:
 * Builds a reflection reference for `moho::CWaitForTask` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CWaitForTask(RRef* const out, moho::CWaitForTask* const value)
{
  return BuildTypedRefWithCache<moho::CWaitForTask>(
    out,
    value,
    typeid(moho::CWaitForTask),
    gCWaitForTaskRRefType,
    gCWaitForTaskRRefCache
  );
}

/**
 * Address: 0x004E5730 (FUN_004E5730, gpg::RRef_CSndParams)
 *
 * What it does:
 * Builds a reflection reference for `moho::CSndParams` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CSndParams(RRef* const out, moho::CSndParams* const value)
{
  return BuildTypedRefWithCache<moho::CSndParams>(
    out,
    value,
    typeid(moho::CSndParams),
    gCSndParamsRRefType,
    gCSndParamsRRefCache
  );
}

/**
 * Address: 0x004E6200 (FUN_004E6200, gpg::RRef_CSndParams_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CSndParams*` slot.
 */
gpg::RRef* RRef_CSndParams_P(RRef* const out, moho::CSndParams** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CSndParams>();
  return out;
}

/**
 * Address: 0x004E5590 (FUN_004E5590, gpg::RRef_CSndVar)
 *
 * What it does:
 * Builds a reflection reference for `moho::CSndVar` using cached RTTI
 * lookups.
 */
gpg::RRef* RRef_CSndVar(RRef* const out, moho::CSndVar* const value)
{
  return BuildTypedRefWithCache<moho::CSndVar>(out, value, typeid(moho::CSndVar), gCSndVarRRefType, gCSndVarRRefCache);
}

/**
 * Address: 0x004E6720 (FUN_004E6720, gpg::RRef_HSound)
 *
 * What it does:
 * Builds a reflection reference for `moho::HSound` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_HSound(RRef* const out, moho::HSound* const value)
{
  return BuildTypedRefWithCache<moho::HSound>(out, value, typeid(moho::HSound), gHSoundRRefType, gHSoundRRefCache);
}

/**
 * Address: 0x00758B00 (FUN_00758B00, gpg::RRef_ISoundManager)
 * Address: 0x00762410 (FUN_00762410)
 *
 * What it does:
 * Builds a reflection reference for `moho::ISoundManager` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_ISoundManager(RRef* const out, moho::ISoundManager* const value)
{
  return BuildTypedRefWithCache<moho::ISoundManager>(
    out,
    value,
    typeid(moho::ISoundManager),
    gISoundManagerRRefType,
    gISoundManagerRRefCache
  );
}

/**
 * Address: 0x00762890 (FUN_00762890, gpg::RRef_SAudioRequest)
 * Address: 0x00762560 (FUN_00762560)
 *
 * What it does:
 * Builds a reflection reference for `moho::SAudioRequest` object pointers.
 */
gpg::RRef* RRef_SAudioRequest(RRef* const out, moho::SAudioRequest* const value)
{
  return BuildTypedRefWithCache<moho::SAudioRequest>(
    out,
    value,
    typeid(moho::SAudioRequest),
    moho::SAudioRequest::sType,
    gSAudioRequestRRefCache
  );
}

/**
 * Address: 0x00761B70 (FUN_00761B70)
 *
 * What it does:
 * Builds one reflected reference from the `index`-th contiguous
 * `SAudioRequest` lane starting at `(*firstElementSlot)`.
 */
gpg::RRef* RRef_SAudioRequestArraySlot(
  RRef* const out,
  moho::SAudioRequest* const* const firstElementSlot,
  const int index
)
{
  if (out == nullptr) {
    return nullptr;
  }

  moho::SAudioRequest* const firstElement = (firstElementSlot != nullptr) ? *firstElementSlot : nullptr;
  if (firstElement == nullptr) {
    out->mObj = nullptr;
    out->mType = nullptr;
    return out;
  }

  return RRef_SAudioRequest(out, firstElement + static_cast<std::ptrdiff_t>(index));
}

/**
 * Address: 0x006805E0 (FUN_006805E0, gpg::RRef_Entity)
 *
 * What it does:
 * Builds a reflection reference for `moho::Entity` using `Entity::sType`
 * cache and derived-type normalization.
 */
gpg::RRef* RRef_Entity(RRef* const out, moho::Entity* const value)
{
  return BuildTypedRefWithCache<moho::Entity>(
    out,
    value,
    typeid(moho::Entity),
    gEntityRRefType,
    gEntityRRefCache
  );
}

/**
 * Address: 0x00675DB0 (FUN_00675DB0, gpg::RRef_CollisionBeamEntity)
 *
 * What it does:
 * Builds a reflection reference for `moho::CollisionBeamEntity` using
 * `CollisionBeamEntity::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CollisionBeamEntity(RRef* const out, moho::CollisionBeamEntity* const value)
{
  return BuildTypedRefWithCache<moho::CollisionBeamEntity>(
    out,
    value,
    typeid(moho::CollisionBeamEntity),
    moho::CollisionBeamEntity::sType,
    gCollisionBeamEntityRRefCache
  );
}

/**
 * Address: 0x006755A0 (FUN_006755A0, helper lane)
 *
 * What it does:
 * Materializes a temporary `RRef_CollisionBeamEntity` and copies the resulting
 * object/type lanes into the destination reference.
 */
gpg::RRef* AssignCollisionBeamEntityRef(RRef* const out, moho::CollisionBeamEntity* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  RRef_CollisionBeamEntity(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006FAF20 (FUN_006FAF20, gpg::RRef_Prop)
 *
 * What it does:
 * Builds a reflection reference for `moho::Prop` using `Prop::sType` cache and
 * derived-type normalization.
 */
gpg::RRef* RRef_Prop(RRef* const out, moho::Prop* const value)
{
  return BuildTypedRefWithCache<moho::Prop>(
    out,
    value,
    typeid(moho::Prop),
    moho::Prop::sType,
    gPropRRefCache
  );
}

/**
 * Address: 0x006FAE00 (FUN_006FAE00)
 *
 * What it does:
 * Packs one temporary `RRef_Prop` and copies `(mObj,mType)` into caller-owned
 * output storage.
 */
gpg::RRef* PackRRef_Prop(RRef* const out, moho::Prop* const value)
{
  RRef tmp{};
  (void)RRef_Prop(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005541F0 (FUN_005541F0, gpg::RRef_EntId)
 *
 * What it does:
 * Builds a reflected reference for one entity-id scalar lane.
 */
gpg::RRef* RRef_EntId(RRef* const out, std::int32_t* const value)
{
  return BuildTypedRefWithCache<std::int32_t>(out, value, typeid(std::int32_t), gEntIdRRefType, gEntIdRRefCache);
}

/**
 * Address: 0x00553CD0 (FUN_00553CD0)
 *
 * What it does:
 * Materializes one temporary `RRef_EntId` and copies object/type lanes into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_EntId(RRef* const out, std::int32_t* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_EntId(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006807B0 (FUN_006807B0, gpg::RRef_Entity_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::Entity*` slot.
 */
gpg::RRef* RRef_Entity_P(RRef* const out, moho::Entity** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::Entity>();
  return out;
}

/**
 * Address: 0x0067F700 (FUN_0067F700, gpg::RRef_Entity_P pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_Entity_P` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_Entity_P(RRef* const out, moho::Entity** const value)
{
  RRef tmp{};
  (void)RRef_Entity_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B21E0 (FUN_006B21E0, gpg::RRef_WeakPtr_Entity)
 *
 * What it does:
 * Builds a reflected reference for one `WeakPtr<Entity>` wrapper value.
 */
gpg::RRef* RRef_WeakPtr_Entity(RRef* const out, moho::WeakPtr<moho::Entity>* const value)
{
  return BuildTypedRefWithCache<moho::WeakPtr<moho::Entity>>(
    out,
    value,
    typeid(moho::WeakPtr<moho::Entity>),
    gWeakPtrEntityRRefType,
    gWeakPtrEntityRRefCache
  );
}

/**
 * Address: 0x006B1320 (FUN_006B1320)
 *
 * What it does:
 * Materializes one temporary `RRef_WeakPtr_Entity` and copies `(mObj,mType)`
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_WeakPtr_Entity(RRef* const out, moho::WeakPtr<moho::Entity>* const value)
{
  RRef tmp{};
  (void)RRef_WeakPtr_Entity(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00689360 (FUN_00689360, gpg::RRef_EntityDB)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEntityDb` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_EntityDB(RRef* const out, moho::CEntityDb* const value)
{
  return BuildTypedRefWithCache<moho::CEntityDb>(
    out,
    value,
    typeid(moho::CEntityDb),
    gEntityDBRRefType,
    gEntityDBRRefCache
  );
}

/**
 * Address: 0x00688D30 (FUN_00688D30, sub_688D30)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_EntityDB` and copies lanes
 * out.
 */
gpg::RRef* AssignEntityDBRef(RRef* const out, moho::CEntityDb* const value)
{
  RRef tmp{};
  RRef_EntityDB(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00689920 (FUN_00689920, gpg::RRef_EntitySetBase)
 *
 * What it does:
 * Builds a reflection reference for `moho::EntitySetBase` using
 * `EntitySetBase::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_EntitySetBase(RRef* const out, moho::EntitySetBase* const value)
{
  return BuildTypedRefWithCache<moho::EntitySetBase>(
    out,
    value,
    typeid(moho::EntitySetBase),
    moho::EntitySetBase::sType,
    gEntitySetBaseRRefCache
  );
}

/**
 * Address: 0x00698D80 (FUN_00698D80, gpg::RRef_SPhysConstants)
 *
 * What it does:
 * Builds a reflection reference for `moho::SPhysConstants` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_SPhysConstants(RRef* const out, moho::SPhysConstants* const value)
{
  return BuildTypedRefWithCache<moho::SPhysConstants>(
    out,
    value,
    typeid(moho::SPhysConstants),
    gSPhysConstantsRRefType,
    gSPhysConstantsRRefCache
  );
}

/**
 * Address: 0x00698D60 (FUN_00698D60, gpg::RRef_SPhysConstants pack lane A)
 *
 * What it does:
 * Builds one temporary `RRef_SPhysConstants` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SPhysConstantsA(RRef* const out, moho::SPhysConstants* const value)
{
  RRef tmp{};
  (void)RRef_SPhysConstants(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0069A0A0 (FUN_0069A0A0, gpg::RRef_SPhysConstants pack lane B)
 *
 * What it does:
 * Secondary pack lane that builds one temporary `RRef_SPhysConstants` and
 * copies its `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SPhysConstantsB(RRef* const out, moho::SPhysConstants* const value)
{
  RRef tmp{};
  (void)RRef_SPhysConstants(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006837E0 (FUN_006837E0, gpg::RRef_SPhysBody)
 *
 * What it does:
 * Builds a reflection reference for `moho::SPhysBody` using cached RTTI
 * lookup.
 */
gpg::RRef* RRef_SPhysBody(RRef* const out, moho::SPhysBody* const value)
{
  return BuildTypedRefWithCache<moho::SPhysBody>(
    out,
    value,
    typeid(moho::SPhysBody),
    gSPhysBodyRRefType,
    gSPhysBodyRRefCache
  );
}

/**
 * Address: 0x00698850 (FUN_00698850, sub_698850)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_SPhysBody` and copies lanes
 * out.
 */
gpg::RRef* AssignSPhysBodyRef(RRef* const out, moho::SPhysBody* const value)
{
  RRef tmp{};
  RRef_SPhysBody(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005A2A40 (FUN_005A2A40, gpg::RRef_Unit)
 *
 * What it does:
 * Builds a reflection reference for `moho::Unit` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_Unit(RRef* const out, moho::Unit* const value)
{
  return BuildTypedRefWithCache<moho::Unit>(out, value, typeid(moho::Unit), gUnitRRefType, gUnitRRefCache);
}

/**
 * Address: 0x006B1040 (FUN_006B1040)
 *
 * What it does:
 * Materializes one temporary `RRef_Unit` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_Unit(RRef* const out, moho::Unit* const value)
{
  RRef tmp{};
  (void)RRef_Unit(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00541C50 (FUN_00541C50, gpg::RRef_IUnit)
 *
 * What it does:
 * Builds a reflection reference for `moho::IUnit` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_IUnit(RRef* const out, moho::IUnit* const value)
{
  return BuildTypedRefWithCache<moho::IUnit>(out, value, typeid(moho::IUnit), gIUnitRRefType, gIUnitRRefCache);
}

/**
 * Address: 0x00541A90 (FUN_00541A90, gpg::RRef_IUnit pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_IUnit` and copies its `(mObj,mType)` pair into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_IUnit(RRef* const out, moho::IUnit* const value)
{
  RRef tmp{};
  (void)RRef_IUnit(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005725F0 (FUN_005725F0, gpg::RRef_WeakPtr_IUnit)
 *
 * What it does:
 * Builds a reflected reference for one `WeakPtr<IUnit>` wrapper value.
 */
gpg::RRef* RRef_WeakPtr_IUnit(RRef* const out, moho::WeakPtr<moho::IUnit>* const value)
{
  return BuildTypedRefWithCache<moho::WeakPtr<moho::IUnit>>(
    out,
    value,
    typeid(moho::WeakPtr<moho::IUnit>),
    gWeakPtrIUnitRRefType,
    gWeakPtrIUnitRRefCache
  );
}

/**
 * Address: 0x00571030 (FUN_00571030)
 *
 * What it does:
 * Builds one temporary `RRef_WeakPtr_IUnit` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_WeakPtr_IUnit(RRef* const out, moho::WeakPtr<moho::IUnit>* const value)
{
  RRef tmp{};
  (void)RRef_WeakPtr_IUnit(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00559790 (FUN_00559790, gpg::RRef_SSTIEntityAttachInfo)
 *
 * IDA signature:
 * gpg::RRef *__cdecl gpg::RRef_SSTIEntityAttachInfo(gpg::RRef *a1, Moho::SSTIEntityAttachInfo *a2);
 *
 * What it does:
 * Builds a reflection reference for one `moho::SSTIEntityAttachInfo`
 * pointer using the cached RTTI lookup + 3-slot derived-type
 * normalization helper, matching the binary's TLS-cached lookup +
 * `IsDerivedFrom` adjustment chain.
 */
gpg::RRef* RRef_SSTIEntityAttachInfo(RRef* const out, moho::SSTIEntityAttachInfo* const value)
{
  return BuildTypedRefWithCache<moho::SSTIEntityAttachInfo>(
    out,
    value,
    typeid(moho::SSTIEntityAttachInfo),
    gSSTIEntityAttachInfoRRefType,
    gSSTIEntityAttachInfoRRefCache
  );
}

/**
 * Address: 0x00559470 (FUN_00559470)
 *
 * What it does:
 * Materializes one temporary `RRef_SSTIEntityAttachInfo` and copies
 * object/type lanes into caller-owned output storage.
 */
gpg::RRef* PackRRef_SSTIEntityAttachInfo(RRef* const out, moho::SSTIEntityAttachInfo* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_SSTIEntityAttachInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005ACCA0 (FUN_005ACCA0, gpg::RRef_PathQueue)
 *
 * IDA signature:
 * gpg::RRef *__cdecl gpg::RRef_PathQueue(gpg::RRef *a1, Moho::PathQueue *a2);
 *
 * What it does:
 * Builds a reflection reference for one `moho::PathQueue` pointer
 * using the cached RTTI lookup + 3-slot derived-type normalization
 * helper, matching the binary's TLS-cached lookup + `IsDerivedFrom`
 * adjustment chain.
 */
gpg::RRef* RRef_PathQueue(RRef* const out, moho::PathQueue* const value)
{
  return BuildTypedRefWithCache<moho::PathQueue>(
    out,
    value,
    typeid(moho::PathQueue),
    gPathQueueRRefType,
    gPathQueueRRefCache
  );
}

/**
 * Address: 0x00768C70 (FUN_00768C70)
 *
 * What it does:
 * Builds one temporary `RRef_PathQueue` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_PathQueue(RRef* const out, moho::PathQueue* const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_PathQueue(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00526C80 (FUN_00526C80, gpg::RRef_RUnitBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RUnitBlueprint` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_RUnitBlueprint(RRef* const out, moho::RUnitBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RUnitBlueprint>(
    out,
    value,
    typeid(moho::RUnitBlueprint),
    gRUnitBlueprintRRefType,
    gRUnitBlueprintRRefCache
  );
}

/**
 * Address: 0x0050E2A0 (FUN_0050E2A0, gpg::RRef_RBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RBlueprint` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_RBlueprint(RRef* const out, moho::RBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RBlueprint>(
    out,
    value,
    typeid(moho::RBlueprint),
    gRBlueprintRRefType,
    gRBlueprintRRefCache
  );
}

/**
 * Address: 0x0050E270 (FUN_0050E270, gpg::RRef_RBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RBlueprint` and copies its `(mObj,mType)` pair
 * into caller-provided storage.
 */
gpg::RRef* PackRRef_RBlueprint(RRef* const out, moho::RBlueprint* const value)
{
  RRef tmp{};
  (void)RRef_RBlueprint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00557BD0 (FUN_00557BD0, gpg::RRef_RBlueprint_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::RBlueprint*` slot.
 */
gpg::RRef* RRef_RBlueprint_P(RRef* const out, moho::RBlueprint** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::RBlueprint>();
  return out;
}

/**
 * Address: 0x00557A60 (FUN_00557A60)
 *
 * What it does:
 * Materializes one temporary `RRef_RBlueprint_P` and copies object/type lanes
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_RBlueprintPointer(RRef* const out, moho::RBlueprint** const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_RBlueprint_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005A22A0 (FUN_005A22A0, gpg::RRef_RUnitBlueprint_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::RUnitBlueprint*` slot.
 */
gpg::RRef* RRef_RUnitBlueprint_P(RRef* const out, moho::RUnitBlueprint** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::RUnitBlueprint>();
  return out;
}

/**
 * Address: 0x00526E30 (FUN_00526E30, gpg::RRef_RUnitBlueprintWeapon)
 *
 * What it does:
 * Builds a reflection reference for one `moho::RUnitBlueprintWeapon` value
 * pointer.
 */
gpg::RRef* RRef_RUnitBlueprintWeapon(RRef* const out, moho::RUnitBlueprintWeapon* const value)
{
  return BuildTypedRefWithCache<moho::RUnitBlueprintWeapon>(
    out,
    value,
    typeid(moho::RUnitBlueprintWeapon),
    gRUnitBlueprintWeaponRRefType,
    gRUnitBlueprintWeaponRRefCache
  );
}

/**
 * Address: 0x00511940 (FUN_00511940, gpg::RRef_RRuleGameRules)
 * Address: 0x00756190 (FUN_00756190)
 *
 * What it does:
 * Builds a reflection reference for `moho::RRuleGameRules` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_RRuleGameRules(RRef* const out, moho::RRuleGameRules* const value)
{
  return BuildTypedRefWithCache<moho::RRuleGameRules>(
    out,
    value,
    typeid(moho::RRuleGameRules),
    gRRuleGameRulesRRefType,
    gRRuleGameRulesRRefCache
  );
}

/**
 * Address: 0x00537850 (FUN_00537850)
 *
 * What it does:
 * Thin adapter lane that forwards `{out,value}` into `RRef_RRuleGameRules`.
 */
gpg::RRef* AssignRRuleGameRulesRef(RRef* const out, moho::RRuleGameRules* const value)
{
  RRef_RRuleGameRules(out, value);
  return out;
}

/**
 * Address: 0x00536BA0 (FUN_00536BA0, gpg::RRef_SRuleFootprintsBlueprint)
 * Address: 0x007561C0 (FUN_007561C0)
 *
 * What it does:
 * Builds a reflection reference for `moho::SRuleFootprintsBlueprint` using
 * cached RTTI lookup.
 */
gpg::RRef* RRef_SRuleFootprintsBlueprint(RRef* const out, moho::SRuleFootprintsBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::SRuleFootprintsBlueprint>(
    out,
    value,
    typeid(moho::SRuleFootprintsBlueprint),
    moho::SRuleFootprintsBlueprint::sType,
    gSRuleFootprintsBlueprintRRefCache
  );
}

/**
 * Address: 0x00533210 (FUN_00533210)
 *
 * What it does:
 * Materializes one temporary `RRef_SRuleFootprintsBlueprint` and copies
 * object/type lanes into `out`.
 */
gpg::RRef* AssignSRuleFootprintsBlueprintRef(RRef* const out, moho::SRuleFootprintsBlueprint* const value)
{
  RRef tmp{};
  RRef_SRuleFootprintsBlueprint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0055AB70 (FUN_0055AB70, gpg::RRef_RScmResource)
 *
 * What it does:
 * Builds a reflection reference for `moho::RScmResource` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_RScmResource(RRef* const out, moho::RScmResource* const value)
{
  return BuildTypedRefWithCache<moho::RScmResource>(
    out,
    value,
    typeid(moho::RScmResource),
    moho::RScmResource::sType,
    gRScmResourceRRefCache
  );
}

/**
 * Address: 0x00549200 (FUN_00549200, gpg::RRef_ResourceDeposit)
 *
 * What it does:
 * Builds a reflected reference for one `moho::ResourceDeposit` value pointer.
 */
gpg::RRef* RRef_ResourceDeposit(RRef* const out, moho::ResourceDeposit* const value)
{
  return BuildTypedRefWithCache<moho::ResourceDeposit>(
    out,
    value,
    typeid(moho::ResourceDeposit),
    gResourceDepositRRefType,
    gResourceDepositRRefCache
  );
}

/**
 * Address: 0x00548950 (FUN_00548950, gpg::RRef_ResourceDeposit pack lane)
 * Address: 0x005FD5D0 (FUN_005FD5D0)
 *
 * What it does:
 * Builds one temporary `RRef_ResourceDeposit` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_ResourceDeposit(RRef* const out, moho::ResourceDeposit* const value)
{
  RRef tmp{};
  (void)RRef_ResourceDeposit(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00511250 (FUN_00511250, gpg::RRef_REmitterBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::REmitterBlueprint` using
 * `REmitterBlueprint::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_REmitterBlueprint(RRef* const out, moho::REmitterBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::REmitterBlueprint>(
    out,
    value,
    typeid(moho::REmitterBlueprint),
    moho::REmitterBlueprint::sType,
    gREmitterBlueprintRRefCache
  );
}

/**
 * Address: 0x005110D0 (FUN_005110D0, gpg::RRef_REmitterBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_REmitterBlueprint` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_REmitterBlueprint(RRef* const out, moho::REmitterBlueprint* const value)
{
  RRef tmp{};
  (void)RRef_REmitterBlueprint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00517AE0 (FUN_00517AE0, gpg::RRef_REmitterCurveKey)
 *
 * What it does:
 * Builds a reflection reference for `moho::REmitterCurveKey` using
 * `REmitterCurveKey::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_REmitterCurveKey(RRef* const out, moho::REmitterCurveKey* const value)
{
  return BuildTypedRefWithCache<moho::REmitterCurveKey>(
    out,
    value,
    typeid(moho::REmitterCurveKey),
    moho::REmitterCurveKey::sType,
    gREmitterCurveKeyRRefCache
  );
}

/**
 * Address: 0x00517060 (FUN_00517060)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_REmitterCurveKey` and
 * writes the resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildEmitterCurveKeyRefAdapterLane(
  moho::REmitterCurveKey* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  (void)gpg::RRef_REmitterCurveKey(&temp, value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x00517D20 (FUN_00517D20, gpg::RRef_REmitterBlueprintCurve)
 *
 * What it does:
 * Builds a reflection reference for `moho::REmitterBlueprintCurve` using
 * cached RTTI lookups and derived-type normalization.
 */
gpg::RRef* RRef_REmitterBlueprintCurve(RRef* const out, moho::REmitterBlueprintCurve* const value)
{
  return BuildTypedRefWithCache<moho::REmitterBlueprintCurve>(
    out,
    value,
    typeid(moho::REmitterBlueprintCurve),
    gREmitterBlueprintCurveRRefType,
    gREmitterBlueprintCurveRRefCache
  );
}

/**
 * Address: 0x005171D0 (FUN_005171D0)
 *
 * What it does:
 * Adapts one register-lane call shape into
 * `gpg::RRef_REmitterBlueprintCurve` and writes the resulting
 * `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildEmitterBlueprintCurveRefAdapterLane(
  moho::REmitterBlueprintCurve* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  (void)gpg::RRef_REmitterBlueprintCurve(&temp, value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x005115B0 (FUN_005115B0, gpg::RRef_RBeamBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RBeamBlueprint` using
 * `RBeamBlueprint::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RBeamBlueprint(RRef* const out, moho::RBeamBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RBeamBlueprint>(
    out,
    value,
    typeid(moho::RBeamBlueprint),
    moho::RBeamBlueprint::sType,
    gRBeamBlueprintRRefCache
  );
}

/**
 * Address: 0x00511170 (FUN_00511170, gpg::RRef_RBeamBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RBeamBlueprint` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_RBeamBlueprint(RRef* const out, moho::RBeamBlueprint* const value)
{
  RRef tmp{};
  (void)RRef_RBeamBlueprint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00511400 (FUN_00511400, gpg::RRef_RTrailBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RTrailBlueprint` using
 * `RTrailBlueprint::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RTrailBlueprint(RRef* const out, moho::RTrailBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RTrailBlueprint>(
    out,
    value,
    typeid(moho::RTrailBlueprint),
    moho::RTrailBlueprint::sType,
    gRTrailBlueprintRRefCache
  );
}

/**
 * Address: 0x00511120 (FUN_00511120, gpg::RRef_RTrailBlueprint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RTrailBlueprint` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_RTrailBlueprint(RRef* const out, moho::RTrailBlueprint* const value)
{
  RRef tmp{};
  (void)RRef_RTrailBlueprint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0051CFF0 (FUN_0051CFF0, gpg::RRef_RProjectileBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RProjectileBlueprint` using
 * `RProjectileBlueprint::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RProjectileBlueprint(RRef* const out, moho::RProjectileBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RProjectileBlueprint>(
    out,
    value,
    typeid(moho::RProjectileBlueprint),
    moho::RProjectileBlueprint::sType,
    gRProjectileBlueprintRRefCache
  );
}

/**
 * Address: 0x0051CF60 (FUN_0051CF60)
 *
 * What it does:
 * Adapts one register-lane call shape into `gpg::RRef_RProjectileBlueprint`
 * and writes the resulting `(mObj, mType)` pair into caller-provided storage.
 */
[[maybe_unused]] gpg::RRef* BuildProjectileBlueprintRefAdapterLane(
  moho::RProjectileBlueprint* const value,
  gpg::RRef* const out
)
{
  if (out == nullptr) {
    return nullptr;
  }

  gpg::RRef temp{};
  (void)gpg::RRef_RProjectileBlueprint(&temp, value);
  out->mObj = temp.mObj;
  out->mType = temp.mType;
  return out;
}

/**
 * Address: 0x0051AAE0 (FUN_0051AAE0, gpg::RRef_RMeshBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RMeshBlueprint` using
 * `RMeshBlueprint::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RMeshBlueprint(RRef* const out, moho::RMeshBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RMeshBlueprint>(
    out,
    value,
    typeid(moho::RMeshBlueprint),
    moho::RMeshBlueprint::sType,
    gRMeshBlueprintRRefCache
  );
}

/**
 * Address: 0x0051AC90 (FUN_0051AC90, gpg::RRef_RMeshBlueprintLOD)
 *
 * What it does:
 * Builds a reflected reference for one `moho::RMeshBlueprintLOD` value
 * pointer.
 */
gpg::RRef* RRef_RMeshBlueprintLOD(RRef* const out, moho::RMeshBlueprintLOD* const value)
{
  return BuildTypedRefWithCache<moho::RMeshBlueprintLOD>(
    out,
    value,
    typeid(moho::RMeshBlueprintLOD),
    gRMeshBlueprintLODRRefType,
    gRMeshBlueprintLODRRefCache
  );
}

/**
 * Address: 0x0051E130 (FUN_0051E130, gpg::RRef_RPropBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RPropBlueprint` using
 * `RPropBlueprint::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RPropBlueprint(RRef* const out, moho::RPropBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RPropBlueprint>(
    out,
    value,
    typeid(moho::RPropBlueprint),
    moho::RPropBlueprint::sType,
    gRPropBlueprintRRefCache
  );
}

/**
 * Address: 0x00500730 (FUN_00500730, gpg::RRef_CColPrimitive_Sphere3f)
 *
 * What it does:
 * Builds a reflection reference for one sphere collision primitive using
 * cached RTTI lookups and derived-type normalization.
 */
gpg::RRef* RRef_CColPrimitive_Sphere3f(RRef* const out, moho::SphereCollisionPrimitive* const value)
{
  return BuildTypedRefWithCache<moho::SphereCollisionPrimitive>(
    out,
    value,
    typeid(moho::SphereCollisionPrimitive),
    gCColPrimitiveSphere3fRRefType,
    gCColPrimitiveSphere3fRRefCache
  );
}

/**
 * Address: 0x005008E0 (FUN_005008E0, gpg::RRef_CColPrimitive_Box3f)
 *
 * What it does:
 * Builds a reflection reference for one box collision primitive using cached
 * RTTI lookups and derived-type normalization.
 */
gpg::RRef* RRef_CColPrimitive_Box3f(RRef* const out, moho::BoxCollisionPrimitive* const value)
{
  return BuildTypedRefWithCache<moho::BoxCollisionPrimitive>(
    out,
    value,
    typeid(moho::BoxCollisionPrimitive),
    gCColPrimitiveBox3fRRefType,
    gCColPrimitiveBox3fRRefCache
  );
}

/**
 * Address: 0x00500480 (FUN_00500480)
 *
 * What it does:
 * Materializes one reflected reference for `SphereCollisionPrimitive` and
 * copies the resulting lanes into `out`.
 */
gpg::RRef* AssignSphereCollisionPrimitiveRef(
  RRef* const out,
  moho::SphereCollisionPrimitive* const value
)
{
  RRef tmp{};
  RRef_CColPrimitive_Sphere3f(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005005C0 (FUN_005005C0)
 *
 * What it does:
 * Materializes one reflected reference for `BoxCollisionPrimitive` and copies
 * the resulting lanes into `out`.
 */
gpg::RRef* AssignBoxCollisionPrimitiveRef(
  RRef* const out,
  moho::BoxCollisionPrimitive* const value
)
{
  RRef tmp{};
  RRef_CColPrimitive_Box3f(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00537250 (FUN_00537250, gpg::RRef_EntityCategory)
 *
 * What it does:
 * Builds a reflection reference for `moho::EntityCategorySet` using
 * `EntityCategorySet::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_EntityCategory(RRef* const out, moho::EntityCategorySet* const value)
{
  return BuildTypedRefWithCache<moho::EntityCategorySet>(
    out,
    value,
    typeid(moho::EntityCategorySet),
    moho::EntityCategorySet::sType,
    gEntityCategorySetRRefCache
  );
}

/**
 * Address: 0x00536B70 (FUN_00536B70)
 * Address: 0x005578F0 (FUN_005578F0)
 *
 * What it does:
 * Materializes one temporary `RRef_EntityCategory` and copies object/type
 * lanes into `out`.
 */
gpg::RRef* AssignEntityCategoryRef(RRef* const out, moho::EntityCategorySet* const value)
{
  RRef tmp{};
  RRef_EntityCategory(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005ACE80 (FUN_005ACE80, gpg::RRef_COGrid)
 *
 * What it does:
 * Builds a reflection reference for `moho::COGrid` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_COGrid(RRef* const out, moho::COGrid* const value)
{
  return BuildTypedRefWithCache<moho::COGrid>(
    out,
    value,
    typeid(moho::COGrid),
    gCOGridRRefType,
    gCOGridRRefCache
  );
}

/**
 * Address: 0x00723A10 (FUN_00723A10, sub_723A10)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_COGrid` and copies lanes
 * out.
 */
gpg::RRef* AssignCOGridRef(RRef* const out, moho::COGrid* const value)
{
  RRef tmp{};
  RRef_COGrid(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005852B0 (FUN_005852B0, gpg::RRef_SimArmy)
 *
 * What it does:
 * Builds a reflection reference for `moho::SimArmy` using `SimArmy::sType`
 * cache and derived-type normalization.
 */
gpg::RRef* RRef_SimArmy(RRef* const out, moho::SimArmy* const value)
{
  return BuildTypedRefWithCache<moho::SimArmy>(
    out,
    value,
    typeid(moho::SimArmy),
    moho::SimArmy::sType,
    gSimArmyRRefCache
  );
}

/**
 * Address: 0x007057D0 (FUN_007057D0, gpg::RRef_CArmyImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CArmyImpl` using `CArmyImpl::sType`
 * cache and derived-type normalization.
 */
gpg::RRef* RRef_CArmyImpl(RRef* const out, moho::CArmyImpl* const value)
{
  return BuildTypedRefWithCache<moho::CArmyImpl>(
    out,
    value,
    typeid(moho::CArmyImpl),
    moho::CArmyImpl::sType,
    gCArmyImplRRefCache
  );
}

/**
 * Address: 0x007047B0 (FUN_007047B0)
 *
 * What it does:
 * Packs one temporary `RRef_CArmyImpl` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_CArmyImpl(RRef* const out, moho::CArmyImpl* const value)
{
  RRef tmp{};
  (void)RRef_CArmyImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00753910 (FUN_00753910, gpg::RRef_SimArmy_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::SimArmy*` slot.
 */
gpg::RRef* RRef_SimArmy_P(RRef* const out, moho::SimArmy** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::SimArmy>();
  return out;
}

/**
 * Address: 0x00751790 (FUN_00751790)
 *
 * What it does:
 * Packs one temporary `RRef_SimArmy_P` result into caller-owned output
 * storage by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_SimArmy_P(RRef* const out, moho::SimArmy** const value)
{
  RRef tmp{};
  (void)RRef_SimArmy_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00751E20 (FUN_00751E20)
 *
 * What it does:
 * Packs one temporary `RRef_SimArmy` result into caller-owned output storage
 * by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_SimArmy(RRef* const out, moho::SimArmy* const value)
{
  RRef tmp{};
  (void)RRef_SimArmy(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0074FF10 (FUN_0074FF10)
 *
 * What it does:
 * Builds one bracketed lexical string (`[TypeLexical]`) for a reflected
 * `moho::SimArmy*` slot, or `"NULL"` when the slot is empty.
 */
msvc8::string* BuildSimArmyPointerLexical(msvc8::string* const out, moho::SimArmy*** const slot)
{
  if (out == nullptr) {
    return nullptr;
  }

  if (slot == nullptr || *slot == nullptr || **slot == nullptr) {
    out->assign_owned("NULL");
    return out;
  }

  gpg::RRef objectRef{};
  (void)gpg::RRef_SimArmy(&objectRef, **slot);

  gpg::RType* runtimeType = moho::SimArmy::sType;
  if (runtimeType == nullptr) {
    runtimeType = gpg::LookupRType(typeid(moho::SimArmy));
    moho::SimArmy::sType = runtimeType;
  }

  const msvc8::string lexical = runtimeType != nullptr ? runtimeType->GetLexical(objectRef) : msvc8::string();
  const msvc8::string bracketed = gpg::STR_Printf("[%s]", lexical.c_str());
  out->assign_owned(bracketed.c_str());
  return out;
}

/**
 * Address: 0x0074FD80 (FUN_0074FD80)
 *
 * What it does:
 * Builds and caches one pointer-type name lane (`"Type*"`) for
 * `moho::SimArmy*`, reusing the reflected `SimArmy::sType` lookup cache.
 */
const char* BuildSimArmyPointerTypeName()
{
  static msvc8::string sCachedName;
  if (sCachedName.empty()) {
    gpg::RType* runtimeType = moho::SimArmy::sType;
    if (runtimeType == nullptr) {
      runtimeType = gpg::LookupRType(typeid(moho::SimArmy));
      moho::SimArmy::sType = runtimeType;
    }

    const char* const baseName = runtimeType != nullptr ? runtimeType->GetName() : "";
    sCachedName.assign_owned(gpg::STR_Printf("%s*", baseName).c_str());
  }
  return sCachedName.c_str();
}

/**
 * Address: 0x00544EE0 (FUN_00544EE0, gpg::RRef_LaunchInfoNew)
 *
 * What it does:
 * Builds a reflection reference for `moho::LaunchInfoNew` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_LaunchInfoNew(RRef* const out, moho::LaunchInfoNew* const value)
{
  return BuildTypedRefWithCache<moho::LaunchInfoNew>(
    out,
    value,
    typeid(moho::LaunchInfoNew),
    gLaunchInfoNewRRefType,
    gLaunchInfoNewRRefCache
  );
}

/**
 * Address: 0x005446D0 (FUN_005446D0, gpg::RRef_LaunchInfoNew pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_LaunchInfoNew` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_LaunchInfoNew(RRef* const out, moho::LaunchInfoNew* const value)
{
  RRef tmp{};
  (void)RRef_LaunchInfoNew(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00544C80 (FUN_00544C80, gpg::RRef_ArmyLaunchInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::ArmyLaunchInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_ArmyLaunchInfo(RRef* const out, moho::ArmyLaunchInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "ArmyLaunchInfo",
    "Moho::ArmyLaunchInfo",
    gArmyLaunchInfoRRefType
  );
}

/**
 * Address: 0x005444E0 (FUN_005444E0, gpg::RRef_ArmyLaunchInfo pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_ArmyLaunchInfo` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_ArmyLaunchInfo(RRef* const out, moho::ArmyLaunchInfo* const value)
{
  RRef tmp{};
  (void)RRef_ArmyLaunchInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00549550 (FUN_00549550, gpg::RRef_CSimResources)
 *
 * What it does:
 * Builds a reflection reference for `moho::CSimResources` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CSimResources(RRef* const out, moho::CSimResources* const value)
{
  return BuildTypedRefWithCache<moho::CSimResources>(
    out,
    value,
    typeid(moho::CSimResources),
    gCSimResourcesRRefType,
    gCSimResourcesRRefCache
  );
}

/**
 * Address: 0x00548BD0 (FUN_00548BD0, gpg::RRef_CSimResources pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CSimResources` and copies its `(mObj,mType)`
 * pair into caller-provided storage.
 */
gpg::RRef* PackRRef_CSimResources(RRef* const out, moho::CSimResources* const value)
{
  RRef tmp{};
  (void)RRef_CSimResources(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00582B50 (FUN_00582B50, gpg::RRef_CAiBrain)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiBrain` using `CAiBrain::sType`
 * cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiBrain(RRef* const out, moho::CAiBrain* const value)
{
  return BuildTypedRefWithCache<moho::CAiBrain>(
    out,
    value,
    typeid(moho::CAiBrain),
    moho::CAiBrain::sType,
    gCAiBrainRRefCache
  );
}

/**
 * Address: 0x005818C0 (FUN_005818C0, gpg::RRef_CAiBrain pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CAiBrain` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiBrain(RRef* const out, moho::CAiBrain* const value)
{
  RRef tmp{};
  (void)RRef_CAiBrain(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005854A0 (FUN_005854A0, gpg::RRef_CAiPersonality)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiPersonality` using
 * `CAiPersonality::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiPersonality(RRef* const out, moho::CAiPersonality* const value)
{
  return BuildTypedRefWithCache<moho::CAiPersonality>(
    out,
    value,
    typeid(moho::CAiPersonality),
    moho::CAiPersonality::sType,
    gCAiPersonalityRRefCache
  );
}

/**
 * Address: 0x005A2030 (FUN_005A2030, gpg::RRef_CAiBuilderImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiBuilderImpl` using
 * `CAiBuilderImpl::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiBuilderImpl(RRef* const out, moho::CAiBuilderImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiBuilderImpl>(
    out,
    value,
    typeid(moho::CAiBuilderImpl),
    moho::CAiBuilderImpl::sType,
    gCAiBuilderImplRRefCache
  );
}

/**
 * Address: 0x0059E2E0 (FUN_0059E2E0, gpg::RRef_CAiFormationInstance)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiFormationInstance` using cached
 * RTTI lookups and derived-type normalization.
 */
gpg::RRef* RRef_CAiFormationInstance(RRef* const out, moho::CAiFormationInstance* const value)
{
  return BuildTypedRefWithCache<moho::CAiFormationInstance>(
    out,
    value,
    typeid(moho::CAiFormationInstance),
    gCAiFormationInstanceRRefType,
    gCAiFormationInstanceRRefCache
  );
}

/**
 * Address: 0x0059E490 (FUN_0059E490, gpg::RRef_CAiFormationDBImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiFormationDBImpl` using cached
 * RTTI lookups and derived-type normalization.
 */
gpg::RRef* RRef_CAiFormationDBImpl(RRef* const out, moho::CAiFormationDBImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiFormationDBImpl>(
    out,
    value,
    typeid(moho::CAiFormationDBImpl),
    gCAiFormationDBImplRRefType,
    gCAiFormationDBImplRRefCache
  );
}

/**
 * Address: 0x005A85D0 (FUN_005A85D0, gpg::RRef_CAiNavigatorLand)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiNavigatorLand` using
 * `CAiNavigatorLand::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiNavigatorLand(RRef* const out, moho::CAiNavigatorLand* const value)
{
  return BuildTypedRefWithCache<moho::CAiNavigatorLand>(
    out,
    value,
    typeid(moho::CAiNavigatorLand),
    moho::CAiNavigatorLand::sType,
    gCAiNavigatorLandRRefCache
  );
}

/**
 * Address: 0x005A87A0 (FUN_005A87A0, gpg::RRef_CAiNavigatorAir)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiNavigatorAir` using
 * `CAiNavigatorAir::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiNavigatorAir(RRef* const out, moho::CAiNavigatorAir* const value)
{
  return BuildTypedRefWithCache<moho::CAiNavigatorAir>(
    out,
    value,
    typeid(moho::CAiNavigatorAir),
    moho::CAiNavigatorAir::sType,
    gCAiNavigatorAirRRefCache
  );
}

/**
 * Address: 0x005A9A40 (FUN_005A9A40, gpg::RRef_CAiPathNavigator)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiPathNavigator` using
 * `CAiPathNavigator::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiPathNavigator(RRef* const out, moho::CAiPathNavigator* const value)
{
  return BuildTypedRefWithCache<moho::CAiPathNavigator>(
    out,
    value,
    typeid(moho::CAiPathNavigator),
    moho::CAiPathNavigator::sType,
    gCAiPathNavigatorRRefCache
  );
}

/**
 * Address: 0x005ABD20 (FUN_005ABD20, gpg::RRef_CAiPathFinder)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiPathFinder` using
 * `CAiPathFinder::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiPathFinder(RRef* const out, moho::CAiPathFinder* const value)
{
  return BuildTypedRefWithCache<moho::CAiPathFinder>(
    out,
    value,
    typeid(moho::CAiPathFinder),
    moho::CAiPathFinder::sType,
    gCAiPathFinderRRefCache
  );
}

/**
 * Address: 0x005B5D60 (FUN_005B5D60, gpg::RRef_CAiPathSpline)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiPathSpline` using
 * `CAiPathSpline::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CAiPathSpline(RRef* const out, moho::CAiPathSpline* const value)
{
  return BuildTypedRefWithCache<moho::CAiPathSpline>(
    out,
    value,
    typeid(moho::CAiPathSpline),
    moho::CAiPathSpline::sType,
    gCAiPathSplineRRefCache
  );
}

/**
 * Address: 0x00572930 (FUN_00572930, gpg::RRef_SAssignedLocInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SAssignedLocInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_SAssignedLocInfo(RRef* const out, moho::SAssignedLocInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "SAssignedLocInfo",
    "Moho::SAssignedLocInfo",
    gSAssignedLocInfoRRefType
  );
}

/**
 * Address: 0x00571090 (FUN_00571090)
 *
 * What it does:
 * Builds one temporary `RRef_SAssignedLocInfo` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SAssignedLocInfo(RRef* const out, moho::SAssignedLocInfo* const value)
{
  RRef tmp{};
  (void)RRef_SAssignedLocInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006288A0 (FUN_006288A0, gpg::RRef_SPickUpInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SPickUpInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_SPickUpInfo(RRef* const out, moho::SPickUpInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "SPickUpInfo",
    "Moho::SPickUpInfo",
    gSPickUpInfoRRefType
  );
}

/**
 * Address: 0x005F5280 (FUN_005F5280, gpg::RRef_CUnitCommand)
 *
 * What it does:
 * Builds a reflection reference for `moho::CUnitCommand` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CUnitCommand(RRef* const out, moho::CUnitCommand* const value)
{
  return BuildTypedRefWithCache<moho::CUnitCommand>(
    out,
    value,
    typeid(moho::CUnitCommand),
    gCUnitCommandRRefType,
    gCUnitCommandRRefCache
  );
}

/**
 * Address: 0x006E3DB0 (FUN_006E3DB0)
 *
 * What it does:
 * Packs one temporary `RRef_CUnitCommand` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_CUnitCommand(RRef* const out, moho::CUnitCommand* const value)
{
  RRef tmp{};
  (void)RRef_CUnitCommand(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006E3150 (FUN_006E3150, gpg::RRef_CCommandDB)
 *
 * What it does:
 * Builds a reflection reference for `moho::CCommandDb` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CCommandDB(RRef* const out, moho::CCommandDb* const value)
{
  return BuildTypedRefWithCache<moho::CCommandDb>(
    out,
    value,
    typeid(moho::CCommandDb),
    gCCommandDbRRefType,
    gCCommandDbRRefCache
  );
}

/**
 * Address: 0x006E3310 (FUN_006E3310, gpg::RRef_CUnitCommand_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CUnitCommand*` slot.
 */
gpg::RRef* RRef_CUnitCommand_P(RRef* const out, moho::CUnitCommand** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CUnitCommand>();
  return out;
}

/**
 * Address: 0x006E3DE0 (FUN_006E3DE0)
 *
 * What it does:
 * Packs one temporary `RRef_CUnitCommand_P` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_CUnitCommand_P(RRef* const out, moho::CUnitCommand** const value)
{
  RRef tmp{};
  (void)RRef_CUnitCommand_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006EC1D0 (FUN_006EC1D0, gpg::RRef_WeakPtr_CUnitCommand)
 *
 * What it does:
 * Builds a reflected reference for one `WeakPtr<CUnitCommand>` wrapper value.
 */
gpg::RRef* RRef_WeakPtr_CUnitCommand(
  RRef* const out,
  moho::WeakPtr<moho::CUnitCommand>* const value
)
{
  return BuildTypedRefWithCache<moho::WeakPtr<moho::CUnitCommand>>(
    out,
    value,
    typeid(moho::WeakPtr<moho::CUnitCommand>),
    gWeakPtrCUnitCommandRRefType,
    gWeakPtrCUnitCommandRRefCache
  );
}

/**
 * Address: 0x006EB770 (FUN_006EB770)
 *
 * What it does:
 * Packs one `RRef_WeakPtr_CUnitCommand` result into caller-owned output
 * storage.
 */
gpg::RRef* PackRRef_WeakPtr_CUnitCommand(
  RRef* const out,
  moho::WeakPtr<moho::CUnitCommand>* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_WeakPtr_CUnitCommand(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0059A070 (FUN_0059A070, gpg::RRef_CUnitCommandQueue)
 *
 * What it does:
 * Builds a reflection reference for `moho::CUnitCommandQueue` using
 * `CUnitCommandQueue::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CUnitCommandQueue(RRef* const out, moho::CUnitCommandQueue* const value)
{
  return BuildTypedRefWithCache<moho::CUnitCommandQueue>(
    out,
    value,
    typeid(moho::CUnitCommandQueue),
    moho::CUnitCommandQueue::sType,
    gCUnitCommandQueueRRefCache
  );
}

/**
 * Address: 0x006F8D30 (FUN_006F8D30)
 *
 * What it does:
 * Packs one temporary `RRef_CUnitCommandQueue` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitCommandQueue(RRef* const out, moho::CUnitCommandQueue* const value)
{
  RRef tmp{};
  (void)RRef_CUnitCommandQueue(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005D1750 (FUN_005D1750, gpg::RRef_UnitWeapon)
 *
 * What it does:
 * Builds a reflection reference for `moho::UnitWeapon` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_UnitWeapon(RRef* const out, moho::UnitWeapon* const value)
{
  return BuildTypedRefWithCache<moho::UnitWeapon>(
    out,
    value,
    typeid(moho::UnitWeapon),
    gUnitWeaponRRefType,
    gUnitWeaponRRefCache
  );
}

/**
 * Address: 0x005DF5E0 (FUN_005DF5E0)
 *
 * What it does:
 * Packs one `RRef_UnitWeapon` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_UnitWeapon(RRef* const out, moho::UnitWeapon* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_UnitWeapon(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0055F020 (FUN_0055F020, gpg::RRef_UnitWeaponInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::UnitWeaponInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_UnitWeaponInfo(RRef* const out, moho::UnitWeaponInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "UnitWeaponInfo",
    "Moho::UnitWeaponInfo",
    gUnitWeaponInfoRRefType
  );
}

/**
 * Address: 0x0055E840 (FUN_0055E840)
 *
 * What it does:
 * Materializes one temporary `RRef_UnitWeaponInfo` and copies object/type
 * lanes into caller-owned output storage.
 */
gpg::RRef* PackRRef_UnitWeaponInfo(RRef* const out, moho::UnitWeaponInfo* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_UnitWeaponInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005E0750 (FUN_005E0750, gpg::RRef_UnitWeapon_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::UnitWeapon*` slot.
 */
gpg::RRef* RRef_UnitWeapon_P(RRef* const out, moho::UnitWeapon** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::UnitWeapon>();
  return out;
}

/**
 * Address: 0x005DF090 (FUN_005DF090)
 *
 * What it does:
 * Packs one `RRef_UnitWeapon_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_UnitWeapon_P(RRef* const out, moho::UnitWeapon** const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_UnitWeapon_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004041F0 (FUN_004041F0, gpg::RRef_IdPool)
 *
 * What it does:
 * Builds a reflection reference for `moho::IdPool` using cached RTTI lookups.
 */
gpg::RRef* RRef_IdPool(RRef* const out, moho::IdPool* const value)
{
  return BuildTypedRefWithCache<moho::IdPool>(out, value, typeid(moho::IdPool), gIdPoolRRefType, gIdPoolRRefCache);
}

/**
 * Address: 0x00404180 (FUN_00404180, sub_404180)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_IdPool` and copies lanes out.
 */
gpg::RRef* AssignIdPoolRef(RRef* const out, moho::IdPool* const value)
{
  RRef tmp{};
  RRef_IdPool(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0040F600 (FUN_0040F600, gpg::RRef_CRandomStream)
 *
 * What it does:
 * Builds a reflection reference for `moho::CRandomStream` using cached RTTI lookups.
 */
gpg::RRef* RRef_CRandomStream(RRef* const out, moho::CRandomStream* const value)
{
  return BuildTypedRefWithCache<moho::CRandomStream>(
    out,
    value,
    typeid(moho::CRandomStream),
    gCRandomStreamRRefType,
    gCRandomStreamRRefCache
  );
}

/**
 * Address: 0x005B5A90 (FUN_005B5A90, gpg::RRef_CPathPoint)
 *
 * What it does:
 * Builds a reflection reference for a `moho::CPathPoint` object pointer with
 * cached RTTI lookup.
 */
gpg::RRef* RRef_CPathPoint(RRef* const out, moho::CPathPoint* const value)
{
  return BuildTypedRefWithCache<moho::CPathPoint>(
    out,
    value,
    typeid(moho::CPathPoint),
    gCPathPointRRefType,
    gCPathPointRRefCache
  );
}

/**
 * Address: 0x00554390 (FUN_00554390, gpg::RRef_SOCellPos)
 *
 * What it does:
 * Builds a reflected reference for one `moho::SOCellPos` value pointer.
 */
gpg::RRef* RRef_SOCellPos(RRef* const out, moho::SOCellPos* const value)
{
  return BuildTypedRefWithCache<moho::SOCellPos>(
    out,
    value,
    typeid(moho::SOCellPos),
    gSOCellPosRRefType,
    gSOCellPosRRefCache
  );
}

/**
 * Address: 0x00572790 (FUN_00572790, gpg::RRef_SOffsetInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SOffsetInfo` via declared type
 * name lookup.
 */
gpg::RRef* RRef_SOffsetInfo(RRef* const out, moho::SOffsetInfo* const value)
{
  return BuildNamedDeclaredRefWithCache(
    out,
    value,
    "SOffsetInfo",
    "Moho::SOffsetInfo",
    gSOffsetInfoRRefType
  );
}

/**
 * Address: 0x00571060 (FUN_00571060)
 *
 * What it does:
 * Builds one temporary `RRef_SOffsetInfo` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SOffsetInfo(RRef* const out, moho::SOffsetInfo* const value)
{
  RRef tmp{};
  (void)RRef_SOffsetInfo(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00764280 (FUN_00764280, gpg::RRef_HPathCell)
 *
 * What it does:
 * Builds a reflection reference for `moho::HPathCell` object pointers.
 */
gpg::RRef* RRef_HPathCell(RRef* const out, moho::HPathCell* const value)
{
  return BuildTypedRefWithCache<moho::HPathCell>(
    out,
    value,
    typeid(moho::HPathCell),
    gHPathCellRRefType,
    gHPathCellRRefCache
  );
}

/**
 * Address: 0x00763C20 (FUN_00763C20, sub_763C20)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_HPathCell` and copies
 * lanes out.
 */
gpg::RRef* AssignHPathCellRef(RRef* const out, moho::HPathCell* const value)
{
  RRef tmp{};
  RRef_HPathCell(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x007571F0 (FUN_007571F0, gpg::RRef_PathTables)
 * Address: 0x00756220 (FUN_00756220)
 *
 * What it does:
 * Builds a reflection reference for `moho::PathTables` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_PathTables(RRef* const out, moho::PathTables* const value)
{
  return BuildTypedRefWithCache<moho::PathTables>(
    out,
    value,
    typeid(moho::PathTables),
    gPathTablesRRefType,
    gPathTablesRRefCache
  );
}

/**
 * Address: 0x00707A10 (FUN_00707A10, gpg::RRef_CArmyStats)
 *
 * What it does:
 * Builds a reflection reference for `moho::CArmyStats` using
 * `CArmyStats::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CArmyStats(RRef* const out, moho::CArmyStats* const value)
{
  return BuildTypedRefWithCache<moho::CArmyStats>(
    out,
    value,
    typeid(moho::CArmyStats),
    moho::CArmyStats::sType,
    gCArmyStatsRRefCache
  );
}

/**
 * Address: 0x007126B0 (FUN_007126B0)
 *
 * What it does:
 * Packs one `RRef_CArmyStats` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_CArmyStats(RRef* const out, moho::CArmyStats* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CArmyStats(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x007139C0 (FUN_007139C0, gpg::RRef_Stats_CArmyStatItem)
 *
 * What it does:
 * Builds a reflection reference for `moho::Stats<moho::CArmyStatItem>` using
 * cached RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_Stats_CArmyStatItem(RRef* const out, moho::Stats<moho::CArmyStatItem>* const value)
{
  return BuildTypedRefWithCache<moho::Stats<moho::CArmyStatItem>>(
    out,
    value,
    typeid(moho::Stats<moho::CArmyStatItem>),
    moho::Stats<moho::CArmyStatItem>::sType,
    gStatsCArmyStatItemRRefCache
  );
}

/**
 * Address: 0x00712900 (FUN_00712900)
 *
 * What it does:
 * Packs one `RRef_Stats_CArmyStatItem` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_Stats_CArmyStatItem(
  RRef* const out,
  moho::Stats<moho::CArmyStatItem>* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_Stats_CArmyStatItem(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00713D90 (FUN_00713D90, gpg::RRef_CArmyStatItem_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CArmyStatItem*` slot.
 */
gpg::RRef* RRef_CArmyStatItem_P(RRef* const out, moho::CArmyStatItem** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CArmyStatItem>();
  return out;
}

/**
 * Address: 0x00712AF0 (FUN_00712AF0, sub_712AF0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CArmyStatItem_P` and
 * copies lanes out.
 */
gpg::RRef* AssignCArmyStatItemPointerRef(RRef* const out, moho::CArmyStatItem** const value)
{
  RRef tmp{};
  RRef_CArmyStatItem_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005CADE0 (FUN_005CADE0, gpg::RRef_ReconBlip)
 *
 * What it does:
 * Builds a reflection reference for `moho::ReconBlip` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_ReconBlip(RRef* const out, moho::ReconBlip* const value)
{
  return BuildTypedRefWithCache<moho::ReconBlip>(out, value, typeid(moho::ReconBlip), moho::ReconBlip::sType, gReconBlipRRefCache);
}

/**
 * Address: 0x005CB790 (FUN_005CB790, gpg::RRef_SPerArmyReconInfo)
 *
 * What it does:
 * Builds a reflection reference for `moho::SPerArmyReconInfo` object pointers.
 */
gpg::RRef* RRef_SPerArmyReconInfo(RRef* const out, moho::SPerArmyReconInfo* const value)
{
  return BuildTypedRefWithCache<moho::SPerArmyReconInfo>(
    out,
    value,
    typeid(moho::SPerArmyReconInfo),
    moho::SPerArmyReconInfo::sType,
    gSPerArmyReconInfoRRefCache
  );
}

/**
 * Address: 0x005CB930 (FUN_005CB930, gpg::RRef_ReconBlip_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::ReconBlip*` slot.
 */
gpg::RRef* RRef_ReconBlip_P(RRef* const out, moho::ReconBlip** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::ReconBlip>();
  return out;
}

/**
 * Address: 0x006B2020 (FUN_006B2020, gpg::RRef_CEconomyEvent_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CEconomyEvent*` slot.
 */
gpg::RRef* RRef_CEconomyEvent_P(RRef* const out, moho::CEconomyEvent** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CEconomyEvent>();
  return out;
}

/**
 * Address: 0x006B3CD0 (FUN_006B3CD0)
 *
 * What it does:
 * Materializes one temporary `RRef_CEconomyEvent_P` and copies `(mObj,mType)`
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_CEconomyEvent_P(RRef* const out, moho::CEconomyEvent** const value)
{
  RRef tmp{};
  (void)RRef_CEconomyEvent_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006B3AD0 (FUN_006B3AD0, gpg::RRef_CEconomyEvent)
 *
 * What it does:
 * Builds a reflection reference for `moho::CEconomyEvent` using
 * `CEconomyEvent::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CEconomyEvent(RRef* const out, moho::CEconomyEvent* const value)
{
  return BuildTypedRefWithCache<moho::CEconomyEvent>(
    out,
    value,
    typeid(moho::CEconomyEvent),
    moho::CEconomyEvent::sType,
    gCEconomyEventRRefCache
  );
}

/**
 * Address: 0x006B3CA0 (FUN_006B3CA0, sub_6B3CA0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CEconomyEvent` and copies
 * lanes out.
 */
gpg::RRef* AssignCEconomyEventRef(RRef* const out, moho::CEconomyEvent* const value)
{
  RRef tmp{};
  RRef_CEconomyEvent(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00758730 (FUN_00758730, gpg::RRef_CDecalBuffer)
 *
 * What it does:
 * Builds a reflection reference for `moho::CDecalBuffer` using
 * `CDecalBuffer::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CDecalBuffer(RRef* const out, moho::CDecalBuffer* const value)
{
  return BuildTypedRefWithCache<moho::CDecalBuffer>(
    out,
    value,
    typeid(moho::CDecalBuffer),
    moho::CDecalBuffer::sType,
    gCDecalBufferRRefCache
  );
}

/**
 * Address: 0x0077DAF0 (FUN_0077DAF0)
 *
 * What it does:
 * Packs one `RRef_CDecalBuffer` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CDecalBuffer(RRef* const out, moho::CDecalBuffer* const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef temporary{};
  (void)RRef_CDecalBuffer(&temporary, value);
  out->mObj = temporary.mObj;
  out->mType = temporary.mType;
  return out;
}

/**
 * Address: 0x0077E540 (FUN_0077E540, gpg::RRef_CDecalHandle_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::CDecalHandle*` slot.
 */
gpg::RRef* RRef_CDecalHandle_P(RRef* const out, moho::CDecalHandle** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::CDecalHandle>();
  return out;
}

/**
 * Address: 0x0077F400 (FUN_0077F400)
 *
 * What it does:
 * Packs one `RRef_CDecalHandle_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CDecalHandle_P(RRef* const out, moho::CDecalHandle** const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef temporary{};
  (void)RRef_CDecalHandle_P(&temporary, value);
  out->mObj = temporary.mObj;
  out->mType = temporary.mType;
  return out;
}

/**
 * Address: 0x0077EC40 (FUN_0077EC40)
 *
 * What it does:
 * Builds one bracketed lexical string (`[TypeLexical]`) for a reflected
 * `moho::CDecalHandle*` slot, or `"NULL"` when the slot is empty.
 */
msvc8::string* BuildCDecalHandlePointerLexical(
  msvc8::string* const out,
  moho::CDecalHandle*** const slot)
{
  if (out == nullptr) {
    return nullptr;
  }

  if (slot == nullptr || *slot == nullptr || **slot == nullptr) {
    out->assign_owned("NULL");
    return out;
  }

  gpg::RRef objectRef{};
  (void)gpg::RRef_CDecalHandle(&objectRef, **slot);

  gpg::RType* runtimeType = moho::CDecalHandle::sType;
  if (runtimeType == nullptr) {
    runtimeType = gpg::LookupRType(typeid(moho::CDecalHandle));
    moho::CDecalHandle::sType = runtimeType;
  }

  const msvc8::string lexical = runtimeType != nullptr ? runtimeType->GetLexical(objectRef) : msvc8::string();
  const msvc8::string bracketed = gpg::STR_Printf("[%s]", lexical.c_str());
  out->assign_owned(bracketed.c_str());
  return out;
}

/**
 * Address: 0x0077EAB0 (FUN_0077EAB0)
 *
 * What it does:
 * Builds and caches one pointer-type name lane (`"Type*"`) for
 * `moho::CDecalHandle*`, reusing the reflected `CDecalHandle::sType` cache.
 */
const char* BuildCDecalHandlePointerTypeName()
{
  static msvc8::string sCachedName;
  if (sCachedName.empty()) {
    gpg::RType* runtimeType = moho::CDecalHandle::sType;
    if (runtimeType == nullptr) {
      runtimeType = gpg::LookupRType(typeid(moho::CDecalHandle));
      moho::CDecalHandle::sType = runtimeType;
    }

    const char* const baseName = runtimeType != nullptr ? runtimeType->GetName() : "";
    sCachedName.assign_owned(gpg::STR_Printf("%s*", baseName).c_str());
  }
  return sCachedName.c_str();
}

/**
 * Address: 0x0077E390 (FUN_0077E390, gpg::RRef_CDecalHandle)
 *
 * What it does:
 * Builds a reflection reference for `moho::CDecalHandle` using
 * `CDecalHandle::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CDecalHandle(RRef* const out, moho::CDecalHandle* const value)
{
  return BuildTypedRefWithCache<moho::CDecalHandle>(
    out,
    value,
    typeid(moho::CDecalHandle),
    moho::CDecalHandle::sType,
    gCDecalHandleRRefCache
  );
}

/**
 * Address: 0x0077DB30 (FUN_0077DB30)
 *
 * What it does:
 * Packs one `RRef_CDecalHandle` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CDecalHandle(RRef* const out, moho::CDecalHandle* const value)
{
  if (out == nullptr) {
    return nullptr;
  }

  RRef temporary{};
  (void)RRef_CDecalHandle(&temporary, value);
  out->mObj = temporary.mObj;
  out->mType = temporary.mType;
  return out;
}

/**
 * Address: 0x0077EDF0 (FUN_0077EDF0)
 *
 * What it does:
 * Builds one reflected reference from the `index`-th contiguous
 * `CDecalHandle` lane starting at `(*firstElementSlot)`.
 */
gpg::RRef* RRef_CDecalHandleArraySlot(
  RRef* const out,
  moho::CDecalHandle* const* const firstElementSlot,
  const int index
)
{
  if (out == nullptr) {
    return nullptr;
  }

  moho::CDecalHandle* const firstElement = (firstElementSlot != nullptr) ? *firstElementSlot : nullptr;
  if (firstElement == nullptr) {
    out->mObj = nullptr;
    out->mType = nullptr;
    return out;
  }

  return RRef_CDecalHandle(out, firstElement + static_cast<std::ptrdiff_t>(index));
}

/**
 * Address: 0x005E0300 (FUN_005E0300, gpg::RRef_CAiAttackerImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiAttackerImpl` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_CAiAttackerImpl(RRef* const out, moho::CAiAttackerImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiAttackerImpl>(
    out,
    value,
    typeid(moho::CAiAttackerImpl),
    gCAiAttackerImplRRefType,
    gCAiAttackerImplRRefCache
  );
}

/**
 * Address: 0x005DEB80 (FUN_005DEB80)
 *
 * What it does:
 * Packs one `RRef_CAiAttackerImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiAttackerImpl(RRef* const out, moho::CAiAttackerImpl* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CAiAttackerImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005EDB00 (FUN_005EDB00, gpg::RRef_CAiTransportImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiTransportImpl` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_CAiTransportImpl(RRef* const out, moho::CAiTransportImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiTransportImpl>(
    out,
    value,
    typeid(moho::CAiTransportImpl),
    gCAiTransportImplRRefType,
    gCAiTransportImplRRefCache
  );
}

/**
 * Address: 0x005EC3B0 (FUN_005EC3B0, gpg::RRef_CAiTransportImpl pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_CAiTransportImpl` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiTransportImpl(RRef* const out, moho::CAiTransportImpl* const value)
{
  RRef tmp{};
  (void)RRef_CAiTransportImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005CC0D0 (FUN_005CC0D0, gpg::RRef_CAiReconDBImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiReconDBImpl` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_CAiReconDBImpl(RRef* const out, moho::CAiReconDBImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiReconDBImpl>(
    out,
    value,
    typeid(moho::CAiReconDBImpl),
    gCAiReconDBImplRRefType,
    gCAiReconDBImplRRefCache
  );
}

/**
 * Address: 0x005D4730 (FUN_005D4730, gpg::RRef_CAiSteeringImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiSteeringImpl` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_CAiSteeringImpl(RRef* const out, moho::CAiSteeringImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiSteeringImpl>(
    out,
    value,
    typeid(moho::CAiSteeringImpl),
    gCAiSteeringImplRRefType,
    gCAiSteeringImplRRefCache
  );
}

/**
 * Address: 0x005D4680 (FUN_005D4680)
 *
 * What it does:
 * Packs one `RRef_CAiSteeringImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiSteeringImpl(RRef* const out, moho::CAiSteeringImpl* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CAiSteeringImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005D0E70 (FUN_005D0E70, gpg::RRef_CAiSiloBuildImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::CAiSiloBuildImpl` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_CAiSiloBuildImpl(RRef* const out, moho::CAiSiloBuildImpl* const value)
{
  return BuildTypedRefWithCache<moho::CAiSiloBuildImpl>(
    out,
    value,
    typeid(moho::CAiSiloBuildImpl),
    moho::CAiSiloBuildImpl::sType,
    gCAiSiloBuildImplRRefCache
  );
}

/**
 * Address: 0x005D08A0 (FUN_005D08A0)
 *
 * What it does:
 * Packs one `RRef_CAiSiloBuildImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiSiloBuildImpl(RRef* const out, moho::CAiSiloBuildImpl* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_CAiSiloBuildImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005E0E80 (FUN_005E0E80, gpg::RRef_LAiAttackerImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::LAiAttackerImpl` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_LAiAttackerImpl(RRef* const out, moho::LAiAttackerImpl* const value)
{
  return BuildTypedRefWithCache<moho::LAiAttackerImpl>(
    out,
    value,
    typeid(moho::LAiAttackerImpl),
    gLAiAttackerImplRRefType,
    gLAiAttackerImplRRefCache
  );
}

/**
 * Address: 0x006B5DA0 (FUN_006B5DA0, gpg::RRef_IAiAttacker)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiAttacker` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiAttacker(RRef* const out, moho::IAiAttacker* const value)
{
  return BuildTypedRefWithCache<moho::IAiAttacker>(
    out,
    value,
    typeid(moho::IAiAttacker),
    moho::IAiAttacker::sType,
    gIAiAttackerRRefCache
  );
}

/**
 * Address: 0x006B59D0 (FUN_006B59D0, gpg::RRef_IAiSteering)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiSteering` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiSteering(RRef* const out, moho::IAiSteering* const value)
{
  return BuildTypedRefWithCache<moho::IAiSteering>(
    out,
    value,
    typeid(moho::IAiSteering),
    gIAiSteeringRRefType,
    gIAiSteeringRRefCache
  );
}

/**
 * Address: 0x006B5F90 (FUN_006B5F90, gpg::RRef_IAiCommandDispatch)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiCommandDispatch` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiCommandDispatch(RRef* const out, moho::IAiCommandDispatch* const value)
{
  return BuildTypedRefWithCache<moho::IAiCommandDispatch>(
    out,
    value,
    typeid(moho::IAiCommandDispatch),
    gIAiCommandDispatchRRefType,
    gIAiCommandDispatchRRefCache
  );
}

/**
 * Address: 0x00599AB0 (FUN_00599AB0, gpg::RRef_IAiCommandDispatchImpl)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiCommandDispatchImpl` using
 * cached RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiCommandDispatchImpl(RRef* const out, moho::IAiCommandDispatchImpl* const value)
{
  return BuildTypedRefWithCache<moho::IAiCommandDispatchImpl>(
    out,
    value,
    typeid(moho::IAiCommandDispatchImpl),
    moho::IAiCommandDispatchImpl::sType,
    gIAiCommandDispatchImplRRefCache
  );
}

/**
 * Address: 0x006B6180 (FUN_006B6180, gpg::RRef_IAiNavigator)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiNavigator` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiNavigator(RRef* const out, moho::IAiNavigator* const value)
{
  return BuildTypedRefWithCache<moho::IAiNavigator>(
    out,
    value,
    typeid(moho::IAiNavigator),
    gIAiNavigatorRRefType,
    gIAiNavigatorRRefCache
  );
}

/**
 * Address: 0x006B6370 (FUN_006B6370, gpg::RRef_IAiBuilder)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiBuilder` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiBuilder(RRef* const out, moho::IAiBuilder* const value)
{
  return BuildTypedRefWithCache<moho::IAiBuilder>(
    out,
    value,
    typeid(moho::IAiBuilder),
    gIAiBuilderRRefType,
    gIAiBuilderRRefCache
  );
}

/**
 * Address: 0x006B6560 (FUN_006B6560, gpg::RRef_IAiSiloBuild)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiSiloBuild` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiSiloBuild(RRef* const out, moho::IAiSiloBuild* const value)
{
  return BuildTypedRefWithCache<moho::IAiSiloBuild>(
    out,
    value,
    typeid(moho::IAiSiloBuild),
    gIAiSiloBuildRRefType,
    gIAiSiloBuildRRefCache
  );
}

/**
 * Address: 0x006B6750 (FUN_006B6750, gpg::RRef_IAiTransport)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiTransport` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiTransport(RRef* const out, moho::IAiTransport* const value)
{
  return BuildTypedRefWithCache<moho::IAiTransport>(
    out,
    value,
    typeid(moho::IAiTransport),
    gIAiTransportRRefType,
    gIAiTransportRRefCache
  );
}

/**
 * Address: 0x006EC620 (FUN_006EC620, gpg::RRef_Listener_ECommandEvent)
 *
 * What it does:
 * Builds a reflection reference for `Listener<ECommandEvent>` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_Listener_ECommandEvent(RRef* const out, moho::Listener<moho::ECommandEvent>* const value)
{
  return BuildTypedRefWithCache<moho::Listener<moho::ECommandEvent>>(
    out,
    value,
    typeid(moho::Listener<moho::ECommandEvent>),
    gListenerECommandEventRRefType,
    gListenerECommandEventRRefCache
  );
}

/**
 * Address: 0x006F9410 (FUN_006F9410, gpg::RRef_Listener_EUnitCommandQueueStatus)
 *
 * What it does:
 * Builds a reflection reference for `Listener<EUnitCommandQueueStatus>` using
 * cached RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_Listener_EUnitCommandQueueStatus(
  RRef* const out,
  moho::Listener<moho::EUnitCommandQueueStatus>* const value
)
{
  return BuildTypedRefWithCache<moho::Listener<moho::EUnitCommandQueueStatus>>(
    out,
    value,
    typeid(moho::Listener<moho::EUnitCommandQueueStatus>),
    gListenerEUnitCommandQueueStatusRRefType,
    gListenerEUnitCommandQueueStatusRRefCache
  );
}

/**
 * Address: 0x00764460 (FUN_00764460, gpg::RRef_Listener_NavPath)
 *
 * What it does:
 * Builds a reflection reference for `Listener<const SNavPath&>` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_Listener_NavPath(RRef* const out, moho::Listener<const moho::SNavPath&>* const value)
{
  return BuildTypedRefWithCache<moho::Listener<const moho::SNavPath&>>(
    out,
    value,
    typeid(moho::Listener<const moho::SNavPath&>),
    gListenerNavPathRRefType,
    gListenerNavPathRRefCache
  );
}

/**
 * Address: 0x005A8A40 (FUN_005A8A40, gpg::RRef_Listener_EAiNavigatorEvent)
 *
 * What it does:
 * Builds a reflection reference for `Listener<EAiNavigatorEvent>` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef*
RRef_Listener_EAiNavigatorEvent(RRef* const out, moho::Listener<moho::EAiNavigatorEvent>* const value)
{
  return BuildTypedRefWithCache<moho::Listener<moho::EAiNavigatorEvent>>(
    out,
    value,
    typeid(moho::Listener<moho::EAiNavigatorEvent>),
    gListenerEAiNavigatorEventRRefType,
    gListenerEAiNavigatorEventRRefCache
  );
}

/**
 * Address: 0x005E0A90 (FUN_005E0A90, gpg::RRef_Listener_EAiAttackerEvent)
 *
 * What it does:
 * Builds a reflection reference for `Listener<EAiAttackerEvent>` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef*
RRef_Listener_EAiAttackerEvent(RRef* const out, moho::Listener<moho::EAiAttackerEvent>* const value)
{
  return BuildTypedRefWithCache<moho::Listener<moho::EAiAttackerEvent>>(
    out,
    value,
    typeid(moho::Listener<moho::EAiAttackerEvent>),
    gListenerEAiAttackerEventRRefType,
    gListenerEAiAttackerEventRRefCache
  );
}

/**
 * Address: 0x005EE1B0 (FUN_005EE1B0, gpg::RRef_Listener_EAiTransportEvent)
 *
 * What it does:
 * Builds a reflection reference for `Listener<EAiTransportEvent>` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef*
RRef_Listener_EAiTransportEvent(RRef* const out, moho::Listener<moho::EAiTransportEvent>* const value)
{
  return BuildTypedRefWithCache<moho::Listener<moho::EAiTransportEvent>>(
    out,
    value,
    typeid(moho::Listener<moho::EAiTransportEvent>),
    gListenerEAiTransportEventRRefType,
    gListenerEAiTransportEventRRefCache
  );
}

/**
 * Address: 0x005EDD30 (FUN_005EDD30, gpg::RRef_SAiReservedTransportBone)
 *
 * What it does:
 * Builds a reflection reference for `moho::SAiReservedTransportBone` object
 * pointers.
 */
gpg::RRef* RRef_SAiReservedTransportBone(RRef* const out, moho::SAiReservedTransportBone* const value)
{
  return BuildTypedRefWithCache<moho::SAiReservedTransportBone>(
    out,
    value,
    typeid(moho::SAiReservedTransportBone),
    moho::SAiReservedTransportBone::sType,
    gSAiReservedTransportBoneRRefCache
  );
}

/**
 * Address: 0x005EC420 (FUN_005EC420, gpg::RRef_SAiReservedTransportBone pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SAiReservedTransportBone` and copies its
 * `(mObj,mType)` pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_SAiReservedTransportBone(RRef* const out, moho::SAiReservedTransportBone* const value)
{
  RRef tmp{};
  (void)RRef_SAiReservedTransportBone(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005EDED0 (FUN_005EDED0, gpg::RRef_SAttachPoint)
 *
 * What it does:
 * Builds a reflection reference for `moho::SAttachPoint` object pointers.
 */
gpg::RRef* RRef_SAttachPoint(RRef* const out, moho::SAttachPoint* const value)
{
  return BuildTypedRefWithCache<moho::SAttachPoint>(
    out,
    value,
    typeid(moho::SAttachPoint),
    gSAttachPointRRefType,
    gSAttachPointRRefCache
  );
}

/**
 * Address: 0x005EC450 (FUN_005EC450, gpg::RRef_SAttachPoint pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SAttachPoint` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_SAttachPoint(RRef* const out, moho::SAttachPoint* const value)
{
  RRef tmp{};
  (void)RRef_SAttachPoint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00582F00 (FUN_00582F00, gpg::RRef_SPointVector)
 *
 * What it does:
 * Builds a reflected reference for one `moho::SPointVector` value pointer.
 */
gpg::RRef* RRef_SPointVector(RRef* const out, moho::SPointVector* const value)
{
  return BuildTypedRefWithCache<moho::SPointVector>(
    out,
    value,
    typeid(moho::SPointVector),
    gSPointVectorRRefType,
    gSPointVectorRRefCache
  );
}

/**
 * Address: 0x00581D60 (FUN_00581D60, gpg::RRef_SPointVector pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_SPointVector` and copies its `(mObj,mType)` pair
 * into caller-owned output storage.
 */
gpg::RRef* PackRRef_SPointVector(RRef* const out, moho::SPointVector* const value)
{
  RRef tmp{};
  (void)RRef_SPointVector(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x007582F0 (FUN_007582F0, gpg::RRef_IAiFormationDB)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiFormationDB` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiFormationDB(RRef* const out, moho::IAiFormationDB* const value)
{
  return BuildTypedRefWithCache<moho::IAiFormationDB>(
    out,
    value,
    typeid(moho::IAiFormationDB),
    gIAiFormationDBRRefType,
    gIAiFormationDBRRefCache
  );
}

/**
 * Address: 0x00758500 (FUN_00758500, gpg::RRef_ISimResources)
 *
 * What it does:
 * Builds a reflection reference for `moho::ISimResources` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_ISimResources(RRef* const out, moho::ISimResources* const value)
{
  return BuildTypedRefWithCache<moho::ISimResources>(
    out,
    value,
    typeid(moho::ISimResources),
    gISimResourcesRRefType,
    gISimResourcesRRefCache
  );
}

/**
 * Address: 0x00683230 (FUN_00683230, gpg::RRef_CColPrimitiveBase)
 *
 * What it does:
 * Builds a reflection reference for `moho::CColPrimitiveBase` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_CColPrimitiveBase(RRef* const out, moho::CColPrimitiveBase* const value)
{
  return BuildTypedRefWithCache<moho::CColPrimitiveBase>(
    out,
    value,
    typeid(moho::CColPrimitiveBase),
    gCColPrimitiveBaseRRefType,
    gCColPrimitiveBaseRRefCache
  );
}

/**
 * Address: 0x006839C0 (FUN_006839C0, gpg::RRef_Motor)
 *
 * What it does:
 * Builds a reflection reference for `moho::EntityMotor` using
 * `EntityMotor::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_Motor(RRef* const out, moho::EntityMotor* const value)
{
  return BuildTypedRefWithCache<moho::EntityMotor>(
    out,
    value,
    typeid(moho::EntityMotor),
    moho::EntityMotor::sType,
    gMotorRRefCache
  );
}

/**
 * Address: 0x00707640 (FUN_00707640, gpg::RRef_IAiReconDB)
 *
 * What it does:
 * Builds a reflection reference for `moho::IAiReconDB` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IAiReconDB(RRef* const out, moho::IAiReconDB* const value)
{
  return BuildTypedRefWithCache<moho::IAiReconDB>(
    out,
    value,
    typeid(moho::IAiReconDB),
    moho::IAiReconDB::sType,
    gIAiReconDBRRefCache
  );
}

/**
 * Address: 0x0076AE70 (FUN_0076AE70, gpg::RRef_IPathTraveler)
 *
 * What it does:
 * Builds a reflection reference for `moho::IPathTraveler` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IPathTraveler(RRef* const out, moho::IPathTraveler* const value)
{
  return BuildTypedRefWithCache<moho::IPathTraveler>(
    out,
    value,
    typeid(moho::IPathTraveler),
    gIPathTravelerRRefType,
    gIPathTravelerRRefCache
  );
}

/**
 * Address: 0x00753FC0 (FUN_00753FC0, gpg::RRef_Shield)
 *
 * What it does:
 * Builds a reflection reference for `moho::Shield` using cached RTTI lookup
 * and derived-type normalization.
 */
gpg::RRef* RRef_Shield(RRef* const out, moho::Shield* const value)
{
  return BuildTypedRefWithCache<moho::Shield>(
    out,
    value,
    typeid(moho::Shield),
    gShieldRRefType,
    gShieldRRefCache
  );
}

/**
 * Address: 0x007542F0 (FUN_007542F0, gpg::RRef_Shield_P)
 *
 * What it does:
 * Builds a reflected reference for one `moho::Shield*` slot.
 */
gpg::RRef* RRef_Shield_P(RRef* const out, moho::Shield** const value)
{
  if (!out) {
    return nullptr;
  }

  out->mObj = value;
  out->mType = CachedPointerType<moho::Shield>();
  return out;
}

/**
 * Address: 0x00751E60 (FUN_00751E60)
 *
 * What it does:
 * Packs one temporary `RRef_Shield` result into caller-owned output storage
 * by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_Shield(RRef* const out, moho::Shield* const value)
{
  RRef tmp{};
  (void)RRef_Shield(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00751F90 (FUN_00751F90)
 *
 * What it does:
 * Packs one temporary `RRef_Shield_P` result into caller-owned output
 * storage by copying the `(mObj,mType)` lane pair.
 */
gpg::RRef* PackRRef_Shield_P(RRef* const out, moho::Shield** const value)
{
  RRef tmp{};
  (void)RRef_Shield_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00750320 (FUN_00750320)
 *
 * What it does:
 * Builds one bracketed lexical string (`[TypeLexical]`) for a reflected
 * `moho::Shield*` slot, or `"NULL"` when the slot is empty.
 */
msvc8::string* BuildShieldPointerLexical(msvc8::string* const out, moho::Shield*** const slot)
{
  if (out == nullptr) {
    return nullptr;
  }

  if (slot == nullptr || *slot == nullptr || **slot == nullptr) {
    out->assign_owned("NULL");
    return out;
  }

  gpg::RRef objectRef{};
  (void)gpg::RRef_Shield(&objectRef, **slot);

  gpg::RType* runtimeType = gShieldRRefType;
  if (runtimeType == nullptr) {
    runtimeType = gpg::LookupRType(typeid(moho::Shield));
    gShieldRRefType = runtimeType;
  }

  const msvc8::string lexical = runtimeType != nullptr ? runtimeType->GetLexical(objectRef) : msvc8::string();
  const msvc8::string bracketed = gpg::STR_Printf("[%s]", lexical.c_str());
  out->assign_owned(bracketed.c_str());
  return out;
}

/**
 * Address: 0x00750190 (FUN_00750190)
 *
 * What it does:
 * Builds and caches one pointer-type name lane (`"Type*"`) for
 * `moho::Shield*`, reusing the reflected `Shield::sType` lookup cache.
 */
const char* BuildShieldPointerTypeName()
{
  static msvc8::string sCachedName;
  if (sCachedName.empty()) {
    gpg::RType* runtimeType = gShieldRRefType;
    if (runtimeType == nullptr) {
      runtimeType = gpg::LookupRType(typeid(moho::Shield));
      gShieldRRefType = runtimeType;
    }

    const char* const baseName = runtimeType != nullptr ? runtimeType->GetName() : "";
    sCachedName.assign_owned(gpg::STR_Printf("%s*", baseName).c_str());
  }
  return sCachedName.c_str();
}

/**
 * Address: 0x00758910 (FUN_00758910, gpg::RRef_IEffectManager)
 *
 * What it does:
 * Builds a reflection reference for `moho::IEffectManager` using cached RTTI
 * lookup and derived-type normalization.
 */
gpg::RRef* RRef_IEffectManager(RRef* const out, moho::IEffectManager* const value)
{
  return BuildTypedRefWithCache<moho::IEffectManager>(
    out,
    value,
    typeid(moho::IEffectManager),
    moho::IEffectManager::sType,
    gIEffectManagerRRefCache
  );
}

/**
 * Address: 0x00680D70 (FUN_00680D70, gpg::RRef_PositionHistory)
 *
 * What it does:
 * Builds a reflection reference for `moho::PositionHistory` object pointers.
 */
gpg::RRef* RRef_PositionHistory(RRef* const out, moho::PositionHistory* const value)
{
  return BuildTypedRefWithCache<moho::PositionHistory>(
    out,
    value,
    typeid(moho::PositionHistory),
    moho::PositionHistory::sType,
    gPositionHistoryRRefCache
  );
}

/**
 * Address: 0x0067FB70 (FUN_0067FB70, sub_67FB70)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_PositionHistory` and
 * copies lanes out.
 */
gpg::RRef* AssignPositionHistoryRef(RRef* const out, moho::PositionHistory* const value)
{
  RRef tmp{};
  RRef_PositionHistory(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00713700 (FUN_00713700, gpg::RRef_STrigger)
 *
 * What it does:
 * Builds a reflection reference for `moho::STrigger` object pointers.
 */
gpg::RRef* RRef_STrigger(RRef* const out, moho::STrigger* const value)
{
  return BuildTypedRefWithCache<moho::STrigger>(
    out,
    value,
    typeid(moho::STrigger),
    moho::STrigger::sType,
    gSTriggerRRefCache
  );
}

/**
 * Address: 0x00712740 (FUN_00712740)
 *
 * What it does:
 * Packs one `RRef_STrigger` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_STrigger(RRef* const out, moho::STrigger* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_STrigger(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00713560 (FUN_00713560, gpg::RRef_SCondition)
 *
 * What it does:
 * Builds a reflection reference for `moho::SCondition` object pointers.
 */
gpg::RRef* RRef_SCondition(RRef* const out, moho::SCondition* const value)
{
  return BuildTypedRefWithCache<moho::SCondition>(
    out,
    value,
    typeid(moho::SCondition),
    moho::SCondition::sType,
    gSConditionRRefCache
  );
}

/**
 * Address: 0x00712700 (FUN_00712700)
 *
 * What it does:
 * Packs one `RRef_SCondition` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_SCondition(RRef* const out, moho::SCondition* const value)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_SCondition(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005CE540 (FUN_005CE540, gpg::RRef_CInfluenceMap)
 *
 * What it does:
 * Builds a reflection reference for `moho::CInfluenceMap` using
 * `CInfluenceMap::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CInfluenceMap(RRef* const out, moho::CInfluenceMap* const value)
{
  return BuildTypedRefWithCache<moho::CInfluenceMap>(
    out,
    value,
    typeid(moho::CInfluenceMap),
    moho::CInfluenceMap::sType,
    gCInfluenceMapRRefCache
  );
}

/**
 * Address: 0x0071E410 (FUN_0071E410, gpg::RRef_InfluenceGrid)
 *
 * What it does:
 * Builds a reflection reference for `moho::InfluenceGrid` object pointers.
 */
gpg::RRef* RRef_InfluenceGrid(RRef* const out, moho::InfluenceGrid* const value)
{
  return BuildTypedRefWithCache<moho::InfluenceGrid>(
    out,
    value,
    typeid(moho::InfluenceGrid),
    moho::InfluenceGrid::sType,
    gInfluenceGridRRefCache
  );
}

/**
 * Address: 0x0071E5B0 (FUN_0071E5B0, gpg::RRef_SThreat)
 *
 * What it does:
 * Builds a reflection reference for `moho::SThreat` object pointers.
 */
gpg::RRef* RRef_SThreat(RRef* const out, moho::SThreat* const value)
{
  return BuildTypedRefWithCache<moho::SThreat>(
    out,
    value,
    typeid(moho::SThreat),
    moho::SThreat::sType,
    gSThreatRRefCache
  );
}

/**
 * Address: 0x0064C960 (FUN_0064C960, gpg::RRef_RDebugCollision)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugCollision` using
 * `RDebugCollision::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugCollision(RRef* const out, moho::RDebugCollision* const value)
{
  return BuildTypedRefWithCache<moho::RDebugCollision>(
    out,
    value,
    typeid(moho::RDebugCollision),
    moho::RDebugCollision::sType,
    gRDebugCollisionRRefCache
  );
}

/**
 * Address: 0x0064C930 (FUN_0064C930)
 *
 * What it does:
 * Packs one `RRef_RDebugCollision` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_RDebugCollision(
  RRef* const out,
  moho::RDebugCollision* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_RDebugCollision(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064FBC0 (FUN_0064FBC0, gpg::RRef_RDebugGrid)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugGrid` using
 * `RDebugGrid::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugGrid(RRef* const out, moho::RDebugGrid* const value)
{
  return BuildTypedRefWithCache<moho::RDebugGrid>(
    out,
    value,
    typeid(moho::RDebugGrid),
    moho::RDebugGrid::sType,
    gRDebugGridRRefCache
  );
}

/**
 * Address: 0x0064F800 (FUN_0064F800)
 *
 * What it does:
 * Packs one `RRef_RDebugGrid` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_RDebugGrid(
  RRef* const out,
  moho::RDebugGrid* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_RDebugGrid(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0064FD70 (FUN_0064FD70, gpg::RRef_RDebugRadar)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugRadar` using
 * `RDebugRadar::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugRadar(RRef* const out, moho::RDebugRadar* const value)
{
  return BuildTypedRefWithCache<moho::RDebugRadar>(
    out,
    value,
    typeid(moho::RDebugRadar),
    moho::RDebugRadar::sType,
    gRDebugRadarRRefCache
  );
}

/**
 * Address: 0x0064F830 (FUN_0064F830)
 *
 * What it does:
 * Packs one `RRef_RDebugRadar` result into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* PackRRef_RDebugRadar(
  RRef* const out,
  moho::RDebugRadar* const value
)
{
  if (!out) {
    return nullptr;
  }

  RRef tmp{};
  (void)RRef_RDebugRadar(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00651200 (FUN_00651200, gpg::RRef_RDebugNavPath)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugNavPath` using
 * `RDebugNavPath::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugNavPath(RRef* const out, moho::RDebugNavPath* const value)
{
  return BuildTypedRefWithCache<moho::RDebugNavPath>(
    out,
    value,
    typeid(moho::RDebugNavPath),
    moho::RDebugNavPath::sType,
    gRDebugNavPathRRefCache
  );
}

/**
 * Address: 0x00651170 (FUN_00651170, gpg::RRef_RDebugNavPath pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugNavPath` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugNavPath(RRef* const out, moho::RDebugNavPath* const value)
{
  RRef tmp{};
  (void)RRef_RDebugNavPath(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006513B0 (FUN_006513B0, gpg::RRef_RDebugNavWaypoints)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugNavWaypoints` using
 * `RDebugNavWaypoints::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugNavWaypoints(RRef* const out, moho::RDebugNavWaypoints* const value)
{
  return BuildTypedRefWithCache<moho::RDebugNavWaypoints>(
    out,
    value,
    typeid(moho::RDebugNavWaypoints),
    moho::RDebugNavWaypoints::sType,
    gRDebugNavWaypointsRRefCache
  );
}

/**
 * Address: 0x006511A0 (FUN_006511A0, gpg::RRef_RDebugNavWaypoints pack lane)
 * Address: 0x005F4A00 (FUN_005F4A00)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugNavWaypoints` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugNavWaypoints(RRef* const out, moho::RDebugNavWaypoints* const value)
{
  RRef tmp{};
  (void)RRef_RDebugNavWaypoints(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00651560 (FUN_00651560, gpg::RRef_RDebugNavSteering)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugNavSteering` using
 * `RDebugNavSteering::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugNavSteering(RRef* const out, moho::RDebugNavSteering* const value)
{
  return BuildTypedRefWithCache<moho::RDebugNavSteering>(
    out,
    value,
    typeid(moho::RDebugNavSteering),
    moho::RDebugNavSteering::sType,
    gRDebugNavSteeringRRefCache
  );
}

/**
 * Address: 0x006511D0 (FUN_006511D0, gpg::RRef_RDebugNavSteering pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugNavSteering` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugNavSteering(RRef* const out, moho::RDebugNavSteering* const value)
{
  RRef tmp{};
  (void)RRef_RDebugNavSteering(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00653C50 (FUN_00653C50, gpg::RRef_RDebugWeapons)
 *
 * What it does:
 * Builds a reflection reference for `moho::RDebugWeapons` using
 * `RDebugWeapons::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_RDebugWeapons(RRef* const out, moho::RDebugWeapons* const value)
{
  return BuildTypedRefWithCache<moho::RDebugWeapons>(
    out,
    value,
    typeid(moho::RDebugWeapons),
    moho::RDebugWeapons::sType,
    gRDebugWeaponsRRefCache
  );
}

/**
 * Address: 0x00653A50 (FUN_00653A50, gpg::RRef_RDebugWeapons pack lane)
 *
 * What it does:
 * Builds one temporary `RRef_RDebugWeapons` and copies its `(mObj,mType)`
 * pair into caller-owned output storage.
 */
gpg::RRef* PackRRef_RDebugWeapons(RRef* const out, moho::RDebugWeapons* const value)
{
  RRef tmp{};
  (void)RRef_RDebugWeapons(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00683420 (FUN_00683420, gpg::RRef_CIntel)
 *
 * What it does:
 * Builds a reflection reference for `moho::CIntel` using
 * `CIntel::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CIntel(RRef* const out, moho::CIntel* const value)
{
  return BuildTypedRefWithCache<moho::CIntel>(
    out,
    value,
    typeid(moho::CIntel),
    moho::CIntel::sType,
    gCIntelRRefCache
  );
}

/**
 * Address: 0x0076EA10 (FUN_0076EA10, sub_76EA10)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CIntel` and copies lanes
 * out.
 */
gpg::RRef* AssignCIntelRef(RRef* const out, moho::CIntel* const value)
{
  RRef tmp{};
  RRef_CIntel(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0076EDD0 (FUN_0076EDD0, gpg::RRef_CIntelPosHandle)
 *
 * What it does:
 * Builds a reflection reference for `moho::CIntelPosHandle` using
 * `CIntelPosHandle::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CIntelPosHandle(RRef* const out, moho::CIntelPosHandle* const value)
{
  return BuildTypedRefWithCache<moho::CIntelPosHandle>(
    out,
    value,
    typeid(moho::CIntelPosHandle),
    moho::CIntelPosHandle::sType,
    gCIntelPosHandleRRefCache
  );
}

/**
 * Address: 0x0076FCE0 (FUN_0076FCE0, sub_76FCE0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CIntelPosHandle` and
 * copies lanes out.
 */
gpg::RRef* AssignCIntelPosHandleRef(RRef* const out, moho::CIntelPosHandle* const value)
{
  RRef tmp{};
  RRef_CIntelPosHandle(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0076FE30 (FUN_0076FE30, gpg::RRef_CIntelCounterHandle)
 *
 * What it does:
 * Builds a reflection reference for `moho::CIntelCounterHandle` using
 * `CIntelCounterHandle::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CIntelCounterHandle(RRef* const out, moho::CIntelCounterHandle* const value)
{
  return BuildTypedRefWithCache<moho::CIntelCounterHandle>(
    out,
    value,
    typeid(moho::CIntelCounterHandle),
    moho::CIntelCounterHandle::sType,
    gCIntelCounterHandleRRefCache
  );
}

/**
 * Address: 0x0076FDC0 (FUN_0076FDC0)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CIntelCounterHandle` and
 * copies `(mObj,mType)` lanes into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* AssignCIntelCounterHandleRef(RRef* const out, moho::CIntelCounterHandle* const value)
{
  RRef tmp{};
  RRef_CIntelCounterHandle(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005D5300 (FUN_005D5300, gpg::RRef_CUnitMotion)
 *
 * What it does:
 * Builds a reflection reference for `moho::CUnitMotion` using
 * `CUnitMotion::sType` cache and derived-type normalization.
 */
gpg::RRef* RRef_CUnitMotion(RRef* const out, moho::CUnitMotion* const value)
{
  return BuildTypedRefWithCache<moho::CUnitMotion>(
    out,
    value,
    typeid(moho::CUnitMotion),
    moho::CUnitMotion::sType,
    gCUnitMotionRRefCache
  );
}

/**
 * Address: 0x006BAC70 (FUN_006BAC70)
 *
 * What it does:
 * Materializes one temporary `RRef_CUnitMotion` and copies `(mObj,mType)` into
 * caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitMotion(RRef* const out, moho::CUnitMotion* const value)
{
  RRef tmp{};
  (void)RRef_CUnitMotion(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0040F590 (FUN_0040F590, sub_40F590)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CRandomStream` and copies lanes out.
 */
gpg::RRef* AssignCRandomStreamRef(RRef* const out, moho::CRandomStream* const value)
{
  RRef tmp{};
  RRef_CRandomStream(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00705120 (FUN_00705120, gpg::RRef_CPlatoon)
 *
 * What it does:
 * Builds a reflection reference for `moho::CPlatoon` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_CPlatoon(RRef* const out, moho::CPlatoon* const value)
{
  return BuildTypedRefWithCache<moho::CPlatoon>(
    out,
    value,
    typeid(moho::CPlatoon),
    gCPlatoonRRefType,
    gCPlatoonRRefCache
  );
}

/**
 * Address: 0x0072AC80 (FUN_0072AC80, sub_72AC80)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CPlatoon` and copies lanes
 * out.
 */
gpg::RRef* AssignCPlatoonRef(RRef* const out, moho::CPlatoon* const value)
{
  RRef tmp{};
  RRef_CPlatoon(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00884A10 (FUN_00884A10, gpg::RRef_SSessionSaveData)
 *
 * What it does:
 * Builds a reflection reference for `moho::SSessionSaveData` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_SSessionSaveData(RRef* const out, moho::SSessionSaveData* const value)
{
  return BuildTypedRefWithCache<moho::SSessionSaveData>(
    out,
    value,
    typeid(moho::SSessionSaveData),
    gSSessionSaveDataRRefType,
    gSSessionSaveDataRRefCache
  );
}

/**
 * Address: 0x0089B150 (FUN_0089B150)
 *
 * What it does:
 * Materializes one temporary `RRef_SSessionSaveData` and copies `{mObj,mType}`
 * lanes into caller-provided output storage.
 */
[[maybe_unused]] gpg::RRef* AssignSSessionSaveDataRef(RRef* const out, moho::SSessionSaveData* const value)
{
  RRef tmp{};
  RRef_SSessionSaveData(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004220D0 (FUN_004220D0, gpg::RRef_CLuaConOutputHandler)
 *
 * What it does:
 * Builds a reflection reference for `moho::CLuaConOutputHandler` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* RRef_CLuaConOutputHandler(RRef* const out, moho::CLuaConOutputHandler* const value)
{
  return BuildTypedRefWithCache<moho::CLuaConOutputHandler>(
    out,
    value,
    typeid(moho::CLuaConOutputHandler),
    gCLuaConOutputHandlerRRefType,
    gCLuaConOutputHandlerRRefCache
  );
}

/**
 * Address: 0x004C16D0 (FUN_004C16D0, gpg::RRef_LuaState)
 * Address: 0x00756160 (FUN_00756160)
 *
 * What it does:
 * Builds a reflection reference for `LuaPlus::LuaState` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* RRef_LuaState(RRef* const out, LuaPlus::LuaState* const value)
{
  return BuildTypedRefWithCache<LuaPlus::LuaState>(
    out,
    value,
    typeid(LuaPlus::LuaState),
    gLuaStateRRefType,
    gLuaStateRRefCache
  );
}

/**
 * Address: 0x0091E550 (FUN_0091E550, gpg::RRef_TString)
 *
 * What it does:
 * Builds a reflection reference for `TString` object pointers.
 */
gpg::RRef* RRef_TString(RRef* const out, TString* const value)
{
  return BuildTypedRefWithCache<TString>(out, value, typeid(TString), gTStringRRefType, gTStringRRefCache);
}

/**
 * Address: 0x0091E730 (FUN_0091E730, gpg::RRef_Table)
 *
 * What it does:
 * Builds a reflection reference for `Table` object pointers.
 */
gpg::RRef* RRef_Table(RRef* const out, Table* const value)
{
  return BuildTypedRefWithCache<Table>(out, value, typeid(Table), gTableRRefType, gTableRRefCache);
}

/**
 * Address: 0x00920500 (FUN_00920500, sub_920500)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_Table` and copies lanes
 * out.
 */
gpg::RRef* AssignTableRef(RRef* const out, Table* const value)
{
  RRef tmp{};
  RRef_Table(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0091E900 (FUN_0091E900, gpg::RRef_LClosure)
 *
 * What it does:
 * Builds a reflection reference for Lua `LClosure` object pointers.
 */
gpg::RRef* RRef_LClosure(RRef* const out, LClosure* const value)
{
  return BuildTypedRefWithCache<LClosure>(out, value, typeid(LClosure), gLClosureRRefType, gLClosureRRefCache);
}

/**
 * Address: 0x0091F170 (FUN_0091F170, gpg::RRef_CClosure)
 *
 * What it does:
 * Builds a reflection reference for Lua `CClosure` object pointers.
 */
gpg::RRef* RRef_CClosure(RRef* const out, CClosure* const value)
{
  return BuildTypedRefWithCache<CClosure>(out, value, typeid(CClosure), gCClosureRRefType, gCClosureRRefCache);
}

/**
 * Address: 0x0091EE10 (FUN_0091EE10, gpg::RRef_Udata)
 *
 * What it does:
 * Builds a reflection reference for Lua `Udata` object pointers.
 */
gpg::RRef* RRef_Udata(RRef* const out, Udata* const value)
{
  return BuildTypedRefWithCache<Udata>(out, value, typeid(Udata), gUdataRRefType, gUdataRRefCache);
}

/**
 * Address: 0x0091EAA0 (FUN_0091EAA0, gpg::RRef_UpVal)
 *
 * What it does:
 * Builds a reflection reference for Lua `UpVal` object pointers.
 */
gpg::RRef* RRef_UpVal(RRef* const out, UpVal* const value)
{
  return BuildTypedRefWithCache<UpVal>(out, value, typeid(UpVal), gUpValRRefType, gUpValRRefCache);
}

/**
 * Address: 0x0091EC40 (FUN_0091EC40, gpg::RRef_Proto)
 *
 * What it does:
 * Builds a reflection reference for Lua `Proto` object pointers.
 */
gpg::RRef* RRef_Proto(RRef* const out, Proto* const value)
{
  return BuildTypedRefWithCache<Proto>(out, value, typeid(Proto), gProtoRRefType, gProtoRRefCache);
}

/**
 * Address: 0x0090B1E0 (FUN_0090B1E0, gpg::RRef_lua_State)
 *
 * What it does:
 * Builds a reflection reference for `lua_State` object pointers.
 */
gpg::RRef* RRef_lua_State(RRef* const out, lua_State* const value)
{
  return BuildTypedRefWithCache<lua_State>(
    out,
    value,
    typeid(lua_State),
    gLuaRawStateRRefType,
    gLuaRawStateRRefCache
  );
}

/**
 * Address: 0x00401280 (FUN_00401280)
 *
 * What it does:
 * Initializes an empty reflection reference `{nullptr, nullptr}`.
 */
RRef::RRef() noexcept
  : mObj(nullptr)
  , mType(nullptr)
{}

/**
 * Address: 0x00401290 (FUN_00401290)
 *
 * What it does:
 * Initializes a reflection reference from explicit object/type lanes.
 */
RRef::RRef(void* const ptr, RType* const type) noexcept
  : mObj(ptr)
  , mType(type)
{}

/**
 * Address: 0x009204A0 (FUN_009204A0)
 *
 * What it does:
 * Initializes one reflection reference from Lua `TString*` by routing through
 * `gpg::RRef_TString`.
 */
RRef::RRef(TString* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_TString(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x009204D0 (FUN_009204D0)
 *
 * What it does:
 * Initializes one reflection reference from a Lua `Table*` by routing through
 * `gpg::RRef_Table`.
 */
RRef::RRef(Table* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_Table(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00920670 (FUN_00920670)
 *
 * What it does:
 * Initializes one reflection reference from Lua `LClosure*` by routing
 * through `gpg::RRef_LClosure`.
 */
RRef::RRef(LClosure* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_LClosure(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x009206A0 (FUN_009206A0)
 *
 * What it does:
 * Initializes one reflection reference from Lua `UpVal*` by routing through
 * `gpg::RRef_UpVal`.
 */
RRef::RRef(UpVal* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_UpVal(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00920750 (FUN_00920750)
 *
 * What it does:
 * Initializes one reflection reference from Lua `Proto*` by routing through
 * `gpg::RRef_Proto`.
 */
RRef::RRef(Proto* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_Proto(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00920780 (FUN_00920780)
 *
 * What it does:
 * Initializes one reflection reference from raw Lua `lua_State*` by routing
 * through `gpg::RRef_lua_State`.
 */
RRef::RRef(lua_State* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_lua_State(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x009207B0 (FUN_009207B0)
 *
 * What it does:
 * Initializes one reflection reference from Lua `Udata*` by routing through
 * `gpg::RRef_Udata`.
 */
RRef::RRef(Udata* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_Udata(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00950640 (FUN_00950640)
 *
 * What it does:
 * Initializes one reflection reference from `gpg::ArchiveToken*` by routing
 * through `gpg::RRef_ArchiveToken`.
 */
RRef::RRef(ArchiveToken* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  const gpg::RRef staged = gpg::RRef_ArchiveToken(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008D6DA0 (FUN_008D6DA0)
 *
 * What it does:
 * Initializes one reflection reference from `moho::RUnitBlueprint*` by
 * routing through `gpg::RRef_RUnitBlueprint`.
 */
RRef::RRef(moho::RUnitBlueprint* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_RUnitBlueprint(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1580 (FUN_008E1580)
 *
 * What it does:
 * Initializes one reflection reference from `char*` by routing through
 * `gpg::RRef_char`.
 */
RRef::RRef(char* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_char(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1650 (FUN_008E1650)
 *
 * What it does:
 * Initializes one reflection reference from `short*` by routing through
 * `gpg::RRef_short`.
 */
RRef::RRef(short* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_short(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E17C0 (FUN_008E17C0)
 *
 * What it does:
 * Initializes one reflection reference from `long*` by routing through
 * `gpg::RRef_long`.
 */
RRef::RRef(long* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_long(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1890 (FUN_008E1890)
 *
 * What it does:
 * Initializes one reflection reference from `signed char*` by routing through
 * `gpg::RRef_schar`.
 */
RRef::RRef(signed char* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_schar(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1A00 (FUN_008E1A00)
 *
 * What it does:
 * Initializes one reflection reference from `unsigned short*` by routing
 * through `gpg::RRef_ushort`.
 */
RRef::RRef(unsigned short* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  (void)gpg::RRef_ushort(&staged, value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x004012B0 (FUN_004012B0)
 *
 * What it does:
 * Returns the raw referenced object pointer lane.
 */
#ifdef GetObject
#undef GetObject
#endif
void* RRef::GetObject() const noexcept
{
  return mObj;
}

/**
 * Address: 0x0094F730 (FUN_0094F730, gpg::RRefCompare::operator())
 *
 * What it does:
 * Orders two reflected references lexicographically by reflected type lane
 * and then by object pointer lane.
 */
bool RRefCompare::operator()(const RRef& lhs, const RRef& rhs) const noexcept
{
  if (lhs.mType != rhs.mType) {
    return lhs.mType < rhs.mType;
  }

  return lhs.mObj < rhs.mObj;
}

/**
 * Address: 0x0084AB10 (FUN_0084AB10, gpg::RRef::CurrentUIState)
 *
 * What it does:
 * Builds one reflected reference bound to global `moho::sUIState`.
 */
RRef* RRef::CurrentUIState(RRef* const out)
{
  return BuildTypedRefWithCache<moho::EUIState>(
    out,
    &moho::sUIState,
    typeid(moho::EUIState),
    gEUIStateRRefType,
    gEUIStateRRefCache
  );
}

/**
 * Address: 0x0084A360 (FUN_0084A360)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef::CurrentUIState` result and
 * copies lanes out.
 */
gpg::RRef* AssignCurrentUIStateRefAdapter(RRef* const out)
{
  RRef tmp{};
  RRef::CurrentUIState(&tmp);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004C1690 (FUN_004C1690, gpg::RRef::CastLuaState)
 *
 * What it does:
 * Upcasts this reflected reference to one `LuaPlus::LuaState` pointer lane.
 */
LuaPlus::LuaState* RRef::CastLuaState()
{
  if (!gLuaStateRRefType) {
    gLuaStateRRefType = gpg::LookupRType(typeid(LuaPlus::LuaState));
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(*this, gLuaStateRRefType);
  return static_cast<LuaPlus::LuaState*>(upcast.mObj);
}

/**
 * Address: 0x00920400 (FUN_00920400, gpg::RRef::TryUpcast_lua_State)
 *
 * What it does:
 * Upcasts this reflected reference to one raw `lua_State*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
lua_State* RRef::TryUpcastLuaThreadState() const
{
  if (!gLuaRawStateRRefType) {
    gLuaRawStateRRefType = gpg::LookupRType(typeid(lua_State));
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(*this, gLuaRawStateRRefType);
  if (!upcast.mObj) {
    const char* const sourceName = mType ? mType->GetName() : "null";
    const char* const targetName = gLuaRawStateRRefType->GetName();
    throw BadRefCast(nullptr, sourceName, targetName);
  }

  return static_cast<lua_State*>(upcast.mObj);
}

/**
 * Address: 0x008E17F0 (FUN_008E17F0, gpg::RRef::TryUpcast_long)
 *
 * What it does:
 * Upcasts this reflected reference to one `long*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
long* RRef::TryUpcastLong() const
{
  static RType* sLongType = nullptr;
  return TryUpcastValueOrThrow<long>(*this, typeid(long), sLongType);
}

/**
 * Address: 0x008E18C0 (FUN_008E18C0, gpg::RRef::TryUpcast_schar)
 *
 * What it does:
 * Upcasts this reflected reference to one `signed char*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
signed char* RRef::TryUpcastSignedChar() const
{
  static RType* sSignedCharType = nullptr;
  return TryUpcastValueOrThrow<signed char>(*this, typeid(signed char), sSignedCharType);
}

/**
 * Address: 0x008E1960 (FUN_008E1960, gpg::RRef::TryUpcast_uchar)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned char*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned char* RRef::TryUpcastUnsignedChar() const
{
  static RType* sUnsignedCharType = nullptr;
  return TryUpcastValueOrThrow<unsigned char>(*this, typeid(unsigned char), sUnsignedCharType);
}

/**
 * Address: 0x008E1A30 (FUN_008E1A30, gpg::RRef::TryUpcast_ushort)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned short*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned short* RRef::TryUpcastUnsignedShort() const
{
  static RType* sUnsignedShortType = nullptr;
  return TryUpcastValueOrThrow<unsigned short>(*this, typeid(unsigned short), sUnsignedShortType);
}

/**
 * Address: 0x008E1AD0 (FUN_008E1AD0, gpg::RRef::TryUpcast_uint)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned int*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned int* RRef::TryUpcastUnsignedInt() const
{
  static RType* sUnsignedIntType = nullptr;
  return TryUpcastValueOrThrow<unsigned int>(*this, typeid(unsigned int), sUnsignedIntType);
}

/**
 * Address: 0x008E1BA0 (FUN_008E1BA0, gpg::RRef::TryUpcast_ulong)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned long*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned long* RRef::TryUpcastUnsignedLong() const
{
  static RType* sUnsignedLongType = nullptr;
  return TryUpcastValueOrThrow<unsigned long>(*this, typeid(unsigned long), sUnsignedLongType);
}

/**
 * Address: 0x00557A90 (FUN_00557A90, gpg::RRef::TryUpcast_RBlueprint_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `RBlueprint*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::RBlueprint** RRef::TryUpcastRBlueprintPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::RBlueprint>(*this);
}

/**
 * Address: 0x0059DE10 (FUN_0059DE10, gpg::RRef::TryUpcast_IFormationInstance_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `IFormationInstance*` pointer-slot
 * lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::IFormationInstance** RRef::TryUpcastIFormationInstancePointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::IFormationInstance>(*this);
}

/**
 * Address: 0x005A1E90 (FUN_005A1E90, gpg::RRef::TryUpcast_RUnitBlueprint_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `RUnitBlueprint*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::RUnitBlueprint** RRef::TryUpcastRUnitBlueprintPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::RUnitBlueprint>(*this);
}

/**
 * Address: 0x005CA2E0 (FUN_005CA2E0, gpg::RRef::TryUpcast_ReconBlip_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `ReconBlip*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::ReconBlip** RRef::TryUpcastReconBlipPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::ReconBlip>(*this);
}

/**
 * Address: 0x005DF630 (FUN_005DF630, gpg::RRef::TryUpcast_UnitWeapon_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `UnitWeapon*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::UnitWeapon** RRef::TryUpcastUnitWeaponPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::UnitWeapon>(*this);
}

/**
 * Address: 0x005DF6B0 (FUN_005DF6B0, gpg::RRef::TryUpcast_CAcquireTargetTask_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CAcquireTargetTask*` pointer-slot
 * lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CAcquireTargetTask** RRef::TryUpcastCAcquireTargetTaskPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CAcquireTargetTask>(*this);
}

/**
 * Address: 0x0063E6E0 (FUN_0063E6E0, gpg::RRef::TryUpcast_IAniManipulator_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `IAniManipulator*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::IAniManipulator** RRef::TryUpcastIAniManipulatorPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::IAniManipulator>(*this);
}

/**
 * Address: 0x0066D110 (FUN_0066D110, gpg::RRef::TryUpcast_IEffect_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `IEffect*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::IEffect** RRef::TryUpcastIEffectPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::IEffect>(*this);
}

/**
 * Address: 0x0067FD80 (FUN_0067FD80, gpg::RRef::TryUpcast_Entity_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `Entity*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::Entity** RRef::TryUpcastEntityPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::Entity>(*this);
}

/**
 * Address: 0x006B3D00 (FUN_006B3D00, gpg::RRef::TryUpcast_CEconomyEvent_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CEconomyEvent*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CEconomyEvent** RRef::TryUpcastCEconomyEventPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CEconomyEvent>(*this);
}

/**
 * Address: 0x006EC5E0 (FUN_006EC5E0, gpg::RRef::TryUpcast_Listener_ECommandEvent)
 *
 * What it does:
 * Upcasts this reflected reference to one `Listener<ECommandEvent>` object
 * lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::Listener<moho::ECommandEvent>* RRef::TryUpcastListenerECommandEvent() const
{
  static RType* sListenerCommandEventType = nullptr;
  return TryUpcastValueOrThrow<moho::Listener<moho::ECommandEvent>>(
    *this,
    typeid(moho::Listener<moho::ECommandEvent>),
    sListenerCommandEventType
  );
}

/**
 * Address: 0x006F93D0 (FUN_006F93D0, gpg::RRef::TryUpcast_Listener_EUnitCommandQueueStatus)
 *
 * What it does:
 * Upcasts this reflected reference to one `Listener<EUnitCommandQueueStatus>`
 * object lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::Listener<moho::EUnitCommandQueueStatus>* RRef::TryUpcastListenerEUnitCommandQueueStatus() const
{
  static RType* sListenerQueueStatusType = nullptr;
  return TryUpcastValueOrThrow<moho::Listener<moho::EUnitCommandQueueStatus>>(
    *this,
    typeid(moho::Listener<moho::EUnitCommandQueueStatus>),
    sListenerQueueStatusType
  );
}

/**
 * Address: 0x006FD290 (FUN_006FD290, gpg::RRef::TryUpcast_Prop)
 *
 * What it does:
 * Upcasts this reflected reference to one `Prop` object lane and throws
 * `BadRefCast` with source/target names on mismatch.
 */
moho::Prop* RRef::TryUpcastProp() const
{
  static RType* sPropType = nullptr;
  return TryUpcastValueOrThrow<moho::Prop>(*this, typeid(moho::Prop), sPropType);
}

/**
 * Address: 0x006E3E10 (FUN_006E3E10, gpg::RRef::TryUpcast_CUnitCommand_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CUnitCommand*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CUnitCommand** RRef::TryUpcastCUnitCommandPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CUnitCommand>(*this);
}

/**
 * Address: 0x00712B20 (FUN_00712B20, gpg::RRef::TryUpcast_CArmyStatItem_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CArmyStatItem*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CArmyStatItem** RRef::TryUpcastCArmyStatItemPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CArmyStatItem>(*this);
}

/**
 * Address: 0x00751F10 (FUN_00751F10, gpg::RRef::TryUpcast_SimArmy_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `SimArmy*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::SimArmy** RRef::TryUpcastSimArmyPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::SimArmy>(*this);
}

/**
 * Address: 0x00751FC0 (FUN_00751FC0, gpg::RRef::TryUpcast_Shield_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `Shield*` pointer-slot lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::Shield** RRef::TryUpcastShieldPointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::Shield>(*this);
}

/**
 * Address: 0x0077F430 (FUN_0077F430, gpg::RRef::TryUpcast_CDecalHandle_P)
 *
 * What it does:
 * Upcasts this reflected reference to one `CDecalHandle*` pointer-slot lane
 * and throws `BadRefCast` with source/target names on mismatch.
 */
moho::CDecalHandle** RRef::TryUpcastCDecalHandlePointerSlot() const
{
  return TryUpcastPointerSlotWithTypeNameOrThrow<moho::CDecalHandle>(*this);
}

/**
 * Address: 0x004A35D0 (FUN_004A35D0)
 *
 * What it does:
 * Reads this reference as lexical text using the bound reflection type.
 */
msvc8::string RRef::GetLexical() const
{
  return mType->GetLexical(*this);
}

/**
 * Address: 0x004A3600 (FUN_004A3600)
 *
 * What it does:
 * Writes one lexical text value through the bound reflection type.
 */
bool RRef::SetLexical(const char* name) const
{
  return mType->SetLexical(*this, name);
}

/**
 * Address: 0x00406690 (FUN_00406690)
 *
 * What it does:
 * Returns reflected type name for this reference, or `"null"` when untyped.
 */
const char* RRef::GetName() const
{
  if (!mType) {
    return "null";
  }

  return mType->GetName();
}

/**
 * Address: 0x004A3610 (FUN_004A3610)
 *
 * What it does:
 * Returns the indexed child reference at `ind`.
 */
RRef RRef::operator[](const unsigned int ind) const
{
  const RIndexed* indexed = mType->IsIndexed();
  return indexed->SubscriptIndex(mObj, static_cast<int>(ind));
}

/**
 * Address: 0x004A3630 (FUN_004A3630)
 *
 * What it does:
 * Returns indexed element count for this reference, or zero when unindexed.
 */
size_t RRef::GetCount() const
{
  const RIndexed* indexed = mType->IsIndexed();
  if (!indexed) {
    return 0;
  }

  return indexed->GetCount(mObj);
}

/**
 * Address: 0x004A3650 (FUN_004A3650)
 *
 * What it does:
 * Returns the bound runtime reflection type descriptor.
 */
const RType* RRef::GetRType() const
{
  return mType;
}

/**
 * Address: 0x004A3660 (FUN_004A3660)
 *
 * What it does:
 * Returns indexed-view support for the bound type.
 */
const RIndexed* RRef::IsIndexed() const
{
  return mType->IsIndexed();
}

/**
 * Address: 0x004CC9E0 (FUN_004CC9E0, gpg::RRef::IsPointer)
 *
 * What it does:
 * Returns pointer-view support for the bound type.
 */
const RIndexed* RRef::IsPointer() const
{
  return mType->IsPointer();
}

int RRef::GetNumBases() const
{
  const RField* first = mType->bases_.begin();
  if (!first) {
    return 0;
  }

  return static_cast<int>(mType->bases_.end() - first);
}

RRef RRef::GetBase(const int ind) const
{
  const RField* first = mType->bases_.begin();
  const RField& base = first[ind];

  RRef out{};
  out.mObj = static_cast<char*>(mObj) + base.mOffset;
  out.mType = base.mType;
  return out;
}

/**
 * Address: 0x004CC9B0 (FUN_004CC9B0, gpg::RRef::GetNumFields)
 *
 * What it does:
 * Returns reflected field count for the bound type.
 */
int RRef::GetNumFields() const
{
  const RField* first = mType->fields_.begin();
  if (!first) {
    return 0;
  }

  return static_cast<int>(mType->fields_.end() - first);
}

RRef RRef::GetField(const int ind) const
{
  const RField* first = mType->fields_.begin();
  const RField& field = first[ind];

  RRef out{};
  out.mObj = static_cast<char*>(mObj) + field.mOffset;
  out.mType = field.mType;
  return out;
}

const char* RRef::GetFieldName(const int ind) const
{
  return mType->fields_.begin()[ind].mName;
}

void RRef::Delete()
{
  if (!mObj) {
    return;
  }

  GPG_ASSERT(mType->deleteFunc_);
  mType->deleteFunc_(mObj);
}

/**
 * Address: 0x004012C0 (FUN_004012C0)
 * Demangled: gpg::RObject::RObject
 *
 * What it does:
 * Initializes the base vftable lane for reflected objects.
 */
RObject::RObject() noexcept = default;

/**
 * Address: 0x008DD460 (FUN_008DD460, ?IsA@RObject@gpg@@QBE_NPAVRType@2@@Z_0)
 *
 * What it does:
 * Returns whether this object's dynamic reflected type is derived from one
 * requested target type lane.
 */
bool RObject::IsA(RType* const type) const
{
  return GetClass()->IsDerivedFrom(type, nullptr);
}

/**
 * Address: 0x004012D0 (FUN_004012D0)
 * Demangled: gpg::RObject::dtr
 *
 * What it does:
 * Owns deleting-dtor lane for RObject base and conditionally frees `this`.
 */
RObject::~RObject() noexcept = default;

/**
 * Address: 0x004012F0 (FUN_004012F0)
 * Demangled: gpg::RIndexed::SetCount
 *
 * What it does:
 * Base implementation rejects resize/count mutation for non-resizable indexed types.
 */
void RIndexed::SetCount(void*, int) const
{
  throw std::bad_cast{};
}

/**
 * Address: 0x00401320 (FUN_00401320)
 * Demangled: gpg::RIndexed::AssignPointer
 *
 * What it does:
 * Base implementation rejects pointer assignment for non-pointer indexed types.
 */
void RIndexed::AssignPointer(void*, const RRef&) const
{
    throw std::bad_cast{};
}

/**
 * Address: 0x0040CB00 (FUN_0040CB00, gpg::RPointerType_CTaskThread::SubscriptIndex)
 * Address: 0x004214F0 (FUN_004214F0, gpg::RPointerType_CLuaConOutputHandler::SubscriptIndex)
 */
RRef gpg::RPointerTypeBase::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<void**>(obj);
    RType* const pointeeType = GetPointeeType();

    RRef out{};
    out.mType = pointeeType;
    if (!slot || !pointeeType || !*slot) {
        out.mObj = nullptr;
        return out;
    }

    const std::ptrdiff_t byteOffset =
      static_cast<std::ptrdiff_t>(pointeeType->size_) * static_cast<std::ptrdiff_t>(ind);
    auto* const base = static_cast<std::uint8_t*>(*slot);
    out.mObj = static_cast<void*>(base + byteOffset);

    if (pointeeType->ctorRefFunc_) {
        return pointeeType->ctorRefFunc_(out.mObj);
    }

    return out;
}

/**
 * Address: 0x0040CAF0 (FUN_0040CAF0, gpg::RPointerType_CTaskThread::GetCount)
 * Address: 0x004214E0 (FUN_004214E0, gpg::RPointerType_CLuaConOutputHandler::GetCount)
 */
size_t gpg::RPointerTypeBase::GetCount(void* const obj) const
{
    auto* const slot = static_cast<void**>(obj);
    return (slot && *slot) ? 1u : 0u;
}

void gpg::RPointerTypeBase::SetCount(void* const obj, const int count) const
{
    auto* const slot = static_cast<void**>(obj);
    if (!slot) {
        throw std::bad_cast{};
    }

    if (count == 0) {
        *slot = nullptr;
        return;
    }
    if (count == 1) {
        return;
    }

    throw std::bad_cast{};
}

/**
 * Address: 0x0040CB40 (FUN_0040CB40, gpg::RPointerType_CTaskThread::AssignPointer)
 * Address: 0x00421530 (FUN_00421530, gpg::RPointerType_CLuaConOutputHandler::AssignPointer)
 */
void gpg::RPointerTypeBase::AssignPointer(void* const obj, const RRef& from) const
{
    auto* const slot = static_cast<void**>(obj);
    GPG_ASSERT(slot != nullptr);
    if (!slot) {
        return;
    }

    if (!from.mObj) {
        *slot = nullptr;
        return;
    }

    const RRef upcast = REF_UpcastPtr(from, GetPointeeType());
    if (!upcast.mObj) {
        throw BadRefCast("type error");
    }

    *slot = upcast.mObj;
}

const RIndexed* gpg::RPointerTypeBase::AsIndexedSelf() const noexcept
{
    return this;
}

/**
 * Address: 0x0040C8B0 (FUN_0040C8B0)
 * Demangled: sub_40C8B0
 */
gpg::RPointerType<moho::CTaskThread>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::CTaskThread*), this);
}

/**
 * Address: 0x0040CBD0 (FUN_0040CBD0)
 * Demangled: sub_40CBD0
 */
gpg::RPointerType<moho::CTaskThread>::~RPointerType() = default;

/**
 * Address: 0x0040C7C0 (FUN_0040C7C0)
 * Demangled: gpg::RPointerType_CTaskThread::GetName
 */
const char* gpg::RPointerType<moho::CTaskThread>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0040C950 (FUN_0040C950)
 * Demangled: gpg::RPointerType_CTaskThread::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CTaskThread>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CTaskThread>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0040CAD0 (FUN_0040CAD0)
 * Demangled: gpg::RPointerType_CTaskThread::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040CAE0 (FUN_0040CAE0)
 * Demangled: gpg::RPointerType_CTaskThread::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040C920 (FUN_0040C920)
 * Demangled: gpg::RPointerType_CTaskThread::Init
 */
void gpg::RPointerType<moho::CTaskThread>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CTaskThread*);
    BindCTaskThreadPointerNewAndConstruct(this);
    BindCTaskThreadPointerCopyAndMove(this);
    deleteFunc_ = &DeletePointerSlot<moho::CTaskThread>;
}

RType* gpg::RPointerType<moho::CTaskThread>::GetPointeeType() const
{
    return CachedCTaskThreadType();
}

/**
 * Address: 0x005DE390 (FUN_005DE390)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::dtr
 */
gpg::RPointerType<moho::CAcquireTargetTask>::~RPointerType() = default;

/**
 * Address: 0x005DDF20 (FUN_005DDF20)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::GetName
 */
const char* gpg::RPointerType<moho::CAcquireTargetTask>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x005DE0B0 (FUN_005DE0B0)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CAcquireTargetTask>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CAcquireTargetTask>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005DE230 (FUN_005DE230)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CAcquireTargetTask>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DE240 (FUN_005DE240)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CAcquireTargetTask>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DE2A0 (FUN_005DE2A0)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CAcquireTargetTask*` and stores it
 * in the destination pointer slot.
 */
void gpg::RPointerType<moho::CAcquireTargetTask>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CAcquireTargetTask>(obj, from, moho::CAcquireTargetTask::sType);
}

/**
 * Address: 0x005DE080 (FUN_005DE080)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::Init
 */
void gpg::RPointerType<moho::CAcquireTargetTask>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CAcquireTargetTask*);
    newRefFunc_ = &NewPointerSlotRef<moho::CAcquireTargetTask>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CAcquireTargetTask>;
    deleteFunc_ = &DeletePointerSlot<moho::CAcquireTargetTask>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CAcquireTargetTask>;
    movRefFunc_ = &MovePointerSlotRef<moho::CAcquireTargetTask>;
}

RType* gpg::RPointerType<moho::CAcquireTargetTask>::GetPointeeType() const
{
    return CachedCAcquireTargetTaskType();
}

/**
 * Address: 0x00556F00 (FUN_00556F00)
 * Demangled: gpg::RPointerType_RBlueprint::GetName
 */
const char* gpg::RPointerType<moho::RBlueprint>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x00557090 (FUN_00557090)
 * Demangled: gpg::RPointerType_RBlueprint::GetLexical
 */
msvc8::string gpg::RPointerType<moho::RBlueprint>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::RBlueprint>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x00557210 (FUN_00557210)
 * Demangled: gpg::RPointerType_RBlueprint::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::RBlueprint>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00557220 (FUN_00557220)
 * Demangled: gpg::RPointerType_RBlueprint::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::RBlueprint>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00557280 (FUN_00557280)
 * Demangled: gpg::RPointerType_RBlueprint::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `RBlueprint*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::RBlueprint>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::RBlueprint>(obj, from, sAssignPointeeType);
}

/**
 * Address: 0x00557060 (FUN_00557060)
 * Demangled: gpg::RPointerType_RBlueprint::Init
 */
void gpg::RPointerType<moho::RBlueprint>::Init()
{
    v24 = true;
    size_ = sizeof(moho::RBlueprint*);
    newRefFunc_ = &NewPointerSlotRef<moho::RBlueprint>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::RBlueprint>;
    deleteFunc_ = &DeletePointerSlot<moho::RBlueprint>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::RBlueprint>;
    movRefFunc_ = &MovePointerSlotRef<moho::RBlueprint>;
}

RType* gpg::RPointerType<moho::RBlueprint>::GetPointeeType() const
{
    return CachedRBlueprintType();
}

/**
 * Address: 0x005DDB10 (FUN_005DDB10)
 * Demangled: gpg::RPointerType_UnitWeapon::GetName
 */
const char* gpg::RPointerType<moho::UnitWeapon>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x005DDCA0 (FUN_005DDCA0)
 * Demangled: gpg::RPointerType_UnitWeapon::GetLexical
 */
msvc8::string gpg::RPointerType<moho::UnitWeapon>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::UnitWeapon>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005DDE20 (FUN_005DDE20)
 * Demangled: gpg::RPointerType_UnitWeapon::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::UnitWeapon>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DDE30 (FUN_005DDE30)
 * Demangled: gpg::RPointerType_UnitWeapon::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::UnitWeapon>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DDE90 (FUN_005DDE90)
 * Demangled: gpg::RPointerType_UnitWeapon::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `UnitWeapon*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::UnitWeapon>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::UnitWeapon>(obj, from, moho::UnitWeapon::sType);
}

/**
 * Address: 0x005DDC70 (FUN_005DDC70)
 * Demangled: gpg::RPointerType_UnitWeapon::Init
 */
void gpg::RPointerType<moho::UnitWeapon>::Init()
{
    v24 = true;
    size_ = sizeof(moho::UnitWeapon*);
    newRefFunc_ = &NewPointerSlotRef<moho::UnitWeapon>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::UnitWeapon>;
    deleteFunc_ = &DeletePointerSlot<moho::UnitWeapon>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::UnitWeapon>;
    movRefFunc_ = &MovePointerSlotRef<moho::UnitWeapon>;
}

RType* gpg::RPointerType<moho::UnitWeapon>::GetPointeeType() const
{
    return CachedUnitWeaponType();
}

/**
 * Address: 0x0063DB40 (FUN_0063DB40)
 * Demangled: gpg::RPointerType_IAniManipulator::GetName
 */
const char* gpg::RPointerType<moho::IAniManipulator>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0063DCD0 (FUN_0063DCD0)
 * Demangled: gpg::RPointerType_IAniManipulator::GetLexical
 */
msvc8::string gpg::RPointerType<moho::IAniManipulator>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::IAniManipulator>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0063DE50 (FUN_0063DE50)
 * Demangled: gpg::RPointerType_IAniManipulator::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::IAniManipulator>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0063DE60 (FUN_0063DE60)
 * Demangled: gpg::RPointerType_IAniManipulator::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::IAniManipulator>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0063DEC0 (FUN_0063DEC0)
 * Demangled: gpg::RPointerType_IAniManipulator::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `IAniManipulator*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::IAniManipulator>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::IAniManipulator>(obj, from, moho::IAniManipulator::sType);
}

/**
 * Address: 0x0063DCA0 (FUN_0063DCA0)
 * Demangled: gpg::RPointerType_IAniManipulator::Init
 */
void gpg::RPointerType<moho::IAniManipulator>::Init()
{
    v24 = true;
    size_ = sizeof(moho::IAniManipulator*);
    newRefFunc_ = &NewPointerSlotRef<moho::IAniManipulator>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::IAniManipulator>;
    deleteFunc_ = &DeletePointerSlot<moho::IAniManipulator>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::IAniManipulator>;
    movRefFunc_ = &MovePointerSlotRef<moho::IAniManipulator>;
}

RType* gpg::RPointerType<moho::IAniManipulator>::GetPointeeType() const
{
    return CachedIAniManipulatorType();
}

/**
 * Address: 0x0066CA40 (FUN_0066CA40)
 * Demangled: gpg::RPointerType_IEffect::GetName
 */
const char* gpg::RPointerType<moho::IEffect>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0066CBD0 (FUN_0066CBD0)
 * Demangled: gpg::RPointerType_IEffect::GetLexical
 */
msvc8::string gpg::RPointerType<moho::IEffect>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::IEffect>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0066CD50 (FUN_0066CD50)
 * Demangled: gpg::RPointerType_IEffect::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::IEffect>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0066CD60 (FUN_0066CD60)
 * Demangled: gpg::RPointerType_IEffect::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::IEffect>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0066CDC0 (FUN_0066CDC0)
 * Demangled: gpg::RPointerType_IEffect::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `IEffect*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::IEffect>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::IEffect>(obj, from, moho::IEffect::sType);
}

/**
 * Address: 0x0066CBA0 (FUN_0066CBA0)
 * Demangled: gpg::RPointerType_IEffect::Init
 */
void gpg::RPointerType<moho::IEffect>::Init()
{
    v24 = true;
    size_ = sizeof(moho::IEffect*);
    newRefFunc_ = &NewPointerSlotRef<moho::IEffect>;
    cpyRefFunc_ = &CopyIEffectPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::IEffect>;
    ctorRefFunc_ = &ConstructIEffectPointerSlotRef;
    movRefFunc_ = &MoveIEffectPointerSlotRef;
}

RType* gpg::RPointerType<moho::IEffect>::GetPointeeType() const
{
    return CachedIEffectType();
}

msvc8::string gpg::RPointerType<moho::CUnitCommand>::sName{};
std::uint32_t gpg::RPointerType<moho::CUnitCommand>::sNameInitGuard = 0u;

/**
 * Address: 0x006E3670 (FUN_006E3670, RPointerType_CUnitCommand non-deleting cleanup body)
 *
 * What it does:
 * Clears reflected base/field vector lanes for one `RPointerType<CUnitCommand>`
 * instance while preserving outer storage ownership.
 */
[[maybe_unused]] void DestroyCUnitCommandPointerTypeBody(gpg::RPointerType<moho::CUnitCommand>* const typeInfo) noexcept
{
    if (typeInfo == nullptr) {
        return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
}

/**
 * Address: 0x006E36B0 (FUN_006E36B0)
 * Demangled: gpg::RPointerType_CUnitCommand::GetName
 */
const char* gpg::RPointerType<moho::CUnitCommand>::GetName() const
{
    if ((sNameInitGuard & 1u) == 0u) {
        sNameInitGuard |= 1u;

        RType* pointeeType = moho::CUnitCommand::sType;
        if (!pointeeType) {
            pointeeType = gpg::LookupRType(typeid(moho::CUnitCommand));
            moho::CUnitCommand::sType = pointeeType;
        }

        const char* pointeeName = pointeeType ? pointeeType->GetName() : nullptr;
        sName = msvc8::string((pointeeName != nullptr) ? pointeeName : "");
        sName += "*";
    }
    return sName.c_str();
}

/**
 * Address: 0x006E3840 (FUN_006E3840)
 * Demangled: gpg::RPointerType_CUnitCommand::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CUnitCommand>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CUnitCommand>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x006E39C0 (FUN_006E39C0)
 * Demangled: gpg::RPointerType_CUnitCommand::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CUnitCommand>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006E39D0 (FUN_006E39D0)
 * Demangled: gpg::RPointerType_CUnitCommand::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CUnitCommand>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006E3A30 (FUN_006E3A30)
 * Demangled: gpg::RPointerType_CUnitCommand::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CUnitCommand*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CUnitCommand>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::CUnitCommand>(obj, from, sAssignPointeeType);
}

/**
 * Address: 0x006E3810 (FUN_006E3810)
 * Demangled: gpg::RPointerType_CUnitCommand::Init
 */
void gpg::RPointerType<moho::CUnitCommand>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CUnitCommand*);
    newRefFunc_ = &NewPointerSlotRef<moho::CUnitCommand>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CUnitCommand>;
    deleteFunc_ = &DeletePointerSlot<moho::CUnitCommand>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CUnitCommand>;
    movRefFunc_ = &MovePointerSlotRef<moho::CUnitCommand>;
}

RType* gpg::RPointerType<moho::CUnitCommand>::GetPointeeType() const
{
    return CachedCUnitCommandType();
}

/**
 * Address: 0x0067E750 (FUN_0067E750)
 * Demangled: gpg::RPointerType_Entity::dtr
 */
gpg::RPointerType<moho::Entity>::~RPointerType() = default;

/**
 * Address: 0x0067E320 (FUN_0067E320)
 * Demangled: gpg::RPointerType_Entity::GetName
 */
const char* gpg::RPointerType<moho::Entity>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0067E4B0 (FUN_0067E4B0)
 * Demangled: gpg::RPointerType_Entity::GetLexical
 */
msvc8::string gpg::RPointerType<moho::Entity>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::Entity>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0067E630 (FUN_0067E630)
 * Demangled: gpg::RPointerType_Entity::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::Entity>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0067E640 (FUN_0067E640)
 * Demangled: gpg::RPointerType_Entity::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::Entity>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0067E6A0 (FUN_0067E6A0)
 * Demangled: gpg::RPointerType_Entity::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `Entity*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::Entity>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::Entity>(obj, from, sAssignPointeeType);
}

/**
 * Address: 0x0067E480 (FUN_0067E480)
 * Demangled: gpg::RPointerType_Entity::Init
 */
void gpg::RPointerType<moho::Entity>::Init()
{
    v24 = true;
    size_ = sizeof(moho::Entity*);
    newRefFunc_ = &NewPointerSlotRef<moho::Entity>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::Entity>;
    deleteFunc_ = &DeletePointerSlot<moho::Entity>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::Entity>;
    movRefFunc_ = &MovePointerSlotRef<moho::Entity>;
}

RType* gpg::RPointerType<moho::Entity>::GetPointeeType() const
{
    return CachedEntityType();
}

/**
 * Address: 0x006B2920 (FUN_006B2920)
 * Demangled: gpg::RPointerType_CEconomyEvent::dtr
 */
gpg::RPointerType<moho::CEconomyEvent>::~RPointerType() = default;

/**
 * Address: 0x006B2510 (FUN_006B2510)
 * Demangled: gpg::RPointerType_CEconomyEvent::GetName
 */
const char* gpg::RPointerType<moho::CEconomyEvent>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x006B26A0 (FUN_006B26A0)
 * Demangled: gpg::RPointerType_CEconomyEvent::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CEconomyEvent>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CEconomyEvent>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x006B2820 (FUN_006B2820)
 * Demangled: gpg::RPointerType_CEconomyEvent::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CEconomyEvent>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006B2830 (FUN_006B2830)
 * Demangled: gpg::RPointerType_CEconomyEvent::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CEconomyEvent>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006B2890 (FUN_006B2890)
 * Demangled: gpg::RPointerType_CEconomyEvent::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CEconomyEvent*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CEconomyEvent>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CEconomyEvent>(obj, from, moho::CEconomyEvent::sType);
}

/**
 * Address: 0x006B2670 (FUN_006B2670)
 * Demangled: gpg::RPointerType_CEconomyEvent::Init
 */
void gpg::RPointerType<moho::CEconomyEvent>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CEconomyEvent*);
    newRefFunc_ = &NewPointerSlotRef<moho::CEconomyEvent>;
    cpyRefFunc_ = &CopyCEconomyEventPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::CEconomyEvent>;
    ctorRefFunc_ = &ConstructCEconomyEventPointerSlotRef;
    movRefFunc_ = &MoveCEconomyEventPointerSlotRef;
}

RType* gpg::RPointerType<moho::CEconomyEvent>::GetPointeeType() const
{
    return CachedCEconomyEventType();
}

/**
 * Address: 0x004212A0 (FUN_004212A0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::RPointerType
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), this);
}

/**
 * Address: 0x004215C0 (FUN_004215C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::dtr
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::~RPointerType() = default;

/**
 * Address: 0x004211B0 (FUN_004211B0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetName
 */
const char* gpg::RPointerType<moho::CLuaConOutputHandler>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x00421340 (FUN_00421340)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CLuaConOutputHandler>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CLuaConOutputHandler>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004214C0 (FUN_004214C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004214D0 (FUN_004214D0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00421310 (FUN_00421310)
  * Alias of FUN_00421620 (non-canonical helper lane).
  * Alias of FUN_00421660 (non-canonical helper lane).
  * Alias of FUN_00421670 (non-canonical helper lane).
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::Init
 */
void gpg::RPointerType<moho::CLuaConOutputHandler>::Init()
{
    BindCLuaConOutputHandlerPointerAll(this);
}

RType* gpg::RPointerType<moho::CLuaConOutputHandler>::GetPointeeType() const
{
    return CachedCLuaConOutputHandlerType();
}

/**
 * Address: 0x004C8A00 (FUN_004C8A00)
 * Demangled: gpg::RPointerType_CScriptObject::dtr
 */
gpg::RPointerType<moho::CScriptObject>::~RPointerType() = default;

/**
 * Address: 0x004C85F0 (FUN_004C85F0)
 * Demangled: gpg::RPointerType_CScriptObject::GetName
 */
const char* gpg::RPointerType<moho::CScriptObject>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x004C8780 (FUN_004C8780)
 * Demangled: gpg::RPointerType_CScriptObject::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CScriptObject>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CScriptObject>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004C8900 (FUN_004C8900)
 * Demangled: gpg::RPointerType_CScriptObject::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CScriptObject>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004C8910 (FUN_004C8910)
 * Demangled: gpg::RPointerType_CScriptObject::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CScriptObject>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004C8930 (FUN_004C8930)
 * Demangled: gpg::RPointerType_CScriptObject::SubscriptIndex
 */
RRef gpg::RPointerType<moho::CScriptObject>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::CScriptObject**>(obj);
    return moho::SCR_MakeScriptObjectRef((*slot) + ind);
}

/**
 * Address: 0x004C8920 (FUN_004C8920)
 * Demangled: gpg::RPointerType_CScriptObject::GetCount
 */
size_t gpg::RPointerType<moho::CScriptObject>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::CScriptObject* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x004C8970 (FUN_004C8970)
 * Demangled: gpg::RPointerType_CScriptObject::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `CScriptObject*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CScriptObject>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CScriptObject>(obj, from, moho::CScriptObject::sType);
}

/**
 * Address: 0x004C8750 (FUN_004C8750)
 * Demangled: gpg::RPointerType_CScriptObject::Init
 */
void gpg::RPointerType<moho::CScriptObject>::Init()
{
    BindCScriptObjectPointerAll(this);
}

RType* gpg::RPointerType<moho::CScriptObject>::GetPointeeType() const
{
    return CachedCScriptObjectType();
}

/**
 * Address: 0x004E5FD0 (FUN_004E5FD0)
 * Demangled: sub_4E5FD0
 */
gpg::RPointerType<moho::CSndParams>::~RPointerType() = default;

/**
 * Address: 0x004E5BC0 (FUN_004E5BC0)
 * Demangled: gpg::RPointerType_CSndParams::GetName
 */
const char* gpg::RPointerType<moho::CSndParams>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x004E5D50 (FUN_004E5D50)
 * Demangled: gpg::RPointerType_CSndParams::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CSndParams>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CSndParams>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004E5ED0 (FUN_004E5ED0)
 * Demangled: gpg::RPointerType_CSndParams::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CSndParams>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004E5EE0 (FUN_004E5EE0)
 * Demangled: gpg::RPointerType_CSndParams::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CSndParams>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004E5F00 (FUN_004E5F00)
 * Demangled: gpg::RPointerType_CSndParams::SubscriptIndex
 */
RRef gpg::RPointerType<moho::CSndParams>::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<moho::CSndParams**>(obj);
    RRef out{};
    gpg::RRef_CSndParams(&out, (*slot) + ind);
    return out;
}

/**
 * Address: 0x004E5EF0 (FUN_004E5EF0)
 * Demangled: gpg::RPointerType_CSndParams::GetCount
 */
size_t gpg::RPointerType<moho::CSndParams>::GetCount(void* const obj) const
{
    auto* const slot = static_cast<moho::CSndParams* const*>(obj);
    return (*slot != nullptr) ? 1u : 0u;
}

/**
 * Address: 0x004E5F40 (FUN_004E5F40)
 * Demangled: gpg::RPointerType_CSndParams::AssignPointer
 */
void gpg::RPointerType<moho::CSndParams>::AssignPointer(void* const obj, const RRef& from) const
{
    auto* const slot = static_cast<moho::CSndParams**>(obj);
    if (!slot) {
        gpg::HandleAssertFailure("void_pptr", 663, kReflectionHeaderPath);
    }

    RType* pointeeType = moho::CSndParams::sType2;
    if (!pointeeType) {
        pointeeType = gpg::LookupRType(typeid(moho::CSndParams));
        moho::CSndParams::sType2 = pointeeType;
    }

    const RRef upcast = gpg::REF_UpcastPtr(from, pointeeType);
    if (from.mObj && !upcast.mObj) {
        throw BadRefCast("type error");
    }

    *slot = static_cast<moho::CSndParams*>(upcast.mObj);
}

/**
 * Address: 0x004E5D20 (FUN_004E5D20)
 * Demangled: gpg::RPointerType_CSndParams::Init
 */
void gpg::RPointerType<moho::CSndParams>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CSndParams*);
    newRefFunc_ = &NewCSndParamsPointerSlotRef;
    cpyRefFunc_ = &CopyCSndParamsPointerSlotRef;
    deleteFunc_ = &DeleteCSndParamsPointerSlot;
    ctorRefFunc_ = &ConstructCSndParamsPointerSlotRef;
    movRefFunc_ = &MoveCSndParamsPointerSlotRef;
}

RType* gpg::RPointerType<moho::CSndParams>::GetPointeeType() const
{
    return CachedCSndParamsType();
}

/**
 * Address: 0x0059D4C0 (FUN_0059D4C0)
 * Demangled: gpg::RPointerType_IFormationInstance::GetName
 */
const char* gpg::RPointerType<moho::IFormationInstance>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0059D650 (FUN_0059D650)
 * Demangled: gpg::RPointerType_IFormationInstance::GetLexical
 */
msvc8::string gpg::RPointerType<moho::IFormationInstance>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::IFormationInstance>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0059D7D0 (FUN_0059D7D0)
 * Demangled: gpg::RPointerType_IFormationInstance::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::IFormationInstance>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0059D7E0 (FUN_0059D7E0)
 * Demangled: gpg::RPointerType_IFormationInstance::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::IFormationInstance>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0059D840 (FUN_0059D840)
 * Demangled: gpg::RPointerType_IFormationInstance::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `IFormationInstance*` and stores it
 * in the destination pointer slot.
 */
void gpg::RPointerType<moho::IFormationInstance>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::IFormationInstance>(obj, from, moho::IFormationInstance::sType);
}

/**
 * Address: 0x0059D620 (FUN_0059D620)
 * Demangled: gpg::RPointerType_IFormationInstance::Init
 */
void gpg::RPointerType<moho::IFormationInstance>::Init()
{
    v24 = true;
    size_ = sizeof(moho::IFormationInstance*);
    newRefFunc_ = &NewPointerSlotRef<moho::IFormationInstance>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::IFormationInstance>;
    deleteFunc_ = &DeletePointerSlot<moho::IFormationInstance>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::IFormationInstance>;
    movRefFunc_ = &MovePointerSlotRef<moho::IFormationInstance>;
}

RType* gpg::RPointerType<moho::IFormationInstance>::GetPointeeType() const
{
    return CachedIFormationInstanceType();
}

/**
 * Address: 0x005A14F0 (FUN_005A14F0)
 * Demangled: gpg::RPointerType_RUnitBlueprint::GetName
 */
const char* gpg::RPointerType<moho::RUnitBlueprint>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x005A1680 (FUN_005A1680)
 * Demangled: gpg::RPointerType_RUnitBlueprint::GetLexical
 */
msvc8::string gpg::RPointerType<moho::RUnitBlueprint>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::RUnitBlueprint>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005A1800 (FUN_005A1800)
 * Demangled: gpg::RPointerType_RUnitBlueprint::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::RUnitBlueprint>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005A1810 (FUN_005A1810)
 * Demangled: gpg::RPointerType_RUnitBlueprint::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::RUnitBlueprint>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005A1870 (FUN_005A1870)
 * Demangled: gpg::RPointerType_RUnitBlueprint::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `RUnitBlueprint*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::RUnitBlueprint>::AssignPointer(void* const obj, const RRef& from) const
{
    static gpg::RType* sAssignPointeeType = nullptr;
    AssignPointerSlotWithTypeCache<moho::RUnitBlueprint>(obj, from, sAssignPointeeType);
}

namespace
{
/**
 * Address: 0x005A1AA0 (FUN_005A1AA0)
 *
 * What it does:
 * Binds copy/move callback lanes for `RUnitBlueprint*` pointer reflection.
 */
gpg::RPointerTypeBase* BindRUnitBlueprintPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyPointerSlotRef<moho::RUnitBlueprint>;
    typeInfo->movRefFunc_ = &MovePointerSlotRef<moho::RUnitBlueprint>;
    return typeInfo;
}

/**
 * Address: 0x005A1A40 (FUN_005A1A40)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `RUnitBlueprint*` reflection.
 */
gpg::RPointerTypeBase* BindRUnitBlueprintPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::RUnitBlueprint*);
    typeInfo->newRefFunc_ = &NewPointerSlotRef<moho::RUnitBlueprint>;
    typeInfo->ctorRefFunc_ = &ConstructPointerSlotRef<moho::RUnitBlueprint>;
    (void)BindRUnitBlueprintPointerCopyAndMove(typeInfo);
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::RUnitBlueprint>;
    return typeInfo;
}
}

/**
 * Address: 0x005A1650 (FUN_005A1650)
 * Demangled: gpg::RPointerType_RUnitBlueprint::Init
 */
void gpg::RPointerType<moho::RUnitBlueprint>::Init()
{
    (void)BindRUnitBlueprintPointerAll(this);
}

RType* gpg::RPointerType<moho::RUnitBlueprint>::GetPointeeType() const
{
    return CachedRUnitBlueprintType();
}

/**
 * Address: 0x005C8080 (FUN_005C8080)
 * Demangled: gpg::RPointerType_ReconBlip::GetName
 */
const char* gpg::RPointerType<moho::ReconBlip>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x005C8210 (FUN_005C8210)
 * Demangled: gpg::RPointerType_ReconBlip::GetLexical
 */
msvc8::string gpg::RPointerType<moho::ReconBlip>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::ReconBlip>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005C8390 (FUN_005C8390)
 * Demangled: gpg::RPointerType_ReconBlip::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::ReconBlip>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005C83A0 (FUN_005C83A0)
 * Demangled: gpg::RPointerType_ReconBlip::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::ReconBlip>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005C8400 (FUN_005C8400)
 * Demangled: gpg::RPointerType_ReconBlip::AssignPointer
 *
 * What it does:
 * Upcasts a reflected source reference to `ReconBlip*` and stores it in the
 * destination pointer slot.
 */
void gpg::RPointerType<moho::ReconBlip>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::ReconBlip>(obj, from, moho::ReconBlip::sType);
}

/**
 * Address: 0x005C81E0 (FUN_005C81E0)
 * Demangled: gpg::RPointerType_ReconBlip::Init
 */
void gpg::RPointerType<moho::ReconBlip>::Init()
{
    v24 = true;
    size_ = sizeof(moho::ReconBlip*);
    newRefFunc_ = &NewPointerSlotRef<moho::ReconBlip>;
    cpyRefFunc_ = &CopyReconBlipPointerSlotRef;
    deleteFunc_ = &DeletePointerSlot<moho::ReconBlip>;
    ctorRefFunc_ = &ConstructReconBlipPointerSlotRef;
    movRefFunc_ = &MoveReconBlipPointerSlotRef;
}

RType* gpg::RPointerType<moho::ReconBlip>::GetPointeeType() const
{
    return CachedReconBlipType();
}

msvc8::string gpg::RPointerType<moho::CArmyStatItem>::sName{};
std::uint32_t gpg::RPointerType<moho::CArmyStatItem>::sNameInitGuard = 0u;

/**
 * Address: 0x007115D0 (FUN_007115D0)
 * Demangled: gpg::RPointerType_CArmyStatItem::GetName
 */
const char* gpg::RPointerType<moho::CArmyStatItem>::GetName() const
{
    if ((sNameInitGuard & 1u) == 0u) {
        sNameInitGuard |= 1u;

        RType* pointeeType = moho::CArmyStatItem::sType;
        if (!pointeeType) {
            pointeeType = gpg::LookupRType(typeid(moho::CArmyStatItem));
            moho::CArmyStatItem::sType = pointeeType;
        }

        const char* pointeeName = pointeeType ? pointeeType->GetName() : nullptr;
        sName = msvc8::string((pointeeName != nullptr) ? pointeeName : "");
        sName += "*";
    }
    return sName.c_str();
}

/**
 * Address: 0x00711760 (FUN_00711760)
 * Demangled: gpg::RPointerType_CArmyStatItem::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CArmyStatItem>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CArmyStatItem>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x007118E0 (FUN_007118E0)
 * Demangled: gpg::RPointerType_CArmyStatItem::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CArmyStatItem>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x007118F0 (FUN_007118F0)
 * Demangled: gpg::RPointerType_CArmyStatItem::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CArmyStatItem>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00711950 (FUN_00711950)
 * Demangled: gpg::RPointerType_CArmyStatItem::AssignPointer
 *
 * What it does:
 * Upcasts one reflected source reference to `CArmyStatItem*` and stores it in
 * the destination pointer slot.
 */
void gpg::RPointerType<moho::CArmyStatItem>::AssignPointer(void* const obj, const RRef& from) const
{
    AssignPointerSlotWithTypeCache<moho::CArmyStatItem>(obj, from, moho::CArmyStatItem::sType);
}

/**
 * Address: 0x00711730 (FUN_00711730)
 * Demangled: gpg::RPointerType_CArmyStatItem::Init
 */
void gpg::RPointerType<moho::CArmyStatItem>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CArmyStatItem*);
    newRefFunc_ = &NewPointerSlotRef<moho::CArmyStatItem>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CArmyStatItem>;
    deleteFunc_ = &DeletePointerSlot<moho::CArmyStatItem>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CArmyStatItem>;
    movRefFunc_ = &MovePointerSlotRef<moho::CArmyStatItem>;
}

RType* gpg::RPointerType<moho::CArmyStatItem>::GetPointeeType() const
{
    return CachedCArmyStatItemType();
}

/**
 * Address: 0x008DD950 (FUN_008DD950, ??0RType@gpg@@QAE@XZ_0)
 * Demangled: gpg::RType::RType
 *
 * What it does:
 * Initializes one reflection type descriptor to an empty, uninitialized state:
 * callback lanes cleared, vectors empty, and version/size reset to zero.
 */
RType::RType()
  : finished_(false)
  , initFinished_(false)
  , size_(0)
  , version_(0)
  , serSaveConstructArgsFunc_(nullptr)
  , serSaveFunc_(nullptr)
  , serConstructFunc_(nullptr)
  , serLoadFunc_(nullptr)
  , v8(0)
  , v9(0)
  , bases_()
  , fields_()
  , newRefFunc_(nullptr)
  , cpyRefFunc_(nullptr)
  , deleteFunc_(nullptr)
  , ctorRefFunc_(nullptr)
  , movRefFunc_(nullptr)
  , dtrFunc_(nullptr)
  , v24(false)
{}

/**
 * Address: 0x008DD9D0 (FUN_008DD9D0)
 * Address: 0x00786760 (FUN_00786760)
 * Address: 0x0078CB00 (FUN_0078CB00)
 * Address: 0x0078DD70 (FUN_0078DD70)
 * Address: 0x0078EF90 (FUN_0078EF90)
 * Address: 0x00796160 (FUN_00796160)
 * Address: 0x00797230 (FUN_00797230)
 * Address: 0x00797750 (FUN_00797750)
 * Address: 0x007992F0 (FUN_007992F0)
 * Address: 0x007A2B90 (FUN_007A2B90)
 * Address: 0x007B5E10 (FUN_007B5E10)
 * Address: 0x007C0920 (FUN_007C0920)
 * Address: 0x0086A4E0 (FUN_0086A4E0)
 * Demangled: gpg::RType::dtr
 *
 * What it does:
 * Destroys base reflection type descriptor state; the listed FUN_0078xxxx and
 * FUN_0086A4E0 lanes are COMDAT clones of the same RType teardown body.
 */
RType::~RType() = default;

/**
 * Address: 0x00401350 (FUN_00401350)
 * Demangled: gpg::RType::StaticGetClass
 *
 * What it does:
 * Lazily resolves and caches the reflection descriptor for `RType`.
 */
RType* RType::StaticGetClass()
{
  if (!sType) {
    sType = CachedRTypeDescriptor();
  }
  return sType;
}

/**
 * Address: 0x00401370 (FUN_00401370)
 * Demangled: gpg::RType::GetClass
 *
 * What it does:
 * Lazily resolves and caches the family descriptor for `RType`.
 */
RType* RType::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x00401390 (FUN_00401390)
 * Demangled: gpg::RType::GetDerivedObjectRef
 *
 * What it does:
 * Packs `{this, GetClass()}` into an `RRef` handle.
 */
RRef RType::GetDerivedObjectRef()
{
  RRef out{};
  out.mObj = this;
  out.mType = GetClass();
  return out;
}

/**
 * Address: 0x008DC130 (FUN_008DC130, gpg::RType::NewRef)
 *
 * What it does:
 * Invokes the registered default-constructor callback and returns the
 * produced reference, or throws `BadRefCast` when no constructor callback is
 * registered for this type.
 */
RRef RType::NewRef() const
{
  if (!newRefFunc_) {
    throw BadRefCast("NewRef() on a type without a registered constructor");
  }

  return newRefFunc_();
}

/**
 * Address: 0x008DB100 (FUN_008DB100)
 * Demangled: gpg::RType::GetLexical
 *
 * What it does:
 * Returns default lexical text in the form `"<name> at 0x<ptr>"`.
 */
msvc8::string RType::GetLexical(const RRef& ref) const
{
  const auto name = GetName();
  return STR_Printf("%s at 0x%p", name, ref.mObj);
}

/**
 * Address: 0x008D86E0 (FUN_008D86E0)
 * Demangled: gpg::RType::SetLexical
 *
 * What it does:
 * Base implementation rejects lexical assignment and returns false.
 */
bool RType::SetLexical(const RRef&, const char*) const
{
  return false;
}

/**
 * Address: 0x004013B0 (FUN_004013B0)
 * Demangled: gpg::RType::IsIndexed
 *
 * What it does:
 * Base implementation reports non-indexed type.
 */
const RIndexed* RType::IsIndexed() const
{
  return nullptr;
}

/**
 * Address: 0x004013C0 (FUN_004013C0)
 * Demangled: gpg::RType::IsPointer
 *
 * What it does:
 * Base implementation reports non-pointer type.
 */
const RIndexed* RType::IsPointer() const
{
  return nullptr;
}

/**
 * Address: 0x004013D0 (FUN_004013D0)
 * Demangled: gpg::RType::IsEnumType
 *
 * What it does:
 * Base implementation reports non-enum type.
 */
const REnumType* RType::IsEnumType() const
{
  return nullptr;
}

void RType::Init() {}

void RType::Finish()
{
  GPG_ASSERT(!initFinished_);

  RField* first = fields_.begin();
  if (!first) {
    return;
  }

  RField* last = fields_.end();
  if (first == last) {
    return;
  }

  std::sort(first, last, [](const RField& a, const RField& b) {
    return std::strcmp(a.mName, b.mName) < 0;
  });
}

/**
 * Address: 0x008D8640 (FUN_008D8640, gpg::RType::Version)
 *
 * What it does:
 * Sets RTTI version once and asserts on conflicting subsequent writes.
 */
void RType::Version(const int version)
{
  GPG_ASSERT(version_ == 0 || version_ == version);
  version_ = version;
}

/**
 * Address: 0x008DF500 (FUN_008DF500)
 *
 * gpg::RField const &
 *
 * IDA signature:
 * void __thiscall gpg::RType::AddBase(gpg::RType *this, gpg::RField const *field);
 *
 * What it does:
 * Appends one direct base descriptor and flattens all fields from the base
 * type into this type's field table with subobject-offset adjustment.
 */
void RType::AddBase(const RField& field)
{
  GPG_ASSERT(!initFinished_);

  // Register the base link itself.
  bases_.push_back(field);

  // Flatten base fields into this->fields_ with offset adjustment.
  const RType* baseType = field.mType;
  if (!baseType) {
    return;
  }

  // MSVC8 vector layout may expose raw pointers;
  // keep null-safe checks like in the original.
  const RField* it = baseType->fields_.begin();
  const RField* end = baseType->fields_.end();
  if (!it)
    return; // consistent with original early-exit when start==nullptr

  for (; it < end; ++it) {
    // Copy-by-value semantics;
    // strings/descriptions are pointer aliases in the original.
    RField out{
      // same literal pointer as in base
      it->mName,
      // same field type
      it->mType,
      // adjust offset by base field offset
      field.mOffset + it->mOffset
    };

    out.v4 = it->v4;
    out.mDesc = it->mDesc;

    fields_.push_back(out);
  }
}

void RType::RegisterType()
{
  // 1) Map name -> type
  // original: this->vtable->GetName(this)
  const char* name = GetName();
  // original: *sub_8DF330(map, &name) = this;
  GetRTypeMap()[name] = this;

  // 2) Append to global type list
  GetRTypeVec().push_back(this);
}

/**
 * Address: 0x0040DFA0 (FUN_0040DFA0, gpg::RType::AddField_float)
 */
RField* RType::AddFieldFloat(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedFloatType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x0040E020 (FUN_0040E020, gpg::RType::AddField_uint)
 */
RField* RType::AddFieldUInt(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedUIntType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x004EDC10 (FUN_004EDC10, gpg::RType::AddField_int)
 */
RField* RType::AddFieldInt(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedIntType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x00510DD0 (FUN_00510DD0, gpg::RType::AddFieldBool)
 */
RField* RType::AddFieldBool(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedBoolType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x0050E1F0 (FUN_0050E1F0, gpg::RType::AddField_string)
 */
RField* RType::AddFieldString(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedStringType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x004EDFD0 (FUN_004EDFD0, gpg::RType::AddField_Vector3f)
 */
RField* RType::AddFieldVector3f(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedVector3fType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x00510D50 (FUN_00510D50, gpg::RType::AddField_RResId)
 */
RField* RType::AddFieldRResId(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedRResIdType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x0050D010 (FUN_0050D010, gpg::RType::AddField_uchar)
 */
RField* RType::AddFieldUChar(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedUCharType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x00510F10 (FUN_00510F10, gpg::RType::AddField_REmitterBlueprintCurve)
 */
RField* RType::AddFieldEmitterBlueprintCurve(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedEmitterBlueprintCurveType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x00510FF0 (FUN_00510FF0, gpg::RType::AddField_Vector4f)
 */
RField* RType::AddFieldVector4f(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedVector4fType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x00513230 (FUN_00513230, gpg::RType::AddField_vector_string)
 */
RField* RType::AddFieldVectorString(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedVectorStringType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x00513330 (FUN_00513330, gpg::RType::AddField_SFootprint)
 */
RField* RType::AddFieldSFootprint(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedSFootprintType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x004EA0E0 (FUN_004EA0E0, gpg::RType::AddBlueprintAxisAlignedBox3f)
 *
 * What it does:
 * Appends six float fields for one axis-aligned-box payload:
 * min xyz at offsets 0/4/8 and max xyz at offsets 12/16/20.
 */
void RType::AddBlueprintAxisAlignedBox3f()
{
  AddFieldFloat("min0", 0x00);
  AddFieldFloat("min1", 0x04);
  AddFieldFloat("min2", 0x08);
  AddFieldFloat("max0", 0x0C);
  AddFieldFloat("max1", 0x10);
  AddFieldFloat("max2", 0x14);
}

const RField* RType::GetFieldNamed(const char* name) const
{
  GPG_ASSERT(initFinished_);

  const RField* start = fields_.begin();
  if (!start) {
    return nullptr;
  }

  const RField* finish = fields_.end();
  if (start == finish) {
    return nullptr;
  }

  // Classic binary search over [lo, hi)
  std::size_t lo = 0;
  std::size_t hi = static_cast<std::size_t>(finish - start);

  while (lo < hi) {
    const std::size_t mid = (lo + hi) >> 1;
    const RField* elem = &start[mid];

    const int cmp = std::strcmp(name, elem->mName);
    if (cmp < 0) {
      hi = mid;
    } else if (cmp > 0) {
      lo = mid + 1;
    } else {
      // exact match
      return elem;
    }
  }
  return nullptr;
}

bool RType::IsDerivedFrom(const RType* baseType, int32_t* outOffset) const
{
  if (this == baseType) {
    if (outOffset) {
      *outOffset = 0;
    }

    return true;
  }

  const RField* first = bases_.begin();
  if (!first) {
    return false;
  }

  const RField* last = bases_.end();
  if (first == last) {
    return false;
  }

  bool found = false;

  for (const RField* it = first; it != last; ++it) {
    if (it->mType->IsDerivedFrom(baseType, outOffset)) {
      if (found) {
        throw std::runtime_error("Ambiguous base class");
      }

      if (!outOffset) {
        return true;
      }

      if (outOffset) {
        *outOffset += it->mOffset;
      }

      found = true;
    }
  }

  return found;
}

/**
 * Address: 0x00905E40 (FUN_00905E40)
 * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<int>>::Init
 *
 * What it does:
 * Lazily resolves Rect2<int> RTTI and installs serializer callbacks from this helper.
 */
void gpg::Rect2iSerializer::RegisterSerializeFunctions()
{
  RType* const type = CachedRect2iType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00905EE0 (FUN_00905EE0)
 * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<float>>::Init
 *
 * What it does:
 * Lazily resolves Rect2<float> RTTI and installs serializer callbacks from this helper.
 */
void gpg::Rect2fSerializer::RegisterSerializeFunctions()
{
  RType* const type = CachedRect2fType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00905FD0 (FUN_00905FD0, gpg::Rect2iTypeInfo::Rect2iTypeInfo)
 *
 * What it does:
 * Constructs the Rect2<int> runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Rect2i)`.
 */
gpg::Rect2iTypeInfo::Rect2iTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(Rect2i), this);
}

/**
 * Address: 0x00906020 (FUN_00906020)
 * Demangled: gpg::Rect2iTypeInfo::GetName
 */
const char* gpg::Rect2iTypeInfo::GetName() const
{
  return "Rect2i";
}

/**
 * Address: 0x00906080 (FUN_00906080, gpg::Rect2fTypeInfo::Rect2fTypeInfo)
 *
 * What it does:
 * Constructs the Rect2<float> runtime type descriptor and preregisters it
 * with reflection registry using `typeid(Rect2f)`.
 */
gpg::Rect2fTypeInfo::Rect2fTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(Rect2f), this);
}

/**
 * Address: 0x009060D0 (FUN_009060D0)
 * Demangled: gpg::Rect2fTypeInfo::GetName
 */
const char* gpg::Rect2fTypeInfo::GetName() const
{
  return "Rect2f";
}

/**
 * Address: 0x00906270 (FUN_00906270)
 * Demangled: gpg::Rect2iTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers int fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2iTypeInfo::Init()
{
  size_ = sizeof(Rect2i);
  gpg::RType::Init();
  AddRect2IntField(this, "x0", offsetof(Rect2i, x0));
  AddRect2IntField(this, "y0", offsetof(Rect2i, z0));
  AddRect2IntField(this, "x1", offsetof(Rect2i, x1));
  AddRect2IntField(this, "y1", offsetof(Rect2i, z1));
  Finish();
}

/**
 * Address: 0x009062D0 (FUN_009062D0)
 * Demangled: gpg::Rect2fTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers float fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2fTypeInfo::Init()
{
  size_ = sizeof(Rect2f);
  gpg::RType::Init();
  AddRect2FloatField(this, "x0", offsetof(Rect2f, x0));
  AddRect2FloatField(this, "y0", offsetof(Rect2f, z0));
  AddRect2FloatField(this, "x1", offsetof(Rect2f, x1));
  AddRect2FloatField(this, "y1", offsetof(Rect2f, z1));
  Finish();
}

/**
 * Address: 0x004180A0 (FUN_004180A0, gpg::REnumType::REnumType)
 */
gpg::REnumType::REnumType()
  : gpg::RType()
  , mPrefix(nullptr)
  , mEnumNames()
{}

/**
 * Address: 0x00418120 (FUN_00418120, gpg::REnumType::~REnumType)
 */
gpg::REnumType::~REnumType() = default;

/**
 * Address: 0x00596690 (FUN_00596690, deleting-destructor thunk)
 *
 * What it does:
 * Runs one `REnumType` destructor lane and conditionally frees this object
 * storage when the low delete flag bit is set.
 */
[[maybe_unused]] gpg::REnumType* DestroyREnumTypeAndMaybeDelete(
  gpg::REnumType* const object,
  const unsigned char deleteFlag
) noexcept
{
  object->~REnumType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(object));
  }
  return object;
}

msvc8::string REnumType::GetLexical(const RRef& ref) const
{
  const int* enumValue = static_cast<const int*>(ref.mObj);
  const int value = enumValue ? *enumValue : 0;

  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (it->mValue == value) {
      return msvc8::string(it->mName ? it->mName : "");
    }
  }

  return STR_Printf("%d", value);
}

bool REnumType::SetLexical(const RRef& dest, const char* str) const
{
  if (!str || !dest.mObj) {
    return false;
  }

  int acc = 0;

  while (true) {
    // Find next separator and define token range
    const char* sep = std::strchr(str, '|');
    const char* tokenEnd = sep ? sep : (str + std::strlen(str));

    // Optional, case-sensitive prefix stripping
    const char* tokenBegin = str;
    if (mPrefix) {
      const std::size_t pn = std::strlen(mPrefix);
      if (std::strncmp(str, mPrefix, pn) == 0) {
        tokenBegin = str + pn;
      }
    }

    const std::size_t n = static_cast<std::size_t>(tokenEnd - tokenBegin);

    int num = 0;
    bool matched = false;

    // Try case-insensitive exact name match
    for (const ROptionValue& opt : mEnumNames) {
      const char* name = opt.mName ? opt.mName : "";

      const bool eq = STR_EqualsNoCaseN(tokenBegin, name, n) && name[n] == '\0';

      if (eq) {
        num = opt.mValue;
        matched = true;
        break;
      }
    }

    // Fallback: numeric parse from span [tokenBegin, tokenEnd)
    if (!matched) {
      if (!ParseNum(tokenBegin, tokenEnd, &num)) {
        return false;
      }
    }

    // Accumulate OR
    acc |= num;

    // Commit on last token
    if (!sep) {
      *static_cast<int*>(dest.mObj) = acc;
      return true;
    }

    // Next token
    str = sep + 1;
  }
}

/**
 * Address: 0x008D86F0 (FUN_008D86F0, gpg::REnumType::StripPrefix)
 *
 * What it does:
 * Returns `name` advanced past the configured enum prefix when it matches,
 * otherwise returns `name` unchanged.
 */
const char* REnumType::StripPrefix(const char* name) const
{
  // Fast path: no prefix configured
  if (!mPrefix || !*mPrefix) {
    return name;
  }

  // Compute prefix length once (the original code effectively did strlen twice)
  const std::size_t n = std::strlen(mPrefix);
  if (std::strncmp(name, mPrefix, n) == 0) {
    return name + n;
  }

  return name;
}

/**
 * Address: 0x008D9FD0 (FUN_008D9FD0)
 *
 * What it does:
 * Scans enum options and writes the matched integer value for a
 * case-insensitive enum token name.
 */
bool REnumType::GetEnumValue(const char* name, int* outVal) const
{
  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (STR_EqualsNoCase(it->mName, name)) {
      *outVal = it->mValue;
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x008DF290 (FUN_008DF290)
 *
 * What it does:
 * Appends one enum option lane into the backing `msvc8::vector` and returns
 * the inserted slot.
 */
[[nodiscard]] static REnumType::ROptionValue* AppendEnumOptionValue(
  msvc8::vector<REnumType::ROptionValue>& options,
  const REnumType::ROptionValue& value
)
{
  options.push_back(value);
  return options.empty() ? nullptr : &options.back();
}

/**
 * Address: 0x008DF5F0 (FUN_008DF5F0, gpg::REnumType::AddEnum)
 *
 * What it does:
 * Appends one `{value,name}` enum option entry to the reflected enum table.
 */
void REnumType::AddEnum(char const* name, const int index)
{
  const ROptionValue opt{index, name};
  (void)AppendEnumOptionValue(mEnumNames, opt);
}

/**
 * Address: 0x004E4BF0 (FUN_004E4BF0)
 *
 * What it does:
 * Packs one `RRef_CSndVar` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndVar(RRef* const out, moho::CSndVar* const value)
{
  RRef tmp{};
  (void)RRef_CSndVar(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E4D00 (FUN_004E4D00)
 *
 * What it does:
 * Packs one `RRef_CSndParams` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndParams(RRef* const out, moho::CSndParams* const value)
{
  RRef tmp{};
  (void)RRef_CSndParams(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E54E0 (FUN_004E54E0)
 *
 * What it does:
 * Packs one `RRef_CSndParams_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndParamsPointer(RRef* const out, moho::CSndParams** const value)
{
  RRef tmp{};
  (void)RRef_CSndParams_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x004E6640 (FUN_004E6640)
 *
 * What it does:
 * Packs one `RRef_CSndParams_P` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CSndParamsPointerSecondary(RRef* const out, moho::CSndParams** const value)
{
  RRef tmp{};
  (void)RRef_CSndParams_P(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0054E200 (FUN_0054E200)
 *
 * What it does:
 * Packs one `RRef_CAniPose` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAniPose(RRef* const out, moho::CAniPose* const value)
{
  RRef tmp{};
  (void)RRef_CAniPose(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00553D00 (FUN_00553D00)
 *
 * What it does:
 * Packs one `RRef_SOCellPos` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_SOCellPos(RRef* const out, moho::SOCellPos* const value)
{
  RRef tmp{};
  (void)RRef_SOCellPos(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0059DD60 (FUN_0059DD60)
 *
 * What it does:
 * Packs one `RRef_CAiFormationInstance` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiFormationInstance(
  RRef* const out,
  moho::CAiFormationInstance* const value
)
{
  RRef tmp{};
  (void)RRef_CAiFormationInstance(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005ABB80 (FUN_005ABB80)
 *
 * What it does:
 * Packs one `RRef_CAiPathFinder` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAiPathFinder(RRef* const out, moho::CAiPathFinder* const value)
{
  RRef tmp{};
  (void)RRef_CAiPathFinder(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF570 (FUN_005DF570)
 *
 * What it does:
 * Packs one `RRef_LAiAttackerImpl` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_LAiAttackerImpl(RRef* const out, moho::LAiAttackerImpl* const value)
{
  RRef tmp{};
  (void)RRef_LAiAttackerImpl(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x005DF5A0 (FUN_005DF5A0)
 *
 * What it does:
 * Packs one `RRef_CAcquireTargetTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CAcquireTargetTask(RRef* const out, moho::CAcquireTargetTask* const value)
{
  RRef tmp{};
  (void)RRef_CAcquireTargetTask(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00605780 (FUN_00605780)
 *
 * What it does:
 * Packs one `RRef_CUnitCaptureTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitCaptureTask(RRef* const out, moho::CUnitCaptureTask* const value)
{
  RRef tmp{};
  (void)RRef_CUnitCaptureTask(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0060C7A0 (FUN_0060C7A0)
 *
 * What it does:
 * Packs one `RRef_CUnitGetBuiltTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitGetBuiltTask(RRef* const out, moho::CUnitGetBuiltTask* const value)
{
  RRef tmp{};
  (void)RRef_CUnitGetBuiltTask(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00614B50 (FUN_00614B50)
 *
 * What it does:
 * Packs one `RRef_CUnitGuardTask` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitGuardTask(RRef* const out, moho::CUnitGuardTask* const value)
{
  RRef tmp{};
  (void)RRef_CUnitGuardTask(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x006282E0 (FUN_006282E0)
 *
 * What it does:
 * Packs one `RRef_CUnitUnloadUnits` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_CUnitUnloadUnits(RRef* const out, moho::CUnitUnloadUnits* const value)
{
  RRef tmp{};
  (void)RRef_CUnitUnloadUnits(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0063E800 (FUN_0063E800)
 *
 * What it does:
 * Packs one `RRef_shared_ptr_CAniPose` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_SharedPtrCAniPose(
  RRef* const out,
  boost::shared_ptr<moho::CAniPose>* const value
)
{
  RRef tmp{};
  (void)RRef_shared_ptr_CAniPose(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0067F600 (FUN_0067F600)
 *
 * What it does:
 * Packs one `RRef_Entity` result into caller-owned output storage.
 */
gpg::RRef* PackRRef_Entity(RRef* const out, moho::Entity* const value)
{
  RRef tmp{};
  (void)RRef_Entity(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

} // namespace gpg
