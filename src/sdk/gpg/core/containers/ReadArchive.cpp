#include "ReadArchive.h"

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <istream>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <string_view>

#include "gpg/core/containers/String.h"

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/ai/CAiPathNavigator.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/EAiResult.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/ai/IAiSteering.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "moho/audio/ISoundManager.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/command/CCommandDb.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityMotor.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/Shield.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/CTextureScroller.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/Listener.h"
#include "moho/misc/StatItem.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/sim/ReconBlip.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CDecalHandle.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimArmy.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SPhysBody.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskEvent.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "moho/unit/tasks/CFireWeaponTask.h"
#include "String.h"
#include "lua/LuaObject.h"

using namespace gpg;

namespace
{
  [[noreturn]] void ThrowSerializationError(const char* const message)
  {
    throw SerializationError(message ? message : "");
  }

  [[noreturn]] void ThrowSerializationError(const msvc8::string& message)
  {
    throw SerializationError(message.c_str());
  }

  const char* SafeTypeName(const RType* const type)
  {
    return type ? type->GetName() : "null";
  }

  [[nodiscard]] RType* CachedLuaStateType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaState));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaCStateType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(lua_State));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaTableType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Table));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaTStringType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(TString));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaLClosureType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LClosure));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaUdataType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Udata));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaProtoType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Proto));
    }
    return cached;
  }

  [[nodiscard]] RType* CachedLuaUpValType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(UpVal));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRRuleGameRulesType()
  {
    gpg::RType* type = moho::RRuleGameRules::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RRuleGameRules));
      moho::RRuleGameRules::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedHSoundType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::HSound));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCSndParamsType()
  {
    gpg::RType* type = moho::CSndParams::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CSndParams));
      moho::CSndParams::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCSndParamsType2()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CSndParams));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedPathQueueType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {"Moho::PathQueue", "PathQueue", "class Moho::PathQueue"};
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedPathQueueImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::PathQueue::Impl", "PathQueue::Impl", "struct Moho::PathQueue::Impl"
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconStorageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::CEconStorage", "CEconStorage", "class Moho::CEconStorage"
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSTIMapType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::STIMap));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCTextureScrollerType()
  {
    gpg::RType* type = moho::CTextureScroller::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CTextureScroller));
      moho::CTextureScroller::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedREntityBlueprintType()
  {
    gpg::RType* type = moho::REntityBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::REntityBlueprint));
      moho::REntityBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRMeshBlueprintType()
  {
    gpg::RType* type = moho::RMeshBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RMeshBlueprint));
      moho::RMeshBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintType()
  {
    gpg::RType* type = moho::RUnitBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RUnitBlueprint));
      moho::RUnitBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintType2()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedREmitterBlueprintType()
  {
    gpg::RType* type = moho::REmitterBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::REmitterBlueprint));
      moho::REmitterBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRTrailBlueprintType()
  {
    gpg::RType* type = moho::RTrailBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RTrailBlueprint));
      moho::RTrailBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (moho::Sim::sType == nullptr) {
      moho::Sim::sType = gpg::LookupRType(typeid(moho::Sim));
    }
    return moho::Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedSimArmyType()
  {
    if (moho::SimArmy::sType == nullptr) {
      moho::SimArmy::sType = gpg::LookupRType(typeid(moho::SimArmy));
    }
    return moho::SimArmy::sType;
  }

  [[nodiscard]] gpg::RType* CachedCAiPersonalityType()
  {
    gpg::RType* type = moho::CAiPersonality::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiPersonality));
      moho::CAiPersonality::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCTaskStageType()
  {
    gpg::RType* type = moho::CTaskStage::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CTaskStage));
      moho::CTaskStage::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    gpg::RType* type = moho::CTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CTask));
      moho::CTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCTaskThreadType()
  {
    gpg::RType* type = moho::CTaskThread::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CTaskThread));
      moho::CTaskThread::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCSquadType()
  {
    gpg::RType* type = moho::CSquad::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CSquad));
      moho::CSquad::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedStatItemType()
  {
    gpg::RType* type = moho::StatItem::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::StatItem));
      moho::StatItem::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSTaskEventLinkageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::STaskEventLinkage));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathNavigatorType()
  {
    gpg::RType* type = moho::CAiPathNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiPathNavigator));
      moho::CAiPathNavigator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    gpg::RType* type = moho::CAiPathFinder::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiPathFinder));
      moho::CAiPathFinder::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathSplineType()
  {
    gpg::RType* type = moho::CAiPathSpline::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiPathSpline));
      moho::CAiPathSpline::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Unit));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IUnit));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedUnitWeaponType()
  {
    gpg::RType* type = moho::UnitWeapon::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::UnitWeapon));
      moho::UnitWeapon::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedReconBlipType()
  {
    gpg::RType* type = moho::ReconBlip::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ReconBlip));
      moho::ReconBlip::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintWeaponType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRProjectileBlueprintType()
  {
    gpg::RType* type = moho::RProjectileBlueprint::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
      moho::RProjectileBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAcquireTargetTaskType()
  {
    gpg::RType* type = moho::CAcquireTargetTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAcquireTargetTask));
      moho::CAcquireTargetTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiAttackerImplType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiAttackerImpl));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedEAiResultType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EAiResult));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconomyEventType()
  {
    gpg::RType* type = moho::CEconomyEvent::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CEconomyEvent));
      moho::CEconomyEvent::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    gpg::RType* type = moho::CUnitCommand::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCommand));
      moho::CUnitCommand::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCParticleTextureType()
  {
    gpg::RType* type = moho::CParticleTexture::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CParticleTexture));
      moho::CParticleTexture::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSPhysBodyType()
  {
    gpg::RType* type = moho::SPhysBody::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SPhysBody));
      moho::SPhysBody::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedMotorType()
  {
    gpg::RType* type = moho::EntityMotor::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntityMotor));
      moho::EntityMotor::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedEntityType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::Entity));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedPositionHistoryType()
  {
    gpg::RType* type = moho::PositionHistory::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::PositionHistory));
      moho::PositionHistory::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCColPrimitiveBaseType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CColPrimitiveBase));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCIntelType()
  {
    gpg::RType* type = moho::CIntel::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CIntel));
      moho::CIntel::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCIntelPosHandleType()
  {
    gpg::RType* type = moho::CIntelPosHandle::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CIntelPosHandle));
      moho::CIntelPosHandle::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiSteeringType()
  {
    gpg::RType* type = moho::IAiSteering::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiSteering));
      moho::IAiSteering::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitMotionType()
  {
    gpg::RType* type = moho::CUnitMotion::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitMotion));
      moho::CUnitMotion::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandQueueType()
  {
    gpg::RType* type = moho::CUnitCommandQueue::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCommandQueue));
      moho::CUnitCommandQueue::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0059A030 (FUN_0059A030, gpg::RRef::Upcast_CUnitCommandQueue)
   *
   * What it does:
   * Upcasts one reflected reference lane to `moho::CUnitCommandQueue`.
   */
  [[nodiscard]] moho::CUnitCommandQueue* UpcastCUnitCommandQueueRef(const gpg::RRef& source)
  {
    return static_cast<moho::CUnitCommandQueue*>(gpg::REF_UpcastPtr(source, CachedCUnitCommandQueueType()).mObj);
  }

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchType()
  {
    gpg::RType* type = moho::IAiCommandDispatch::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiCommandDispatch));
      moho::IAiCommandDispatch::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    gpg::RType* type = moho::IAiNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiNavigator));
      moho::IAiNavigator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiBuilderType()
  {
    gpg::RType* type = moho::IAiBuilder::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiBuilder));
      moho::IAiBuilder::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = moho::CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiBrain));
      moho::CAiBrain::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiReconDBType()
  {
    gpg::RType* type = moho::IAiReconDB::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiReconDB));
      moho::IAiReconDB::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiSiloBuildType()
  {
    gpg::RType* type = moho::IAiSiloBuild::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiSiloBuild));
      moho::IAiSiloBuild::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiTransportType()
  {
    gpg::RType* type = moho::IAiTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiTransport));
      moho::IAiTransport::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCFireWeaponTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CFireWeaponTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCArmyStatsType()
  {
    gpg::RType* type = moho::CArmyStats::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CArmyStats));
      moho::CArmyStats::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCInfluenceMapType()
  {
    gpg::RType* type = moho::CInfluenceMap::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CInfluenceMap));
      moho::CInfluenceMap::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCOGridType()
  {
    gpg::RType* type = moho::COGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::COGrid));
      moho::COGrid::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCArmyStatItemType()
  {
    gpg::RType* type = moho::CArmyStatItem::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CArmyStatItem));
      moho::CArmyStatItem::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCRandomStreamType()
  {
    gpg::RType* type = moho::CRandomStream::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CRandomStream));
      moho::CRandomStream::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedOwnedSPhysConstantsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SPhysConstants));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIAiFormationDBType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IAiFormationDB));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCCommandDBType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CCommandDb));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCDecalBufferType()
  {
    gpg::RType* type = moho::CDecalBuffer::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CDecalBuffer));
      moho::CDecalBuffer::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCDecalHandleType()
  {
    gpg::RType* type = moho::CDecalHandle::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CDecalHandle));
      moho::CDecalHandle::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIEffectManagerType()
  {
    gpg::RType* type = moho::IEffectManager::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IEffectManager));
      moho::IEffectManager::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedISoundManagerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ISoundManager));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntityDBType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CEntityDb));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    gpg::RType* type = moho::IFormationInstance::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IFormationInstance));
      moho::IFormationInstance::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedListenerEFormationdStatusType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<enum Moho::EFormationdStatus>",
        "Listener<enum Moho::EFormationdStatus>",
        "Listener<EFormationdStatus>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<moho::EFormationdStatus>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerEAiNavigatorEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<enum Moho::EAiNavigatorEvent>",
        "Listener<enum Moho::EAiNavigatorEvent>",
        "Listener<EAiNavigatorEvent>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<moho::EAiNavigatorEvent>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerEAiAttackerEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<enum Moho::EAiAttackerEvent>",
        "Listener<enum Moho::EAiAttackerEvent>",
        "Listener<EAiAttackerEvent>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<moho::EAiAttackerEvent>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerEAiTransportEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<enum Moho::EAiTransportEvent>",
        "Listener<enum Moho::EAiTransportEvent>",
        "Listener<EAiTransportEvent>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<moho::EAiTransportEvent>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedManyToOneListenerECollisionBeamEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::ManyToOneListener<enum Moho::ECollisionBeamEvent>",
        "ManyToOneListener<enum Moho::ECollisionBeamEvent>",
        "ManyToOneListener<ECollisionBeamEvent>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::ManyToOneListener<moho::ECollisionBeamEvent>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedManyToOneListenerEProjectileImpactEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::ManyToOneListener<enum Moho::EProjectileImpactEvent>",
        "ManyToOneListener<enum Moho::EProjectileImpactEvent>",
        "ManyToOneListener<EProjectileImpactEvent>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::ManyToOneListener<moho::EProjectileImpactEvent>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<enum Moho::ECommandEvent>",
        "Listener<enum Moho::ECommandEvent>",
        "Listener<ECommandEvent>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<moho::ECommandEvent>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerEUnitCommandQueueStatusType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<enum Moho::EUnitCommandQueueStatus>",
        "Listener<enum Moho::EUnitCommandQueueStatus>",
        "Listener<EUnitCommandQueueStatus>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<moho::EUnitCommandQueueStatus>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerNavPathType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<Moho::NavPath const &>",
        "Listener<Moho::NavPath const &>",
        "Moho::Listener<Moho::SNavPath const &>",
        "Listener<Moho::SNavPath const &>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<const moho::SNavPath&>));
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCAniPoseType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAniPose));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCAniActorType()
  {
    gpg::RType* type = moho::CAniActor::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAniActor));
      moho::CAniActor::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIEffectType()
  {
    gpg::RType* type = moho::IEffect::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IEffect));
      moho::IEffect::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiAttackerType()
  {
    gpg::RType* type = moho::IAiAttacker::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAiAttacker));
      moho::IAiAttacker::sType = type;
    }
    return type;
  }

  // Per-type reflected upcasts. Each of these is a distinct function in the
  // binary that the ReadPointerOwned_* readers call rather than open-coding
  // the REF_UpcastPtr sequence; they lazily resolve the target RType, upcast
  // the reference, and hand back the pointee (null when the runtime type does
  // not derive from the requested one, which the caller turns into an error).

  /**
   * Address: 0x006B5990 (FUN_006B5990, gpg::RRef::Upcast_IAiSteering)
   *
   * IDA signature:
   * Moho::IAiSteering *__usercall gpg::RRef::Upcast_IAiSteering@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiSteering`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiSteering* UpcastToIAiSteering(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiSteeringType());
    return static_cast<moho::IAiSteering*>(upcast.mObj);
  }

  /**
   * Address: 0x006B5D60 (FUN_006B5D60, gpg::RRef::Upcast_IAiAttacker)
   *
   * IDA signature:
   * Moho::IAiAttacker *__usercall gpg::RRef::Upcast_IAiAttacker@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiAttacker`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiAttacker* UpcastToIAiAttacker(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiAttackerType());
    return static_cast<moho::IAiAttacker*>(upcast.mObj);
  }

  /**
   * Address: 0x006B6140 (FUN_006B6140, gpg::RRef::Upcast_IAiNavigator)
   *
   * IDA signature:
   * Moho::IAiNavigator *__usercall gpg::RRef::Upcast_IAiNavigator@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiNavigator`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiNavigator* UpcastToIAiNavigator(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiNavigatorType());
    return static_cast<moho::IAiNavigator*>(upcast.mObj);
  }

  /**
   * Address: 0x006B6330 (FUN_006B6330, gpg::RRef::Upcast_IAiBuilder)
   *
   * IDA signature:
   * Moho::IAiBuilder *__usercall gpg::RRef::Upcast_IAiBuilder@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiBuilder`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiBuilder* UpcastToIAiBuilder(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiBuilderType());
    return static_cast<moho::IAiBuilder*>(upcast.mObj);
  }

  /**
   * Address: 0x006B6520 (FUN_006B6520, gpg::RRef::Upcast_IAiSiloBuild)
   *
   * IDA signature:
   * Moho::IAiSiloBuild *__usercall gpg::RRef::Upcast_IAiSiloBuild@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiSiloBuild`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiSiloBuild* UpcastToIAiSiloBuild(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiSiloBuildType());
    return static_cast<moho::IAiSiloBuild*>(upcast.mObj);
  }

  /**
   * Address: 0x006B6710 (FUN_006B6710, gpg::RRef::Upcast_IAiTransport)
   *
   * IDA signature:
   * Moho::IAiTransport *__usercall gpg::RRef::Upcast_IAiTransport@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiTransport`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiTransport* UpcastToIAiTransport(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiTransportType());
    return static_cast<moho::IAiTransport*>(upcast.mObj);
  }

  /**
   * Address: 0x006B5F50 (FUN_006B5F50, gpg::RRef::Upcast_IAiCommandDispatch)
   *
   * IDA signature:
   * Moho::IAiCommandDispatch *__usercall gpg::RRef::Upcast_IAiCommandDispatch@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiCommandDispatch`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiCommandDispatch* UpcastToIAiCommandDispatch(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiCommandDispatchType());
    return static_cast<moho::IAiCommandDispatch*>(upcast.mObj);
  }

  /**
   * Address: 0x006B5B80 (FUN_006B5B80, gpg::RRef::Upcast_CEconStorage)
   *
   * IDA signature:
   * Moho::CEconStorage *__usercall gpg::RRef::Upcast_CEconStorage@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CEconStorage`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::CEconStorage* UpcastToCEconStorage(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconStorageType());
    return static_cast<moho::CEconStorage*>(upcast.mObj);
  }

  /**
   * Address: 0x006B21A0 (FUN_006B21A0, gpg::RRef::Upcast_CEconomyEvent)
   *
   * IDA signature:
   * Moho::CEconomyEvent *__usercall gpg::RRef::Upcast_CEconomyEvent@<eax>(gpg::RRef *a1);
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CEconomyEvent`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::CEconomyEvent* UpcastToCEconomyEvent(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconomyEventType());
    return static_cast<moho::CEconomyEvent*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RType* CachedShieldType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Shield));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedPathTablesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::PathTables));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntitySetBaseType()
  {
    gpg::RType* type = moho::EntitySetBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetBase));
      moho::EntitySetBase::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCPathPointType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CPathPoint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIPathTravelerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IPathTraveler));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconRequestType()
  {
    gpg::RType* type = moho::CEconRequest::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CEconRequest));
      moho::CEconRequest::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCEconomyType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {"Moho::CEconomy", "CEconomy", "class Moho::CEconomy"};
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }
    }
    return cached;
  }
  // Reflected per-type upcasts. Each of these is its own function in the
  // binary that the corresponding reader calls, rather than open-coding the
  // REF_UpcastPtr sequence at the call site.

  /**
   * Address: 0x00585270 (FUN_00585270, gpg::RRef::Upcast_SimArmy)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::SimArmy`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::SimArmy* UpcastToSimArmy(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSimArmyType());
    return static_cast<moho::SimArmy*>(upcast.mObj);
  }

  /**
   * Address: 0x00585460 (FUN_00585460, gpg::RRef::Upcast_CAiPersonality)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAiPersonality`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAiPersonality* UpcastToCAiPersonality(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiPersonalityType());
    return static_cast<moho::CAiPersonality*>(upcast.mObj);
  }

  /**
   * Address: 0x005943C0 (FUN_005943C0, gpg::RRef::Upcast_CAiBrain)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAiBrain`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAiBrain* UpcastToCAiBrain(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiBrainType());
    return static_cast<moho::CAiBrain*>(upcast.mObj);
  }

  /**
   * Address: 0x0059EB00 (FUN_0059EB00, gpg::RRef::Upcast_IFormationInstance)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IFormationInstance`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::IFormationInstance* UpcastToIFormationInstance(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIFormationInstanceType());
    return static_cast<moho::IFormationInstance*>(upcast.mObj);
  }

  /**
   * Address: 0x005A89B0 (FUN_005A89B0, gpg::RRef::Upcast_Entity)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::Entity`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::Entity* UpcastToEntity(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEntityType());
    return static_cast<moho::Entity*>(upcast.mObj);
  }

  /**
   * Address: 0x005A9A00 (FUN_005A9A00, gpg::RRef::Upcast_CAiPathNavigator)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAiPathNavigator`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAiPathNavigator* UpcastToCAiPathNavigator(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiPathNavigatorType());
    return static_cast<moho::CAiPathNavigator*>(upcast.mObj);
  }

  /**
   * Address: 0x005ACC60 (FUN_005ACC60, gpg::RRef::Upcast_PathQueue)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::PathQueue`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::PathQueue* UpcastToPathQueue(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedPathQueueType());
    return static_cast<moho::PathQueue*>(upcast.mObj);
  }

  /**
   * Address: 0x005B1B90 (FUN_005B1B90, gpg::RRef::Upcast_CAiPathFinder)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAiPathFinder`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAiPathFinder* UpcastToCAiPathFinder(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiPathFinderType());
    return static_cast<moho::CAiPathFinder*>(upcast.mObj);
  }

  /**
   * Address: 0x005CE500 (FUN_005CE500, gpg::RRef::Upcast_CInfluenceMap)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CInfluenceMap`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CInfluenceMap* UpcastToCInfluenceMap(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCInfluenceMapType());
    return static_cast<moho::CInfluenceMap*>(upcast.mObj);
  }

  /**
   * Address: 0x005D1710 (FUN_005D1710, gpg::RRef::Upcast_UnitWeapon)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::UnitWeapon`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::UnitWeapon* UpcastToUnitWeapon(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitWeaponType());
    return static_cast<moho::UnitWeapon*>(upcast.mObj);
  }

  /**
   * Address: 0x005D1C30 (FUN_005D1C30, gpg::RRef::Upcast_CEconRequest)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CEconRequest`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CEconRequest* UpcastToCEconRequest(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconRequestType());
    return static_cast<moho::CEconRequest*>(upcast.mObj);
  }

  /**
   * Address: 0x005D5280 (FUN_005D5280, gpg::RRef::Upcast_CAiPathSpline)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAiPathSpline`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAiPathSpline* UpcastToCAiPathSpline(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiPathSplineType());
    return static_cast<moho::CAiPathSpline*>(upcast.mObj);
  }

  /**
   * Address: 0x005D52C0 (FUN_005D52C0, gpg::RRef::Upcast_CUnitMotion)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CUnitMotion`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CUnitMotion* UpcastToCUnitMotion(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitMotionType());
    return static_cast<moho::CUnitMotion*>(upcast.mObj);
  }

  /**
   * Address: 0x005E0680 (FUN_005E0680, gpg::RRef::Upcast_CAcquireTargetTask)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAcquireTargetTask`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAcquireTargetTask* UpcastToCAcquireTargetTask(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAcquireTargetTaskType());
    return static_cast<moho::CAcquireTargetTask*>(upcast.mObj);
  }

  /**
   * Address: 0x005F5240 (FUN_005F5240, gpg::RRef::Upcast_CUnitCommand)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CUnitCommand`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CUnitCommand* UpcastToCUnitCommand(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitCommandType());
    return static_cast<moho::CUnitCommand*>(upcast.mObj);
  }

  /**
   * Address: 0x0063D720 (FUN_0063D720, gpg::RRef::Upcast_IAniManipulator)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAniManipulator`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::IAniManipulator* UpcastToIAniManipulator(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAniManipulatorType());
    return static_cast<moho::IAniManipulator*>(upcast.mObj);
  }

  /**
   * Address: 0x0063EDD0 (FUN_0063EDD0, gpg::RRef::Upcast_CAniActor)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CAniActor`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CAniActor* UpcastToCAniActor(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAniActorType());
    return static_cast<moho::CAniActor*>(upcast.mObj);
  }

  /**
   * Address: 0x006587A0 (FUN_006587A0, gpg::RRef::Upcast_IEffect)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IEffect`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::IEffect* UpcastToIEffect(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIEffectType());
    return static_cast<moho::IEffect*>(upcast.mObj);
  }

  /**
   * Address: 0x0065AF60 (FUN_0065AF60, gpg::RRef::Upcast_CParticleTexture)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CParticleTexture`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CParticleTexture* UpcastToCParticleTexture(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCParticleTextureType());
    return static_cast<moho::CParticleTexture*>(upcast.mObj);
  }

  /**
   * Address: 0x00671140 (FUN_00671140, gpg::RRef::Upcast_CDecalHandle)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CDecalHandle`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CDecalHandle* UpcastToCDecalHandle(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCDecalHandleType());
    return static_cast<moho::CDecalHandle*>(upcast.mObj);
  }

  /**
   * Address: 0x00680F10 (FUN_00680F10, gpg::RRef::Upcast_PositionHistory)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::PositionHistory`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::PositionHistory* UpcastToPositionHistory(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedPositionHistoryType());
    return static_cast<moho::PositionHistory*>(upcast.mObj);
  }

  /**
   * Address: 0x006831F0 (FUN_006831F0, gpg::RRef::Upcast_CColPrimitiveBase)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CColPrimitiveBase`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CColPrimitiveBase* UpcastToCColPrimitiveBase(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCColPrimitiveBaseType());
    return static_cast<moho::CColPrimitiveBase*>(upcast.mObj);
  }

  /**
   * Address: 0x006833E0 (FUN_006833E0, gpg::RRef::Upcast_CIntel)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CIntel`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CIntel* UpcastToCIntel(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCIntelType());
    return static_cast<moho::CIntel*>(upcast.mObj);
  }

  /**
   * Address: 0x006835C0 (FUN_006835C0, gpg::RRef::Upcast_CTextureScroller)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CTextureScroller`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CTextureScroller* UpcastToCTextureScroller(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTextureScrollerType());
    return static_cast<moho::CTextureScroller*>(upcast.mObj);
  }

  /**
   * Address: 0x006837A0 (FUN_006837A0, gpg::RRef::Upcast_SPhysBody)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::SPhysBody`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::SPhysBody* UpcastToSPhysBody(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSPhysBodyType());
    return static_cast<moho::SPhysBody*>(upcast.mObj);
  }

  /**
   * Address: 0x00683980 (FUN_00683980, gpg::RRef::Upcast_Motor)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::Motor`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::Motor* UpcastToMotor(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedMotorType());
    return static_cast<moho::Motor*>(upcast.mObj);
  }

  /**
   * Address: 0x006E07A0 (FUN_006E07A0, gpg::RRef::Upcast_CFireWeaponTask)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CFireWeaponTask`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CFireWeaponTask* UpcastToCFireWeaponTask(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCFireWeaponTaskType());
    return static_cast<moho::CFireWeaponTask*>(upcast.mObj);
  }

  /**
   * Address: 0x00707600 (FUN_00707600, gpg::RRef::Upcast_IAiReconDB)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiReconDB`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiReconDB* UpcastToIAiReconDB(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiReconDBType());
    return static_cast<moho::IAiReconDB*>(upcast.mObj);
  }

  /**
   * Address: 0x007077F0 (FUN_007077F0, gpg::RRef::Upcast_CEconomy)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CEconomy`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CEconomy* UpcastToCEconomy(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconomyType());
    return static_cast<moho::CEconomy*>(upcast.mObj);
  }

  /**
   * Address: 0x007079D0 (FUN_007079D0, gpg::RRef::Upcast_CArmyStats)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CArmyStats`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CArmyStats* UpcastToCArmyStats(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCArmyStatsType());
    return static_cast<moho::CArmyStats*>(upcast.mObj);
  }

  /**
   * Address: 0x007149D0 (FUN_007149D0, gpg::RRef::Upcast_CArmyStatItem)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CArmyStatItem`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CArmyStatItem* UpcastToCArmyStatItem(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCArmyStatItemType());
    return static_cast<moho::CArmyStatItem*>(upcast.mObj);
  }

  /**
   * Address: 0x0072B0E0 (FUN_0072B0E0, gpg::RRef::Upcast_CSquad)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CSquad`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CSquad* UpcastToCSquad(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCSquadType());
    return static_cast<moho::CSquad*>(upcast.mObj);
  }

  /**
   * Address: 0x00758230 (FUN_00758230, gpg::RRef::Upcast_CRandomStream)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CRandomStream`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CRandomStream* UpcastToCRandomStream(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCRandomStreamType());
    return static_cast<moho::CRandomStream*>(upcast.mObj);
  }

  /**
   * Address: 0x007582B0 (FUN_007582B0, gpg::RRef::Upcast_IAiFormationDB)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IAiFormationDB`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::IAiFormationDB* UpcastToIAiFormationDB(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiFormationDBType());
    return static_cast<moho::IAiFormationDB*>(upcast.mObj);
  }

  /**
   * Address: 0x007586B0 (FUN_007586B0, gpg::RRef::Upcast_CCommandDB)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CCommandDB`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CCommandDb* UpcastToCCommandDb(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCCommandDBType());
    return static_cast<moho::CCommandDb*>(upcast.mObj);
  }

  /**
   * Address: 0x007586F0 (FUN_007586F0, gpg::RRef::Upcast_CDecalBuffer)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CDecalBuffer`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CDecalBuffer* UpcastToCDecalBuffer(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCDecalBufferType());
    return static_cast<moho::CDecalBuffer*>(upcast.mObj);
  }

  /**
   * Address: 0x007588D0 (FUN_007588D0, gpg::RRef::Upcast_IEffectManager)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::IEffectManager`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::IEffectManager* UpcastToIEffectManager(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIEffectManagerType());
    return static_cast<moho::IEffectManager*>(upcast.mObj);
  }

  /**
   * Address: 0x00758AC0 (FUN_00758AC0, gpg::RRef::Upcast_ISoundManager)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::ISoundManager`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::ISoundManager* UpcastToISoundManager(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedISoundManagerType());
    return static_cast<moho::ISoundManager*>(upcast.mObj);
  }

  /**
   * Address: 0x00758CB0 (FUN_00758CB0, gpg::RRef::Upcast_EntityDB)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::EntityDB`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CEntityDb* UpcastToCEntityDb(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEntityDBType());
    return static_cast<moho::CEntityDb*>(upcast.mObj);
  }

  /**
   * Address: 0x0076ED90 (FUN_0076ED90, gpg::RRef::Upcast_CIntelPosHandle)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CIntelPosHandle`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CIntelPosHandle* UpcastToCIntelPosHandle(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCIntelPosHandleType());
    return static_cast<moho::CIntelPosHandle*>(upcast.mObj);
  }

  /**
   * Address: 0x00758270 (FUN_00758270, gpg::RRef::Upcast_SPhysConstants)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::SPhysConstants`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::SPhysConstants* UpcastToSPhysConstants(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedOwnedSPhysConstantsType());
    return static_cast<moho::SPhysConstants*>(upcast.mObj);
  }

  /**
   * Address: 0x0076B6E0 (FUN_0076B6E0, gpg::RRef::Upcast_PathQueueImpl)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::PathQueue::Impl`, returning null
   * when the reference does not denote that type.
   */
  [[nodiscard]] moho::PathQueue::Impl* UpcastToPathQueueImpl(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedPathQueueImplType());
    return static_cast<moho::PathQueue::Impl*>(upcast.mObj);
  }


  [[nodiscard]] gpg::RType* CachedCPlatoonType()
  {
    gpg::RType* type = moho::CPlatoon::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CPlatoon));
      moho::CPlatoon::sType = type;
    }
    return type;
  }

  class BinaryReadArchive final : public gpg::ReadArchive
  {
  public:
    explicit BinaryReadArchive(const boost::shared_ptr<std::FILE>& file)
      : mFile(file)
      , mCachedFile(file.get())
    {
    }

    /**
     * Address: 0x00904810 (FUN_00904810)
     *
     * What it does:
     * Runs non-deleting teardown for one binary-read archive lane, releasing
     * file shared-owner state before base `ReadArchive` destruction.
     */
    ~BinaryReadArchive() override = default;

    /**
     * Address: 0x00904960 (FUN_00904960, gpg::BinaryReadArchive::ReadBytes)
     *
     * What it does:
     * Reads one contiguous byte range from the backing FILE and throws
     * serialization failure on EOF/read errors.
     */
    void ReadBytes(char* const bytes, const size_t byteCount) override
    {
      // Ground truth is exactly this shape, and the details matter:
      //
      //   if (fread(a2, a3, 1u, this->str) != 1) {
      //     if (feof(this->str))  throw runtime_error("eof");
      //     if (ferror(this->str)) throw runtime_error("noread");
      //   }
      //
      // A short read with NEITHER flag set falls out of the branch and
      // returns normally - it is not an error. A zero-length read is not
      // special-cased either: `fread(p, 0, 1, f)` returns 0, so at EOF a
      // 0-byte read throws "eof" here. Both behaviours were lost to an
      // earlier defensive rewrite (null guards, an early return on
      // `byteCount == 0`, and an unconditional throw) that this restores.
      if (std::fread(bytes, byteCount, 1, mCachedFile) == 1) {
        return;
      }

      if (std::feof(mCachedFile) != 0) {
        ThrowSerializationError("eof");
      }

      if (std::ferror(mCachedFile) != 0) {
        ThrowSerializationError("noread");
      }
    }

    /**
     * Address: 0x00905600 (FUN_00905600, BinaryReadArchive::ReadString)
     *
     * What it does:
     * Reads one length-prefixed string payload by first loading a 32-bit byte
     * count, resizing the destination string, and then reading raw bytes.
     */
    void ReadString(msvc8::string* const out) override
    {
      unsigned int byteCount = 0;
      ReadInt2(&byteCount);

      const size_t currentSize = out->size();
      if (byteCount > currentSize) {
        std::string resized = out->to_std();
        resized.resize(byteCount, '\0');
        out->assign_owned(std::string_view(resized.data(), resized.size()));
      } else {
        out->erase(byteCount);
      }

      if (byteCount != 0U) {
        ReadBytes(out->raw_data_mut_unsafe(), byteCount);
      }
    }

    /**
     * Address: 0x009055F0 (FUN_009055F0, BinaryReadArchive::ReadFloat)
     * Address: 0x0098FEC0 (FUN_0098FEC0)
     *
     * What it does:
     * Reads one 32-bit float lane from the binary archive stream.
     */
    void ReadFloat(float* const value) override
    {
      ReadFloat2(value);
    }

    /**
     * Address: 0x009055E0 (FUN_009055E0, BinaryReadArchive::ReadDouble)
     *
     * What it does:
     * Reads one 64-bit primitive lane used by this archive vtable slot.
     */
    void ReadUInt64(unsigned __int64* const value) override
    {
      ReadUInt642(value);
    }

    /**
     * Address: 0x009055D0 (FUN_009055D0, BinaryReadArchive::ReadInt64)
     *
     * What it does:
     * Reads one signed 64-bit primitive lane from the stream.
     */
    void ReadInt64(__int64* const value) override
    {
      ReadInt642(value);
    }

    /**
     * Address: 0x009055C0 (FUN_009055C0, BinaryReadArchive::ReadULong)
     *
     * What it does:
     * Reads one unsigned long lane from the stream.
     */
    void ReadULong(unsigned long* const value) override
    {
      ReadULong2(value);
    }

    /**
     * Address: 0x009055B0 (FUN_009055B0, BinaryReadArchive::ReadLong)
     *
     * What it does:
     * Reads one signed long lane from the stream.
     */
    void ReadLong(long* const value) override
    {
      ReadLong2(value);
    }

    /**
     * Address: 0x009055A0 (FUN_009055A0, BinaryReadArchive::ReadUInt)
     * Address: 0x009C6860 (FUN_009C6860)
     *
     * What it does:
     * Thunk lane that forwards 32-bit primitive reads to `ReadInt2`.
     */
    void ReadUInt(unsigned int* const value) override
    {
      ReadInt2(value);
    }

    /**
     * Address: 0x00905590 (FUN_00905590, BinaryReadArchive::ReadInt)
     *
     * What it does:
     * Thunk lane forwarding signed 32-bit reads to `ReadUInt2`.
     */
    void ReadInt(int* const value) override
    {
      ReadUInt2(value);
    }

    /**
     * Address: 0x00905580 (FUN_00905580, BinaryReadArchive::ReadUShort)
     *
     * What it does:
     * Reads one unsigned 16-bit primitive lane from the stream.
     */
    void ReadUShort(unsigned short* const value) override
    {
      ReadUShort2(value);
    }

    /**
     * Address: 0x00905570 (FUN_00905570, BinaryReadArchive::ReadShort)
     *
     * What it does:
     * Reads one signed 16-bit primitive lane from the stream.
     */
    void ReadShort(short* const value) override
    {
      ReadShort2(value);
    }

    /**
     * Address: 0x00905560 (FUN_00905560, BinaryReadArchive::ReadUByte)
     *
     * What it does:
     * Reads one unsigned byte lane through the shared one-byte read helper.
     */
    void ReadUByte(unsigned __int8* const value) override
    {
      ReadUByte2(value);
    }

    /**
     * Address: 0x00905550 (FUN_00905550, BinaryReadArchive::ReadByte)
     *
     * What it does:
     * Reads one signed byte lane through the shared one-byte read helper.
     */
    void ReadByte(__int8* const value) override
    {
      ReadByte2(value);
    }

    /**
     * Address: 0x00905540 (FUN_00905540, BinaryReadArchive::ReadBool)
     *
     * What it does:
     * Thunk lane forwarding bool reads to `ReadBool2`.
     */
    void ReadBool(bool* const value) override
    {
      ReadBool2(value);
    }

    /**
     * Address: 0x00905670 (FUN_00905670, BinaryReadArchive::NextToken)
     *
     * What it does:
     * Reads one marker byte and maps lexical archive tokens (`} N 0 * {`) to
     * runtime `ArchiveToken` integers; throws on unknown marker bytes.
     */
    int NextMarker() override
    {
      signed char marker = 0;
      ReadBool2(&marker);

      switch (marker) {
      case '}':
        return static_cast<int>(ArchiveToken::ObjectTerminator);
      case 'N':
        return static_cast<int>(ArchiveToken::NewObjectToken);
      case '0':
        return static_cast<int>(ArchiveToken::NullPointerToken);
      case '*':
        return static_cast<int>(ArchiveToken::ExistingPointerToken);
      case '{':
        return static_cast<int>(ArchiveToken::ObjectStart);
      default:
        ThrowSerializationError(
          STR_Printf("Error detected in archive: invalid marker token 0x%02x", static_cast<int>(marker))
        );
      }
    }

  private:
    /**
     * Address: 0x00904AB0 (FUN_00904AB0, BinaryReadArchive::ReadBool2)
     *
     * What it does:
     * Reads one byte lane from the backing FILE and throws
     * `SerializationError("eof")`/`SerializationError("noread")` on stream
     * failure states.
     */
    void ReadBool2(void* const outValue)
    {
      std::FILE* const file = mCachedFile;
      if (std::fread(outValue, 1u, 1u, file) != 1) {
        if (std::feof(file) != 0) {
          ThrowSerializationError("eof");
        }

        if (std::ferror(file) != 0) {
          ThrowSerializationError("noread");
        }
      }
    }

    /**
     * Address: 0x00904B40 (FUN_00904B40)
     *
     * What it does:
     * One-byte signed lane helper used by `ReadByte`.
     */
    void ReadByte2(void* const outValue)
    {
      ReadBool2(outValue);
    }

    /**
     * Address: 0x00904BD0 (FUN_00904BD0)
     *
     * What it does:
     * One-byte unsigned lane helper used by `ReadUByte`.
     */
    void ReadUByte2(void* const outValue)
    {
      ReadBool2(outValue);
    }

    /**
     * Address: 0x00904C60 (FUN_00904C60)
     *
     * What it does:
     * Two-byte signed lane helper used by `ReadShort`.
     */
    void ReadShort2(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(short));
    }

    /**
     * Address: 0x00904CF0 (FUN_00904CF0)
     *
     * What it does:
     * Two-byte unsigned lane helper used by `ReadUShort`.
     */
    void ReadUShort2(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(unsigned short));
    }

    /**
     * Address: 0x00904D80 (FUN_00904D80, BinaryReadArchive::ReadUInt2)
     *
     * What it does:
     * Reads one 32-bit lane directly from the backing FILE and throws
     * `SerializationError("eof")`/`SerializationError("noread")` on stream
     * failure states.
     */
    void ReadUInt2(void* const outValue)
    {
      std::FILE* const file = mCachedFile;
      if (std::fread(outValue, 4u, 1u, file) != 1) {
        if (std::feof(file) != 0) {
          ThrowSerializationError("eof");
        }

        if (std::ferror(file) != 0) {
          ThrowSerializationError("noread");
        }
      }
    }

    /**
     * Address: 0x00904E10 (FUN_00904E10, BinaryReadArchive::ReadInt2)
     *
     * What it does:
     * Thunk lane forwarding 32-bit primitive reads to `ReadUInt2`.
     */
    void ReadInt2(void* const outValue)
    {
      ReadUInt2(outValue);
    }

    /**
     * Address: 0x00904EA0 (FUN_00904EA0)
     *
     * What it does:
     * Signed long lane helper used by `ReadLong`.
     */
    void ReadLong2(void* const outValue)
    {
      ReadUInt2(outValue);
    }

    /**
     * Address: 0x00904F30 (FUN_00904F30)
     *
     * What it does:
     * Unsigned long lane helper used by `ReadULong`.
     */
    void ReadULong2(void* const outValue)
    {
      ReadUInt2(outValue);
    }

    /**
     * Address: 0x00904FC0 (FUN_00904FC0)
     *
     * What it does:
     * Signed 64-bit lane helper used by `ReadInt64`.
     */
    void ReadInt642(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(__int64));
    }

    /**
     * Address: 0x00905050 (FUN_00905050)
     *
     * What it does:
     * 64-bit lane helper used by the vtable slot recovered as `ReadUInt64`.
     */
    void ReadUInt642(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(unsigned __int64));
    }

    /**
     * Address: 0x009050E0 (FUN_009050E0)
     *
     * What it does:
     * 32-bit float lane helper used by `ReadFloat`.
     */
    void ReadFloat2(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(float));
    }

    // `gpg::CreateBinaryReadArchive` (0x009048B0) allocates 0x44 and sets
    // three members in this order: the shared owner's `px` at +0x38 and
    // `pn.pi_` at +0x3C, then a plain duplicate of the same handle at +0x40.
    // Every read slot dereferences that duplicate rather than the smart
    // pointer -- `BinaryReadArchive::ReadBytes` (0x00904960) is
    // `fread(..., this->str)`, and its `feof`/`ferror` retries use it too.
    // Keeping it is what makes this class 0x44 rather than 0x40.
    boost::shared_ptr<std::FILE> mFile;   // +0x38
    std::FILE* mCachedFile = nullptr;     // +0x40
  };

  static_assert(sizeof(BinaryReadArchive) == 0x44, "BinaryReadArchive size must be 0x44");

  /**
   * Address: 0x00904890 (FUN_00904890)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `BinaryReadArchive`, forwarding
   * through non-deleting teardown and optional storage release.
   */
  [[nodiscard]] BinaryReadArchive* DestroyBinaryReadArchiveDeleting(
    BinaryReadArchive* const archive,
    const unsigned char deleteFlag
  )
  {
    archive->~BinaryReadArchive();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(archive));
    }
    return archive;
  }

  struct TextReadArchiveRuntimeView
  {
    std::uint8_t pad_0000_0038[0x38];
    std::istream* streamOwnerPx;              // +0x38 (boost::shared_ptr<std::istream>::px)
    boost::detail::sp_counted_base* control;  // +0x3C (boost::shared_ptr<std::istream>::pn.pi_)
    std::istream* stream;                     // +0x40 (raw cached copy for hot Read* paths)
  };
  static_assert(
    offsetof(TextReadArchiveRuntimeView, streamOwnerPx) == 0x38,
    "TextReadArchiveRuntimeView::streamOwnerPx offset must be 0x38"
  );
  static_assert(
    offsetof(TextReadArchiveRuntimeView, control) == 0x3C,
    "TextReadArchiveRuntimeView::control offset must be 0x3C"
  );
  static_assert(
    offsetof(TextReadArchiveRuntimeView, stream) == 0x40,
    "TextReadArchiveRuntimeView::stream offset must be 0x40"
  );
  static_assert(sizeof(TextReadArchiveRuntimeView) == 0x44, "TextReadArchiveRuntimeView size must be 0x44");

  class TextReadArchive : public gpg::ReadArchive
  {
  public:
    /**
     * Address: 0x00939330 (FUN_00939330, ??0TextReadArchive@@QAE@ABV?$shared_ptr@Vistream@std@@@boost@@@Z)
     * Mangled: ??0TextReadArchive@@QAE@ABV?$shared_ptr@Vistream@std@@@boost@@@Z
     *
     * IDA signature:
     * TextReadArchive *__thiscall TextReadArchive::TextReadArchive(TextReadArchive *this, boost::shared_ptr_istream *a2);
     *
     * What it does:
     * Runs `gpg::ReadArchive` base construction, installs the
     * `TextReadArchive` vtable, then copies the caller's
     * `boost::shared_ptr<std::istream>` into the owning slot (retaining its
     * control block via `add_ref_copy()`) and caches the raw
     * `std::istream*` separately for the hot `Read*` accessor paths.
     * Finishes by clearing the stream's error state via
     * `std::ios_base::clear`.
     */
    explicit TextReadArchive(const boost::shared_ptr<std::istream>& stream)
      : gpg::ReadArchive()
    {
      // `boost::shared_ptr<T>` has the same {px, pi} layout as this
      // codebase's `SharedPtrRaw<T>` (see BoostWrappers.h) on this VC8-era
      // Boost; reinterpret to pull the raw owning pointers into the
      // already-established byte-offset fields the sibling `Read*` methods
      // and destructor expect (see `TextReadArchiveRuntimeView`).
      const auto& raw = reinterpret_cast<const boost::SharedPtrRaw<std::istream>&>(stream);
      auto* const runtime = reinterpret_cast<TextReadArchiveRuntimeView*>(this);
      runtime->streamOwnerPx = raw.px;
      boost::detail::sp_counted_base* const control = raw.pi;
      runtime->control = control;
      if (control != nullptr) {
        control->add_ref_copy();
      }
      runtime->stream = raw.px;
      runtime->stream->clear();
    }

    /**
     * Address: 0x00939700 (FUN_00939700, ??1TextReadArchive@@QAE@@Z)
     *
     * What it does:
     * Releases the stream shared-control lane and then runs
     * `gpg::ReadArchive` base destruction.
     */
    ~TextReadArchive() override
    {
      auto* const runtime = reinterpret_cast<TextReadArchiveRuntimeView*>(this);
      boost::detail::sp_counted_base* const control = runtime->control;
      runtime->streamOwnerPx = nullptr;
      runtime->stream = nullptr;
      runtime->control = nullptr;
      if (control != nullptr) {
        control->release();
      }
    }

    /**
     * Address: 0x0093E770 (FUN_0093E770, TextReadArchive::ReadDouble)
     *
     * What it does:
     * Extracts one unsigned 64-bit token from the text stream lane.
     */
    void ReadUInt64(unsigned __int64* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E760 (FUN_0093E760, TextReadArchive::ReadInt64)
     *
     * What it does:
     * Extracts one signed 64-bit token from the text stream lane.
     */
    void ReadInt64(__int64* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E750 (FUN_0093E750, TextReadArchive::ReadULong)
     *
     * What it does:
     * Extracts one unsigned long token from the text stream lane.
     */
    void ReadULong(unsigned long* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E740 (FUN_0093E740, TextReadArchive::ReadLong)
     *
     * What it does:
     * Extracts one signed long primitive from the text stream lane.
     */
    void ReadLong(long* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E730 (FUN_0093E730, TextReadArchive::ReadUInt)
     *
     * What it does:
     * Extracts one unsigned 32-bit primitive from the text stream lane.
     */
    void ReadUInt(unsigned int* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E720 (FUN_0093E720, TextReadArchive::ReadInt)
     *
     * What it does:
     * Extracts one signed 32-bit primitive from the text stream lane.
     */
    void ReadInt(int* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E710 (FUN_0093E710, TextReadArchive::ReadUShort)
     *
     * What it does:
     * Extracts one unsigned 16-bit primitive from the text stream lane.
     */
    void ReadUShort(unsigned short* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E700 (FUN_0093E700, TextReadArchive::ReadShort)
     *
     * What it does:
     * Extracts one signed 16-bit primitive from the text stream lane.
     */
    void ReadShort(short* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093E6E0 (FUN_0093E6E0, TextReadArchive::ReadUByte)
     *
     * What it does:
     * Reads one integer token from the text stream and truncates it to the low
     * unsigned-byte lane.
     */
    void ReadUByte(unsigned __int8* const value) override
    {
      int parsedValue = 0;
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> parsedValue;
      *value = static_cast<unsigned __int8>(parsedValue);
    }

    /**
     * Address: 0x0093E6C0 (FUN_0093E6C0, TextReadArchive::ReadByte)
     *
     * What it does:
     * Reads one integer token from the text stream and truncates it to the low
     * signed-byte lane.
     */
    void ReadByte(__int8* const value) override
    {
      int parsedValue = 0;
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> parsedValue;
      *value = static_cast<__int8>(parsedValue);
    }

    /**
     * Address: 0x0093E6B0 (FUN_0093E6B0, TextReadArchive::ReadBool)
     *
     * What it does:
     * Extracts one bool token from the text archive stream lane.
     */
    void ReadBool(bool* const value) override
    {
      (*reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream) >> *value;
    }

    /**
     * Address: 0x0093B760 (FUN_0093B760, TextReadArchive::ReadBytes)
     *
     * What it does:
     * Reads `byteCount` raw bytes from the text stream, one whitespace-separated
     * hexadecimal token per byte.
     */
    void ReadBytes(char* const bytes, const size_t byteCount) override
    {
      std::istream& stream = *reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream;
      std::string token;
      for (size_t index = 0; index < byteCount; ++index) {
        stream >> token;
        bytes[index] = static_cast<char>(gpg::STR_Xtoi(token.c_str()));
      }
    }

    /**
     * Address: 0x0093ECE0 (FUN_0093ECE0, TextReadArchive::ReadFloat)
     *
     * What it does:
     * Reads one float token; the sentinel text "1.#INF" decodes to +infinity,
     * otherwise the token is parsed as a floating-point value.
     */
    void ReadFloat(float* const value) override
    {
      std::istream& stream = *reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream;
      std::string token;
      stream >> token;
      if (token != "1.#INF") {
        std::istringstream parser(token);
        parser >> *value;
      } else {
        *value = std::numeric_limits<float>::infinity();
      }
    }

    /**
     * Address: 0x0093E780 (FUN_0093E780, TextReadArchive::ReadString)
     *
     * What it does:
     * Parses one double-quoted string primitive, decoding backslash escapes
     * (`\n`, `\t`, `\"`, `\\`, and up to 3-digit octal `\NNN`) into `out`.
     * Throws SerializationError on a malformed or truncated primitive.
     */
    void ReadString(msvc8::string* const out) override
    {
      std::istream& stream = *reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream;
      stream >> std::ws;
      if (stream.get() != '"') {
        ThrowSerializationError("Error detected in archive: malformed string primitive.");
      }

      std::string decoded;
      int ch = stream.get();
      if (ch == std::char_traits<char>::eof()) {
        ThrowSerializationError("Error detected in archive: malformed string primitive.");
      }

      while (ch != '"') {
        if (ch == '\\') {
          const int escape = stream.get();
          switch (escape) {
            case 'n': decoded.push_back('\n'); break;
            case 't': decoded.push_back('\t'); break;
            case '"': decoded.push_back('"'); break;
            case '\\': decoded.push_back('\\'); break;
            default: {
              if (escape < '0' || escape > '7') {
                ThrowSerializationError("Error detected in archive: malformed string primitive.");
              }
              int octalValue = escape - '0';
              int extraDigits = 0;
              while (true) {
                const int next = stream.get();
                if (next < '0' || next > '7') {
                  stream.putback(static_cast<char>(next));
                  decoded.push_back(static_cast<char>(octalValue));
                  break;
                }
                octalValue = octalValue * 8 + (next - '0');
                if (++extraDigits >= 2) {
                  decoded.push_back(static_cast<char>(octalValue));
                  break;
                }
              }
              break;
            }
          }
        } else {
          decoded.push_back(static_cast<char>(ch));
        }

        ch = stream.get();
        if (ch == std::char_traits<char>::eof()) {
          ThrowSerializationError("Error detected in archive: malformed string primitive.");
        }
      }

      out->assign_owned(std::string_view(decoded.data(), decoded.size()));
    }

    /**
     * Address: 0x0093B810 (FUN_0093B810, TextReadArchive::NextMarker)
     *
     * What it does:
     * Reads one section-marker token from the text stream and maps it to the
     * archive marker code (`N`=1, `0`=2, `*`=3, `{`=4, `}`=0); throws on any
     * other character.
     */
    int NextMarker() override
    {
      std::istream& stream = *reinterpret_cast<TextReadArchiveRuntimeView*>(this)->stream;
      char marker = 0;
      stream >> marker;
      switch (marker) {
        case 'N': return 1;
        case '0': return 2;
        case '*': return 3;
        case '{': return 4;
        case '}': return 0;
        default:
          ThrowSerializationError(
            gpg::STR_Printf("Error detected in archive: invalid marker token 0x%02x", marker).c_str());
      }
    }
  };

  /**
   * Address: 0x009397E0 (FUN_009397E0, TextReadArchive::dtr)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `TextReadArchive`, forwarding
   * through non-deleting teardown and optional storage release.
   */
  [[maybe_unused]] [[nodiscard]] TextReadArchive* DestroyTextReadArchiveDeleting(
    TextReadArchive* const archive,
    const unsigned char deleteFlag
  )
  {
    archive->~TextReadArchive();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(archive));
    }
    return archive;
  }

  /**
   * Address: 0x00952C90 (FUN_00952C90)
   *
   * What it does:
   * Appends one reflected `TypeHandle` lane to the archive-local handle table,
   * preserving the in-capacity fast path and vector-growth fallback behavior.
   */
  TypeHandle* AppendTypeHandle(msvc8::vector<TypeHandle>& typeHandles, const TypeHandle& handle)
  {
    const std::size_t insertIndex = typeHandles.size();
    typeHandles.push_back(handle);
    return &typeHandles[insertIndex];
  }
} // namespace

/**
 * Address: 0x00939800 (FUN_00939800, ?CreateTextReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@Vistream@std@@@boost@@@Z)
 * Mangled: ?CreateTextReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@Vistream@std@@@boost@@@Z
 *
 * IDA signature:
 * gpg::ReadArchive *__cdecl gpg::CreateTextReadArchive(boost::shared_ptr_istream *a1);
 *
 * What it does:
 * Heap-allocates and constructs one `TextReadArchive` bound to the given
 * input stream, returning it through the polymorphic `gpg::ReadArchive*`
 * factory interface. Returns `nullptr` if allocation fails.
 */
ReadArchive* gpg::CreateTextReadArchive(const boost::shared_ptr<std::istream>& stream)
{
  // Binary: `push 44h` before `operator new` (0x00939816-0x00939818), not
  // sizeof(TextReadArchive). TextReadArchive declares no fields of its own -
  // every byte of its real state lives in TextReadArchiveRuntimeView, whose
  // last field (`stream`) ends at +0x44 - while its base `gpg::ReadArchive`
  // (and therefore TextReadArchive itself) is only 0x38 bytes. Allocating
  // sizeof(TextReadArchive) here silently overflowed the block by 12 bytes on
  // every text-archive construction, corrupting whatever the allocator handed
  // out next to it.
  void* const storage = ::operator new(0x44u, std::nothrow);
  if (storage == nullptr) {
    return nullptr;
  }
  return new (storage) TextReadArchive(stream);
}

/**
 * Address: 0x00952B60 (FUN_00952B60, ??0ReadArchive@gpg@@QAE@XZ)
 *
 * What it does:
 * Initializes read-archive type/pointer tracking lanes and refreshes global
 * serializer helper registrations used by reflection load paths.
 */
ReadArchive::ReadArchive()
  : mTypeHandles()
  , mTrackedPtrs()
  , mNullTrackedPointer{}
{
  mNullTrackedPointer.object = nullptr;
  mNullTrackedPointer.type = nullptr;
  mNullTrackedPointer.sharedObject = nullptr;
  mNullTrackedPointer.sharedControl = nullptr;
  mNullTrackedPointer.state = TrackedPointerState::Reserved;
  SerHelperBase::InitNewHelpers();
}

/**
 * Address: 0x00952E40 (FUN_00952E40, ??1ReadArchive@gpg@@UAE@XZ)
 * Address: 0x00953700 (FUN_00953700, scalar deleting destructor thunk)
 *
 * What it does:
 * Destroys read-archive bookkeeping state. Binary body is the compiler-emitted
 * defaulted destructor (sets vtable + member subobject teardown).
 */
ReadArchive::~ReadArchive() = default;

/**
 * Address: 0x00952F10 (FUN_00952F10)
 * Demangled: gpg::ReadArchive::ReadTypeHandle
 *
 * What it does:
 * Reads or resolves reflected type/version handle from archive token stream.
 */
TypeHandle ReadArchive::ReadTypeHandle()
{
  int index = 0;
  ReadInt(&index);

  if (index == -1) {
    msvc8::string typeName;
    ReadString(&typeName);

    RType* type = REF_FindTypeNamed(typeName.c_str());
    if (!type) {
      ThrowSerializationError(STR_Printf("No type named \"%s\"", typeName.c_str()));
    }

    int version = 0;
    ReadInt(&version);

    TypeHandle handle{};
    handle.type = type;
    handle.version = version;
    static_cast<void>(AppendTypeHandle(mTypeHandles, handle));
    return handle;
  }

  if (index < 0 || static_cast<size_t>(index) >= mTypeHandles.size()) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found a reference to type index %d, but only %d types have been mentioned.",
      index,
      static_cast<int>(mTypeHandles.size())
    ));
  }

  return mTypeHandles[static_cast<size_t>(index)];
}

/**
 * Address: 0x00953DA0 (FUN_00953DA0)
 * Demangled: public: void __thiscall gpg::ReadArchive::Read(class gpg::RType const *,void *,class gpg::RRef const &)
 *
 * What it does:
 * Reads one typed object payload using reflection serializer callbacks.
 */
void ReadArchive::Read(const RType* const type, void* const object, const RRef& ownerRef)
{
  if (!type->serLoadFunc_) {
    const RIndexed* pointerType = type->IsPointer();
    if (pointerType) {
      const TrackedPointerInfo tracked = ReadRawPointer(this, ownerRef);
      RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      pointerType->AssignPointer(object, source);
      return;
    }

    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but we don't have a loader for it.",
      SafeTypeName(type)
    ));
  }

  const int marker = NextMarker();
  if (marker != static_cast<int>(ArchiveToken::ObjectStart)) {
    ArchiveToken tokenCopy = static_cast<ArchiveToken>(marker);
    const RRef tokenRef = RRef_ArchiveToken(&tokenCopy);
    const msvc8::string tokenLexical = tokenRef.mType ? tokenRef.GetLexical() : STR_Printf("%d", marker);
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected an OBJECT_START token marking the beginning of a \"%s\", but got a %s "
      "instead.",
      SafeTypeName(type),
      tokenLexical.c_str()
    ));
  }

  const TypeHandle handle = ReadTypeHandle();
  if (handle.type != type) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but expected one of \"%s\".",
      SafeTypeName(handle.type),
      SafeTypeName(type)
    ));
  }

  type->serLoadFunc_(this, reinterpret_cast<int>(object), handle.version, const_cast<RRef*>(&ownerRef));

  if (NextMarker() != static_cast<int>(ArchiveToken::ObjectTerminator)) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: data for object of type \"%s\" did not terminate properly.", SafeTypeName(type)
    ));
  }
}

/**
 * Address: 0x0072ACD0 (FUN_0072ACD0, gpg::ReadArchive::ReadPointerOwned_CSquad)
 *
 * IDA signature:
 * gpg::ReadArchive* __userpurge ReadPointerOwned_CSquad@<eax>(
 *     moho::CSquad** outValue@<ecx>, gpg::ReadArchive* this@<ebx>, const gpg::RRef* ownerRef);
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CSquad`.
 *
 * Callsite evidence (per CLAUDE.md callsite verification rule):
 *  - code xref from sub_72A210 (FUN_0072A210) at 0x0072A22B (in src/sdk/moho/sim/CPlatoon.cpp)
 *  - code xref from sub_72A210 (FUN_0072A210) at 0x0072A276
 */
ReadArchive* ReadArchive::ReadPointerOwned_CSquad(moho::CSquad** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCSquad(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCSquadType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CSquad",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0040B530 (FUN_0040B530, gpg::ReadArchive::ReadPointerOwned_CTask)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CTask`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CTask(moho::CTask** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskType());
  *outValue = static_cast<moho::CTask*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCTaskType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CTask",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0040B640 (FUN_0040B640, gpg::ReadArchive::ReadPointer_CTask)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CTask`,
 * raising `SerializationError` when the pointer is not CTask-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CTask(moho::CTask** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskType());
  *outValue = static_cast<moho::CTask*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCTaskType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CTask",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0040B800 (FUN_0040B800, gpg::ReadArchive::ReadPointerOwned_CTaskThread)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CTaskThread`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CTaskThread(moho::CTaskThread** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskThreadType());
  *outValue = static_cast<moho::CTaskThread*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCTaskThreadType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CTaskThread",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0040C4A0 (FUN_0040C4A0, gpg::ReadArchive::ReadPointer_CTaskThread)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CTaskThread`,
 * raising `SerializationError` when the pointer is not
 * CTaskThread-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CTaskThread(moho::CTaskThread** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskThreadType());
  *outValue = static_cast<moho::CTaskThread*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCTaskThreadType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CTaskThread",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0040D650 (FUN_0040D650, gpg::ReadArchive::ReadPointer_CTaskStage)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CTaskStage`,
 * raising `SerializationError` when the pointer is not
 * CTaskStage-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CTaskStage(moho::CTaskStage** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskStageType());
  *outValue = static_cast<moho::CTaskStage*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCTaskStageType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CTaskStage",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0041A3D0 (FUN_0041A3D0, gpg::ReadArchive::ReadPointerOwned_StatItem)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::StatItem`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_StatItem(moho::StatItem** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedStatItemType());
  *outValue = static_cast<moho::StatItem*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedStatItemType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "StatItem",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x004081E0 (FUN_004081E0, gpg::ReadArchive::ReadPointer_STaskEventLinkage)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::STaskEventLinkage`, raising `SerializationError` when the pointer
 * is not STaskEventLinkage-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_STaskEventLinkage(
  moho::STaskEventLinkage** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTaskEventLinkageType());
  *outValue = static_cast<moho::STaskEventLinkage*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedSTaskEventLinkageType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "STaskEventLinkage",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00407A50 (FUN_00407A50, gpg::ReadArchive::ReadPointerOwned_STaskEventLinkage)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::STaskEventLinkage`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_STaskEventLinkage(
  moho::STaskEventLinkage** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTaskEventLinkageType());
  *outValue = static_cast<moho::STaskEventLinkage*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedSTaskEventLinkageType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "STaskEventLinkage",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x004C1520 (FUN_004C1520, gpg::ReadArchive::ReadPointer_LuaState)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `LuaPlus::LuaState`,
 * raising `SerializationError` when the pointer is not LuaState-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_LuaState(LuaPlus::LuaState** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  LuaPlus::LuaState* const asState = source.CastLuaState();
  *outValue = asState;
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaStateType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "LuaState",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x004CC550 (FUN_004CC550, gpg::ReadArchive::ReadPointerOwned_LuaState)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `LuaPlus::LuaState`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_LuaState(LuaPlus::LuaState** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  *outValue = source.CastLuaState();
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedLuaStateType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "LuaState",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0090BA60 (FUN_0090BA60, gpg::ReadArchive::ReadPointer_lua_State)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to C Lua `lua_State`,
 * raising `SerializationError` when the pointer is not
 * lua_State-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_lua_State(lua_State** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaCStateType());
  *outValue = static_cast<lua_State*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaCStateType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "lua_State",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00921950 (FUN_00921950, gpg::ReadArchive::ReadPointer_Table)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to Lua `Table`,
 * raising `SerializationError` when the pointer is not
 * Table-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Table(Table** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaTableType());
  *outValue = static_cast<Table*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaTableType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Table",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00921830 (FUN_00921830, gpg::ReadArchive::ReadPointer_TString)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to Lua `TString`,
 * raising `SerializationError` when the pointer is not
 * TString-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_TString(TString** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaTStringType());
  *outValue = static_cast<TString*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaTStringType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "TString",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00921A70 (FUN_00921A70, gpg::ReadArchive::ReadPointer_LClosure)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to Lua `LClosure`,
 * raising `SerializationError` when the pointer is not
 * LClosure-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_LClosure(LClosure** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaLClosureType());
  *outValue = static_cast<LClosure*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaLClosureType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "LClosure",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00921B90 (FUN_00921B90, gpg::ReadArchive::ReadPointer_Udata)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to Lua `Udata`,
 * raising `SerializationError` when the pointer is not
 * Udata-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Udata(Udata** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaUdataType());
  *outValue = static_cast<Udata*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaUdataType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Udata",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00921CB0 (FUN_00921CB0, gpg::ReadArchive::ReadPointer_Proto)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to Lua `Proto`,
 * raising `SerializationError` when the pointer is not
 * Proto-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Proto(Proto** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaProtoType());
  *outValue = static_cast<Proto*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaProtoType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Proto",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00921DD0 (FUN_00921DD0, gpg::ReadArchive::ReadPointer_UpVal)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to Lua `UpVal`,
 * raising `SerializationError` when the pointer is not
 * UpVal-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_UpVal(UpVal** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaUpValType());
  *outValue = static_cast<UpVal*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaUpValType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "UpVal",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x004E63A0 (FUN_004E63A0, gpg::ReadArchive::ReadPointer_CSndParams)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CSndParams`,
 * raising `SerializationError` when the pointer is not
 * CSndParams-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CSndParams(moho::CSndParams** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCSndParamsType());
  *outValue = static_cast<moho::CSndParams*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCSndParamsType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CSndParams",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0055A920 (FUN_0055A920, gpg::ReadArchive::ReadPointer_CSndParams2)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CSndParams`,
 * raising `SerializationError` when the pointer is not
 * CSndParams-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CSndParams2(moho::CSndParams** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCSndParamsType2());
  *outValue = static_cast<moho::CSndParams*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCSndParamsType2());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CSndParams",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x004E64E0 (FUN_004E64E0, gpg::ReadArchive::ReadPointer_HSound)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::HSound`,
 * raising `SerializationError` when the pointer is not HSound-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_HSound(moho::HSound** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedHSoundType());
  *outValue = static_cast<moho::HSound*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedHSoundType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "HSound",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00511790 (FUN_00511790, gpg::ReadArchive::ReadPointer_RRuleGameRules2)
 * Address: 0x005375C0 (FUN_005375C0, alias/duplicate body)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::RRuleGameRules`,
 * raising `SerializationError` when the pointer is not
 * RRuleGameRules-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RRuleGameRules(
  moho::RRuleGameRules** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRRuleGameRulesType());
  *outValue = static_cast<moho::RRuleGameRules*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRRuleGameRulesType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RRuleGameRules",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00554E80 (FUN_00554E80, gpg::ReadArchive::ReadPointer_REntityBlueprint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::REntityBlueprint`,
 * raising `SerializationError` when the pointer is not
 * REntityBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_REntityBlueprint(
  moho::REntityBlueprint** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedREntityBlueprintType());
  *outValue = static_cast<moho::REntityBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedREntityBlueprintType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "REntityBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0055A7E0 (FUN_0055A7E0, gpg::ReadArchive::ReadPointer_RMeshBlueprint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::RMeshBlueprint`,
 * raising `SerializationError` when the pointer is not
 * RMeshBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RMeshBlueprint(
  moho::RMeshBlueprint** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRMeshBlueprintType());
  *outValue = static_cast<moho::RMeshBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRMeshBlueprintType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RMeshBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0055F640 (FUN_0055F640, gpg::ReadArchive::ReadPointer_RUnitBlueprint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::RUnitBlueprint`,
 * raising `SerializationError` when the pointer is not
 * RUnitBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RUnitBlueprint(
  moho::RUnitBlueprint** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRUnitBlueprintType());
  *outValue = static_cast<moho::RUnitBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRUnitBlueprintType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RUnitBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00527480 (FUN_00527480, gpg::ReadArchive::ReadPointer_RUnitBlueprint2)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::RUnitBlueprint`,
 * raising `SerializationError` when the pointer is not
 * RUnitBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RUnitBlueprint2(
  moho::RUnitBlueprint** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRUnitBlueprintType2());
  *outValue = static_cast<moho::RUnitBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRUnitBlueprintType2());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RUnitBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0059E810 (FUN_0059E810, gpg::ReadArchive::ReadPointer_IFormationInstance)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IFormationInstance`,
 * raising `SerializationError` when the pointer is not
 * IFormationInstance-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IFormationInstance(
  moho::IFormationInstance** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIFormationInstanceType());
  *outValue = static_cast<moho::IFormationInstance*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIFormationInstanceType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IFormationInstance",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00571230 (FUN_00571230, gpg::ReadArchive::ReadPointer_Listener_EFormationdStatus)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<moho::EFormationdStatus>`, raising `SerializationError`
 * when the pointer is not Listener<EFormationdStatus>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_EFormationdStatus(
  moho::Listener<moho::EFormationdStatus>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerEFormationdStatusType());
  *outValue = static_cast<moho::Listener<moho::EFormationdStatus>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerEFormationdStatusType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<EFormationdStatus>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00599ED0 (FUN_00599ED0, gpg::ReadArchive::ReadPointer_CUnitCommandQueue)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::CUnitCommandQueue`, raising `SerializationError` when the pointer
 * is not CUnitCommandQueue-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CUnitCommandQueue(
  moho::CUnitCommandQueue** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitCommandQueueType());
  *outValue = static_cast<moho::CUnitCommandQueue*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCUnitCommandQueueType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CUnitCommandQueue",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005F5100 (FUN_005F5100, gpg::ReadArchive::ReadPointer_CUnitCommand)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CUnitCommand`,
 * raising `SerializationError` when the pointer is not
 * CUnitCommand-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CUnitCommand(
  moho::CUnitCommand** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitCommandType());
  *outValue = static_cast<moho::CUnitCommand*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCUnitCommandType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CUnitCommand",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00584D30 (FUN_00584D30, gpg::ReadArchive::ReadPointer_SimArmy)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::SimArmy`,
 * raising `SerializationError` when the pointer is not SimArmy-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_SimArmy(moho::SimArmy** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSimArmyType());
  *outValue = static_cast<moho::SimArmy*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedSimArmyType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "SimArmy",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00750FD0 (FUN_00750FD0, gpg::ReadArchive::ReadPointerOwned_SimArmy)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::SimArmy`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_SimArmy(moho::SimArmy** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToSimArmy(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedSimArmyType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "SimArmy",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00584E70 (FUN_00584E70, gpg::ReadArchive::ReadPointerOwned_CAiPersonality)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAiPersonality`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAiPersonality(
  moho::CAiPersonality** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAiPersonality(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAiPersonalityType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAiPersonality",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005850F0 (FUN_005850F0, gpg::ReadArchive::ReadPointerOwned_CTaskStage)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CTaskStage`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CTaskStage(moho::CTaskStage** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskStageType());
  *outValue = static_cast<moho::CTaskStage*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCTaskStageType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CTaskStage",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00584FB0 (FUN_00584FB0, gpg::ReadArchive::ReadPointer_Sim)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::Sim`,
 * raising `SerializationError` when the pointer is not Sim-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Sim(moho::Sim** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSimType());
  *outValue = static_cast<moho::Sim*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedSimType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Sim",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005A2900 (FUN_005A2900, gpg::ReadArchive::ReadPointer_Unit)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::Unit`,
 * raising `SerializationError` when the pointer is not Unit-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Unit(moho::Unit** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitType());
  *outValue = static_cast<moho::Unit*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedUnitType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Unit",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005A8130 (FUN_005A8130, gpg::ReadArchive::ReadPointer_Listener_EAiNavigatorEvent)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<moho::EAiNavigatorEvent>`, raising `SerializationError`
 * when the pointer is not Listener<EAiNavigatorEvent>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_EAiNavigatorEvent(
  moho::Listener<moho::EAiNavigatorEvent>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerEAiNavigatorEventType());
  *outValue = static_cast<moho::Listener<moho::EAiNavigatorEvent>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerEAiNavigatorEventType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<EAiNavigatorEvent>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00541E00 (FUN_00541E00, gpg::ReadArchive::ReadPointer_IUnit)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IUnit`,
 * raising `SerializationError` when the pointer is not IUnit-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IUnit(moho::IUnit** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIUnitType());
  *outValue = static_cast<moho::IUnit*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIUnitType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IUnit",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005AC9A0 (FUN_005AC9A0, gpg::ReadArchive::ReadPointer_PathQueue)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::PathQueue`,
 * raising `SerializationError` when the pointer is not
 * PathQueue-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_PathQueue(moho::PathQueue** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedPathQueueType());
  *outValue = static_cast<moho::PathQueue*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedPathQueueType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "PathQueue",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00707460 (FUN_00707460, gpg::ReadArchive::ReadPointerOwned_PathQueue)
 *
 * What it does:
 * Reads one tracked pointer lane from the archive, enforces the
 * `UNOWNED -> OWNED` ownership transition, and upcasts the referenced object
 * to `moho::PathQueue`. On type mismatch, raises `SerializationError` with
 * the expected and actual type names.
 */
ReadArchive* ReadArchive::ReadPointerOwned_PathQueue(moho::PathQueue** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToPathQueue(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedPathQueueType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "PathQueue",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0076B570 (FUN_0076B570, gpg::ReadArchive::ReadPointerOwned_PathQueue_Impl)
 *
 * IDA signature:
 * gpg::ReadArchive* __userpurge gpg::ReadArchive::ReadPointerOwned_PathQueue_Impl@<eax>(
 *     Moho::PathQueue::Impl** outValue@<ecx>, gpg::ReadArchive* this@<ebx>, gpg::RRef* ownerRef);
 *
 * What it does:
 * Reads one tracked pointer lane, requires it to arrive UNOWNED and claims it,
 * upcasts to `PathQueue::Impl`, and throws a serialization error if the archive
 * held a different type. Same shape as the `PathQueue` reader above.
 */
ReadArchive* ReadArchive::ReadPointerOwned_PathQueue_Impl(
  moho::PathQueue::Impl** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToPathQueueImpl(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedPathQueueImplType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "PathQueue::Impl",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B4F70 (FUN_006B4F70, gpg::ReadArchive::ReadPointerOwned_CEconStorage)
 *
 * What it does:
 * Reads one tracked pointer lane from the archive, enforces the
 * `UNOWNED -> OWNED` ownership transition, and upcasts the referenced object
 * to `moho::CEconStorage`. On type mismatch, raises `SerializationError` with
 * the expected and actual type names.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CEconStorage(
  moho::CEconStorage** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCEconStorage(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCEconStorageType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CEconStorage",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00682DB0 (FUN_00682DB0, gpg::ReadArchive::ReadPointerOwned_CTextureScroller)
 *
 * IDA signature:
 * gpg::ReadArchive *__userpurge ReadPointerOwned_CTextureScroller@<eax>(
 *   Moho::CTextureScroller **a1@<ecx>,
 *   gpg::ReadArchive *a2@<ebx>,
 *   struct gpg::RRef *a3);
 *
 * What it does:
 * Reads one tracked pointer lane from the archive, enforces the
 * `UNOWNED -> OWNED` ownership transition, and upcasts the referenced object
 * to `moho::CTextureScroller`. On type mismatch, raises `SerializationError`
 * with the expected and actual type names.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CTextureScroller(
  moho::CTextureScroller** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCTextureScroller(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCTextureScrollerType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CTextureScroller",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005096E0 (FUN_005096E0, gpg::ReadArchive::ReadPointer_STIMap)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::STIMap`,
 * raising `SerializationError` when the pointer is not STIMap-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_STIMap(moho::STIMap** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTIMapType());
  *outValue = static_cast<moho::STIMap*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedSTIMapType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "STIMap",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005ACAE0 (FUN_005ACAE0, gpg::ReadArchive::ReadPointer_COGrid)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::COGrid`,
 * raising `SerializationError` when the pointer is not COGrid-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_COGrid(moho::COGrid** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCOGridType());
  *outValue = static_cast<moho::COGrid*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCOGridType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "COGrid",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005A98A0 (FUN_005A98A0, gpg::ReadArchive::ReadPointerOwned_CAiPathNavigator)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAiPathNavigator`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAiPathNavigator(
  moho::CAiPathNavigator** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAiPathNavigator(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAiPathNavigatorType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAiPathNavigator",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005B1A50 (FUN_005B1A50, gpg::ReadArchive::ReadPointerOwned_CAiPathFinder)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAiPathFinder`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAiPathFinder(
  moho::CAiPathFinder** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAiPathFinder(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAiPathFinderType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAiPathFinder",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005CC370 (FUN_005CC370, gpg::ReadArchive::ReadPointer_ReconBlip)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::ReconBlip`,
 * raising `SerializationError` when the pointer is not ReconBlip-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_ReconBlip(moho::ReconBlip** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedReconBlipType());
  *outValue = static_cast<moho::ReconBlip*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedReconBlipType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "ReconBlip",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005CE0E0 (FUN_005CE0E0, gpg::ReadArchive::ReadPointer_CInfluenceMap)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CInfluenceMap`,
 * raising `SerializationError` when the pointer is not
 * CInfluenceMap-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CInfluenceMap(
  moho::CInfluenceMap** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCInfluenceMapType());
  *outValue = static_cast<moho::CInfluenceMap*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCInfluenceMapType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CInfluenceMap",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005D13E0 (FUN_005D13E0, gpg::ReadArchive::ReadPointer_UnitWeapon)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::UnitWeapon`,
 * raising `SerializationError` when the pointer is not
 * UnitWeapon-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_UnitWeapon(moho::UnitWeapon** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitWeaponType());
  *outValue = static_cast<moho::UnitWeapon*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedUnitWeaponType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "UnitWeapon",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005DEC30 (FUN_005DEC30, gpg::ReadArchive::ReadPointerOwned_UnitWeapon)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::UnitWeapon`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_UnitWeapon(moho::UnitWeapon** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToUnitWeapon(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedUnitWeaponType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "UnitWeapon",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005DED40 (FUN_005DED40, gpg::ReadArchive::ReadPointerOwned_CAcquireTargetTask)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAcquireTargetTask`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAcquireTargetTask(
  moho::CAcquireTargetTask** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAcquireTargetTask(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAcquireTargetTaskType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAcquireTargetTask",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005D4FE0 (FUN_005D4FE0, gpg::ReadArchive::ReadPointerOwned_CAiPathSpline)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAiPathSpline`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAiPathSpline(
  moho::CAiPathSpline** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAiPathSpline(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAiPathSplineType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAiPathSpline",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x005D5120 (FUN_005D5120, gpg::ReadArchive::ReadPointer_CUnitMotion)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CUnitMotion`,
 * raising `SerializationError` when the pointer is not
 * CUnitMotion-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CUnitMotion(moho::CUnitMotion** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitMotionType());
  *outValue = static_cast<moho::CUnitMotion*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCUnitMotionType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CUnitMotion",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005E10B0 (FUN_005E10B0, gpg::ReadArchive::ReadPointer_CAcquireTargetTask)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::CAcquireTargetTask`, raising `SerializationError` when the
 * pointer is not CAcquireTargetTask-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CAcquireTargetTask(
  moho::CAcquireTargetTask** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAcquireTargetTaskType());
  *outValue = static_cast<moho::CAcquireTargetTask*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCAcquireTargetTaskType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CAcquireTargetTask",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005E21D0 (FUN_005E21D0, gpg::ReadArchive::ReadPointer_CAiAttackerImpl)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CAiAttackerImpl`,
 * raising `SerializationError` when the pointer is not
 * CAiAttackerImpl-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CAiAttackerImpl(
  moho::CAiAttackerImpl** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiAttackerImplType());
  *outValue = static_cast<moho::CAiAttackerImpl*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCAiAttackerImplType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CAiAttackerImpl",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005DF0F0 (FUN_005DF0F0, gpg::ReadArchive::ReadPointer_Listener_EAiAttackerEvent)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<moho::EAiAttackerEvent>`, raising `SerializationError`
 * when the pointer is not Listener<EAiAttackerEvent>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_EAiAttackerEvent(
  moho::Listener<moho::EAiAttackerEvent>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerEAiAttackerEventType());
  *outValue = static_cast<moho::Listener<moho::EAiAttackerEvent>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerEAiAttackerEventType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<EAiAttackerEvent>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005EC540 (FUN_005EC540, gpg::ReadArchive::ReadPointer_Listener_EAiTransportEvent)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<moho::EAiTransportEvent>`, raising `SerializationError`
 * when the pointer is not Listener<EAiTransportEvent>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_EAiTransportEvent(
  moho::Listener<moho::EAiTransportEvent>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerEAiTransportEventType());
  *outValue = static_cast<moho::Listener<moho::EAiTransportEvent>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerEAiTransportEventType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<EAiTransportEvent>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005F2170 (FUN_005F2170, gpg::ReadArchive::ReadPointer_CCommandTask)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CCommandTask`,
 * raising `SerializationError` when the pointer is not CCommandTask-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CCommandTask(moho::CCommandTask** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCCommandTaskType());
  *outValue = static_cast<moho::CCommandTask*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCCommandTaskType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CCommandTask",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0060D940 (FUN_0060D940, gpg::ReadArchive::ReadPointer_EAiResult)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::EAiResult`,
 * raising `SerializationError` when the pointer is not EAiResult-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_EAiResult(moho::EAiResult** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEAiResultType());
  *outValue = static_cast<moho::EAiResult*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedEAiResultType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "EAiResult",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00633FB0 (FUN_00633FB0, gpg::ReadArchive::ReadPointer_RUnitBlueprintWeapon)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::RUnitBlueprintWeapon`, raising `SerializationError` when the
 * pointer is not RUnitBlueprintWeapon-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RUnitBlueprintWeapon(
  moho::RUnitBlueprintWeapon** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRUnitBlueprintWeaponType());
  *outValue = static_cast<moho::RUnitBlueprintWeapon*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRUnitBlueprintWeaponType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RUnitBlueprintWeapon",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006340F0 (FUN_006340F0, gpg::ReadArchive::ReadPointer_RProjectileBlueprint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::RProjectileBlueprint`, raising `SerializationError` when the
 * pointer is not RProjectileBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RProjectileBlueprint(
  moho::RProjectileBlueprint** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRProjectileBlueprintType());
  *outValue = static_cast<moho::RProjectileBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRProjectileBlueprintType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RProjectileBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006607B0 (FUN_006607B0, gpg::ReadArchive::ReadPointer_REmitterBlueprint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::REmitterBlueprint`, raising `SerializationError` when the pointer
 * is not REmitterBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_REmitterBlueprint(
  moho::REmitterBlueprint** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedREmitterBlueprintType());
  *outValue = static_cast<moho::REmitterBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedREmitterBlueprintType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "REmitterBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006729C0 (FUN_006729C0, gpg::ReadArchive::ReadPointer_RTrailBlueprint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::RTrailBlueprint`, raising `SerializationError` when the pointer
 * is not RTrailBlueprint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_RTrailBlueprint(
  moho::RTrailBlueprint** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRTrailBlueprintType());
  *outValue = static_cast<moho::RTrailBlueprint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedRTrailBlueprintType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "RTrailBlueprint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0065A810 (FUN_0065A810, gpg::ReadArchive::ReadPointer_CParticleTexture)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
 * transition, and upcasts the pointee to `moho::CParticleTexture`.
 */
ReadArchive* ReadArchive::ReadPointer_CParticleTexture(
  moho::CParticleTexture** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state == TrackedPointerState::Unowned) {
    tracked.state = TrackedPointerState::Shared;
  }
  if (tracked.state != TrackedPointerState::Shared) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCParticleTexture(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCParticleTextureType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CParticleTexture",
      actualName ? actualName : "null"
    ));
  }

  return this;
}

/**
 * Address: 0x0063E530 (FUN_0063E530, gpg::ReadArchive::ReadPointer_CAniPose)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CAniPose`,
 * raising `SerializationError` when the pointer is not
 * CAniPose-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CAniPose(moho::CAniPose** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAniPoseType());
  *outValue = static_cast<moho::CAniPose*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCAniPoseType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CAniPose",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0063EC70 (FUN_0063EC70, gpg::ReadArchive::ReadPointer_CAniActor)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CAniActor`,
 * raising `SerializationError` when the pointer is not
 * CAniActor-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CAniActor(moho::CAniActor** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAniActorType());
  *outValue = static_cast<moho::CAniActor*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCAniActorType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CAniActor",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006761B0 (FUN_006761B0, gpg::ReadArchive::ReadPointer_IEffect)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IEffect`,
 * raising `SerializationError` when the pointer is not IEffect-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IEffect(moho::IEffect** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIEffectType());
  *outValue = static_cast<moho::IEffect*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIEffectType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IEffect",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006756E0 (FUN_006756E0, gpg::ReadArchive::ReadPointer_ManyToOneListener_ECollisionBeamEvent)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::ManyToOneListener<moho::ECollisionBeamEvent>`, raising
 * `SerializationError` when the pointer is not
 * ManyToOneListener<ECollisionBeamEvent>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_ManyToOneListener_ECollisionBeamEvent(
  moho::ManyToOneListener<moho::ECollisionBeamEvent>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedManyToOneListenerECollisionBeamEventType());
  *outValue = static_cast<moho::ManyToOneListener<moho::ECollisionBeamEvent>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedManyToOneListenerECollisionBeamEventType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "ManyToOneListener<ECollisionBeamEvent>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00698900 (FUN_00698900, gpg::ReadArchive::ReadPointer_SPhysConstants)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::SPhysConstants`,
 * raising `SerializationError` when the pointer is not
 * SPhysConstants-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_SPhysConstants(
  moho::SPhysConstants** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedOwnedSPhysConstantsType());
  *outValue = static_cast<moho::SPhysConstants*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedOwnedSPhysConstantsType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "SPhysConstants",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0069F920 (FUN_0069F920, gpg::ReadArchive::ReadPointer_ManyToOneListener_EProjectileImpactEvent)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::ManyToOneListener<moho::EProjectileImpactEvent>`, raising
 * `SerializationError` when the pointer is not
 * ManyToOneListener<EProjectileImpactEvent>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_ManyToOneListener_EProjectileImpactEvent(
  moho::ManyToOneListener<moho::EProjectileImpactEvent>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedManyToOneListenerEProjectileImpactEventType());
  *outValue = static_cast<moho::ManyToOneListener<moho::EProjectileImpactEvent>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedManyToOneListenerEProjectileImpactEventType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "ManyToOneListener<EProjectileImpactEvent>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006E0500 (FUN_006E0500, gpg::ReadArchive::ReadPointer_IAiAttacker)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IAiAttacker`,
 * raising `SerializationError` when the pointer is not
 * IAiAttacker-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IAiAttacker(
  moho::IAiAttacker** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiAttackerType());
  *outValue = static_cast<moho::IAiAttacker*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIAiAttackerType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IAiAttacker",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006EB870 (FUN_006EB870, gpg::ReadArchive::ReadPointer_Listener_ECommandEvent)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<moho::ECommandEvent>`, raising `SerializationError` when
 * the pointer is not Listener<ECommandEvent>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_ECommandEvent(
  moho::Listener<moho::ECommandEvent>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerECommandEventType());
  *outValue = static_cast<moho::Listener<moho::ECommandEvent>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerECommandEventType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<ECommandEvent>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006F8F60 (FUN_006F8F60, gpg::ReadArchive::ReadPointer_Listener_EUnitCommandQueueStatus)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<moho::EUnitCommandQueueStatus>`, raising
 * `SerializationError` when the pointer is not
 * Listener<EUnitCommandQueueStatus>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_EUnitCommandQueueStatus(
  moho::Listener<moho::EUnitCommandQueueStatus>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerEUnitCommandQueueStatusType());
  *outValue = static_cast<moho::Listener<moho::EUnitCommandQueueStatus>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerEUnitCommandQueueStatusType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<EUnitCommandQueueStatus>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00713F30 (FUN_00713F30, gpg::ReadArchive::ReadPointer_CAiBrain)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CAiBrain`,
 * raising `SerializationError` when the pointer is not
 * CAiBrain-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CAiBrain(moho::CAiBrain** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiBrainType());
  *outValue = static_cast<moho::CAiBrain*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCAiBrainType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CAiBrain",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x007703A0 (FUN_007703A0, gpg::ReadArchive::ReadPointer_IAiReconDB)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IAiReconDB`,
 * raising `SerializationError` when the pointer is not
 * IAiReconDB-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IAiReconDB(
  moho::IAiReconDB** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIAiReconDBType());
  *outValue = static_cast<moho::IAiReconDB*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIAiReconDBType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IAiReconDB",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00763C80 (FUN_00763C80, gpg::ReadArchive::ReadPointer_Listener_NavPath)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<const moho::SNavPath&>`, raising `SerializationError` when
 * the pointer is not Listener<NavPath const &>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_NavPath(
  moho::Listener<const moho::SNavPath&>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerNavPathType());
  *outValue = static_cast<moho::Listener<const moho::SNavPath&>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerNavPathType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<NavPath const &>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x007638D0 (FUN_007638D0)
 *
 * What it does:
 * Repeatedly reads `Listener<const SNavPath&>` pointers from `archive` and
 * relinks each non-null listener node into the intrusive ring immediately
 * before the broadcaster sentinel `listHead`. `listHead` is the reflected
 * object (`typeid(moho::Broadcaster)`), i.e. a bare `Broadcaster` ring node
 * (mPrev@+0/mNext@+4) — the FUN_007638D0 asm links each node before
 * `listHead` at offset 0, so the sentinel is the `Broadcaster` itself, not a
 * `Listener::mListenerLink` sub-object.
 */
moho::Listener<const moho::SNavPath&>* gpg::ReadAndLinkNavPathListeners(
  ReadArchive* const archive,
  moho::Broadcaster* const listHead,
  const int version,
  const gpg::RRef* const ownerRef
)
{
  (void)version;

  if (archive == nullptr || listHead == nullptr) {
    return nullptr;
  }

  moho::Listener<const moho::SNavPath&>* listener = nullptr;
  archive->ReadPointer_Listener_NavPath(&listener, ownerRef);
  while (listener != nullptr) {
    listener->mListenerLink.ListLinkBefore(listHead);
    archive->ReadPointer_Listener_NavPath(&listener, ownerRef);
  }

  return listener;
}

/**
 * Address: 0x00771550 (FUN_00771550, gpg::ReadArchive::ReadPointer_IEffectManager)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IEffectManager`,
 * raising `SerializationError` when the pointer is not
 * IEffectManager-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IEffectManager(
  moho::IEffectManager** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIEffectManagerType());
  *outValue = static_cast<moho::IEffectManager*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIEffectManagerType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IEffectManager",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006895A0 (FUN_006895A0, gpg::ReadArchive::ReadPointer_EntitySetBase)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::EntitySetBase`,
 * raising `SerializationError` when the pointer is not
 * EntitySetBase-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_EntitySetBase(
  moho::EntitySetBase** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEntitySetBaseType());
  *outValue = static_cast<moho::EntitySetBase*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedEntitySetBaseType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "EntitySetBase",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x006BC1E0 (FUN_006BC1E0, gpg::ReadArchive::ReadPointer_CPathPoint)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CPathPoint`,
 * raising `SerializationError` when the pointer is not
 * CPathPoint-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CPathPoint(moho::CPathPoint** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCPathPointType());
  *outValue = static_cast<moho::CPathPoint*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCPathPointType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CPathPoint",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x007545A0 (FUN_007545A0, gpg::ReadArchive::ReadPointer_Shield)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::Shield`,
 * raising `SerializationError` when the pointer is not
 * Shield-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Shield(moho::Shield** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedShieldType());
  *outValue = static_cast<moho::Shield*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedShieldType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Shield",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0076A8E0 (FUN_0076A8E0, gpg::ReadArchive::ReadPointer_IPathTraveler)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::IPathTraveler`,
 * raising `SerializationError` when the pointer is not
 * IPathTraveler-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_IPathTraveler(
  moho::IPathTraveler** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIPathTravelerType());
  *outValue = static_cast<moho::IPathTraveler*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedIPathTravelerType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "IPathTraveler",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x0076B1C0 (FUN_0076B1C0, gpg::ReadArchive::ReadPointer_PathTables)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::PathTables`,
 * raising `SerializationError` when the pointer is not
 * PathTables-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_PathTables(moho::PathTables** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedPathTablesType());
  *outValue = static_cast<moho::PathTables*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedPathTablesType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "PathTables",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x007745F0 (FUN_007745F0, gpg::ReadArchive::ReadPointer_CEconRequest)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CEconRequest`,
 * raising `SerializationError` when the pointer is not
 * CEconRequest-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CEconRequest(
  moho::CEconRequest** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconRequestType());
  *outValue = static_cast<moho::CEconRequest*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCEconRequestType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CEconRequest",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005D1AD0 (FUN_005D1AD0, gpg::ReadArchive::ReadPointerOwned_CEconRequest)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CEconRequest`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CEconRequest(
  moho::CEconRequest** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCEconRequest(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCEconRequestType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CEconRequest",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00774BF0 (FUN_00774BF0, gpg::ReadArchive::ReadPointer_CEconomy)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CEconomy`,
 * raising `SerializationError` when the pointer is not
 * CEconomy-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CEconomy(moho::CEconomy** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconomyType());
  *outValue = static_cast<moho::CEconomy*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCEconomyType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CEconomy",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x007070A0 (FUN_007070A0, gpg::ReadArchive::ReadPointerOwned_CEconomy)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CEconomy`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CEconomy(moho::CEconomy** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCEconomy(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCEconomyType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CEconomy",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x007040E0 (FUN_007040E0, gpg::ReadArchive::ReadPointerOwned_CPlatoon)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CPlatoon`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CPlatoon(moho::CPlatoon** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCPlatoonType());
  *outValue = static_cast<moho::CPlatoon*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCPlatoonType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CPlatoon",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B10F0 (FUN_006B10F0, gpg::ReadArchive::ReadPointerOwned_CEconomyEvent)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CEconomyEvent`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CEconomyEvent(
  moho::CEconomyEvent** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCEconomyEvent(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCEconomyEventType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CEconomyEvent",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006E2B60 (FUN_006E2B60, gpg::ReadArchive::ReadPointerOwned_CUnitCommand)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CUnitCommand`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CUnitCommand(
  moho::CUnitCommand** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCUnitCommand(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCUnitCommandType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CUnitCommand",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0063CB90 (FUN_0063CB90, gpg::ReadArchive::ReadPointerOwned_IAniManipulator)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAniManipulator`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAniManipulator(
  moho::IAniManipulator** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAniManipulator(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAniManipulatorType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAniManipulator",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0066C350 (FUN_0066C350, gpg::ReadArchive::ReadPointerOwned_IEffect)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IEffect`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IEffect(moho::IEffect** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIEffect(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIEffectType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IEffect",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006829F0 (FUN_006829F0, gpg::ReadArchive::ReadPointerOwned_PositionHistory)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::PositionHistory`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_PositionHistory(
  moho::PositionHistory** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToPositionHistory(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedPositionHistoryType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "PositionHistory",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00682B30 (FUN_00682B30, gpg::ReadArchive::ReadPointerOwned_CColPrimitiveBase)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CColPrimitiveBase`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CColPrimitiveBase(
  moho::CColPrimitiveBase** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCColPrimitiveBase(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCColPrimitiveBaseType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CColPrimitiveBase",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00682C70 (FUN_00682C70, gpg::ReadArchive::ReadPointerOwned_CIntel)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CIntel`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CIntel(moho::CIntel** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCIntel(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCIntelType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CIntel",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00682EF0 (FUN_00682EF0, gpg::ReadArchive::ReadPointerOwned_SPhysBody)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::SPhysBody`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_SPhysBody(moho::SPhysBody** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToSPhysBody(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedSPhysBodyType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "SPhysBody",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00683030 (FUN_00683030, gpg::ReadArchive::ReadPointerOwned_Motor)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::EntityMotor`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_Motor(moho::EntityMotor** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToMotor(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedMotorType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "Motor",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00680FB0 (FUN_00680FB0, gpg::ReadArchive::ReadPointer_Entity)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts the pointee to `moho::Entity`
 * without consuming ownership state.
 */
ReadArchive* ReadArchive::ReadPointer_Entity(moho::Entity** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEntityType());
  *outValue = static_cast<moho::Entity*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedEntityType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Entity",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00688AC0 (FUN_00688AC0, gpg::ReadArchive::ReadPointerOwned_Entity)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::Entity`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_Entity(moho::Entity** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToEntity(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedEntityType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "Entity",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B4A70 (FUN_006B4A70, gpg::ReadArchive::ReadPointerOwned_IAiSteering)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiSteering`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiSteering(
  moho::IAiSteering** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiSteering(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiSteeringType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiSteering",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B4BB0 (FUN_006B4BB0, gpg::ReadArchive::ReadPointerOwned_CUnitMotion)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CUnitMotion`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CUnitMotion(
  moho::CUnitMotion** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCUnitMotion(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCUnitMotionType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CUnitMotion",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B4CF0 (FUN_006B4CF0, gpg::ReadArchive::ReadPointerOwned_CUnitCommandQueue)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CUnitCommandQueue`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CUnitCommandQueue(
  moho::CUnitCommandQueue** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastCUnitCommandQueueRef(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCUnitCommandQueueType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CUnitCommandQueue",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B4E30 (FUN_006B4E30, gpg::ReadArchive::ReadPointerOwned_IFormationInstance)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IFormationInstance`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IFormationInstance(
  moho::IFormationInstance** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIFormationInstance(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIFormationInstanceType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IFormationInstance",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B50B0 (FUN_006B50B0, gpg::ReadArchive::ReadPointerOwned_CAniActor)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAniActor`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAniActor(moho::CAniActor** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAniActor(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAniActorType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAniActor",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B51F0 (FUN_006B51F0, gpg::ReadArchive::ReadPointerOwned_IAiAttacker)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiAttacker`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiAttacker(moho::IAiAttacker** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiAttacker(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiAttackerType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiAttacker",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B5330 (FUN_006B5330, gpg::ReadArchive::ReadPointerOwned_IAiCommandDispatch)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiCommandDispatch`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiCommandDispatch(
  moho::IAiCommandDispatch** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiCommandDispatch(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiCommandDispatchType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiCommandDispatch",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B5470 (FUN_006B5470, gpg::ReadArchive::ReadPointerOwned_IAiNavigator)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiNavigator`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiNavigator(
  moho::IAiNavigator** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiNavigator(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiNavigatorType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiNavigator",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B55B0 (FUN_006B55B0, gpg::ReadArchive::ReadPointerOwned_IAiBuilder)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiBuilder`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiBuilder(moho::IAiBuilder** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiBuilder(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiBuilderType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiBuilder",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B56F0 (FUN_006B56F0, gpg::ReadArchive::ReadPointerOwned_IAiSiloBuild)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiSiloBuild`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiSiloBuild(
  moho::IAiSiloBuild** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiSiloBuild(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiSiloBuildType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiSiloBuild",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006B5830 (FUN_006B5830, gpg::ReadArchive::ReadPointerOwned_IAiTransport)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiTransport`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiTransport(
  moho::IAiTransport** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiTransport(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiTransportType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiTransport",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006E0640 (FUN_006E0640, gpg::ReadArchive::ReadPointerOwned_CFireWeaponTask)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CFireWeaponTask`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CFireWeaponTask(
  moho::CFireWeaponTask** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCFireWeaponTask(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCFireWeaponTaskType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CFireWeaponTask",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x006EB9E0 (FUN_006EB9E0, gpg::ReadArchive::ReadPointerWeak_IFormationInstance)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
 * transition, and upcasts the pointee to `moho::IFormationInstance`.
 */
ReadArchive* ReadArchive::ReadPointerWeak_IFormationInstance(
  moho::IFormationInstance** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state == TrackedPointerState::Unowned) {
    tracked.state = TrackedPointerState::Shared;
  }
  if (tracked.state != TrackedPointerState::Shared) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIFormationInstanceType());
  *outValue = static_cast<moho::IFormationInstance*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIFormationInstanceType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IFormationInstance",
      actualName ? actualName : "null"
    ));
  }

  return this;
}

/**
 * Address: 0x007071E0 (FUN_007071E0, gpg::ReadArchive::ReadPointerOwned_CArmyStats)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CArmyStats`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CArmyStats(moho::CArmyStats** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCArmyStats(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCArmyStatsType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CArmyStats",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00707320 (FUN_00707320, gpg::ReadArchive::ReadPointerOwned_CInfluenceMap)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CInfluenceMap`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CInfluenceMap(
  moho::CInfluenceMap** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCInfluenceMap(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCInfluenceMapType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CInfluenceMap",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00706E20 (FUN_00706E20, gpg::ReadArchive::ReadPointerOwned_CAiBrain)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CAiBrain`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CAiBrain(moho::CAiBrain** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCAiBrain(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCAiBrainType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CAiBrain",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00706F60 (FUN_00706F60, gpg::ReadArchive::ReadPointerOwned_IAiReconDB)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiReconDB`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiReconDB(
  moho::IAiReconDB** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiReconDB(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiReconDBType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiReconDB",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00714070 (FUN_00714070, gpg::ReadArchive::ReadPointerOwned_CArmyStatItem)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CArmyStatItem`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CArmyStatItem(
  moho::CArmyStatItem** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCArmyStatItem(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCArmyStatItemType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CArmyStatItem",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x007141B0 (FUN_007141B0, gpg::ReadArchive::ReadPointer_CArmyStatItem)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::CArmyStatItem`,
 * raising `SerializationError` when the pointer is not
 * CArmyStatItem-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_CArmyStatItem(
  moho::CArmyStatItem** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCArmyStatItemType());
  *outValue = static_cast<moho::CArmyStatItem*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedCArmyStatItemType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "CArmyStatItem",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00757540 (FUN_00757540, gpg::ReadArchive::ReadPointerOwned_CRandomStream)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CRandomStream`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CRandomStream(
  moho::CRandomStream** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCRandomStream(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCRandomStreamType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CRandomStream",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00757680 (FUN_00757680, gpg::ReadArchive::ReadPointerOwned_SPhysConstants)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::SPhysConstants`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_SPhysConstants(
  moho::SPhysConstants** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToSPhysConstants(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedOwnedSPhysConstantsType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "SPhysConstants",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x007577C0 (FUN_007577C0, gpg::ReadArchive::ReadPointerOwned_IAiFormationDB)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IAiFormationDB`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IAiFormationDB(
  moho::IAiFormationDB** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIAiFormationDB(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIAiFormationDBType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IAiFormationDB",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00757B10 (FUN_00757B10, gpg::ReadArchive::ReadPointerOwned_CCommandDB)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CCommandDb`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CCommandDB(
  moho::CCommandDb** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCCommandDb(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCCommandDBType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CCommandDB",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00757C50 (FUN_00757C50, gpg::ReadArchive::ReadPointerOwned_CDecalBuffer)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CDecalBuffer`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CDecalBuffer(
  moho::CDecalBuffer** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCDecalBuffer(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCDecalBufferType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CDecalBuffer",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00757D90 (FUN_00757D90, gpg::ReadArchive::ReadPointerOwned_IEffectManager)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::IEffectManager`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_IEffectManager(
  moho::IEffectManager** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToIEffectManager(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIEffectManagerType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IEffectManager",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00757ED0 (FUN_00757ED0, gpg::ReadArchive::ReadPointerOwned_ISoundManager)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::ISoundManager`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_ISoundManager(
  moho::ISoundManager** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToISoundManager(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedISoundManagerType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "ISoundManager",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00758010 (FUN_00758010, gpg::ReadArchive::ReadPointerOwned_EntityDB)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CEntityDb`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_EntityDB(moho::CEntityDb** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCEntityDb(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedEntityDBType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "EntityDB",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0076EC30 (FUN_0076EC30, gpg::ReadArchive::ReadPointerOwned_CIntelPosHandle)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CIntelPosHandle`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CIntelPosHandle(
  moho::CIntelPosHandle** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCIntelPosHandle(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCIntelPosHandleType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CIntelPosHandle",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x0077D7A0 (FUN_0077D7A0, gpg::ReadArchive::ReadPointerOwned_CDecalHandle)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> OWNED` ownership
 * transition, and upcasts the pointee to `moho::CDecalHandle`.
 */
ReadArchive* ReadArchive::ReadPointerOwned_CDecalHandle(
  moho::CDecalHandle** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state != TrackedPointerState::Unowned) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCDecalHandle(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCDecalHandleType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CDecalHandle",
      actualName ? actualName : "null"
    ));
  }

  tracked.state = TrackedPointerState::Owned;
  return this;
}

/**
 * Address: 0x00953B30 (FUN_00953B30)
 * Demangled: public: class gpg::ReadArchive & __thiscall gpg::ReadArchive::TrackPointer(class gpg::RRef const &)
 *
 * What it does:
 * Appends one tracked-pointer table lane for an object that already exists
 * at the time its serializer starts reading nested payload.
 */
ReadArchive& ReadArchive::TrackPointer(const RRef& objectRef)
{
  TrackedPointerInfo tracked{};
  tracked.object = objectRef.mObj;
  tracked.type = objectRef.mType;
  tracked.state = TrackedPointerState::Owned;
  tracked.sharedObject = nullptr;
  tracked.sharedControl = nullptr;
  mTrackedPtrs.push_back(tracked);
  return *this;
}

namespace
{
  struct TrackedPointerCopyLaneRuntimeView
  {
    void* objectLane = nullptr;                         // +0x00
    gpg::RType* typeLane = nullptr;                     // +0x04
    std::uint32_t stateLane = 0;                        // +0x08
    boost::detail::sp_counted_base* sharedControlLane = nullptr; // +0x0C
    void* sharedObjectLane = nullptr;                   // +0x10
  };
  static_assert(
    offsetof(TrackedPointerCopyLaneRuntimeView, sharedControlLane) == 0x0C,
    "TrackedPointerCopyLaneRuntimeView::sharedControlLane offset must be 0x0C"
  );
  static_assert(
    offsetof(TrackedPointerCopyLaneRuntimeView, sharedObjectLane) == 0x10,
    "TrackedPointerCopyLaneRuntimeView::sharedObjectLane offset must be 0x10"
  );
  static_assert(sizeof(TrackedPointerCopyLaneRuntimeView) == 0x14, "TrackedPointerCopyLaneRuntimeView size must be 0x14");

  /**
   * Address: 0x009506C0 (FUN_009506C0)
   *
   * What it does:
   * Copies one `TypeHandle` lane from `sourceHandle` into each destination
   * slot for `repeatCount` entries.
   */
  [[maybe_unused]] void CopyConstructTypeHandleCountFromSingleSource(
    gpg::TypeHandle* const destinationBegin,
    const std::int32_t repeatCount,
    const gpg::TypeHandle* const sourceHandle
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destinationBegin);
    for (std::int32_t remaining = repeatCount; remaining > 0; --remaining) {
      if (destinationAddress != 0u) {
        auto* const destination = reinterpret_cast<gpg::TypeHandle*>(destinationAddress);
        destination->type = sourceHandle->type;
        destination->version = sourceHandle->version;
      }
      destinationAddress += sizeof(gpg::TypeHandle);
    }
  }

  /**
   * Address: 0x00950BC0 (FUN_00950BC0)
   *
   * What it does:
   * Preserves one register-adapter lane for repeated type-handle copy
   * construction from a single source lane.
   */
  [[maybe_unused]] void CopyConstructTypeHandleCountFromSingleSourceRegisterAdapterA(
    gpg::TypeHandle* const destinationBegin,
    const std::int32_t repeatCount,
    const gpg::TypeHandle* const sourceHandle
  ) noexcept
  {
    CopyConstructTypeHandleCountFromSingleSource(destinationBegin, repeatCount, sourceHandle);
  }

  /**
   * Address: 0x00950EA0 (FUN_00950EA0)
   *
   * What it does:
   * Copies one tracked-pointer lane from `sourceLane` into each destination
   * slot for `repeatCount` entries and retains copied shared-control lanes.
   */
  [[maybe_unused]] void CopyConstructTrackedPointerCountFromSingleSource(
    TrackedPointerCopyLaneRuntimeView* const destinationBegin,
    const std::int32_t repeatCount,
    const TrackedPointerCopyLaneRuntimeView* const sourceLane
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destinationBegin);
    for (std::int32_t remaining = repeatCount; remaining > 0; --remaining) {
      if (destinationAddress != 0u) {
        auto* const destination = reinterpret_cast<TrackedPointerCopyLaneRuntimeView*>(destinationAddress);
        destination->objectLane = sourceLane->objectLane;
        destination->typeLane = sourceLane->typeLane;
        destination->stateLane = sourceLane->stateLane;
        destination->sharedControlLane = sourceLane->sharedControlLane;
        if (destination->sharedControlLane != nullptr) {
          destination->sharedControlLane->add_ref_copy();
        }
        destination->sharedObjectLane = sourceLane->sharedObjectLane;
      }
      destinationAddress += sizeof(TrackedPointerCopyLaneRuntimeView);
    }
  }

  /**
   * Address: 0x00951010 (FUN_00951010)
   *
   * What it does:
   * Preserves one register-adapter lane for repeated tracked-pointer copy
   * construction from a single source lane.
   */
  [[maybe_unused]] void CopyConstructTrackedPointerCountFromSingleSourceRegisterAdapterA(
    TrackedPointerCopyLaneRuntimeView* const destinationBegin,
    const std::int32_t repeatCount,
    const TrackedPointerCopyLaneRuntimeView* const sourceLane
  ) noexcept
  {
    CopyConstructTrackedPointerCountFromSingleSource(destinationBegin, repeatCount, sourceLane);
  }

  struct TrackedPointerVectorRuntimeView
  {
    void* proxyLane = nullptr;                 // +0x00
    gpg::TrackedPointerInfo* beginLane = nullptr;    // +0x04
    gpg::TrackedPointerInfo* endLane = nullptr;      // +0x08
    gpg::TrackedPointerInfo* capacityLane = nullptr; // +0x0C
  };
  static_assert(offsetof(TrackedPointerVectorRuntimeView, endLane) == 0x08, "TrackedPointerVectorRuntimeView::endLane offset must be 0x08");

  /**
   * Address: 0x009506F0 (FUN_009506F0)
   *
   * What it does:
   * Copy-assigns tracked-pointer lanes from `[source, sourceEnd)` into
   * `destination`, retaining incoming shared-control lanes and releasing
   * replaced destination shared-control lanes.
   */
  [[nodiscard]] gpg::TrackedPointerInfo* MoveTrackedPointerRangeWithRetainedSharedOwners(
    const gpg::TrackedPointerInfo* source,
    const gpg::TrackedPointerInfo* const sourceEnd,
    gpg::TrackedPointerInfo* destination
  ) noexcept
  {
    while (source != sourceEnd) {
      destination->object = source->object;
      destination->type = source->type;
      destination->state = source->state;

      boost::detail::sp_counted_base* const incomingControl = source->sharedControl;
      if (incomingControl != destination->sharedControl) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }

        if (destination->sharedControl != nullptr) {
          destination->sharedControl->release();
        }

        destination->sharedControl = incomingControl;
      }

      destination->sharedObject = source->sharedObject;
      ++source;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x00950790 (FUN_00950790)
   *
   * What it does:
   * Copy-assigns one tracked-pointer source lane into each destination lane in
   * `[destinationBegin, destinationEnd)`, retaining incoming shared-control
   * lanes and releasing replaced destination shared-control lanes.
   */
  [[maybe_unused]] void CopyAssignTrackedPointerRangeFromSingleSourceWithRetainedSharedOwners(
    gpg::TrackedPointerInfo* destinationBegin,
    gpg::TrackedPointerInfo* const destinationEnd,
    const gpg::TrackedPointerInfo* const sourceLane
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      destinationBegin->object = sourceLane->object;
      destinationBegin->type = sourceLane->type;
      destinationBegin->state = sourceLane->state;

      boost::detail::sp_counted_base* const incomingControl = sourceLane->sharedControl;
      if (incomingControl != destinationBegin->sharedControl) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }

        if (destinationBegin->sharedControl != nullptr) {
          destinationBegin->sharedControl->release();
        }

        destinationBegin->sharedControl = incomingControl;
      }

      destinationBegin->sharedObject = sourceLane->sharedObject;
      ++destinationBegin;
    }
  }

  /**
   * Address: 0x00950BF0 (FUN_00950BF0)
   *
   * What it does:
   * Preserves one register-adapter lane for forward tracked-pointer range copy
   * while retaining/releasing shared-control ownership.
   */
  [[maybe_unused]] [[nodiscard]] gpg::TrackedPointerInfo* MoveTrackedPointerRangeWithRetainedSharedOwnersRegisterAdapterA(
    const gpg::TrackedPointerInfo* const source,
    const gpg::TrackedPointerInfo* const sourceEnd,
    gpg::TrackedPointerInfo* const destination
  ) noexcept
  {
    return MoveTrackedPointerRangeWithRetainedSharedOwners(source, sourceEnd, destination);
  }

  /**
   * Address: 0x00950C30 (FUN_00950C30)
   *
   * What it does:
   * Preserves one jump-only adapter lane that forwards to `FUN_00950790`.
   */
  [[maybe_unused]] void CopyAssignTrackedPointerRangeFromSingleSourceWithRetainedSharedOwnersRegisterAdapterA(
    gpg::TrackedPointerInfo* const destinationBegin,
    gpg::TrackedPointerInfo* const destinationEnd,
    const gpg::TrackedPointerInfo* const sourceLane
  ) noexcept
  {
    CopyAssignTrackedPointerRangeFromSingleSourceWithRetainedSharedOwners(
      destinationBegin,
      destinationEnd,
      sourceLane
    );
  }

  /**
   * Address: 0x00950F20 (FUN_00950F20, func_ReleaseRefsRange_TrackedPointerInfo)
   * Address: 0x00951510 (FUN_00951510)
   *
   * What it does:
   * Releases shared control blocks for one half-open tracked-pointer range and
   * clears released shared-pointer lanes.
   */
  void ReleaseTrackedPointerInfoSharedRange(
    gpg::TrackedPointerInfo* trackedBegin,
    gpg::TrackedPointerInfo* const trackedEnd
  ) noexcept
  {
    while (trackedBegin != trackedEnd) {
      if (trackedBegin->sharedControl != nullptr) {
        trackedBegin->sharedControl->release();
        trackedBegin->sharedControl = nullptr;
        trackedBegin->sharedObject = nullptr;
      }
      ++trackedBegin;
    }
  }

  /**
   * Address: 0x00951070 (FUN_00951070)
   *
   * What it does:
   * Preserves one register-adapter lane for tracked-pointer shared-control
   * release over a half-open range.
   */
  [[maybe_unused]] void ReleaseTrackedPointerInfoSharedRangeRegisterAdapterA(
    gpg::TrackedPointerInfo* const trackedBegin,
    gpg::TrackedPointerInfo* const trackedEnd
  ) noexcept
  {
    ReleaseTrackedPointerInfoSharedRange(trackedBegin, trackedEnd);
  }

  /**
   * Address: 0x00951E40 (FUN_00951E40)
   *
   * What it does:
   * Erases one tracked-pointer range from vector storage by moving the tail
   * lane down, releasing detached shared-control lanes, and storing the output
   * cursor at the erase-begin position.
   */
  [[maybe_unused]] gpg::TrackedPointerInfo** EraseTrackedPointerRangeAndStoreCursorRuntime(
    TrackedPointerVectorRuntimeView* const trackedVector,
    gpg::TrackedPointerInfo** const outCursor,
    gpg::TrackedPointerInfo* const eraseFirst,
    gpg::TrackedPointerInfo* const eraseLast
  ) noexcept
  {
    if (eraseFirst != eraseLast) {
      gpg::TrackedPointerInfo* const oldEnd = trackedVector->endLane;
      gpg::TrackedPointerInfo* const newEnd =
        MoveTrackedPointerRangeWithRetainedSharedOwners(eraseLast, oldEnd, eraseFirst);
      ReleaseTrackedPointerInfoSharedRange(newEnd, oldEnd);
      trackedVector->endLane = newEnd;
    }

    *outCursor = eraseFirst;
    return outCursor;
  }
} // namespace

/**
 * Address: 0x00952BD0 (FUN_00952BD0)
 * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
 *
 * What it does:
 * Releases tracked pointer/type-handle section state, including releasing
 * shared control blocks for tracked shared-pointer lanes.
 */
void ReadArchive::EndSection(const bool)
{
  for (size_t i = 0; i < mTrackedPtrs.size(); ++i) {
    TrackedPointerInfo& tracked = mTrackedPtrs[i];
    if (tracked.state == TrackedPointerState::Owned && tracked.object && tracked.type) {
      RRef ref{};
      ref.mObj = tracked.object;
      ref.mType = tracked.type;
      ref.Delete();
    }
  }

  if (!mTrackedPtrs.empty()) {
    ReleaseTrackedPointerInfoSharedRange(&mTrackedPtrs[0], &mTrackedPtrs[0] + mTrackedPtrs.size());
  }

  mTypeHandles.clear();
  mTrackedPtrs.clear();
  mNullTrackedPointer = {};
}

/**
 * Address: 0x009048B0 (FUN_009048B0)
 * Mangled: ?CreateBinaryReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z
 *
 * What it does:
 * Allocates one file-backed concrete `ReadArchive` (BinaryReadArchive) bound to
 * the given stdio stream for save/load serializers. The binary performs no
 * validity check on the stream: it allocates with non-throwing new (returning
 * null on allocation failure) and constructs unconditionally -- matching the
 * write-side CreateBinaryWriteArchive.
 */
ReadArchive* gpg::CreateBinaryReadArchive(const boost::shared_ptr<std::FILE>& file)
{
  return new (std::nothrow) BinaryReadArchive(file);
}
