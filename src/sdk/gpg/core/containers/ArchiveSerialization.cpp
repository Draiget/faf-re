#include "ArchiveSerialization.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <new>
#include <typeinfo>
#include <utility>
#include <vector>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/ai/IAiSteering.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniSkel.h"
#include "moho/animation/CAniPose.h"
#include "moho/audio/ISoundManager.h"
#include "moho/command/CCommandDb.h"
#include "moho/debug/RDebugOverlay.h"
#include "moho/entity/CTextureScroller.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/ECollisionBeamEvent.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityMotor.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/Shield.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/Listener.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/Stats.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/resource/ISimResources.h"
#include "moho/resource/CParticleTextureReflection.h"
#include "moho/resource/RScaResource.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/path/IPathTraveler.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CDamage.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CEconomy.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/IdPool.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/EUnitCommandQueueStatus.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "moho/unit/tasks/CFireWeaponTask.h"
#include "legacy/containers/Tree.h"
#include "ReadArchive.h"
#include "Rect2.h"
#include "String.h"
#include "WriteArchive.h"

using namespace gpg;

namespace
{
  template <class T>
  [[nodiscard]] gpg::RType* CachedCompatRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(T));
    }
    return sType;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildCompatTypedRef(gpg::RRef* const out, TObject* const object, gpg::RType* const staticType)
  {
    if (out == nullptr) {
      return nullptr;
    }

    out->mObj = nullptr;
    out->mType = staticType;
    if (object == nullptr) {
      return out;
    }

    gpg::RType* runtimeType = staticType;
    try {
      runtimeType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      runtimeType = staticType;
    }

    int baseOffset = 0;
    if (runtimeType != nullptr && staticType != nullptr && runtimeType->IsDerivedFrom(staticType, &baseOffset)) {
      out->mObj = reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset)
      );
      out->mType = runtimeType;
      return out;
    }

    out->mObj = object;
    out->mType = runtimeType != nullptr ? runtimeType : staticType;
    return out;
  }

  template <class TView>
  void SaveContiguousArchiveVectorPayload(
    gpg::WriteArchive* const archive,
    const TView& view,
    gpg::RType* const elementType,
    const gpg::RRef& ownerRef
  )
  {
    const unsigned int count = view.begin != nullptr ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, view.begin + i, ownerRef);
    }
  }

  struct SerSaveLoadHelperNodeRuntime
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    void* mPrimaryCallback = nullptr;
    void* mSecondaryCallback = nullptr;
  };
  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mNext) == 0x04,
    "SerSaveLoadHelperNodeRuntime::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mPrev) == 0x08,
    "SerSaveLoadHelperNodeRuntime::mPrev offset must be 0x08"
  );
  static_assert(sizeof(SerSaveLoadHelperNodeRuntime) == 0x14, "SerSaveLoadHelperNodeRuntime size must be 0x14");

  [[nodiscard]] gpg::SerHelperBase* SerSaveLoadHelperSelfNode(SerSaveLoadHelperNodeRuntime& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerSaveLoadHelperNode(SerSaveLoadHelperNodeRuntime& helper) noexcept
  {
    helper.mNext->mPrev = helper.mPrev;
    helper.mPrev->mNext = helper.mNext;

    gpg::SerHelperBase* const self = SerSaveLoadHelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  struct SerHelperQueueNodeRuntime
  {
    SerHelperQueueNodeRuntime* mNext = nullptr;
    SerHelperQueueNodeRuntime* mPrev = nullptr;
  };
  static_assert(sizeof(SerHelperQueueNodeRuntime) == 0x08, "SerHelperQueueNodeRuntime size must be 0x08");

  [[nodiscard]] SerSaveLoadHelperNodeRuntime* QueueSerSaveLoadHelperNodeForInit(SerSaveLoadHelperNodeRuntime& helper) noexcept
  {
    auto* const links = reinterpret_cast<SerHelperQueueNodeRuntime*>(&helper.mNext);
    links->mNext = links;
    links->mPrev = links;

    auto* root = reinterpret_cast<SerHelperQueueNodeRuntime*>(gpg::SerHelperBase::sNewHelpers);
    if (root == nullptr) {
      root = static_cast<SerHelperQueueNodeRuntime*>(::operator new(sizeof(SerHelperQueueNodeRuntime), std::nothrow));
      if (root != nullptr) {
        root->mNext = root;
        root->mPrev = root;
      }
      gpg::SerHelperBase::sNewHelpers = reinterpret_cast<gpg::SerHelperBase*>(root);
    }

    if (root != nullptr) {
      links->mNext = root->mNext;
      links->mPrev = root;
      root->mNext = links;
      links->mNext->mPrev = links;
    }

    return &helper;
  }

  struct PathNeighborCellWeightPairRuntime
  {
    moho::HPathCell mCell;
    float mWeight;
  };
  static_assert(sizeof(PathNeighborCellWeightPairRuntime) == 0x08, "PathNeighborCellWeightPairRuntime size must be 0x08");
  static_assert(offsetof(PathNeighborCellWeightPairRuntime, mWeight) == 0x04,
    "PathNeighborCellWeightPairRuntime::mWeight offset must be 0x04");

  void RegisterPathNeighborCellWeightSerializerCallbacks(SerSaveLoadHelperNodeRuntime* helper);

  void* gSPathNeighborSerializerVtableRuntime[1] = {
    reinterpret_cast<void*>(&RegisterPathNeighborCellWeightSerializerCallbacks),
  };

  gpg::RType* gPathNeighborCellWeightType = nullptr;

  SerSaveLoadHelperNodeRuntime gHPathCellSerializerHelper{};
  SerSaveLoadHelperNodeRuntime gNavPathSerializerHelper{};
  SerSaveLoadHelperNodeRuntime gPathQueueSerializerHelper{};
  SerSaveLoadHelperNodeRuntime gPathQueueImplSerializerHelper{};
  SerSaveLoadHelperNodeRuntime gSPathNeighborSerializerHelper{};

  /**
   * Address: 0x00762FF0 (FUN_00762FF0)
   *
   * What it does:
   * Unlinks startup `HPathCellSerializer` helper links and rewires the node
   * into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkHPathCellSerializerNodeVariantA() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gHPathCellSerializerHelper);
  }

  /**
   * Address: 0x00763020 (FUN_00763020)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `HPathCellSerializer` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkHPathCellSerializerNodeVariantB() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gHPathCellSerializerHelper);
  }

  /**
   * Address: 0x00763240 (FUN_00763240)
   *
   * What it does:
   * Unlinks startup `NavPathSerializer` helper links and rewires the node into
   * one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkNavPathSerializerNodeVariantA() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gNavPathSerializerHelper);
  }

  /**
   * Address: 0x00763270 (FUN_00763270)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `NavPathSerializer` helper links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkNavPathSerializerNodeVariantB() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gNavPathSerializerHelper);
  }

  /**
   * Address: 0x007669F0 (FUN_007669F0)
   *
   * What it does:
   * Unlinks startup `PathQueueSerializer` helper links and rewires the node
   * into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkPathQueueSerializerNodeVariantA() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gPathQueueSerializerHelper);
  }

  /**
   * Address: 0x00766A20 (FUN_00766A20)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `PathQueueSerializer` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkPathQueueSerializerNodeVariantB() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gPathQueueSerializerHelper);
  }

  /**
   * Address: 0x00766C00 (FUN_00766C00)
   *
   * What it does:
   * Unlinks startup `PathQueueImplSerializer` helper links and rewires the
   * node into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkPathQueueImplSerializerNodeVariantA() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gPathQueueImplSerializerHelper);
  }

  /**
   * Address: 0x00766C30 (FUN_00766C30)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `PathQueueImplSerializer` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkPathQueueImplSerializerNodeVariantB() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gPathQueueImplSerializerHelper);
  }

  /**
   * Address: 0x0076D500 (FUN_0076D500)
   *
   * What it does:
   * Unlinks startup `SPathNeighborSerializer` helper links and rewires the
   * node into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSPathNeighborSerializerNodeVariantA() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gSPathNeighborSerializerHelper);
  }

  /**
   * Address: 0x0076D530 (FUN_0076D530)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `SPathNeighborSerializer` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSPathNeighborSerializerNodeVariantB() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gSPathNeighborSerializerHelper);
  }

  [[nodiscard]] gpg::RType* ResolveHPathCellSerializerType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::HPathCell");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("HPathCell");
      }
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::HPathCell));
      }
    }
    return sType;
  }

  /**
   * Address: 0x0076D760 (FUN_0076D760)
   *
   * What it does:
   * Reads one `{HPathCell,float}` pair lane by deserializing the `HPathCell`
   * head first and then one trailing float.
   */
  void DeserializePathNeighborCellWeightPair(
    PathNeighborCellWeightPairRuntime* const value,
    gpg::ReadArchive* const archive
  )
  {
    if (value == nullptr || archive == nullptr) {
      return;
    }

    gpg::RType* const hPathCellType = ResolveHPathCellSerializerType();
    gpg::RRef ownerRef{};
    archive->Read(hPathCellType, &value->mCell, ownerRef);
    archive->ReadFloat(&value->mWeight);
  }

  /**
   * Address: 0x0076D7B0 (FUN_0076D7B0)
   *
   * What it does:
   * Writes one `{HPathCell,float}` pair lane by serializing the `HPathCell`
   * head first and then one trailing float.
   */
  void SerializePathNeighborCellWeightPair(
    const PathNeighborCellWeightPairRuntime* const value,
    gpg::WriteArchive* const archive
  )
  {
    if (value == nullptr || archive == nullptr) {
      return;
    }

    gpg::RType* const hPathCellType = ResolveHPathCellSerializerType();
    const gpg::RRef ownerRef{};
    archive->Write(hPathCellType, &value->mCell, ownerRef);
    archive->WriteFloat(value->mWeight);
  }

  /**
   * Address: 0x0076D4A0 (FUN_0076D4A0, Moho::SPathNeighborSerializer::Deserialize)
   *
   * What it does:
   * Archive callback wrapper that forwards one reflected object lane into the
   * typed path-neighbor pair read helper.
   */
  [[maybe_unused]] void DeserializeSPathNeighborSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectStorage,
    const int,
    gpg::RRef*
  )
  {
    auto* const value = reinterpret_cast<PathNeighborCellWeightPairRuntime*>(static_cast<std::uintptr_t>(objectStorage));
    DeserializePathNeighborCellWeightPair(value, archive);
  }

  /**
   * Address: 0x0076D4B0 (FUN_0076D4B0, Moho::SPathNeighborSerializer::Serialize)
   *
   * What it does:
   * Archive callback wrapper that forwards one reflected object lane into the
   * typed path-neighbor pair write helper.
   */
  [[maybe_unused]] void SerializeSPathNeighborSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectStorage,
    const int,
    gpg::RRef*
  )
  {
    const auto* const value =
      reinterpret_cast<const PathNeighborCellWeightPairRuntime*>(static_cast<std::uintptr_t>(objectStorage));
    SerializePathNeighborCellWeightPair(value, archive);
  }

  /**
   * Address: 0x0076D6D0 (FUN_0076D6D0, gpg::SerSaveLoadHelper_pair_HPathCell_float::Init)
   *
   * What it does:
   * Binds load/save callbacks from one `SerSaveLoadHelper` runtime node onto
   * the reflected `std::pair<Moho::HPathCell,float>` type.
   */
  void RegisterPathNeighborCellWeightSerializerCallbacks(SerSaveLoadHelperNodeRuntime* const helper)
  {
    if (helper == nullptr) {
      return;
    }

    gpg::RType* type = gPathNeighborCellWeightType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(std::pair<moho::HPathCell, float>));
      gPathNeighborCellWeightType = type;
    }

    if (type == nullptr) {
      return;
    }

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure(
        "!type->mSerLoadFunc",
        84,
        "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h"
      );
    }

    const bool saveWasNull = type->serSaveFunc_ == nullptr;
    type->serLoadFunc_ = reinterpret_cast<gpg::RType::load_func_t>(helper->mPrimaryCallback);

    if (!saveWasNull) {
      gpg::HandleAssertFailure(
        "!type->mSerSaveFunc",
        87,
        "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h"
      );
    }

    type->serSaveFunc_ = reinterpret_cast<gpg::RType::save_func_t>(helper->mSecondaryCallback);
  }

  /**
   * Address: 0x0076D4D0 (FUN_0076D4D0)
   *
   * What it does:
   * Initializes startup `SPathNeighborSerializer` helper links and binds the
   * deserialize/serialize callback pair used by its save/load helper lane.
   */
  [[nodiscard]] SerSaveLoadHelperNodeRuntime* InitializeSPathNeighborSerializerHelperStorage() noexcept
  {
    (void)QueueSerSaveLoadHelperNodeForInit(gSPathNeighborSerializerHelper);
    gSPathNeighborSerializerHelper.mPrimaryCallback =
      reinterpret_cast<void*>(&DeserializeSPathNeighborSerializerCallback);
    gSPathNeighborSerializerHelper.mSecondaryCallback =
      reinterpret_cast<void*>(&SerializeSPathNeighborSerializerCallback);
    gSPathNeighborSerializerHelper.mVtable = static_cast<void*>(gSPathNeighborSerializerVtableRuntime);
    return &gSPathNeighborSerializerHelper;
  }

  struct SPathNeighborSerializerHelperBootstrap
  {
    SPathNeighborSerializerHelperBootstrap()
    {
      (void)InitializeSPathNeighborSerializerHelperStorage();
    }
  };

  [[maybe_unused]] SPathNeighborSerializerHelperBootstrap gSPathNeighborSerializerHelperBootstrap;

  [[nodiscard]] gpg::RType* CachedPathQueueImplType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::PathQueue::Impl");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("PathQueue::Impl");
      }
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("PathQueue_Impl");
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedSOffsetInfoType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::SOffsetInfo");
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedSAssignedLocInfoType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::SAssignedLocInfo");
    }
    return sType;
  }
} // namespace

namespace gpg
{
  /**
   * Address: 0x005504C0 (FUN_005504C0, gpg::RRef_CAniSkel)
   * Mangled: ?RRef_CAniSkel@gpg@@YAPAVRRef@1@PAV01@PAVCAniSkel@Moho@@@Z
   *
   * IDA signature:
   * gpg::RRef *__cdecl gpg::RRef_CAniSkel(gpg::RRef *outRef, Moho::CAniSkel *value);
   *
   * What it does:
   * Builds one reflected reference for `moho::CAniSkel`, preserving derived
   * runtime type and base-adjusted object lane when needed.
   */
  gpg::RRef* RRef_CAniSkel(gpg::RRef* const outRef, moho::CAniSkel* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::CAniSkel>());
  }

  gpg::RRef* RRef_Stats_StatItem(gpg::RRef* const outRef, moho::Stats_StatItem* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::Stats_StatItem>());
  }

  gpg::RRef* RRef_Listener_EFormationdStatus(
    gpg::RRef* const outRef, moho::Listener_EFormationdStatus* const value
  )
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::Listener_EFormationdStatus>());
  }

  gpg::RRef* RRef_Sim(gpg::RRef* const outRef, moho::Sim* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::Sim>());
  }

  /**
   * Address: 0x00756130 (FUN_00756130, sub_756130)
   *
   * What it does:
   * Thin wrapper that materializes a temporary `RRef_Sim` and copies lanes
   * out.
   */
  gpg::RRef* AssignSimRef(gpg::RRef* const outRef, moho::Sim* const value)
  {
    gpg::RRef tmp{};
    RRef_Sim(&tmp, value);
    outRef->mObj = tmp.mObj;
    outRef->mType = tmp.mType;
    return outRef;
  }

  gpg::RRef* RRef_CTaskStage(gpg::RRef* const outRef, moho::CTaskStage* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::CTaskStage>());
  }

  /**
   * Address: 0x006431E0 (FUN_006431E0, gpg::RRef_RScaResource)
   * Mangled: ?RRef_RScaResource@gpg@@YAPAVRRef@1@PAV01@PAVRScaResource@Moho@@@Z
   *
   * IDA signature:
   * gpg::RRef *__cdecl gpg::RRef_RScaResource(gpg::RRef *outRef, Moho::RScaResource *value);
   *
   * What it does:
   * Builds one reflected reference for `moho::RScaResource`, preserving derived
   * runtime type and base-adjusted object lane when needed.
   */
  gpg::RRef* RRef_RScaResource(gpg::RRef* const outRef, moho::RScaResource* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::RScaResource>());
  }

  /**
   * Address: 0x006B5BC0 (FUN_006B5BC0, gpg::RRef_CEconStorage)
   * Mangled: ?RRef_CEconStorage@gpg@@YAPAVRRef@1@PAV01@PAVCEconStorage@Moho@@@Z
   *
   * IDA signature:
   * gpg::RRef *__cdecl gpg::RRef_CEconStorage(gpg::RRef *outRef, Moho::CEconStorage *value);
   *
   * What it does:
   * Builds one reflected reference for `moho::CEconStorage`, preserving derived
   * runtime type and base-adjusted object lane when needed.
   */
  gpg::RRef* RRef_CEconStorage(gpg::RRef* const outRef, moho::CEconStorage* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::CEconStorage>());
  }

  /**
   * Address: 0x00707830 (FUN_00707830, gpg::RRef_CEconomy)
   *
   * What it does:
   * Builds one reflected reference for `moho::CEconomy`, preserving derived
   * runtime type and base-adjusted object lane when needed.
   */
  gpg::RRef* RRef_CEconomy(gpg::RRef* const outRef, moho::CEconomy* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::CEconomy>());
  }

  /**
   * Address: 0x00683600 (FUN_00683600, gpg::RRef_CTextureScroller)
   * Mangled: ?RRef_CTextureScroller@gpg@@YAPAVRRef@1@PAV01@PAVCTextureScroller@Moho@@@Z
   *
   * IDA signature:
   * gpg::RRef *__cdecl gpg::RRef_CTextureScroller(gpg::RRef *outRef, Moho::CTextureScroller *value);
   *
   * What it does:
   * Builds one reflected reference for `moho::CTextureScroller`, preserving
   * derived runtime type and base-adjusted object lane when needed.
   */
  gpg::RRef* RRef_CTextureScroller(gpg::RRef* const outRef, moho::CTextureScroller* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::CTextureScroller>());
  }

  /**
   * Address: 0x007742C0 (FUN_007742C0)
   *
   * What it does:
   * Builds one temporary `RRef_CEconomy` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CEconomy(gpg::RRef* const outRef, moho::CEconomy* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    (void)RRef_CEconomy(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x00774390 (FUN_00774390)
   *
   * What it does:
   * Builds one temporary `RRef_CEconStorage` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CEconStorage(gpg::RRef* const outRef, moho::CEconStorage* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    (void)RRef_CEconStorage(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x00778340 (FUN_00778340)
   *
   * What it does:
   * Builds one temporary `RRef_CTextureScroller` and copies its
   * `(mObj,mType)` pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CTextureScroller(
    gpg::RRef* const outRef,
    moho::CTextureScroller* const value
  )
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    (void)RRef_CTextureScroller(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x0072AF00 (FUN_0072AF00, gpg::RRef_CSquad)
   * Mangled: ?RRef_CSquad@gpg@@YAPAVRRef@1@PAV01@PAVCSquad@Moho@@@Z
   *
   * IDA signature:
   * gpg::RRef *__cdecl gpg::RRef_CSquad(gpg::RRef *outRef, Moho::CSquad *value);
   *
   * What it does:
   * Builds one reflected reference for `moho::CSquad`, preserving derived
   * runtime type and base-adjusted object lane when needed.
   */
  gpg::RRef* RRef_CSquad(gpg::RRef* const outRef, moho::CSquad* const value)
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::CSquad>());
  }

  gpg::RRef* RRef_ManyToOneListener_ECollisionBeamEvent(
    gpg::RRef* const outRef,
    moho::ManyToOneListener_ECollisionBeamEvent* const value
  )
  {
    return BuildCompatTypedRef(outRef, value, CachedCompatRType<moho::ManyToOneListener_ECollisionBeamEvent>());
  }

  /**
   * Address: 0x0076A5F0 (FUN_0076A5F0, gpg::RRef_PathQueue_Impl)
   *
   * What it does:
   * Builds one reflected reference for `moho::PathQueue::Impl` using the
   * preregistered named RTTI lane for the opaque impl payload.
   */
  gpg::RRef* RRef_PathQueue_Impl(gpg::RRef* const outRef, moho::PathQueue::Impl* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    outRef->mObj = value;
    outRef->mType = CachedPathQueueImplType();
    return outRef;
  }

  /**
   * Address: 0x00768CA0 (FUN_00768CA0)
   *
   * What it does:
   * Builds one temporary `RRef_PathQueue_Impl` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_PathQueue_Impl(gpg::RRef* const outRef, moho::PathQueue::Impl* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    (void)RRef_PathQueue_Impl(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x0055D590 (FUN_0055D590)
   *
   * What it does:
   * Writes one contiguous `UnitWeaponInfo` payload by saving the element count
   * and each reflected lane in order.
   */
  void SaveFastVectorUnitWeaponInfo(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto& view =
      gpg::AsFastVectorRuntimeView<moho::UnitWeaponInfo>(reinterpret_cast<const void*>(static_cast<std::uintptr_t>(objectPtr)));
    SaveContiguousArchiveVectorPayload(archive, view, CachedCompatRType<moho::UnitWeaponInfo>(), ownerRef ? *ownerRef : gpg::RRef{});
  }

  /**
   * Address: 0x0056DF80 (FUN_0056DF80)
   *
   * What it does:
   * Writes one contiguous `SOffsetInfo` payload by saving the element count
   * and each reflected lane in order.
   */
  void SaveFastVectorSOffsetInfo(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SUnitOffsetInfo>(
      reinterpret_cast<const void*>(static_cast<std::uintptr_t>(objectPtr))
    );
    SaveContiguousArchiveVectorPayload(archive, view, CachedSOffsetInfoType(), ownerRef ? *ownerRef : gpg::RRef{});
  }

  /**
   * Address: 0x0056E0A0 (FUN_0056E0A0)
   *
   * What it does:
   * Writes one contiguous `SAssignedLocInfo` payload by saving the element
   * count and each reflected lane in order.
   */
  void SaveFastVectorSAssignedLocInfo(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SFormationOccupiedSlot>(
      reinterpret_cast<const void*>(static_cast<std::uintptr_t>(objectPtr))
    );
    SaveContiguousArchiveVectorPayload(
      archive, view, CachedSAssignedLocInfoType(), ownerRef ? *ownerRef : gpg::RRef{}
    );
  }

  /**
   * Address: 0x005B4FF0 (FUN_005B4FF0)
   *
   * What it does:
   * Writes one contiguous `CPathPoint` payload by saving the element count and
   * each reflected lane in order.
   */
  void SaveFastVectorCPathPoint(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto& view =
      gpg::AsFastVectorRuntimeView<moho::CPathPoint>(reinterpret_cast<const void*>(static_cast<std::uintptr_t>(objectPtr)));
    SaveContiguousArchiveVectorPayload(archive, view, CachedCompatRType<moho::CPathPoint>(), ownerRef ? *ownerRef : gpg::RRef{});
  }

  /**
   * Address: 0x005C5860 (FUN_005C5860)
   *
   * What it does:
   * Writes one contiguous `vector<SPerArmyReconInfo>` payload by saving the
   * element count and each reflected lane in order.
   */
  void SaveVectorSPerArmyReconInfo(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const storage =
      reinterpret_cast<const msvc8::vector<moho::SPerArmyReconInfo>*>(static_cast<std::uintptr_t>(objectPtr));
    const auto& view = msvc8::AsVectorRuntimeView(*storage);
    SaveContiguousArchiveVectorPayload(
      archive, view, CachedCompatRType<moho::SPerArmyReconInfo>(), ownerRef ? *ownerRef : gpg::RRef{}
    );
  }

  /**
   * Address: 0x00702250 (FUN_00702250)
   *
   * What it does:
   * Writes one contiguous `vector<EntitySetTemplate<Unit>>` payload by saving
   * the element count and each reflected lane in order.
   */
  void SaveVectorEntitySetTemplateUnit(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const storage = reinterpret_cast<const msvc8::vector<moho::EntitySetTemplate<moho::Unit>>*>(
      static_cast<std::uintptr_t>(objectPtr)
    );
    const auto& view = msvc8::AsVectorRuntimeView(*storage);
    SaveContiguousArchiveVectorPayload(
      archive, view, CachedCompatRType<moho::EntitySetTemplate<moho::Unit>>(), ownerRef ? *ownerRef : gpg::RRef{}
    );
  }

  class SerConstructResult
  {
  public:
    /**
     * Address: 0x0094F5E0 (FUN_0094F5E0, gpg::SerConstructResult::SetOwned)
     *
     * What it does:
     * Marks load-construct result ownership as `OWNED` and stores the
     * constructed reflected reference.
     */
    void SetOwned(const RRef& ref, unsigned int flags);

    /**
     * Address: 0x0094F630 (FUN_0094F630, gpg::SerConstructResult::SetUnowned)
     *
     * What it does:
     * Marks load-construct result ownership as `UNOWNED` and stores the
     * constructed reflected reference.
     */
    void SetUnowned(const RRef& ref, unsigned int flags);

    /**
     * Address: 0x0094F680 (FUN_0094F680, gpg::SerConstructResult::SetShared)
     * Mangled: ?SetShared@SerConstructResult@gpg@@QAEXABVRRef@2@I@Z_0
     *
     * What it does:
     * Marks load-construct result ownership as `SHARED` and stores one
     * reflected reference lane directly.
     */
    void SetShared(const RRef& ref, unsigned int flags);

    /**
     * Address: 0x0094F6D0 (FUN_0094F6D0, gpg::SerConstructResult::SetShared)
     *
     * What it does:
     * Marks load-construct result ownership as `SHARED`, retains one
     * `boost::shared_ptr<void>` lane, and stores the reflected reference.
     */
    void SetShared(const boost::shared_ptr<void>& object, RType* type, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    /**
     * Address: 0x0094F750 (FUN_0094F750, gpg::SerSaveConstructArgsResult::SetOwned)
     *
     * What it does:
     * Marks save-construct ownership lane as `OWNED` from the reserved state.
     */
    void SetOwned(unsigned int flags);

    /**
     * Address: 0x0094F7D0 (FUN_0094F7D0, gpg::SerSaveConstructArgsResult::SetShared)
     *
     * What it does:
     * Marks save-construct ownership lane as `SHARED` from the reserved state.
     */
    void SetShared(unsigned int flags);

    /**
     * Address: 0x0094F790 (FUN_0094F790, gpg::SerSaveConstructArgsResult::SetUnowned)
     *
     * What it does:
     * Marks save-construct ownership lane as `UNOWNED` from the reserved state.
     */
    void SetUnowned(unsigned int flags);
  };
} // namespace gpg

namespace
{
  struct SerConstructResultView
  {
    gpg::RRef mRef;                   // +0x00
    boost::SharedPtrRaw<void> mSharedPtr; // +0x08
    TrackedPointerState mState;       // +0x10
    std::uint8_t mSharedFlag;         // +0x14
  };
  static_assert(offsetof(SerConstructResultView, mRef) == 0x0, "SerConstructResultView::mRef offset must be 0x0");
  static_assert(
    offsetof(SerConstructResultView, mSharedPtr) == 0x8, "SerConstructResultView::mSharedPtr offset must be 0x8"
  );
  static_assert(offsetof(SerConstructResultView, mState) == 0x10, "SerConstructResultView::mState offset must be 0x10");
  static_assert(
    offsetof(SerConstructResultView, mSharedFlag) == 0x14, "SerConstructResultView::mSharedFlag offset must be 0x14"
  );
  static_assert(sizeof(SerConstructResultView) == 0x18, "SerConstructResultView size must be 0x18");

  struct SerSaveConstructArgsResultView
  {
    TrackedPointerState mOwnership;
    std::uint8_t mFlagByte4;
  };
  static_assert(
    offsetof(SerSaveConstructArgsResultView, mOwnership) == 0x0,
    "SerSaveConstructArgsResultView::mOwnership offset must be 0x0"
  );
  static_assert(
    offsetof(SerSaveConstructArgsResultView, mFlagByte4) == 0x4,
    "SerSaveConstructArgsResultView::mFlagByte4 offset must be 0x4"
  );

  struct TrackedPointerTreeNodeView : msvc8::Tree<TrackedPointerTreeNodeView>
  {
    gpg::RRef ref;                         // +0x0C
    std::uint8_t reserved14_24[0x11]{};   // +0x14
    std::uint8_t isNil = 0;               // +0x25
  };
  static_assert(offsetof(TrackedPointerTreeNodeView, ref) == 0x0C, "TrackedPointerTreeNodeView::ref offset must be 0x0C");
  static_assert(
    offsetof(TrackedPointerTreeNodeView, isNil) == 0x25,
    "TrackedPointerTreeNodeView::isNil offset must be 0x25"
  );

  struct TrackedPointerTreeView
  {
    void* unknown00 = nullptr;             // +0x00
    TrackedPointerTreeNodeView* head = nullptr; // +0x04
  };
  static_assert(offsetof(TrackedPointerTreeView, head) == 0x04, "TrackedPointerTreeView::head offset must be 0x04");

  /**
   * Address: 0x0094FA20 (FUN_0094FA20, _Tree_RRef_TrackedPointer::_Lbound)
   *
   * What it does:
   * Performs one lower-bound walk over the tracked-pointer RB-tree using
   * `RRef` key ordering (`mType`, then `mObj`) and returns the first node not
   * less than the probe key.
   */
  [[maybe_unused]] TrackedPointerTreeNodeView* FindLowerBoundTrackedPointerNode(
    TrackedPointerTreeView* const tree,
    const gpg::RRef& objectRef
  ) noexcept
  {
    TrackedPointerTreeNodeView* result = tree->head;
    TrackedPointerTreeNodeView* parent = result->parent;

    if (parent->isNil == 0) {
      gpg::RType* const probeType = objectRef.mType;
      do {
        gpg::RType* const nodeType = parent->ref.mType;
        bool nodeLessThanProbe = nodeType < probeType;

        if (nodeType == probeType) {
          nodeLessThanProbe = parent->ref.mObj < objectRef.mObj;
        }

        if (nodeLessThanProbe) {
          parent = parent->right;
        } else {
          result = parent;
          parent = parent->left;
        }
      } while (parent->isNil == 0);
    }

    return result;
  }

  constexpr const char* kSerializationCppPath = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.cpp";

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

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  [[nodiscard]] gpg::RType* CachedLaunchInfoBaseType()
  {
    gpg::RType* type = moho::LaunchInfoBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::LaunchInfoBase));
      moho::LaunchInfoBase::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSessionSaveDataType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::SSessionSaveData));
    }
    return sType;
  }

  /**
   * Address: 0x008849B0 (FUN_008849B0, func_CastSSessionSaveData)
   *
   * What it does:
   * Upcasts one reflected reference to `SSessionSaveData` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::SSessionSaveData* func_CastSSessionSaveData(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSessionSaveDataType());
    return static_cast<moho::SSessionSaveData*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RType* CachedCAniPoseType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::CAniPose));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedCAniSkelType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::CAniSkel));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedRScmResourceType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::RScmResource));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedSTriggerType()
  {
    gpg::RType* type = moho::STrigger::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::STrigger));
      moho::STrigger::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedStatsStatItemType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::Stats<moho::StatItem>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedISimResourcesType()
  {
    gpg::RType* type = moho::ISimResources::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ISimResources));
      moho::ISimResources::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCIntelGridType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CIntelGrid));
    }
    return type;
  }

  template <class T>
  [[nodiscard]] boost::SharedPtrRaw<T>* AssignSharedPtrRawRetained(
    const boost::SharedPtrRaw<T>* const source,
    boost::SharedPtrRaw<T>* const destination
  ) noexcept
  {
    destination->assign_retain(*source);
    return destination;
  }

  template <class T>
  [[nodiscard]] boost::SharedPtrRaw<T>* ResetSharedPtrRaw(boost::SharedPtrRaw<T>* const value) noexcept
  {
    value->release();
    return value;
  }

  template <class T>
  [[nodiscard]] boost::SharedPtrRaw<T>* CopySharedPtrRawRetained(
    boost::SharedPtrRaw<T>* const destination,
    const boost::SharedPtrRaw<T>* const source
  ) noexcept
  {
    destination->px = source->px;
    destination->pi = source->pi;
    if (destination->pi != nullptr) {
      destination->pi->add_ref_copy();
    }
    return destination;
  }

  template <class T>
  [[nodiscard]] boost::SharedPtrRaw<T>* ReleaseSharedControlOnly(boost::SharedPtrRaw<T>* const value) noexcept
  {
    if (value->pi != nullptr) {
      value->pi->release();
    }
    return value;
  }

  /**
   * Address: 0x0054B200 (FUN_0054B200)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<CAniSkel>` lane and releases the
   * previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CAniSkel>* AssignSharedCAniSkelRetained(
    const boost::SharedPtrRaw<moho::CAniSkel>* const source,
    boost::SharedPtrRaw<moho::CAniSkel>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x00550130 (FUN_00550130)
   *
   * What it does:
   * Clears one `shared_ptr<CAniSkel>` lane and releases one retained owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CAniSkel>* ResetSharedCAniSkel(
    boost::SharedPtrRaw<moho::CAniSkel>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x005503F0 (FUN_005503F0)
   *
   * What it does:
   * Copies one raw `shared_ptr<CAniSkel>` pair and retains the source owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CAniSkel>* CopySharedCAniSkelRetained(
    boost::SharedPtrRaw<moho::CAniSkel>* const destination,
    const boost::SharedPtrRaw<moho::CAniSkel>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x00551ED0 (FUN_00551ED0)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<CIntelGrid>` lane and releases the
   * previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CIntelGrid>* AssignSharedCIntelGridRetained(
    const boost::SharedPtrRaw<moho::CIntelGrid>* const source,
    boost::SharedPtrRaw<moho::CIntelGrid>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x00551F00 (FUN_00551F00)
   *
   * What it does:
   * Clears one `shared_ptr<CIntelGrid>` lane and releases one retained owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CIntelGrid>* ResetSharedCIntelGrid(
    boost::SharedPtrRaw<moho::CIntelGrid>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x00551FE0 (FUN_00551FE0)
   *
   * What it does:
   * Copies one raw `shared_ptr<CIntelGrid>` pair and retains the source owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CIntelGrid>* CopySharedCIntelGridRetained(
    boost::SharedPtrRaw<moho::CIntelGrid>* const destination,
    const boost::SharedPtrRaw<moho::CIntelGrid>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x0055B760 (FUN_0055B760)
   *
   * What it does:
   * Releases one retained control-block owner without changing raw pointer
   * lanes in the `shared_ptr<Stats<StatItem>>` scratch pair.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* ReleaseSharedStatsStatItemControlOnly(
    boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* const value
  ) noexcept
  {
    return ReleaseSharedControlOnly(value);
  }

  /**
   * Address: 0x0055FBA0 (FUN_0055FBA0)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<Stats<StatItem>>` lane and releases
   * the previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* AssignSharedStatsStatItemRetained(
    const boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* const source,
    boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x0055FC00 (FUN_0055FC00)
   *
   * What it does:
   * Clears one `shared_ptr<Stats<StatItem>>` lane and releases one retained
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* ResetSharedStatsStatItem(
    boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x0055FDB0 (FUN_0055FDB0)
   *
   * What it does:
   * Copies one raw `shared_ptr<Stats<StatItem>>` pair and retains the source
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* CopySharedStatsStatItemRetained(
    boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* const destination,
    const boost::SharedPtrRaw<moho::Stats<moho::StatItem>>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x0055FDD0 (FUN_0055FDD0)
   *
   * What it does:
   * Copies one raw `shared_ptr<CAniPose>` pair and retains the source owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CAniPose>* CopySharedCAniPoseRetained(
    boost::SharedPtrRaw<moho::CAniPose>* const destination,
    const boost::SharedPtrRaw<moho::CAniPose>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x005CE430 (FUN_005CE430)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<CIntelGrid>` lane for the legacy
   * CIntelPosHandle serializer path and releases the previous owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CIntelGrid>* AssignSharedCIntelGrid2Retained(
    const boost::SharedPtrRaw<moho::CIntelGrid>* const source,
    boost::SharedPtrRaw<moho::CIntelGrid>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x005CE720 (FUN_005CE720)
   *
   * What it does:
   * Copies one raw `shared_ptr<CIntelGrid>` pair for the legacy
   * CIntelPosHandle serializer path and retains the source owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::CIntelGrid>* CopySharedCIntelGrid2Retained(
    boost::SharedPtrRaw<moho::CIntelGrid>* const destination,
    const boost::SharedPtrRaw<moho::CIntelGrid>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x00714530 (FUN_00714530)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<STrigger>` lane and releases the
   * previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::STrigger>* AssignSharedSTriggerRetained(
    const boost::SharedPtrRaw<moho::STrigger>* const source,
    boost::SharedPtrRaw<moho::STrigger>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x00714560 (FUN_00714560)
   *
   * What it does:
   * Clears one `shared_ptr<STrigger>` lane and releases one retained owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::STrigger>* ResetSharedSTrigger(
    boost::SharedPtrRaw<moho::STrigger>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x00714A50 (FUN_00714A50)
   *
   * What it does:
   * Copies one raw `shared_ptr<STrigger>` pair and retains the source owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::STrigger>* CopySharedSTriggerRetained(
    boost::SharedPtrRaw<moho::STrigger>* const destination,
    const boost::SharedPtrRaw<moho::STrigger>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x0073F5B0 (FUN_0073F5B0)
   *
   * What it does:
   * Clears one `shared_ptr<LaunchInfoBase>` lane and releases one retained
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::LaunchInfoBase>* ResetSharedLaunchInfoBase(
    boost::SharedPtrRaw<moho::LaunchInfoBase>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x00758150 (FUN_00758150)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<ISimResources>` lane and releases the
   * previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::ISimResources>* AssignSharedISimResourcesRetained(
    const boost::SharedPtrRaw<moho::ISimResources>* const source,
    boost::SharedPtrRaw<moho::ISimResources>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x00758180 (FUN_00758180)
   *
   * What it does:
   * Clears one `shared_ptr<ISimResources>` lane and releases one retained
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::ISimResources>* ResetSharedISimResources(
    boost::SharedPtrRaw<moho::ISimResources>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x007584A0 (FUN_007584A0, func_CastISimResources)
   *
   * What it does:
   * Upcasts one reflected reference to `ISimResources` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::ISimResources* func_CastISimResources(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedISimResourcesType());
    return static_cast<moho::ISimResources*>(upcast.mObj);
  }

  /**
   * Address: 0x007584E0 (FUN_007584E0)
   *
   * What it does:
   * Copies one raw `shared_ptr<ISimResources>` pair and retains the source
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::ISimResources>* CopySharedISimResourcesRetained(
    boost::SharedPtrRaw<moho::ISimResources>* const destination,
    const boost::SharedPtrRaw<moho::ISimResources>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x0087FCB0 (FUN_0087FCB0)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<LaunchInfoBase>` lane and releases
   * the previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::LaunchInfoBase>* AssignSharedLaunchInfoBaseRetained(
    const boost::SharedPtrRaw<moho::LaunchInfoBase>* const source,
    boost::SharedPtrRaw<moho::LaunchInfoBase>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x00884670 (FUN_00884670)
   *
   * What it does:
   * Rebinds one retained raw `shared_ptr<SSessionSaveData>` lane and releases
   * the previously bound owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::SSessionSaveData>* AssignSharedSSessionSaveDataRetained(
    const boost::SharedPtrRaw<moho::SSessionSaveData>* const source,
    boost::SharedPtrRaw<moho::SSessionSaveData>* const destination
  ) noexcept
  {
    return AssignSharedPtrRawRetained(source, destination);
  }

  /**
   * Address: 0x008846E0 (FUN_008846E0)
   *
   * What it does:
   * Clears one `shared_ptr<SSessionSaveData>` lane and releases one retained
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::SSessionSaveData>* ResetSharedSSessionSaveData(
    boost::SharedPtrRaw<moho::SSessionSaveData>* const value
  ) noexcept
  {
    return ResetSharedPtrRaw(value);
  }

  /**
   * Address: 0x008849F0 (FUN_008849F0)
   *
   * What it does:
   * Copies one raw `shared_ptr<SSessionSaveData>` pair and retains the source
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::SSessionSaveData>* CopySharedSSessionSaveDataRetained(
    boost::SharedPtrRaw<moho::SSessionSaveData>* const destination,
    const boost::SharedPtrRaw<moho::SSessionSaveData>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x00885110 (FUN_00885110, func_CastLaunchInfoBase)
   *
   * What it does:
   * Upcasts one reflected reference to `LaunchInfoBase` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::LaunchInfoBase* func_CastLaunchInfoBase(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLaunchInfoBaseType());
    return static_cast<moho::LaunchInfoBase*>(upcast.mObj);
  }

  /**
   * Address: 0x00885150 (FUN_00885150)
   *
   * What it does:
   * Copies one raw `shared_ptr<LaunchInfoBase>` pair and retains the source
   * owner.
   */
  [[nodiscard]] boost::SharedPtrRaw<moho::LaunchInfoBase>* CopySharedLaunchInfoBaseRetained(
    boost::SharedPtrRaw<moho::LaunchInfoBase>* const destination,
    const boost::SharedPtrRaw<moho::LaunchInfoBase>* const source
  ) noexcept
  {
    return CopySharedPtrRawRetained(destination, source);
  }

  /**
   * Address: 0x0094F5A0 (FUN_0094F5A0)
   *
   * What it does:
   * Releases one retained tracked-pointer shared control lane without changing
   * the raw object/type payload.
   */
  void ReleaseTrackedPointerSharedControl(gpg::TrackedPointerInfo* const tracked) noexcept
  {
    if (tracked != nullptr && tracked->sharedControl != nullptr) {
      tracked->sharedControl->release();
    }
  }

  /**
   * Address: 0x00550670 (FUN_00550670, ??1WeakPtr_CIntelGrid@Moho@@QAE@@Z)
   *
   * What it does:
   * Releases one retained `boost::shared_ptr<CIntelGrid>` control-block owner
   * from raw `(px,pi)` storage and clears both lanes.
   */
  void ReleaseSharedCIntelGrid(boost::SharedPtrRaw<moho::CIntelGrid>& pointer) noexcept
  {
    pointer.release();
  }

  [[nodiscard]] bool IsPointerCompatibleWithExpectedType(
    const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType
  )
  {
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return upcast.mObj != nullptr;
  }

  void PromoteTrackedPointerToShared(gpg::TrackedPointerInfo& tracked)
  {
    GPG_ASSERT(tracked.type != nullptr);
    GPG_ASSERT(tracked.type != nullptr && tracked.type->deleteFunc_ != nullptr);
    if (!tracked.type || !tracked.type->deleteFunc_) {
      ThrowSerializationError("Ownership conflict while loading archive");
    }

    auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
      tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
    );

    tracked.sharedObject = tracked.object;
    tracked.sharedControl = control;
    tracked.state = gpg::TrackedPointerState::Shared;
  }

  void EnsureTrackedPointerSharedOwnership(gpg::TrackedPointerInfo& tracked)
  {
    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      PromoteTrackedPointerToShared(tracked);
      return;
    }

    if (tracked.state != gpg::TrackedPointerState::Shared) {
      ThrowSerializationError("Ownership conflict while loading archive");
    }

    if (!tracked.sharedObject || !tracked.sharedControl) {
      ThrowSerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }
  }

  [[noreturn]]
  void ThrowTypeMismatch(const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType)
  {
    const char* const expectedName = expectedType ? expectedType->GetName() : "LaunchInfoBase";
    const char* const actualName = tracked.type ? tracked.type->GetName() : "null";

    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "LaunchInfoBase",
      actualName ? actualName : "null"
    ));
  }

  template <class T>
  void AssignRetainedRawSharedPointer(
    boost::SharedPtrRaw<T>& outPointer, const gpg::TrackedPointerInfo& tracked
  )
  {
    boost::SharedPtrRaw<T> source{};
    source.px = static_cast<T*>(tracked.sharedObject);
    source.pi = tracked.sharedControl;
    outPointer.assign_retain(source);
  }
} // namespace

/**
 * Address: 0x0094F5E0 (FUN_0094F5E0, gpg::SerConstructResult::SetOwned)
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `OWNED`, stores the
 * reflected object reference, and clears the shared-flag byte when bit 0 in
 * `flags` is set.
 */
void gpg::SerConstructResult::SetOwned(const RRef& ref, const unsigned int flags)
{
  auto* const view = reinterpret_cast<SerConstructResultView*>(this);
  if (view->mState != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 196, kSerializationCppPath);
  }

  view->mRef = ref;
  view->mState = TrackedPointerState::Owned;
  if ((flags & 1u) != 0u) {
    view->mSharedFlag = 0;
  }
}

/**
 * Address: 0x0094F630 (FUN_0094F630, gpg::SerConstructResult::SetUnowned)
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `UNOWNED`, stores
 * the reflected object reference, and clears the shared-flag byte when bit 0
 * in `flags` is set.
 */
void gpg::SerConstructResult::SetUnowned(const RRef& ref, const unsigned int flags)
{
  auto* const view = reinterpret_cast<SerConstructResultView*>(this);
  if (view->mState != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 204, kSerializationCppPath);
  }

  view->mRef = ref;
  view->mState = TrackedPointerState::Unowned;
  if ((flags & 1u) != 0u) {
    view->mSharedFlag = 0;
  }
}

/**
 * Address: 0x0094F680 (FUN_0094F680, gpg::SerConstructResult::SetShared)
 * Mangled: ?SetShared@SerConstructResult@gpg@@QAEXABVRRef@2@I@Z_0
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `SHARED`, stores
 * the reflected object reference lane directly, and clears the shared-flag
 * byte when bit 0 in `flags` is set.
 */
void gpg::SerConstructResult::SetShared(const RRef& ref, const unsigned int flags)
{
  auto* const view = reinterpret_cast<SerConstructResultView*>(this);
  if (view->mState != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 212, kSerializationCppPath);
  }

  view->mRef = ref;
  view->mState = TrackedPointerState::Shared;
  if ((flags & 1u) != 0u) {
    view->mSharedFlag = 0;
  }
}

/**
 * Address: 0x0094F6D0 (FUN_0094F6D0, gpg::SerConstructResult::SetShared)
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `SHARED`, retains
 * the incoming shared control block, stores the reflected object reference,
 * and clears the shared-flag byte when bit 0 in `flags` is set.
 */
void gpg::SerConstructResult::SetShared(
  const boost::shared_ptr<void>& object,
  RType* const type,
  const unsigned int flags
)
{
  auto* const view = reinterpret_cast<SerConstructResultView*>(this);
  if (view->mState != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 220, kSerializationCppPath);
  }

  const boost::SharedPtrRaw<void> sourceShared = boost::SharedPtrRawFromSharedBorrow(object);
  view->mSharedPtr.assign_retain(sourceShared);
  view->mRef.mObj = sourceShared.px;
  view->mRef.mType = type;
  view->mState = TrackedPointerState::Shared;
  if ((flags & 1u) != 0u) {
    view->mSharedFlag = 0;
  }
}

/**
 * Address: 0x0094F750 (FUN_0094F750, gpg::SerSaveConstructArgsResult::SetOwned)
 * Mangled: ?SetOwned@SerSaveConstructArgsResult@gpg@@QAEXI@Z_0
 *
 * What it does:
 * Transitions one save-construct result lane from `RESERVED` to `OWNED`
 * and clears the byte-at-+4 lane when bit 0 in `flags` is set.
 */
void gpg::SerSaveConstructArgsResult::SetOwned(const unsigned int flags)
{
  auto* const view = reinterpret_cast<SerSaveConstructArgsResultView*>(this);
  if (view->mOwnership != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mOwnership == RESERVED", 402, kSerializationCppPath);
  }

  view->mOwnership = TrackedPointerState::Owned;
  if ((flags & 1u) != 0u) {
    view->mFlagByte4 = 0;
  }
}

/**
 * Address: 0x0094F790 (FUN_0094F790, gpg::SerSaveConstructArgsResult::SetUnowned)
 *
 * What it does:
 * Transitions one save-construct result lane from `RESERVED` to `UNOWNED`
 * and clears the byte-at-+4 lane when bit 0 in `flags` is set.
 */
void gpg::SerSaveConstructArgsResult::SetUnowned(const unsigned int flags)
{
  auto* const view = reinterpret_cast<SerSaveConstructArgsResultView*>(this);
  if (view->mOwnership != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mOwnership == RESERVED", 409, kSerializationCppPath);
  }

  view->mOwnership = TrackedPointerState::Unowned;
  if ((flags & 1u) != 0u) {
    view->mFlagByte4 = 0;
  }
}

/**
 * Address: 0x0094F7D0 (FUN_0094F7D0, gpg::SerSaveConstructArgsResult::SetShared)
 *
 * What it does:
 * Transitions one save-construct result lane from `RESERVED` to `SHARED`
 * and clears the byte-at-+4 lane when bit 0 in `flags` is set.
 */
void gpg::SerSaveConstructArgsResult::SetShared(const unsigned int flags)
{
  auto* const view = reinterpret_cast<SerSaveConstructArgsResultView*>(this);
  if (view->mOwnership != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mOwnership == RESERVED", 416, kSerializationCppPath);
  }

  view->mOwnership = TrackedPointerState::Shared;
  if ((flags & 1u) != 0u) {
    view->mFlagByte4 = 0;
  }
}

/**
 * Address: 0x00953320 (FUN_00953320)
 * Demangled: gpg::WriteArchive::WriteRawPointer
 *
 * What it does:
 * Writes tracked-pointer token payload and serializes newly seen pointees.
 */
void gpg::WriteRawPointer(
  WriteArchive* const archive, const RRef& objectRef, const TrackedPointerState state, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error while creating archive: null WriteArchive.");
  }

  if (!objectRef.mObj) {
    archive->WriteMarker(static_cast<int>(ArchiveToken::NullPointer));
    return;
  }

  std::map<const void*, WriteArchive::TrackedPointerRecord>::iterator it = archive->mObjRefs.find(objectRef.mObj);
  WriteArchive::TrackedPointerRecord* record = nullptr;

  if (it == archive->mObjRefs.end()) {
    WriteArchive::TrackedPointerRecord fresh{};
    fresh.type = objectRef.mType;
    fresh.index = static_cast<int>(archive->mObjRefs.size());
    fresh.ownership = TrackedPointerState::Reserved;

    const std::pair<std::map<const void*, WriteArchive::TrackedPointerRecord>::iterator, bool> inserted =
      archive->mObjRefs.insert(std::make_pair(objectRef.mObj, fresh));
    record = &inserted.first->second;

    archive->WriteMarker(static_cast<int>(ArchiveToken::NewObject));
    archive->WriteRefCounts(objectRef.mType);

    if (!objectRef.mType || !objectRef.mType->serSaveFunc_) {
      ThrowSerializationError(STR_Printf(
        "Error while creating archive: encounted an object of type \"%s\", but we don't have a save function for it.",
        SafeTypeName(objectRef.mType)
      ));
    }

    objectRef.mType->serSaveFunc_(
      archive, reinterpret_cast<int>(objectRef.mObj), objectRef.mType->version_, const_cast<RRef*>(&ownerRef)
    );

    if (record->ownership == TrackedPointerState::Reserved) {
      record->ownership = TrackedPointerState::Unowned;
    }

    archive->WriteMarker(static_cast<int>(ArchiveToken::ObjectTerminator));
  } else {
    record = &it->second;
    if (record->ownership == TrackedPointerState::Reserved) {
      ThrowSerializationError(
        "Error while creating archive: recursively encountered a pointer to an object for which construction data is "
        "still being written"
      );
    }

    archive->WriteMarker(static_cast<int>(ArchiveToken::ExistingPointer));
    archive->WriteInt(record->index);
  }

  if (state == TrackedPointerState::Owned) {
    if (record->ownership != TrackedPointerState::Unowned) {
      ThrowSerializationError("Ownership conflict while writing archive.");
    }
    record->ownership = TrackedPointerState::Owned;
  } else if (state == TrackedPointerState::Shared) {
    if (record->ownership == TrackedPointerState::Owned) {
      ThrowSerializationError("Shared/owned conflict while writing archive.");
    }
    record->ownership = TrackedPointerState::Shared;
  }
}

/**
 * Address: 0x00953720 (FUN_00953720)
 * Demangled: gpg::ReadArchive::ReadRawPointer
 *
 * What it does:
 * Reads pointer token payload and resolves a tracked pointer reference.
 */
TrackedPointerInfo& gpg::ReadRawPointer(ReadArchive* const archive, const RRef& ownerRef)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  const ArchiveToken token = static_cast<ArchiveToken>(archive->NextMarker());
  if (token == ArchiveToken::NullPointer) {
    archive->mNullTrackedPointer = {};
    return archive->mNullTrackedPointer;
  }

  if (token == ArchiveToken::ExistingPointer) {
    int index = -1;
    archive->ReadInt(&index);

    if (index < 0 || static_cast<size_t>(index) >= archive->mTrackedPtrs.size()) {
      ThrowSerializationError(STR_Printf(
        "Error detected in archive: found a reference to an existing pointer of index %d, but only %d pointers have "
        "been created.",
        index,
        static_cast<int>(archive->mTrackedPtrs.size())
      ));
    }

    TrackedPointerInfo& tracked = archive->mTrackedPtrs[static_cast<size_t>(index)];
    if (tracked.state == TrackedPointerState::Reserved) {
      ThrowSerializationError(
        "Error detected in archive: found a reference to an existing pointer that has not been constructed yet."
      );
    }
    return tracked;
  }

  if (token != ArchiveToken::NewObject) {
    ThrowSerializationError(
      STR_Printf("Error detected in archive: found an invalid token value of %d", static_cast<int>(token))
    );
  }

  const TypeHandle handle = archive->ReadTypeHandle();
  if (!handle.type) {
    ThrowSerializationError("Error detected in archive: null type handle.");
  }

  if (!handle.type->newRefFunc_) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found a pointer to an object of type \"%s\", but we don't have a constructor for it.",
      SafeTypeName(handle.type)
    ));
  }

  const RRef objectRef = handle.type->newRefFunc_();
  TrackedPointerInfo tracked{};
  tracked.object = objectRef.mObj;
  tracked.type = objectRef.mType ? objectRef.mType : handle.type;
  tracked.state = TrackedPointerState::Reserved;
  tracked.sharedObject = nullptr;
  tracked.sharedControl = nullptr;

  const size_t trackedIndex = archive->mTrackedPtrs.size();
  archive->mTrackedPtrs.push_back(tracked);

  RType* const loadedType = archive->mTrackedPtrs[trackedIndex].type;
  void* const loadedObject = archive->mTrackedPtrs[trackedIndex].object;
  if (!loadedType || !loadedType->serLoadFunc_) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but we don't have a loader for it.",
      SafeTypeName(loadedType)
    ));
  }

  loadedType->serLoadFunc_(archive, reinterpret_cast<int>(loadedObject), handle.version, const_cast<RRef*>(&ownerRef));

  TrackedPointerInfo& trackedRef = archive->mTrackedPtrs[trackedIndex];

  if (archive->NextMarker() != static_cast<int>(ArchiveToken::ObjectTerminator)) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: data for object of type \"%s\" did not terminate properly.",
      SafeTypeName(trackedRef.type)
    ));
  }

  if (trackedRef.state == TrackedPointerState::Reserved) {
    trackedRef.state = TrackedPointerState::Unowned;
  }

  return trackedRef;
}

/**
 * Address: 0x00884C90 (FUN_00884C90)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<LaunchInfoBase>`,
 * promotes unowned entries to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_LaunchInfoBase(
  boost::SharedPtrRaw<moho::LaunchInfoBase>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RRef trackedRef{};
  trackedRef.mObj = tracked.object;
  trackedRef.mType = tracked.type;

  gpg::RType* const expectedType = CachedLaunchInfoBaseType();
  if (func_CastLaunchInfoBase(trackedRef) == nullptr) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x008843F0 (FUN_008843F0)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<SSessionSaveData>`,
 * promotes unowned entries to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_SSessionSaveData(
  boost::SharedPtrRaw<moho::SSessionSaveData>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RRef trackedRef{};
  trackedRef.mObj = tracked.object;
  trackedRef.mType = tracked.type;
  if (func_CastSSessionSaveData(trackedRef) == nullptr) {
    gpg::RType* const expectedType = CachedSessionSaveDataType();
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x0055F990 (FUN_0055F990)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<CAniPose>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_CAniPose(
  boost::SharedPtrRaw<moho::CAniPose>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedCAniPoseType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x0054FF20 (FUN_0054FF20)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<CAniSkel>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_CAniSkel(
  boost::SharedPtrRaw<moho::CAniSkel>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedCAniSkelType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x0055F780 (FUN_0055F780)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<Stats<StatItem>>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_Stats_StatItem(
  boost::SharedPtrRaw<moho::Stats<moho::StatItem>>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedStatsStatItemType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x00757900 (FUN_00757900)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<ISimResources>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_ISimResources(
  boost::SharedPtrRaw<moho::ISimResources>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RRef trackedRef{};
  trackedRef.mObj = tracked.object;
  trackedRef.mType = tracked.type;

  gpg::RType* const expectedType = CachedISimResourcesType();
  if (func_CastISimResources(trackedRef) == nullptr) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x00551CC0 (FUN_00551CC0)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<CIntelGrid>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_CIntelGrid(
  boost::SharedPtrRaw<moho::CIntelGrid>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    ReleaseSharedCIntelGrid(outPointer);
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedCIntelGridType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x005CE220 (FUN_005CE220, gpg::ReadArchive::ReadPointerShared_CIntelGrid2)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<CIntelGrid>` for the
 * legacy CIntelPosHandle serializer lane.
 */
void gpg::ReadPointerShared_CIntelGrid2(
  boost::SharedPtrRaw<moho::CIntelGrid>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    ReleaseSharedCIntelGrid(outPointer);
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedCIntelGridType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x00642F60 (FUN_00642F60, gpg::ReadArchive::ReadPointerShared_RScaResource)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<RScaResource>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_RScaResource(
  boost::SharedPtrRaw<moho::RScaResource>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedCompatRType<moho::RScaResource>();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x0055A5D0 (FUN_0055A5D0)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<RScmResource>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_RScmResource(
  boost::SharedPtrRaw<moho::RScmResource>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    (void)boost::DestroySharedPtrRScmResource(&outPointer);
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedRScmResourceType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x007142F0 (FUN_007142F0)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<STrigger>`,
 * promotes unowned lanes to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_STrigger(
  boost::SharedPtrRaw<moho::STrigger>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedSTriggerType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

namespace
{
  template <class TValue>
  [[nodiscard]] gpg::WriteArchive* WriteTrackedPointerFromRefBuilder(
    gpg::WriteArchive* const archive,
    gpg::RRef* (*const buildRef)(gpg::RRef*, TValue),
    TValue value,
    const gpg::TrackedPointerState trackedState
  )
  {
    gpg::RRef objectRef{};
    buildRef(&objectRef, value);
    gpg::WriteRawPointer(archive, objectRef, trackedState, gpg::RRef{});
    return archive;
  }

  template <class TValue>
  void SaveTrackedPointerFromRefBuilder(
    gpg::WriteArchive* const archive,
    gpg::RRef* (*const buildRef)(gpg::RRef*, TValue),
    TValue value,
    const gpg::TrackedPointerState trackedState
  )
  {
    (void)WriteTrackedPointerFromRefBuilder(archive, buildRef, value, trackedState);
  }

  [[nodiscard]] gpg::ReadArchive* ReadPointerOwned_CEconStorageCompat(
    moho::CEconStorage** const outValue, gpg::ReadArchive* const archive, const gpg::RRef* const ownerRef
  )
  {
    // Delegate to the canonical gpg::ReadArchive method recovered from
    // FUN_006B4F70 so all CEconStorage owned-pointer reads funnel through one
    // typed implementation.
    return archive ? archive->ReadPointerOwned_CEconStorage(outValue, ownerRef) : archive;
  }

  [[nodiscard]] gpg::ReadArchive* ReadPointerOwned_CTextureScrollerCompat(
    moho::CTextureScroller** const outValue, gpg::ReadArchive* const archive, const gpg::RRef* const ownerRef
  )
  {
    // Delegate to the canonical gpg::ReadArchive method recovered from
    // FUN_00682DB0 so all CTextureScroller owned-pointer reads funnel
    // through one typed implementation.
    return archive ? archive->ReadPointerOwned_CTextureScroller(outValue, ownerRef) : archive;
  }

  [[nodiscard]] gpg::ReadArchive* ReadPointerOwned_PathQueueCompat(
    moho::PathQueue** const outValue, gpg::ReadArchive* const archive, const gpg::RRef* const ownerRef
  )
  {
    // Delegate to the canonical gpg::ReadArchive method recovered from
    // FUN_00707460 so all PathQueue owned-pointer reads funnel through one
    // typed implementation.
    return archive ? archive->ReadPointerOwned_PathQueue(outValue, ownerRef) : archive;
  }

  [[nodiscard]] gpg::RType* ResolveRect2iArchiveAdapterType()
  {
    gpg::RType* type = gpg::Rect2i::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(gpg::Rect2<int>));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveELayerArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::ELayer");
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::ELayer));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::EntId");
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::EntId));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEEconResourceArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::EEconResource");
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::EEconResource));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveCThrustManipulatorArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::CThrustManipulator");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("CThrustManipulator");
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveRDebugOverlayArchiveAdapterType()
  {
    gpg::RType* type = moho::RDebugOverlay::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RDebugOverlay));
      moho::RDebugOverlay::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveCEffectImplArchiveAdapterType()
  {
    gpg::RType* type = moho::CEffectImpl::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CEffectImpl));
      moho::CEffectImpl::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveSEntAttachInfoArchiveAdapterType()
  {
    gpg::RType* type = moho::SEntAttachInfo::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SEntAttachInfo));
      moho::SEntAttachInfo::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveSWorldBeamArchiveAdapterType()
  {
    gpg::RType* type = moho::SWorldBeam::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SWorldBeam));
      moho::SWorldBeam::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveREmitterBlueprintArchiveAdapterType()
  {
    gpg::RType* type = moho::REmitterBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::REmitterBlueprint));
      moho::REmitterBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveRTrailBlueprintArchiveAdapterType()
  {
    gpg::RType* type = moho::RTrailBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RTrailBlueprint));
      moho::RTrailBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveCollisionBeamEntityArchiveAdapterType()
  {
    gpg::RType* type = moho::CollisionBeamEntity::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CollisionBeamEntity));
      moho::CollisionBeamEntity::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveManyToOneCollisionBeamEventArchiveAdapterType()
  {
    gpg::RType* type = moho::ManyToOneListener_ECollisionBeamEvent::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::ManyToOneListener_ECollisionBeamEvent));
      moho::ManyToOneListener_ECollisionBeamEvent::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveRProjectileBlueprintArchiveAdapterType()
  {
    gpg::RType* type = moho::RProjectileBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
      moho::RProjectileBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveIdPoolArchiveAdapterType()
  {
    gpg::RType* type = moho::IdPool::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::IdPool));
      moho::IdPool::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetBaseArchiveAdapterType()
  {
    gpg::RType* type = moho::EntitySetBase::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::EntitySetBase));
      moho::EntitySetBase::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveMapUIntIdPoolArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::map<unsigned int, moho::IdPool>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveListEntityPtrArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::list<moho::Entity*>));
    }
    return sType;
  }

  /**
   * Address: 0x0050AD20 (FUN_0050AD20)
   *
   * What it does:
   * Forwards one integer lane to `WriteArchive::WriteUByte`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneValueFromInt(
    gpg::WriteArchive* const archive,
    const int value
  )
  {
    archive->WriteUByte(static_cast<unsigned __int8>(value));
    return archive;
  }

  /**
   * Address: 0x0050AD40 (FUN_0050AD40)
   *
   * What it does:
   * Dereferences one byte lane and forwards it to `WriteArchive::WriteUByte`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneValueFromPointer(
    gpg::WriteArchive* const archive,
    const unsigned __int8* const value
  )
  {
    archive->WriteUByte(*value);
    return archive;
  }

  /**
   * Address: 0x0050AD60 (FUN_0050AD60)
   *
   * What it does:
   * Forwards one integer lane to `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneValueFromInt(
    gpg::WriteArchive* const archive,
    const int value
  )
  {
    archive->WriteShort(static_cast<short>(value));
    return archive;
  }

  /**
   * Address: 0x0050AD70 (FUN_0050AD70)
   *
   * What it does:
   * Dereferences one 16-bit lane and forwards it to `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneValueFromPointer(
    gpg::WriteArchive* const archive,
    const unsigned short* const value
  )
  {
    archive->WriteShort(static_cast<short>(*value));
    return archive;
  }

  /**
   * Address: 0x0050CD30 (FUN_0050CD30)
   *
   * What it does:
   * Writes two consecutive 32-bit lanes through `WriteArchive::WriteInt`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteInt32PairArchiveLanes(
    const std::int32_t* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteInt(pairValue[0]);
    archive->WriteInt(pairValue[1]);
    return archive;
  }

  /**
   * Address: 0x0050CD50 (FUN_0050CD50)
   *
   * What it does:
   * Writes two consecutive float lanes through `WriteArchive::WriteFloat`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteFloatPairArchiveLanes(
    const float* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteFloat(pairValue[0]);
    archive->WriteFloat(pairValue[1]);
    return archive;
  }

  /**
   * Address: 0x0050CD70 (FUN_0050CD70)
   *
   * What it does:
   * Writes two consecutive 16-bit signed lanes through `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortPairArchiveLanesFromSignedPointer(
    const std::int16_t* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(pairValue[0]);
    archive->WriteShort(pairValue[1]);
    return archive;
  }

  /**
   * Address: 0x0050CD90 (FUN_0050CD90)
   *
   * What it does:
   * Writes two consecutive 16-bit unsigned lanes through `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortPairArchiveLanesFromUnsignedPointer(
    const unsigned short* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(static_cast<short>(pairValue[0]));
    archive->WriteShort(static_cast<short>(pairValue[1]));
    return archive;
  }

  /**
   * Address: 0x0050D170 (FUN_0050D170)
   *
   * What it does:
   * Writes one signed 16-bit lane and returns the archive lane.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneAndReturnArchive(
    const std::int16_t value,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(value);
    return archive;
  }

  /**
   * Address: 0x0050D180 (FUN_0050D180)
   *
   * What it does:
   * Writes one referenced 16-bit lane and returns the archive lane.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneFromPointerAndReturnArchive(
    const unsigned short* const value,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(static_cast<short>(*value));
    return archive;
  }

  /**
   * Address: 0x0050D290 (FUN_0050D290)
   *
   * What it does:
   * Writes one byte lane through `WriteArchive::WriteUByte` and returns the
   * archive object for chained callsites.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneAndReturnArchive(
    gpg::WriteArchive* const archive,
    const unsigned __int8 value,
    const int /*unusedStackLane*/
  )
  {
    archive->WriteUByte(value);
    return archive;
  }

  /**
   * Address: 0x0050D2B0 (FUN_0050D2B0)
   *
   * What it does:
   * Writes one referenced byte lane and returns the archive object for
   * chained callsites.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneFromPointerAndReturnArchive(
    gpg::WriteArchive* const archive,
    const unsigned __int8* const value,
    const int /*unusedStackLane*/
  )
  {
    archive->WriteUByte(*value);
    return archive;
  }

  /**
   * Address: 0x0050D190 (FUN_0050D190)
   *
   * What it does:
   * Lazily resolves the reflected `Rect2<int>` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadRect2iArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveRect2iArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0050D210 (FUN_0050D210)
   *
   * What it does:
   * Lazily resolves the reflected `Rect2<int>` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteRect2iArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveRect2iArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0050D1D0 (FUN_0050D1D0)
   *
   * What it does:
   * Lazily resolves the reflected `ELayer` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadELayerArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveELayerArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0050D250 (FUN_0050D250)
   *
   * What it does:
   * Lazily resolves the reflected `ELayer` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteELayerArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveELayerArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x004E5920 (FUN_004E5920)
   *
   * What it does:
   * Writes one reflected `RRef_HSound` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromHSoundSlotLane1(moho::HSound** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_HSound, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x004E5B00 (FUN_004E5B00)
   *
   * What it does:
   * Writes one reflected `RRef_CSndParams` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCSndParamsSlotLane1(moho::CSndParams** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CSndParams, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x004E5B40 (FUN_004E5B40)
   *
   * What it does:
   * Writes one reflected `RRef_HSound` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromHSoundSlotLane1(moho::HSound** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_HSound, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x004E65F0 (FUN_004E65F0)
   *
   * What it does:
   * Writes one reflected `RRef_HSound` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromHSoundValueLane1(moho::HSound* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_HSound, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0050D2D0 (FUN_0050D2D0)
   *
   * What it does:
   * Lazily resolves the reflected `Rect2<int>` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  void ReadRect2iArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    gpg::RType* const objectType = ResolveRect2iArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0050D300 (FUN_0050D300)
   *
   * What it does:
   * Lazily resolves the reflected `Rect2<int>` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  void WriteRect2iArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveRect2iArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0050D330 (FUN_0050D330)
   *
   * What it does:
   * Lazily resolves the reflected `ELayer` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  void ReadELayerArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    gpg::RType* const objectType = ResolveELayerArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0050D360 (FUN_0050D360)
   *
   * What it does:
   * Lazily resolves the reflected `ELayer` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  void WriteELayerArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveELayerArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x00511070 (FUN_00511070)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRRuleGameRulesSlotLane1(moho::RRuleGameRules** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00511220 (FUN_00511220)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRRuleGameRulesSlotLane1(moho::RRuleGameRules** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005118A0 (FUN_005118A0)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRRuleGameRulesValueLane1(moho::RRuleGameRules* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00525DD0 (FUN_00525DD0)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRUnitBlueprintSlotLane1(moho::RUnitBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00526650 (FUN_00526650)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRUnitBlueprintSlotLane1(moho::RUnitBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00527590 (FUN_00527590)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRUnitBlueprintValueLane1(moho::RUnitBlueprint* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprint, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00541AD0 (FUN_00541AD0)
   *
   * What it does:
   * Writes one reflected `RRef_IUnit` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIUnitSlotLane1(moho::IUnit** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IUnit, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00541BC0 (FUN_00541BC0)
   *
   * What it does:
   * Writes one reflected `RRef_IUnit` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIUnitSlotLane1(moho::IUnit** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IUnit, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00541F10 (FUN_00541F10)
   *
   * What it does:
   * Writes one reflected `RRef_IUnit` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIUnitValueLane1(moho::IUnit* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IUnit, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0055A260 (FUN_0055A260)
   *
   * What it does:
   * Writes one reflected `RRef_RScmResource` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromRScmResourceSlotLane1(moho::RScmResource** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RScmResource, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x0055A300 (FUN_0055A300)
   *
   * What it does:
   * Writes one reflected `RRef_CSndParams` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCSndParamsSlotLane1(moho::CSndParams** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSndParams, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0055A3C0 (FUN_0055A3C0)
   *
   * What it does:
   * Writes one reflected `RRef_RScmResource` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromRScmResourceSlotLane1(moho::RScmResource** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RScmResource, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x0055A4A0 (FUN_0055A4A0)
   *
   * What it does:
   * Writes one reflected `RRef_CSndParams` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCSndParamsSlotLane2(moho::CSndParams** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CSndParams, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0055A7B0 (FUN_0055A7B0)
   *
   * What it does:
   * Writes one reflected `RRef_RScmResource` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromRScmResourceSlotLane2(moho::RScmResource** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RScmResource, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x0055AA30 (FUN_0055AA30)
   *
   * What it does:
   * Writes one reflected `RRef_CSndParams` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCSndParamsValueLane1(moho::CSndParams* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSndParams, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0055EF50 (FUN_0055EF50)
   *
   * What it does:
   * Writes one reflected `RRef_CAniPose` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCAniPoseSlotLane1(moho::CAniPose** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniPose, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x0055F4F0 (FUN_0055F4F0)
   *
   * What it does:
   * Writes one reflected `RRef_CAniPose` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromCAniPoseSlotLane1(moho::CAniPose** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniPose, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x0055FB70 (FUN_0055FB70)
   *
   * What it does:
   * Writes one reflected `RRef_CAniPose` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCAniPoseSlotLane2(moho::CAniPose** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniPose, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00584720 (FUN_00584720)
   *
   * What it does:
   * Writes one reflected `RRef_SimArmy` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromSimArmySlotLane1(moho::SimArmy** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SimArmy, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00584750 (FUN_00584750)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPersonality` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPersonalitySlotLane1(moho::CAiPersonality** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPersonality, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005849F0 (FUN_005849F0)
   *
   * What it does:
   * Writes one reflected `RRef_SimArmy` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimArmySlotLane1(moho::SimArmy** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_SimArmy, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00584A50 (FUN_00584A50)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPersonality` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCAiPersonalitySlotLane1(moho::CAiPersonality** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPersonality, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00584E40 (FUN_00584E40)
   *
   * What it does:
   * Writes one reflected `RRef_SimArmy` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromSimArmyValueLane1(moho::SimArmy* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SimArmy, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00584F80 (FUN_00584F80)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPersonality` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPersonalityValueLane1(moho::CAiPersonality* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPersonality, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00599E00 (FUN_00599E00)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommandQueue` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCUnitCommandQueueSlotLane1(moho::CUnitCommandQueue** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommandQueue, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00599EA0 (FUN_00599EA0)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommandQueue` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCUnitCommandQueueSlotLane1(moho::CUnitCommandQueue** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommandQueue, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00599FE0 (FUN_00599FE0)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommandQueue` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCUnitCommandQueueValueLane1(moho::CUnitCommandQueue* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommandQueue, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005A2710 (FUN_005A2710)
   *
   * What it does:
   * Writes one reflected `RRef_Unit` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromUnitSlotLane1(moho::Unit** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Unit, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005A27D0 (FUN_005A27D0)
   *
   * What it does:
   * Writes one reflected `RRef_Unit` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromUnitSlotLane1(moho::Unit** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Unit, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005A2A10 (FUN_005A2A10)
   *
   * What it does:
   * Writes one reflected `RRef_Unit` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromUnitValueLane1(moho::Unit* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Unit, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005A9550 (FUN_005A9550)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathNavigator` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPathNavigatorSlotLane1(moho::CAiPathNavigator** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathNavigator, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005A9750 (FUN_005A9750)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathNavigator` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCAiPathNavigatorSlotLane1(moho::CAiPathNavigator** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathNavigator, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005A99B0 (FUN_005A99B0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathNavigator` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPathNavigatorValueLane1(moho::CAiPathNavigator* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathNavigator, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005AC5A0 (FUN_005AC5A0)
   *
   * What it does:
   * Writes one reflected `RRef_PathQueue` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromPathQueueSlotLane1(moho::PathQueue** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005AC5D0 (FUN_005AC5D0)
   *
   * What it does:
   * Writes one reflected `RRef_COGrid` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCOGridSlotLane1(moho::COGrid** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_COGrid, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005AC770 (FUN_005AC770)
   *
   * What it does:
   * Writes one reflected `RRef_PathQueue` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromPathQueueSlotLane1(moho::PathQueue** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005AC7B0 (FUN_005AC7B0)
   *
   * What it does:
   * Writes one reflected `RRef_COGrid` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCOGridSlotLane1(moho::COGrid** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_COGrid, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005ACAB0 (FUN_005ACAB0)
   *
   * What it does:
   * Writes one reflected `RRef_PathQueue` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromPathQueueValueLane1(moho::PathQueue* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005ACBF0 (FUN_005ACBF0)
   *
   * What it does:
   * Writes one reflected `RRef_COGrid` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCOGridValueLane1(moho::COGrid* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_COGrid, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005B1820 (FUN_005B1820)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathFinder` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPathFinderSlotLane1(moho::CAiPathFinder** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathFinder, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005B1930 (FUN_005B1930)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathFinder` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCAiPathFinderSlotLane1(moho::CAiPathFinder** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathFinder, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005B1B60 (FUN_005B1B60)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathFinder` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPathFinderValueLane1(moho::CAiPathFinder* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathFinder, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005C9C40 (FUN_005C9C40)
   *
   * What it does:
   * Writes one reflected `RRef_ReconBlip` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromReconBlipSlotLane1(moho::ReconBlip** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ReconBlip, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005CA720 (FUN_005CA720)
   *
   * What it does:
   * Writes one reflected `RRef_ReconBlip` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromReconBlipSlotLane1(moho::ReconBlip** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_ReconBlip, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005CC480 (FUN_005CC480)
   *
   * What it does:
   * Writes one reflected `RRef_ReconBlip` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromReconBlipValueLane1(moho::ReconBlip* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ReconBlip, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005CD950 (FUN_005CD950)
   *
   * What it does:
   * Writes one reflected `RRef_CInfluenceMap` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCInfluenceMapSlotLane1(moho::CInfluenceMap** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CInfluenceMap, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005CDE00 (FUN_005CDE00)
   *
   * What it does:
   * Writes one reflected `RRef_CInfluenceMap` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCInfluenceMapSlotLane1(moho::CInfluenceMap** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CInfluenceMap, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005CE1F0 (FUN_005CE1F0)
   *
   * What it does:
   * Writes one reflected `RRef_CInfluenceMap` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCInfluenceMapValueLane1(moho::CInfluenceMap* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CInfluenceMap, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005D0CD0 (FUN_005D0CD0)
   *
   * What it does:
   * Writes one reflected `RRef_UnitWeapon` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromUnitWeaponSlotLane1(moho::UnitWeapon** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_UnitWeapon, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005D1050 (FUN_005D1050)
   *
   * What it does:
   * Writes one reflected `RRef_UnitWeapon` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromUnitWeaponSlotLane1(moho::UnitWeapon** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_UnitWeapon, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005D14F0 (FUN_005D14F0)
   *
   * What it does:
   * Writes one reflected `RRef_UnitWeapon` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromUnitWeaponValueLane1(moho::UnitWeapon* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_UnitWeapon, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005D4E50 (FUN_005D4E50)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathSpline` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPathSplineSlotLane1(moho::CAiPathSpline** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathSpline, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005D4E80 (FUN_005D4E80)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitMotion` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCUnitMotionSlotLane1(moho::CUnitMotion** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitMotion, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005D4F10 (FUN_005D4F10)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathSpline` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCAiPathSplineSlotLane1(moho::CAiPathSpline** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathSpline, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005D4F50 (FUN_005D4F50)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitMotion` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCUnitMotionSlotLane1(moho::CUnitMotion** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitMotion, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005D50F0 (FUN_005D50F0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiPathSpline` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiPathSplineValueLane1(moho::CAiPathSpline* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiPathSpline, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005D5230 (FUN_005D5230)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitMotion` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCUnitMotionValueLane1(moho::CUnitMotion* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitMotion, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005DF2A0 (FUN_005DF2A0)
   *
   * What it does:
   * Writes one reflected `RRef_CAcquireTargetTask` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAcquireTargetTaskSlotLane1(moho::CAcquireTargetTask** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAcquireTargetTask, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005DFB60 (FUN_005DFB60)
   *
   * What it does:
   * Writes one reflected `RRef_CAcquireTargetTask` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAcquireTargetTaskSlotLane1(moho::CAcquireTargetTask** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAcquireTargetTask, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005E11C0 (FUN_005E11C0)
   *
   * What it does:
   * Writes one reflected `RRef_CAcquireTargetTask` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAcquireTargetTaskValueLane1(moho::CAcquireTargetTask* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAcquireTargetTask, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005E1AC0 (FUN_005E1AC0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiAttackerImpl` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAiAttackerImplSlotLane1(moho::CAiAttackerImpl** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiAttackerImpl, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005E1F00 (FUN_005E1F00)
   *
   * What it does:
   * Writes one reflected `RRef_CAiAttackerImpl` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiAttackerImplSlotLane1(moho::CAiAttackerImpl** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiAttackerImpl, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005E22E0 (FUN_005E22E0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiAttackerImpl` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAiAttackerImplValueLane1(moho::CAiAttackerImpl* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiAttackerImpl, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005F5090 (FUN_005F5090)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommand` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCUnitCommandSlotLane1(moho::CUnitCommand** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommand, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005F50D0 (FUN_005F50D0)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommand` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCUnitCommandSlotLane1(moho::CUnitCommand** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommand, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005F5210 (FUN_005F5210)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommand` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCUnitCommandValueLane1(moho::CUnitCommand* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommand, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0060D6D0 (FUN_0060D6D0)
   *
   * What it does:
   * Writes one reflected `RRef_EAiResult` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromEAiResultSlotLane1(moho::EAiResult** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_EAiResult, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0060D770 (FUN_0060D770)
   *
   * What it does:
   * Writes one reflected `RRef_EAiResult` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromEAiResultSlotLane1(moho::EAiResult** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_EAiResult, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0060DA50 (FUN_0060DA50)
   *
   * What it does:
   * Writes one reflected `RRef_EAiResult` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromEAiResultValueLane1(moho::EAiResult* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_EAiResult, value, gpg::TrackedPointerState::Unowned);
  }

} // namespace
namespace
{
  /**
   * Address: 0x005332D0 (FUN_005332D0)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRRuleGameRulesSlotLane2(gpg::WriteArchive* archive, moho::RRuleGameRules** valueSlot)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00537220 (FUN_00537220)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRRuleGameRulesSlotLane3(moho::RRuleGameRules** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0055A400 (FUN_0055A400)
   *
   * What it does:
   * Writes one reflected `RRef_RMeshBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRMeshBlueprintSlotLane1(moho::RMeshBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RMeshBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0055F290 (FUN_0055F290)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRUnitBlueprintSlotLane2(moho::RUnitBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005DEBD0 (FUN_005DEBD0)
   *
   * What it does:
   * Writes one reflected `RRef_UnitWeapon` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromUnitWeaponValueLane1(moho::UnitWeapon* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_UnitWeapon, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005DEC00 (FUN_005DEC00)
   *
   * What it does:
   * Writes one reflected `RRef_CAcquireTargetTask` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAcquireTargetTaskValueLane1(moho::CAcquireTargetTask* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAcquireTargetTask, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005DF200 (FUN_005DF200)
   *
   * What it does:
   * Writes one reflected `RRef_Listener_EAiAttackerEvent` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromListener_EAiAttackerEventValueLane1(moho::Listener<moho::EAiAttackerEvent>* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Listener_EAiAttackerEvent, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005EC650 (FUN_005EC650)
   *
   * What it does:
   * Writes one reflected `RRef_Listener_EAiTransportEvent` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromListener_EAiTransportEventValueLane1(moho::Listener<moho::EAiTransportEvent>* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Listener_EAiTransportEvent, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00633F20 (FUN_00633F20)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprintWeapon` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRUnitBlueprintWeaponSlotLane1(moho::RUnitBlueprintWeapon** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprintWeapon, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00633F60 (FUN_00633F60)
   *
   * What it does:
   * Writes one reflected `RRef_RProjectileBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRProjectileBlueprintSlotLane1(moho::RProjectileBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RProjectileBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0063CB30 (FUN_0063CB30)
   *
   * What it does:
   * Writes one reflected `RRef_IAniManipulator` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAniManipulatorValueLane1(moho::IAniManipulator* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAniManipulator, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x0063D790 (FUN_0063D790)
   *
   * What it does:
   * Writes one reflected `RRef_CAniPose` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAniPoseSlotLane1(moho::CAniPose** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniPose, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0063DAD0 (FUN_0063DAD0)
   *
   * What it does:
   * Writes one reflected `RRef_CAniPose` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAniPoseSlotLane1(moho::CAniPose** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniPose, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0063E640 (FUN_0063E640)
   *
   * What it does:
   * Writes one reflected `RRef_CAniPose` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAniPoseValueLane1(moho::CAniPose* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniPose, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0063E900 (FUN_0063E900)
   *
   * What it does:
   * Writes one reflected `RRef_CAniActor` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAniActorSlotLane1(moho::CAniActor** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniActor, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0063EA00 (FUN_0063EA00)
   *
   * What it does:
   * Writes one reflected `RRef_CAniActor` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAniActorSlotLane1(moho::CAniActor** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniActor, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0063ED80 (FUN_0063ED80)
   *
   * What it does:
   * Writes one reflected `RRef_CAniActor` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAniActorValueLane1(moho::CAniActor* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniActor, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0064A040 (FUN_0064A040)
   *
   * What it does:
   * Lazily resolves the reflected `EEconResource` type and reads one object
   * lane through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadEEconResourceArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveEEconResourceArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0064A080 (FUN_0064A080)
   *
   * What it does:
   * Lazily resolves the reflected `EEconResource` type and writes one object
   * lane through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteEEconResourceArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveEEconResourceArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0064A0C0 (FUN_0064A0C0)
   *
   * What it does:
   * Lazily resolves the reflected `EEconResource` type and reads one object
   * lane through `ReadArchive::Read` using the provided owner reference.
   */
  void ReadEEconResourceArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveEEconResourceArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0064A0F0 (FUN_0064A0F0)
   *
   * What it does:
   * Lazily resolves the reflected `EEconResource` type and writes one object
   * lane through `WriteArchive::Write` using the provided owner reference.
   */
  void WriteEEconResourceArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveEEconResourceArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0064B4F0 (FUN_0064B4F0)
   *
   * What it does:
   * Upcasts one reflected reference to `CThrustManipulator` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::CThrustManipulator* func_CastCThrustManipulator(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCThrustManipulatorArchiveAdapterType());
    return static_cast<moho::CThrustManipulator*>(upcast.mObj);
  }

  /**
   * Address: 0x00652940 (FUN_00652940)
   *
   * What it does:
   * Upcasts one reflected reference to `RDebugOverlay` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::RDebugOverlay* func_CastRDebugOverlay(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveRDebugOverlayArchiveAdapterType());
    return static_cast<moho::RDebugOverlay*>(upcast.mObj);
  }

  /**
   * Address: 0x00658C20 (FUN_00658C20)
   *
   * What it does:
   * Lazily resolves the reflected `CEffectImpl` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadCEffectImplArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveCEffectImplArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00658C60 (FUN_00658C60)
   *
   * What it does:
   * Lazily resolves the reflected `SEntAttachInfo` type and reads one object
   * lane through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadSEntAttachInfoArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveSEntAttachInfoArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00658CA0 (FUN_00658CA0)
   *
   * What it does:
   * Lazily resolves the reflected `SWorldBeam` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadSWorldBeamArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveSWorldBeamArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00658CE0 (FUN_00658CE0)
   *
   * What it does:
   * Lazily resolves the reflected `CEffectImpl` type and writes one object
   * lane through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteCEffectImplArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveCEffectImplArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00658D20 (FUN_00658D20)
   *
   * What it does:
   * Lazily resolves the reflected `SEntAttachInfo` type and writes one object
   * lane through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteSEntAttachInfoArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveSEntAttachInfoArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00658D60 (FUN_00658D60)
   *
   * What it does:
   * Lazily resolves the reflected `SWorldBeam` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteSWorldBeamArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveSWorldBeamArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x006605A0 (FUN_006605A0)
   *
   * What it does:
   * Writes one reflected `RRef_REmitterBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromREmitterBlueprintSlotLane1(moho::REmitterBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_REmitterBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006606E0 (FUN_006606E0)
   *
   * What it does:
   * Writes one reflected `RRef_REmitterBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromREmitterBlueprintSlotLane1(moho::REmitterBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_REmitterBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006608C0 (FUN_006608C0)
   *
   * What it does:
   * Writes one reflected `RRef_REmitterBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromREmitterBlueprintValueLane1(moho::REmitterBlueprint* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_REmitterBlueprint, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006608F0 (FUN_006608F0)
   *
   * What it does:
   * Upcasts one reflected reference to `REmitterBlueprint` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::REmitterBlueprint* func_CastREmitterBlueprint(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveREmitterBlueprintArchiveAdapterType());
    return static_cast<moho::REmitterBlueprint*>(upcast.mObj);
  }

  /**
   * Address: 0x00672950 (FUN_00672950)
   *
   * What it does:
   * Writes one reflected `RRef_RTrailBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRTrailBlueprintSlotLane1(moho::RTrailBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RTrailBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00672990 (FUN_00672990)
   *
   * What it does:
   * Writes one reflected `RRef_RTrailBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromRTrailBlueprintSlotLane1(moho::RTrailBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RTrailBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00672AD0 (FUN_00672AD0)
   *
   * What it does:
   * Writes one reflected `RRef_RTrailBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRTrailBlueprintValueLane1(moho::RTrailBlueprint* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RTrailBlueprint, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00672B00 (FUN_00672B00)
   *
   * What it does:
   * Upcasts one reflected reference to `RTrailBlueprint` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::RTrailBlueprint* func_CastRTrailBlueprint(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveRTrailBlueprintArchiveAdapterType());
    return static_cast<moho::RTrailBlueprint*>(upcast.mObj);
  }

  /**
   * Address: 0x00675F80 (FUN_00675F80)
   *
   * What it does:
   * Upcasts one reflected reference to `CollisionBeamEntity` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::CollisionBeamEntity* func_CastCollisionBeamEntity(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCollisionBeamEntityArchiveAdapterType());
    return static_cast<moho::CollisionBeamEntity*>(upcast.mObj);
  }

  /**
   * Address: 0x00675FC0 (FUN_00675FC0)
   *
   * What it does:
   * Upcasts one reflected reference to `ManyToOneListener_ECollisionBeamEvent`
   * and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::ManyToOneListener_ECollisionBeamEvent*
  func_CastManyToOneListener_ECollisionBeamEvent(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveManyToOneCollisionBeamEventArchiveAdapterType());
    return static_cast<moho::ManyToOneListener_ECollisionBeamEvent*>(upcast.mObj);
  }

  /**
   * Address: 0x0067F0A0 (FUN_0067F0A0)
   *
   * What it does:
   * Upcasts one reflected reference to `RProjectileBlueprint` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::RProjectileBlueprint* func_CastRProjectileBlueprint(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveRProjectileBlueprintArchiveAdapterType());
    return static_cast<moho::RProjectileBlueprint*>(upcast.mObj);
  }

  /**
   * Address: 0x0067F890 (FUN_0067F890)
   *
   * What it does:
   * Writes one reflected `RRef_Entity` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromEntitySlotLane1(moho::Entity** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Entity, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006810C0 (FUN_006810C0)
   *
   * What it does:
   * Writes one reflected `RRef_Entity` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromEntityValueLane1(moho::Entity* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Entity, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00682110 (FUN_00682110)
   *
   * What it does:
   * Writes one reflected `RRef_PositionHistory` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromPositionHistorySlotLane1(moho::PositionHistory** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PositionHistory, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682140 (FUN_00682140)
   *
   * What it does:
   * Writes one reflected `RRef_CColPrimitiveBase` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCColPrimitiveBaseSlotLane1(moho::CColPrimitiveBase** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CColPrimitiveBase, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006821F0 (FUN_006821F0)
   *
   * What it does:
   * Writes one reflected `RRef_CIntel` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCIntelSlotLane1(moho::CIntel** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntel, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682250 (FUN_00682250)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysBody` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromSPhysBodySlotLane1(moho::SPhysBody** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysBody, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682280 (FUN_00682280)
   *
   * What it does:
   * Writes one reflected `RRef_Motor` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromMotorSlotLane1(moho::EntityMotor** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Motor, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682520 (FUN_00682520)
   *
   * What it does:
   * Writes one reflected `RRef_PositionHistory` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromPositionHistorySlotLane1(moho::PositionHistory** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PositionHistory, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682570 (FUN_00682570)
   *
   * What it does:
   * Writes one reflected `RRef_CColPrimitiveBase` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCColPrimitiveBaseSlotLane1(moho::CColPrimitiveBase** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CColPrimitiveBase, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006826A0 (FUN_006826A0)
   *
   * What it does:
   * Writes one reflected `RRef_CIntel` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCIntelSlotLane1(moho::CIntel** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntel, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682750 (FUN_00682750)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysBody` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromSPhysBodySlotLane1(moho::SPhysBody** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysBody, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006827B0 (FUN_006827B0)
   *
   * What it does:
   * Writes one reflected `RRef_Motor` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromMotorSlotLane1(moho::EntityMotor** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Motor, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682B00 (FUN_00682B00)
   *
   * What it does:
   * Writes one reflected `RRef_PositionHistory` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromPositionHistoryValueLane1(moho::PositionHistory* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PositionHistory, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682C40 (FUN_00682C40)
   *
   * What it does:
   * Writes one reflected `RRef_CColPrimitiveBase` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCColPrimitiveBaseValueLane1(moho::CColPrimitiveBase* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CColPrimitiveBase, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682D80 (FUN_00682D80)
   *
   * What it does:
   * Writes one reflected `RRef_CIntel` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCIntelValueLane1(moho::CIntel* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntel, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00683000 (FUN_00683000)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysBody` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromSPhysBodyValueLane1(moho::SPhysBody* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysBody, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00683140 (FUN_00683140)
   *
   * What it does:
   * Writes one reflected `RRef_Motor` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromMotorValueLane1(moho::EntityMotor* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Motor, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00688BE0 (FUN_00688BE0)
   *
   * What it does:
   * Writes one reflected `RRef_EntitySetBase` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromEntitySetBaseSlotLane1(moho::EntitySetBase** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_EntitySetBase, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00688C50 (FUN_00688C50)
   *
   * What it does:
   * Lazily resolves the reflected `IdPool` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadIdPoolArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveIdPoolArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00688C90 (FUN_00688C90)
   *
   * What it does:
   * Lazily resolves the reflected `IdPool` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteIdPoolArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveIdPoolArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00689160 (FUN_00689160)
   *
   * What it does:
   * Writes one reflected `RRef_EntitySetBase` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromEntitySetBaseSlotLane1(moho::EntitySetBase** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_EntitySetBase, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00689190 (FUN_00689190)
   *
   * What it does:
   * Lazily resolves the reflected `IdPool` type and reads one object lane
   * through `ReadArchive::Read` using the provided owner reference.
   */
  void ReadIdPoolArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveIdPoolArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x006891C0 (FUN_006891C0)
   *
   * What it does:
   * Lazily resolves the reflected `IdPool` type and writes one object lane
   * through `WriteArchive::Write` using the provided owner reference.
   */
  void WriteIdPoolArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveIdPoolArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x006896B0 (FUN_006896B0)
   *
   * What it does:
   * Writes one reflected `RRef_EntitySetBase` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromEntitySetBaseValueLane1(moho::EntitySetBase* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_EntitySetBase, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006898E0 (FUN_006898E0)
   *
   * What it does:
   * Upcasts one reflected reference to `EntitySetBase` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::EntitySetBase* func_CastEntitySetBase(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveEntitySetBaseArchiveAdapterType());
    return static_cast<moho::EntitySetBase*>(upcast.mObj);
  }

  /**
   * Address: 0x00689B40 (FUN_00689B40)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int,IdPool>` type and reads
   * one object lane through `ReadArchive::Read` using the provided owner
   * reference.
   */
  gpg::ReadArchive* ReadMapUIntIdPoolArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIdPoolArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00689B80 (FUN_00689B80)
   *
   * What it does:
   * Lazily resolves the reflected `list<Entity*>` type and reads one object
   * lane through `ReadArchive::Read` using the provided owner reference.
   */
  gpg::ReadArchive* ReadListEntityPtrArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveListEntityPtrArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00689BC0 (FUN_00689BC0)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int,IdPool>` type and writes
   * one object lane through `WriteArchive::Write` using the provided owner
   * reference.
   */
  gpg::WriteArchive* WriteMapUIntIdPoolArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIdPoolArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00689C00 (FUN_00689C00)
   *
   * What it does:
   * Lazily resolves the reflected `list<Entity*>` type and writes one object
   * lane through `WriteArchive::Write` using the provided owner reference.
   */
  gpg::WriteArchive* WriteListEntityPtrArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveListEntityPtrArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00689C70 (FUN_00689C70)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int,IdPool>` type and reads
   * one object lane through `ReadArchive::Read` using the provided owner
   * reference.
   */
  void ReadMapUIntIdPoolArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIdPoolArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x00689CA0 (FUN_00689CA0)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int,IdPool>` type and writes
   * one object lane through `WriteArchive::Write` using the provided owner
   * reference.
   */
  void WriteMapUIntIdPoolArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIdPoolArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x00689CD0 (FUN_00689CD0)
   *
   * What it does:
   * Lazily resolves the reflected `list<Entity*>` type and reads one object
   * lane through `ReadArchive::Read` using the provided owner reference.
   */
  void ReadListEntityPtrArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveListEntityPtrArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x00689D00 (FUN_00689D00)
   *
   * What it does:
   * Lazily resolves the reflected `list<Entity*>` type and writes one object
   * lane through `WriteArchive::Write` using the provided owner reference.
   */
  void WriteListEntityPtrArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveListEntityPtrArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x006941E0 (FUN_006941E0)
   *
   * What it does:
   * Lazily resolves the reflected `EntitySetBase` type and reads one object
   * lane through `ReadArchive::Read` with one local null owner reference.
   */
  void ReadEntitySetBaseArchiveObjectWithNullOwner(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RType* const objectType = ResolveEntitySetBaseArchiveAdapterType();
    gpg::RRef ownerRef{};
    archive->Read(objectType, object, ownerRef);
  }

  /**
   * Address: 0x00694220 (FUN_00694220)
   *
   * What it does:
   * Lazily resolves the reflected `EntitySetBase` type and writes one object
   * lane through `WriteArchive::Write` with one local null owner reference.
   */
  void WriteEntitySetBaseArchiveObjectWithNullOwner(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    gpg::RType* const objectType = ResolveEntitySetBaseArchiveAdapterType();
    const gpg::RRef ownerRef{};
    archive->Write(objectType, objectSlot, ownerRef);
  }

  /**
   * Address: 0x006988B0 (FUN_006988B0)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysConstants` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSPhysConstantsSlotLane1(moho::SPhysConstants** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysConstants, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006B40D0 (FUN_006B40D0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiSteering` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiSteeringSlotLane1(moho::IAiSteering** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiSteering, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4100 (FUN_006B4100)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitMotion` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCUnitMotionSlotLane1(moho::CUnitMotion** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitMotion, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4130 (FUN_006B4130)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommandQueue` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCUnitCommandQueueSlotLane1(moho::CUnitCommandQueue** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommandQueue, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B41C0 (FUN_006B41C0)
   *
   * What it does:
   * Writes one reflected `RRef_CAniActor` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAniActorSlotLane1(moho::CAniActor** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniActor, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B41F0 (FUN_006B41F0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiAttacker` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiAttackerSlotLane1(moho::IAiAttacker** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiAttacker, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4220 (FUN_006B4220)
   *
   * What it does:
   * Writes one reflected `RRef_IAiCommandDispatch` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiCommandDispatchSlotLane1(moho::IAiCommandDispatch** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiCommandDispatch, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4250 (FUN_006B4250)
   *
   * What it does:
   * Writes one reflected `RRef_IAiNavigator` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiNavigatorSlotLane1(moho::IAiNavigator** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiNavigator, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4280 (FUN_006B4280)
   *
   * What it does:
   * Writes one reflected `RRef_IAiBuilder` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiBuilderSlotLane1(moho::IAiBuilder** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiBuilder, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B42B0 (FUN_006B42B0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiSiloBuild` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiSiloBuildSlotLane1(moho::IAiSiloBuild** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiSiloBuild, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B42E0 (FUN_006B42E0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiTransport` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiTransportSlotLane1(moho::IAiTransport** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiTransport, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4450 (FUN_006B4450)
   *
   * What it does:
   * Writes one reflected `RRef_IAiSteering` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiSteeringSlotLane1(moho::IAiSteering** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiSteering, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B44B0 (FUN_006B44B0)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitMotion` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCUnitMotionSlotLane1(moho::CUnitMotion** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitMotion, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4510 (FUN_006B4510)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommandQueue` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCUnitCommandQueueSlotLane1(moho::CUnitCommandQueue** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommandQueue, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4630 (FUN_006B4630)
   *
   * What it does:
   * Writes one reflected `RRef_CAniActor` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCAniActorSlotLane1(moho::CAniActor** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniActor, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4680 (FUN_006B4680)
   *
   * What it does:
   * Writes one reflected `RRef_IAiAttacker` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiAttackerSlotLane1(moho::IAiAttacker** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiAttacker, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B46D0 (FUN_006B46D0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiCommandDispatch` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiCommandDispatchSlotLane1(moho::IAiCommandDispatch** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiCommandDispatch, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4720 (FUN_006B4720)
   *
   * What it does:
   * Writes one reflected `RRef_IAiNavigator` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiNavigatorSlotLane1(moho::IAiNavigator** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiNavigator, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4770 (FUN_006B4770)
   *
   * What it does:
   * Writes one reflected `RRef_IAiBuilder` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiBuilderSlotLane1(moho::IAiBuilder** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiBuilder, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B47C0 (FUN_006B47C0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiSiloBuild` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiSiloBuildSlotLane1(moho::IAiSiloBuild** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiSiloBuild, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4810 (FUN_006B4810)
   *
   * What it does:
   * Writes one reflected `RRef_IAiTransport` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiTransportSlotLane1(moho::IAiTransport** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiTransport, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4B80 (FUN_006B4B80)
   *
   * What it does:
   * Writes one reflected `RRef_IAiSteering` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiSteeringValueLane1(moho::IAiSteering* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiSteering, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4CC0 (FUN_006B4CC0)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitMotion` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCUnitMotionValueLane1(moho::CUnitMotion* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitMotion, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4E00 (FUN_006B4E00)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommandQueue` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCUnitCommandQueueValueLane1(moho::CUnitCommandQueue* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommandQueue, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B51C0 (FUN_006B51C0)
   *
   * What it does:
   * Writes one reflected `RRef_CAniActor` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAniActorValueLane1(moho::CAniActor* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniActor, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B5300 (FUN_006B5300)
   *
   * What it does:
   * Writes one reflected `RRef_IAiAttacker` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiAttackerValueLane1(moho::IAiAttacker* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiAttacker, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B5440 (FUN_006B5440)
   *
   * What it does:
   * Writes one reflected `RRef_IAiCommandDispatch` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiCommandDispatchValueLane1(moho::IAiCommandDispatch* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiCommandDispatch, value, gpg::TrackedPointerState::Owned);
  }

} // namespace
namespace
{
  /**
   * Address: 0x006B5580 (FUN_006B5580)
   *
   * What it does:
   * Writes one reflected `RRef_IAiNavigator` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiNavigatorValueLane1(moho::IAiNavigator* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiNavigator, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B56C0 (FUN_006B56C0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiBuilder` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiBuilderValueLane1(moho::IAiBuilder* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiBuilder, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B5800 (FUN_006B5800)
   *
   * What it does:
   * Writes one reflected `RRef_IAiSiloBuild` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiSiloBuildValueLane1(moho::IAiSiloBuild* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiSiloBuild, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B5940 (FUN_006B5940)
   *
   * What it does:
   * Writes one reflected `RRef_IAiTransport` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiTransportValueLane1(moho::IAiTransport* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiTransport, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006BBF70 (FUN_006BBF70)
   *
   * What it does:
   * Writes one reflected `RRef_CPathPoint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCPathPointSlotLane1(moho::CPathPoint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CPathPoint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006DFDB0 (FUN_006DFDB0)
   *
   * What it does:
   * Reads one owned `CFireWeaponTask` pointer lane, swaps it into the
   * destination slot, and deletes the replaced task object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCFireWeaponTaskSlotLaneLegacyA(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CFireWeaponTask** const valueSlot
  )
  {
    moho::CFireWeaponTask* loadedValue = nullptr;
    archive->ReadPointerOwned_CFireWeaponTask(&loadedValue, ownerRef);

    moho::CFireWeaponTask* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006E0200 (FUN_006E0200)
   *
   * What it does:
   * Alternate argument-order wrapper for `ReadPointer_IAiAttacker`.
   */
  gpg::ReadArchive* ReadRawPointerFromIAiAttackerSlotLaneLegacyA(
    gpg::RRef* const ownerRef, moho::IAiAttacker** const valueSlot, gpg::ReadArchive* const archive
  )
  {
    return archive->ReadPointer_IAiAttacker(valueSlot, ownerRef);
  }

  /**
   * Address: 0x006E02A0 (FUN_006E02A0)
   *
   * What it does:
   * Reads one owned `CFireWeaponTask` pointer lane (starting from one seed
   * pointer register lane), swaps it into the destination slot, and deletes the
   * replaced task object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCFireWeaponTaskSlotLaneLegacyB(
    gpg::RRef* const ownerRef,
    moho::CFireWeaponTask* seedValue,
    gpg::ReadArchive* const archive,
    moho::CFireWeaponTask** const valueSlot
  )
  {
    gpg::ReadArchive* const result = archive->ReadPointerOwned_CFireWeaponTask(&seedValue, ownerRef);
    moho::CFireWeaponTask* const previousValue = *valueSlot;
    *valueSlot = seedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return result;
  }

  /**
   * Address: 0x006DFE60 (FUN_006DFE60)
   *
   * What it does:
   * Writes one reflected `RRef_IAiAttacker` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIAiAttackerSlotLane1(moho::IAiAttacker** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiAttacker, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006DFED0 (FUN_006DFED0)
   *
   * What it does:
   * Writes one reflected `RRef_CFireWeaponTask` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCFireWeaponTaskSlotLane1(moho::CFireWeaponTask** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CFireWeaponTask, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006E0210 (FUN_006E0210)
   *
   * What it does:
   * Writes one reflected `RRef_IAiAttacker` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIAiAttackerSlotLane1(moho::IAiAttacker** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiAttacker, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006E02C0 (FUN_006E02C0)
   *
   * What it does:
   * Writes one reflected `RRef_CFireWeaponTask` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCFireWeaponTaskSlotLane1(moho::CFireWeaponTask** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CFireWeaponTask, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006E0610 (FUN_006E0610)
   *
   * What it does:
   * Writes one reflected `RRef_IAiAttacker` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIAiAttackerValueLane1(moho::IAiAttacker* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiAttacker, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006E0750 (FUN_006E0750)
   *
   * What it does:
   * Writes one reflected `RRef_CFireWeaponTask` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCFireWeaponTaskValueLane1(moho::CFireWeaponTask* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CFireWeaponTask, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006E2B00 (FUN_006E2B00)
   *
   * What it does:
   * Writes one reflected `RRef_CUnitCommand` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCUnitCommandValueLane1(moho::CUnitCommand* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommand, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006EB980 (FUN_006EB980)
   *
   * What it does:
   * Writes one reflected `RRef_Listener_ECommandEvent` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromListener_ECommandEventValueLane1(moho::Listener<moho::ECommandEvent>* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Listener_ECommandEvent, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00706650 (FUN_00706650)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiBrainSlotLane1(moho::CAiBrain** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706680 (FUN_00706680)
   *
   * What it does:
   * Writes one reflected `RRef_IAiReconDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiReconDBSlotLane1(moho::IAiReconDB** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiReconDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007066E0 (FUN_007066E0)
   *
   * What it does:
   * Writes one reflected `RRef_CArmyStats` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCArmyStatsSlotLane1(moho::CArmyStats** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStats, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706710 (FUN_00706710)
   *
   * What it does:
   * Writes one reflected `RRef_CInfluenceMap` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCInfluenceMapSlotLane1(moho::CInfluenceMap** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CInfluenceMap, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706740 (FUN_00706740)
   *
   * What it does:
   * Writes one reflected `RRef_PathQueue` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromPathQueueSlotLane1(moho::PathQueue** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706A80 (FUN_00706A80)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCAiBrainSlotLane1(moho::CAiBrain** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706AD0 (FUN_00706AD0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiReconDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiReconDBSlotLane1(moho::IAiReconDB** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiReconDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706B90 (FUN_00706B90)
   *
   * What it does:
   * Writes one reflected `RRef_CArmyStats` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCArmyStatsSlotLane1(moho::CArmyStats** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStats, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706BF0 (FUN_00706BF0)
   *
   * What it does:
   * Writes one reflected `RRef_CInfluenceMap` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCInfluenceMapSlotLane1(moho::CInfluenceMap** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CInfluenceMap, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706F30 (FUN_00706F30)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCAiBrainValueLane1(moho::CAiBrain* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00707070 (FUN_00707070)
   *
   * What it does:
   * Writes one reflected `RRef_IAiReconDB` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiReconDBValueLane1(moho::IAiReconDB* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiReconDB, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007072F0 (FUN_007072F0)
   *
   * What it does:
   * Writes one reflected `RRef_CArmyStats` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCArmyStatsValueLane1(moho::CArmyStats* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStats, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00707430 (FUN_00707430)
   *
   * What it does:
   * Writes one reflected `RRef_CInfluenceMap` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCInfluenceMapValueLane1(moho::CInfluenceMap* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CInfluenceMap, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00707570 (FUN_00707570)
   *
   * What it does:
   * Writes one reflected `RRef_PathQueue` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromPathQueueValueLane1(moho::PathQueue* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00712650 (FUN_00712650)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAiBrainSlotLane1(moho::CAiBrain** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00712980 (FUN_00712980)
   *
   * What it does:
   * Writes one reflected `RRef_STrigger` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromSTriggerSlotLane1(moho::STrigger** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_STrigger, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00712FD0 (FUN_00712FD0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiBrainSlotLane1(moho::CAiBrain** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00713100 (FUN_00713100)
   *
   * What it does:
   * Writes one reflected `RRef_STrigger` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromSTriggerSlotLane1(moho::STrigger** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_STrigger, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00714040 (FUN_00714040)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCAiBrainValueLane1(moho::CAiBrain* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x007144D0 (FUN_007144D0)
   *
   * What it does:
   * Writes one reflected `RRef_STrigger` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromSTriggerSlotLane2(moho::STrigger** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_STrigger, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00750FA0 (FUN_00750FA0)
   *
   * What it does:
   * Writes one reflected `RRef_SimArmy` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromSimArmyValueLane1(moho::SimArmy* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SimArmy, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00751870 (FUN_00751870)
   *
   * What it does:
   * Writes one reflected `RRef_Shield` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromShieldSlotLane1(moho::Shield** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Shield, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x007523F0 (FUN_007523F0)
   *
   * What it does:
   * Writes one reflected `RRef_Shield` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromShieldSlotLane1(moho::Shield** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Shield, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x007546B0 (FUN_007546B0)
   *
   * What it does:
   * Writes one reflected `RRef_Shield` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromShieldValueLane1(moho::Shield* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Shield, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00756250 (FUN_00756250)
   *
   * What it does:
   * Reads one owned `CRandomStream` pointer lane, swaps it into the destination
   * slot, and deallocates the replaced stream storage when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCRandomStreamSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CRandomStream** const valueSlot
  )
  {
    moho::CRandomStream* loadedValue = nullptr;
    archive->ReadPointerOwned_CRandomStream(&loadedValue, ownerRef);

    moho::CRandomStream* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x00756280 (FUN_00756280)
   *
   * What it does:
   * Reads one owned `SPhysConstants` pointer lane, swaps it into the
   * destination slot, then deallocates the replaced storage lane.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromSPhysConstantsSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::SPhysConstants** const valueSlot
  )
  {
    moho::SPhysConstants* loadedValue = nullptr;
    archive->ReadPointerOwned_SPhysConstants(&loadedValue, ownerRef);

    moho::SPhysConstants* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    ::operator delete(previousValue);
    return archive;
  }

  /**
   * Address: 0x007562F0 (FUN_007562F0)
   *
   * What it does:
   * Reads one owned `IAiFormationDB` pointer lane, swaps it into the
   * destination slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiFormationDBSlotLane1(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiFormationDB** const valueSlot
  )
  {
    moho::IAiFormationDB* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiFormationDB(&loadedValue, ownerRef);

    moho::IAiFormationDB* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x00756330 (FUN_00756330)
   *
   * What it does:
   * Reads one owned `CCommandDb` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced command-db object when it differs.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCCommandDbSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CCommandDb** const valueSlot
  )
  {
    moho::CCommandDb* loadedValue = nullptr;
    archive->ReadPointerOwned_CCommandDB(&loadedValue, ownerRef);

    moho::CCommandDb* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CCommandDb();
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x00756360 (FUN_00756360)
   *
   * What it does:
   * Reads one owned `CDecalBuffer` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced decal buffer when it differs.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCDecalBufferSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CDecalBuffer** const valueSlot
  )
  {
    moho::CDecalBuffer* loadedValue = nullptr;
    archive->ReadPointerOwned_CDecalBuffer(&loadedValue, ownerRef);

    moho::CDecalBuffer* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CDecalBuffer();
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x00756390 (FUN_00756390)
   *
   * What it does:
   * Reads one owned `IEffectManager` pointer lane, swaps it into the
   * destination slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIEffectManagerSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IEffectManager** const valueSlot
  )
  {
    moho::IEffectManager* loadedValue = nullptr;
    archive->ReadPointerOwned_IEffectManager(&loadedValue, ownerRef);

    moho::IEffectManager* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x007563C0 (FUN_007563C0)
   *
   * What it does:
   * Reads one owned `ISoundManager` pointer lane, swaps it into the
   * destination slot, and dispatches deleting teardown on the replaced
   * interface object.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromISoundManagerSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::ISoundManager** const valueSlot
  )
  {
    moho::ISoundManager* loadedValue = nullptr;
    archive->ReadPointerOwned_ISoundManager(&loadedValue, ownerRef);

    moho::ISoundManager* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->Destroy(1);
    }
    return archive;
  }

  /**
   * Address: 0x00756430 (FUN_00756430)
   *
   * What it does:
   * Reads one owned `CEntityDb` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced entity-db object when it differs.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCEntityDbSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CEntityDb** const valueSlot
  )
  {
    moho::CEntityDb* loadedValue = nullptr;
    archive->ReadPointerOwned_EntityDB(&loadedValue, ownerRef);

    moho::CEntityDb* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CEntityDb();
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x00756460 (FUN_00756460)
   *
   * What it does:
   * Writes one reflected `RRef_CRandomStream` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCRandomStreamSlotLane1(moho::CRandomStream** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CRandomStream, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756490 (FUN_00756490)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysConstants` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromSPhysConstantsSlotLane1(moho::SPhysConstants** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysConstants, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756500 (FUN_00756500)
   *
   * What it does:
   * Writes one reflected `RRef_IAiFormationDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiFormationDBSlotLane1(moho::IAiFormationDB** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiFormationDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756530 (FUN_00756530)
   *
   * What it does:
   * Writes one reflected `RRef_ISimResources` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromISimResourcesSlotLane1(moho::ISimResources** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ISimResources, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00756560 (FUN_00756560)
   *
   * What it does:
   * Writes one reflected `RRef_CCommandDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCCommandDBSlotLane1(moho::CCommandDb** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CCommandDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756590 (FUN_00756590)
   *
   * What it does:
   * Writes one reflected `RRef_CDecalBuffer` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCDecalBufferSlotLane1(moho::CDecalBuffer** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CDecalBuffer, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007565C0 (FUN_007565C0)
   *
   * What it does:
   * Writes one reflected `RRef_IEffectManager` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIEffectManagerSlotLane1(moho::IEffectManager** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffectManager, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007565F0 (FUN_007565F0)
   *
   * What it does:
   * Writes one reflected `RRef_ISoundManager` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromISoundManagerSlotLane1(moho::ISoundManager** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ISoundManager, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756660 (FUN_00756660)
   *
   * What it does:
   * Writes one reflected `RRef_EntityDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromEntityDBSlotLane1(moho::CEntityDb** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_EntityDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756E20 (FUN_00756E20)
   *
   * What it does:
   * Writes one reflected `RRef_CRandomStream` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCRandomStreamSlotLane1(moho::CRandomStream** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CRandomStream, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756E70 (FUN_00756E70)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysConstants` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromSPhysConstantsSlotLane1(moho::SPhysConstants** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysConstants, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756F20 (FUN_00756F20)
   *
   * What it does:
   * Writes one reflected `RRef_IAiFormationDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIAiFormationDBSlotLane1(moho::IAiFormationDB** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiFormationDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756F60 (FUN_00756F60)
   *
   * What it does:
   * Writes one reflected `RRef_ISimResources` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromISimResourcesSlotLane1(moho::ISimResources** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_ISimResources, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00756F90 (FUN_00756F90)
   *
   * What it does:
   * Reads one owned `CCommandDb` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced command-db object when it differs.
   */
  void LoadOwnedRawPointerFromCCommandDbSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CCommandDb** const valueSlot
  )
  {
    moho::CCommandDb* loadedValue = nullptr;
    archive->ReadPointerOwned_CCommandDB(&loadedValue, ownerRef);

    moho::CCommandDb* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CCommandDb();
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x00756FC0 (FUN_00756FC0)
   *
   * What it does:
   * Writes one reflected `RRef_CCommandDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCCommandDBSlotLane1(moho::CCommandDb** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CCommandDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00756FF0 (FUN_00756FF0)
   *
   * What it does:
   * Reads one owned `CDecalBuffer` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced decal buffer when it differs.
   */
  void LoadOwnedRawPointerFromCDecalBufferSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CDecalBuffer** const valueSlot
  )
  {
    moho::CDecalBuffer* loadedValue = nullptr;
    archive->ReadPointerOwned_CDecalBuffer(&loadedValue, ownerRef);

    moho::CDecalBuffer* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CDecalBuffer();
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x00757020 (FUN_00757020)
   *
   * What it does:
   * Writes one reflected `RRef_CDecalBuffer` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCDecalBufferSlotLane1(moho::CDecalBuffer** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CDecalBuffer, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757070 (FUN_00757070)
   *
   * What it does:
   * Writes one reflected `RRef_IEffectManager` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIEffectManagerSlotLane1(moho::IEffectManager** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffectManager, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007570D0 (FUN_007570D0)
   *
   * What it does:
   * Writes one reflected `RRef_ISoundManager` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromISoundManagerSlotLane1(moho::ISoundManager** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_ISoundManager, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757160 (FUN_00757160)
   *
   * What it does:
   * Reads one owned `CEntityDb` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced entity-db object when it differs.
   */
  void LoadOwnedRawPointerFromCEntityDbSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CEntityDb** const valueSlot
  )
  {
    moho::CEntityDb* loadedValue = nullptr;
    archive->ReadPointerOwned_EntityDB(&loadedValue, ownerRef);

    moho::CEntityDb* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CEntityDb();
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x00757190 (FUN_00757190)
   *
   * What it does:
   * Writes one reflected `RRef_EntityDB` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromEntityDBSlotLane1(moho::CEntityDb** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_EntityDB, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757650 (FUN_00757650)
   *
   * What it does:
   * Writes one reflected `RRef_CRandomStream` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCRandomStreamValueLane1(moho::CRandomStream* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CRandomStream, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757790 (FUN_00757790)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysConstants` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromSPhysConstantsValueLane1(moho::SPhysConstants* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysConstants, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007578D0 (FUN_007578D0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiFormationDB` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAiFormationDBValueLane1(moho::IAiFormationDB* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiFormationDB, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757AE0 (FUN_00757AE0)
   *
   * What it does:
   * Writes one reflected `RRef_ISimResources` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromISimResourcesSlotLane2(moho::ISimResources** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ISimResources, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00757C20 (FUN_00757C20)
   *
   * What it does:
   * Writes one reflected `RRef_CCommandDB` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCCommandDBValueLane1(moho::CCommandDb* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CCommandDB, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757D60 (FUN_00757D60)
   *
   * What it does:
   * Writes one reflected `RRef_CDecalBuffer` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCDecalBufferValueLane1(moho::CDecalBuffer* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CDecalBuffer, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757EA0 (FUN_00757EA0)
   *
   * What it does:
   * Writes one reflected `RRef_IEffectManager` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIEffectManagerValueLane1(moho::IEffectManager* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffectManager, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00757FE0 (FUN_00757FE0)
   *
   * What it does:
   * Writes one reflected `RRef_ISoundManager` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromISoundManagerValueLane1(moho::ISoundManager* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ISoundManager, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00758120 (FUN_00758120)
   *
   * What it does:
   * Writes one reflected `RRef_EntityDB` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromEntityDBValueLane1(moho::CEntityDb* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_EntityDB, value, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00763D90 (FUN_00763D90)
   *
   * What it does:
   * Writes one reflected `RRef_Listener_NavPath` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromListener_NavPathValueLane1(moho::Listener<const moho::SNavPath&>* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Listener_NavPath, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00768C10 (FUN_00768C10)
   *
   * What it does:
   * Writes one reflected `RRef_IPathTraveler` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIPathTravelerSlotLane1(moho::IPathTraveler** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IPathTraveler, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00769220 (FUN_00769220)
   *
   * What it does:
   * Writes one reflected `RRef_IPathTraveler` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIPathTravelerSlotLane1(moho::IPathTraveler** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IPathTraveler, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00769260 (FUN_00769260)
   *
   * What it does:
   * Writes one reflected `RRef_IPathTraveler` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIPathTravelerSlotLane2(moho::IPathTraveler** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IPathTraveler, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0076A4E0 (FUN_0076A4E0)
   *
   * What it does:
   * Writes one reflected `RRef_PathTables` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromPathTablesSlotLane1(moho::PathTables** valueSlot, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathTables, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0076A9F0 (FUN_0076A9F0)
   *
   * What it does:
   * Writes one reflected `RRef_IPathTraveler` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIPathTravelerValueLane1(moho::IPathTraveler* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IPathTraveler, value, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0076ABD0 (FUN_0076ABD0)
   *
   * What it does:
   * Writes one reflected `RRef_PathTables` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromPathTablesSlotLane1(moho::PathTables** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PathTables, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0076B2D0 (FUN_0076B2D0)
   *
   * What it does:
   * Writes one reflected `RRef_PathTables` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromPathTablesValueLane1(moho::PathTables* value, gpg::WriteArchive* archive)
  {
    return WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathTables, value, gpg::TrackedPointerState::Unowned);
  }

} // namespace
namespace
{
  /**
   * Address: 0x004E58F0 (FUN_004E58F0)
   *
   * What it does:
   * Writes one reflected `RRef_CSndParams` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCSndParamsSlotLane2(moho::CSndParams** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSndParams, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x004E64B0 (FUN_004E64B0)
   *
   * What it does:
   * Writes one reflected `RRef_CSndParams` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCSndParamsValueLane2(moho::CSndParams* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSndParams, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00536D50 (FUN_00536D50)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRRuleGameRulesSlotLane2(moho::RRuleGameRules** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x005376D0 (FUN_005376D0)
   *
   * What it does:
   * Writes one reflected `RRef_RRuleGameRules` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRRuleGameRulesValueLane2(moho::RRuleGameRules* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0055A290 (FUN_0055A290)
   *
   * What it does:
   * Writes one reflected `RRef_RMeshBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRMeshBlueprintSlotLane1(moho::RMeshBlueprint** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RMeshBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0055A8F0 (FUN_0055A8F0)
   *
   * What it does:
   * Writes one reflected `RRef_RMeshBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRMeshBlueprintValueLane1(moho::RMeshBlueprint* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RMeshBlueprint, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0055EC40 (FUN_0055EC40)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRUnitBlueprintSlotLane2(moho::RUnitBlueprint** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0055F750 (FUN_0055F750)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRUnitBlueprintValueLane2(moho::RUnitBlueprint* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprint, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x005DEAC0 (FUN_005DEAC0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiAttackerImpl` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiAttackerImplOwnerFieldLane1(gpg::WriteArchive* archive, int ownerToken)
  {

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x1C]{};
      moho::CAiAttackerImpl* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x1C, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiAttackerImpl, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005E02C0 (FUN_005E02C0)
   *
   * What it does:
   * Writes one reflected `RRef_CAiAttackerImpl` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiAttackerImplOwnerFieldLane2(gpg::WriteArchive* archive, int ownerToken)
  {

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x1C]{};
      moho::CAiAttackerImpl* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x1C, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiAttackerImpl, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005E1370 (FUN_005E1370)
   *
   * What it does:
   * Writes one reflected `RRef_CAiAttackerImpl` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiAttackerImplOwnerFieldLane3(int ownerToken, gpg::WriteArchive* archive)
  {

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x1C]{};
      moho::CAiAttackerImpl* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x1C, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiAttackerImpl, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00633DF0 (FUN_00633DF0)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprintWeapon` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRUnitBlueprintWeaponSlotLane1(moho::RUnitBlueprintWeapon** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprintWeapon, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00633E20 (FUN_00633E20)
   *
   * What it does:
   * Writes one reflected `RRef_RProjectileBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRProjectileBlueprintSlotLane1(moho::RProjectileBlueprint** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RProjectileBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x006340C0 (FUN_006340C0)
   *
   * What it does:
   * Writes one reflected `RRef_RUnitBlueprintWeapon` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRUnitBlueprintWeaponValueLane1(moho::RUnitBlueprintWeapon* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RUnitBlueprintWeapon, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00634200 (FUN_00634200)
   *
   * What it does:
   * Writes one reflected `RRef_RProjectileBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromRProjectileBlueprintValueLane1(moho::RProjectileBlueprint* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RProjectileBlueprint, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0063CB60 (FUN_0063CB60)
   *
   * What it does:
   * Writes one null reflected `RRef_IAniManipulator_P` lane as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIAniManipulator_PNullLane1(gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAniManipulator_P, static_cast<moho::IAniManipulator**>(nullptr), gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0066C320 (FUN_0066C320)
   *
   * What it does:
   * Writes one null reflected `RRef_IEffect_P` lane as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIEffect_PNullLane1(gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffect_P, static_cast<moho::IEffect**>(nullptr), gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00698800 (FUN_00698800)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysConstants` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromSPhysConstantsSlotLane1(moho::SPhysConstants** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysConstants, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00698A10 (FUN_00698A10)
   *
   * What it does:
   * Writes one reflected `RRef_SPhysConstants` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromSPhysConstantsValueLane1(moho::SPhysConstants* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SPhysConstants, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0069EF60 (FUN_0069EF60)
   *
   * What it does:
   * Writes one intrusive-list-head-adjusted
   * `gpg::RRef_ManyToOneListener_EProjectileImpactEvent` lane as `unowned`
   * tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1(
    gpg::WriteArchive* archive,
    std::uint32_t* intrusiveListHeadSlot
  )
  {
    moho::ManyToOneListener<moho::EProjectileImpactEvent>* listener = nullptr;
    if (intrusiveListHeadSlot != nullptr && *intrusiveListHeadSlot != 0u) {
      listener = reinterpret_cast<moho::ManyToOneListener<moho::EProjectileImpactEvent>*>(
        *intrusiveListHeadSlot - sizeof(std::uint32_t)
      );
    }

    gpg::RRef listenerRef{};
    (void)gpg::RRef_ManyToOneListener_EProjectileImpactEvent(&listenerRef, listener);
    gpg::WriteRawPointer(archive, listenerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

  /**
   * Address: 0x0069FA30 (FUN_0069FA30)
   *
   * What it does:
   * Writes one reflected `RRef_ManyToOneListener_EProjectileImpactEvent` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromManyToOneListener_EProjectileImpactEventValueLane1(moho::ManyToOneListener<moho::EProjectileImpactEvent>* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_ManyToOneListener_EProjectileImpactEvent, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x006B1090 (FUN_006B1090)
   *
   * What it does:
   * Writes one reflected `RRef_CEconomyEvent` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconomyEventValueLane1(moho::CEconomyEvent* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconomyEvent, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x006B10C0 (FUN_006B10C0)
   *
   * What it does:
   * Writes one null reflected `RRef_CEconomyEvent_P` lane as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconomyEvent_PNullLane1(gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconomyEvent_P, static_cast<moho::CEconomyEvent**>(nullptr), gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x006BBDB0 (FUN_006BBDB0)
   *
   * What it does:
   * Writes one reflected `RRef_CPathPoint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCPathPointSlotLane1(moho::CPathPoint** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CPathPoint, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x006BC2F0 (FUN_006BC2F0)
   *
   * What it does:
   * Writes one reflected `RRef_CPathPoint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCPathPointValueLane1(moho::CPathPoint* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CPathPoint, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x006E2B30 (FUN_006E2B30)
   *
   * What it does:
   * Writes one null reflected `RRef_CUnitCommand_P` lane as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCUnitCommand_PNullLane1(gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CUnitCommand_P, static_cast<moho::CUnitCommand**>(nullptr), gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x006F8CB0 (FUN_006F8CB0)
   *
   * What it does:
   * Writes one reflected `RRef_Unit` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromUnitOwnerFieldLane1(int ownerToken, gpg::WriteArchive* archive)
  {

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x8]{};
      moho::Unit* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x8, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Unit, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x006F9070 (FUN_006F9070)
   *
   * What it does:
   * Writes one reflected `RRef_Listener_EUnitCommandQueueStatus` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromListener_EUnitCommandQueueStatusValueLane1(moho::Listener<moho::EUnitCommandQueueStatus>* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Listener_EUnitCommandQueueStatus, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0070E010 (FUN_0070E010)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiBrainOwnerFieldLane1(int ownerToken, gpg::WriteArchive* archive)
  {

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x10]{};
      moho::CAiBrain* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x10, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x0070E060 (FUN_0070E060)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiBrainOwnerFieldLane2(int ownerToken, gpg::WriteArchive* archive, int a3)
  {
    (void)a3;

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x10]{};
      moho::CAiBrain* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x10, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x00712600 (FUN_00712600)
   *
   * What it does:
   * Writes one reflected `RRef_CAiBrain` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCAiBrainOwnerFieldLane3(int ownerToken, gpg::WriteArchive* archive)
  {

    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x10]{};
      moho::CAiBrain* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x10, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAiBrain, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x00768BE0 (FUN_00768BE0)
   *
   * What it does:
   * Writes one reflected `RRef_IPathTraveler` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIPathTravelerSlotLane2(moho::IPathTraveler** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IPathTraveler, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0076A8B0 (FUN_0076A8B0)
   *
   * What it does:
   * Writes one reflected `RRef_IPathTraveler` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIPathTravelerValueLane2(moho::IPathTraveler* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IPathTraveler, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0076EB60 (FUN_0076EB60)
   *
   * What it does:
   * Reads one owned `CIntelPosHandle` pointer lane, swaps it into the
   * destination slot, and dispatches deleting teardown on the replaced handle.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCIntelPosHandleSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CIntelPosHandle** const valueSlot
  )
  {
    moho::CIntelPosHandle* loadedValue = nullptr;
    archive->ReadPointerOwned_CIntelPosHandle(&loadedValue, ownerRef);

    moho::CIntelPosHandle* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->Destroy(1);
    }
    return archive;
  }

  /**
   * Address: 0x0076EB90 (FUN_0076EB90)
   *
   * What it does:
   * Writes one reflected `RRef_CIntelPosHandle` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCIntelPosHandleSlotLane1(moho::CIntelPosHandle** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelPosHandle, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0076EBF0 (FUN_0076EBF0)
   *
   * What it does:
   * Writes one reflected `RRef_CIntelPosHandle` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCIntelPosHandleSlotLane1(moho::CIntelPosHandle** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelPosHandle, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x0076ED40 (FUN_0076ED40)
   *
   * What it does:
   * Writes one reflected `RRef_CIntelPosHandle` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCIntelPosHandleValueLane1(moho::CIntelPosHandle* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelPosHandle, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00770290 (FUN_00770290)
   *
   * What it does:
   * Writes one reflected `RRef_IAiReconDB` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIAiReconDBSlotLane1(moho::IAiReconDB** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiReconDB, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00770310 (FUN_00770310)
   *
   * What it does:
   * Writes one reflected `RRef_IAiReconDB` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIAiReconDBSlotLane1(moho::IAiReconDB** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiReconDB, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x007704B0 (FUN_007704B0)
   *
   * What it does:
   * Writes one reflected `RRef_IAiReconDB` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIAiReconDBValueLane1(moho::IAiReconDB* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IAiReconDB, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00771520 (FUN_00771520)
   *
   * What it does:
   * Writes one reflected `RRef_IEffectManager` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIEffectManagerSlotLane1(moho::IEffectManager** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffectManager, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00771660 (FUN_00771660)
   *
   * What it does:
   * Writes one reflected `RRef_IEffectManager` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIEffectManagerValueLane1(moho::IEffectManager* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffectManager, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0077D740 (FUN_0077D740)
   *
   * What it does:
   * Writes one reflected `RRef_CDecalHandle` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCDecalHandleValueLane1(moho::CDecalHandle* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CDecalHandle, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0077D770 (FUN_0077D770)
   *
   * What it does:
   * Writes one null reflected `RRef_CDecalHandle_P` lane as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCDecalHandle_PNullLane1(gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CDecalHandle_P, static_cast<moho::CDecalHandle**>(nullptr), gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00883630 (FUN_00883630)
   *
   * What it does:
   * Writes one reflected `RRef_SSessionSaveData` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromSSessionSaveDataSlotLane1(moho::SSessionSaveData** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SSessionSaveData, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x00883A40 (FUN_00883A40)
   *
   * What it does:
   * Writes one reflected `RRef_SSessionSaveData` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromSSessionSaveDataSlotLane1(moho::SSessionSaveData** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_SSessionSaveData, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x008845D0 (FUN_008845D0)
   *
   * What it does:
   * Writes one reflected `RRef_SSessionSaveData` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromSSessionSaveDataSlotLane2(moho::SSessionSaveData** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_SSessionSaveData, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x0090B7E0 (FUN_0090B7E0)
   *
   * What it does:
   * Writes one reflected `RRef_LuaState` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromLuaStateValueLane1(gpg::WriteArchive* archive, LuaPlus::LuaState* value, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_LuaState, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0091E8D0 (FUN_0091E8D0)
   *
   * What it does:
   * Writes one reflected `RRef_Table` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromTableValueLane1(gpg::WriteArchive* archive, Table* value, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Table, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0091EDE0 (FUN_0091EDE0)
   *
   * What it does:
   * Writes one reflected `RRef_TString` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromTStringValueLane1(gpg::WriteArchive* archive, TString* value, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_TString, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00920970 (FUN_00920970)
   *
   * What it does:
   * Writes one reflected `RRef_Proto` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromProtoValueLane1(gpg::WriteArchive* archive, Proto* value, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Proto, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x009209A0 (FUN_009209A0)
   *
   * What it does:
   * Writes one reflected `RRef_UpVal` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromUpValValueLane1(gpg::WriteArchive* archive, UpVal* value, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_UpVal, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00921210 (FUN_00921210)
   *
   * What it does:
   * Writes one reflected `RRef_TString` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromTStringSlotLane1(gpg::WriteArchive* archive, TString** valueSlot)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_TString, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00921420 (FUN_00921420)
   *
   * What it does:
   * Writes one reflected `RRef_TString` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromTStringSlotLane1(gpg::WriteArchive* archive, TString** valueSlot, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_TString, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  void SaveUnownedRawPointerAndNameFromRRuleGameRulesOwnerFieldLane1(
    int ownerToken,
    gpg::WriteArchive* archive,
    gpg::SerSaveConstructArgsResult* constructResult
  );

  SerSaveLoadHelperNodeRuntime gRRuleGameRulesOwnerFieldSaveConstructHelper{};

  /**
   * Address: 0x0051DB30 (FUN_0051DB30)
   *
   * What it does:
   * Register-shape thunk that forwards save-construct serialization for one
   * owner-field lane (`RRuleGameRules*` + name) to the canonical helper.
   */
  void SaveUnownedRawPointerAndNameFromRRuleGameRulesOwnerFieldLane1Thunk(
    gpg::WriteArchive* const archive,
    const int ownerToken,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const constructResult
  )
  {
    SaveUnownedRawPointerAndNameFromRRuleGameRulesOwnerFieldLane1(ownerToken, archive, constructResult);
  }

  /**
   * Address: 0x0051DB50 (FUN_0051DB50)
   *
   * What it does:
   * Unlinks save-construct helper links for the
   * `{RRuleGameRules*,name}` owner-field lane and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupRRuleGameRulesOwnerFieldSaveConstructHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRRuleGameRulesOwnerFieldSaveConstructHelper);
  }

  /**
   * Address: 0x0051DB80 (FUN_0051DB80)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same save-construct helper
   * lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupRRuleGameRulesOwnerFieldSaveConstructHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRRuleGameRulesOwnerFieldSaveConstructHelper);
  }

  /**
   * Address: 0x0051DBB0 (FUN_0051DBB0)
   *
   * What it does:
   * Writes one tracked pointer lane, serializes one companion name string, and updates save-construct ownership metadata.
   */
  void SaveUnownedRawPointerAndNameFromRRuleGameRulesOwnerFieldLane1(int ownerToken, gpg::WriteArchive* archive, gpg::SerSaveConstructArgsResult* constructResult)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x4]{};
      moho::RRuleGameRules* ownerField;
      msvc8::string ownerName;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x4, "OwnerFieldView::ownerField offset must match evidence");
    static_assert(offsetof(OwnerFieldView, ownerName) == 0x8, "OwnerFieldView::ownerName offset must match evidence");

    auto* const ownerView = reinterpret_cast<OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RRuleGameRules, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    archive->WriteString(&ownerView->ownerName);
    constructResult->SetOwned(1);
  }

  /**
   * Address: 0x0054FAC0 (FUN_0054FAC0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CAniSkel` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCAniSkelSlotLane1(moho::CAniSkel** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniSkel, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x0054FBA0 (FUN_0054FBA0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CAniSkel` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromCAniSkelSlotLane1(moho::CAniSkel** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniSkel, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00550100 (FUN_00550100)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CAniSkel` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCAniSkelSlotLane2(moho::CAniSkel** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CAniSkel, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x005518B0 (FUN_005518B0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CIntelGrid` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCIntelGridSlotLane1(moho::CIntelGrid** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelGrid, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x00551AF0 (FUN_00551AF0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CIntelGrid` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromCIntelGridSlotLane1(moho::CIntelGrid** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelGrid, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00551EA0 (FUN_00551EA0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CIntelGrid` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCIntelGridSlotLane2(moho::CIntelGrid** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelGrid, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x005549F0 (FUN_005549F0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_REntityBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromREntityBlueprintSlotLane1(moho::REntityBlueprint** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_REntityBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00554C30 (FUN_00554C30)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_REntityBlueprint` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromREntityBlueprintSlotLane1(moho::REntityBlueprint** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_REntityBlueprint, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00554F90 (FUN_00554F90)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_REntityBlueprint` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromREntityBlueprintValueLane1(moho::REntityBlueprint* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_REntityBlueprint, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x005592D0 (FUN_005592D0)
   *
   * What it does:
   * Lazily resolves the reflected `EntId` type and reads one object lane
   * through `ReadArchive::Read` with a local empty owner reference.
   */
  void ReadEntIdArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RType* const objectType = ResolveEntIdArchiveAdapterType();
    gpg::RRef ownerRef{};
    archive->Read(objectType, object, ownerRef);
  }

  /**
   * Address: 0x00559310 (FUN_00559310)
   *
   * What it does:
   * Lazily resolves the reflected `EntId` type and writes one object lane
   * through `WriteArchive::Write` with a local empty owner reference.
   */
  void WriteEntIdArchiveObjectLane1(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    gpg::RType* const objectType = ResolveEntIdArchiveAdapterType();
    const gpg::RRef ownerRef{};
    archive->Write(objectType, objectSlot, ownerRef);
  }

  /**
   * Address: 0x005596F0 (FUN_005596F0)
   *
   * What it does:
   * Lazily resolves the reflected `EntId` type and reads one object lane
   * through `ReadArchive::Read` with a local empty owner reference.
   */
  void ReadEntIdArchiveObjectLane2(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RType* const objectType = ResolveEntIdArchiveAdapterType();
    gpg::RRef ownerRef{};
    archive->Read(objectType, object, ownerRef);
  }

  /**
   * Address: 0x00559730 (FUN_00559730)
   *
   * What it does:
   * Lazily resolves the reflected `EntId` type and writes one object lane
   * through `WriteArchive::Write` with a local empty owner reference.
   */
  void WriteEntIdArchiveObjectLane2(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    gpg::RType* const objectType = ResolveEntIdArchiveAdapterType();
    const gpg::RRef ownerRef{};
    archive->Write(objectType, objectSlot, ownerRef);
  }

  /**
   * Address: 0x0055ED00 (FUN_0055ED00)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Stats_StatItem` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromStats_StatItemSlotLane1(moho::Stats_StatItem** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Stats_StatItem, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x0055F390 (FUN_0055F390)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Stats_StatItem` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromStats_StatItemSlotLane1(moho::Stats_StatItem** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Stats_StatItem, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x0055F960 (FUN_0055F960)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Stats_StatItem` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromStats_StatItemSlotLane2(moho::Stats_StatItem** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Stats_StatItem, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x00571340 (FUN_00571340)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Listener_EFormationdStatus` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromListener_EFormationdStatusValueLane1(moho::Listener_EFormationdStatus* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Listener_EFormationdStatus, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00584800 (FUN_00584800)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromSimSlotLane1(moho::Sim** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00584830 (FUN_00584830)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CTaskStage` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCTaskStageSlotLane1(moho::CTaskStage** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CTaskStage, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00584B50 (FUN_00584B50)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimSlotLane1(moho::Sim** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00584BB0 (FUN_00584BB0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CTaskStage` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCTaskStageSlotLane1(moho::CTaskStage** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CTaskStage, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005850C0 (FUN_005850C0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromSimValueLane1(moho::Sim* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00585200 (FUN_00585200)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CTaskStage` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCTaskStageValueLane1(moho::CTaskStage* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CTaskStage, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0059DD30 (FUN_0059DD30)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIFormationInstanceSlotLane1(moho::IFormationInstance** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0059DF70 (FUN_0059DF70)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIFormationInstanceSlotLane1(moho::IFormationInstance** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0059E920 (FUN_0059E920)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIFormationInstanceValueLane1(moho::IFormationInstance* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x005CD980 (FUN_005CD980)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CIntelGrid` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCIntelGridSlotLane3(moho::CIntelGrid** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelGrid, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x005CDE40 (FUN_005CDE40)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CIntelGrid` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromCIntelGridSlotLane2(moho::CIntelGrid** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelGrid, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x005CE400 (FUN_005CE400)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CIntelGrid` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCIntelGridSlotLane4(moho::CIntelGrid** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CIntelGrid, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x005D16A0 (FUN_005D16A0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconRequest` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconRequestSlotLane1(moho::CEconRequest** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconRequest, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x005D1A00 (FUN_005D1A00)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconRequest` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCEconRequestSlotLane1(moho::CEconRequest** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconRequest, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x005D1BE0 (FUN_005D1BE0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconRequest` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconRequestValueLane1(moho::CEconRequest* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconRequest, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x005F2100 (FUN_005F2100)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CCommandTask` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCCommandTaskSlotLane1(moho::CCommandTask** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CCommandTask, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x005F2140 (FUN_005F2140)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CCommandTask` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCCommandTaskSlotLane1(moho::CCommandTask** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CCommandTask, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x005F2280 (FUN_005F2280)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CCommandTask` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCCommandTaskValueLane1(moho::CCommandTask* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CCommandTask, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00642E00 (FUN_00642E00)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_RScaResource` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromRScaResourceSlotLane1(moho::RScaResource** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RScaResource, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x00642ED0 (FUN_00642ED0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_RScaResource` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromRScaResourceSlotLane1(moho::RScaResource** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_RScaResource, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00643140 (FUN_00643140)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_RScaResource` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromRScaResourceSlotLane2(moho::RScaResource** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_RScaResource, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x0065A930 (FUN_0065A930)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CParticleTexture` value as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromCParticleTextureValueLane1(moho::CParticleTexture* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CParticleTexture, value, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x0066C2F0 (FUN_0066C2F0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IEffect` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIEffectValueLane1(moho::IEffect* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffect, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00673950 (FUN_00673950)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane1(int ownerToken, gpg::WriteArchive* archive)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x148]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x148, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x00675170 (FUN_00675170)
   *
   * What it does:
   * Writes one intrusive-list-head-adjusted
   * `gpg::RRef_ManyToOneListener_ECollisionBeamEvent` lane as `unowned`
   * tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1(
    gpg::WriteArchive* archive,
    std::uint32_t* intrusiveListHeadSlot
  )
  {
    moho::ManyToOneListener<moho::ECollisionBeamEvent>* listener = nullptr;
    if (intrusiveListHeadSlot != nullptr && *intrusiveListHeadSlot != 0u) {
      listener = reinterpret_cast<moho::ManyToOneListener<moho::ECollisionBeamEvent>*>(
        *intrusiveListHeadSlot - sizeof(std::uint32_t)
      );
    }

    gpg::RRef listenerRef{};
    (void)gpg::RRef_ManyToOneListener_ECollisionBeamEvent(&listenerRef, listener);
    gpg::WriteRawPointer(archive, listenerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

  /**
   * Address: 0x006757F0 (FUN_006757F0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_ManyToOneListener_ECollisionBeamEvent` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventValueLane1(
    moho::ManyToOneListener<moho::ECollisionBeamEvent>* value,
    gpg::WriteArchive* archive
  )
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(
      archive,
      gpg::RRef_ManyToOneListener_ECollisionBeamEvent,
      value,
      gpg::TrackedPointerState::Unowned
    );
    return writeResult;
  }

  /**
   * Address: 0x00675830 (FUN_00675830)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IEffect` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIEffectSlotLane1(moho::IEffect** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffect, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00675B40 (FUN_00675B40)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IEffect` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromIEffectSlotLane1(moho::IEffect** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffect, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x006762C0 (FUN_006762C0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IEffect` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromIEffectValueLane1(moho::IEffect* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IEffect, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00682220 (FUN_00682220)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CTextureScroller` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCTextureScrollerSlotLane1(moho::CTextureScroller** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CTextureScroller, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00682700 (FUN_00682700)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CTextureScroller` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCTextureScrollerSlotLane1(moho::CTextureScroller** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CTextureScroller, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00682EC0 (FUN_00682EC0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CTextureScroller` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCTextureScrollerValueLane1(moho::CTextureScroller* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CTextureScroller, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0069E420 (FUN_0069E420)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane2(int ownerToken, gpg::WriteArchive* archive)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x148]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x148, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x006AD2C0 (FUN_006AD2C0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane3(int ownerToken, gpg::WriteArchive* archive)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x150]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x150, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x006B4160 (FUN_006B4160)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIFormationInstanceSlotLane1(moho::IFormationInstance** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x006B4190 (FUN_006B4190)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconStorage` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconStorageSlotLane1(moho::CEconStorage** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconStorage, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00584630 (FUN_00584630)
   *
   * What it does:
   * Reads one owned `CAiPersonality` pointer lane, swaps it into the
   * destination slot, and deletes the replaced pointer lane.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCAiPersonalitySlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CAiPersonality** const valueSlot
  )
  {
    moho::CAiPersonality* loadedValue = nullptr;
    archive->ReadPointerOwned_CAiPersonality(&loadedValue, ownerRef);

    moho::CAiPersonality* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x005D15A0 (FUN_005D15A0)
   *
   * What it does:
   * Reads one owned `CEconRequest` pointer lane into one intrusive-node slot
   * and unlinks/frees the replaced node.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCEconRequestNodeSlotLaneLegacyA(
    const gpg::RRef* const ownerRef,
    gpg::ReadArchive* const archive,
    moho::TDatListItem<void, void>** const valueSlot
  )
  {
    moho::CEconRequest* loadedValue = nullptr;
    archive->ReadPointerOwned_CEconRequest(&loadedValue, ownerRef);

    moho::TDatListItem<void, void>* const previousNode = *valueSlot;
    *valueSlot = loadedValue != nullptr ? &loadedValue->mNode : nullptr;

    if (previousNode != nullptr) {
      previousNode->ListUnlinkSelf();
      ::operator delete(previousNode);
    }

    return archive;
  }

  /**
   * Address: 0x005D4DD0 (FUN_005D4DD0)
   *
   * What it does:
   * Reads one owned `CAiPathSpline` pointer lane, swaps it into the destination
   * slot, and runs non-deleting teardown on the replaced spline.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCAiPathSplineSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CAiPathSpline** const valueSlot
  )
  {
    moho::CAiPathSpline* loadedValue = nullptr;
    archive->ReadPointerOwned_CAiPathSpline(&loadedValue, ownerRef);

    moho::CAiPathSpline* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->~CAiPathSpline();
    }
    return archive;
  }

  /**
   * Address: 0x005D4EF0 (FUN_005D4EF0)
   *
   * What it does:
   * Void-return variant of the owned `CAiPathSpline` slot read-and-replace lane.
   */
  void LoadOwnedRawPointerFromCAiPathSplineSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CAiPathSpline** const valueSlot
  )
  {
    moho::CAiPathSpline* loadedValue = nullptr;
    archive->ReadPointerOwned_CAiPathSpline(&loadedValue, ownerRef);

    moho::CAiPathSpline* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->~CAiPathSpline();
    }
  }

  /**
   * Address: 0x00681EA0 (FUN_00681EA0)
   *
   * What it does:
   * Reads one owned `PositionHistory` pointer lane, swaps it into the
   * destination slot, and frees the replaced allocation.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromPositionHistorySlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::PositionHistory** const valueSlot
  )
  {
    moho::PositionHistory* loadedValue = nullptr;
    archive->ReadPointerOwned_PositionHistory(&loadedValue, ownerRef);

    moho::PositionHistory* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    ::operator delete(previousValue);
    return archive;
  }

  /**
   * Address: 0x00681ED0 (FUN_00681ED0)
   *
   * What it does:
   * Reads one owned `CColPrimitiveBase` pointer lane, swaps it into the
   * destination slot, and frees the replaced allocation.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCColPrimitiveBaseSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CColPrimitiveBase** const valueSlot
  )
  {
    moho::CColPrimitiveBase* loadedValue = nullptr;
    archive->ReadPointerOwned_CColPrimitiveBase(&loadedValue, ownerRef);

    moho::CColPrimitiveBase* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    ::operator delete(previousValue);
    return archive;
  }

  /**
   * Address: 0x00681FC0 (FUN_00681FC0)
   *
   * What it does:
   * Reads one owned `CTextureScroller` pointer lane, swaps it into the
   * destination slot, and frees the replaced allocation when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCTextureScrollerSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CTextureScroller** const valueSlot
  )
  {
    moho::CTextureScroller* loadedValue = nullptr;
    ReadPointerOwned_CTextureScrollerCompat(&loadedValue, archive, ownerRef);

    moho::CTextureScroller* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x00681FF0 (FUN_00681FF0)
   *
   * What it does:
   * Reads one owned `SPhysBody` pointer lane, swaps it into the destination
   * slot, and frees the replaced allocation.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromSPhysBodySlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::SPhysBody** const valueSlot
  )
  {
    moho::SPhysBody* loadedValue = nullptr;
    archive->ReadPointerOwned_SPhysBody(&loadedValue, ownerRef);

    moho::SPhysBody* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    ::operator delete(previousValue);
    return archive;
  }

  /**
   * Address: 0x00682020 (FUN_00682020)
   *
   * What it does:
   * Reads one owned `Motor` pointer lane, swaps it into the destination slot,
   * and destroys/deletes the replaced motor object.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromMotorSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::EntityMotor** const valueSlot
  )
  {
    moho::EntityMotor* loadedValue = nullptr;
    archive->ReadPointerOwned_Motor(&loadedValue, ownerRef);

    moho::EntityMotor* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x00688BD0 (FUN_00688BD0)
   *
   * What it does:
   * Thin wrapper around `ReadPointer_EntitySetBase` preserving archive return.
   */
  gpg::ReadArchive* ReadRawPointerFromEntitySetBaseSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::EntitySetBase** const valueSlot
  )
  {
    archive->ReadPointer_EntitySetBase(valueSlot, ownerRef);
    return archive;
  }

  /**
   * Address: 0x00689150 (FUN_00689150)
   *
   * What it does:
   * Alternate argument-order wrapper for `ReadPointer_EntitySetBase`.
   */
  gpg::ReadArchive* ReadRawPointerFromEntitySetBaseSlotLaneLegacyB(
    const gpg::RRef* const ownerRef, moho::EntitySetBase** const valueSlot, gpg::ReadArchive* const archive
  )
  {
    return archive->ReadPointer_EntitySetBase(valueSlot, ownerRef);
  }

  /**
   * Address: 0x00698840 (FUN_00698840)
   *
   * What it does:
   * Thin wrapper around `ReadPointer_SPhysConstants` preserving archive return.
   */
  gpg::ReadArchive* ReadRawPointerFromSPhysConstantsSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::SPhysConstants** const valueSlot
  )
  {
    archive->ReadPointer_SPhysConstants(valueSlot, ownerRef);
    return archive;
  }

  /**
   * Address: 0x006988A0 (FUN_006988A0)
   *
   * What it does:
   * Alternate argument-order wrapper for `ReadPointer_SPhysConstants`.
   */
  gpg::ReadArchive* ReadRawPointerFromSPhysConstantsSlotLaneLegacyB(
    const gpg::RRef* const ownerRef, moho::SPhysConstants** const valueSlot, gpg::ReadArchive* const archive
  )
  {
    return archive->ReadPointer_SPhysConstants(valueSlot, ownerRef);
  }

  /**
   * Address: 0x006B3D80 (FUN_006B3D80)
   *
   * What it does:
   * Reads one owned `IAiSteering` pointer lane, swaps it into the destination
   * slot, and invokes deleting teardown on the replaced interface object.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiSteeringSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiSteering** const valueSlot
  )
  {
    moho::IAiSteering* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiSteering(&loadedValue, ownerRef);

    moho::IAiSteering* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B3E10 (FUN_006B3E10)
   *
   * What it does:
   * Reads one owned `IFormationInstance` pointer lane, swaps it into the
   * destination slot, and dispatches virtual delete on the replaced interface.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIFormationInstanceSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IFormationInstance** const valueSlot
  )
  {
    moho::IFormationInstance* loadedValue = nullptr;
    archive->ReadPointerOwned_IFormationInstance(&loadedValue, ownerRef);

    moho::IFormationInstance* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->operator_delete(1);
    }
    return archive;
  }

  /**
   * Address: 0x006B3EB0 (FUN_006B3EB0)
   *
   * What it does:
   * Reads one owned `IAiAttacker` pointer lane, swaps it into the destination
   * slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiAttackerSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiAttacker** const valueSlot
  )
  {
    moho::IAiAttacker* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiAttacker(&loadedValue, ownerRef);

    moho::IAiAttacker* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B3EE0 (FUN_006B3EE0)
   *
   * What it does:
   * Reads one owned `IAiCommandDispatch` pointer lane, swaps it into the
   * destination slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiCommandDispatchSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiCommandDispatch** const valueSlot
  )
  {
    moho::IAiCommandDispatch* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiCommandDispatch(&loadedValue, ownerRef);

    moho::IAiCommandDispatch* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B3F10 (FUN_006B3F10)
   *
   * What it does:
   * Reads one owned `IAiNavigator` pointer lane, swaps it into the destination
   * slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiNavigatorSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiNavigator** const valueSlot
  )
  {
    moho::IAiNavigator* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiNavigator(&loadedValue, ownerRef);

    moho::IAiNavigator* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B3F40 (FUN_006B3F40)
   *
   * What it does:
   * Reads one owned `IAiBuilder` pointer lane, swaps it into the destination
   * slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiBuilderSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiBuilder** const valueSlot
  )
  {
    moho::IAiBuilder* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiBuilder(&loadedValue, ownerRef);

    moho::IAiBuilder* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B3F70 (FUN_006B3F70)
   *
   * What it does:
   * Reads one owned `IAiSiloBuild` pointer lane, swaps it into the destination
   * slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiSiloBuildSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiSiloBuild** const valueSlot
  )
  {
    moho::IAiSiloBuild* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiSiloBuild(&loadedValue, ownerRef);

    moho::IAiSiloBuild* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B3FA0 (FUN_006B3FA0)
   *
   * What it does:
   * Reads one owned `IAiTransport` pointer lane, swaps it into the destination
   * slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiTransportSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiTransport** const valueSlot
  )
  {
    moho::IAiTransport* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiTransport(&loadedValue, ownerRef);

    moho::IAiTransport* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x006B4560 (FUN_006B4560)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromIFormationInstanceSlotLane1(moho::IFormationInstance** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B45D0 (FUN_006B45D0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconStorage` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCEconStorageSlotLane1(moho::CEconStorage** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconStorage, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x006B4590 (FUN_006B4590)
   *
   * What it does:
   * Reads one owned `CEconStorage` pointer lane, swaps it into the destination
   * slot, and releases the replaced storage object when it differs.
   */
  void LoadOwnedRawPointerFromCEconStorageSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CEconStorage** const valueSlot
  )
  {
    moho::CEconStorage* loadedValue = nullptr;
    (void)ReadPointerOwned_CEconStorageCompat(&loadedValue, archive, ownerRef);

    moho::CEconStorage* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      if (previousValue->mEconomy != nullptr) {
        (void)previousValue->Chng(-1);
      }
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x006B4600 (FUN_006B4600)
   *
   * What it does:
   * Reads one owned `CAniActor` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced actor when it differs.
   */
  void LoadOwnedRawPointerFromCAniActorSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CAniActor** const valueSlot
  )
  {
    moho::CAniActor* loadedValue = nullptr;
    archive->ReadPointerOwned_CAniActor(&loadedValue, ownerRef);

    moho::CAniActor* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CAniActor();
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x006B4F40 (FUN_006B4F40)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromIFormationInstanceValueLane1(moho::IFormationInstance* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x006B5080 (FUN_006B5080)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconStorage` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconStorageValueLane1(moho::CEconStorage* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconStorage, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x006E10F0 (FUN_006E10F0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimSlotLane1Variant2(moho::Sim** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, *valueSlot, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x006E1140 (FUN_006E1140)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimSlotLane2(moho::Sim** valueSlot, gpg::WriteArchive* archive, int a3)
  {
    (void)a3;
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, *valueSlot, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x006E2A40 (FUN_006E2A40)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimSlotLane3(moho::Sim** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, *valueSlot, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x006EBB00 (FUN_006EBB00)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_IFormationInstance` value as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromIFormationInstanceValueLane1(moho::IFormationInstance* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_IFormationInstance, value, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x006FA5B0 (FUN_006FA5B0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane4(int ownerToken, gpg::WriteArchive* archive)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x148]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x148, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x007064B0 (FUN_007064B0)
   *
   * What it does:
   * Reads one owned `CAiBrain` pointer lane, swaps it into the destination
   * slot, and deletes the replaced brain object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCAiBrainSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CAiBrain** const valueSlot
  )
  {
    moho::CAiBrain* loadedValue = nullptr;
    archive->ReadPointerOwned_CAiBrain(&loadedValue, ownerRef);

    moho::CAiBrain* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x007064E0 (FUN_007064E0)
   *
   * What it does:
   * Reads one owned `IAiReconDB` pointer lane, swaps it into the destination
   * slot, and deletes the replaced interface object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromIAiReconDBSlotLaneLegacyA(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::IAiReconDB** const valueSlot
  )
  {
    moho::IAiReconDB* loadedValue = nullptr;
    archive->ReadPointerOwned_IAiReconDB(&loadedValue, ownerRef);

    moho::IAiReconDB* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x00706510 (FUN_00706510)
   *
   * What it does:
   * Reads one owned `CEconomy` pointer lane, swaps it into the destination
   * slot, and clears the replaced economy object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCEconomySlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CEconomy** const valueSlot
  )
  {
    moho::CEconomy* loadedValue = nullptr;
    archive->ReadPointerOwned_CEconomy(&loadedValue, ownerRef);

    moho::CEconomy* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->Clear();
    }
    return archive;
  }

  /**
   * Address: 0x00706540 (FUN_00706540)
   *
   * What it does:
   * Reads one owned `CArmyStats` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced stats object when it differs.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCArmyStatsSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CArmyStats** const valueSlot
  )
  {
    moho::CArmyStats* loadedValue = nullptr;
    archive->ReadPointerOwned_CArmyStats(&loadedValue, ownerRef);

    moho::CArmyStats* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CArmyStats();
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x00706570 (FUN_00706570)
   *
   * What it does:
   * Reads one owned `CInfluenceMap` pointer lane, swaps it into the
   * destination slot, and destroys/deletes the replaced map object when it
   * differs.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCInfluenceMapSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CInfluenceMap** const valueSlot
  )
  {
    moho::CInfluenceMap* loadedValue = nullptr;
    archive->ReadPointerOwned_CInfluenceMap(&loadedValue, ownerRef);

    moho::CInfluenceMap* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CInfluenceMap();
      ::operator delete(previousValue);
    }
    return archive;
  }

  /**
   * Address: 0x007066B0 (FUN_007066B0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconomy` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconomySlotLane1(moho::CEconomy** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconomy, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00706B30 (FUN_00706B30)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconomy` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCEconomySlotLane1(moho::CEconomy** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconomy, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x00706B00 (FUN_00706B00)
   *
   * What it does:
   * Reads one owned `CEconomy` pointer lane, swaps it into the destination
   * slot, and clears the replaced economy object when present.
   */
  void LoadOwnedRawPointerFromCEconomySlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CEconomy** const valueSlot
  )
  {
    moho::CEconomy* loadedValue = nullptr;
    archive->ReadPointerOwned_CEconomy(&loadedValue, ownerRef);

    moho::CEconomy* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      previousValue->Clear();
    }
  }

  /**
   * Address: 0x00706B60 (FUN_00706B60)
   *
   * What it does:
   * Reads one owned `CArmyStats` pointer lane, swaps it into the destination
   * slot, and destroys/deletes the replaced stats object when it differs.
   */
  void LoadOwnedRawPointerFromCArmyStatsSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CArmyStats** const valueSlot
  )
  {
    moho::CArmyStats* loadedValue = nullptr;
    archive->ReadPointerOwned_CArmyStats(&loadedValue, ownerRef);

    moho::CArmyStats* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CArmyStats();
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x00706BC0 (FUN_00706BC0)
   *
   * What it does:
   * Reads one owned `CInfluenceMap` pointer lane, swaps it into the
   * destination slot, and destroys/deletes the replaced map object when it
   * differs.
   */
  void LoadOwnedRawPointerFromCInfluenceMapSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CInfluenceMap** const valueSlot
  )
  {
    moho::CInfluenceMap* loadedValue = nullptr;
    archive->ReadPointerOwned_CInfluenceMap(&loadedValue, ownerRef);

    moho::CInfluenceMap* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr && previousValue != loadedValue) {
      previousValue->~CInfluenceMap();
      ::operator delete(previousValue);
    }
  }

  /**
   * Address: 0x00706C20 (FUN_00706C20)
   *
   * What it does:
   * Reads one owned `PathQueue` pointer lane and moves it into the destination
   * slot via `PathQueue::Move`.
   */
  void LoadOwnedRawPointerFromPathQueueSlotLane1(
    gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::PathQueue** const valueSlot
  )
  {
    moho::PathQueue* loadedValue = nullptr;
    ReadPointerOwned_PathQueueCompat(&loadedValue, archive, ownerRef);
    moho::PathQueue::Move(valueSlot, loadedValue);
  }

  /**
   * Address: 0x00706C40 (FUN_00706C40)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromPathQueueSlotLane1(moho::PathQueue** valueSlot, gpg::RRef* ownerRef, gpg::WriteArchive* archive)
  {
    gpg::RRef objectRef{};
    gpg::RRef_PathQueue(&objectRef, *valueSlot);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Owned, *ownerRef);
  }

  /**
   * Address: 0x007071B0 (FUN_007071B0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconomy` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCEconomyValueLane1(moho::CEconomy* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconomy, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00710340 (FUN_00710340)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` owner-field lane as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCArmyStatItemOwnerFieldLane1(gpg::WriteArchive* archive, int ownerToken)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x4]{};
      moho::CArmyStatItem* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x4, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, ownerView->ownerField, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007128A0 (FUN_007128A0)
   *
   * What it does:
   * Reads one owned `CArmyStatItem` pointer lane, swaps it into the
   * destination slot, and deletes the replaced stat-item object when present.
   */
  gpg::ReadArchive* ReadOwnedRawPointerFromCArmyStatItemSlotLaneLegacyA(
    const gpg::RRef* const ownerRef, gpg::ReadArchive* const archive, moho::CArmyStatItem** const valueSlot
  )
  {
    moho::CArmyStatItem* loadedValue = nullptr;
    archive->ReadPointerOwned_CArmyStatItem(&loadedValue, ownerRef);

    moho::CArmyStatItem* const previousValue = *valueSlot;
    *valueSlot = loadedValue;
    if (previousValue != nullptr) {
      delete previousValue;
    }
    return archive;
  }

  /**
   * Address: 0x007128D0 (FUN_007128D0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCArmyStatItemSlotLane1(moho::CArmyStatItem** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00712940 (FUN_00712940)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCArmyStatItemSlotLane1(moho::CArmyStatItem** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00713080 (FUN_00713080)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromCArmyStatItemSlotLane1(moho::CArmyStatItem** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x007130C0 (FUN_007130C0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCArmyStatItemSlotLane1(moho::CArmyStatItem** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00714180 (FUN_00714180)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCArmyStatItemValueLane1(moho::CArmyStatItem* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x007142C0 (FUN_007142C0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CArmyStatItem` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCArmyStatItemValueLane1(moho::CArmyStatItem* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CArmyStatItem, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0072ADE0 (FUN_0072ADE0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CSquad` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromCSquadValueLane1(moho::CSquad* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSquad, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0072AE10 (FUN_0072AE10)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CSquad` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCSquadSlotLane1(moho::CSquad** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSquad, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x0072AED0 (FUN_0072AED0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CSquad` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCSquadSlotLane1(moho::CSquad** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CSquad, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x0072B1A0 (FUN_0072B1A0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CSquad` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCSquadValueLane1(moho::CSquad* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CSquad, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x007610B0 (FUN_007610B0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane5(gpg::WriteArchive* archive, int ownerToken, int a3, gpg::SerSaveConstructArgsResult* constructResult)
  {
    (void)a3;
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x4]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x4, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    constructResult->SetUnowned(0);
  }

  /**
   * Address: 0x00761160 (FUN_00761160)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane6(int ownerToken, gpg::WriteArchive* archive)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x4]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x4, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x007689D0 (FUN_007689D0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue_Impl` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromPathQueue_ImplSlotLane1(gpg::WriteArchive* archive, moho::PathQueue::Impl** valueSlot)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue_Impl, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x0076A450 (FUN_0076A450)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue_Impl` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromPathQueue_ImplSlotLane2(gpg::WriteArchive* archive, moho::PathQueue::Impl** valueSlot)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue_Impl, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x0076ADA0 (FUN_0076ADA0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue_Impl` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromPathQueue_ImplSlotLane3(moho::PathQueue::Impl** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue_Impl, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x0076B330 (FUN_0076B330)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue_Impl` slot as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromPathQueue_ImplSlotLane1(moho::PathQueue::Impl** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue_Impl, *valueSlot, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x0076B490 (FUN_0076B490)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue_Impl` slot as `owned` tracked-pointer state into one write archive lane.
   */
  void SaveOwnedRawPointerFromPathQueue_ImplSlotLane4(moho::PathQueue::Impl** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue_Impl, *valueSlot, gpg::TrackedPointerState::Owned);
  }

  /**
   * Address: 0x0076B680 (FUN_0076B680)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_PathQueue_Impl` value as `owned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteOwnedRawPointerFromPathQueue_ImplValueLane1(moho::PathQueue::Impl* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_PathQueue_Impl, value, gpg::TrackedPointerState::Owned);
    return writeResult;
  }

  /**
   * Address: 0x00774320 (FUN_00774320)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconRequest` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCEconRequestSlotLane1(moho::CEconRequest** valueSlot, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconRequest, *valueSlot, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x007744E0 (FUN_007744E0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconRequest` slot as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromCEconRequestSlotLane1(moho::CEconRequest** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconRequest, *valueSlot, gpg::TrackedPointerState::Unowned);
  }

  /**
   * Address: 0x00774700 (FUN_00774700)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconRequest` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCEconRequestValueLane1(moho::CEconRequest* value, gpg::WriteArchive* archive, int a5)
  {
    (void)a5;
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconRequest, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x00774D00 (FUN_00774D00)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_CEconomy` value as `unowned` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteUnownedRawPointerFromCEconomyValueLane1(moho::CEconomy* value, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_CEconomy, value, gpg::TrackedPointerState::Unowned);
    return writeResult;
  }

  /**
   * Address: 0x007766B0 (FUN_007766B0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane7(gpg::WriteArchive* archive, int ownerToken, int a3, gpg::SerSaveConstructArgsResult* constructResult)
  {
    (void)a3;
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x148]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x148, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    constructResult->SetUnowned(0);
  }

  /**
   * Address: 0x00776760 (FUN_00776760)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_Sim` owner-field lane as `unowned` tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromSimOwnerFieldLane8(int ownerToken, gpg::WriteArchive* archive)
  {
    struct OwnerFieldView
    {
      std::uint8_t reserved00[0x148]{};
      moho::Sim* ownerField;
    };
    static_assert(offsetof(OwnerFieldView, ownerField) == 0x148, "OwnerFieldView::ownerField offset must match evidence");

    const auto* const ownerView = reinterpret_cast<const OwnerFieldView*>(static_cast<std::uintptr_t>(ownerToken));
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_Sim, ownerView->ownerField, gpg::TrackedPointerState::Unowned);
    reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)->SetUnowned(0);
  }

  /**
   * Address: 0x00883EA0 (FUN_00883EA0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_LaunchInfoBase` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromLaunchInfoBaseSlotLane1(moho::LaunchInfoBase** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_LaunchInfoBase, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

  /**
   * Address: 0x008847C0 (FUN_008847C0)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_LaunchInfoBase` slot as `shared` tracked-pointer state into one write archive lane.
   */
  void SaveSharedRawPointerFromLaunchInfoBaseSlotLane1(moho::LaunchInfoBase** valueSlot, gpg::WriteArchive* archive)
  {
    SaveTrackedPointerFromRefBuilder(archive, gpg::RRef_LaunchInfoBase, *valueSlot, gpg::TrackedPointerState::Shared);
  }

  /**
   * Address: 0x00884E70 (FUN_00884E70)
   *
   * What it does:
   * Writes one reflected `gpg::RRef_LaunchInfoBase` slot as `shared` tracked-pointer state into one write archive lane.
   */
  gpg::WriteArchive* WriteSharedRawPointerFromLaunchInfoBaseSlotLane2(moho::LaunchInfoBase** valueSlot, gpg::WriteArchive* archive)
  {
    auto* const writeResult = WriteTrackedPointerFromRefBuilder(archive, gpg::RRef_LaunchInfoBase, *valueSlot, gpg::TrackedPointerState::Shared);
    return writeResult;
  }

} // namespace
namespace
{
  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  struct SerSaveLoadHelperInitView
  {
    void* vtable = nullptr;                     // +0x00
    gpg::SerHelperBase* helperNext = nullptr;  // +0x04
    gpg::SerHelperBase* helperPrev = nullptr;  // +0x08
    gpg::RType::load_func_t loadCallback = nullptr;
    gpg::RType::save_func_t saveCallback = nullptr;
  };
  static_assert(offsetof(SerSaveLoadHelperInitView, helperNext) == 0x04,
    "SerSaveLoadHelperInitView::helperNext offset must be 0x04");
  static_assert(offsetof(SerSaveLoadHelperInitView, helperPrev) == 0x08,
    "SerSaveLoadHelperInitView::helperPrev offset must be 0x08");
  static_assert(offsetof(SerSaveLoadHelperInitView, loadCallback) == 0x0C,
    "SerSaveLoadHelperInitView::loadCallback offset must be 0x0C");
  static_assert(offsetof(SerSaveLoadHelperInitView, saveCallback) == 0x10,
    "SerSaveLoadHelperInitView::saveCallback offset must be 0x10");
  static_assert(sizeof(SerSaveLoadHelperInitView) == 0x14,
    "SerSaveLoadHelperInitView size must be 0x14");

  using SerializerWord = std::uint32_t;

  [[nodiscard]] gpg::RType::load_func_t InstallSerSaveLoadHelperCallbacksByTypeName(
    SerSaveLoadHelperInitView* const helper,
    const char* const reflectedTypeName
  )
  {
    GPG_ASSERT(helper != nullptr);
    GPG_ASSERT(reflectedTypeName != nullptr);

    gpg::RType* const type = gpg::REF_FindTypeNamed(reflectedTypeName);
    GPG_ASSERT(type != nullptr);

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
    }

    const bool saveWasNull = type->serSaveFunc_ == nullptr;
    const gpg::RType::load_func_t loadCallback = helper->loadCallback;
    type->serLoadFunc_ = loadCallback;

    if (!saveWasNull) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
    }

    type->serSaveFunc_ = helper->saveCallback;
    return loadCallback;
  }

  /**
   * Address: 0x004ED140 (FUN_004ED140)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Wm3::AxisAlignedBox3f`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallWm3AxisAlignedBox3fSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Wm3::AxisAlignedBox3f");
  }

  /**
   * Address: 0x004ED1E0 (FUN_004ED1E0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Wm3::IVector2i`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallWm3IVector2iSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Wm3::IVector2i");
  }

  /**
   * Address: 0x004ED280 (FUN_004ED280)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Wm3::IVector3i`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallWm3IVector3iSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Wm3::IVector3i");
  }

  /**
   * Address: 0x004ED320 (FUN_004ED320)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Wm3::Vector2f`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallWm3Vector2fSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Wm3::Vector2f");
  }

  /**
   * Address: 0x004ED3C0 (FUN_004ED3C0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Wm3::Vector3f`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallWm3Vector3fSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Wm3::Vector3f");
  }

  /**
   * Address: 0x004ED460 (FUN_004ED460)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::Vector4f`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoVector4fSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::Vector4f");
  }

  /**
   * Address: 0x004ED500 (FUN_004ED500)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Wm3::Quaternionf`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallWm3QuaternionfSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Wm3::Quaternionf");
  }

  /**
   * Address: 0x004ED5A0 (FUN_004ED5A0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::VEulers3`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoVEulers3SerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::VEulers3");
  }

  /**
   * Address: 0x004ED640 (FUN_004ED640)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::VAxes3`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoVAxes3SerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::VAxes3");
  }

  /**
   * Address: 0x004F0840 (FUN_004F0840)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::VTransform`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoVTransformSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::VTransform");
  }

  /**
   * Address: 0x0050C730 (FUN_0050C730)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SCoordsVec2`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSCoordsVec2SerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SCoordsVec2");
  }

  /**
   * Address: 0x0050C7D0 (FUN_0050C7D0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SOCellPos`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSOCellPosSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SOCellPos");
  }

  /**
   * Address: 0x0050C910 (FUN_0050C910)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SPointVector`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSPointVectorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SPointVector");
  }

  /**
   * Address: 0x0050C9B0 (FUN_0050C9B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SFootprint`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSFootprintSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SFootprint");
  }

  /**
   * Address: 0x00523110 (FUN_00523110)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ERuleBPUnitMovementType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoERuleBPUnitMovementTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ERuleBPUnitMovementType");
  }

  /**
   * Address: 0x005231B0 (FUN_005231B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ERuleBPUnitCommandCaps`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoERuleBPUnitCommandCapsSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ERuleBPUnitCommandCaps");
  }

  /**
   * Address: 0x00523250 (FUN_00523250)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ERuleBPUnitToggleCaps`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoERuleBPUnitToggleCapsSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ERuleBPUnitToggleCaps");
  }

  /**
   * Address: 0x00543260 (FUN_00543260)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::LaunchInfoNew`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoLaunchInfoNewSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::LaunchInfoNew");
  }

  /**
   * Address: 0x005473B0 (FUN_005473B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EResourceType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEResourceTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EResourceType");
  }

  /**
   * Address: 0x00547450 (FUN_00547450)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ResourceDeposit`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoResourceDepositSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ResourceDeposit");
  }

  /**
   * Address: 0x0054C610 (FUN_0054C610)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CAniPose`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCAniPoseSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CAniPose");
  }

  /**
   * Address: 0x0054C8F0 (FUN_0054C8F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CAniPoseBone`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCAniPoseBoneSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CAniPoseBone");
  }

  /**
   * Address: 0x00550CF0 (FUN_00550CF0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SSTIArmyConstantData`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSSTIArmyConstantDataSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SSTIArmyConstantData");
  }

  /**
   * Address: 0x005589E0 (FUN_005589E0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EntId`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEntIdSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EntId");
  }

  /**
   * Address: 0x00558A80 (FUN_00558A80)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SSTIEntityConstantData`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSSTIEntityConstantDataSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SSTIEntityConstantData");
  }

  /**
   * Address: 0x0055B200 (FUN_0055B200)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ESTITargetType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoESTITargetTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ESTITargetType");
  }

  /**
   * Address: 0x0055B2A0 (FUN_0055B2A0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SSTITarget`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSSTITargetSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SSTITarget");
  }

  /**
   * Address: 0x0055C860 (FUN_0055C860)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EJobType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEJobTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EJobType");
  }

  /**
   * Address: 0x0055C900 (FUN_0055C900)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EFireState`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEFireStateSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EFireState");
  }

  /**
   * Address: 0x0055C9A0 (FUN_0055C9A0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EUnitState`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEUnitStateSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitState");
  }

  /**
   * Address: 0x0055CA40 (FUN_0055CA40)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::UnitWeaponInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoUnitWeaponInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::UnitWeaponInfo");
  }

  /**
   * Address: 0x0055D100 (FUN_0055D100)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SSTIUnitVariableData`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSSTIUnitVariableDataSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SSTIUnitVariableData");
  }

  /**
   * Address: 0x00563F70 (FUN_00563F70)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EEconResource`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEEconResourceSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EEconResource");
  }

  /**
   * Address: 0x00564010 (FUN_00564010)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SEconValue`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSEconValueSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SEconValue");
  }

  /**
   * Address: 0x005640B0 (FUN_005640B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SEconTotals`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSEconTotalsSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SEconTotals");
  }

  /**
   * Address: 0x0056B8C0 (FUN_0056B8C0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SUnitOffsetInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSUnitOffsetInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SUnitOffsetInfo");
  }

  /**
   * Address: 0x0056BAD0 (FUN_0056BAD0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SOffsetInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSOffsetInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SOffsetInfo");
  }

  /**
   * Address: 0x0056BCE0 (FUN_0056BCE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::IFormationInstance`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoIFormationInstanceSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::IFormationInstance");
  }

  /**
   * Address: 0x0056BD80 (FUN_0056BD80)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SAssignedLocInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSAssignedLocInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SAssignedLocInfo");
  }

  /**
   * Address: 0x0056CA10 (FUN_0056CA10)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CFormationInstance`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCFormationInstanceSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CFormationInstance");
  }

  /**
   * Address: 0x00591B90 (FUN_00591B90)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SMassInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSMassInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SMassInfo");
  }

  /**
   * Address: 0x005982F0 (FUN_005982F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ECollisionType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoECollisionTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ECollisionType");
  }

  /**
   * Address: 0x005A6EF0 (FUN_005A6EF0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAiNavigatorStatus`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAiNavigatorStatusSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAiNavigatorStatus");
  }

  /**
   * Address: 0x005A6F90 (FUN_005A6F90)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAiNavigatorEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAiNavigatorEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAiNavigatorEvent");
  }

  /**
   * Address: 0x005B9230 (FUN_005B9230)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SValuePair`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSValuePairSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SValuePair");
  }

  /**
   * Address: 0x005DB720 (FUN_005DB720)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAiAttackerEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAiAttackerEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAiAttackerEvent");
  }

  /**
   * Address: 0x005E34A0 (FUN_005E34A0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAiTargetType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAiTargetTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAiTargetType");
  }

  /**
   * Address: 0x005E8B90 (FUN_005E8B90)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAiTransportEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAiTransportEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAiTransportEvent");
  }

  /**
   * Address: 0x005E91E0 (FUN_005E91E0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SAttachPoint`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSAttachPointSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SAttachPoint");
  }

  /**
   * Address: 0x005E9490 (FUN_005E9490)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::STransportPickUpInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSTransportPickUpInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::STransportPickUpInfo");
  }

  /**
   * Address: 0x005F1A70 (FUN_005F1A70)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitAssistMoveTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitAssistMoveTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitAssistMoveTask");
  }

  /**
   * Address: 0x005F44F0 (FUN_005F44F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitAttackTargetTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitAttackTargetTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitAttackTargetTask");
  }

  /**
   * Address: 0x005FBAE0 (FUN_005FBAE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CBuildTaskHelper`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCBuildTaskHelperSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CBuildTaskHelper");
  }

  /**
   * Address: 0x005FBBA0 (FUN_005FBBA0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitMobileBuildTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitMobileBuildTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitMobileBuildTask");
  }

  /**
   * Address: 0x005FBC90 (FUN_005FBC90)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitUpgradeTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitUpgradeTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitUpgradeTask");
  }

  /**
   * Address: 0x005FBD50 (FUN_005FBD50)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitRepairTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitRepairTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitRepairTask");
  }

  /**
   * Address: 0x005FBE10 (FUN_005FBE10)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CFactoryBuildTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCFactoryBuildTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CFactoryBuildTask");
  }

  /**
   * Address: 0x005FBED0 (FUN_005FBED0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitSacrificeTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitSacrificeTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitSacrificeTask");
  }

  /**
   * Address: 0x00605320 (FUN_00605320)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitCaptureTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitCaptureTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitCaptureTask");
  }

  /**
   * Address: 0x00607730 (FUN_00607730)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitCarrierRetrieve`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitCarrierRetrieveSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitCarrierRetrieve");
  }

  /**
   * Address: 0x006077F0 (FUN_006077F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitCarrierLand`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitCarrierLandSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitCarrierLand");
  }

  /**
   * Address: 0x006078B0 (FUN_006078B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitCarrierLaunch`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitCarrierLaunchSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitCarrierLaunch");
  }

  /**
   * Address: 0x0060B980 (FUN_0060B980)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAiResult`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAiResultSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAiResult");
  }

  /**
   * Address: 0x0060BAE0 (FUN_0060BAE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitGetBuiltTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitGetBuiltTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitGetBuiltTask");
  }
} // namespace

namespace
{

  /**
   * Address: 0x0060BBA0 (FUN_0060BBA0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitTeleportTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitTeleportTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitTeleportTask");
  }

  /**
   * Address: 0x0060BC60 (FUN_0060BC60)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitFireAtTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitFireAtTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitFireAtTask");
  }

  /**
   * Address: 0x00610000 (FUN_00610000)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitFerryTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitFerryTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitFerryTask");
  }

  /**
   * Address: 0x006100C0 (FUN_006100C0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitWaitForFerryTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitWaitForFerryTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitWaitForFerryTask");
  }

  /**
   * Address: 0x006148A0 (FUN_006148A0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitGuardTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitGuardTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitGuardTask");
  }

  /**
   * Address: 0x00619C20 (FUN_00619C20)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitMoveTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitMoveTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitMoveTask");
  }

  /**
   * Address: 0x00619CE0 (FUN_00619CE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitFormAndMoveTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitFormAndMoveTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitFormAndMoveTask");
  }

  /**
   * Address: 0x0061C6E0 (FUN_0061C6E0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitPatrolTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitPatrolTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitPatrolTask");
  }

  /**
   * Address: 0x0061E500 (FUN_0061E500)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitPodAssist`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitPodAssistSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitPodAssist");
  }

  /**
   * Address: 0x006204B0 (FUN_006204B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitReclaimTask`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitReclaimTaskSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitReclaimTask");
  }

  /**
   * Address: 0x00622210 (FUN_00622210)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitRefuel`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitRefuelSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitRefuel");
  }

  /**
   * Address: 0x00626B30 (FUN_00626B30)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SPickUpInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSPickUpInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SPickUpInfo");
  }

  /**
   * Address: 0x00626F90 (FUN_00626F90)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitLoadUnits`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitLoadUnitsSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitLoadUnits");
  }

  /**
   * Address: 0x00627050 (FUN_00627050)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CUnitUnloadUnits`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCUnitUnloadUnitsSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CUnitUnloadUnits");
  }

  /**
   * Address: 0x0062F870 (FUN_0062F870)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EPathPointState`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEPathPointStateSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EPathPointState");
  }

  /**
   * Address: 0x00635140 (FUN_00635140)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CBoneEntityManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCBoneEntityManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CBoneEntityManipulator");
  }

  /**
   * Address: 0x00636F80 (FUN_00636F80)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CBuilderArmManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCBuilderArmManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CBuilderArmManipulator");
  }

  /**
   * Address: 0x00639FA0 (FUN_00639FA0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CFootPlantManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCFootPlantManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CFootPlantManipulator");
  }

  /**
   * Address: 0x00645310 (FUN_00645310)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CRotateManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCRotateManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CRotateManipulator");
  }

  /**
   * Address: 0x006466B0 (FUN_006466B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CSlaveManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCSlaveManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CSlaveManipulator");
  }

  /**
   * Address: 0x006484C0 (FUN_006484C0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CSlideManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCSlideManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CSlideManipulator");
  }

  /**
   * Address: 0x00649930 (FUN_00649930)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CStorageManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCStorageManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CStorageManipulator");
  }

  /**
   * Address: 0x0064B150 (FUN_0064B150)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CThrustManipulator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCThrustManipulatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CThrustManipulator");
  }

  /**
   * Address: 0x0065F150 (FUN_0065F150)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CEfxEmitter`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCEfxEmitterSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CEfxEmitter");
  }

  /**
   * Address: 0x006722F0 (FUN_006722F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CEfxTrailEmitter`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCEfxTrailEmitterSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CEfxTrailEmitter");
  }

  /**
   * Address: 0x00693DE0 (FUN_00693DE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EntitySetBase`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEntitySetBaseSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EntitySetBase");
  }

  /**
   * Address: 0x00693E80 (FUN_00693E80)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EntitySetTemplate_Entity`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEntitySetTemplateEntitySerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EntitySetTemplate_Entity");
  }

  /**
   * Address: 0x00693F20 (FUN_00693F20)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::WeakEntitySetTemplate_Entity`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoWeakEntitySetTemplateEntitySerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::WeakEntitySetTemplate_Entity");
  }

  /**
   * Address: 0x00696CE0 (FUN_00696CE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::MotorSinkAway`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoMotorSinkAwaySerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::MotorSinkAway");
  }

  /**
   * Address: 0x0069E860 (FUN_0069E860)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EProjectileImpactEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEProjectileImpactEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EProjectileImpactEvent");
  }

  /**
   * Address: 0x006AE810 (FUN_006AE810)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SInfoCache`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSInfoCacheSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SInfoCache");
  }

  /**
   * Address: 0x006AEA20 (FUN_006AEA20)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::Unit`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoUnitSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::Unit");
  }

  /**
   * Address: 0x006BA420 (FUN_006BA420)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EUnitMotionState`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEUnitMotionStateSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitMotionState");
  }

  /**
   * Address: 0x006BA4C0 (FUN_006BA4C0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EUnitMotionCarrierEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEUnitMotionCarrierEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitMotionCarrierEvent");
  }

  /**
   * Address: 0x006BA560 (FUN_006BA560)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EUnitMotionHorzEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEUnitMotionHorzEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitMotionHorzEvent");
  }

  /**
   * Address: 0x006BA600 (FUN_006BA600)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EUnitMotionVertEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEUnitMotionVertEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitMotionVertEvent");
  }

  /**
   * Address: 0x006BA6A0 (FUN_006BA6A0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EUnitMotionTurnEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEUnitMotionTurnEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitMotionTurnEvent");
  }

  /**
   * Address: 0x006BA740 (FUN_006BA740)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EAirCombatState`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEAirCombatStateSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAirCombatState");
  }

  /**
   * Address: 0x006E9760 (FUN_006E9760)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ECommandEvent`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoECommandEventSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ECommandEvent");
  }

  /**
   * Address: 0x0070E510 (FUN_0070E510)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ETriggerOperator`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoETriggerOperatorSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ETriggerOperator");
  }

  /**
   * Address: 0x0070E5B0 (FUN_0070E5B0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SCondition`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSConditionSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SCondition");
  }

  /**
   * Address: 0x0070E9F0 (FUN_0070E9F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::STrigger`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSTriggerSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::STrigger");
  }

  /**
   * Address: 0x00718900 (FUN_00718900)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EThreatType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEThreatTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EThreatType");
  }

  /**
   * Address: 0x0072A4D0 (FUN_0072A4D0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::ESquadClass`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoESquadClassSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ESquadClass");
  }

  /**
   * Address: 0x0072A5F0 (FUN_0072A5F0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CSquad`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCSquadSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CSquad");
  }

  /**
   * Address: 0x0072A710 (FUN_0072A710)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CPlatoon`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCPlatoonSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CPlatoon");
  }

  /**
   * Address: 0x007632D0 (FUN_007632D0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::HPathCell`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoHPathCellSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::HPathCell");
  }

  /**
   * Address: 0x00763370 (FUN_00763370)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::NavPath`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoNavPathSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::NavPath");
  }

  /**
   * Address: 0x00767080 (FUN_00767080)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::PathQueue`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoPathQueueSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::PathQueue");
  }

  /**
   * Address: 0x00773D00 (FUN_00773D00)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CEconomy`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCEconomySerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CEconomy");
  }

  /**
   * Address: 0x00773E20 (FUN_00773E20)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CEconStorage`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCEconStorageSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CEconStorage");
  }

  /**
   * Address: 0x00773F40 (FUN_00773F40)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::CEconRequest`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoCEconRequestSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::CEconRequest");
  }

  /**
   * Address: 0x00777E20 (FUN_00777E20)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::EScrollType`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoEScrollTypeSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EScrollType");
  }

  /**
   * Address: 0x00777EC0 (FUN_00777EC0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SScroller`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSScrollerSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SScroller");
  }

  /**
   * Address: 0x0077A6D0 (FUN_0077A6D0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SDecalInfo`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSDecalInfoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SDecalInfo");
  }

  /**
   * Address: 0x00899220 (FUN_00899220)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `Moho::SSessionSaveData`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallMohoSSessionSaveDataSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::SSessionSaveData");
  }

  /**
   * Address: 0x0091FA30 (FUN_0091FA30)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::TString`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallluaTStringSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::TString");
  }

  /**
   * Address: 0x0091FBC0 (FUN_0091FBC0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::Table`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallluaTableSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::Table");
  }

  /**
   * Address: 0x0091FD50 (FUN_0091FD50)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::LClosure`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallluaLClosureSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::LClosure");
  }

  /**
   * Address: 0x0091FEE0 (FUN_0091FEE0)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::UpVal`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallluaUpValSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::UpVal");
  }

  /**
   * Address: 0x00920070 (FUN_00920070)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::Proto`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallluaProtoSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::Proto");
  }

  /**
   * Address: 0x00920200 (FUN_00920200)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::lua_State`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstalllualuaStateSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::lua_State");
  }

  /**
   * Address: 0x00920390 (FUN_00920390)
   *
   * What it does:
   * Installs serializer load/save callbacks for reflected type `lua::Udata`.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallluaUdataSerializerCallbacks(
    SerSaveLoadHelperInitView* const helper
  )
  {
    return InstallSerSaveLoadHelperCallbacksByTypeName(helper, "lua::Udata");
  }

  [[nodiscard]] gpg::RType* ResolveInfluenceMapEntryArchiveAdapterType()
  {
    gpg::RType* type = moho::InfluenceMapEntry::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::InfluenceMapEntry));
      moho::InfluenceMapEntry::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveSThreatArchiveAdapterType()
  {
    gpg::RType* type = moho::SThreat::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SThreat));
      moho::SThreat::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveMapUIntInfluenceMapEntryArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::map<unsigned int, moho::InfluenceMapEntry>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVectorSThreatArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::vector<moho::SThreat>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveMapUIntIntArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::map<unsigned int, int>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVectorInfluenceGridArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::vector<moho::InfluenceGrid>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveESquadClassArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::ESquadClass");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("ESquadClass");
      }
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::ESquadClass));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveCDamageArchiveAdapterType()
  {
    gpg::RType* type = moho::CDamage::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CDamage));
      moho::CDamage::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveShieldArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::Shield");
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::Shield));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVectorHPathCellArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(std::vector<moho::HPathCell>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveListenerNavPathArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::Listener<Moho::NavPath const &>");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("Listener<Moho::NavPath const &>");
      }
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("Moho::Listener_NavPath");
      }
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::Listener<const moho::SNavPath&>));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveIPathTravelerArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::IPathTraveler");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("IPathTraveler");
      }
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::IPathTraveler));
      }
    }
    return sType;
  }

  /**
   * Address: 0x0071DB80 (FUN_0071DB80)
   *
   * What it does:
   * Lazily resolves the reflected `InfluenceMapEntry` type and reads one object lane through `ReadArchive::Read`.
   */
  void ReadInfluenceMapEntryArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveInfluenceMapEntryArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0071DBB0 (FUN_0071DBB0)
   *
   * What it does:
   * Lazily resolves the reflected `InfluenceMapEntry` type and writes one object lane through `WriteArchive::Write`.
   */
  void WriteInfluenceMapEntryArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveInfluenceMapEntryArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0071DBE0 (FUN_0071DBE0)
   *
   * What it does:
   * Lazily resolves the reflected `SThreat` type and reads one object lane through `ReadArchive::Read`.
   */
  void ReadSThreatArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    gpg::RType* const objectType = ResolveSThreatArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0071DC10 (FUN_0071DC10)
   *
   * What it does:
   * Lazily resolves the reflected `SThreat` type and writes one object lane through `WriteArchive::Write`.
   */
  void WriteSThreatArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveSThreatArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0071E310 (FUN_0071E310)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, InfluenceMapEntry>` type and reads one object lane through
   * `ReadArchive::Read`.
   */
  gpg::ReadArchive* ReadMapUIntInfluenceMapEntryArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntInfluenceMapEntryArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071E350 (FUN_0071E350)
   *
   * What it does:
   * Lazily resolves the reflected `vector<SThreat>` type and reads one object lane through `ReadArchive::Read`.
   */
  gpg::ReadArchive* ReadVectorSThreatArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorSThreatArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071E390 (FUN_0071E390)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, InfluenceMapEntry>` type and writes one object lane through
   * `WriteArchive::Write`.
   */
  gpg::WriteArchive* WriteMapUIntInfluenceMapEntryArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntInfluenceMapEntryArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071E3D0 (FUN_0071E3D0)
   *
   * What it does:
   * Lazily resolves the reflected `vector<SThreat>` type and writes one object lane through `WriteArchive::Write`.
   */
  gpg::WriteArchive* WriteVectorSThreatArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorSThreatArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071EEA0 (FUN_0071EEA0)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, InfluenceMapEntry>` type and reads one object lane through
   * `ReadArchive::Read`.
   */
  void ReadMapUIntInfluenceMapEntryArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntInfluenceMapEntryArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0071EED0 (FUN_0071EED0)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, InfluenceMapEntry>` type and writes one object lane through
   * `WriteArchive::Write`.
   */
  void WriteMapUIntInfluenceMapEntryArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntInfluenceMapEntryArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0071EF00 (FUN_0071EF00)
   *
   * What it does:
   * Lazily resolves the reflected `vector<SThreat>` type and reads one object lane through `ReadArchive::Read`.
   */
  void ReadVectorSThreatArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    gpg::RType* const objectType = ResolveVectorSThreatArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0071EF30 (FUN_0071EF30)
   *
   * What it does:
   * Lazily resolves the reflected `vector<SThreat>` type and writes one object lane through `WriteArchive::Write`.
   */
  void WriteVectorSThreatArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorSThreatArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0071FAE0 (FUN_0071FAE0)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, int>` type and reads one object lane through `ReadArchive::Read`.
   */
  gpg::ReadArchive* ReadMapUIntIntArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIntArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071FB20 (FUN_0071FB20)
   *
   * What it does:
   * Lazily resolves the reflected `vector<InfluenceGrid>` type and reads one object lane through `ReadArchive::Read`.
   */
  gpg::ReadArchive* ReadVectorInfluenceGridArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorInfluenceGridArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071FB60 (FUN_0071FB60)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, int>` type and writes one object lane through `WriteArchive::Write`.
   */
  gpg::WriteArchive* WriteMapUIntIntArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIntArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071FBA0 (FUN_0071FBA0)
   *
   * What it does:
   * Lazily resolves the reflected `vector<InfluenceGrid>` type and writes one object lane through `WriteArchive::Write`.
   */
  gpg::WriteArchive* WriteVectorInfluenceGridArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorInfluenceGridArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0071FDE0 (FUN_0071FDE0)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, int>` type and reads one object lane through `ReadArchive::Read`.
   */
  void ReadMapUIntIntArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    gpg::RType* const objectType = ResolveMapUIntIntArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0071FE10 (FUN_0071FE10)
   *
   * What it does:
   * Lazily resolves the reflected `map<unsigned int, int>` type and writes one object lane through `WriteArchive::Write`.
   */
  void WriteMapUIntIntArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveMapUIntIntArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0071FE40 (FUN_0071FE40)
   *
   * What it does:
   * Lazily resolves the reflected `vector<InfluenceGrid>` type and reads one object lane through `ReadArchive::Read`.
   */
  void ReadVectorInfluenceGridArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorInfluenceGridArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0071FE70 (FUN_0071FE70)
   *
   * What it does:
   * Lazily resolves the reflected `vector<InfluenceGrid>` type and writes one object lane through `WriteArchive::Write`.
   */
  void WriteVectorInfluenceGridArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveVectorInfluenceGridArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0072B620 (FUN_0072B620)
   *
   * What it does:
   * Lazily resolves the reflected `ESquadClass` type and reads one object lane through `ReadArchive::Read`.
   */
  gpg::ReadArchive* ReadESquadClassArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveESquadClassArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0072B660 (FUN_0072B660)
   *
   * What it does:
   * Lazily resolves the reflected `ESquadClass` type and writes one object lane through `WriteArchive::Write`.
   */
  gpg::WriteArchive* WriteESquadClassArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveESquadClassArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x0072B6A0 (FUN_0072B6A0)
   *
   * What it does:
   * Lazily resolves the reflected `ESquadClass` type and reads one object lane through `ReadArchive::Read`.
   */
  void ReadESquadClassArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    gpg::RType* const objectType = ResolveESquadClassArchiveAdapterType();
    archive->Read(objectType, object, *ownerRef);
  }

  /**
   * Address: 0x0072B6D0 (FUN_0072B6D0)
   *
   * What it does:
   * Lazily resolves the reflected `ESquadClass` type and writes one object lane through `WriteArchive::Write`.
   */
  void WriteESquadClassArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const objectType = ResolveESquadClassArchiveAdapterType();
    archive->Write(objectType, objectSlot, *ownerRef);
  }

  /**
   * Address: 0x0073AD60 (FUN_0073AD60)
   *
   * What it does:
   * Upcasts one reflected reference to `CDamage` and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::CDamage* func_CastCDamage(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCDamageArchiveAdapterType());
    return static_cast<moho::CDamage*>(upcast.mObj);
  }

  /**
   * Address: 0x00755AC0 (FUN_00755AC0)
   *
   * What it does:
   * Upcasts one reflected reference to `Shield` and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::Shield* func_CastShield(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveShieldArchiveAdapterType());
    return static_cast<moho::Shield*>(upcast.mObj);
  }

  /**
   * Address: 0x00763BA0 (FUN_00763BA0)
   *
   * What it does:
   * Lazily resolves the reflected `vector<HPathCell>` type and reads one object lane through `ReadArchive::Read` with one
   * local null owner reference.
   */
  void ReadVectorHPathCellArchiveObjectWithNullOwner(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RType* const objectType = ResolveVectorHPathCellArchiveAdapterType();
    gpg::RRef ownerRef{};
    archive->Read(objectType, object, ownerRef);
  }

  /**
   * Address: 0x00763BE0 (FUN_00763BE0)
   *
   * What it does:
   * Lazily resolves the reflected `vector<HPathCell>` type and writes one object lane through `WriteArchive::Write` with
   * one local null owner reference.
   */
  void WriteVectorHPathCellArchiveObjectWithNullOwner(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    gpg::RType* const objectType = ResolveVectorHPathCellArchiveAdapterType();
    const gpg::RRef ownerRef{};
    archive->Write(objectType, objectSlot, ownerRef);
  }

  /**
   * Address: 0x00764420 (FUN_00764420)
   *
   * What it does:
   * Upcasts one reflected reference to `Listener<NavPath const&>` and returns the typed object pointer when the source is
   * compatible.
   */
  [[nodiscard]] moho::Listener<const moho::SNavPath&>* func_CastListener_NavPath(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveListenerNavPathArchiveAdapterType());
    return static_cast<moho::Listener<const moho::SNavPath&>*>(upcast.mObj);
  }

  /**
   * Address: 0x0076AE30 (FUN_0076AE30)
   *
   * What it does:
   * Upcasts one reflected reference to `IPathTraveler` and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::IPathTraveler* func_CastIPathTraveler(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveIPathTravelerArchiveAdapterType());
    return static_cast<moho::IPathTraveler*>(upcast.mObj);
  }

} // namespace
