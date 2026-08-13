#include "moho/unit/tasks/CUnitCarrierLandTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/ai/IAiTransport.h"
#include "moho/entity/Entity.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitCarrierLand.h"
#include "Wm3Vector3.h"

#include <limits>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitCarrierLandTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      new (gTypeInfoStorage) TypeInfo();
      gTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gTypeInfoStorage);
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitCarrierLandTypeInfo();
    gTypeInfoConstructed = false;
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

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCarrierLandRef(moho::CUnitCarrierLand* const object)
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CUnitCarrierLand(&ref, object);
    return ref;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00606B70 (FUN_00606B70)
   */
  CUnitCarrierLandTypeInfo::CUnitCarrierLandTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCarrierLand), this);
  }

  /**
   * Address: 0x00606C20 (FUN_00606C20, scalar deleting thunk)
   */
  CUnitCarrierLandTypeInfo::~CUnitCarrierLandTypeInfo() = default;

  /**
   * Address: 0x00606C10 (FUN_00606C10)
   */
  const char* CUnitCarrierLandTypeInfo::GetName() const
  {
    return "CUnitCarrierLand";
  }

  /**
   * Address: 0x00606BD0 (FUN_00606BD0)
   */
  void CUnitCarrierLandTypeInfo::Init()
  {
    size_ = sizeof(CUnitCarrierLand);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCarrierLandTypeInfo::NewRef,
      &CUnitCarrierLandTypeInfo::CtrRef,
      &CUnitCarrierLandTypeInfo::Delete,
      &CUnitCarrierLandTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00607EA0 (FUN_00607EA0, Moho::CUnitCarrierLandTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitCarrierLandTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCCommandTaskType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00607B50 (FUN_00607B50, Moho::CUnitCarrierLandTypeInfo::NewRef)
   */
  gpg::RRef CUnitCarrierLandTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) moho::CUnitCarrierLand();
    return MakeCUnitCarrierLandRef(object);
  }

  /**
   * Address: 0x00607C30 (FUN_00607C30, Moho::CUnitCarrierLandTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one carrier-land task runtime lane in caller storage
   * and returns typed reflection reference.
   */
  gpg::RRef CUnitCarrierLandTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitCarrierLand*>(objectStorage);
    if (object) {
      new (object) moho::CUnitCarrierLand();
    }
    return MakeCUnitCarrierLandRef(object);
  }

  /**
   * Address: 0x00607C10 (FUN_00607C10, Moho::CUnitCarrierLandTypeInfo::Delete)
   */
  void CUnitCarrierLandTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitCarrierLand*>(objectStorage);
  }

  /**
   * Address: 0x00607CF0 (FUN_00607CF0, Moho::CUnitCarrierLandTypeInfo::Destruct)
   */
  void CUnitCarrierLandTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitCarrierLand*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitCarrierLand();
  }

  /**
   * Address: 0x006086C0 (FUN_006086C0, Moho::CUnitCarrierLand::MemberDeserialize)
   *
   * What it does:
   * Deserializes base command-task state, target transport weak pointer, and
   * carrier-landing reservation payload lanes.
   */
  void CUnitCarrierLand::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mTargetCarrier, ownerRef);
    archive->ReadBool(&mHasLoadedIntoCarrier);
    archive->ReadInt(&mReservationResult);
    archive->ReadFloat(&mCarrierHeight);
    archive->Read(CachedVector3fType(), &mCarrierAttachPos, ownerRef);
    archive->Read(CachedVector3fType(), &mCarrierAttachDir, ownerRef);
    archive->Read(CachedVector3fType(), &mCarrierApproachPos, ownerRef);
  }

  /**
   * Address: 0x00608800 (FUN_00608800, Moho::CUnitCarrierLand::MemberSerialize)
   *
   * What it does:
   * Serializes base command-task state, target transport weak pointer, and
   * carrier-landing reservation payload lanes.
   */
  void CUnitCarrierLand::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);
    archive->Write(CachedWeakPtrUnitType(), &mTargetCarrier, ownerRef);
    archive->WriteBool(mHasLoadedIntoCarrier);
    archive->WriteInt(mReservationResult);
    archive->WriteFloat(mCarrierHeight);
    archive->Write(CachedVector3fType(), &mCarrierAttachPos, ownerRef);
    archive->Write(CachedVector3fType(), &mCarrierAttachDir, ownerRef);
    archive->Write(CachedVector3fType(), &mCarrierApproachPos, ownerRef);
  }

  /**
   * Address: 0x00606610 (FUN_00606610, Moho::CUnitCarrierLand::~CUnitCarrierLand)
   *
   * What it does:
   * Aborts an in-progress carrier landing: clears the unit's carrier motion
   * event and the carrier-landing state bit, releases the focus-entity weak
   * link, and — unless the unit already loaded — resets the flyer to climb
   * (height infinity, air layer) and clears the target carrier's transport
   * reservation. Publishes the dispatch result, unlinks the target-carrier weak
   * pointer, then runs the base command-task teardown.
   */
  CUnitCarrierLand::~CUnitCarrierLand()
  {
    Unit* const unit = mUnit;

    if (CUnitMotion* const motion = unit->UnitMotion) {
      motion->mCarrierEvent = static_cast<EUnitMotionCarrierEvent>(0);
    }
    unit->UnitStateMask &= ~static_cast<std::uint64_t>(0x100u);

    // Release the focus-entity weak link this carrier-land task established.
    unit->FocusEntityRef.AsWeakPtr<Entity>().UnlinkFromOwnerChain();
    unit->NeedSyncGameData = true;

    if (!mHasLoadedIntoCarrier) {
      if (CUnitMotion* const motion = unit->UnitMotion) {
        motion->mHeight = std::numeric_limits<float>::infinity();
        motion->mLayer = LAYER_Air;
      }
      if (Unit* const targetCarrier = mTargetCarrier.GetObjectPtr()) {
        if (!targetCarrier->IsDead() && targetCarrier->AiTransport != nullptr) {
          targetCarrier->AiTransport->TransportClearReservation(unit);
        }
      }
    }

    *mDispatchResult = static_cast<EAiResult>(2 - static_cast<int>(mHasLoadedIntoCarrier));

    mTargetCarrier.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00608050 (FUN_00608050)
   *
   * What it does:
   * Preserves one jump-thunk deserialize adapter lane that tail-forwards into
   * `CUnitCarrierLand::MemberDeserialize`.
   */
  [[maybe_unused]] void CUnitCarrierLandMemberDeserializeAdapterLaneB(
    CUnitCarrierLand* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }

  int register_CUnitCarrierLandTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitCarrierLandSerializer{};

  /**
   * Address: 0x00606D20 (FUN_00606D20)
   *
   * What it does:
   * Unlinks `CUnitCarrierLandSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierLandSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCarrierLandSerializer);
  }

  /**
   * Address: 0x00606D50 (FUN_00606D50)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCarrierLandSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierLandSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCarrierLandSerializer);
  }
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCarrierLandTypeInfo_f5d39f, moho::register_CUnitCarrierLandTypeInfo)
