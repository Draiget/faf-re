#include "moho/unit/tasks/CUnitCarrierLandTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
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

  /**
   * Address: 0x00BF9960 (FUN_00BF9960, atexit destructor of the CUnitCarrierLandTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCarrierLandRef(moho::CUnitCarrierLand* const object)
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CUnitCarrierLand>(object);
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
    gpg::AddReflectedBase<moho::CCommandTask>(typeInfo);
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
    auto* const object = gpg::ConstructInStorage<moho::CUnitCarrierLand>(objectStorage);
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
    archive->Read(gpg::RTypeOf<moho::CCommandTask>(), static_cast<CCommandTask*>(this), ownerRef);
    archive->Read(gpg::RTypeOf<moho::WeakPtr<moho::Unit>>(), &mTargetCarrier, ownerRef);
    archive->ReadBool(&mHasLoadedIntoCarrier);
    archive->ReadInt(&mReservationResult);
    archive->ReadFloat(&mCarrierHeight);
    archive->Read(gpg::RTypeOf<Wm3::Vector3f>(), &mCarrierAttachPos, ownerRef);
    archive->Read(gpg::RTypeOf<Wm3::Vector3f>(), &mCarrierAttachDir, ownerRef);
    archive->Read(gpg::RTypeOf<Wm3::Vector3f>(), &mCarrierApproachPos, ownerRef);
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
    archive->Write(gpg::RTypeOf<moho::CCommandTask>(), static_cast<const CCommandTask*>(this), ownerRef);
    archive->Write(gpg::RTypeOf<moho::WeakPtr<moho::Unit>>(), &mTargetCarrier, ownerRef);
    archive->WriteBool(mHasLoadedIntoCarrier);
    archive->WriteInt(mReservationResult);
    archive->WriteFloat(mCarrierHeight);
    archive->Write(gpg::RTypeOf<Wm3::Vector3f>(), &mCarrierAttachPos, ownerRef);
    archive->Write(gpg::RTypeOf<Wm3::Vector3f>(), &mCarrierAttachDir, ownerRef);
    archive->Write(gpg::RTypeOf<Wm3::Vector3f>(), &mCarrierApproachPos, ownerRef);
  }

  /**
   * Address: 0x00606610 (FUN_00606610, Moho::CUnitCarrierLand::~CUnitCarrierLand)
   * Address: 0x00606B50 (FUN_00606B50, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
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
    unit->mUnitVarDat.mUnitStates &= ~static_cast<std::uint64_t>(0x100u);

    // Release the focus-entity weak link this carrier-land task established.
    unit->FocusEntityRef.UnlinkFromOwnerChain();
    unit->NeedSyncGameData = true;

    if (!mHasLoadedIntoCarrier) {
      if (CUnitMotion* const motion = unit->UnitMotion) {
        motion->mHeight = gpg::pInf;
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

  /**
   * Address: 0x00BD0260 (FUN_00BD0260, register_CUnitCarrierLandTypeInfo)
   */
  void register_CUnitCarrierLandTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho

namespace
{

  /**
   * Address: 0x00606CD0 (FUN_00606CD0, Moho::CUnitCarrierLandSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `CUnitCarrierLand`. Forwards the
   * reflected object pointer to `CUnitCarrierLand::MemberDeserialize`;
   * `version` and the owner-ref lane are unused by the member (mirrors the
   * binary tail call).
   */
  [[maybe_unused]] void DeserializeCUnitCarrierLandSerializerCallback(
    gpg::ReadArchive* const archive,
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitCarrierLand*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00606CE0 (FUN_00606CE0, Moho::CUnitCarrierLandSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `CUnitCarrierLand`. Forwards the
   * reflected object pointer to `CUnitCarrierLand::MemberSerialize`;
   * `version` and the owner-ref lane are unused by the member (mirrors the
   * binary tail call).
   */
  [[maybe_unused]] void SerializeCUnitCarrierLandSerializerCallback(
    gpg::WriteArchive* const archive,
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitCarrierLand*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCarrierLandTypeInfo_f5d39f, moho::register_CUnitCarrierLandTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CUnitCarrierLand>`, vtable 0x00E200CC.
   *
   * Address: 0x00BD0280 (FUN_00BD0280 -- constructs the global and registers its destructor.)
   * Address: 0x00BF99C0 (FUN_00BF99C0 -- the global's destructor.)
   * Address: 0x006077F0 (FUN_006077F0 -- `Init`.)
   * Address: 0x00606CD0 (FUN_00606CD0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00606CE0 (FUN_00606CE0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CUnitCarrierLandSerializer : gpg::SerSaveLoadHelper<CUnitCarrierLand>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B1134 -- process-global `CUnitCarrierLandSerializer` singleton.
  moho::CUnitCarrierLandSerializer gCUnitCarrierLandSerializer;
} // namespace
