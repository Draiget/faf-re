#include "moho/unit/tasks/CUnitCarrierLandTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCarrierLand.h"
#include "Wm3Vector3.h"

namespace
{
  using TypeInfo = moho::CUnitCarrierLandTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitCarrierLandRuntimeView final : moho::CCommandTask
  {
    std::uint32_t mUnknownWord0 = 0; // +0x30
    std::uint32_t mUnknownWord1 = 0; // +0x34
    std::uint8_t mUnknownByte0 = 0;  // +0x38
    std::uint8_t mPad39_3B[3] = {0, 0, 0};
    std::uint32_t mUnknownWord2 = 0;  // +0x3C
    std::uint32_t mUnknownWord3 = 0;  // +0x40
    std::uint32_t mUnknownWord4 = 0;  // +0x44
    std::uint32_t mUnknownWord5 = 0;  // +0x48
    std::uint32_t mUnknownWord6 = 0;  // +0x4C
    std::uint32_t mUnknownWord7 = 0;  // +0x50
    std::uint32_t mUnknownWord8 = 0;  // +0x54
    std::uint32_t mUnknownWord9 = 0;  // +0x58
    std::uint32_t mUnknownWord10 = 0; // +0x5C
    std::uint32_t mUnknownWord11 = 0; // +0x60
    std::uint32_t mUnknownWord12 = 0; // +0x64

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(sizeof(CUnitCarrierLandRuntimeView) == sizeof(moho::CUnitCarrierLand), "CUnitCarrierLandRuntimeView size must match CUnitCarrierLand");
  static_assert(offsetof(CUnitCarrierLandRuntimeView, mUnknownWord0) == 0x30, "CUnitCarrierLandRuntimeView::mUnknownWord0 offset must be 0x30");
  static_assert(offsetof(CUnitCarrierLandRuntimeView, mUnknownWord12) == 0x64, "CUnitCarrierLandRuntimeView::mUnknownWord12 offset must be 0x64");

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

  [[nodiscard]] gpg::RType* CachedCUnitCarrierLandType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCarrierLand));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCarrierLandRef(CUnitCarrierLandRuntimeView* const object)
  {
    return gpg::RRef{reinterpret_cast<moho::CUnitCarrierLand*>(object), CachedCUnitCarrierLandType()};
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
    auto* const object = new (std::nothrow) CUnitCarrierLandRuntimeView();
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
    auto* const object = static_cast<CUnitCarrierLandRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitCarrierLandRuntimeView();
    }
    return MakeCUnitCarrierLandRef(object);
  }

  /**
   * Address: 0x00607C10 (FUN_00607C10, Moho::CUnitCarrierLandTypeInfo::Delete)
   */
  void CUnitCarrierLandTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCarrierLandRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x00607CF0 (FUN_00607CF0, Moho::CUnitCarrierLandTypeInfo::Destruct)
   */
  void CUnitCarrierLandTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitCarrierLandRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitCarrierLandRuntimeView();
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
