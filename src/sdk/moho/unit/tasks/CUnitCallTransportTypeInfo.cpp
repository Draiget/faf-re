#include "moho/unit/tasks/CUnitCallTransportTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallTransport.h"

namespace
{
  using TypeInfo = moho::CUnitCallTransportTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitCallTransportTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitCallTransportTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCUnitCallTransportTypeInfoConstructed) {
      new (gCUnitCallTransportTypeInfoStorage) TypeInfo();
      gCUnitCallTransportTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitCallTransportTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FF990 (FUN_005FF990)
   */
  CUnitCallTransportTypeInfo::CUnitCallTransportTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCallTransport), this);
  }

  /**
   * Address: 0x005FFA40 (FUN_005FFA40, scalar deleting destructor thunk)
   */
  CUnitCallTransportTypeInfo::~CUnitCallTransportTypeInfo() = default;

  /**
   * Address: 0x005FFA30 (FUN_005FFA30)
   */
  const char* CUnitCallTransportTypeInfo::GetName() const
  {
    return "CUnitCallTransport";
  }

  /**
   * Address: 0x005FF9F0 (FUN_005FF9F0)
   */
  void CUnitCallTransportTypeInfo::Init()
  {
    size_ = sizeof(CUnitCallTransport);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCallTransportTypeInfo::NewRef,
      &CUnitCallTransportTypeInfo::CtrRef,
      &CUnitCallTransportTypeInfo::Delete,
      &CUnitCallTransportTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00602C20 (FUN_00602C20, AddBase_CCommandTask)
   */
  void __stdcall CUnitCallTransportTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = CCommandTask::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = baseType;
    }

    GPG_ASSERT(baseType != nullptr);
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00602760 (FUN_00602760)
   */
  gpg::RRef CUnitCallTransportTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCallTransport();
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallTransport))};
  }

  /**
   * Address: 0x00602800 (FUN_00602800)
   */
  gpg::RRef CUnitCallTransportTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallTransport*>(objectStorage);
    if (task) {
      new (task) CUnitCallTransport();
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallTransport))};
  }

  /**
   * Address: 0x006027E0 (FUN_006027E0)
   */
  void CUnitCallTransportTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCallTransport*>(objectStorage);
  }

  /**
   * Address: 0x00602870 (FUN_00602870)
   */
  void CUnitCallTransportTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallTransport*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitCallTransport();
  }

  /**
   * Address: 0x00BF95C0 (FUN_00BF95C0, cleanup_CUnitCallTransportTypeInfo)
   */
  void cleanup_CUnitCallTransportTypeInfo()
  {
    if (!gCUnitCallTransportTypeInfoConstructed) {
      return;
    }

    auto& typeInfo = *reinterpret_cast<TypeInfo*>(gCUnitCallTransportTypeInfoStorage);
    typeInfo.fields_.clear();
    typeInfo.bases_.clear();
  }

  /**
   * Address: 0x00BCFC40 (FUN_00BCFC40, register_CUnitCallTransportTypeInfo)
   */
  int register_CUnitCallTransportTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitCallTransportTypeInfo);
  }
} // namespace moho

