#include "moho/unit/tasks/CUnitCallLandTransportTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallLandTransport.h"

namespace
{
  using TypeInfo = moho::CUnitCallLandTransportTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitCallLandTransportTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitCallLandTransportTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCUnitCallLandTransportTypeInfoConstructed) {
      new (gCUnitCallLandTransportTypeInfoStorage) TypeInfo();
      gCUnitCallLandTransportTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitCallLandTransportTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006005A0 (FUN_006005A0)
   */
  CUnitCallLandTransportTypeInfo::CUnitCallLandTransportTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCallLandTransport), this);
  }

  /**
   * Address: 0x00600650 (FUN_00600650, scalar deleting destructor thunk)
   */
  CUnitCallLandTransportTypeInfo::~CUnitCallLandTransportTypeInfo() = default;

  /**
   * Address: 0x00600640 (FUN_00600640)
   */
  const char* CUnitCallLandTransportTypeInfo::GetName() const
  {
    return "CUnitCallLandTransport";
  }

  /**
   * Address: 0x00600600 (FUN_00600600)
   */
  void CUnitCallLandTransportTypeInfo::Init()
  {
    size_ = sizeof(CUnitCallLandTransport);
    newRefFunc_ = &CUnitCallLandTransportTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitCallLandTransportTypeInfo::CtrRef;
    deleteFunc_ = &CUnitCallLandTransportTypeInfo::Delete;
    dtrFunc_ = &CUnitCallLandTransportTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00602E20 (FUN_00602E20, AddBase_CCommandTask)
   */
  void __stdcall CUnitCallLandTransportTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x00602880 (FUN_00602880)
   */
  gpg::RRef CUnitCallLandTransportTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCallLandTransport();
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallLandTransport))};
  }

  /**
   * Address: 0x00602920 (FUN_00602920)
   */
  gpg::RRef CUnitCallLandTransportTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallLandTransport*>(objectStorage);
    if (task) {
      new (task) CUnitCallLandTransport();
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallLandTransport))};
  }

  /**
   * Address: 0x00602900 (FUN_00602900)
   */
  void CUnitCallLandTransportTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCallLandTransport*>(objectStorage);
  }

  /**
   * Address: 0x00602990 (FUN_00602990)
   */
  void CUnitCallLandTransportTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallLandTransport*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitCallLandTransport();
  }

  /**
   * Address: 0x00BF9650 (FUN_00BF9650, cleanup_CUnitCallLandTransportTypeInfo)
   */
  void cleanup_CUnitCallLandTransportTypeInfo()
  {
    if (!gCUnitCallLandTransportTypeInfoConstructed) {
      return;
    }

    auto& typeInfo = *reinterpret_cast<TypeInfo*>(gCUnitCallLandTransportTypeInfoStorage);
    typeInfo.fields_.clear();
    typeInfo.bases_.clear();
  }

  /**
   * Address: 0x00BCFCA0 (FUN_00BCFCA0, register_CUnitCallLandTransportTypeInfo)
   */
  int register_CUnitCallLandTransportTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitCallLandTransportTypeInfo);
  }
} // namespace moho

