#include "moho/unit/tasks/CUnitPodAssistTypeInfo.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitPodAssist.h"

namespace
{
  using TypeInfo = moho::CUnitPodAssistTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitPodAssistRuntimeView final : moho::CCommandTask
  {
    moho::CCommandTask* mDispatchTask = nullptr; // +0x30
    moho::WeakPtr<moho::Unit> mAssistTarget{};   // +0x34

    int Execute() override
    {
      return 1;
    }
  };

  static_assert(
    sizeof(CUnitPodAssistRuntimeView) == sizeof(moho::CUnitPodAssist),
    "CUnitPodAssistRuntimeView size must match CUnitPodAssist"
  );
  static_assert(
    offsetof(CUnitPodAssistRuntimeView, mDispatchTask) == 0x30,
    "CUnitPodAssistRuntimeView::mDispatchTask offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitPodAssistRuntimeView, mAssistTarget) == 0x34,
    "CUnitPodAssistRuntimeView::mAssistTarget offset must be 0x34"
  );

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      new (gTypeInfoStorage) TypeInfo();
      gTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gTypeInfoStorage);
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

  [[nodiscard]] gpg::RType* CachedCUnitPodAssistType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitPodAssist));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitPodAssistRef(moho::CUnitPodAssist* const object)
  {
    return gpg::RRef{object, CachedCUnitPodAssistType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0061D5A0 (FUN_0061D5A0, sub_61D5A0)
   */
  CUnitPodAssistTypeInfo::CUnitPodAssistTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitPodAssist), this);
  }

  /**
   * Address: 0x0061D650 (FUN_0061D650, Moho::CUnitPodAssistTypeInfo::dtr)
   */
  CUnitPodAssistTypeInfo::~CUnitPodAssistTypeInfo() = default;

  /**
   * Address: 0x0061D640 (FUN_0061D640, Moho::CUnitPodAssistTypeInfo::GetName)
   */
  const char* CUnitPodAssistTypeInfo::GetName() const
  {
    return "CUnitPodAssist";
  }

  /**
   * Address: 0x0061D600 (FUN_0061D600, Moho::CUnitPodAssistTypeInfo::Init)
   */
  void CUnitPodAssistTypeInfo::Init()
  {
    size_ = sizeof(CUnitPodAssist);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    newRefFunc_ = &CUnitPodAssistTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitPodAssistTypeInfo::CtrRef;
    deleteFunc_ = &CUnitPodAssistTypeInfo::Delete;
    dtrFunc_ = &CUnitPodAssistTypeInfo::Destruct;
    Finish();
  }

  /**
   * Address: 0x0061E6F0 (FUN_0061E6F0, Moho::CUnitPodAssistTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitPodAssistTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x0061E5B0 (FUN_0061E5B0, Moho::CUnitPodAssistTypeInfo::NewRef)
   */
  gpg::RRef CUnitPodAssistTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitPodAssistRuntimeView();
    return MakeCUnitPodAssistRef(reinterpret_cast<CUnitPodAssist*>(object));
  }

  /**
   * Address: 0x0061E660 (FUN_0061E660, Moho::CUnitPodAssistTypeInfo::CtrRef)
   */
  gpg::RRef CUnitPodAssistTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitPodAssistRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitPodAssistRuntimeView();
    }

    return MakeCUnitPodAssistRef(reinterpret_cast<CUnitPodAssist*>(object));
  }

  /**
   * Address: 0x0061E640 (FUN_0061E640, Moho::CUnitPodAssistTypeInfo::Delete)
   */
  void CUnitPodAssistTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitPodAssistRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x0061E6E0 (FUN_0061E6E0, Moho::CUnitPodAssistTypeInfo::Destruct)
   */
  void CUnitPodAssistTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitPodAssistRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitPodAssistRuntimeView();
  }

  /**
   * Address: 0x00BFA200 (FUN_00BFA200)
   */
  void cleanup_CUnitPodAssistTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitPodAssistTypeInfo();
    gTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD1570 (FUN_00BD1570, sub_BD1570)
   */
  int register_CUnitPodAssistTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitPodAssistTypeInfo);
  }
} // namespace moho
