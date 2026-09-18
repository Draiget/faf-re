#include "moho/unit/tasks/CUnitPodAssistTypeInfo.h"

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitPodAssist.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitPodAssistTypeInfo;

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
    gpg::PreRegisterRType(typeid(moho::CUnitPodAssist), this);
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
    return "moho::CUnitPodAssist";
  }

  /**
   * Address: 0x0061D600 (FUN_0061D600, Moho::CUnitPodAssistTypeInfo::Init)
   */
  void CUnitPodAssistTypeInfo::Init()
  {
    size_ = sizeof(moho::CUnitPodAssist);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitPodAssistTypeInfo::NewRef,
      &CUnitPodAssistTypeInfo::CtrRef,
      &CUnitPodAssistTypeInfo::Delete,
      &CUnitPodAssistTypeInfo::Destruct
    );
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
    auto* const object = new (std::nothrow) moho::CUnitPodAssist();
    return MakeCUnitPodAssistRef(object);
  }

  /**
   * Address: 0x0061E660 (FUN_0061E660, Moho::CUnitPodAssistTypeInfo::CtrRef)
   */
  gpg::RRef CUnitPodAssistTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitPodAssist*>(objectStorage);
    if (object) {
      new (object) moho::CUnitPodAssist();
    }

    return MakeCUnitPodAssistRef(object);
  }

  /**
   * Address: 0x0061E640 (FUN_0061E640, Moho::CUnitPodAssistTypeInfo::Delete)
   */
  void CUnitPodAssistTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitPodAssist*>(objectStorage);
  }

  /**
   * Address: 0x0061E6E0 (FUN_0061E6E0, Moho::CUnitPodAssistTypeInfo::Destruct)
   */
  void CUnitPodAssistTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitPodAssist*>(objectStorage);
    if (!object) {
      return;
    }

    std::destroy_at(object);
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


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitPodAssistTypeInfo_77e443, moho::register_CUnitPodAssistTypeInfo)
