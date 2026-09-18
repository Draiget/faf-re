#include "moho/unit/tasks/CUnitCarrierRetrieveTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCarrierRetrieve.h"

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitCarrierRetrieveTypeInfo;

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

    AcquireTypeInfo().~CUnitCarrierRetrieveTypeInfo();
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

  [[nodiscard]] gpg::RRef MakeCUnitCarrierRetrieveRef(moho::CUnitCarrierRetrieve* const object)
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CUnitCarrierRetrieve(&ref, object);
    return ref;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00606240 (FUN_00606240)
   */
  CUnitCarrierRetrieveTypeInfo::CUnitCarrierRetrieveTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(moho::CUnitCarrierRetrieve), this);
  }

  /**
   * Address: 0x006062F0 (FUN_006062F0, scalar deleting thunk)
   */
  CUnitCarrierRetrieveTypeInfo::~CUnitCarrierRetrieveTypeInfo() = default;

  /**
   * Address: 0x006062E0 (FUN_006062E0)
   */
  const char* CUnitCarrierRetrieveTypeInfo::GetName() const
  {
    return "moho::CUnitCarrierRetrieve";
  }

  /**
   * Address: 0x006062A0 (FUN_006062A0)
   */
  void CUnitCarrierRetrieveTypeInfo::Init()
  {
    size_ = sizeof(moho::CUnitCarrierRetrieve);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCarrierRetrieveTypeInfo::NewRef,
      &CUnitCarrierRetrieveTypeInfo::CtrRef,
      &CUnitCarrierRetrieveTypeInfo::Delete,
      &CUnitCarrierRetrieveTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00607E20 (FUN_00607E20, Moho::CUnitCarrierRetrieveTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitCarrierRetrieveTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x006079E0 (FUN_006079E0, Moho::CUnitCarrierRetrieveTypeInfo::NewRef)
   */
  gpg::RRef CUnitCarrierRetrieveTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) moho::CUnitCarrierRetrieve();
    return MakeCUnitCarrierRetrieveRef(object);
  }

  /**
   * Address: 0x00607AA0 (FUN_00607AA0, Moho::CUnitCarrierRetrieveTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one carrier-retrieve task runtime lane in caller
   * storage and returns typed reflection reference.
   */
  gpg::RRef CUnitCarrierRetrieveTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitCarrierRetrieve*>(objectStorage);
    if (object) {
      new (object) moho::CUnitCarrierRetrieve();
    }
    return MakeCUnitCarrierRetrieveRef(object);
  }

  /**
   * Address: 0x00607A80 (FUN_00607A80, Moho::CUnitCarrierRetrieveTypeInfo::Delete)
   */
  void CUnitCarrierRetrieveTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitCarrierRetrieve*>(objectStorage);
  }

  /**
   * Address: 0x00607B40 (FUN_00607B40, Moho::CUnitCarrierRetrieveTypeInfo::Destruct)
   */
  void CUnitCarrierRetrieveTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitCarrierRetrieve*>(objectStorage);
    if (!object) {
      return;
    }

    std::destroy_at(object);
  }

  int register_CUnitCarrierRetrieveTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCarrierRetrieveTypeInfo_a01e2d, moho::register_CUnitCarrierRetrieveTypeInfo)
