#include "moho/script/CUnitScriptTaskTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/script/CUnitScriptTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  using TypeInfo = CUnitScriptTaskTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitScriptTaskTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitScriptTaskTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCUnitScriptTaskTypeInfoConstructed) {
      new (gCUnitScriptTaskTypeInfoStorage) TypeInfo();
      gCUnitScriptTaskTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitScriptTaskTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCUnitScriptTaskType()
  {
    gpg::RType* type = CUnitScriptTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CUnitScriptTask));
      CUnitScriptTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    return CScriptObject::StaticGetClass();
  }

  [[nodiscard]] gpg::RType* CachedCommandEventListenerType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Listener<ECommandEvent>));
    }
    return type;
  }

  void AddBaseIfPresent(gpg::RType* const typeInfo, gpg::RType* const baseType, const int offset)
  {
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = offset;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] gpg::RRef MakeCUnitScriptTaskRef(CUnitScriptTask* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedCUnitScriptTaskType();
    return ref;
  }

  /**
   * Address: 0x00623CB0 (FUN_00623CB0, CUnitScriptTaskTypeInfo::newRefFunc_)
   */
  [[nodiscard]] gpg::RRef CreateCUnitScriptTaskRefOwned()
  {
    return MakeCUnitScriptTaskRef(new CUnitScriptTask());
  }

  /**
   * Address: 0x00623D30 (FUN_00623D30, CUnitScriptTaskTypeInfo::deleteFunc_)
   */
  void DeleteCUnitScriptTaskOwned(void* object)
  {
    delete static_cast<CUnitScriptTask*>(object);
  }

  /**
   * Address: 0x00623D50 (FUN_00623D50, CUnitScriptTaskTypeInfo::ctorRefFunc_)
   */
  [[nodiscard]] gpg::RRef ConstructCUnitScriptTaskRefInPlace(void* storage)
  {
    auto* const task = static_cast<CUnitScriptTask*>(storage);
    if (task) {
      new (task) CUnitScriptTask();
    }
    return MakeCUnitScriptTaskRef(task);
  }

  /**
   * Address: 0x00623DC0 (FUN_00623DC0, CUnitScriptTaskTypeInfo::dtrFunc_)
   */
  void DestroyCUnitScriptTaskInPlace(void* object)
  {
    auto* const task = static_cast<CUnitScriptTask*>(object);
    if (task) {
      task->~CUnitScriptTask();
    }
  }
} // namespace

namespace moho
{
/**
 * Address: 0x00622D20 (FUN_00622D20)
 */
gpg::RType* register_CUnitScriptTaskTypeInfo()
{
  TypeInfo& typeInfo = AcquireTypeInfo();
  gpg::PreRegisterRType(typeid(CUnitScriptTask), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x00622DE0 (FUN_00622DE0, scalar deleting thunk)
 */
CUnitScriptTaskTypeInfo::~CUnitScriptTaskTypeInfo() = default;

/**
 * Address: 0x00622DD0 (FUN_00622DD0, ?GetName@CUnitScriptTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CUnitScriptTaskTypeInfo::GetName() const
{
  return "CUnitScriptTask";
}

/**
 * Address: 0x00622D80 (FUN_00622D80, ?Init@CUnitScriptTaskTypeInfo@Moho@@UAEXXZ)
 */
void CUnitScriptTaskTypeInfo::Init()
{
  size_ = sizeof(CUnitScriptTask);
  (void)gpg::BindRTypeLifecycleCallbacks(
    this,
    &CreateCUnitScriptTaskRefOwned,
    &ConstructCUnitScriptTaskRefInPlace,
    &DeleteCUnitScriptTaskOwned,
    &DestroyCUnitScriptTaskInPlace
  );

  gpg::RType::Init();
  version_ = 1;

  AddBase_CCommandTask(this);
  AddBase_CScriptObject(this);
  AddBase_Listener_ECommandEvent(this);

  Finish();
}

/**
 * Address: 0x00623DD0 (FUN_00623DD0, Moho::CUnitScriptTaskTypeInfo::AddBase_CCommandTask)
 *
 * IDA signature:
 * void __stdcall Moho::CUnitScriptTaskTypeInfo::AddBase_CCommandTask(gpg::RType *typeInfo);
 *
 * What it does:
 * Registers `CCommandTask` as the primary base at offset 0. The binary emits
 * one such function per base rather than a shared offset-taking helper.
 */
void CUnitScriptTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
{
  AddBaseIfPresent(typeInfo, CachedCCommandTaskType(), 0x00);
}

/**
 * Address: 0x00623E30 (FUN_00623E30, Moho::CUnitScriptTaskTypeInfo::AddBase_CScriptObject)
 *
 * What it does:
 * Registers the `CScriptObject` sub-object base at +0x30.
 */
void CUnitScriptTaskTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
{
  AddBaseIfPresent(typeInfo, CachedCScriptObjectType(), 0x30);
}

/**
 * Address: 0x00623E90 (FUN_00623E90, Moho::CUnitScriptTaskTypeInfo::AddBase_Listener_ECommandEvent)
 *
 * What it does:
 * Registers the `Listener<ECommandEvent>` sub-object base at +0x64.
 */
void CUnitScriptTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
{
  AddBaseIfPresent(typeInfo, CachedCommandEventListenerType(), 0x64);
}

/**
 * Address: 0x00BFA410 (FUN_00BFA410)
 */
void cleanup_CUnitScriptTaskTypeInfo()
{
  if (!gCUnitScriptTaskTypeInfoConstructed) {
    return;
  }

  auto& typeInfo = *reinterpret_cast<TypeInfo*>(gCUnitScriptTaskTypeInfoStorage);
  typeInfo.fields_.clear();
  typeInfo.bases_.clear();
}

/**
 * Address: 0x00BD1960 (FUN_00BD1960)
 */
int register_CUnitScriptTaskTypeInfo_AtExit()
{
  (void)register_CUnitScriptTaskTypeInfo();
  return std::atexit(&cleanup_CUnitScriptTaskTypeInfo);
}
} // namespace moho

namespace
{
  struct CUnitScriptTaskTypeInfoBootstrap
  {
    CUnitScriptTaskTypeInfoBootstrap()
    {
      (void)moho::register_CUnitScriptTaskTypeInfo_AtExit();
    }
  };

  CUnitScriptTaskTypeInfoBootstrap gCUnitScriptTaskTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitScriptTaskTypeInfo_31c747, moho::register_CUnitScriptTaskTypeInfo)
