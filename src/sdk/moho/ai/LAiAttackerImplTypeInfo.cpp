#include "moho/ai/LAiAttackerImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/LAiAttackerImpl.h"
#include "moho/task/CTask.h"

using namespace moho;

namespace
{
  alignas(LAiAttackerImplTypeInfo) unsigned char gLAiAttackerImplTypeInfoStorage[sizeof(LAiAttackerImplTypeInfo)];
  bool gLAiAttackerImplTypeInfoConstructed = false;

  [[nodiscard]] LAiAttackerImplTypeInfo* AcquireLAiAttackerImplTypeInfo()
  {
    if (!gLAiAttackerImplTypeInfoConstructed) {
      new (gLAiAttackerImplTypeInfoStorage) LAiAttackerImplTypeInfo();
      gLAiAttackerImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<LAiAttackerImplTypeInfo*>(gLAiAttackerImplTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    gpg::RType* type = CTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CTask));
      CTask::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF8370 (FUN_00BF8370, sub_BF8370)
   *
   * What it does:
   * Tears down recovered static `LAiAttackerImplTypeInfo` storage.
   */
  void cleanup_LAiAttackerImplTypeInfo()
  {
    if (!gLAiAttackerImplTypeInfoConstructed) {
      return;
    }

    AcquireLAiAttackerImplTypeInfo()->~LAiAttackerImplTypeInfo();
    gLAiAttackerImplTypeInfoConstructed = false;
  }

  /**
   * Address: 0x005DBF30 (FUN_005DBF30)
   *
   * What it does:
   * Assigns all lifecycle callback slots (`NewRef`, `CtrRef`, `Delete`,
   * `Destruct`) on one `LAiAttackerImplTypeInfo` descriptor.
   */
  [[maybe_unused]] [[nodiscard]] moho::LAiAttackerImplTypeInfo* AssignLAiAttackerImplLifecycleCallbacks(
    moho::LAiAttackerImplTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->newRefFunc_ = &moho::LAiAttackerImplTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &moho::LAiAttackerImplTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &moho::LAiAttackerImplTypeInfo::Delete;
    typeInfo->dtrFunc_ = &moho::LAiAttackerImplTypeInfo::Destruct;
    return typeInfo;
  }
} // namespace

/**
 * Address: 0x005D6040 (FUN_005D6040, Moho::LAiAttackerImplTypeInfo::LAiAttackerImplTypeInfo)
 *
 * What it does:
 * Preregisters `LAiAttackerImpl` RTTI so the reflection table resolves to the
 * recovered helper.
 */
LAiAttackerImplTypeInfo::LAiAttackerImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(LAiAttackerImpl), this);
}

/**
 * Address: 0x005D60F0 (FUN_005D60F0, scalar deleting thunk)
 */
LAiAttackerImplTypeInfo::~LAiAttackerImplTypeInfo() = default;

/**
 * Address: 0x005D60E0 (FUN_005D60E0, Moho::LAiAttackerImplTypeInfo::GetName)
 */
const char* LAiAttackerImplTypeInfo::GetName() const
{
  return "LAiAttackerImpl";
}

/**
 * Address: 0x005D60A0 (FUN_005D60A0, Moho::LAiAttackerImplTypeInfo::Init)
 */
void LAiAttackerImplTypeInfo::Init()
{
  size_ = sizeof(LAiAttackerImpl);
  (void)AssignLAiAttackerImplLifecycleCallbacks(this);
  gpg::RType::Init();
  AddBase_CTask(this);
  Finish();
}

/**
 * Address: 0x005DEA30 (FUN_005DEA30, Moho::LAiAttackerImplTypeInfo::AddBase_CTask)
 */
void __stdcall LAiAttackerImplTypeInfo::AddBase_CTask(gpg::RType* const typeInfo)
{
  gpg::RType* const baseType = CachedCTaskType();

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x005DD850 (FUN_005DD850, Moho::LAiAttackerImplTypeInfo::NewRef)
 *
 * What it does:
 * Allocates one `LAiAttackerImpl` with null owner lane and returns a typed
 * reflection reference.
 */
gpg::RRef LAiAttackerImplTypeInfo::NewRef()
{
  auto* const task = new (std::nothrow) LAiAttackerImpl(nullptr);
  gpg::RRef out{};
  gpg::RRef_LAiAttackerImpl(&out, task);
  return out;
}

/**
 * Address: 0x005DD8E0 (FUN_005DD8E0, Moho::LAiAttackerImplTypeInfo::CtrRef)
 *
 * What it does:
 * Constructs one `LAiAttackerImpl` with null owner lane in caller-provided
 * storage and returns a typed reflection reference.
 */
gpg::RRef LAiAttackerImplTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const task = static_cast<LAiAttackerImpl*>(objectStorage);
  if (task) {
    new (task) LAiAttackerImpl(nullptr);
  }

  gpg::RRef out{};
  gpg::RRef_LAiAttackerImpl(&out, task);
  return out;
}

/**
 * Address: 0x005DD8C0 (FUN_005DD8C0, Moho::LAiAttackerImplTypeInfo::Delete)
 */
void LAiAttackerImplTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<LAiAttackerImpl*>(objectStorage);
}

/**
 * Address: 0x005DD950 (FUN_005DD950, Moho::LAiAttackerImplTypeInfo::Destruct)
 */
void LAiAttackerImplTypeInfo::Destruct(void* const objectStorage)
{
  static_cast<LAiAttackerImpl*>(objectStorage)->~LAiAttackerImpl();
}

/**
 * Address: 0x00BCE830 (FUN_00BCE830, register_LAiAttackerImplTypeInfo)
 *
 * What it does:
 * Registers `LAiAttackerImpl` type-info object and installs process-exit
 * cleanup.
 */
void moho::register_LAiAttackerImplTypeInfo()
{
  (void)AcquireLAiAttackerImplTypeInfo();
  (void)std::atexit(&cleanup_LAiAttackerImplTypeInfo);
}
