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
  size_ = 0x20;
  gpg::RType::Init();

  if (gpg::RType* const baseType = CachedCTaskType()) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x00;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  Finish();
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
