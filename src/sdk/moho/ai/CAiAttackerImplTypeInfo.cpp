#include "moho/ai/CAiAttackerImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiAttackerImplConstruct.h"
#include "moho/ai/CAiAttackerImplSerializer.h"
#include "moho/ai/LAiAttackerImplSerializer.h"
#include "moho/ai/LAiAttackerImplTypeInfo.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/script/CScriptObject.h"

using namespace moho;

namespace
{
  alignas(CAiAttackerImplTypeInfo) unsigned char gCAiAttackerImplTypeInfoStorage[sizeof(CAiAttackerImplTypeInfo)];
  bool gCAiAttackerImplTypeInfoConstructed = false;

  [[nodiscard]] CAiAttackerImplTypeInfo* AcquireCAiAttackerImplTypeInfo()
  {
    if (!gCAiAttackerImplTypeInfoConstructed) {
      new (gCAiAttackerImplTypeInfoStorage) CAiAttackerImplTypeInfo();
      gCAiAttackerImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiAttackerImplTypeInfo*>(gCAiAttackerImplTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedIAiAttackerType()
  {
    gpg::RType* type = IAiAttacker::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiAttacker));
      IAiAttacker::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    gpg::RType* type = CScriptObject::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CScriptObject));
      CScriptObject::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF8310 (FUN_00BF8310, sub_BF8310)
   *
   * What it does:
   * Tears down recovered static `CAiAttackerImplTypeInfo` storage.
   */
  void cleanup_CAiAttackerImplTypeInfo()
  {
    if (!gCAiAttackerImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiAttackerImplTypeInfo()->~CAiAttackerImplTypeInfo();
    gCAiAttackerImplTypeInfoConstructed = false;
  }

  struct AiAttackerRecoveryBootstrap
  {
    AiAttackerRecoveryBootstrap()
    {
      (void)moho::register_CAiAttackerImplTypeInfo();
      (void)moho::register_LAiAttackerImplTypeInfo();
      (void)moho::register_CAiAttackerImplSerializer();
      (void)moho::register_LAiAttackerImplSerializer();
      (void)moho::register_CAiAttackerImplConstruct();
    }
  };

  [[maybe_unused]] AiAttackerRecoveryBootstrap gAiAttackerRecoveryBootstrap;
} // namespace

/**
 * Address: 0x005D5DE0 (FUN_005D5DE0, Moho::CAiAttackerImplTypeInfo::CAiAttackerImplTypeInfo)
 *
 * What it does:
 * Preregisters `CAiAttackerImpl` RTTI so the reflection table resolves to the
 * recovered helper.
 */
CAiAttackerImplTypeInfo::CAiAttackerImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiAttackerImpl), this);
}

/**
 * Address: 0x005D5E80 (FUN_005D5E80, scalar deleting thunk)
 */
CAiAttackerImplTypeInfo::~CAiAttackerImplTypeInfo() = default;

/**
 * Address: 0x005D5E70 (FUN_005D5E70, Moho::CAiAttackerImplTypeInfo::GetName)
 */
const char* CAiAttackerImplTypeInfo::GetName() const
{
  return "CAiAttackerImpl";
}

/**
 * Address: 0x005D5E40 (FUN_005D5E40, Moho::CAiAttackerImplTypeInfo::Init)
 */
void CAiAttackerImplTypeInfo::Init()
{
  size_ = 0xA4;
  gpg::RType::Init();

  gpg::RField baseField{};

  baseField.mName = CachedIAiAttackerType()->GetName();
  baseField.mType = CachedIAiAttackerType();
  baseField.mOffset = 0x00;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  baseField.mName = CachedCScriptObjectType()->GetName();
  baseField.mType = CachedCScriptObjectType();
  baseField.mOffset = 0x0C;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}

/**
 * Address: 0x00BCE810 (FUN_00BCE810, register_CAiAttackerImplTypeInfo)
 *
 * What it does:
 * Registers `CAiAttackerImpl` type-info object and installs process-exit
 * cleanup.
 */
void moho::register_CAiAttackerImplTypeInfo()
{
  (void)AcquireCAiAttackerImplTypeInfo();
  (void)std::atexit(&cleanup_CAiAttackerImplTypeInfo);
}
