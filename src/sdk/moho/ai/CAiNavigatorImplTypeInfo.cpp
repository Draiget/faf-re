#include "moho/ai/CAiNavigatorImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorImpl.h"

using namespace moho;

namespace
{
  alignas(CAiNavigatorImplTypeInfo) unsigned char gCAiNavigatorImplTypeInfoStorage[sizeof(CAiNavigatorImplTypeInfo)] = {};
  bool gCAiNavigatorImplTypeInfoConstructed = false;

  [[nodiscard]] CAiNavigatorImplTypeInfo* AcquireCAiNavigatorImplTypeInfo()
  {
    if (!gCAiNavigatorImplTypeInfoConstructed) {
      new (gCAiNavigatorImplTypeInfoStorage) CAiNavigatorImplTypeInfo();
      gCAiNavigatorImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorImplTypeInfo*>(gCAiNavigatorImplTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    if (!IAiNavigator::sType) {
      IAiNavigator::sType = gpg::LookupRType(typeid(IAiNavigator));
    }
    return IAiNavigator::sType;
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  /**
   * Address: 0x00BF6D50 (FUN_00BF6D50)
   *
   * What it does:
   * Tears down startup-owned `CAiNavigatorImplTypeInfo` storage.
   */
  void cleanup_CAiNavigatorImplTypeInfo()
  {
    if (!gCAiNavigatorImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiNavigatorImplTypeInfo()->~CAiNavigatorImplTypeInfo();
    gCAiNavigatorImplTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005A3880 (FUN_005A3880, ctor)
 *
 * What it does:
 * Preregisters `CAiNavigatorImpl` RTTI so lookup resolves to this type helper.
 */
CAiNavigatorImplTypeInfo::CAiNavigatorImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiNavigatorImpl), this);
}

/**
 * Address: 0x005A3930 (FUN_005A3930, scalar deleting thunk)
 */
CAiNavigatorImplTypeInfo::~CAiNavigatorImplTypeInfo() = default;

/**
 * Address: 0x005A3920 (FUN_005A3920, ?GetName@CAiNavigatorImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorImplTypeInfo::GetName() const
{
  return "CAiNavigatorImpl";
}

/**
 * Address: 0x005A38E0 (FUN_005A38E0, ?Init@CAiNavigatorImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorImplTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorImpl);
  Version(1);
  gpg::RType::Init();

  gpg::RField baseField{};

  baseField.mName = CachedIAiNavigatorType()->GetName();
  baseField.mType = CachedIAiNavigatorType();
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  baseField.mName = CachedCTaskType()->GetName();
  baseField.mType = CachedCTaskType();
  baseField.mOffset = 0x10;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  baseField.mName = CachedCScriptObjectType()->GetName();
  baseField.mType = CachedCScriptObjectType();
  baseField.mOffset = 0x28;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}

/**
 * Address: 0x00BCC700 (FUN_00BCC700, register_CAiNavigatorImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiNavigatorImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiNavigatorImplTypeInfo()
{
  (void)AcquireCAiNavigatorImplTypeInfo();
  (void)std::atexit(&cleanup_CAiNavigatorImplTypeInfo);
}

namespace
{
  struct CAiNavigatorImplTypeInfoBootstrap
  {
    CAiNavigatorImplTypeInfoBootstrap()
    {
      (void)moho::register_CAiNavigatorImplTypeInfo();
    }
  };

  [[maybe_unused]] CAiNavigatorImplTypeInfoBootstrap gCAiNavigatorImplTypeInfoBootstrap;
} // namespace

