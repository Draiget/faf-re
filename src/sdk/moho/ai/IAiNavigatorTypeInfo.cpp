#include "moho/ai/IAiNavigatorTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

namespace
{
  alignas(IAiNavigatorTypeInfo) unsigned char gIAiNavigatorTypeInfoStorage[sizeof(IAiNavigatorTypeInfo)] = {};
  bool gIAiNavigatorTypeInfoConstructed = false;

  [[nodiscard]] IAiNavigatorTypeInfo* AcquireIAiNavigatorTypeInfo()
  {
    if (!gIAiNavigatorTypeInfoConstructed) {
      new (gIAiNavigatorTypeInfoStorage) IAiNavigatorTypeInfo();
      gIAiNavigatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiNavigatorTypeInfo*>(gIAiNavigatorTypeInfoStorage);
  }

  /**
   * Address: 0x00BF6D00 (FUN_00BF6D00)
   *
   * What it does:
   * Tears down startup-owned `IAiNavigatorTypeInfo` storage.
   */
  void cleanup_IAiNavigatorTypeInfo()
  {
    if (!gIAiNavigatorTypeInfoConstructed) {
      return;
    }

    AcquireIAiNavigatorTypeInfo()->~IAiNavigatorTypeInfo();
    gIAiNavigatorTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005A3190 (FUN_005A3190, ctor)
 *
 * What it does:
 * Preregisters `IAiNavigator` RTTI so lookup resolves to this type helper.
 */
IAiNavigatorTypeInfo::IAiNavigatorTypeInfo()
{
  gpg::PreRegisterRType(typeid(IAiNavigator), this);
}

/**
 * Address: 0x005A3220 (FUN_005A3220, scalar deleting thunk)
 */
IAiNavigatorTypeInfo::~IAiNavigatorTypeInfo() = default;

/**
 * Address: 0x005A3210 (FUN_005A3210, ?GetName@IAiNavigatorTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiNavigatorTypeInfo::GetName() const
{
  return "IAiNavigator";
}

/**
 * Address: 0x005A31F0 (FUN_005A31F0, ?Init@IAiNavigatorTypeInfo@Moho@@UAEXXZ)
 */
void IAiNavigatorTypeInfo::Init()
{
  size_ = sizeof(IAiNavigator);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCC6A0 (FUN_00BCC6A0)
 *
 * What it does:
 * Constructs startup-owned `IAiNavigatorTypeInfo` storage and installs
 * process-exit cleanup.
 */
int moho::register_IAiNavigatorTypeInfo()
{
  (void)AcquireIAiNavigatorTypeInfo();
  return std::atexit(&cleanup_IAiNavigatorTypeInfo);
}

namespace
{
  struct IAiNavigatorTypeInfoBootstrap
  {
    IAiNavigatorTypeInfoBootstrap()
    {
      (void)moho::register_IAiNavigatorTypeInfo();
    }
  };

  [[maybe_unused]] IAiNavigatorTypeInfoBootstrap gIAiNavigatorTypeInfoBootstrap;
} // namespace

