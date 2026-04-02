#include "moho/ai/IAiBuilderTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiBuilder.h"

using namespace moho;

namespace
{
  alignas(IAiBuilderTypeInfo) unsigned char gIAiBuilderTypeInfoStorage[sizeof(IAiBuilderTypeInfo)] = {};
  bool gIAiBuilderTypeInfoConstructed = false;

  [[nodiscard]] IAiBuilderTypeInfo* AcquireIAiBuilderTypeInfo()
  {
    if (!gIAiBuilderTypeInfoConstructed) {
      new (gIAiBuilderTypeInfoStorage) IAiBuilderTypeInfo();
      gIAiBuilderTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiBuilderTypeInfo*>(gIAiBuilderTypeInfoStorage);
  }

  /**
   * Address: 0x00BF6A00 (FUN_00BF6A00)
   *
   * What it does:
   * Tears down startup-owned `IAiBuilderTypeInfo` storage.
   */
  void cleanup_IAiBuilderTypeInfo()
  {
    if (!gIAiBuilderTypeInfoConstructed) {
      return;
    }

    AcquireIAiBuilderTypeInfo()->~IAiBuilderTypeInfo();
    gIAiBuilderTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x0059ED90 (FUN_0059ED90, ctor)
 *
 * What it does:
 * Preregisters `IAiBuilder` RTTI so lookup resolves to this type helper.
 */
IAiBuilderTypeInfo::IAiBuilderTypeInfo()
{
  gpg::PreRegisterRType(typeid(IAiBuilder), this);
}

/**
 * Address: 0x0059EE20 (FUN_0059EE20, scalar deleting thunk)
 */
IAiBuilderTypeInfo::~IAiBuilderTypeInfo() = default;

/**
 * Address: 0x0059EE10 (FUN_0059EE10, ?GetName@IAiBuilderTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiBuilderTypeInfo::GetName() const
{
  return "IAiBuilder";
}

/**
 * Address: 0x0059EDF0 (FUN_0059EDF0, ?Init@IAiBuilderTypeInfo@Moho@@UAEXXZ)
 */
void IAiBuilderTypeInfo::Init()
{
  size_ = sizeof(IAiBuilder);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCC2A0 (FUN_00BCC2A0)
 *
 * What it does:
 * Constructs startup-owned `IAiBuilderTypeInfo` storage and installs
 * process-exit cleanup.
 */
int moho::register_IAiBuilderTypeInfo()
{
  (void)AcquireIAiBuilderTypeInfo();
  return std::atexit(&cleanup_IAiBuilderTypeInfo);
}

namespace
{
  struct IAiBuilderTypeInfoBootstrap
  {
    IAiBuilderTypeInfoBootstrap()
    {
      (void)moho::register_IAiBuilderTypeInfo();
    }
  };

  [[maybe_unused]] IAiBuilderTypeInfoBootstrap gIAiBuilderTypeInfoBootstrap;
} // namespace
