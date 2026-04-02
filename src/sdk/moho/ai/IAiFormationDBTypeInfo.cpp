#include "moho/ai/IAiFormationDBTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiFormationDB.h"

using namespace moho;

namespace
{
  alignas(IAiFormationDBTypeInfo) unsigned char gIAiFormationDBTypeInfoStorage[sizeof(IAiFormationDBTypeInfo)] = {};
  bool gIAiFormationDBTypeInfoConstructed = false;

  [[nodiscard]] IAiFormationDBTypeInfo* AcquireIAiFormationDBTypeInfo()
  {
    if (!gIAiFormationDBTypeInfoConstructed) {
      new (gIAiFormationDBTypeInfoStorage) IAiFormationDBTypeInfo();
      gIAiFormationDBTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiFormationDBTypeInfo*>(gIAiFormationDBTypeInfoStorage);
  }

  /**
   * Address: 0x00BF67D0 (FUN_00BF67D0)
   *
   * What it does:
   * Tears down startup-owned `IAiFormationDBTypeInfo` storage.
   */
  void cleanup_IAiFormationDBTypeInfo()
  {
    if (!gIAiFormationDBTypeInfoConstructed) {
      return;
    }

    AcquireIAiFormationDBTypeInfo()->~IAiFormationDBTypeInfo();
    gIAiFormationDBTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x0059C3D0 (FUN_0059C3D0, ctor)
 *
 * What it does:
 * Preregisters `IAiFormationDB` RTTI so lookup resolves to this type helper.
 */
IAiFormationDBTypeInfo::IAiFormationDBTypeInfo()
{
  gpg::PreRegisterRType(typeid(IAiFormationDB), this);
}

/**
 * Address: 0x0059C460 (FUN_0059C460, scalar deleting thunk)
 */
IAiFormationDBTypeInfo::~IAiFormationDBTypeInfo() = default;

/**
 * Address: 0x0059C450 (FUN_0059C450, ?GetName@IAiFormationDBTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiFormationDBTypeInfo::GetName() const
{
  return "IAiFormationDB";
}

/**
 * Address: 0x0059C430 (FUN_0059C430, ?Init@IAiFormationDBTypeInfo@Moho@@UAEXXZ)
 */
void IAiFormationDBTypeInfo::Init()
{
  size_ = sizeof(IAiFormationDB);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCC190 (FUN_00BCC190)
 *
 * What it does:
 * Constructs startup-owned `IAiFormationDBTypeInfo` storage and installs
 * process-exit cleanup.
 */
int moho::register_IAiFormationDBTypeInfo()
{
  (void)AcquireIAiFormationDBTypeInfo();
  return std::atexit(&cleanup_IAiFormationDBTypeInfo);
}

namespace
{
  struct IAiFormationDBTypeInfoBootstrap
  {
    IAiFormationDBTypeInfoBootstrap()
    {
      (void)moho::register_IAiFormationDBTypeInfo();
    }
  };

  [[maybe_unused]] IAiFormationDBTypeInfoBootstrap gIAiFormationDBTypeInfoBootstrap;
} // namespace
