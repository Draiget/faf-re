#include "moho/ai/SContinueInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
  alignas(SContinueInfoTypeInfo) unsigned char gSContinueInfoTypeInfoStorage[sizeof(SContinueInfoTypeInfo)] = {};
  bool gSContinueInfoTypeInfoConstructed = false;

  [[nodiscard]] SContinueInfoTypeInfo* AcquireSContinueInfoTypeInfo()
  {
    if (!gSContinueInfoTypeInfoConstructed) {
      auto* const typeInfo = new (gSContinueInfoTypeInfoStorage) SContinueInfoTypeInfo();
      gpg::PreRegisterRType(typeid(SContinueInfo), typeInfo);
      gSContinueInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<SContinueInfoTypeInfo*>(gSContinueInfoTypeInfoStorage);
  }

  /**
   * Address: 0x00BF7450 (FUN_00BF7450, cleanup_SContinueInfoTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SContinueInfoTypeInfo` reflection storage.
   */
  void cleanup_SContinueInfoTypeInfo()
  {
    if (!gSContinueInfoTypeInfoConstructed) {
      return;
    }

    AcquireSContinueInfoTypeInfo()->~SContinueInfoTypeInfo();
    gSContinueInfoTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005B21E0 (FUN_005B21E0, scalar deleting thunk)
 */
SContinueInfoTypeInfo::~SContinueInfoTypeInfo() = default;

/**
 * Address: 0x005B21D0 (FUN_005B21D0)
 */
const char* SContinueInfoTypeInfo::GetName() const
{
  return "SContinueInfo";
}

/**
 * Address: 0x005B21B0 (FUN_005B21B0)
 */
void SContinueInfoTypeInfo::Init()
{
  size_ = sizeof(SContinueInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCD2D0 (FUN_00BCD2D0, register_SContinueInfoTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `SContinueInfo` and
 * installs process-exit cleanup.
 */
int moho::register_SContinueInfoTypeInfo()
{
  (void)AcquireSContinueInfoTypeInfo();
  return std::atexit(&cleanup_SContinueInfoTypeInfo);
}

namespace
{
  struct SContinueInfoTypeInfoBootstrap
  {
    SContinueInfoTypeInfoBootstrap()
    {
      (void)moho::register_SContinueInfoTypeInfo();
    }
  };

  [[maybe_unused]] SContinueInfoTypeInfoBootstrap gSContinueInfoTypeInfoBootstrap;
} // namespace
