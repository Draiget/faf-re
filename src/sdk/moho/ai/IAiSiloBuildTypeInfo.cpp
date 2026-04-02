#include "moho/ai/IAiSiloBuildTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiSiloBuild.h"

using namespace moho;

namespace
{
  alignas(IAiSiloBuildTypeInfo) unsigned char gIAiSiloBuildTypeInfoStorage[sizeof(IAiSiloBuildTypeInfo)];
  bool gIAiSiloBuildTypeInfoConstructed = false;

  [[nodiscard]] IAiSiloBuildTypeInfo* AcquireIAiSiloBuildTypeInfo()
  {
    if (!gIAiSiloBuildTypeInfoConstructed) {
      auto* const typeInfo = new (gIAiSiloBuildTypeInfoStorage) IAiSiloBuildTypeInfo();
      gpg::PreRegisterRType(typeid(IAiSiloBuild), typeInfo);
      gIAiSiloBuildTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiSiloBuildTypeInfo*>(gIAiSiloBuildTypeInfoStorage);
  }

  /**
   * Address: 0x005CE8B0 (FUN_005CE8B0, sub_5CE8B0)
   *
   * What it does:
   * Constructs and preregisters the static `IAiSiloBuildTypeInfo` instance.
   */
  [[nodiscard]] gpg::RType* preregister_IAiSiloBuildTypeInfo()
  {
    return AcquireIAiSiloBuildTypeInfo();
  }

  /**
   * Address: 0x00BF7DA0 (FUN_00BF7DA0, sub_BF7DA0)
   *
   * What it does:
   * Tears down the static `IAiSiloBuildTypeInfo` storage at process exit.
   */
  void cleanup_IAiSiloBuildTypeInfo()
  {
    if (!gIAiSiloBuildTypeInfoConstructed) {
      return;
    }

    AcquireIAiSiloBuildTypeInfo()->~IAiSiloBuildTypeInfo();
    gIAiSiloBuildTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005CE940 (FUN_005CE940, scalar deleting thunk)
 */
IAiSiloBuildTypeInfo::~IAiSiloBuildTypeInfo() = default;

/**
 * Address: 0x005CE930 (FUN_005CE930, ?GetName@IAiSiloBuildTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiSiloBuildTypeInfo::GetName() const
{
  return "IAiSiloBuild";
}

/**
 * Address: 0x005CE910 (FUN_005CE910, ?Init@IAiSiloBuildTypeInfo@Moho@@UAEXXZ)
 */
void IAiSiloBuildTypeInfo::Init()
{
  size_ = sizeof(IAiSiloBuild);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCE010 (FUN_00BCE010, register_IAiSiloBuildTypeInfo)
 *
 * What it does:
 * Constructs and preregisters `IAiSiloBuildTypeInfo`, then schedules
 * process-exit cleanup for its static storage.
 */
int moho::register_IAiSiloBuildTypeInfo()
{
  (void)preregister_IAiSiloBuildTypeInfo();
  return std::atexit(&cleanup_IAiSiloBuildTypeInfo);
}

namespace
{
  struct IAiSiloBuildTypeInfoBootstrap
  {
    IAiSiloBuildTypeInfoBootstrap()
    {
      (void)moho::register_IAiSiloBuildTypeInfo();
    }
  };

  [[maybe_unused]] IAiSiloBuildTypeInfoBootstrap gIAiSiloBuildTypeInfoBootstrap;
} // namespace
