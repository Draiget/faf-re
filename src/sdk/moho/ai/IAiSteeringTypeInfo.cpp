#include "moho/ai/IAiSteeringTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiSteering.h"

using namespace moho;

namespace
{
  alignas(IAiSteeringTypeInfo) unsigned char gIAiSteeringTypeInfoStorage[sizeof(IAiSteeringTypeInfo)];
  bool gIAiSteeringTypeInfoConstructed = false;

  [[nodiscard]] IAiSteeringTypeInfo* AcquireIAiSteeringTypeInfo()
  {
    if (!gIAiSteeringTypeInfoConstructed) {
      new (gIAiSteeringTypeInfoStorage) IAiSteeringTypeInfo();
      gIAiSteeringTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiSteeringTypeInfo*>(gIAiSteeringTypeInfoStorage);
  }

  /**
   * Address: 0x005D1FD0 (FUN_005D1FD0)
   *
   * What it does:
   * Initializes the startup-owned `IAiSteeringTypeInfo` instance and
   * preregisters RTTI for `IAiSteering`.
   */
  [[nodiscard]] gpg::RType* preregister_IAiSteeringTypeInfoStartup()
  {
    auto* const typeInfo = AcquireIAiSteeringTypeInfo();
    gpg::PreRegisterRType(typeid(IAiSteering), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF80D0 (FUN_00BF80D0, cleanup_IAiSteeringTypeInfo)
   *
   * What it does:
   * Tears down recovered static `IAiSteeringTypeInfo` storage.
   */
  void cleanup_IAiSteeringTypeInfo()
  {
    if (!gIAiSteeringTypeInfoConstructed) {
      return;
    }

    AcquireIAiSteeringTypeInfo()->~IAiSteeringTypeInfo();
    gIAiSteeringTypeInfoConstructed = false;
  }

  struct IAiSteeringTypeInfoBootstrap
  {
    IAiSteeringTypeInfoBootstrap()
    {
      (void)moho::register_IAiSteeringTypeInfo();
    }
  };

  [[maybe_unused]] IAiSteeringTypeInfoBootstrap gIAiSteeringTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x005D2060 (FUN_005D2060, scalar deleting thunk)
 */
IAiSteeringTypeInfo::~IAiSteeringTypeInfo() = default;

/**
 * Address: 0x005D2050 (FUN_005D2050, ?GetName@IAiSteeringTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiSteeringTypeInfo::GetName() const
{
  return "IAiSteering";
}

/**
 * Address: 0x005D2030 (FUN_005D2030, ?Init@IAiSteeringTypeInfo@Moho@@UAEXXZ)
 */
void IAiSteeringTypeInfo::Init()
{
  size_ = sizeof(IAiSteering);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCE460 (FUN_00BCE460, register_IAiSteeringTypeInfo)
 *
 * What it does:
 * Registers the `IAiSteering` RTTI type-info object and installs process-exit
 * cleanup.
 */
int moho::register_IAiSteeringTypeInfo()
{
  auto* const typeInfo = static_cast<IAiSteeringTypeInfo*>(preregister_IAiSteeringTypeInfoStartup());
  IAiSteering::sType = typeInfo;
  return std::atexit(&cleanup_IAiSteeringTypeInfo);
}
