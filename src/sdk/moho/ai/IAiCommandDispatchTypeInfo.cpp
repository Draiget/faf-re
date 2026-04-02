#include "moho/ai/IAiCommandDispatchTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatch.h"
#include "moho/misc/Stats.h"

using namespace moho;

namespace
{
  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AE39Cu>::value = nullptr;

  alignas(IAiCommandDispatchTypeInfo)
  unsigned char gIAiCommandDispatchTypeInfoStorage[sizeof(IAiCommandDispatchTypeInfo)] = {};
  bool gIAiCommandDispatchTypeInfoConstructed = false;

  [[nodiscard]] IAiCommandDispatchTypeInfo* AcquireIAiCommandDispatchTypeInfo()
  {
    return reinterpret_cast<IAiCommandDispatchTypeInfo*>(gIAiCommandDispatchTypeInfoStorage);
  }

  /**
   * Address: 0x00598BC0 (FUN_00598BC0, constructor lane for IAiCommandDispatchTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `IAiCommandDispatchTypeInfo` storage and
   * preregisters RTTI for `IAiCommandDispatch`.
   */
  [[nodiscard]] gpg::RType* construct_IAiCommandDispatchTypeInfo()
  {
    if (!gIAiCommandDispatchTypeInfoConstructed) {
      IAiCommandDispatchTypeInfo* const typeInfo =
        new (gIAiCommandDispatchTypeInfoStorage) IAiCommandDispatchTypeInfo();
      gpg::PreRegisterRType(typeid(IAiCommandDispatch), typeInfo);
      gIAiCommandDispatchTypeInfoConstructed = true;
    }

    return AcquireIAiCommandDispatchTypeInfo();
  }

  /**
   * Address: 0x00BF6600 (FUN_00BF6600, cleanup_IAiCommandDispatchTypeInfo)
   *
   * What it does:
   * Tears down startup-owned IAiCommandDispatch type-info storage by running
   * the `gpg::RType` destructor lane.
   */
  void cleanup_IAiCommandDispatchTypeInfoStorage()
  {
    if (!gIAiCommandDispatchTypeInfoConstructed) {
      return;
    }

    AcquireIAiCommandDispatchTypeInfo()->gpg::RType::~RType();
    gIAiCommandDispatchTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF65E0 (FUN_00BF65E0, cleanup_IAiCommandDispatchTypeInfoStartupStatsSlot)
   *
   * What it does:
   * Destroys one startup-owned IAiCommandDispatch stats slot.
   */
  void cleanup_IAiCommandDispatchTypeInfoStartupStatsSlot()
  {
    EngineStats* const slot = StartupEngineStatsSlot<0x10AE39Cu>::value;
    if (!slot) {
      return;
    }

    delete slot;
  }
} // namespace

/**
 * Address: 0x00598C50 (FUN_00598C50, scalar deleting thunk)
 */
IAiCommandDispatchTypeInfo::~IAiCommandDispatchTypeInfo() = default;

/**
 * Address: 0x00598C40 (FUN_00598C40, ?GetName@IAiCommandDispatchTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiCommandDispatchTypeInfo::GetName() const
{
  return "IAiCommandDispatch";
}

/**
 * Address: 0x00598C20 (FUN_00598C20, ?Init@IAiCommandDispatchTypeInfo@Moho@@UAEXXZ)
 */
void IAiCommandDispatchTypeInfo::Init()
{
  size_ = sizeof(IAiCommandDispatch);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCBE80 (FUN_00BCBE80, register_IAiCommandDispatchTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI storage for `IAiCommandDispatch` and
 * installs process-exit cleanup.
 */
int moho::register_IAiCommandDispatchTypeInfo()
{
  (void)construct_IAiCommandDispatchTypeInfo();
  return std::atexit(&cleanup_IAiCommandDispatchTypeInfoStorage);
}

/**
 * Address: 0x00BCBE10 (FUN_00BCBE10, register_IAiCommandDispatchTypeInfoStartupStatsCleanup)
 *
 * What it does:
 * Registers process-exit cleanup for one startup-owned engine-stats slot.
 */
int moho::register_IAiCommandDispatchTypeInfoStartupStatsCleanup()
{
  return std::atexit(&cleanup_IAiCommandDispatchTypeInfoStartupStatsSlot);
}

namespace
{
  struct IAiCommandDispatchTypeInfoBootstrap
  {
    IAiCommandDispatchTypeInfoBootstrap()
    {
      (void)moho::register_IAiCommandDispatchTypeInfoStartupStatsCleanup();
      (void)moho::register_IAiCommandDispatchTypeInfo();
    }
  };

  [[maybe_unused]] IAiCommandDispatchTypeInfoBootstrap gIAiCommandDispatchTypeInfoBootstrap;
} // namespace
