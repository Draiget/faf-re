#include "moho/unit/Broadcaster.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiNavigatorTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF6D00 (FUN_00BF6D00, atexit destructor of the IAiNavigatorTypeInfo object)
   */
  [[nodiscard]] IAiNavigatorTypeInfo* AcquireIAiNavigatorTypeInfo()
  {
    static IAiNavigatorTypeInfo sInstance;
    return &sInstance;
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
/**
 * Address: 0x005A7B00 (FUN_005A7B00,
 *   Moho::IAiNavigatorTypeInfo::AddBase_Broadcaster_EAiNavigatorEvent)
 *
 * What it does:
 * Registers the navigator-event broadcaster as a reflected base at offset 4.
 */
void IAiNavigatorTypeInfo::AddBase_Broadcaster_EAiNavigatorEvent(gpg::RType* const typeInfo)
{
  static gpg::RType* sBroadcasterType = nullptr;
  if (!sBroadcasterType) {
    sBroadcasterType = gpg::LookupRType(typeid(Broadcaster<EAiNavigatorEvent>));
  }
  gpg::AddBaseIfPresent(typeInfo, sBroadcasterType, gpg::BaseSubobjectOffset<IAiNavigator, Broadcaster<EAiNavigatorEvent>>());
}

void IAiNavigatorTypeInfo::Init()
{
  // 0x005A31F3 stores the literal 0x0C: `sizeof(IAiNavigator)` without the
  // `mPad0C` slot (see IAiNavigator.h).
  static_assert(offsetof(moho::IAiNavigator, mPad0C) == 0x0C, "IAiNavigator registers 0x0C bytes on x86");
  size_ = offsetof(moho::IAiNavigator, mPad0C);
  gpg::RType::Init();
  AddBase_Broadcaster_EAiNavigatorEvent(this);
  Finish();
}

/**
 * Address: 0x00BCC6A0 (FUN_00BCC6A0)
 *
 * What it does:
 * Constructs startup-owned `IAiNavigatorTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_IAiNavigatorTypeInfo()
{
  (void)AcquireIAiNavigatorTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IAiNavigatorTypeInfo_2d060b, moho::register_IAiNavigatorTypeInfo)
