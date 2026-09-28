#include "moho/ai/EAiPathNavigatorStateTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathNavigator.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF7320 (FUN_00BF7320, atexit destructor of the EAiPathNavigatorStateTypeInfo object)
   */
  [[nodiscard]] EAiPathNavigatorStateTypeInfo* AcquireEAiPathNavigatorStateTypeInfo()
  {
    static EAiPathNavigatorStateTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005AD240 (FUN_005AD240)
   *
   * What it does:
   * Constructs and preregisters the static `EAiPathNavigatorStateTypeInfo`
   * instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_EAiPathNavigatorStateTypeInfo()
  {
    EAiPathNavigatorStateTypeInfo* const typeInfo = AcquireEAiPathNavigatorStateTypeInfo();
    gpg::PreRegisterRType(typeid(EAiPathNavigatorState), typeInfo);
    return typeInfo;
  }

  // Address: 0x010AEE20 -- process-global `PrimitiveSerHelper<CAiPathNavigator::
  // State,int>` singleton (constructed by FUN_00BCCFE0, self-registering via
  // `__xc_a`; see EAiPathNavigatorStateTypeInfo.h for the real-ctor/atexit-
  // target evidence and the CAiPathNavigator::State vs. EAiPathNavigatorState
  // naming note).
  moho::EAiPathNavigatorStatePrimitiveSerializer gEAiPathNavigatorStatePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005AD2D0 (FUN_005AD2D0, scalar deleting thunk)
 */
EAiPathNavigatorStateTypeInfo::~EAiPathNavigatorStateTypeInfo() = default;

/**
 * Address: 0x005AD2C0 (FUN_005AD2C0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiPathNavigatorState.
 */
const char* EAiPathNavigatorStateTypeInfo::GetName() const
{
  return "EAiPathNavigatorState";
}

/**
 * Address: 0x005AD2A0 (FUN_005AD2A0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAiPathNavigatorStateTypeInfo::Init()
{
  size_ = sizeof(EAiPathNavigatorState);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCCFC0 (FUN_00BCCFC0, register_EAiPathNavigatorStateTypeInfo)
 *
 * What it does:
 * Registers `EAiPathNavigatorState` enum type-info.
 */
void moho::register_EAiPathNavigatorStateTypeInfo()
{
  (void)preregister_EAiPathNavigatorStateTypeInfo();
}

namespace
{
  struct EAiPathNavigatorStateTypeInfoBootstrap
  {
    EAiPathNavigatorStateTypeInfoBootstrap()
    {
      moho::register_EAiPathNavigatorStateTypeInfo();
    }
  };

  [[maybe_unused]] EAiPathNavigatorStateTypeInfoBootstrap gEAiPathNavigatorStateTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiPathNavigatorStateTypeInfo_5c34f8, moho::register_EAiPathNavigatorStateTypeInfo)

GPG_PREREGISTER_INIT(AcquireEAiPathNavigatorStateTypeInfo_5c34f8, AcquireEAiPathNavigatorStateTypeInfo)
