#include "moho/ai/EAiNavigatorStatusTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(EAiNavigatorStatusTypeInfo)
    unsigned char gEAiNavigatorStatusTypeInfoStorage[sizeof(EAiNavigatorStatusTypeInfo)] = {};
  bool gEAiNavigatorStatusTypeInfoConstructed = false;

  [[nodiscard]] EAiNavigatorStatusTypeInfo* AcquireEAiNavigatorStatusTypeInfo()
  {
    if (!gEAiNavigatorStatusTypeInfoConstructed) {
      new (gEAiNavigatorStatusTypeInfoStorage) EAiNavigatorStatusTypeInfo();
      gEAiNavigatorStatusTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiNavigatorStatusTypeInfo*>(gEAiNavigatorStatusTypeInfoStorage);
  }

  /**
   * Address: 0x00BF6C50 (FUN_00BF6C50, cleanup_EAiNavigatorStatusTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EAiNavigatorStatusTypeInfo` storage.
   */
  void cleanup_EAiNavigatorStatusTypeInfo()
  {
    if (!gEAiNavigatorStatusTypeInfoConstructed) {
      return;
    }

    AcquireEAiNavigatorStatusTypeInfo()->~EAiNavigatorStatusTypeInfo();
    gEAiNavigatorStatusTypeInfoConstructed = false;
  }

  // Address: 0x010AE774 -- process-global `PrimitiveSerHelper<EAiNavigatorStatus,int>`
  // singleton (constructed by FUN_00BCC600, self-registering via `__xc_a`; see
  // EAiNavigatorStatusTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::EAiNavigatorStatusPrimitiveSerializer gEAiNavigatorStatusPrimitiveSerializer;
} // namespace

/**
 * Address: 0x005A2EB0 (FUN_005A2EB0, Moho::EAiNavigatorStatusTypeInfo::EAiNavigatorStatusTypeInfo)
 *
 * IDA signature:
 * Moho::EAiNavigatorStatusTypeInfo *__thiscall
 * Moho::EAiNavigatorStatusTypeInfo::EAiNavigatorStatusTypeInfo(EAiNavigatorStatusTypeInfo *this);
 *
 * What it does:
 * Constructs the `EAiNavigatorStatus` enum reflection descriptor and hands it
 * to `gpg::PreRegisterRType` so the enum resolves through `gpg::LookupRType`.
 *
 *   0x005A2ED2  call ??0REnumType@gpg@@QAE@@Z     ; base
 *   0x005A2EE9  mov  vftable, ??_7EAiNavigatorStatusTypeInfo@Moho@@6B@
 *   0x005A2EF3  call gpg::PreRegisterRType(typeid(EAiNavigatorStatus), this)
 *
 * The vftable store is the compiler's; only the base call and the
 * pre-registration are this body's own work.
 */
EAiNavigatorStatusTypeInfo::EAiNavigatorStatusTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(EAiNavigatorStatus), this);
}

/**
 * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
 */
EAiNavigatorStatusTypeInfo::~EAiNavigatorStatusTypeInfo() = default;

/**
 * Address: 0x005A2F30 (FUN_005A2F30)
 *
 * What it does:
 * Returns the reflection type name literal for EAiNavigatorStatus.
 */
const char* EAiNavigatorStatusTypeInfo::GetName() const
{
  return "EAiNavigatorStatus";
}

/**
 * Address: 0x005A2F70 (FUN_005A2F70)
 *
 * What it does:
 * Registers EAiNavigatorStatus enum option names/values.
 */
void EAiNavigatorStatusTypeInfo::AddEnums()
{
  mPrefix = "AINAVSTATUS_";
  AddEnum(StripPrefix("AINAVSTATUS_Idle"), static_cast<std::int32_t>(AINAVSTATUS_Idle));
  AddEnum(StripPrefix("AINAVSTATUS_Thinking"), static_cast<std::int32_t>(AINAVSTATUS_Thinking));
  AddEnum(StripPrefix("AINAVSTATUS_Steering"), static_cast<std::int32_t>(AINAVSTATUS_Steering));
}

/**
 * Address: 0x005A2F10 (FUN_005A2F10)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiNavigatorStatusTypeInfo::Init()
{
  size_ = sizeof(EAiNavigatorStatus);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x00BCC5E0 (FUN_00BCC5E0, register_EAiNavigatorStatusTypeInfo)
 *
 * What it does:
 * Preregisters startup construction for the `EAiNavigatorStatus` enum RTTI
 * descriptor and installs exit-time teardown.
 */
void moho::register_EAiNavigatorStatusTypeInfo()
{
  (void)AcquireEAiNavigatorStatusTypeInfo();
  (void)std::atexit(&cleanup_EAiNavigatorStatusTypeInfo);
}

namespace
{
  struct EAiNavigatorStatusTypeInfoBootstrap
  {
    EAiNavigatorStatusTypeInfoBootstrap()
    {
      (void)moho::register_EAiNavigatorStatusTypeInfo();
    }
  };

  [[maybe_unused]] EAiNavigatorStatusTypeInfoBootstrap gEAiNavigatorStatusTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiNavigatorStatusTypeInfo_cb0714, moho::register_EAiNavigatorStatusTypeInfo)
