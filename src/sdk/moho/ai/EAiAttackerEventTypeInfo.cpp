#include "moho/ai/EAiAttackerEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/EAiAttackerEvent.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(EAiAttackerEventTypeInfo) unsigned char gEAiAttackerEventTypeInfoStorage[sizeof(EAiAttackerEventTypeInfo)];
  bool gEAiAttackerEventTypeInfoConstructed = false;

  [[nodiscard]] EAiAttackerEventTypeInfo* AcquireEAiAttackerEventTypeInfo()
  {
    if (!gEAiAttackerEventTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiAttackerEventTypeInfoStorage) EAiAttackerEventTypeInfo();
      gEAiAttackerEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiAttackerEventTypeInfo*>(gEAiAttackerEventTypeInfoStorage);
  }

  /**
   * Address: 0x00BF8240 (FUN_00BF8240, sub_BF8240)
   *
   * What it does:
   * Tears down recovered static `EAiAttackerEventTypeInfo` storage.
   */
  void cleanup_EAiAttackerEventTypeInfo()
  {
    if (!gEAiAttackerEventTypeInfoConstructed) {
      return;
    }

    AcquireEAiAttackerEventTypeInfo()->~EAiAttackerEventTypeInfo();
    gEAiAttackerEventTypeInfoConstructed = false;
  }

  // Address: 0x010B0304 -- process-global `PrimitiveSerHelper<EAiAttackerEvent,int>`
  // singleton (constructed by FUN_00BCE770, self-registering via `__xc_a`; see
  // EAiAttackerEventTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::EAiAttackerEventPrimitiveSerializer gEAiAttackerEventPrimitiveSerializer;
} // namespace

/**
 * Address: 0x005D59A0 (FUN_005D59A0, Moho::EAiAttackerEventTypeInfo::EAiAttackerEventTypeInfo)
 */
EAiAttackerEventTypeInfo::EAiAttackerEventTypeInfo()
{
  gpg::PreRegisterRType(typeid(EAiAttackerEvent), this);
}

/**
 * Address: 0x005D5A30 (FUN_005D5A30, scalar deleting thunk)
 */
EAiAttackerEventTypeInfo::~EAiAttackerEventTypeInfo() = default;

/**
 * Address: 0x005D5A20 (FUN_005D5A20)
 *
 * What it does:
 * Returns the reflection type name literal for EAiAttackerEvent.
 */
const char* EAiAttackerEventTypeInfo::GetName() const
{
  return "EAiAttackerEvent";
}

/**
 * Address: 0x005D5A60 (FUN_005D5A60)
 *
 * What it does:
 * Registers EAiAttackerEvent enum option names/values.
 */
void EAiAttackerEventTypeInfo::AddEnums()
{
  mPrefix = "AIATTACKEVENT_";
  AddEnum(
    StripPrefix("AIATTACKEVENT_AcquiredDesiredTarget"),
    static_cast<std::int32_t>(AIATTACKEVENT_AcquiredDesiredTarget)
  );
  AddEnum(StripPrefix("AIATTACKEVENT_OutOfRange"), static_cast<std::int32_t>(AIATTACKEVENT_OutOfRange));
  AddEnum(StripPrefix("AIATTACKEVENT_Success"), static_cast<std::int32_t>(AIATTACKEVENT_Success));
}

/**
 * Address: 0x005D5A00 (FUN_005D5A00)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiAttackerEventTypeInfo::Init()
{
  size_ = sizeof(EAiAttackerEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x00BCE750 (FUN_00BCE750, sub_BCE750)
 *
 * What it does:
 * Registers `EAiAttackerEvent` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_EAiAttackerEventTypeInfo()
{
  (void)AcquireEAiAttackerEventTypeInfo();
  return std::atexit(&cleanup_EAiAttackerEventTypeInfo);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiAttackerEventTypeInfo_eef8ca, moho::register_EAiAttackerEventTypeInfo)
