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
  /**
   * Address: 0x00BF8240 (FUN_00BF8240, atexit destructor of the EAiAttackerEventTypeInfo object)
   */
  [[nodiscard]] EAiAttackerEventTypeInfo* AcquireEAiAttackerEventTypeInfo()
  {
    static EAiAttackerEventTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010B0304 -- process-global `PrimitiveSerHelper<EAiAttackerEvent,int>`
  // singleton (constructed by FUN_00BCE770, self-registering via `__xc_a`; see
  // EAiAttackerEventTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiAttackerEvent,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiAttackerEvent@Moho@@H@gpg'`):
   * `FUN_00BCE770` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_005DC390`/`FUN_005DC3B0`, installs the
   * `PrimitiveSerHelper<EAiAttackerEvent,int>` vtable, and pushes plain
   * unmangled `FUN_00BF8250` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiAttackerEventPrimitiveSerializer()`
   * free function eagerly invoked a second time from `IAiAttacker.cpp`'s
   * `IAiAttackerReflectionBootstrap` constructor -- that second call is
   * absent from the real ctor's disassembly (`FUN_00BCE770` already
   * self-registers via `__xc_a` like every other `PrimitiveSerHelper<T,int>`
   * instantiation); removed from both files.
   */
  gpg::PrimitiveSerHelper<moho::EAiAttackerEvent, int> gEAiAttackerEventPrimitiveSerializer;
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
 * Registers `EAiAttackerEvent` enum type-info.
 */
void moho::register_EAiAttackerEventTypeInfo()
{
  (void)AcquireEAiAttackerEventTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiAttackerEventTypeInfo_eef8ca, moho::register_EAiAttackerEventTypeInfo)
