#include "moho/ai/EAiNavigatorEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(EAiNavigatorEventTypeInfo)
    unsigned char gEAiNavigatorEventTypeInfoStorage[sizeof(EAiNavigatorEventTypeInfo)] = {};
  bool gEAiNavigatorEventTypeInfoConstructed = false;

  [[nodiscard]] EAiNavigatorEventTypeInfo* AcquireEAiNavigatorEventTypeInfo()
  {
    if (!gEAiNavigatorEventTypeInfoConstructed) {
      new (gEAiNavigatorEventTypeInfoStorage) EAiNavigatorEventTypeInfo();
      gEAiNavigatorEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiNavigatorEventTypeInfo*>(gEAiNavigatorEventTypeInfoStorage);
  }

  /**
   * Address: 0x00BF6C70 (FUN_00BF6C70, cleanup_EAiNavigatorEventTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EAiNavigatorEventTypeInfo` storage.
   */
  void cleanup_EAiNavigatorEventTypeInfo()
  {
    if (!gEAiNavigatorEventTypeInfoConstructed) {
      return;
    }

    AcquireEAiNavigatorEventTypeInfo()->~EAiNavigatorEventTypeInfo();
    gEAiNavigatorEventTypeInfoConstructed = false;
  }

  // Address: 0x010AE6EC -- process-global `PrimitiveSerHelper<EAiNavigatorEvent,int>`
  // singleton (constructed by FUN_00BCC660, self-registering via `__xc_a`; see
  // EAiNavigatorEventTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::EAiNavigatorEventPrimitiveSerializer gEAiNavigatorEventPrimitiveSerializer;
} // namespace

/**
 * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
 */
/**
 * Address: 0x005A3020 (FUN_005A3020,
 *   Moho::EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo)
 *
 * IDA signature:
 * gpg::REnumType *Moho::EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo();
 *
 * What it does:
 * Runs the REnumType base constructor, installs the most-derived vftable lane,
 * and pre-registers the descriptor under `typeid(EAiNavigatorEvent)`.
 *
 * The recovery previously declared no constructor at all, so the implicit one
 * ran the base chain but never pre-registered - leaving
 * LookupRType(typeid(EAiNavigatorEvent)) to throw during REF_RegisterAllTypes
 * even though the registrar and its bootstrap were both present.
 */
EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(EAiNavigatorEvent), this);
}

EAiNavigatorEventTypeInfo::~EAiNavigatorEventTypeInfo() = default;

/**
 * Address: 0x005A30A0 (FUN_005A30A0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiNavigatorEvent.
 */
const char* EAiNavigatorEventTypeInfo::GetName() const
{
  return "EAiNavigatorEvent";
}

/**
 * Address: 0x005A30E0 (FUN_005A30E0)
 *
 * What it does:
 * Registers EAiNavigatorEvent enum option names/values.
 */
void EAiNavigatorEventTypeInfo::AddEnums()
{
  mPrefix = "AINAVEVENT_";
  AddEnum(StripPrefix("AINAVEVENT_Failed"), static_cast<std::int32_t>(AINAVEVENT_Failed));
  AddEnum(StripPrefix("AINAVEVENT_Aborted"), static_cast<std::int32_t>(AINAVEVENT_Aborted));
  AddEnum(StripPrefix("AINAVEVENT_Succeeded"), static_cast<std::int32_t>(AINAVEVENT_Succeeded));
}

/**
 * Address: 0x005A3080 (FUN_005A3080)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiNavigatorEventTypeInfo::Init()
{
  size_ = sizeof(EAiNavigatorEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x00BCC640 (FUN_00BCC640, register_EAiNavigatorEventTypeInfo)
 *
 * What it does:
 * Preregisters startup construction for the `EAiNavigatorEvent` enum RTTI
 * descriptor and installs exit-time teardown.
 */
void moho::register_EAiNavigatorEventTypeInfo()
{
  (void)AcquireEAiNavigatorEventTypeInfo();
  (void)std::atexit(&cleanup_EAiNavigatorEventTypeInfo);
}

namespace
{
  struct EAiNavigatorEventTypeInfoBootstrap
  {
    EAiNavigatorEventTypeInfoBootstrap()
    {
      (void)moho::register_EAiNavigatorEventTypeInfo();
    }
  };

  [[maybe_unused]] EAiNavigatorEventTypeInfoBootstrap gEAiNavigatorEventTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiNavigatorEventTypeInfo_0c1335, moho::register_EAiNavigatorEventTypeInfo)
