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
  /**
   * Address: 0x00BF6C50 (FUN_00BF6C50, atexit destructor of the EAiNavigatorStatusTypeInfo object)
   */
  [[nodiscard]] EAiNavigatorStatusTypeInfo* AcquireEAiNavigatorStatusTypeInfo()
  {
    static EAiNavigatorStatusTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010AE774 -- process-global `PrimitiveSerHelper<EAiNavigatorStatus,int>`
  // singleton (constructed by FUN_00BCC600, self-registering via `__xc_a`; see
  // EAiNavigatorStatusTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiNavigatorStatus,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiNavigatorStatus@Moho@@H@gpg'`):
   * `FUN_00BCC600` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). This address's IDA export
   * already carried synthetic struct names (`gpg::PrimitiveSerHelper_
   * EAiNavigatorStatus`), confirming via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_005A76B0`/`FUN_005A76D0`, installs the
   * `PrimitiveSerHelper<EAiNavigatorStatus,int>` vtable, and pushes
   * `FUN_00BF6C90` (IDA-labeled `??1PrimitiveSerHelper_EAiNavigatorStatus@
   * gpg@@QAE@@Z` -- a synthetic/heuristic name, not real MSVC mangling for
   * this template) as its `atexit` target; confirmed to be the same bare
   * unlink-then-self-link shape as every other instantiation's atexit
   * target, matching the helper node's unlink (`gpg::DListItem::ListUnlink`) -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiNavigatorStatusPrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiNavigatorStatusTypeInfoBootstrap` constructor -- absent from the
   * real ctor's disassembly (`FUN_00BCC600` already self-registers via
   * `__xc_a`); removed.
   */
  gpg::PrimitiveSerHelper<moho::EAiNavigatorStatus, int> gEAiNavigatorStatusPrimitiveSerializer;
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
