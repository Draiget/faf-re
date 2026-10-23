#include "moho/ai/EAiTargetTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/EAiTargetType.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF8870 (FUN_00BF8870, atexit destructor of the EAiTargetTypeTypeInfo object)
   */
  [[nodiscard]] EAiTargetTypeTypeInfo* AcquireEAiTargetTypeTypeInfo()
  {
    static EAiTargetTypeTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005E2370 (FUN_005E2370, sub_5E2370)
   *
   * What it does:
   * Constructs and preregisters the static `EAiTargetTypeTypeInfo` instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_EAiTargetTypeTypeInfo()
  {
    EAiTargetTypeTypeInfo* const typeInfo = AcquireEAiTargetTypeTypeInfo();
    gpg::PreRegisterRType(typeid(EAiTargetType), typeInfo);
    return typeInfo;
  }

  // Address: 0x010B049C -- process-global `PrimitiveSerHelper<EAiTargetType,int>`
  // singleton (constructed by FUN_00BCEBF0, self-registering via `__xc_a`; see
  // EAiTargetTypeTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiTargetType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiTargetType@Moho@@H@gpg'`):
   * `FUN_00BCEBF0` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005E35B0`/`FUN_005E35D0`, installs the
   * `PrimitiveSerHelper<EAiTargetType,int>` vtable, and pushes plain
   * unmangled `FUN_00BF8880` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiTargetTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiTargetTypeTypeInfoBootstrap` constructor -- absent from the real
   * ctor's disassembly; removed.
   */
  gpg::PrimitiveSerHelper<moho::EAiTargetType, int> gEAiTargetTypePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005E2400 (FUN_005E2400, scalar deleting thunk)
 */
EAiTargetTypeTypeInfo::~EAiTargetTypeTypeInfo() = default;

/**
 * Address: 0x005E23F0 (FUN_005E23F0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiTargetType.
 */
const char* EAiTargetTypeTypeInfo::GetName() const
{
  return "EAiTargetType";
}

/**
 * Address: 0x005E2430 (FUN_005E2430)
 *
 * What it does:
 * Registers `EAiTargetType` enum option names/values.
 */
void EAiTargetTypeTypeInfo::AddEnums()
{
  mPrefix = "AITARGET_";
  AddEnum(StripPrefix("AITARGET_None"), static_cast<std::int32_t>(EAiTargetType::AITARGET_None));
  AddEnum(StripPrefix("AITARGET_Entity"), static_cast<std::int32_t>(EAiTargetType::AITARGET_Entity));
  AddEnum(StripPrefix("AITARGET_Ground"), static_cast<std::int32_t>(EAiTargetType::AITARGET_Ground));
}

/**
 * Address: 0x005E23D0 (FUN_005E23D0)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiTargetTypeTypeInfo::Init()
{
  size_ = sizeof(EAiTargetType);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x00BCEBD0 (FUN_00BCEBD0, register_EAiTargetTypeTypeInfo)
 *
 * What it does:
 * Registers `EAiTargetType` enum type-info.
 */
void moho::register_EAiTargetTypeTypeInfo()
{
  (void)preregister_EAiTargetTypeTypeInfo();
}

namespace
{
  struct EAiTargetTypeTypeInfoBootstrap
  {
    EAiTargetTypeTypeInfoBootstrap()
    {
      moho::register_EAiTargetTypeTypeInfo();
    }
  };

  [[maybe_unused]] EAiTargetTypeTypeInfoBootstrap gEAiTargetTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiTargetTypeTypeInfo_f31c38, moho::register_EAiTargetTypeTypeInfo)

GPG_PREREGISTER_INIT(AcquireEAiTargetTypeTypeInfo_f31c38, AcquireEAiTargetTypeTypeInfo)
