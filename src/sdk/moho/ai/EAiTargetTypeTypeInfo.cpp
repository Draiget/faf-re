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
  alignas(EAiTargetTypeTypeInfo) unsigned char gEAiTargetTypeTypeInfoStorage[sizeof(EAiTargetTypeTypeInfo)];
  bool gEAiTargetTypeTypeInfoConstructed = false;

  [[nodiscard]] EAiTargetTypeTypeInfo* AcquireEAiTargetTypeTypeInfo()
  {
    if (!gEAiTargetTypeTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiTargetTypeTypeInfoStorage) EAiTargetTypeTypeInfo();
      gpg::PreRegisterRType(typeid(EAiTargetType), typeInfo);
      gEAiTargetTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiTargetTypeTypeInfo*>(gEAiTargetTypeTypeInfoStorage);
  }

  /**
   * Address: 0x005E2370 (FUN_005E2370, sub_5E2370)
   *
   * What it does:
   * Constructs and preregisters the static `EAiTargetTypeTypeInfo` instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_EAiTargetTypeTypeInfo()
  {
    return AcquireEAiTargetTypeTypeInfo();
  }

  /**
   * Address: 0x00BF8870 (FUN_00BF8870, sub_BF8870)
   *
   * What it does:
   * Tears down recovered static `EAiTargetTypeTypeInfo` storage.
   */
  void cleanup_EAiTargetTypeTypeInfo()
  {
    if (!gEAiTargetTypeTypeInfoConstructed) {
      return;
    }

    AcquireEAiTargetTypeTypeInfo()->~EAiTargetTypeTypeInfo();
    gEAiTargetTypeTypeInfoConstructed = false;
  }

  // Address: 0x010B049C -- process-global `PrimitiveSerHelper<EAiTargetType,int>`
  // singleton (constructed by FUN_00BCEBF0, self-registering via `__xc_a`; see
  // EAiTargetTypeTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::EAiTargetTypePrimitiveSerializer gEAiTargetTypePrimitiveSerializer;
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
 * Registers `EAiTargetType` enum type-info and installs process-exit cleanup.
 */
int moho::register_EAiTargetTypeTypeInfo()
{
  (void)preregister_EAiTargetTypeTypeInfo();
  return std::atexit(&cleanup_EAiTargetTypeTypeInfo);
}

namespace
{
  struct EAiTargetTypeTypeInfoBootstrap
  {
    EAiTargetTypeTypeInfoBootstrap()
    {
      (void)moho::register_EAiTargetTypeTypeInfo();
    }
  };

  [[maybe_unused]] EAiTargetTypeTypeInfoBootstrap gEAiTargetTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiTargetTypeTypeInfo_f31c38, moho::register_EAiTargetTypeTypeInfo)

GPG_PREREGISTER_INIT(AcquireEAiTargetTypeTypeInfo_f31c38, AcquireEAiTargetTypeTypeInfo)
