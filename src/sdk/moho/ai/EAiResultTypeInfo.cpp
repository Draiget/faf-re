#include "moho/ai/EAiResultTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include "moho/ai/EAiResult.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(moho::EAiResultTypeInfo) unsigned char gEAiResultTypeInfoStorage[sizeof(moho::EAiResultTypeInfo)]{};
  bool gEAiResultTypeInfoConstructed = false;

  // Address: 0x010B12DC -- process-global `PrimitiveSerHelper<EAiResult,int>`
  // singleton (constructed by FUN_00BD0530, self-registering via `__xc_a`;
  // see the per-instantiation address list on gpg::PrimitiveSerHelper in
  // Reflection.h for the real-ctor/atexit-target evidence).
  moho::EAiResultPrimitiveSerializer gEAiResultPrimitiveSerializer;

  [[nodiscard]] moho::EAiResultTypeInfo& GetEAiResultTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::EAiResultTypeInfo*>(gEAiResultTypeInfoStorage);
  }

  /**
   * Address: 0x00608B70 (FUN_00608B70, sub_608B70)
   *
   * What it does:
   * Constructs static `EAiResult` enum type-info storage and preregisters RTTI.
   */
  gpg::REnumType* construct_EAiResultTypeInfo()
  {
    if (!gEAiResultTypeInfoConstructed) {
      new (gEAiResultTypeInfoStorage) moho::EAiResultTypeInfo();
      gpg::PreRegisterRType(typeid(moho::EAiResult), &GetEAiResultTypeInfo());
      gEAiResultTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(&GetEAiResultTypeInfo());
  }

  /**
   * Address: 0x00BF9AA0 (FUN_00BF9AA0, sub_BF9AA0)
   *
   * What it does:
   * Tears down static `EAiResult` type-info storage at process exit.
   */
  void cleanup_EAiResultTypeInfo()
  {
    if (!gEAiResultTypeInfoConstructed) {
      return;
    }

    GetEAiResultTypeInfo().~EAiResultTypeInfo();
    gEAiResultTypeInfoConstructed = false;
  }

} // namespace

/**
 * Address: 0x00608C00 (FUN_00608C00, scalar deleting thunk)
 */
EAiResultTypeInfo::~EAiResultTypeInfo() = default;

/**
 * Address: 0x00608BF0 (FUN_00608BF0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiResult.
 */
const char* EAiResultTypeInfo::GetName() const
{
  return "EAiResult";
}

/**
 * Address: 0x00608BD0 (FUN_00608BD0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAiResultTypeInfo::Init()
{
  size_ = sizeof(EAiResult);
  gpg::RType::Init();
  Finish();
}

namespace moho
{
  /**
   * Address: 0x00BD0510 (FUN_00BD0510, sub_BD0510)
   *
   * What it does:
   * Registers static `EAiResult` type-info storage and schedules teardown.
   */
  int register_EAiResultTypeInfo()
  {
    (void)construct_EAiResultTypeInfo();
    return std::atexit(&cleanup_EAiResultTypeInfo);
  }

} // namespace moho

namespace
{
  struct EAiResultTypeInfoBootstrap
  {
    EAiResultTypeInfoBootstrap()
    {
      (void)moho::register_EAiResultTypeInfo();
    }
  };

  EAiResultTypeInfoBootstrap gEAiResultTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiResultTypeInfo_003fd7, moho::register_EAiResultTypeInfo)

GPG_PREREGISTER_INIT(construct_EAiResultTypeInfo_003fd7, construct_EAiResultTypeInfo)
