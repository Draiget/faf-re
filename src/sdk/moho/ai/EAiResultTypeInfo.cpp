#include "moho/ai/EAiResultTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include "moho/ai/EAiResult.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  // Address: 0x010B12DC -- process-global `PrimitiveSerHelper<EAiResult,int>`
  // singleton (constructed by FUN_00BD0530, self-registering via `__xc_a`;
  // see the per-instantiation address list on gpg::PrimitiveSerHelper in
  // Reflection.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiResult,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiResult@Moho@@H@gpg'`):
   * `FUN_00BD0530` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_0060BCD0`/`FUN_0060BCF0`, installs the
   * `PrimitiveSerHelper<EAiResult,int>` vtable, and pushes plain unmangled
   * `FUN_00BF9AB0` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target. `Init()` is
   * `FUN_0060B980`, found via a vtable-slot xref search on
   * `??_7?$PrimitiveSerHelper@W4EAiResult@Moho@@H@gpg@@6B@`; its body
   * matches the template's `Init()` exactly.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` (`EAiResultPrimitiveSerializer`) with bespoke free
   * `Deserialize_EAiResult`/`Serialize_EAiResult` functions at those same
   * two addresses -- redundant with the template's own generic
   * `Deserialize`/`Serialize`, so removed in favor of this alias.
   */
  gpg::PrimitiveSerHelper<moho::EAiResult, int> gEAiResultPrimitiveSerializer;

  /**
   * Address: 0x00608B70 (FUN_00608B70, sub_608B70)
   * Address: 0x00BF9AA0 (FUN_00BF9AA0, atexit destructor of the EAiResultTypeInfo object)
   *
   * What it does:
   * Constructs the static `EAiResult` enum type-info object and preregisters RTTI.
   */
  gpg::REnumType* construct_EAiResultTypeInfo()
  {
    static moho::EAiResultTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(moho::EAiResult), &sInstance);
    return &sInstance;
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
   * Registers the static `EAiResult` type-info object.
   */
  void register_EAiResultTypeInfo()
  {
    (void)construct_EAiResultTypeInfo();
  }

} // namespace moho

namespace
{
  struct EAiResultTypeInfoBootstrap
  {
    EAiResultTypeInfoBootstrap()
    {
      moho::register_EAiResultTypeInfo();
    }
  };

  EAiResultTypeInfoBootstrap gEAiResultTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiResultTypeInfo_003fd7, moho::register_EAiResultTypeInfo)

GPG_PREREGISTER_INIT(construct_EAiResultTypeInfo_003fd7, construct_EAiResultTypeInfo)
